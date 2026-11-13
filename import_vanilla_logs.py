#!/usr/bin/env python3
"""Import chat logs from the vanilla F-Chat 3.0 Android app into Solstice.

Android sandboxes each app's data, so Solstice cannot read the vanilla client's logs directly. This script bridges the gap from a computer with ADB:

  1. Extract  - pulls /data/data/net.f_list.fchat/files/<Character>/logs/* off the device via ADB (`adb backup`, or root).
  2. Convert  - decodes the binary log files (identical record layout across vanilla Android, Horizon and Solstice) into the Horizon export format v2 zip, restricted to logs (Horizon docs/export-format.md).
  3. Serve    - starts the desktop side of the Horizon Device Sync protocol (Horizon docs/log-sync-protocol.md, the canonical spec; Horizon electron/services/sync/ is the reference server): a single-use LAN HTTP server plus a QR code in the terminal. In Solstice: Data Manager -> Device Sync -> Scan QR code.

The QR payload carries a fresh bearer token and AES-256-GCM session key; every non-empty HTTP body on the wire is `IV(12) || ciphertext || tag(16)`. Logs go to the phone in bounded batches when it asks for them (`GET /v1/logs?cursor=`), or as one archive for a client that predates batching. The phone also uploads its own logs during the sync (the protocol is two-way), possibly in several batches; this script only reports what would have merged and discards the upload unless --save-upload is given.

Requires: Python 3.9+ (on Windows run it as `py -3 import_vanilla_logs.py`), `adb` for extraction, and `qrcode` (python) or `qrencode` (CLI) for the QR render - without either, the sync code is printed for Solstice's "Enter code manually". AES-GCM comes from the `cryptography` package when installed, else from the OpenSSL that ships with Python itself.

Examples:
  ./import_vanilla_logs.py --account MyAccount
  ./import_vanilla_logs.py --account MyAccount --method root --qr-png qr.png
  ./import_vanilla_logs.py --dry-run --out vanilla-logs.zip
  ./import_vanilla_logs.py --from-ab backup.ab --account MyAccount
"""
# /// script
# requires-python = ">=3.9"
# dependencies = ["qrcode"]
# ///
from __future__ import annotations

import argparse
import base64
import hmac
import io
import json
import os
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
import zipfile
import zlib
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Set, Tuple

VANILLA_PACKAGE = 'net.f_list.fchat'

# Fixed identifiers from the sync protocol (Horizon docs/log-sync-protocol.md, electron/services/sync/protocol.ts; Solstice mobile/sync/payload.ts).
SYNC_APP_ID = 'horizon-log-sync'
SYNC_PROTOCOL_VERSION = 1
SYNC_IV_LENGTH = 12
SYNC_TAG_LENGTH = 16
SYNC_KEY_LENGTH = 32

# Limits, numerically identical to Horizon's protocol.ts so neither side rejects what the other accepts.
SYNC_MAX_BODY_BYTES = 512 * 1024 * 1024               # any encrypted HTTP body
SYNC_MAX_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024  # one archive, uncompressed
SYNC_BATCH_TARGET_BYTES = 16 * 1024 * 1024            # JSON one outgoing batch aims for
SYNC_BATCH_MAX_RECORDS = 350000                       # allocation backstop per batch
SYNC_MAX_BATCHES = 1024                               # download batches per session
SYNC_BATCH_ENTRY = 'sync-batch.json'
SYNC_CURSOR_START = 'start'
SYNC_SESSION_TIMEOUT = 10 * 60                        # seconds to wait for the handshake
SYNC_ACTIVE_IDLE_TIMEOUT = 5 * 60                     # seconds a paired session may sit idle
SYNC_MAX_AUTH_FAILURES = 5

# The binary store reads times back as a signed Int32, so larger values would not round-trip and every re-sync would re-add them (mobile/sync/logMessage.ts). Tighter than the spec's u32 on purpose: Solstice is the receiver here.
MAX_TIME = 0x7fffffff

# Highest Conversation.Message.Type (Bcast); the spec supports 0 through 6 only.
MAX_MESSAGE_TYPE = 6

# Dotfiles and Windows shell litter, screened out of sync archives by both peers (Horizon log-backup.ts / Solstice logMessage.ts isFilesystemArtifact).
FILESYSTEM_ARTIFACT = re.compile(r'^\.|^(thumbs\.db|desktop\.ini)(\.json)?$', re.IGNORECASE)

# filesDir children that are not character directories.
NON_CHARACTER_DIRS = {'settings', 'eicons'}

Message = Dict[str, object]                     # {time:int, type:int, sender:str, text:str}
Conversation = Dict[str, object]                # {'name': Optional[str], 'messages': List[Message]}
Store = Dict[str, Dict[str, Conversation]]      # character -> key -> conversation
RawFiles = Dict[Tuple[str, str], bytes]         # (character, file name) -> file bytes


def log(msg: str) -> None:
    print(msg, flush=True)


def make_output_safe() -> None:
    """Never let a character name, a phone's name or the QR's block characters crash output. A Windows console is UTF-8 already, but a pipe or redirect (Git Bash, `| more`, a log file) uses the ANSI code page before Python 3.15, and that has no block characters at all."""
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, 'encoding', None) or '').lower().replace('-', '').replace('_', '')
        if encoding != 'utf8' and hasattr(stream, 'reconfigure'):
            try:
                stream.reconfigure(encoding='utf-8', errors='replace')
            except (ValueError, OSError):
                pass


def venv_python_works(python: str) -> bool:
    """False for a missing venv, or one whose base Python was since uninstalled or upgraded away (its python then fails to start, on Windows and POSIX alike)."""
    try:
        return subprocess.run([python, '-c', 'import sys'], stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=60).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def ensure_python_deps() -> None:
    """Auto-install missing Python dependencies into a private venv and rerun the script there. An AES-GCM backend is required, but this Python's own OpenSSL usually provides one, so `cryptography` is only installed when it does not; the qrcode module is wanted only when the qrencode CLI is not around to render the QR instead. System tools (adb, qrencode) cannot be installed this way and keep their own error messages."""
    missing = []
    if not available_gcm_backends():
        missing.append('cryptography')
    if shutil.which('qrencode') is None:
        try:
            import qrcode  # noqa: F401
        except ImportError:
            missing.append('qrcode')
    if not missing:
        return
    if os.environ.get('VANILLA_IMPORTER_BOOTSTRAPPED'):
        if 'cryptography' in missing:
            die(f'still missing {", ".join(missing)} after the automatic install; install manually: pip install {" ".join(missing)}')
        return                                  # no QR module: the sync code is printed as text instead
    cache = os.environ.get('XDG_CACHE_HOME') or os.path.expanduser('~/.cache')
    venv_dir = os.path.join(cache, 'vanilla-importer', 'venv')
    python = (os.path.join(venv_dir, 'Scripts', 'python.exe') if os.name == 'nt'
              else os.path.join(venv_dir, 'bin', 'python'))
    log(f'Missing Python packages: {", ".join(missing)}. Installing into {venv_dir} (once; --no-bootstrap disables this)...')
    try:
        if not venv_python_works(python):
            import venv
            venv.EnvBuilder(with_pip=True, clear=os.path.isdir(venv_dir)).create(venv_dir)
        subprocess.run([python, '-m', 'pip', 'install', '--quiet', '--disable-pip-version-check', *missing],
                       stdin=subprocess.DEVNULL, check=True, timeout=600)
    except Exception as error:
        if 'cryptography' in missing:
            die(f'automatic install failed ({error}); install manually: pip install {" ".join(missing)}')
        log(f'Could not install qrcode ({error}); the sync code will be printed as text instead.')
        return
    os.environ['VANILLA_IMPORTER_BOOTSTRAPPED'] = '1'
    command = [python, os.path.abspath(__file__), *sys.argv[1:]]
    if os.name != 'nt':
        os.execv(python, command)
    # Windows has no real exec: os.execv neither quotes the arguments (a path with a space splits in two) nor keeps this process alive, so the shell takes the console back while the new process still prompts in it. Run it as a child and wait.
    child = subprocess.Popen(command)
    while True:
        try:
            sys.exit(child.wait())
        except KeyboardInterrupt:
            pass                                # the child got the same Ctrl+C and winds down itself


def die(msg: str) -> 'NoReturn':  # type: ignore[name-defined]
    print(f'error: {msg}', file=sys.stderr, flush=True)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Binary log format
#
# Data file `<key>` is a sequence of little-endian records (vanilla Logs.kt, Solstice NativeLogs.swift, Horizon desktop - all byte-identical):
#   [u32 time][u8 type][u8 senderLen S][S sender][u16 textLen T][T text][u16 total = 8+S+T]
# Index file `<key>.idx` starts with [u8 nameLen N][N name] (the conversation display name); the day entries that follow are irrelevant here.
# ---------------------------------------------------------------------------

def parse_binary_log(buf: bytes) -> List[Message]:
    """Decode every record, stopping at the first truncated/corrupt one."""
    messages: List[Message] = []
    pos, n = 0, len(buf)
    while pos + 10 <= n:
        time, mtype, sender_len = struct.unpack_from('<IBB', buf, pos)
        text_len_pos = pos + 6 + sender_len
        if text_len_pos + 2 > n:
            break
        (text_len,) = struct.unpack_from('<H', buf, text_len_pos)
        body_len = 8 + sender_len + text_len
        if pos + body_len + 2 > n:
            break
        (total,) = struct.unpack_from('<H', buf, pos + body_len)
        if total != body_len:
            break
        messages.append({
            'time': time,
            'type': mtype,
            'sender': buf[pos + 6:pos + 6 + sender_len].decode('utf-8', 'replace'),
            'text': buf[text_len_pos + 2:text_len_pos + 2 + text_len].decode('utf-8', 'replace')
        })
        pos += body_len + 2
    return messages


def serialize_messages(messages: List[Message]) -> bytes:
    """Inverse of parse_binary_log (used by the self-test)."""
    out = bytearray()
    for m in messages:
        sender = str(m['sender']).encode('utf-8')
        text = str(m['text']).encode('utf-8')
        body_len = 8 + len(sender) + len(text)
        out += struct.pack('<IBB', int(m['time']), int(m['type']), len(sender))
        out += sender
        out += struct.pack('<H', len(text))
        out += text
        out += struct.pack('<H', body_len)
    return bytes(out)


def read_index_name(idx: bytes) -> Optional[str]:
    """The conversation display name stored in a `.idx` header."""
    if len(idx) < 1:
        return None
    name_len = idx[0]
    if len(idx) < 1 + name_len:
        return None
    name = idx[1:1 + name_len].decode('utf-8', 'replace')
    return name if name else None


# ---------------------------------------------------------------------------
# ADB extraction
# ---------------------------------------------------------------------------

_ADB = 'adb'


def find_adb() -> Optional[str]:
    """adb from PATH, else from an Android SDK in its usual place (Android Studio installs one but does not put it on PATH, notably on Windows)."""
    found = shutil.which('adb')
    if found:
        return found
    roots = [os.environ.get('ANDROID_HOME'), os.environ.get('ANDROID_SDK_ROOT')]
    if os.name == 'nt':
        roots.append(os.path.join(os.environ.get('LOCALAPPDATA') or '', 'Android', 'Sdk'))
    elif sys.platform == 'darwin':
        roots.append(os.path.expanduser('~/Library/Android/sdk'))
    else:
        roots.append(os.path.expanduser('~/Android/Sdk'))
    for root in roots:
        if root:
            candidate = os.path.join(root, 'platform-tools', 'adb.exe' if os.name == 'nt' else 'adb')
            if os.path.isfile(candidate):
                return candidate
    return None


def adb_command(serial: Optional[str], *args: str) -> List[str]:
    cmd = [_ADB]
    if serial:
        cmd += ['-s', serial]
    return cmd + list(args)


def run_adb(serial: Optional[str], *args: str, timeout: Optional[int] = 120) -> subprocess.CompletedProcess:
    return subprocess.run(adb_command(serial, *args), capture_output=True, timeout=timeout)


def shell_quote(s: str) -> str:
    """Quote for the *device* shell (adb re-parses the command string there)."""
    return "'" + s.replace("'", "'\\''") + "'"


def parse_app_info(dumpsys_text: str) -> Dict[str, object]:
    """Pull the fields we care about out of `adb shell dumpsys package <pkg>` (needs no root). `probed` is False when the text carried no package block, so callers can tell "unknown" apart from a genuine False."""
    version_name = re.search(r'versionName=(\S+)', dumpsys_text)
    version_code = re.search(r'versionCode=(\d+)', dumpsys_text)
    target_sdk = re.search(r'targetSdk=(\d+)', dumpsys_text)
    # ALLOW_BACKUP lives inside the flags=[...] / pkgFlags=[...] blocks.
    flags = ' '.join(re.findall(r'[Ff]lags=\[([^\]]*)\]', dumpsys_text))
    return {
        'version_name': version_name.group(1) if version_name else None,
        'version_code': int(version_code.group(1)) if version_code else None,
        'target_sdk': int(target_sdk.group(1)) if target_sdk else None,
        'allow_backup': 'ALLOW_BACKUP' in flags,
        'probed': bool(version_name or version_code),
    }


def device_sdk(serial: Optional[str]) -> Optional[int]:
    text = run_adb(serial, 'shell', 'getprop ro.build.version.sdk').stdout.decode('utf-8', 'replace').strip()
    return int(text) if text.isdigit() else None


def probe_app(serial: Optional[str]) -> Dict[str, object]:
    proc = run_adb(serial, 'shell', f'dumpsys package {shell_quote(VANILLA_PACKAGE)}')
    info = parse_app_info(proc.stdout.decode('utf-8', 'replace'))
    info['device_sdk'] = device_sdk(serial)
    return info


def backup_viable(info: Dict[str, object]) -> bool:
    """adb backup captures an app's data unless the app targets SDK 31+ AND the device runs Android 12+ (API 31+); it also needs allowBackup. Unknowns are treated optimistically so we still attempt the backup."""
    if info.get('probed') and info.get('allow_backup') is False:
        return False
    target, device = info.get('target_sdk'), info.get('device_sdk')
    if isinstance(target, int) and isinstance(device, int) and target >= 31 and device >= 31:
        return False
    return True


def auto_order(info: Dict[str, object]) -> List[str]:
    """Extraction strategies to try, ordered by what the probe found."""
    if backup_viable(info):
        return ['backup', 'root']                   # every released build so far (targetSdk 27)
    return ['root', 'backup']                        # backup-excluded: root only


def describe_app(info: Dict[str, object]) -> str:
    """One-line diagnosis of the installed app for the user."""
    if not info.get('probed'):
        return ''
    head = f"Installed {VANILLA_PACKAGE} {info.get('version_name') or '?'}"
    if info.get('version_code') is not None:
        head += f" (code {info['version_code']})"
    bits = [head]
    if info.get('target_sdk') is not None:
        bits.append(f"targetSdk {info['target_sdk']}")
    bits.append('allowBackup=' + ('yes' if info.get('allow_backup') else 'no'))
    rec = 'adb backup is the extraction method.' if backup_viable(info) else 'adb backup excludes its data -> root is required.'
    return ', '.join(bits) + '. ' + rec


def parse_adb_devices(text: str) -> Dict[str, str]:
    """serial -> state ('device', 'unauthorized', 'offline', ...) from `adb devices`."""
    states: Dict[str, str] = {}
    for line in text.splitlines():
        fields = line.strip().split('\t')
        if len(fields) >= 2 and fields[0] and not line.startswith(('List of devices', '*')):
            states[fields[0]] = fields[1].strip()
    return states


def check_device(serial: Optional[str]) -> Dict[str, object]:
    global _ADB
    adb = find_adb()
    if adb is None:
        if os.name == 'nt':
            die('adb was not found. Download "SDK Platform-Tools for Windows" from https://developer.android.com/tools/releases/platform-tools, unzip it, and add that folder to PATH (or install Android Studio). Or skip ADB with --from-dir/--from-tar/--from-ab.')
        die('adb was not found; install android-tools (or the Android SDK Platform-Tools), or skip ADB with --from-dir/--from-tar/--from-ab')
    _ADB = adb
    # Start the server up front with its output detached: a server spawned by a captured command can inherit that command's pipes and keep them open.
    try:
        subprocess.run(adb_command(None, 'start-server'), stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
    except subprocess.TimeoutExpired:
        pass
    states = parse_adb_devices(run_adb(serial, 'devices').stdout.decode('utf-8', 'replace'))
    if serial is not None:
        states = {s: st for s, st in states.items() if s == serial}
    devices = [s for s, state in states.items() if state == 'device']
    if not devices:
        if 'unauthorized' in states.values():
            die('the phone has not authorized this computer yet: unlock it, accept the "Allow USB debugging?" prompt (tick "Always allow"), then run the importer again')
        hint = ''
        if os.name == 'nt':
            hint = ("; on Windows some phones (Samsung, Xiaomi, ...) also need the manufacturer's USB driver before adb can see them, and Pixels need Google's USB Driver")
        die(f'no ADB device connected: plug the phone in by USB, enable Developer options -> USB debugging, and check that `adb devices` lists it{hint}')
    if serial is None and len(devices) > 1:
        die(f'multiple devices connected, pick one with --serial: {", ".join(devices)}')
    proc = run_adb(serial, 'shell', f'pm path {shell_quote(VANILLA_PACKAGE)}')
    if b'package:' not in proc.stdout:
        die(f'{VANILLA_PACKAGE} is not installed on the device')
    info = probe_app(serial)
    description = describe_app(info)
    if description:
        log(description)
    return info


def files_from_tar_bytes(data: bytes) -> Optional[RawFiles]:
    """Collect <character>/logs/* files from a tar produced by any strategy."""
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode='r:*')
    except tarfile.TarError:
        return None
    # root produces files/<char>/logs/<f>; adb backup apps/<pkg>/f/<char>/logs/<f>
    pattern = re.compile(r'^(?:\./)?(?:apps/[^/]+/f|files)/([^/]+)/logs/([^/]+)$')
    raw: RawFiles = {}
    with tf:
        for member in tf:
            if not member.isfile():
                continue
            match = pattern.match(member.name)
            if match is None:
                continue
            extracted = tf.extractfile(member)
            if extracted is not None:
                raw[(match.group(1), match.group(2))] = extracted.read()
    return raw


def extract_via_root(serial: Optional[str]) -> Optional[RawFiles]:
    data_dir = f'/data/data/{VANILLA_PACKAGE}'
    tar_cmd = f'tar cf - -C {data_dir} files'
    attempts = []
    whoami = run_adb(serial, 'shell', 'id -u')
    if whoami.stdout.strip() == b'0':          # adbd already runs as root
        attempts.append(tar_cmd)
    attempts += [f'su 0 {tar_cmd}', f'su -c {shell_quote(tar_cmd)}']
    for attempt in attempts:
        proc = subprocess.run(adb_command(serial, 'exec-out', attempt), capture_output=True, timeout=600)
        raw = files_from_tar_bytes(proc.stdout)
        if raw:
            return raw
    return None


def parse_android_backup(data: bytes) -> bytes:
    """Unwrap an `adb backup` .ab file into its tar payload."""
    if not data.startswith(b'ANDROID BACKUP\n'):
        raise ValueError('not an adb backup file (bad magic)')
    rest = data[len(b'ANDROID BACKUP\n'):]
    fields = []
    for _ in range(3):                          # version, compressed, encryption
        newline = rest.index(b'\n')
        fields.append(rest[:newline].decode('ascii', 'replace'))
        rest = rest[newline + 1:]
    _version, compressed, encryption = fields
    if encryption != 'none':
        raise ValueError('the backup is password-encrypted; retry without a backup password')
    if compressed == '1':
        rest = zlib.decompressobj().decompress(rest)
    return rest


def backup_empty_reason(info: Optional[Dict[str, object]]) -> str:
    """Why an adb backup came back empty, tuned to what the probe found."""
    if info and info.get('probed') and not backup_viable(info):
        return (f"(this build targets SDK {info.get('target_sdk')} on Android {info.get('device_sdk')}, so Android strips its data from adb backup - root is required).")
    return '(the on-device prompt was probably cancelled, or this ROM disables adb backup).'


def extract_via_backup(serial: Optional[str], scratch: str,
                       info: Optional[Dict[str, object]] = None) -> Optional[RawFiles]:
    ab_path = os.path.join(scratch, 'vanilla-backup.ab')
    log('Requesting an app backup. ON THE PHONE NOW: unlock it, tap "Back up my data", and leave the password field EMPTY (a password encrypts the file so the importer cannot read it).')
    try:
        subprocess.run(adb_command(serial, 'backup', '-f', ab_path, '-noapk', VANILLA_PACKAGE), timeout=600)
    except subprocess.TimeoutExpired:
        log('  adb backup timed out waiting for the on-device confirmation.')
        return None
    if not os.path.exists(ab_path) or os.path.getsize(ab_path) < 32:
        log('  adb backup produced no data ' + backup_empty_reason(info))
        return None
    with open(ab_path, 'rb') as f:
        try:
            tar_bytes = parse_android_backup(f.read())
        except ValueError as error:
            log(f'  adb backup produced an unusable file: {error}')
            return None
    raw = files_from_tar_bytes(tar_bytes)
    if not raw:
        log('  the backup contained no log files ' + backup_empty_reason(info))
    return raw


def extract_from_device(serial: Optional[str], method: str, scratch: str) -> RawFiles:
    info = check_device(serial)
    strategies = {'root': extract_via_root, 'backup': lambda s: extract_via_backup(s, scratch, info)}
    order = [method] if method != 'auto' else auto_order(info)
    if method == 'auto' and not backup_viable(info):
        log('Warning: Android excludes this build\'s data from adb backup, so extraction needs root.')
    for name in order:
        log(f'Trying extraction via {name}...')
        raw = strategies[name](serial)
        if raw:
            log(f'Extracted {len(raw)} files via {name}.')
            return raw
        log(f'  {name} did not work{" (no root?)" if name == "root" else ""}')

    # Nothing worked - give guidance tuned to what the probe found.
    if backup_viable(info):
        die('could not extract logs. adb backup should work for this build: re-run and COMPLETE THE ON-DEVICE PROMPT - unlock the phone, tap "Back up my data", and leave the password blank. If the prompt never appears, this ROM disables adb backup - then you need root, or extract by other means and use --from-dir/--from-tar/--from-ab.')
    die(f"could not extract logs. This build (targetSdk {info.get('target_sdk')}) on Android API {info.get('device_sdk')} has its data excluded from adb backup, so without root the logs are unreachable. Options: root the device, or extract by other means and use --from-dir/--from-tar/--from-ab.")


def files_from_dir(root: str) -> RawFiles:
    """Collect logs from an extracted directory (any nesting: it finds .../<Character>/logs/* wherever it sits)."""
    raw: RawFiles = {}
    for dirpath, dirnames, filenames in os.walk(root):
        if os.path.basename(dirpath) != 'logs':
            continue
        character = os.path.basename(os.path.dirname(dirpath))
        if not character:
            continue
        dirnames[:] = []
        for name in filenames:
            with open(os.path.join(dirpath, name), 'rb') as f:
                raw[(character, name)] = f.read()
    return raw


# ---------------------------------------------------------------------------
# Conversion to the Horizon export format (v2, logs only)
# ---------------------------------------------------------------------------

def dedupe_key(m: Message) -> Tuple[object, ...]:
    """Merge identity: the exact (time, type, sender, text) tuple."""
    return (m['time'], m['type'], m['sender'], m['text'])


def utf8_size(value: str) -> Optional[int]:
    """UTF-8 byte length, or None for a string that is not valid Unicode (a lone surrogate, which JSON can carry but UTF-8 cannot encode)."""
    try:
        return len(value.encode('utf-8'))
    except UnicodeEncodeError:
        return None


def is_mergeable(m: object) -> bool:
    """The protocol's message bounds (Horizon docs/log-sync-protocol.md): a known type, a sender of at most 255 UTF-8 bytes, sender + text + 8 bytes of record overhead within 65535, valid Unicode. Receivers skip anything else."""
    if not isinstance(m, dict):
        return False
    time, mtype, sender, text = m.get('time'), m.get('type'), m.get('sender'), m.get('text')
    if not (isinstance(time, int) and not isinstance(time, bool) and 0 <= time <= MAX_TIME
            and isinstance(mtype, int) and not isinstance(mtype, bool) and 0 <= mtype <= MAX_MESSAGE_TYPE
            and isinstance(sender, str) and isinstance(text, str)):
        return False
    sender_size, text_size = utf8_size(sender), utf8_size(text)
    return (sender_size is not None and text_size is not None
            and sender_size <= 0xff and sender_size + text_size + 8 <= 0xffff)


def is_filesystem_artifact(name: str) -> bool:
    return bool(FILESYSTEM_ARTIFACT.match(name))


def build_store(raw: RawFiles, only_characters: Optional[List[str]]) -> Store:
    wanted = {c.lower() for c in only_characters} if only_characters else None
    grouped: Dict[str, Dict[str, Dict[str, bytes]]] = {}
    for (character, file_name), data in raw.items():
        if character in NON_CHARACTER_DIRS or character.startswith('.'):
            continue
        if wanted is not None and character.lower() not in wanted:
            continue
        key = file_name[:-len('.idx')] if file_name.endswith('.idx') else file_name
        if is_filesystem_artifact(key):
            continue
        slot = grouped.setdefault(character, {}).setdefault(key, {})
        slot['idx' if file_name.endswith('.idx') else 'data'] = data

    store: Store = {}
    skipped_out_of_bounds = 0
    for character, conversations in grouped.items():
        for key, parts in conversations.items():
            data = parts.get('data')
            if not data:
                continue
            messages = parse_binary_log(data)
            in_bounds = [m for m in messages if is_mergeable(m)]
            skipped_out_of_bounds += len(messages) - len(in_bounds)
            # Dedupe (keep first), then stable-sort by time as the sync merge does.
            seen = set()
            unique = []
            for m in in_bounds:
                k = dedupe_key(m)
                if k not in seen:
                    seen.add(k)
                    unique.append(m)
            unique.sort(key=lambda m: m['time'])  # sort() is stable
            if not unique:
                continue
            idx = parts.get('idx')
            store.setdefault(character, {})[key] = {
                'name': read_index_name(idx) if idx else None,
                'messages': unique
            }
    if skipped_out_of_bounds:
        log(f'Skipped {skipped_out_of_bounds} out-of-bounds messages (timestamps past 2038, unknown message types, oversized records).')
    return {c: k for c, k in store.items() if k}


def record_json(m: Message) -> bytes:
    """One message as the sync zip's JSON record."""
    return json.dumps(m, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def sync_manifest(characters: List[str], expected_files: int) -> str:
    """A Horizon export manifest restricted to logs (Horizon exporter/manifest.ts). `expected_files` counts the log and logs-names entries, not the manifest."""
    return json.dumps({
        'version': 2,
        'createdAt': datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
        'app': 'horizon',
        'expectedFiles': expected_files,
        'characters': characters,
        'includes': {
            'generalSettings': False, 'logs': True, 'drafts': False, 'characterSettings': False,
            'pinned': False, 'eicons': False, 'recents': False, 'hidden': False, 'jsonLogs': True
        }
    }, indent=2)


def names_json(names: Dict[str, str]) -> str:
    return json.dumps({k: names[k] for k in sorted(names)}, ensure_ascii=False, separators=(',', ':'))


def build_sync_archive(store: Store) -> bytes:
    """The whole log set as one sync zip: the Horizon export format restricted to logs (mirrors Solstice mobile/sync/archive.ts buildSyncArchive). Also what a client that predates batching receives from a cursor-less GET /v1/logs."""
    entries: List[Tuple[str, bytes]] = []
    included: List[str] = []
    for character in sorted(store):
        names: Dict[str, str] = {}
        any_logs = False
        for key in sorted(store[character]):
            conversation = store[character][key]
            messages = conversation['messages']
            if not messages:
                continue
            body = b'[' + b','.join(record_json(m) for m in messages) + b']'
            entries.append((f'characters/{character}/logs/{key}.json', body))
            if conversation['name']:
                names[key] = str(conversation['name'])
            any_logs = True
        if any_logs:
            entries.append((f'characters/{character}/logs-names.json', names_json(names).encode('utf-8')))
            included.append(character)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        zf.writestr('manifest.json', sync_manifest(included, len(entries)))  # must be the first entry
        for name, data in entries:
            zf.writestr(name, data)
    return buffer.getvalue()


def archive_uncompressed_bytes(zf: zipfile.ZipFile) -> int:
    """Total declared uncompressed size, read from the central directory so an oversized archive is refused before any entry is inflated."""
    return sum(info.file_size for info in zf.infolist())


# A download cursor's position: (index into the conversation plan, message offset).
BatchPosition = Tuple[int, int]


def conversation_plan(store: Store) -> List[Tuple[str, str]]:
    """Every conversation, in the order batches walk them."""
    return [(c, k) for c in sorted(store) for k in sorted(store[c]) if store[c][k]['messages']]


def build_sync_batch(store: Store, plan: List[Tuple[str, str]], start: BatchPosition, index: int,
                     next_cursor: str, budget: int = SYNC_BATCH_TARGET_BYTES,
                     max_records: int = SYNC_BATCH_MAX_RECORDS) -> Tuple[bytes, Optional[BatchPosition], int]:
    """One batch of a batched GET /v1/logs (Horizon logs-zip.ts buildLogsBatchZip): the conversations from `start` on, until `budget` bytes of JSON or `max_records` records, cut after the record that crosses the budget. A conversation larger than what is left continues in the next batch under the same entry path; the store is time-sorted, so each slice is an ascending run, and the receiver's union merge reassembles the pieces with no extra machinery.

    logs-names.json covers only the conversations this batch carries (receivers take a name when they create a conversation and never revisit it), and the manifest describes this batch alone. Returns the zip, where the next batch resumes (None once this one is `done`), and how many messages it carries."""
    remaining, records_left = budget, max_records
    slices: List[Tuple[str, bytes]] = []
    names: Dict[str, Dict[str, str]] = {}
    included: List[str] = []
    carried = 0
    position, offset = start
    following: Optional[BatchPosition] = None
    while position < len(plan):
        character, key = plan[position]
        conversation = store[character][key]
        messages = conversation['messages']
        parts: List[bytes] = []
        json_bytes = 2                          # the array brackets
        end = offset
        while end < len(messages):
            record = record_json(messages[end])
            json_bytes += len(record) + (1 if parts else 0)
            parts.append(record)
            end += 1
            if json_bytes >= remaining or len(parts) >= records_left:
                break
        if parts:
            slices.append((f'characters/{character}/logs/{key}.json', b'[' + b','.join(parts) + b']'))
            if character not in included:
                included.append(character)
            if conversation['name']:
                names.setdefault(character, {})[key] = str(conversation['name'])
            remaining -= json_bytes
            records_left -= len(parts)
            carried += len(parts)
        if end < len(messages):                 # the budget ran out inside this conversation
            following = (position, end)
            break
        position, offset = position + 1, 0
        if remaining <= 0 or records_left <= 0:
            following = (position, 0) if position < len(plan) else None
            break

    envelope = ({'index': index, 'done': True} if following is None
                else {'index': index, 'done': False, 'cursor': next_cursor})
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        zf.writestr('manifest.json', sync_manifest(included, len(slices) + len(names)))
        for name, data in slices:
            zf.writestr(name, data)
        for character in included:
            if character in names:
                zf.writestr(f'characters/{character}/logs-names.json', names_json(names[character]))
        zf.writestr(SYNC_BATCH_ENTRY, json.dumps(envelope, separators=(',', ':')))
    return buffer.getvalue(), following, carried


def is_safe_segment(segment: str) -> bool:
    return (0 < len(segment.encode('utf-8', 'surrogatepass')) <= 255
            and not segment.startswith('.') and '\0' not in segment)


def parse_log_entry_path(entry: str) -> Optional[Tuple[str, str]]:
    """(character, key) for a safe `characters/<Character>/logs/<key>.json` entry, else None. Keys are lower-cased, as Solstice's merge does."""
    segments = entry.replace('\\', '/').split('/')
    if (len(segments) != 4 or segments[0] != 'characters' or segments[2] != 'logs'
            or not segments[3].endswith('.json')):
        return None
    character, key = segments[1], segments[3][:-len('.json')].lower()
    if not is_safe_segment(character) or not is_safe_segment(key):
        return None
    if character.lower() in NON_CHARACTER_DIRS or key.endswith('.idx') or is_filesystem_artifact(key):
        return None
    return character, key


# What reading one zip entry of an untrusted upload can raise.
ENTRY_READ_ERRORS = (ValueError, RecursionError, zipfile.BadZipFile, zlib.error,
                     NotImplementedError, EOFError, OSError)


def read_json_entry(zf: zipfile.ZipFile, member: object) -> object:
    """A zip entry decoded as JSON, or None when it is unreadable."""
    try:
        return json.loads(zf.read(member).decode('utf-8'))   # type: ignore[arg-type]
    except ENTRY_READ_ERRORS:
        return None


class UploadTally:
    """What the phone's uploads would add to the converted store, as the running session total POST /v1/logs reports (Horizon server.ts recordMerge). Nothing is persisted. Conversations are unioned by identity, so one split across batches counts once; only messagesAdded is additive.

    Dedupe state is kept only for the conversation currently arriving. The phone sends its log set in one total order, with a split conversation in consecutive batches, so this stays exact while bounding memory to one conversation (the same model as Solstice's SyncMerge)."""

    def __init__(self, store: Store):
        self.store = store
        self.created: Set[str] = set()
        self.updated: Set[str] = set()
        self.characters: Set[str] = set()
        self.messages_added = 0
        self.batches = 0
        self._open: Optional[str] = None
        self._seen: Set[Tuple[object, ...]] = set()

    def add(self, zf: zipfile.ZipFile) -> Dict[str, int]:
        for info in zf.infolist():
            parsed = parse_log_entry_path(info.filename)
            if parsed is None or info.is_dir():
                continue
            messages = read_json_entry(zf, info)
            if not isinstance(messages, list):
                continue
            character, key = parsed
            identity = f'{character}/{key}'
            existing = self.store.get(character, {}).get(key)
            if identity != self._open:
                self._open = identity
                self._seen = {dedupe_key(m) for m in existing['messages']} if existing else set()
            added = 0
            for m in messages:
                if not is_mergeable(m):
                    continue
                k = dedupe_key(m)
                if k in self._seen:
                    continue
                self._seen.add(k)
                added += 1
            if not added:
                continue
            self.messages_added += added
            (self.updated if existing else self.created).add(identity)
            self.characters.add(character)
        self.batches += 1
        return self.totals()

    def totals(self) -> Dict[str, int]:
        return {
            'conversationsCreated': len(self.created),
            'conversationsUpdated': len(self.updated - self.created),
            'messagesAdded': self.messages_added,
            'charactersTouched': len(self.characters),
            'conversationsSkipped': 0           # nothing is merged here, so nothing is ever damaged
        }


def combine_upload_batches(paths: List[str], out_path: str) -> int:
    """Join the phone's upload batches into one logs-only export at `out_path`, so --save-upload yields a single archive (importable like --out) however many batches the phone sent. A conversation split across batches becomes one entry again, its pieces in arrival order; display names keep the first value seen; messages no receiver would accept are dropped. Returns the conversation count."""
    pieces: Dict[str, List[Tuple[str, zipfile.ZipInfo]]] = {}
    characters: List[str] = []
    names: Dict[str, Dict[str, str]] = {}
    for path in paths:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                segments = info.filename.replace('\\', '/').split('/')
                if len(segments) == 3 and segments[0] == 'characters' and segments[2] == 'logs-names.json':
                    parsed = read_json_entry(zf, info)
                    if isinstance(parsed, dict) and is_safe_segment(segments[1]):
                        slot = names.setdefault(segments[1], {})
                        for k, v in parsed.items():
                            if isinstance(v, str) and utf8_size(k) is not None and utf8_size(v) is not None:
                                slot.setdefault(k, v)
                    continue
                entry = parse_log_entry_path(info.filename)
                if entry is None or info.is_dir():
                    continue
                character, key = entry
                pieces.setdefault(f'characters/{character}/logs/{key}.json', []).append((path, info))
                if character not in characters:
                    characters.append(character)

    opened: Dict[str, zipfile.ZipFile] = {}     # small cache: a split conversation's pieces are adjacent
    try:
        with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as out:
            out.writestr('manifest.json', sync_manifest(characters, len(pieces) + len(characters)))
            for entry, sources in pieces.items():
                with out.open(entry, 'w') as target:
                    target.write(b'[')
                    first = True
                    for path, info in sources:
                        if path not in opened:
                            if len(opened) >= 8:
                                opened.pop(next(iter(opened))).close()
                            opened[path] = zipfile.ZipFile(path)
                        messages = read_json_entry(opened[path], info)
                        for m in messages if isinstance(messages, list) else []:
                            if is_mergeable(m):
                                record = {f: m[f] for f in ('time', 'type', 'sender', 'text')}
                                target.write((b'' if first else b',') + record_json(record))
                                first = False
                    target.write(b']')
            for character in characters:
                out.writestr(f'characters/{character}/logs-names.json', names_json(names.get(character, {})))
    finally:
        for zf in opened.values():
            zf.close()
    return len(pieces)


# ---------------------------------------------------------------------------
# Sync protocol crypto: every non-empty body is IV(12) || ciphertext || tag(16)
#
# Two interchangeable AES-256-GCM backends: the `cryptography` package when it is installed, else OpenSSL's libcrypto through ctypes. Every CPython build already carries a libcrypto for its own ssl/hashlib modules (python.org's Windows builds ship it beside them as libcrypto-3*.dll), so the fallback needs no install at all. That matters on Windows on ARM and 32-bit Windows, where current cryptography releases publish no wheels and pip would try to compile.
# ---------------------------------------------------------------------------

# Known-answer vector pinning the wire framing (Solstice crypto.test.ts / McGrew-Viega AES-256-GCM test case 15, 60-byte plaintext, no AAD).
GCM_KAT_KEY = bytes.fromhex('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308')
GCM_KAT_IV = bytes.fromhex('cafebabefacedbaddecaf888')
GCM_KAT_PLAIN = bytes.fromhex('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39')
GCM_KAT_SEALED = bytes.fromhex('522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662eb9f796c8d356fc31a8433884b696f4f')


class CryptographyGCM:
    name = 'cryptography'

    def __init__(self):
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        self._aesgcm, self._invalid = AESGCM, InvalidTag

    def seal(self, key: bytes, iv: bytes, plain: bytes) -> bytes:
        return self._aesgcm(key).encrypt(iv, plain, None)

    def open(self, key: bytes, iv: bytes, sealed: bytes) -> bytes:
        try:
            return self._aesgcm(key).decrypt(iv, sealed, None)
        except self._invalid as error:          # not a ValueError, so callers would miss it
            raise ValueError('body failed authentication') from error


class OpenSSLGCM:
    """AES-256-GCM through libcrypto's EVP interface (12-byte IV, 16-byte tag, no AAD)."""
    name = 'OpenSSL'
    CTRL_GCM_GET_TAG = 0x10
    CTRL_GCM_SET_TAG = 0x11

    def __init__(self, path: str):
        import ctypes
        c = self._c = ctypes
        lib = self._lib = ctypes.CDLL(path)
        self.name = f'OpenSSL ({os.path.basename(path)})'
        lib.EVP_CIPHER_CTX_new.argtypes, lib.EVP_CIPHER_CTX_new.restype = [], c.c_void_p
        lib.EVP_CIPHER_CTX_free.argtypes, lib.EVP_CIPHER_CTX_free.restype = [c.c_void_p], None
        lib.EVP_aes_256_gcm.argtypes, lib.EVP_aes_256_gcm.restype = [], c.c_void_p
        lib.EVP_CIPHER_CTX_ctrl.argtypes = [c.c_void_p, c.c_int, c.c_int, c.c_void_p]
        lib.EVP_CIPHER_CTX_ctrl.restype = c.c_int
        for name, argtypes in (
                ('EVP_EncryptInit_ex', [c.c_void_p, c.c_void_p, c.c_void_p, c.c_char_p, c.c_char_p]),
                ('EVP_DecryptInit_ex', [c.c_void_p, c.c_void_p, c.c_void_p, c.c_char_p, c.c_char_p]),
                ('EVP_EncryptUpdate', [c.c_void_p, c.c_void_p, c.POINTER(c.c_int), c.c_char_p, c.c_int]),
                ('EVP_DecryptUpdate', [c.c_void_p, c.c_void_p, c.POINTER(c.c_int), c.c_char_p, c.c_int]),
                ('EVP_EncryptFinal_ex', [c.c_void_p, c.c_void_p, c.POINTER(c.c_int)]),
                ('EVP_DecryptFinal_ex', [c.c_void_p, c.c_void_p, c.POINTER(c.c_int)])):
            function = getattr(lib, name)
            function.argtypes, function.restype = argtypes, c.c_int

    def _run(self, encrypt: bool, key: bytes, iv: bytes, data: bytes, tag: bytes = b'') -> bytes:
        c, lib = self._c, self._lib
        if len(key) != 32 or len(iv) != SYNC_IV_LENGTH or len(data) >= 0x7fffff00:
            raise ValueError('bad AES-GCM parameters')
        ctx = lib.EVP_CIPHER_CTX_new()
        if not ctx:
            raise MemoryError('EVP_CIPHER_CTX_new failed')
        try:
            init, update, final = ((lib.EVP_EncryptInit_ex, lib.EVP_EncryptUpdate, lib.EVP_EncryptFinal_ex)
                                   if encrypt else
                                   (lib.EVP_DecryptInit_ex, lib.EVP_DecryptUpdate, lib.EVP_DecryptFinal_ex))
            if init(ctx, lib.EVP_aes_256_gcm(), None, key, iv) != 1:   # 12 bytes is GCM's default IV
                raise ValueError('AES-GCM init failed')
            out = c.create_string_buffer(len(data) + 16)
            produced = c.c_int(0)
            if update(ctx, out, c.byref(produced), data, len(data)) != 1:
                raise ValueError('AES-GCM update failed')
            total = produced.value
            if not encrypt:
                tag_buffer = c.create_string_buffer(tag, 16)
                if lib.EVP_CIPHER_CTX_ctrl(ctx, self.CTRL_GCM_SET_TAG, 16, tag_buffer) != 1:
                    raise ValueError('AES-GCM set tag failed')
            if final(ctx, c.byref(out, total), c.byref(produced)) != 1:
                raise ValueError('body failed authentication')
            total += produced.value
            result = c.string_at(out, total)
            if encrypt:
                tag_buffer = c.create_string_buffer(16)
                if lib.EVP_CIPHER_CTX_ctrl(ctx, self.CTRL_GCM_GET_TAG, 16, tag_buffer) != 1:
                    raise ValueError('AES-GCM get tag failed')
                result += tag_buffer.raw
            return result
        finally:
            lib.EVP_CIPHER_CTX_free(ctx)

    def seal(self, key: bytes, iv: bytes, plain: bytes) -> bytes:
        return self._run(True, key, iv, plain)

    def open(self, key: bytes, iv: bytes, sealed: bytes) -> bytes:
        if len(sealed) < SYNC_TAG_LENGTH:
            raise ValueError('body too short')
        return self._run(False, key, iv, sealed[:-SYNC_TAG_LENGTH], sealed[-SYNC_TAG_LENGTH:])


def libcrypto_candidates() -> List[str]:
    """Paths of the libcrypto this Python already ships or links, best first."""
    import glob
    import _hashlib                             # loads libcrypto into the process
    found: List[str] = []
    if sys.platform.startswith('linux'):
        try:                                    # exactly the one _hashlib linked
            with open('/proc/self/maps', encoding='utf-8', errors='replace') as maps:
                for line in maps:
                    path = line.split()[-1] if line.strip() else ''
                    if '/libcrypto.so' in path:
                        found.append(path)
        except OSError:
            pass
    pattern = 'libcrypto*.dll' if os.name == 'nt' else 'libcrypto*.dylib' if sys.platform == 'darwin' else 'libcrypto.so*'
    # Beside _hashlib (Windows DLLs\, or the root of an embeddable zip), then the install tree. macOS's own /usr/lib/libcrypto is never tried: loading it aborts the process.
    for folder in (os.path.dirname(getattr(_hashlib, '__file__', '') or ''), os.path.join(sys.base_prefix, 'DLLs'),
                   sys.base_prefix, os.path.join(sys.base_prefix, 'lib'), os.path.dirname(sys.executable)):
        if folder:
            found += sorted(glob.glob(os.path.join(folder, pattern)), reverse=True)
    if os.name != 'nt' and sys.platform != 'darwin':
        import ctypes.util
        name = ctypes.util.find_library('crypto')
        if name:
            found.append(name)
    return list(dict.fromkeys(found))


def gcm_backend_works(backend) -> bool:
    try:
        return (backend.seal(GCM_KAT_KEY, GCM_KAT_IV, GCM_KAT_PLAIN) == GCM_KAT_SEALED
                and backend.open(GCM_KAT_KEY, GCM_KAT_IV, GCM_KAT_SEALED) == GCM_KAT_PLAIN)
    except (ValueError, OSError, AttributeError):
        return False


def available_gcm_backends() -> List[object]:
    """Every working backend, preferred first; each must pass the known-answer test. VANILLA_IMPORTER_AES=openssl or =cryptography restricts the choice (for testing)."""
    wanted = os.environ.get('VANILLA_IMPORTER_AES', '').lower()
    backends: List[object] = []
    if wanted in ('', 'cryptography'):
        try:
            backend = CryptographyGCM()
            if gcm_backend_works(backend):
                backends.append(backend)
        except ImportError:
            pass
    if wanted in ('', 'openssl'):
        try:
            candidates = libcrypto_candidates()
        except ImportError:                     # a Python built without OpenSSL
            candidates = []
        for path in candidates:
            try:
                backend = OpenSSLGCM(path)
            except (OSError, AttributeError):   # unloadable, or not an OpenSSL with EVP GCM
                continue
            if gcm_backend_works(backend):
                backends.append(backend)
                break
    return backends


_GCM_BACKEND = None


def gcm() -> object:
    global _GCM_BACKEND
    if _GCM_BACKEND is None:
        backends = available_gcm_backends()
        if not backends:
            die('no AES-GCM implementation found: this Python has no usable OpenSSL, so install the "cryptography" package (pip install cryptography)')
        _GCM_BACKEND = backends[0]
    return _GCM_BACKEND


def encrypt_body(key: bytes, plain: bytes) -> bytes:
    iv = secrets.token_bytes(SYNC_IV_LENGTH)
    return iv + gcm().seal(key, iv, plain)       # type: ignore[attr-defined]


def decrypt_body(key: bytes, data: bytes) -> bytes:
    """Raises ValueError for a short body or one that fails GCM authentication."""
    if len(data) < SYNC_IV_LENGTH + SYNC_TAG_LENGTH:
        raise ValueError('body too short')
    return gcm().open(key, data[:SYNC_IV_LENGTH], data[SYNC_IV_LENGTH:])   # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# The Device Sync server (desktop side of the protocol)
# ---------------------------------------------------------------------------

class SyncFailure(Exception):
    """A protocol error answer: `status` with the encrypted `{"error": code}` body (or, for 401, an empty one: no session proof, no encrypted channel)."""

    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status = status
        self.code = code


def batch_target_bytes() -> int:
    """The outgoing batch budget. HORIZON_SYNC_BATCH_BYTES overrides it exactly as it does for Horizon, so a small log set can be split into many batches."""
    raw = os.environ.get('HORIZON_SYNC_BATCH_BYTES', '')
    return int(raw) if raw.isdigit() and 0 < int(raw) <= SYNC_MAX_BODY_BYTES else SYNC_BATCH_TARGET_BYTES


class SyncServer(ThreadingHTTPServer):
    """The desktop side of one single-use sync session (Horizon server.ts).

    state: waiting -> paired -> ended. `end_reason` says why it ended: finished, expired (no handshake within 10 minutes), timed-out (paired but idle for 5), or too-many-auth-failures (5 bad tokens or undecryptable bodies)."""
    daemon_threads = True

    def __init__(self, bind_port: int, account: str, store: Store, save_upload: Optional[str],
                 archive: Optional[bytes] = None, bind_addr: str = ''):
        super().__init__((bind_addr, bind_port), SyncHandler)
        self.token = secrets.token_hex(32)
        self.key = secrets.token_bytes(SYNC_KEY_LENGTH)
        self.account = account
        self.store = store
        self.plan = conversation_plan(store)
        self.batch_bytes = batch_target_bytes()
        self.device_name = socket.gethostname() or 'importer'
        self.lock = threading.Lock()
        self.state = 'waiting'
        self.end_reason: Optional[str] = None
        self.done = threading.Event()
        self.busy = False                       # one transfer at a time; others get 409 busy
        self.auth_failures = 0
        self.idle_since = time.monotonic()      # not advanced while a transfer is in flight
        # Live download cursors, token -> (position, batch index). At most two: the one that produced the batch just sent, so a failed download can be repeated, and the one naming the next batch.
        self.send_cursors: Dict[str, Tuple[BatchPosition, int]] = {}
        # Set once an upload arrives. The store here never changes, but Horizon's cursors are file offsets an upload's merge moves, so the spec makes every later cursor request fail; doing the same keeps a client that interleaves honest.
        self.cursors_stale = False
        self.batching = False
        self.sent_batches = 0
        self.sent_messages = 0
        self.tally = UploadTally(store)
        self.save_upload = save_upload
        self.upload_dir = tempfile.mkdtemp(prefix='vanilla-upload-') if save_upload else None
        self.upload_files: List[str] = []
        self._archive = archive
        self._archive_lock = threading.Lock()

    def whole_archive(self) -> bytes:
        """The unbatched archive, built on first use and bounded like Horizon's."""
        with self._archive_lock:
            if self._archive is None:
                self._archive = build_sync_archive(self.store)
            archive = self._archive
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            uncompressed = archive_uncompressed_bytes(zf)
        if (uncompressed > SYNC_MAX_UNCOMPRESSED_BYTES
                or len(archive) + SYNC_IV_LENGTH + SYNC_TAG_LENGTH > SYNC_MAX_BODY_BYTES):
            raise SyncFailure(413, 'archive-too-large')
        return archive

    def end(self, reason: str) -> None:
        """Caller holds the lock."""
        if self.state != 'ended':
            self.state, self.end_reason = 'ended', reason
            self.done.set()

    def note_auth_failure(self) -> None:
        """Caller holds the lock."""
        self.auth_failures += 1
        if self.auth_failures >= SYNC_MAX_AUTH_FAILURES:
            self.end('too-many-auth-failures')

    def check_idle(self, now: float) -> None:
        with self.lock:
            if self.state == 'ended' or self.busy:
                return
            limit = SYNC_SESSION_TIMEOUT if self.state == 'waiting' else SYNC_ACTIVE_IDLE_TIMEOUT
            if now - self.idle_since >= limit:
                self.end('expired' if self.state == 'waiting' else 'timed-out')

    def watch_idle(self) -> None:
        while not self.done.wait(1.0):
            self.check_idle(time.monotonic())

    def discard_uploads(self) -> None:
        if self.upload_dir:
            shutil.rmtree(self.upload_dir, ignore_errors=True)


class SyncHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    timeout = SYNC_ACTIVE_IDLE_TIMEOUT          # a stalled socket is dropped after 5 idle minutes
    server: SyncServer

    def log_message(self, *_args) -> None:      # silence the default access log
        pass

    def _read_body(self) -> bytes:
        if self._unread < 0:
            raise SyncFailure(400, 'read-failed')   # chunked or garbled length: unsupported
        if self._unread > SYNC_MAX_BODY_BYTES:
            raise SyncFailure(413, 'body-too-large')
        length, self._unread = self._unread, 0
        body = self.rfile.read(length) if length else b''
        if len(body) != length:
            self.close_connection = True
            raise SyncFailure(400, 'read-aborted')
        return body

    def _respond(self, status: int, body: bytes = b'') -> None:
        self._responded = True
        self.send_response(status)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(body)))
        if self._unread:                        # an unread body would desync keep-alive
            self.close_connection = True
            self.send_header('Connection', 'close')
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _respond_json(self, status: int, payload: dict) -> None:
        plain = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        self._respond(status, encrypt_body(self.server.key, plain))

    def _handle(self, method: str) -> None:
        self._responded = False
        try:
            self._unread = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            self._unread = -1
        if self.headers.get('Transfer-Encoding') or self._unread < 0:
            self._unread = -1
        try:
            self._route(method)
        except SyncFailure as failure:
            if self._responded:
                self.close_connection = True
            elif failure.status == 401:
                self._respond(401)
            else:
                self._respond_json(failure.status, {'error': failure.code})
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            self.close_connection = True        # the phone went away mid-transfer
        except Exception as error:              # never let one request kill the session silently
            log(f'  internal error on {method} {self.path.split("?")[0]}: {error!r}')
            if self._responded:
                self.close_connection = True
            else:
                self._respond_json(500, {'error': 'internal-error'})

    def _authorized(self) -> bool:
        header = self.headers.get('Authorization') or ''
        presented = header[len('Bearer '):].strip() if header.startswith('Bearer ') else ''
        # Bytes, not str: compare_digest refuses non-ASCII strings, and headers arrive latin-1.
        return bool(presented) and hmac.compare_digest(presented.encode('utf-8', 'surrogateescape'),
                                                       self.server.token.encode('ascii'))

    def _route(self, method: str) -> None:
        server = self.server
        with server.lock:
            if server.state == 'ended':
                raise SyncFailure(410, 'session-ended')
            if not self._authorized():
                server.note_auth_failure()
                raise SyncFailure(401, 'unauthorized')
        parts = urllib.parse.urlsplit(self.path)
        match = re.fullmatch(r'/v(\d+)/([^/]+)', parts.path)
        if match is None:
            raise SyncFailure(404, 'not-found')
        if match.group(1) != str(SYNC_PROTOCOL_VERSION):
            raise SyncFailure(404, 'unsupported-version')   # still a 404, so a newer client can fall back
        handler = {
            ('POST', 'handshake'): self._handshake,
            ('GET', 'logs'): self._send_logs,
            ('POST', 'logs'): self._receive_logs,
            ('POST', 'finish'): self._finish,
        }.get((method, match.group(2)))
        if handler is None:
            raise SyncFailure(404, 'not-found')
        handler(parts.query)

    def _decrypt_request(self, body: bytes) -> bytes:
        try:
            return decrypt_body(self.server.key, body)
        except ValueError:
            # A valid token without the key: counted like an auth failure, so a token-sniffing attacker is cut off quickly.
            with self.server.lock:
                self.server.note_auth_failure()
            raise SyncFailure(400, 'bad-encryption')

    def _handshake(self, _query: str) -> None:
        server = self.server
        with server.lock:
            if server.state != 'waiting':
                raise SyncFailure(409, 'already-paired')
        plain = self._decrypt_request(self._read_body())
        try:
            hello = json.loads(plain.decode('utf-8'))
        except (ValueError, RecursionError):
            raise SyncFailure(400, 'bad-json')
        if (not isinstance(hello, dict) or not isinstance(hello.get('account'), str)
                or not isinstance(hello.get('deviceName'), str)):
            raise SyncFailure(400, 'bad-handshake')
        if hello['account'].strip().lower() != server.account.strip().lower():
            raise SyncFailure(403, 'account-mismatch')
        with server.lock:                       # a second slow handshake may have raced this one
            if server.state == 'ended':
                raise SyncFailure(410, 'session-ended')
            if server.state != 'waiting':
                raise SyncFailure(409, 'already-paired')
            server.state = 'paired'
            server.idle_since = time.monotonic()
        log(f'Phone connected: {hello["deviceName"] or "unknown device"} ({hello.get("platform") or "?"}, app {hello.get("appVersion") or "?"})')
        self._respond_json(200, {
            'ok': True, 'deviceName': server.device_name,
            'account': server.account, 'protocolVersion': SYNC_PROTOCOL_VERSION
        })

    def _send_logs(self, query: str) -> None:
        """GET /v1/logs: the whole archive, or with `cursor` (the capability signal) one bounded batch whose sync-batch.json names the next."""
        server = self.server
        params = urllib.parse.parse_qs(query, keep_blank_values=True)
        cursor = params['cursor'][0] if 'cursor' in params else None
        start: BatchPosition = (0, 0)
        index = 0
        # Opaque on purpose: the query string is not encrypted, so a readable position would leak character names and conversation keys.
        next_cursor = secrets.token_hex(16)
        with server.lock:
            if server.busy:
                raise SyncFailure(409, 'busy')
            if server.state != 'paired':
                raise SyncFailure(409, 'not-paired')
            if cursor is not None:
                if server.cursors_stale:
                    raise SyncFailure(409, 'cursor-stale')
                if cursor != SYNC_CURSOR_START:
                    known = server.send_cursors.get(cursor)
                    if known is None:
                        raise SyncFailure(409, 'unknown-cursor')
                    start, index = known
                if index >= SYNC_MAX_BATCHES:
                    raise SyncFailure(409, 'too-many-batches')
                server.batching = True
            server.busy = True
        try:
            self._read_body()                   # none expected; keeps keep-alive in step
            following: Optional[BatchPosition] = None
            if cursor is None:
                plain = server.whole_archive()
                carried = sum(len(server.store[c][k]['messages']) for c, k in server.plan)
            else:
                plain, following, carried = build_sync_batch(server.store, server.plan, start, index,
                                                             next_cursor, server.batch_bytes)
                if len(plain) + SYNC_IV_LENGTH + SYNC_TAG_LENGTH > SYNC_MAX_BODY_BYTES:
                    raise SyncFailure(413, 'archive-too-large')
            self._respond(200, encrypt_body(server.key, plain))
            self.wfile.flush()
            with server.lock:
                server.sent_batches += 1
                server.sent_messages += carried
                if cursor is not None:
                    retained: Dict[str, Tuple[BatchPosition, int]] = {}
                    if cursor in server.send_cursors:
                        retained[cursor] = server.send_cursors[cursor]
                    if following is not None:
                        retained[next_cursor] = (following, index + 1)
                    server.send_cursors = retained
            if cursor is None:
                log(f'  -> sent the whole converted log archive ({len(plain)} bytes zipped).')
            else:
                log(f'  -> sent batch {index + 1}{" (last)" if following is None else ""}: {carried} messages, {len(plain)} bytes zipped.')
        finally:
            with server.lock:
                server.busy = False
                server.idle_since = time.monotonic()

    def _receive_logs(self, _query: str) -> None:
        """POST /v1/logs: one upload batch; answers with the session's running total."""
        server = self.server
        with server.lock:
            if server.busy:
                raise SyncFailure(409, 'busy')
            if server.state != 'paired':
                raise SyncFailure(409, 'not-paired')
            server.busy = True
        try:
            body = self._read_body()
            with server.lock:
                if server.state == 'ended':
                    raise SyncFailure(410, 'session-ended')
                server.cursors_stale = True     # even for an upload that then fails, as Horizon does
            upload = self._decrypt_request(body)
            try:
                zf = zipfile.ZipFile(io.BytesIO(upload))
            except (zipfile.BadZipFile, ValueError, EOFError, OSError, struct.error):
                raise SyncFailure(400, 'bad-zip')
            with zf:
                if archive_uncompressed_bytes(zf) > SYNC_MAX_UNCOMPRESSED_BYTES:
                    raise SyncFailure(413, 'archive-too-large')
                stats = server.tally.add(zf)
            if server.upload_dir:
                path = os.path.join(server.upload_dir, f'batch-{server.tally.batches:04d}.zip')
                with open(path, 'wb') as f:
                    f.write(upload)
                server.upload_files.append(path)
            self._respond_json(200, {'ok': True, **stats})
            log(f'  <- received upload batch {server.tally.batches} ({len(upload)} bytes); so far {stats["messagesAdded"]} messages would be new to this export.')
        finally:
            with server.lock:
                server.busy = False
                server.idle_since = time.monotonic()

    def _finish(self, _query: str) -> None:
        server = self.server
        with server.lock:
            if server.busy:
                raise SyncFailure(409, 'busy')
            if server.state != 'paired':
                raise SyncFailure(409, 'not-paired')
        self._read_body()                       # empty or "{}"; nothing in it matters
        with server.lock:
            if server.state != 'paired':
                raise SyncFailure(409, 'not-paired')
            server.state, server.end_reason = 'ended', 'finished'
        self._respond_json(200, {'ok': True})
        self.wfile.flush()
        server.done.set()                       # only after the answer is out, so main can shut down

    def do_GET(self) -> None:
        self._handle('GET')

    def do_POST(self) -> None:
        self._handle('POST')


# ---------------------------------------------------------------------------
# QR code + payload
# ---------------------------------------------------------------------------

def lan_addresses(overrides: Optional[List[str]]) -> List[str]:
    if overrides:
        return overrides
    addrs: List[str] = []
    try:                                        # the default-route address first
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 53))
            addrs.append(s.getsockname()[0])
    except OSError:
        pass
    try:
        proc = subprocess.run(['ip', '-j', '-4', 'addr', 'show'], capture_output=True, timeout=10)
        for iface in json.loads(proc.stdout or b'[]'):
            for info in iface.get('addr_info', []):
                if info.get('scope') == 'global':
                    addrs.append(info.get('local', ''))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    try:
        addrs.extend(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    seen = set()
    result = [a for a in addrs
              if a and not a.startswith(('127.', '169.254.')) and not (a in seen or seen.add(a))]
    if not result:
        die('could not determine a LAN IPv4 address; pass one with --addr')
    return result


def session_payload_text(addrs: List[str], port: int, token: str, key: bytes, account: str) -> str:
    return json.dumps({
        'v': SYNC_PROTOCOL_VERSION, 'app': SYNC_APP_ID, 'addrs': addrs, 'port': port,
        'token': token, 'key': base64.b64encode(key).decode('ascii'), 'account': account
    }, separators=(',', ':'))


def print_qr(text: str) -> bool:
    try:
        import qrcode
        qr = qrcode.QRCode(border=2)
        qr.add_data(text)
        qr.print_ascii(invert=True)
        return True
    except ImportError:
        pass
    if shutil.which('qrencode'):
        proc = subprocess.run(['qrencode', '-t', 'ANSIUTF8', '-m', '2', '-o', '-'],
                              input=text.encode('utf-8'), capture_output=True)
        if proc.returncode == 0:
            sys.stdout.write(proc.stdout.decode('utf-8', 'replace'))
            sys.stdout.flush()
            return True
    return False


def save_qr_png(text: str, path: str) -> bool:
    if shutil.which('qrencode'):
        proc = subprocess.run(['qrencode', '-o', path, '-s', '8', '-m', '2'], input=text.encode('utf-8'))
        return proc.returncode == 0
    try:
        import qrcode
        qrcode.make(text).save(path)
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def self_test() -> None:
    # Known-answer vector pinning the wire framing (Solstice crypto.test.ts / McGrew-Viega AES-256-GCM test case 15), written out independently of the constants.
    key = bytes.fromhex('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308')
    plain = bytes.fromhex('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39')
    expected = bytes.fromhex('cafebabefacedbaddecaf888522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662eb9f796c8d356fc31a8433884b696f4f')
    assert (key, plain, expected) == (GCM_KAT_KEY, GCM_KAT_PLAIN, GCM_KAT_IV + GCM_KAT_SEALED)
    assert decrypt_body(key, expected) == plain, 'AES-GCM decrypt KAT failed'
    assert decrypt_body(key, encrypt_body(key, b'')) == b'', 'empty body round trip failed'

    # Every available backend agrees with every other, and all reject tampering.
    backends = available_gcm_backends()
    log(f'AES-GCM backends: {", ".join(b.name for b in backends)} (using {gcm().name}).')  # type: ignore
    for size in (0, 1, 15, 16, 17, 4096, 1_000_003):
        data, iv = secrets.token_bytes(size), secrets.token_bytes(SYNC_IV_LENGTH)
        for sealer in backends:
            sealed = sealer.seal(key, iv, data)  # type: ignore[attr-defined]
            for opener in backends:
                assert opener.open(key, iv, sealed) == data, (sealer, opener, size)  # type: ignore
                for flipped in (0, len(sealed) - 1):
                    bad = bytearray(sealed)
                    bad[flipped] ^= 1
                    try:
                        opener.open(key, iv, bytes(bad))  # type: ignore[attr-defined]
                        raise AssertionError(f'{opener} accepted a tampered body')
                    except ValueError:
                        pass

    # Binary log round trip, including the corrupt-record stop.
    messages = [
        {'time': 1_700_000_000, 'type': 0, 'sender': 'Alice', 'text': 'Hello there!'},
        {'time': 1_700_000_060, 'type': 1, 'sender': 'Böb', 'text': 'waves \U0001f98a'},
        {'time': 1_700_086_400, 'type': 5, 'sender': '', 'text': 'Alice has joined'}
    ]
    blob = serialize_messages(messages)
    assert parse_binary_log(blob) == messages, 'binary log round trip failed'
    assert parse_binary_log(blob + b'\x01\x02\x03') == messages, 'trailing garbage not ignored'
    corrupt = bytearray(blob)
    corrupt[-1] ^= 0xff                         # break the first record's trailing total
    assert parse_binary_log(bytes(corrupt))[:2] == messages[:2], 'corrupt record not dropped'

    # Index name header.
    assert read_index_name(b'\x05Alice\x00\x00\x00\x00\x00\x00\x00') == 'Alice'
    assert read_index_name(b'') is None

    # Archive layout.
    store: Store = {'MyChar': {'alice': {'name': 'Alice', 'messages': messages}}}
    archive = build_sync_archive(store)
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        names = zf.namelist()
        assert names[0] == 'manifest.json', 'manifest must be the first entry'
        manifest = json.loads(zf.read('manifest.json'))
        assert manifest['version'] == 2 and manifest['app'] == 'horizon'
        assert manifest['characters'] == ['MyChar'] and manifest['expectedFiles'] == 2
        assert manifest['includes']['logs'] and manifest['includes']['jsonLogs']
        assert json.loads(zf.read('characters/MyChar/logs/alice.json')) == messages
        assert json.loads(zf.read('characters/MyChar/logs-names.json')) == {'alice': 'Alice'}

    # Merge stats: one duplicate, one new, one out of bounds.
    upload_buffer = io.BytesIO()
    with zipfile.ZipFile(upload_buffer, 'w') as zf:
        zf.writestr('manifest.json', '{}')
        zf.writestr('characters/MyChar/logs/alice.json', json.dumps([
            messages[0],
            {'time': 1_700_000_120, 'type': 0, 'sender': 'Alice', 'text': 'new on phone'},
            {'time': MAX_TIME + 1, 'type': 0, 'sender': 'Alice', 'text': 'out of bounds'}
        ]))
        zf.writestr('characters/Other/logs/bob.json', json.dumps(
            [{'time': 5, 'type': 0, 'sender': 'Bob', 'text': 'hi'}]))
    with zipfile.ZipFile(io.BytesIO(upload_buffer.getvalue())) as zf:
        stats = UploadTally(store).add(zf)
    assert stats == {'conversationsCreated': 1, 'conversationsUpdated': 1, 'messagesAdded': 2,
                     'charactersTouched': 2, 'conversationsSkipped': 0}, f'merge stats wrong: {stats}'

    # Message bounds from the spec: types stop at 6, sender + text + 8 fits a u16, valid Unicode.
    ok = {'time': 5, 'type': 6, 'sender': 'A', 'text': 'x'}
    assert is_mergeable(ok)
    assert not is_mergeable({**ok, 'type': 7}), 'type past Bcast accepted'
    assert is_mergeable({**ok, 'sender': 'a' * 255, 'text': 'b' * (0xffff - 8 - 255)})
    assert not is_mergeable({**ok, 'sender': 'a' * 255, 'text': 'b' * (0xffff - 8 - 254)}), 'record overflow'
    assert not is_mergeable({**ok, 'text': 'lone \ud800 surrogate'}), 'invalid Unicode accepted'
    assert not is_mergeable({**ok, 'time': MAX_TIME + 1})
    assert is_filesystem_artifact('Thumbs.db') and is_filesystem_artifact('.DS_Store')
    assert not is_filesystem_artifact('#abc123') and not is_filesystem_artifact('alice')

    # `adb devices`, including Windows line endings and a server-start banner.
    assert parse_adb_devices('* daemon started successfully\r\nList of devices attached\r\nR5CT\tunauthorized\r\nemulator-5554\tdevice\r\n0A1B\toffline\r\n\r\n') == {
        'R5CT': 'unauthorized', 'emulator-5554': 'device', '0A1B': 'offline'}
    assert parse_adb_devices('List of devices attached\n\n') == {}

    self_test_batches()
    self_test_server()

    # Store building from raw files (skips settings/eicons, reads idx names).
    raw: RawFiles = {
        ('MyChar', 'alice'): blob,
        ('MyChar', 'alice.idx'): b'\x05Alice',
        ('settings', 'whatever'): b'\x00\x01'
    }
    built = build_store(raw, None)
    assert list(built) == ['MyChar'] and built['MyChar']['alice']['name'] == 'Alice'
    assert built['MyChar']['alice']['messages'] == messages

    # adb backup unwrapping.
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode='w') as tf:
        info = tarfile.TarInfo(f'apps/{VANILLA_PACKAGE}/f/MyChar/logs/alice')
        info.size = len(blob)
        tf.addfile(info, io.BytesIO(blob))
    ab = b'ANDROID BACKUP\n5\n1\nnone\n' + zlib.compress(tar_buffer.getvalue())
    unwrapped = files_from_tar_bytes(parse_android_backup(ab))
    assert unwrapped == {('MyChar', 'alice'): blob}, 'adb backup unwrap failed'

    # Session payload shape.
    payload = json.loads(session_payload_text(['192.168.1.5'], 51234, 'ab' * 32, bytes(range(32)), 'Acc'))
    assert payload == {'v': 1, 'app': SYNC_APP_ID, 'addrs': ['192.168.1.5'], 'port': 51234,
                       'token': 'ab' * 32, 'key': base64.b64encode(bytes(range(32))).decode(), 'account': 'Acc'}

    # App-info probe parsing (dumpsys package output): a build from current source (targetSdk 34) and a store build.
    modern = parse_app_info('Packages:\n  Package [net.f_list.fchat] (abc):\n    versionCode=28 minSdk=21 targetSdk=34\n    versionName=3.0.16\n    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]\n')
    assert modern == {'version_name': '3.0.16', 'version_code': 28, 'target_sdk': 34, 'allow_backup': True, 'probed': True}, modern
    stock = parse_app_info('Packages:\n  Package [net.f_list.fchat] (def):\n    versionCode=27 minSdk=21 targetSdk=30\n    versionName=3.0.15\n    pkgFlags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]\n')
    assert stock == {'version_name': '3.0.15', 'version_code': 27, 'target_sdk': 30, 'allow_backup': True, 'probed': True}, stock
    assert parse_app_info('')['probed'] is False, 'empty dumpsys must read as unprobed'

    # backup_viable: excluded only when a modern-target app meets a modern device.
    assert backup_viable({'probed': True, 'allow_backup': True, 'target_sdk': 30, 'device_sdk': 34})
    assert not backup_viable({'probed': True, 'allow_backup': True, 'target_sdk': 34, 'device_sdk': 34})
    assert backup_viable({'probed': True, 'allow_backup': True, 'target_sdk': 34, 'device_sdk': 30})
    assert not backup_viable({'probed': True, 'allow_backup': False, 'target_sdk': 30, 'device_sdk': 34})
    assert backup_viable({'probed': False, 'allow_backup': False}), 'unknown app must stay optimistic'

    # auto_order picks a strategy sequence from those capabilities.
    assert auto_order({**modern, 'device_sdk': 34}) == ['root', 'backup']
    assert auto_order({**stock, 'device_sdk': 34}) == ['backup', 'root']
    assert auto_order({'probed': False}) == ['backup', 'root'], 'an unknown build must still try adb backup first'

    # The released 3.0.16 APK as a Galaxy S22 Ultra on Android 15 reports it: old target, so backup works.
    released = parse_app_info('  Package [net.f_list.fchat] (ce3c6a6):\n    versionCode=28 minSdk=21 targetSdk=27\n    versionName=3.0.16\n    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]\n    privateFlags=[ PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE_VIA_SDK_VERSION PRIVATE_FLAG_REQUEST_LEGACY_EXTERNAL_STORAGE PRIVATE_FLAG_ALLOW_NATIVE_HEAP_POINTER_TAGGING ]\n    pkgFlags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]\n')
    assert released == {'version_name': '3.0.16', 'version_code': 28, 'target_sdk': 27, 'allow_backup': True, 'probed': True}, released
    assert auto_order({**released, 'device_sdk': 35}) == ['backup', 'root']

    log('All self-tests passed.')


def self_test_store() -> Store:
    def conversation(n: int, sender: str, t0: int) -> List[Message]:
        return [{'time': t0 + i * 3600, 'type': 0, 'sender': sender, 'text': f'{sender} message {i} ' + 'x' * (i % 7)}
                for i in range(n)]
    return {
        'MyChar': {'alice': {'name': 'Alice', 'messages': conversation(40, 'Alice', 1_700_000_000)},
                   '#room': {'name': 'The Room', 'messages': conversation(6, 'Chan', 1_700_100_000)}},
        'Other': {'bob': {'name': None, 'messages': conversation(3, 'Bob', 1_700_200_000)}}
    }


def open_batch(data: bytes) -> Tuple[dict, Dict[str, List[Message]], Dict[str, dict], dict]:
    """(envelope, logs by entry path, names by character, manifest) of one sync zip."""
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        members = zf.namelist()
        envelope = json.loads(zf.read(SYNC_BATCH_ENTRY)) if SYNC_BATCH_ENTRY in members else {}
        logs = {n: json.loads(zf.read(n)) for n in members if n.startswith('characters/') and '/logs/' in n}
        names = {n.split('/')[1]: json.loads(zf.read(n)) for n in members if n.endswith('/logs-names.json')}
        return envelope, logs, names, json.loads(zf.read('manifest.json'))


def self_test_batches() -> None:
    store = self_test_store()
    plan = conversation_plan(store)
    total = sum(len(store[c][k]['messages']) for c, k in plan)

    # A 1-byte budget is crossed by every record, so each batch carries exactly one.
    position: Optional[BatchPosition] = (0, 0)
    count = 0
    while position is not None:
        _data, position, carried = build_sync_batch(store, plan, position, count, 'c', budget=1)
        assert carried == 1, carried
        count += 1
    assert count == total, (count, total)

    # A mid-size budget splits 'alice' across batches; the pieces reassemble in order.
    position, index, seen_names = (0, 0), 0, {}
    reassembled: Dict[str, List[Message]] = {}
    while position is not None:
        data, position, _carried = build_sync_batch(store, plan, position, index, f'cur{index}', budget=900)
        envelope, logs, names, manifest = open_batch(data)
        assert envelope['index'] == index and envelope['done'] == (position is None)
        assert ('cursor' in envelope) == (position is not None)
        assert manifest['expectedFiles'] == len(logs) + len(names)
        for path, messages in logs.items():
            reassembled.setdefault(path, []).extend(messages)
            character, key = path.split('/')[1], path.split('/')[3][:-len('.json')]
            if store[character][key]['name']:  # names travel with every batch carrying the conversation
                assert names[character][key] == store[character][key]['name']
        for character, mapping in names.items():
            seen_names.setdefault(character, {}).update(mapping)
            assert set(mapping) <= {p.split('/')[3][:-len('.json')] for p in logs if p.split('/')[1] == character}
        index += 1
    assert index > 3, f'budget did not split: {index} batches'
    assert reassembled == {f'characters/{c}/logs/{k}.json': store[c][k]['messages'] for c, k in plan}
    assert 'Other' not in seen_names, 'a conversation without a name must not get a names entry'

    # --save-upload joins upload batches; a split conversation becomes one entry again.
    with tempfile.TemporaryDirectory(prefix='vanilla-selftest-') as scratch:
        paths = []
        for i in range(2):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as zf:
                zf.writestr('manifest.json', '{}')
                zf.writestr(SYNC_BATCH_ENTRY, '{}')
                messages = store['MyChar']['alice']['messages']
                zf.writestr('characters/MyChar/logs/alice.json',
                            json.dumps(messages[:20] if i == 0 else messages[20:]))
                zf.writestr('characters/MyChar/logs-names.json', json.dumps({'alice': 'Alice' if i == 0 else 'Late'}))
                if i == 1:
                    zf.writestr('characters/MyChar/logs/thumbs.db.json', '[]')
                    zf.writestr('characters/MyChar/logs/#room.json', json.dumps(
                        store['MyChar']['#room']['messages'] + [{'time': 1, 'type': 9, 'sender': '', 'text': 'bad'}]))
            path = os.path.join(scratch, f'b{i}.zip')
            with open(path, 'wb') as f:
                f.write(buffer.getvalue())
            paths.append(path)
        out = os.path.join(scratch, 'joined.zip')
        assert combine_upload_batches(paths, out) == 2
        with zipfile.ZipFile(out) as zf:
            assert zf.namelist()[0] == 'manifest.json'
            assert len(zf.namelist()) == len(set(zf.namelist())), 'duplicate entries'
        _envelope, logs, names, manifest = open_batch(open(out, 'rb').read())
        assert logs['characters/MyChar/logs/alice.json'] == store['MyChar']['alice']['messages']
        assert logs['characters/MyChar/logs/#room.json'] == store['MyChar']['#room']['messages'], 'bad type kept'
        assert names == {'MyChar': {'alice': 'Alice'}} and manifest['characters'] == ['MyChar']


def self_test_server() -> None:
    """Drive the real server over loopback the way Solstice's client does."""
    import http.client

    def call(server: SyncServer, method: str, path: str, plain: Optional[bytes] = None,
             token: Optional[str] = None, raw: Optional[bytes] = None) -> Tuple[int, bytes]:
        conn = http.client.HTTPConnection('127.0.0.1', server.server_address[1], timeout=10)
        body = raw if raw is not None else (encrypt_body(server.key, plain) if plain is not None else None)
        conn.request(method, path, body=body, headers={
            'Authorization': f'Bearer {token if token is not None else server.token}',
            'Content-Type': 'application/octet-stream'})
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response.status, (decrypt_body(server.key, data) if data else b'')

    def error(result: Tuple[int, bytes]) -> Tuple[int, str]:
        return result[0], json.loads(result[1])['error']

    def started(store: Store) -> SyncServer:
        server = SyncServer(0, 'Acc', store, None, bind_addr='127.0.0.1')
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def stopped(server: SyncServer) -> None:
        server.shutdown()
        server.server_close()

    hello = json.dumps({'account': ' acc ', 'deviceName': 'Test phone', 'platform': 'test'}).encode()
    store = self_test_store()
    server = started(store)
    server.batch_bytes = 900
    try:
        assert error(call(server, 'GET', '/v1/logs?cursor=start')) == (409, 'not-paired')
        assert call(server, 'GET', '/v1/logs', token='nope') == (401, b''), 'bad token must be an empty 401'
        assert call(server, 'GET', '/v1/logs', token='té') == (401, b''), 'non-ASCII token crashed'
        assert error(call(server, 'POST', '/v2/handshake', hello)) == (404, 'unsupported-version')
        assert error(call(server, 'POST', '/v1/nope', hello)) == (404, 'not-found')
        assert error(call(server, 'POST', '/v1/handshake', b'{"account":"Acc"}')) == (400, 'bad-handshake')
        assert error(call(server, 'POST', '/v1/handshake', raw=b'\x00' * 40)) == (400, 'bad-encryption')
        assert error(call(server, 'POST', '/v1/handshake',
                          b'{"account":"Else","deviceName":"x"}')) == (403, 'account-mismatch')
        status, body = call(server, 'POST', '/v1/handshake', hello)
        assert status == 200 and json.loads(body)['protocolVersion'] == 1, (status, body)
        assert error(call(server, 'POST', '/v1/handshake', hello)) == (409, 'already-paired')

        # Unbatched: a client that sends no cursor still gets the whole archive, no envelope.
        status, body = call(server, 'GET', '/v1/logs')
        envelope, logs, _names, _manifest = open_batch(body)
        assert status == 200 and envelope == {} and len(logs) == 3

        # Batched: follow cursors to `done`. The cursor that produced the batch just sent may be repeated (a failed download); doing so mints a fresh next cursor, and older ones retire.
        cursor, batches, used = SYNC_CURSOR_START, 0, []
        reassembled: Dict[str, List[Message]] = {}
        while cursor is not None:
            path = f'/v1/logs?cursor={urllib.parse.quote(cursor)}'
            status, body = call(server, 'GET', path)
            assert status == 200, (status, body)
            if batches == 1:
                status, again = call(server, 'GET', path)
                assert status == 200 and open_batch(again)[1] == open_batch(body)[1], 'repeat differs'
                body = again                    # only the newest next-cursor stays valid
            envelope, logs, _names, _manifest = open_batch(body)
            assert envelope['index'] == batches
            for entry, messages in logs.items():
                reassembled.setdefault(entry, []).extend(messages)
            used.append(cursor)
            cursor = envelope.get('cursor')
            batches += 1
        assert batches > 3 and reassembled == {
            f'characters/{c}/logs/{k}.json': store[c][k]['messages'] for c, k in server.plan}
        assert error(call(server, 'GET', f'/v1/logs?cursor={used[1]}')) == (409, 'unknown-cursor')
        assert error(call(server, 'GET', '/v1/logs?cursor=')) == (409, 'unknown-cursor')
        server.send_cursors['far'] = ((0, 0), SYNC_MAX_BATCHES)
        assert error(call(server, 'GET', '/v1/logs?cursor=far')) == (409, 'too-many-batches')
        server.busy = True
        assert error(call(server, 'GET', '/v1/logs?cursor=start')) == (409, 'busy')
        assert error(call(server, 'POST', '/v1/finish', b'{}')) == (409, 'busy')
        server.busy = False

        # Uploads: totals run across batches, a split conversation counts once.
        def upload(entries: Dict[str, list]) -> bytes:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as zf:
                zf.writestr('manifest.json', '{}')
                for name, messages in entries.items():
                    zf.writestr(name, json.dumps(messages))
            return buffer.getvalue()
        known = store['MyChar']['alice']['messages'][0]
        new = [{'time': 1_800_000_000 + i, 'type': 1, 'sender': 'Me', 'text': f'phone {i}'} for i in range(4)]
        status, body = call(server, 'POST', '/v1/logs', upload({
            'characters/MyChar/logs/alice.json': [known, new[0]],
            'characters/Phone/logs/carol.json': [new[1]]}))
        assert status == 200 and json.loads(body) == {
            'ok': True, 'conversationsCreated': 1, 'conversationsUpdated': 1, 'messagesAdded': 2,
            'charactersTouched': 2, 'conversationsSkipped': 0}, body
        status, body = call(server, 'POST', '/v1/logs', upload({
            'characters/Phone/logs/carol.json': [new[1], new[2]],     # continues the split conversation
            'characters/MyChar/logs/#room.json': [new[3]]}))
        assert status == 200 and json.loads(body) == {
            'ok': True, 'conversationsCreated': 1, 'conversationsUpdated': 2, 'messagesAdded': 4,
            'charactersTouched': 2, 'conversationsSkipped': 0}, body
        assert error(call(server, 'POST', '/v1/logs', b'not a zip')) == (400, 'bad-zip')
        assert error(call(server, 'GET', '/v1/logs?cursor=start')) == (409, 'cursor-stale')

        assert call(server, 'POST', '/v1/finish', b'{}') == (200, b'{"ok":true}')
        assert server.end_reason == 'finished' and server.done.is_set()
        assert error(call(server, 'GET', '/v1/logs')) == (410, 'session-ended')
    finally:
        stopped(server)

    # Five failed authorizations end the session.
    server = started(store)
    try:
        for _ in range(SYNC_MAX_AUTH_FAILURES):
            call(server, 'POST', '/v1/handshake', hello, token='wrong')
        assert server.end_reason == 'too-many-auth-failures', server.end_reason
        assert error(call(server, 'POST', '/v1/handshake', hello)) == (410, 'session-ended')
    finally:
        stopped(server)

    # Idle limits: 10 minutes to pair, then 5 between requests, suspended mid-transfer.
    server = SyncServer(0, 'Acc', store, None, bind_addr='127.0.0.1')
    try:
        server.check_idle(server.idle_since + SYNC_SESSION_TIMEOUT - 1)
        assert server.state == 'waiting'
        server.check_idle(server.idle_since + SYNC_SESSION_TIMEOUT + 1)
        assert server.end_reason == 'expired'
        server.state, server.end_reason = 'paired', None
        server.busy = True
        server.check_idle(server.idle_since + SYNC_ACTIVE_IDLE_TIMEOUT * 10)
        assert server.state == 'paired', 'idle timer must be suspended during a transfer'
        server.busy = False
        server.check_idle(server.idle_since + SYNC_ACTIVE_IDLE_TIMEOUT + 1)
        assert server.end_reason == 'timed-out'
    finally:
        server.server_close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def summarize(store: Store) -> None:
    characters = len(store)
    conversations = sum(len(k) for k in store.values())
    messages = sum(len(c['messages']) for k in store.values() for c in k.values())
    times = [m['time'] for k in store.values() for c in k.values() for m in c['messages']]
    log(f'Converted {messages} messages in {conversations} conversations across {characters} characters.')
    if times:
        fmt = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime('%Y-%m-%d')
        log(f'Date range: {fmt(min(times))} to {fmt(max(times))} (UTC).')
    for character in sorted(store):
        convs = store[character]
        count = sum(len(c['messages']) for c in convs.values())
        log(f'  {character}: {len(convs)} conversations, {count} messages')


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Extract vanilla F-Chat Android logs via ADB, convert them to the Horizon format, and serve them to Solstice through Device Sync (QR code).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='In Solstice: Data Manager -> Device Sync -> Scan QR code (or Enter code manually).\nBoth devices must be on the same Wi-Fi network.')
    source = parser.add_argument_group('source (default: extract from the device via ADB)')
    source.add_argument('-s', '--serial', help='ADB device serial (when several devices are connected)')
    source.add_argument('--method', choices=['auto', 'backup', 'root'], default='auto', help='ADB extraction strategy (default: adb backup, then root; root first when Android excludes the app from backups)')
    source.add_argument('--from-dir', metavar='DIR', help='convert an already-extracted directory instead of ADB')
    source.add_argument('--from-tar', metavar='FILE', help='convert an extracted tar instead of ADB')
    source.add_argument('--from-ab', metavar='FILE', help='convert an existing `adb backup` .ab file instead of ADB')
    convert = parser.add_argument_group('conversion')
    convert.add_argument('--character', action='append', metavar='NAME', help='only include this character (repeatable, case-insensitive)')
    convert.add_argument('--out', metavar='FILE', help='also write the converted Horizon export zip to this path')
    convert.add_argument('--dry-run', action='store_true', help='extract and convert only; do not serve')
    serve = parser.add_argument_group('device sync')
    serve.add_argument('--account', help='your F-List account name (the login name, not a character); must match the account signed in on Solstice; prompted if omitted')
    serve.add_argument('--port', type=int, default=0, help='listen port (default: random)')
    serve.add_argument('--addr', action='append', metavar='IP', help='advertise this LAN address in the QR code (repeatable; default: autodetect)')
    serve.add_argument('--qr-png', metavar='FILE', help='also save the QR code as a PNG')
    serve.add_argument('--save-upload', metavar='FILE', help='save the logs Solstice uploads back, joined into one archive (default: discard)')
    parser.add_argument('--self-test', action='store_true', help='run internal format/crypto tests and exit')
    parser.add_argument('--no-bootstrap', action='store_true', help='never auto-install missing Python packages into ~/.cache/vanilla-importer')
    make_output_safe()
    args = parser.parse_args()

    if not args.no_bootstrap:
        ensure_python_deps()
    if args.self_test:
        return self_test()
    gcm()                                       # fail early without an AES-GCM backend
    if not args.dry_run and not args.account:
        if sys.stdin.isatty():
            try:
                args.account = input('Your F-List account name (the one Solstice is signed into): ').strip()
            except (EOFError, KeyboardInterrupt):
                print()
                args.account = ''
        if not args.account:
            die('an account name is required to serve (pass --account, or use --dry-run to only convert)')

    # 1. Extract.
    sources = [s for s in (args.from_dir, args.from_tar, args.from_ab) if s]
    if len(sources) > 1:
        die('pick only one of --from-dir/--from-tar/--from-ab')
    if args.from_dir:
        raw = files_from_dir(args.from_dir)
    elif args.from_tar:
        with open(args.from_tar, 'rb') as f:
            raw = files_from_tar_bytes(f.read()) or {}
    elif args.from_ab:
        with open(args.from_ab, 'rb') as f:
            try:
                raw = files_from_tar_bytes(parse_android_backup(f.read())) or {}
            except ValueError as error:
                die(str(error))
    else:
        # Not TemporaryDirectory: on Windows a virus scanner still holding the backup file would make its cleanup raise after a successful extraction.
        scratch = tempfile.mkdtemp(prefix='vanilla-import-')
        try:
            raw = extract_from_device(args.serial, args.method, scratch)
        except subprocess.TimeoutExpired as error:
            die(f'adb stopped responding ({" ".join(error.cmd[1:]) if isinstance(error.cmd, list) else error.cmd}); unplug and replug the phone, run `adb kill-server`, and try again')
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    if not raw:
        die('no log files found in the source')

    # 2. Convert.
    store = build_store(raw, args.character)
    if not store:
        die('no messages survived conversion (empty logs, or --character filtered everything out)')
    summarize(store)
    # The whole archive is only needed for --out, a dry run, or a phone that predates batching; a batching phone gets bounded batches built on demand instead.
    archive: Optional[bytes] = None
    if args.out or args.dry_run:
        archive = build_sync_archive(store)
        log(f'Horizon export archive: {len(archive)} bytes zipped.')
    if args.out and archive is not None:
        with open(args.out, 'wb') as f:
            f.write(archive)
        log(f'Wrote {args.out} (importable via Horizon\'s Data Manager as well).')
    if args.dry_run:
        return

    # 3. Serve device sync.
    server = SyncServer(args.port, args.account, store, args.save_upload, archive)
    port = server.server_address[1]
    addrs = lan_addresses(args.addr)
    payload = session_payload_text(addrs, port, server.token, server.key, args.account)

    log('')
    log(f'Device Sync server listening on port {port} (addresses: {", ".join(addrs)}).')
    log('On the phone: open Solstice -> Data Manager -> Device Sync -> Scan QR code.')
    log('')
    if not print_qr(payload):
        log('(No QR renderer found - install python-qrcode or qrencode for a scannable code.)')
    if args.qr_png:
        if save_qr_png(payload, args.qr_png):
            log(f'QR code saved to {args.qr_png}')
        else:
            log('Could not save the QR PNG (needs qrencode or python-qrcode).')
    log('If scanning fails, choose "Enter code manually" in Solstice and paste this sync code:')
    log('')
    log(f'  {payload}')
    log('')
    if os.name == 'nt':
        log('Windows: the phone connects in to this PC, so if Windows Defender Firewall asks whether Python may communicate on networks, allow it - on a network set to Public, tick Public too.')
        log('')
    log(f'Waiting for the phone (the code expires in {SYNC_SESSION_TIMEOUT // 60} minutes; Ctrl+C to abort)...')

    threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Thread(target=server.watch_idle, daemon=True).start()
    try:
        while not server.done.wait(0.5):        # a bare wait() would not see Ctrl+C promptly
            pass
    except KeyboardInterrupt:
        log('\nAborted.')
        server.shutdown()
        server.discard_uploads()
        sys.exit(130)
    server.shutdown()
    reason = server.end_reason
    log('')

    if args.save_upload and server.upload_files:
        try:
            count = combine_upload_batches(server.upload_files, args.save_upload)
            ending = '.' if reason == 'finished' else ' - the session did not finish, so it may be incomplete.'
            log(f'Saved the phone\'s upload ({count} conversations from {len(server.upload_files)} batch(es)) to {args.save_upload}{ending}')
        except (OSError, zipfile.BadZipFile) as error:
            log(f'Could not save the phone\'s upload to {args.save_upload}: {error}')
    server.discard_uploads()

    if reason == 'expired':
        firewall = ' If Solstice said it could not reach the computer, Windows Firewall is the usual cause: allow Python under Windows Security -> Firewall & network protection -> Allow an app through firewall (for this network type), or set the Wi-Fi network to Private.' if os.name == 'nt' else ''
        die(f'no phone connected within {SYNC_SESSION_TIMEOUT // 60} minutes, so the sync code expired. Run the importer again for a fresh one.' + firewall)
    if reason == 'timed-out':
        die(f'the phone went quiet for {SYNC_ACTIVE_IDLE_TIMEOUT // 60} minutes mid-sync, so the session ended. Run the importer again; re-syncing is safe, since nothing gets duplicated.')
    if reason == 'too-many-auth-failures':
        die(f'{SYNC_MAX_AUTH_FAILURES} requests failed authentication, so the session was closed for safety. Run the importer again for a fresh code, ideally on a trusted network.')

    if server.batching:
        log(f'Sent {server.sent_messages} messages to the phone in {server.sent_batches} batch(es).')
    log('Sync complete. The imported messages appear the next time you open those logs in Solstice.')
    if server.tally.messages_added > 0 and not args.save_upload:
        log('Note: the phone also uploaded its own logs (two-way protocol); they were discarded here.')
        log('Re-run with --save-upload FILE if you want to keep them next time.')


if __name__ == '__main__':
    main()
