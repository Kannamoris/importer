#!/usr/bin/env python3
"""Import chat logs from the vanilla F-Chat 3.0 Android app into Solstice.

Android sandboxes each app's data, so Solstice cannot read the vanilla client's
logs directly. This script bridges the gap from a computer with ADB:

  1. Extract  - pulls /data/data/net.f_list.fchat/files/<Character>/logs/* off
                the device via ADB (run-as for debuggable builds, root, or
                `adb backup` as a fallback).
  2. Convert  - decodes the binary log files (identical record layout across
                vanilla Android, Horizon and Solstice) into the Horizon export
                format v2 zip, restricted to logs (Horizon docs/export-format.md).
  3. Serve    - starts the desktop side of the Horizon Device Sync protocol
                (Solstice mobile/sync/*, Horizon docs/log-sync-protocol.md):
                a single-use LAN HTTP server plus a QR code in the terminal.
                In Solstice: Data Manager -> Device Sync -> Scan QR code.

The QR payload carries a fresh bearer token and AES-256-GCM session key; every
non-empty HTTP body on the wire is `IV(12) || ciphertext || tag(16)`. The phone
also uploads its own logs during the sync (the protocol is two-way); this
script only reports what would have merged and discards the upload unless
--save-upload is given.

Requires: python3 (3.9+), the `cryptography` package, `adb` on PATH for
extraction, and `qrcode` (python) or `qrencode` (CLI) for the QR render -
without either, the sync code is printed for Solstice's "Enter code manually".

Examples:
  ./import_vanilla_logs.py --account MyAccount
  ./import_vanilla_logs.py --account MyAccount --method root --qr-png qr.png
  ./import_vanilla_logs.py --dry-run --out vanilla-logs.zip
  ./import_vanilla_logs.py --from-ab backup.ab --account MyAccount
"""
# /// script
# requires-python = ">=3.9"
# dependencies = ["cryptography", "qrcode"]
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
import threading
import zipfile
import zlib
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Tuple

VANILLA_PACKAGE = 'net.f_list.fchat'

# Fixed identifiers from the sync protocol (Solstice mobile/sync/payload.ts).
SYNC_APP_ID = 'horizon-log-sync'
SYNC_PROTOCOL_VERSION = 1
SYNC_IV_LENGTH = 12
SYNC_TAG_LENGTH = 16
SYNC_KEY_LENGTH = 32

# The binary store reads times back as a signed Int32, so larger values would
# not round-trip and every re-sync would re-add them (mobile/sync/logMessage.ts).
MAX_TIME = 0x7fffffff

# filesDir children that are not character directories.
NON_CHARACTER_DIRS = {'settings', 'eicons'}

Message = Dict[str, object]                     # {time:int, type:int, sender:str, text:str}
Conversation = Dict[str, object]                # {'name': Optional[str], 'messages': List[Message]}
Store = Dict[str, Dict[str, Conversation]]      # character -> key -> conversation
RawFiles = Dict[Tuple[str, str], bytes]         # (character, file name) -> file bytes


def log(msg: str) -> None:
    print(msg, flush=True)


def ensure_python_deps() -> None:
    """Auto-install missing Python dependencies into a private venv and re-exec
    there. cryptography is required; the qrcode module only when the qrencode
    CLI is not around to render the QR instead. System tools (adb, qrencode)
    cannot be installed this way and keep their own error messages."""
    missing = []
    try:
        import cryptography  # noqa: F401
    except ImportError:
        missing.append('cryptography')
    if shutil.which('qrencode') is None:
        try:
            import qrcode  # noqa: F401
        except ImportError:
            missing.append('qrcode')
    if not missing:
        return
    if os.environ.get('VANILLA_IMPORTER_BOOTSTRAPPED'):
        die(f'still missing {", ".join(missing)} after the automatic install; '
            f'install manually: pip install {" ".join(missing)}')
    cache = os.environ.get('XDG_CACHE_HOME') or os.path.expanduser('~/.cache')
    venv_dir = os.path.join(cache, 'vanilla-importer', 'venv')
    python = os.path.join(venv_dir, 'Scripts' if os.name == 'nt' else 'bin', 'python')
    log(f'Missing Python packages: {", ".join(missing)}. Installing into {venv_dir} '
        '(once; --no-bootstrap disables this)...')
    try:
        if not os.path.exists(python):
            import venv
            venv.EnvBuilder(with_pip=True).create(venv_dir)
        subprocess.run([python, '-m', 'pip', 'install', '--quiet', *missing], check=True, timeout=300)
    except Exception as error:
        die(f'automatic install failed ({error}); install manually: pip install {" ".join(missing)}')
    os.environ['VANILLA_IMPORTER_BOOTSTRAPPED'] = '1'
    os.execv(python, [python, os.path.abspath(__file__), *sys.argv[1:]])


def die(msg: str) -> 'NoReturn':  # type: ignore[name-defined]
    print(f'error: {msg}', file=sys.stderr, flush=True)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Binary log format
#
# Data file `<key>` is a sequence of little-endian records (vanilla Logs.kt,
# Solstice NativeLogs.swift, Horizon desktop - all byte-identical):
#   [u32 time][u8 type][u8 senderLen S][S sender][u16 textLen T][T text]
#   [u16 total = 8+S+T]
# Index file `<key>.idx` starts with [u8 nameLen N][N name] (the conversation
# display name); the day entries that follow are irrelevant here.
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

def adb_command(serial: Optional[str], *args: str) -> List[str]:
    cmd = ['adb']
    if serial:
        cmd += ['-s', serial]
    return cmd + list(args)


def run_adb(serial: Optional[str], *args: str, timeout: Optional[int] = 120) -> subprocess.CompletedProcess:
    return subprocess.run(adb_command(serial, *args), capture_output=True, timeout=timeout)


def shell_quote(s: str) -> str:
    """Quote for the *device* shell (adb re-parses the command string there)."""
    return "'" + s.replace("'", "'\\''") + "'"


def parse_app_info(dumpsys_text: str) -> Dict[str, object]:
    """Pull the fields we care about out of `adb shell dumpsys package <pkg>`
    (needs no root). `probed` is False when the text carried no package block, so
    callers can tell "unknown" apart from a genuine False."""
    version_name = re.search(r'versionName=(\S+)', dumpsys_text)
    version_code = re.search(r'versionCode=(\d+)', dumpsys_text)
    target_sdk = re.search(r'targetSdk=(\d+)', dumpsys_text)
    # DEBUGGABLE / ALLOW_BACKUP live inside the flags=[...] / pkgFlags=[...] blocks.
    flags = ' '.join(re.findall(r'[Ff]lags=\[([^\]]*)\]', dumpsys_text))
    return {
        'version_name': version_name.group(1) if version_name else None,
        'version_code': int(version_code.group(1)) if version_code else None,
        'target_sdk': int(target_sdk.group(1)) if target_sdk else None,
        'debuggable': 'DEBUGGABLE' in flags,
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
    """adb backup captures an app's data unless the app targets SDK 31+ AND the
    device runs Android 12+ (API 31+); it also needs allowBackup. Unknowns are
    treated optimistically so we still attempt the backup."""
    if info.get('probed') and info.get('allow_backup') is False:
        return False
    target, device = info.get('target_sdk'), info.get('device_sdk')
    if isinstance(target, int) and isinstance(device, int) and target >= 31 and device >= 31:
        return False
    return True


def auto_order(info: Dict[str, object]) -> List[str]:
    """Extraction strategies to try, ordered by what the probe found."""
    if info.get('debuggable'):
        return ['run-as', 'root', 'backup']         # normal side-loaded tester build
    if backup_viable(info):
        return ['backup', 'root']                   # stock store build: run-as is hopeless
    return ['root', 'backup']                        # sandboxed and backup-excluded: root only


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
    bits.append('debuggable=' + ('yes' if info.get('debuggable') else 'no'))
    bits.append('allowBackup=' + ('yes' if info.get('allow_backup') else 'no'))
    if info.get('debuggable'):
        rec = 'run-as extraction is available.'
    elif backup_viable(info):
        rec = 'not debuggable -> adb backup is the recommended method.'
    else:
        rec = 'not debuggable and adb backup excludes its data -> root is required.'
    return ', '.join(bits) + '. ' + rec


def check_device(serial: Optional[str]) -> Dict[str, object]:
    if shutil.which('adb') is None:
        die('adb is not on PATH; install android-tools or use --from-dir/--from-tar/--from-ab')
    proc = run_adb(serial, 'devices')
    lines = [l for l in proc.stdout.decode('utf-8', 'replace').splitlines()[1:] if l.strip()]
    devices = [l.split('\t')[0] for l in lines if '\tdevice' in l]
    if not devices:
        die('no ADB device connected (check USB debugging and `adb devices`)')
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
    # run-as/root produce files/<char>/logs/<f>; adb backup apps/<pkg>/f/<char>/logs/<f>
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


def extract_via_run_as(serial: Optional[str]) -> Optional[RawFiles]:
    """Debuggable builds only: run-as gives us the app's uid."""
    probe = run_adb(serial, 'shell', f'run-as {VANILLA_PACKAGE} ls files')
    noise = (probe.stderr + probe.stdout).decode('utf-8', 'replace').lower()
    if probe.returncode != 0 or 'not debuggable' in noise or 'unknown package' in noise:
        return None
    tar = subprocess.run(adb_command(serial, 'exec-out', f'run-as {VANILLA_PACKAGE} tar cf - files'),
                         capture_output=True, timeout=600)
    raw = files_from_tar_bytes(tar.stdout)
    if raw:
        return raw
    # No tar on the device (or it failed): fall back to find + cat per file.
    listing = run_adb(serial, 'shell', f"run-as {VANILLA_PACKAGE} find files -type f -path '*/logs/*'")
    if listing.returncode != 0:
        return None
    pattern = re.compile(r'^files/([^/]+)/logs/([^/]+)$')
    raw = {}
    for line in listing.stdout.decode('utf-8', 'replace').splitlines():
        match = pattern.match(line.strip())
        if match is None:
            continue
        blob = subprocess.run(
            adb_command(serial, 'exec-out', f'run-as {VANILLA_PACKAGE} cat {shell_quote(line.strip())}'),
            capture_output=True, timeout=600)
        if blob.returncode == 0:
            raw[(match.group(1), match.group(2))] = blob.stdout
    return raw or None


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
        return (f"(this build targets SDK {info.get('target_sdk')} on Android {info.get('device_sdk')}, "
                'so Android strips its data from adb backup - root is required).')
    return '(the on-device prompt was probably cancelled, or this ROM disables adb backup).'


def extract_via_backup(serial: Optional[str], scratch: str,
                       info: Optional[Dict[str, object]] = None) -> Optional[RawFiles]:
    ab_path = os.path.join(scratch, 'vanilla-backup.ab')
    log('Requesting an app backup. ON THE PHONE NOW: unlock it, tap "Back up my data", and leave '
        'the password field EMPTY (a password encrypts the file so the importer cannot read it).')
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
    strategies = {'run-as': extract_via_run_as, 'root': extract_via_root,
                  'backup': lambda s: extract_via_backup(s, scratch, info)}
    order = [method] if method != 'auto' else auto_order(info)
    if method == 'auto' and not info.get('debuggable') and not backup_viable(info):
        log('Warning: this build is not debuggable and Android excludes its data from adb backup, '
            'so extraction needs root.')
    for name in order:
        log(f'Trying extraction via {name}...')
        raw = strategies[name](serial)
        if raw:
            log(f'Extracted {len(raw)} files via {name}.')
            return raw
        log(f'  {name} did not work'
            + (' (app not debuggable - this is a stock/store build)' if name == 'run-as' else
               ' (no root?)' if name == 'root' else ''))

    # Nothing worked - give guidance tuned to what the probe found.
    if not info.get('debuggable') and backup_viable(info):
        die('could not extract logs.\n'
            "  This is a store build (not debuggable), so run-as can't reach it, but adb backup\n"
            '  should work. Re-run and COMPLETE THE ON-DEVICE PROMPT: unlock the phone, tap\n'
            '  "Back up my data", and leave the password blank. If the prompt never appears, this\n'
            '  ROM disables adb backup - then you need root, or extract by other means and use\n'
            '  --from-dir/--from-tar/--from-ab.')
    if not info.get('debuggable'):
        die('could not extract logs.\n'
            f"  This build (targetSdk {info.get('target_sdk')}) is not debuggable and Android excludes\n"
            '  its data from adb backup, so without root the sandboxed logs are unreachable. Options:\n'
            '  root the device, or extract by other means and use --from-dir/--from-tar/--from-ab.\n'
            '  (A debuggable build only helps as a FRESH install - it cannot recover existing logs.)')
    die('could not extract logs from the device.\n'
        '  Options: root the device, complete the on-device adb backup prompt, or extract by\n'
        '  other means and use --from-dir/--from-tar/--from-ab.')


def files_from_dir(root: str) -> RawFiles:
    """Collect logs from an extracted directory (any nesting: it finds
    .../<Character>/logs/* wherever it sits)."""
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


def is_mergeable(m: object) -> bool:
    """The protocol's field bounds; out-of-bounds messages are skipped."""
    if not isinstance(m, dict):
        return False
    time, mtype, sender, text = m.get('time'), m.get('type'), m.get('sender'), m.get('text')
    return (isinstance(time, int) and not isinstance(time, bool) and 0 <= time <= MAX_TIME
            and isinstance(mtype, int) and not isinstance(mtype, bool) and 0 <= mtype <= 0xff
            and isinstance(sender, str) and len(sender.encode('utf-8')) <= 0xff
            and isinstance(text, str) and len(text.encode('utf-8')) <= 0xffff)


def build_store(raw: RawFiles, only_characters: Optional[List[str]]) -> Store:
    wanted = {c.lower() for c in only_characters} if only_characters else None
    grouped: Dict[str, Dict[str, Dict[str, bytes]]] = {}
    for (character, file_name), data in raw.items():
        if character in NON_CHARACTER_DIRS or character.startswith('.'):
            continue
        if wanted is not None and character.lower() not in wanted:
            continue
        key = file_name[:-len('.idx')] if file_name.endswith('.idx') else file_name
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
        log(f'Skipped {skipped_out_of_bounds} out-of-bounds messages (timestamps past 2038 etc.).')
    return {c: k for c, k in store.items() if k}


def build_sync_archive(store: Store) -> bytes:
    """The sync zip: the Horizon export format restricted to logs
    (mirrors Solstice mobile/sync/archive.ts buildSyncArchive)."""
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
            body = json.dumps(messages, ensure_ascii=False, separators=(',', ':'))
            entries.append((f'characters/{character}/logs/{key}.json', body.encode('utf-8')))
            if conversation['name']:
                names[key] = str(conversation['name'])
            any_logs = True
        if any_logs:
            names_body = json.dumps({k: names[k] for k in sorted(names)},
                                    ensure_ascii=False, separators=(',', ':'))
            entries.append((f'characters/{character}/logs-names.json', names_body.encode('utf-8')))
            included.append(character)

    manifest = {
        'version': 2,
        'createdAt': datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
        'app': 'horizon',
        'expectedFiles': len(entries),
        'characters': included,
        'includes': {
            'generalSettings': False, 'logs': True, 'drafts': False, 'characterSettings': False,
            'pinned': False, 'eicons': False, 'recents': False, 'hidden': False, 'jsonLogs': True
        }
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        zf.writestr('manifest.json', json.dumps(manifest, indent=2))  # must be the first entry
        for name, data in entries:
            zf.writestr(name, data)
    return buffer.getvalue()


def is_safe_segment(segment: str) -> bool:
    return (0 < len(segment.encode('utf-8')) <= 255
            and not segment.startswith('.') and '\0' not in segment)


def compute_merge_stats(upload: bytes, store: Store) -> Dict[str, int]:
    """What the phone's upload would add to this store, with the protocol's
    merge semantics (mirrors mobile/sync/archive.ts mergeLogs). Nothing is
    persisted; the numbers feed the POST /v1/logs response the phone displays."""
    stats = {'conversationsCreated': 0, 'conversationsUpdated': 0, 'messagesAdded': 0, 'charactersTouched': 0}
    try:
        zf = zipfile.ZipFile(io.BytesIO(upload))
    except zipfile.BadZipFile:
        return stats
    touched = set()
    with zf:
        for entry in zf.namelist():
            segments = entry.replace('\\', '/').split('/')
            if (len(segments) != 4 or segments[0] != 'characters' or segments[2] != 'logs'
                    or not segments[3].endswith('.json')):
                continue
            character = segments[1]
            key = segments[3][:-len('.json')].lower()
            if not is_safe_segment(character) or not is_safe_segment(key) or key.endswith('.idx'):
                continue
            if character in NON_CHARACTER_DIRS:
                continue
            try:
                parsed = json.loads(zf.read(entry).decode('utf-8'))
            except (ValueError, UnicodeDecodeError):
                continue
            if not isinstance(parsed, list):
                continue
            existing = store.get(character, {}).get(key, {}).get('messages', [])
            seen = {dedupe_key(m) for m in existing}
            added = 0
            for m in parsed:
                if not is_mergeable(m):
                    continue
                k = dedupe_key(m)
                if k in seen:
                    continue
                seen.add(k)
                added += 1
            if added == 0:
                continue
            stats['messagesAdded'] += added
            if existing:
                stats['conversationsUpdated'] += 1
            else:
                stats['conversationsCreated'] += 1
            touched.add(character)
    stats['charactersTouched'] = len(touched)
    return stats


# ---------------------------------------------------------------------------
# Sync protocol crypto: every non-empty body is IV(12) || ciphertext || tag(16)
# ---------------------------------------------------------------------------

def load_aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        die('the "cryptography" package is required (pacman -S python-cryptography / pip install cryptography)')
    return AESGCM


def encrypt_body(key: bytes, plain: bytes) -> bytes:
    iv = secrets.token_bytes(SYNC_IV_LENGTH)
    return iv + load_aesgcm()(key).encrypt(iv, plain, None)


def decrypt_body(key: bytes, data: bytes) -> bytes:
    if len(data) < SYNC_IV_LENGTH + SYNC_TAG_LENGTH:
        raise ValueError('body too short')
    return load_aesgcm()(key).decrypt(data[:SYNC_IV_LENGTH], data[SYNC_IV_LENGTH:], None)


# ---------------------------------------------------------------------------
# The Device Sync server (desktop side of the protocol)
# ---------------------------------------------------------------------------

class SyncServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, bind_port: int, account: str, archive: bytes, store: Store,
                 save_upload: Optional[str]):
        super().__init__(('', bind_port), SyncHandler)
        self.token = secrets.token_hex(32)
        self.key = secrets.token_bytes(SYNC_KEY_LENGTH)
        self.account = account
        self.archive = archive
        self.store = store
        self.save_upload = save_upload
        self.device_name = socket.gethostname() or 'importer'
        self.lock = threading.Lock()
        self.state = 'waiting'                  # waiting -> paired -> finished
        self.done = threading.Event()
        self.sent_stats: Optional[Dict[str, int]] = None


class SyncHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    timeout = 300
    server: SyncServer

    def log_message(self, *_args) -> None:      # silence the default access log
        pass

    def _read_body(self) -> bytes:
        length = int(self.headers.get('Content-Length') or 0)
        return self.rfile.read(length) if length > 0 else b''

    def _respond(self, status: int, body: bytes = b'') -> None:
        self.send_response(status)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _respond_json(self, status: int, payload: dict) -> None:
        plain = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        self._respond(status, encrypt_body(self.server.key, plain))

    def _handle(self, method: str) -> None:
        body = self._read_body()
        path = self.path.split('?')[0]

        with self.server.lock:
            state = self.server.state
        if state == 'finished':
            return self._respond_json(410, {'error': 'session-ended'})

        auth = self.headers.get('Authorization') or ''
        presented = auth[len('Bearer '):] if auth.startswith('Bearer ') else ''
        if not hmac.compare_digest(presented, self.server.token):
            return self._respond(401)           # no session proof, no encrypted channel

        route = f'{method} {path}'
        if route == 'POST /v1/handshake':
            return self._handshake(body)
        if route == 'GET /v1/logs':
            if state != 'paired':
                return self._respond_json(409, {'error': 'not-paired'})
            log(f'  -> sending the converted log archive ({len(self.server.archive)} bytes zipped)...')
            return self._respond(200, encrypt_body(self.server.key, self.server.archive))
        if route == 'POST /v1/logs':
            if state != 'paired':
                return self._respond_json(409, {'error': 'not-paired'})
            return self._upload(body)
        if route == 'POST /v1/finish':
            if state != 'paired':
                return self._respond_json(409, {'error': 'not-paired'})
            with self.server.lock:
                self.server.state = 'finished'
            self._respond_json(200, {'ok': True})
            self.server.done.set()
            return
        return self._respond_json(404, {'error': 'not-found'})

    def _handshake(self, body: bytes) -> None:
        with self.server.lock:
            if self.server.state != 'waiting':
                return self._respond_json(409, {'error': 'already-paired'})
        try:
            hello = json.loads(decrypt_body(self.server.key, body).decode('utf-8'))
            account = hello['account']
        except (ValueError, KeyError, TypeError):
            return self._respond_json(400, {'error': 'bad-handshake'})
        if not isinstance(account, str) or account.lower() != self.server.account.lower():
            return self._respond_json(403, {'error': 'account-mismatch'})
        with self.server.lock:
            self.server.state = 'paired'
        device = hello.get('deviceName') or 'unknown device'
        log(f'Phone connected: {device} ({hello.get("platform", "?")}, app {hello.get("appVersion", "?")})')
        return self._respond_json(200, {
            'ok': True, 'deviceName': self.server.device_name,
            'account': self.server.account, 'protocolVersion': SYNC_PROTOCOL_VERSION
        })

    def _upload(self, body: bytes) -> None:
        try:
            upload = decrypt_body(self.server.key, body)
        except ValueError:
            return self._respond_json(400, {'error': 'bad-upload'})
        if self.server.save_upload:
            with open(self.server.save_upload, 'wb') as f:
                f.write(upload)
            log(f'  <- saved the phone\'s uploaded log archive to {self.server.save_upload}')
        stats = compute_merge_stats(upload, self.server.store)
        with self.server.lock:
            self.server.sent_stats = stats
        log(f'  <- received the phone\'s logs ({len(upload)} bytes): {stats["messagesAdded"]} messages '
            f'across {stats["conversationsCreated"] + stats["conversationsUpdated"]} conversations '
            f'would be new to this export (upload is {"saved" if self.server.save_upload else "discarded"}).')
        return self._respond_json(200, {'ok': True, **stats})

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
    aesgcm = load_aesgcm()

    # Known-answer vector pinning the wire framing (Solstice crypto.test.ts /
    # McGrew-Viega AES-256-GCM test case 15, 60-byte plaintext, no AAD).
    key = bytes.fromhex('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308')
    iv = bytes.fromhex('cafebabefacedbaddecaf888')
    plain = bytes.fromhex('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72'
                          '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39')
    expected = bytes.fromhex('cafebabefacedbaddecaf888522dc1f099567d07f47f37a32a84427d643a8cdc'
                             'bfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e63'
                             '93ba7a0abcc9f662eb9f796c8d356fc31a8433884b696f4f')
    assert iv + aesgcm(key).encrypt(iv, plain, None) == expected, 'AES-GCM framing KAT failed'
    assert decrypt_body(key, expected) == plain, 'AES-GCM decrypt KAT failed'
    assert decrypt_body(key, encrypt_body(key, b'')) == b'', 'empty body round trip failed'

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
    stats = compute_merge_stats(upload_buffer.getvalue(), store)
    assert stats == {'conversationsCreated': 1, 'conversationsUpdated': 1,
                     'messagesAdded': 2, 'charactersTouched': 2}, f'merge stats wrong: {stats}'

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

    # App-info probe parsing (dumpsys package output): a debuggable side-load and a stock build.
    debuggable = parse_app_info(
        'Packages:\n  Package [net.f_list.fchat] (abc):\n'
        '    versionCode=99 minSdk=21 targetSdk=34\n    versionName=3.0.16-debug\n'
        '    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP DEBUGGABLE ]\n')
    assert debuggable == {'version_name': '3.0.16-debug', 'version_code': 99, 'target_sdk': 34,
                          'debuggable': True, 'allow_backup': True, 'probed': True}, debuggable
    stock = parse_app_info(
        'Packages:\n  Package [net.f_list.fchat] (def):\n'
        '    versionCode=27 minSdk=21 targetSdk=30\n    versionName=3.0.15\n'
        '    pkgFlags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]\n')
    assert stock == {'version_name': '3.0.15', 'version_code': 27, 'target_sdk': 30,
                     'debuggable': False, 'allow_backup': True, 'probed': True}, stock
    assert parse_app_info('')['probed'] is False, 'empty dumpsys must read as unprobed'

    # backup_viable: excluded only when a modern-target app meets a modern device.
    assert backup_viable({'probed': True, 'allow_backup': True, 'target_sdk': 30, 'device_sdk': 34})
    assert not backup_viable({'probed': True, 'allow_backup': True, 'target_sdk': 34, 'device_sdk': 34})
    assert backup_viable({'probed': True, 'allow_backup': True, 'target_sdk': 34, 'device_sdk': 30})
    assert not backup_viable({'probed': True, 'allow_backup': False, 'target_sdk': 30, 'device_sdk': 34})
    assert backup_viable({'probed': False, 'allow_backup': False}), 'unknown app must stay optimistic'

    # auto_order picks a strategy sequence from those capabilities.
    assert auto_order({**debuggable, 'device_sdk': 34}) == ['run-as', 'root', 'backup']
    assert auto_order({**stock, 'device_sdk': 34}) == ['backup', 'root']
    assert auto_order({'probed': True, 'debuggable': False, 'allow_backup': True,
                       'target_sdk': 34, 'device_sdk': 34}) == ['root', 'backup']

    log('All self-tests passed.')


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
        description='Extract vanilla F-Chat Android logs via ADB, convert them to the Horizon '
                    'format, and serve them to Solstice through Device Sync (QR code).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='In Solstice: Data Manager -> Device Sync -> Scan QR code (or Enter code manually).\n'
               'Both devices must be on the same Wi-Fi network.')
    source = parser.add_argument_group('source (default: extract from the device via ADB)')
    source.add_argument('-s', '--serial', help='ADB device serial (when several devices are connected)')
    source.add_argument('--method', choices=['auto', 'run-as', 'root', 'backup'], default='auto',
                        help='ADB extraction strategy (default: try them in order)')
    source.add_argument('--from-dir', metavar='DIR', help='convert an already-extracted directory instead of ADB')
    source.add_argument('--from-tar', metavar='FILE', help='convert an extracted tar instead of ADB')
    source.add_argument('--from-ab', metavar='FILE', help='convert an existing `adb backup` .ab file instead of ADB')
    convert = parser.add_argument_group('conversion')
    convert.add_argument('--character', action='append', metavar='NAME',
                         help='only include this character (repeatable, case-insensitive)')
    convert.add_argument('--out', metavar='FILE',
                         help='also write the converted Horizon export zip to this path')
    convert.add_argument('--dry-run', action='store_true', help='extract and convert only; do not serve')
    serve = parser.add_argument_group('device sync')
    serve.add_argument('--account', help='your F-List account name (the login name, not a character); '
                                         'must match the account signed in on Solstice; prompted if omitted')
    serve.add_argument('--port', type=int, default=0, help='listen port (default: random)')
    serve.add_argument('--addr', action='append', metavar='IP',
                       help='advertise this LAN address in the QR code (repeatable; default: autodetect)')
    serve.add_argument('--qr-png', metavar='FILE', help='also save the QR code as a PNG')
    serve.add_argument('--save-upload', metavar='FILE',
                       help='save the log archive Solstice uploads back (default: discard)')
    parser.add_argument('--self-test', action='store_true', help='run internal format/crypto tests and exit')
    parser.add_argument('--no-bootstrap', action='store_true',
                        help='never auto-install missing Python packages into ~/.cache/vanilla-importer')
    args = parser.parse_args()

    if not args.no_bootstrap:
        ensure_python_deps()
    if args.self_test:
        return self_test()
    load_aesgcm()                               # fail early if cryptography is missing
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
        import tempfile
        with tempfile.TemporaryDirectory(prefix='vanilla-import-') as scratch:
            raw = extract_from_device(args.serial, args.method, scratch)
    if not raw:
        die('no log files found in the source')

    # 2. Convert.
    store = build_store(raw, args.character)
    if not store:
        die('no messages survived conversion (empty logs, or --character filtered everything out)')
    summarize(store)
    archive = build_sync_archive(store)
    log(f'Horizon export archive: {len(archive)} bytes zipped.')
    if args.out:
        with open(args.out, 'wb') as f:
            f.write(archive)
        log(f'Wrote {args.out} (importable via Horizon\'s Data Manager as well).')
    if args.dry_run:
        return

    # 3. Serve device sync.
    server = SyncServer(args.port, args.account, archive, store, args.save_upload)
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
    log('Waiting for the phone (Ctrl+C to abort)...')

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        server.done.wait()
    except KeyboardInterrupt:
        log('\nAborted.')
        server.shutdown()
        sys.exit(130)
    server.shutdown()
    log('')
    log('Sync complete. The imported messages appear the next time you open those logs in Solstice.')
    if server.sent_stats and server.sent_stats['messagesAdded'] > 0 and not args.save_upload:
        log('Note: the phone also uploaded its own logs (two-way protocol); they were discarded here.')
        log('Re-run with --save-upload FILE if you want to keep them next time.')


if __name__ == '__main__':
    main()
