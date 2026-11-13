# importer

Imports chat logs from the **vanilla F-Chat 3.0 Android app** (`net.f_list.fchat`) into **Solstice** (`../Solstice`), which cannot read them itself because Android sandboxes each app's data.

`import_vanilla_logs.py` does the whole trip in one run:

1. **Extract** the binary logs off the device with ADB: `adb backup`, or root. Every released build of the app (store or direct APK) targets SDK 27 or lower, so `adb backup` still includes its logs on current Android; confirm the on-device backup prompt within a minute (it times out) by tapping "Back up my data" with the password left empty. A build targeting SDK 31+ is excluded from backups on Android 12+ and needs root; the script probes the install (`dumpsys package`) and picks the order accordingly.
2. **Convert** them to the Horizon export format v2 restricted to logs (`../Horizon/docs/export-format.md`) - the vanilla binary record layout is byte-identical to Horizon/Solstice, so this is a binary -> JSON-zip decode.
3. **Serve** the desktop side of the Horizon Device Sync protocol (spec: `../Horizon/docs/log-sync-protocol.md`; reference server: `../Horizon/electron/services/sync/`) on the LAN and show the QR code; in Solstice 2026.10.0 or later, tap Device sync on the sign-in screen and scan it. Logs go to the phone in bounded batches (16 MiB of JSON each, `GET /v1/logs?cursor=`), so the phone never has to merge the whole log set at once; a client that predates batching still gets one archive. The session limits match Horizon's: the code expires after 10 minutes without a handshake, a paired session ends after 5 idle minutes, and 5 failed authentications close it.

```sh
./import_vanilla_logs.py    # asks for your F-List account name, or pass --account
```

Useful flags: `--dry-run --out logs.zip` (convert only; the zip also imports through Horizon's Manage Data), `--from-dir/--from-tar/--from-ab` (skip ADB), `--character NAME` (filter), `--qr-png qr.png`, `--save-upload phone.zip` (keep the logs Solstice uploads back, joined into one archive however many batches it sent; discarded by default), `--self-test`. `HORIZON_SYNC_BATCH_BYTES=20000` shrinks the batch budget, as it does for Horizon, to exercise multi-batch transfers with a small log set.

Requires Python 3.9+ and `adb`. AES-GCM uses the `cryptography` package when it is installed, else the OpenSSL that ships inside Python itself, so nothing has to be compiled on any platform (current `cryptography` releases have no wheels for Windows on ARM or 32-bit Windows). `qrcode` installs itself on first run into a private venv under `~/.cache/vanilla-importer/` when the `qrencode` CLI is absent (disable with `--no-bootstrap`); a venv broken by a Python upgrade is rebuilt automatically. The script also carries PEP 723 metadata, so `uv run import_vanilla_logs.py` works too. Without any QR renderer, or offline, paste the printed sync code into Solstice's "Enter code manually".

**Windows:** run it from PowerShell or Command Prompt as `py -3 import_vanilla_logs.py` (on a fresh install `python3` is often only the Microsoft Store placeholder, and the explicit `-3` keeps the launcher from acting on the script's Unix shebang). `adb` comes from Google's SDK Platform-Tools; the script also finds the copy Android Studio installs under `%LOCALAPPDATA%\Android\Sdk`. Some phones need their manufacturer's USB driver before `adb devices` lists them. The phone connects in to the PC, so when Windows Defender Firewall asks whether Python may communicate on networks, allow it, and tick Public too if the Wi-Fi is set to Public.

Verified against Solstice's real sync client (`mobile/sync/client.ts` driven by Node against this server, with batched transfers in both directions, on both AES-GCM backends), the AES-256-GCM known-answer vector from `crypto.test.ts`, and `zbarimg` decoding of the generated QR.
