# importer

Imports chat logs from the **vanilla F-Chat 3.0 Android app** (`net.f_list.fchat`, `../chat3clientForAndroid`) into **Solstice** (`../Solstice`), which cannot read them itself because Android sandboxes each app's data.

`import_vanilla_logs.py` does the whole trip in one run:

1. **Extract** the binary logs off the device with ADB (`run-as` for debuggable builds -> root -> `adb backup`, first that works). Store builds (Amazon/Google Play) ship non-debuggable, so `run-as` can't reach them; the script probes the install (`dumpsys package`) and steers to `adb backup`, which still captures logs from older builds - but not a current targetSdk-34 build on Android 12+ without root. Confirm the on-device backup prompt with an empty password.
2. **Convert** them to the Horizon export format v2 restricted to logs (`../Horizon/docs/export-format.md`) - the vanilla binary record layout is byte-identical to Horizon/Solstice, so this is a binary -> JSON-zip decode.
3. **Serve** the desktop side of the Horizon Device Sync protocol (`../Solstice/mobile/sync/`) on the LAN and show the QR code; scan it in Solstice via Data Manager -> Device Sync.

```sh
./import_vanilla_logs.py    # asks for your F-List account name, or pass --account
```

Useful flags: `--dry-run --out logs.zip` (convert only; the zip also imports through Horizon's Data Manager), `--from-dir/--from-tar/--from-ab` (skip ADB), `--character NAME` (filter), `--qr-png qr.png`, `--save-upload phone.zip` (keep the logs Solstice uploads back; discarded by default), `--self-test`.

Requires `python3` and `adb`; the Python dependencies (`cryptography`, and `qrcode` when the `qrencode` CLI is absent) install themselves on first run into a private venv under `~/.cache/vanilla-importer/` (disable with `--no-bootstrap`). The script also carries PEP 723 metadata, so `uv run import_vanilla_logs.py` works too. Without any QR renderer, paste the printed sync code into Solstice's "Enter code manually".

Verified against Solstice's real sync client (`mobile/sync/client.ts` driven by Node against this server), the AES-256-GCM known-answer vector from `crypto.test.ts`, and `zbarimg` decoding of the generated QR.
