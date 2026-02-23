# IP Camera Scanner v2

A Python tool for discovering and identifying IP cameras on your local network. Finds cameras, probes RTSP stream paths, and attempts to recover credentials — including on cameras with non-standard or RFC-violating firmware.

Built through real-world testing against a heterogeneous collection of cheap Chinese cameras (JOOAN, ANRAN, Hikvision-clone, and others), so it handles the firmware quirks that most scanners don't.

---

## Features

- **Network scan** — parallel port scanning across 254 hosts (~5 seconds)
- **ONVIF WS-Discovery** — multicast probe to find cameras that announce themselves
- **RTSP stream detection** — probes 31 known stream paths per camera
- **Credential list-forcing** — built-in defaults + your own wordlist
- **Smart auth handling** — supports Digest (with/without qop) and Basic auth
- **Firmware-aware probing** — handles cameras that:
  - Close TCP connections after every response
  - Return 461 on root path instead of 404
  - Rate-limit rapid connection attempts
  - Stay silent until credentials are sent upfront
- **Blocklist** — automatically excludes Unifi, Shelly, Synology, and other non-camera devices
- **ONVIF credential probing** — tries credentials against ONVIF device service (returns manufacturer/model)
- **Ready-to-use output** — VLC and ffmpeg command lines for every confirmed stream

---

## Requirements

```bash
pip install requests
```

Python 3.8+ required. No other dependencies — RTSP probing uses raw sockets.

---

## Quick Start

```bash
python ip_camera_scanner.py
```

This scans `192.168.1.x` with default settings. Most home networks will work with no arguments.

---

## Usage

```bash
python ip_camera_scanner.py [options]
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--network` | `192.168.1` | Network prefix to scan (e.g. `192.168.0`) |
| `--timeout` | `0.8` | Seconds per connection attempt. Use `2.0` for WiFi cameras |
| `--workers` | `60` | Parallel scan threads |
| `--wordlist` | — | Path to optional password file (see format below) |
| `--wordlist-only` | — | Skip built-in defaults, use only your wordlist |
| `--user` | — | Username for wordlist entries without `user:pass` format |
| `--top` | `20` | Max number of candidates to probe credentials on |
| `--skip-creds` | — | Skip credential probing entirely |
| `--skip-onvif` | — | Skip ONVIF WS-Discovery multicast probe |

### Examples

```bash
# Basic scan with defaults
python ip_camera_scanner.py

# Slower timeout for WiFi cameras, with your own passwords
python ip_camera_scanner.py --timeout 2.0 --wordlist passwords.txt --user admin

# Different subnet
python ip_camera_scanner.py --network 192.168.0

# Wordlist only — skip the built-in 22 defaults
python ip_camera_scanner.py --wordlist passwords.txt --wordlist-only --user admin
```

---

## Wordlist Format

One entry per line. Either a bare password (username supplied via `--user` or tried as common names), or an explicit `user:password` pair:

```
# passwords only — will try admin, root, user, guest as username
admin123
mypassword
supersecret

# explicit user:password pairs
admin:mypassword
operator:op1234
root:toor
```

Wordlist entries are tried **before** the built-in defaults, so your known passwords are found quickly.

---

## Diagnostic Tools

Two helper scripts are included for debugging cameras that the scanner can't crack.

### `debug_rtsp.py` — RTSP Auth Debugger

Tests a single camera path with a single credential, printing every byte of the RTSP exchange and showing exactly how the Digest hash is computed.

```bash
python debug_rtsp.py --ip 192.168.7.148 --port 554 --path /live/ch00_0 --user admin --password admin123

# Test Basic auth sent upfront (no challenge-response)
python debug_rtsp.py --ip 192.168.8.234 --port 554 --path /live/ch00_0 --user admin --password admin123 --preauth
```

### `rtsp_paths_probe.py` — Path Existence Prober

Probes all 32 known RTSP paths on a camera without credentials, showing which paths exist (401), which don't (404 or silence), and diagnosing firmware behaviour.

```bash
python rtsp_paths_probe.py --ip 192.168.9.148 --port 554
```

Useful for understanding why a camera shows `nopaths` — some firmware returns 401 for everything, others return silence, others return non-standard codes like 461.

### `debug_phase2.py` — Credential Loop Debugger

Simulates exactly what the scanner's Phase 2 credential loop does for a single camera and credential, with verbose output at every step. Use this when the scanner reports `no default credentials worked` but you know the password is correct.

```bash
python debug_phase2.py --ip 192.168.1.148 --port 554 --path /live/ch00_0 --user admin --password admin123
```

---

## Output

```
🎥  LIKELY CAMERAS  (9 found)

┌─ IP: 192.168.10.148  (score: 78)
│  Ports   : 80/HTTP, 443/HTTPS, 554/RTSP
│  RTSP    : Port 554 path '/live/ch00_0': RTSP OK
│  Web UI  : http://192.168.10.148:80/
│  ✔ RTSP confirmed on :554 path /live/ch00_0
│  ✔ Responded to ONVIF WS-Discovery
│  🔑 RTSP: user='admin' pass='admin' → rtsp://admin:admin@192.168.10.148:554/live/ch00_0
└───────────────────────────────────────────────────────

QUICK ACCESS URLS

── 192.168.1.148 ────────────────────────────────
  ✅ CONFIRMED STREAM  →  rtsp://admin:admin123@192.168.1.148:554/live/ch00_0
     VLC  : vlc "rtsp://admin:admin123@192.168.1.148:554/live/ch00_0"
     ffmpeg: ffmpeg -rtsp_transport tcp -i "rtsp://admin:admin@192.168.1.148:554/live/ch00_0" ...
```

---

## Firmware Quirks Handled

This scanner was developed against cameras that exhibit the following non-RFC behaviour:

| Behaviour | Cameras | Handling |
|-----------|---------|----------|
| One TCP response then close | JOOAN, ANRAN | Reconnects transparently, retries same path |
| 461 on DESCRIBE `/` | JOOAN firmware | `/live/ch00_0` probed first to avoid wasting the connection slot |
| Rate-limits rapid connections | JOOAN, others | Delays between Phase 1 probes and Phase 2 attempts |
| Silent on unauthenticated requests | Some JOOAN | Basic auth sent upfront as fallback |
| Digest without qop | Most cheap cameras | Both qop and non-qop Digest computed correctly |
| Nonce tied to TCP connection | JOOAN firmware | Fresh connection per credential attempt |

---

## Scoring System

Candidates are ranked by confidence score:

| Signal | Points |
|--------|--------|
| RTSP confirmed (stream responds) | +40 |
| Camera keywords in HTTP response | +30 |
| ONVIF WS-Discovery response | +35 |
| Port 34567 open (Chinese DVR) | +25 |
| Port 37777 open (Dahua) | +20 |
| Port 8000 open (Hikvision SDK) | +10 |
| Port 9527 open (Chinese IPC) | +15 |
| Port 554/8554 open (RTSP, unconfirmed) | +10 |

Devices scoring below 20 are shown as low-confidence. Devices matching the blocklist (Unifi, Shelly, Synology, nginx, Apache) are excluded entirely.

---

## Security Note

If the scanner finds a credential you didn't set — for example `admin/123456` on a camera you configured with a different password — this means the camera has a **factory default password that was never removed**. If possible, log into the camera's web UI, check the user account list, and remove or change any accounts you didn't create.

Cheap Chinese camera firmware commonly ships with multiple valid credentials simultaneously. Changing the admin password does not automatically invalidate the factory default.

Note: If you can not delete or change the factory passwords, you have an open security hole in you network. Please consider firewalling the camera(s).

---

## Limitations

- Only scans `/24` networks (254 hosts)
- RTSP credential probing can take several minutes on large networks with many cameras due to rate-limit delays
- Some cameras use completely non-standard stream paths not in the built-in list — use `rtsp_paths_probe.py` to investigate, then add the path to your wordlist as `user:password` won't help; you'd need to add the path to `RTSP_PATHS` in the source
- ONVIF credential probing requires the `requests` library

---

## License

Do whatever you want with it. Just don't use it on networks you don't own. Commercial reuse prohibited.
