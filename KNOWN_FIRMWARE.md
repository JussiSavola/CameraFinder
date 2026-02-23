# Known Firmware Behaviours

This document records non-standard and RFC-violating RTSP behaviours observed during real-world testing of IP cameras. Each entry describes what the firmware does, why it breaks naive scanners, and how CameraFinder handles it.

Contributions welcome — if you encounter a camera with unusual behaviour, open an issue or PR with the details.

---

## JOOAN / ANRAN (and clones)

**Identified cameras:** JOOAN JA-B7G2E and similar models  
**RTSP port:** 554  
**Stream paths:** `/live/ch00_0` (main), `/live/ch00_1` (substream)  
**Default credentials:** `admin/admin123`, sometimes also `admin/123456` (see note below)  
**Realm:** `ipc`  
**Media server:** LIVE555

### Quirk 1 — 461 Unsupported Transport on root path

```
DESCRIBE rtsp://192.168.1.x:554/ RTSP/1.0
→ RTSP/1.0 461 Unsupported Transport
```

The root path `/` returns 461, which is an RTSP error code normally associated with `SETUP` requests (transport negotiation), not `DESCRIBE`. This suggests the firmware is misidentifying the request type. It is not a valid path and should be ignored.

**Impact:** Scanners that probe `/` first and interpret any response as "camera found" may then waste the connection budget before reaching real paths.

**Handling:** CameraFinder probes `/live/ch00_0` before `/` to ensure the real path is checked while the camera is still responsive.

---

### Quirk 2 — One response per TCP connection

After sending any RTSP response (including 401), the camera closes the TCP connection. This means the standard Digest auth flow — get challenge on CSeq 1, send credentials on CSeq 2, all on one connection — only works if both requests are sent before the camera processes and closes.

In practice, the two-request same-connection approach works reliably because the camera processes them sequentially before closing. However, if the first request gets a response and the camera has already closed by the time the second is sent, you will get an empty response or OSError.

**Impact:** Scanners that open a fresh TCP connection to get a nonce and then open another fresh connection to send the auth will find that the nonce is valid — JOOAN nonces are not tied to TCP sessions — but the second connection may hit the rate limiter (see Quirk 3).

**Handling:** CameraFinder sends both CSeq 1 and CSeq 2 on the same connection. If that fails, it falls back to two separate connections with a delay between them.

---

### Quirk 3 — Connection rate limiting

The firmware enforces a limit on how many TCP connections it will accept within a short time window. When the limit is exceeded, subsequent connections are accepted but receive no response — the socket stays open but the camera sends nothing.

This is the most insidious quirk because it is indistinguishable from "path does not exist" if you are not aware of it. A scanner that fires 30 path probes in rapid succession will hit the rate limiter by the 3rd or 4th probe and conclude the camera has no valid paths.

**Observed behaviour:**
- First 1–2 connections: normal responses
- Subsequent connections within ~1–2 seconds: silent (no response, no close)
- After ~2 seconds of quiet: camera becomes responsive again

**Impact:** Path discovery fails. Credential brute-forcing fails. Camera appears unresponsive.

**Handling:** CameraFinder adds 100ms delay between Phase 1 path probes and 300ms between Phase 2 credential attempts, plus a 2 second pause before starting credential probing on each camera.

---

### Quirk 4 — Multiple valid passwords simultaneously

Some JOOAN cameras ship with `admin/123456` as a factory default and accept it even after the admin password has been changed to something else. Both passwords authenticate successfully as the same user against the same streams.

This is not a backdoor in the traditional sense — it appears to be a firmware bug where changing the password creates a new credential entry rather than replacing the old one.

**Security implication:** If you set `admin/admin123` on your camera but never explicitly changed or removed the factory default, `admin/123456` (or other common defaults) may still work. Log into the web UI, check the user account list, and remove any accounts you did not create.

**Detection:** CameraFinder will report whichever credential it finds first. If your wordlist contains `admin123` as the first entry, that will be found before `123456`. Running the scanner with a comprehensive wordlist will reveal all valid credentials.

---

## Hikvision-clone (rtsp_demo firmware)

**Identified cameras:** Various unbranded cameras with `Server: rtsp_demo`  
**RTSP port:** 8554  
**Stream paths:** `/Streaming/Channels/101` (main), `/Streaming/Channels/102` (substream)  
**Default credentials:** `admin/admin`, sometimes `root/admin`  
**Realm:** varies

These cameras run a minimal RTSP server identifying itself as `rtsp_demo`. They behave much more RFC-compliant than JOOAN firmware — standard Digest challenge-response works on a single connection, no rate limiting observed, root path `/` returns a valid (if unhelpful) response.

The username is not always `admin` — `root/admin` has been observed. CameraFinder tries both.

---

## General Notes

### Digest auth without qop

Many cheap cameras send a WWW-Authenticate header without a `qop` parameter:

```
WWW-Authenticate: Digest realm="ipc", nonce="abc123"
```

The response hash formula differs depending on whether `qop` is present:

**Without qop:**
```
HA1 = MD5(username:realm:password)
HA2 = MD5(method:uri)
response = MD5(HA1:nonce:HA2)
```

**With qop=auth:**
```
HA1 = MD5(username:realm:password)
HA2 = MD5(method:uri)
response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
```

Many implementations only handle one or the other. CameraFinder handles both.

---

### Nonce validity

JOOAN firmware nonces are **not** tied to the TCP session — a nonce obtained on connection A is valid when presented on connection B. This is technically correct RFC behaviour (nonces are server-generated tokens, not session tokens), but it means the two-connection fallback approach works.

Some other firmware (not yet documented here) ties nonces to TCP sessions, meaning a nonce obtained on a closed connection cannot be reused. If you encounter this, the only approach is to get a fresh nonce on the same connection you intend to use for authentication.

---

*Last updated: February 2026*  
*Tested network: mix of JOOAN, ANRAN, and Hikvision-clone cameras on a home LAN*
