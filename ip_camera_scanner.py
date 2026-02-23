#!/usr/bin/env python3
"""
IP Camera Scanner v2
--------------------
Improvements over v1:
  - Device blocklist (Unifi, Shelly, routers, NAS, printers, etc.)
  - Wider port coverage including UDP RTSP
  - Smarter RTSP probing with common stream paths
  - Default credential brute-force on HTTP and RTSP
  - ONVIF WS-Discovery + ONVIF auth probe

Usage:
    pip install requests
    python ip_camera_scanner_v2.py

    Options:
    --network 192.168.1     subnet prefix (default: 192.168.1)
    --timeout 1.0           socket timeout in seconds
    --workers 60            parallel threads
    --skip-onvif            skip multicast discovery
    --skip-creds            skip credential probing
    --top N                 only probe creds on top N candidates (default: 20)
"""

import argparse
import concurrent.futures
import re
import socket
import sys
import time
import threading

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("[!] 'requests' not found. HTTP probing limited. Run: pip install requests\n")

# ─────────────────────────────────────────────────────────────────────
#  BLOCKLIST — page titles / server headers that mean NOT a camera
# ─────────────────────────────────────────────────────────────────────
BLOCKLIST_TITLE = [
    "unifi", "ubiquiti", "edgeos", "edgeswitch",
    "shelly", "sonoff",
    "fritz", "fritzbox",
    "synology", "qnap", "nas",
    "mikrotik", "routeros",
    "openwrt", "dd-wrt", "tomato",
    "plex", "home assistant", "homeassistant",
    "pihole", "pi-hole",
    "proxmox", "esxi", "vmware",
    "samsung", "lg webos",
    "printer", "hp laserjet", "brother",
    "cisco", "linksys", "netgear", "asus router",
    "tplink", "tp-link",
    "nginx", "apache", "iis",   # generic web servers — very unlikely cameras
]

BLOCKLIST_SERVER = [
    "unifi", "ubnt",
    "shellyhttp",
    "synology",
    "mikrotik",
    "apache", "nginx",          # real cameras almost never run Apache/nginx
    "lighttpd",                 # debatable — some cameras do use it, but rare
    "microsoft-iis",
    "jetty", "tomcat",
]

# ─────────────────────────────────────────────────────────────────────
#  CAMERA SIGNALS
# ─────────────────────────────────────────────────────────────────────
CAMERA_PORTS = {
    80:    "HTTP",
    8080:  "HTTP-alt",
    8081:  "HTTP-alt2",
    443:   "HTTPS",
    8443:  "HTTPS-alt",
    554:   "RTSP",
    8554:  "RTSP-alt",
    34567: "DVR-Chinese",
    37777: "Dahua",
    9527:  "Chinese-IPC",
    1935:  "RTMP",
    5000:  "Synology-or-cam",  # some cameras use 5000 for HTTP
    8000:  "Hikvision-SDK",    # Hikvision SDK port
}

CAMERA_KEYWORDS_BODY = [
    "ipcamera", "ipc", "ip camera", "ip-camera",
    "dvr", "nvr", "netcam", "webcam", "network camera",
    "video server", "ipcam", "cctv", "surveillance",
    "hikvision", "dahua", "reolink", "foscam", "axis",
    "amcrest", "annke", "uniview", "tiandy",
    "h.264", "h.265", "h264", "h265",
    "onvif",
    "live view", "liveview", "live stream",
    "ptz", "pan tilt",
]

CAMERA_SERVER_HEADERS = [
    "boa", "ipcamera", "mini_httpd", "alphapd",
    "crossweb", "goahead", "thttpd",
    "rtsp", "camera", "ipc-server",
    "hikvision", "dahua",
]

# RTSP paths to try (ordered by likelihood for cheap Chinese cameras)
# IMPORTANT: /live/ch00_0 must come BEFORE "/" because some cameras
# rate-limit after the first response. "/" often returns 461 (firmware bug)
# which wastes the one free connection slot before we try the real path.
RTSP_PATHS = [
    "/live/ch00_0",         # JOOAN, ANRAN, many cheap Chinese cameras (main stream) — FIRST
    "/live/ch00_1",         # JOOAN substream
    "/Streaming/Channels/101",  # Hikvision / Hikvision-clone
    "/",
    "/live/ch00_1",         # JOOAN substream
    "/live/ch01_0",
    "/Streaming/Channels/101",  # Hikvision / Hikvision-clone
    "/Streaming/Channels/102",  # Hikvision substream
    "/stream",
    "/stream0",
    "/stream1",
    "/live",
    "/live/main",
    "/live/sub",
    "/live0",
    "/live1",
    "/ch0_0.264",
    "/ch0_1.264",
    "/ch01.264",
    "/video",
    "/video0",
    "/video1",
    "/cam/realmonitor?channel=1&subtype=0",   # Dahua main
    "/cam/realmonitor?channel=1&subtype=1",   # Dahua sub
    "/h264/ch1/main/av_stream",               # Hikvision alt
    "/h264/ch1/sub/av_stream",
    "/onvif/profile1/media.smp",
    "/onvif/profile2/media.smp",
    "/MediaInput/h264",
    "/11",
    "/12",
    "/1",
    "/0",
]

# ONVIF device service endpoint for credential probing
ONVIF_DEVICE_SERVICE = "/onvif/device_service"
ONVIF_GETDEVICEINFO = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <soap:Body>
    <tds:GetDeviceInformation/>
  </soap:Body>
</soap:Envelope>"""

ONVIF_GETDEVICEINFO_AUTH = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
               xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
               xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <soap:Header>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>{username}</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PasswordDigest">{password_digest}</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#Base64Binary">{nonce}</wsse:Nonce>
        <wsu:Created>{created}</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <tds:GetDeviceInformation/>
  </soap:Body>
</soap:Envelope>"""

# Default credentials to try (username, password)
DEFAULT_CREDS = [
    ("admin",   ""),
    ("admin",   "admin"),
    ("admin",   "admin123"),
    ("admin",   "12345"),
    ("admin",   "123456"),
    ("admin",   "password"),
    ("admin",   "1234"),
    ("admin",   "888888"),
    ("admin",   "666666"),
    ("admin",   "111111"),
    ("admin",   "000000"),
    ("admin",   "54321"),
    ("root",    ""),
    ("root",    "root"),
    ("root",    "admin"),
    ("root",    "12345"),
    ("user",    "user"),
    ("guest",   "guest"),
    ("admin",   "admin1234"),
    ("admin",   "ipcamera"),
    ("admin",   "camera"),
    ("admin",   "meinsm"),
]

WSD_PROBE = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<Envelope xmlns:dn="http://www.onvif.org/ver10/network/wsdl"'
    ' xmlns="http://www.w3.org/2003/05/soap-envelope">'
    '<Header>'
    '<wsa:MessageID xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
    'uuid:12345678-1234-1234-1234-123456789abc'
    '</wsa:MessageID>'
    '<wsa:To xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
    'urn:schemas-xmlsoap-org:ws:2005:04:discovery'
    '</wsa:To>'
    '<wsa:Action xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
    'http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe'
    '</wsa:Action>'
    '</Header>'
    '<Body>'
    '<Probe xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
    ' xmlns:xsd="http://www.w3.org/2001/XMLSchema"'
    ' xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
    '<Types>dn:NetworkVideoTransmitter</Types>'
    '<Scopes/>'
    '</Probe>'
    '</Body>'
    '</Envelope>'
)

lock = threading.Lock()


def log(msg):
    with lock:
        print(msg)


# ─────────────────────────────────────────────────────────────────────
#  Port / service probes
# ─────────────────────────────────────────────────────────────────────
def check_port(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_rtsp(ip, port, timeout, path="/"):
    """Send RTSP OPTIONS for a given path. Returns server banner or None."""
    probe = (
        f"OPTIONS rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
        f"CSeq: 1\r\n"
        f"User-Agent: CameraScanner/2.0\r\n"
        f"\r\n"
    ).encode()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(probe)
            data = s.recv(512).decode(errors="replace")
            if "RTSP/1.0" in data or "RTSP/1.1" in data:
                server = ""
                for line in data.splitlines():
                    if line.lower().startswith("server:"):
                        server = line.strip()
                return server or "RTSP OK"
    except OSError:
        pass
    return None


import hashlib, base64 as _base64


def _rtsp_recv(sock):
    """Read a full RTSP response (headers at minimum)."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="replace")


def _rtsp_describe(ip, port, timeout, url, cseq, auth_header=""):
    """
    Open a FRESH TCP connection and send one RTSP DESCRIBE.
    A new connection per request is necessary because many cameras
    close the socket after a 401, making connection reuse unreliable.
    """
    req = (
        f"DESCRIBE {url} RTSP/1.0\r\n"
        f"CSeq: {cseq}\r\n"
        f"User-Agent: CameraScanner/2.0\r\n"
        f"Accept: application/sdp\r\n"
        f"{auth_header}"
        f"\r\n"
    ).encode()
    with socket.create_connection((ip, port), timeout=timeout) as s:
        s.sendall(req)
        return _rtsp_recv(s)


def _parse_www_authenticate(response):
    """
    Parse WWW-Authenticate header. Returns ("digest", params) or ("basic", {}) or None.
    Handles both Digest (with optional qop) and Basic challenges.
    """
    m = re.search(r'WWW-Authenticate:\s*(\w+)\s*(.*)', response, re.I)
    if not m:
        return None
    scheme = m.group(1).lower()
    rest   = m.group(2)
    params = {}
    for key, val in re.findall(r'(\w+)="([^"]*)"', rest):
        params[key] = val
    # Also capture unquoted values (e.g. qop=auth without quotes)
    for key, val in re.findall(r'(\w+)=([^",\s]+)', rest):
        if key not in params:
            params[key] = val
    return (scheme, params)


def _make_digest_auth(user, password, method, uri, params):
    """
    Build Authorization: Digest header, correctly handling qop="auth".
    Without qop:  response = MD5(HA1:nonce:HA2)
    With qop=auth: response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
    """
    realm  = params.get("realm", "")
    nonce  = params.get("nonce", "")
    qop    = params.get("qop", "").strip()
    ha1 = hashlib.md5(f"{user}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()

    if qop == "auth":
        cnonce = "4b6f6172616e6d69"   # fixed client nonce (fine for a scanner)
        nc     = "00000001"
        resp_hash = hashlib.md5(
            f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()
        ).hexdigest()
        return (
            f'Authorization: Digest username="{user}", realm="{realm}", '
            f'nonce="{nonce}", uri="{uri}", qop={qop}, nc={nc}, '
            f'cnonce="{cnonce}", response="{resp_hash}"\r\n'
        )
    else:
        resp_hash = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        return (
            f'Authorization: Digest username="{user}", realm="{realm}", '
            f'nonce="{nonce}", uri="{uri}", response="{resp_hash}"\r\n'
        )


def _make_basic_auth(user, password):
    b64 = _base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Authorization: Basic {b64}\r\n"


def _rtsp_status(resp):
    """Extract numeric status code from RTSP response string, or None."""
    m = re.search(r"RTSP/1\.[01]\s+(\d+)", resp)
    return int(m.group(1)) if m else None


def probe_rtsp_with_creds(ip, port, timeout, path, user, password):
    """
    Try RTSP DESCRIBE with credentials, supporting Digest (with/without qop) and Basic.

    Strategy: open ONE TCP connection, send the unauthenticated DESCRIBE to get
    the 401 challenge and nonce, then immediately send the authenticated DESCRIBE
    on the SAME connection (so the nonce is still valid).

    If the camera closes the socket after the 401 (empty response on retry),
    fall back to a fresh connection — some cameras accept a replayed nonce on
    a new connection, others don't. Both attempts are made before giving up.

    Returns:
      "200 OK - stream accessible"  — success
      "401 Auth required"           — path exists, credentials wrong/missing
      "403 Forbidden"               — path exists but access denied
      None                          — path absent, or no RTSP response at all
    """
    url = f"rtsp://{ip}:{port}{path}"

    # ── Step 1: open connection, send unauthenticated DESCRIBE ───────
    try:
        conn = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None

    try:
        resp1 = _rtsp_recv_on(conn,
            f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\n"
            f"User-Agent: CameraScanner/2.0\r\nAccept: application/sdp\r\n\r\n"
            .encode())
    except OSError:
        conn.close()
        return None

    status1 = _rtsp_status(resp1)
    if status1 == 200:
        conn.close()
        return "200 OK - stream accessible"
    if status1 == 404 or status1 is None:
        conn.close()
        return None
    if status1 != 401:
        conn.close()
        return None

    # Path exists and requires auth
    if not user and not password:
        conn.close()
        return "401 Auth required"

    # ── Step 2: build auth header from the challenge in resp1 ────────
    challenge = _parse_www_authenticate(resp1)
    if challenge is None:
        auth_header = _make_basic_auth(user, password)
    elif challenge[0] == "digest":
        auth_header = _make_digest_auth(user, password, "DESCRIBE", url, challenge[1])
    else:
        auth_header = _make_basic_auth(user, password)

    req2 = (
        f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 2\r\n"
        f"User-Agent: CameraScanner/2.0\r\nAccept: application/sdp\r\n"
        f"{auth_header}\r\n"
    ).encode()

    # ── Step 3A: send auth on the SAME connection ────────────────────
    resp2 = None
    try:
        resp2 = _rtsp_recv_on(conn, req2)
    except OSError:
        pass
    finally:
        conn.close()

    status2 = _rtsp_status(resp2) if resp2 else None

    # ── Step 3B: if camera closed socket, retry on a fresh connection ─
    # (some cameras accept the replayed nonce on a new TCP connection)
    if status2 is None:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                resp2 = _rtsp_recv_on(s, req2)
                status2 = _rtsp_status(resp2)
        except OSError:
            pass

    if status2 == 200:
        return "200 OK - stream accessible"
    if status2 == 401:
        return "401 Auth required"
    if status2 == 403:
        return "403 Forbidden"
    return None


def _rtsp_recv_on(sock, request_bytes):
    """Send request_bytes on sock and read the full RTSP response."""
    sock.sendall(request_bytes)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="replace")


def is_blocklisted(title, server):
    """Return (True, reason) if this device is clearly NOT a camera."""
    title_l = (title or "").lower()
    server_l = (server or "").lower()
    for kw in BLOCKLIST_TITLE:
        if kw in title_l:
            return True, f"Blocklisted title keyword: '{kw}'"
    for kw in BLOCKLIST_SERVER:
        if kw in server_l:
            return True, f"Blocklisted server header: '{kw}'"
    return False, ""


def probe_http(ip, port, timeout):
    """Fetch HTTP root. Returns dict with title, server, camera_hit, blocked, url."""
    info = {
        "title": "", "server": "", "camera_hit": False,
        "blocked": False, "block_reason": "", "url": None
    }
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    info["url"] = url

    try:
        if HAS_REQUESTS:
            r = requests.get(url, timeout=timeout, verify=False,
                             allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0"})
            body = r.text.lower()
            info["server"] = r.headers.get("Server", "")
            title_m = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
            info["title"] = title_m.group(1).strip() if title_m else ""
        else:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                req = f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                s.sendall(req.encode())
                raw = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
                    if len(raw) > 65536:
                        break
            body = raw.decode(errors="replace").lower()
            m = re.search(r"server:\s*(.+)", body)
            info["server"] = m.group(1).strip() if m else ""
            title_m = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
            info["title"] = title_m.group(1).strip() if title_m else ""

        # Blocklist check
        blocked, reason = is_blocklisted(info["title"], info["server"])
        info["blocked"] = blocked
        info["block_reason"] = reason
        if blocked:
            return info

        # Camera signal check
        for kw in CAMERA_KEYWORDS_BODY:
            if kw in body:
                info["camera_hit"] = True
                break
        for sv in CAMERA_SERVER_HEADERS:
            if sv in info["server"].lower():
                info["camera_hit"] = True
                break

    except Exception:
        pass
    return info


# ─────────────────────────────────────────────────────────────────────
#  Credential probing
# ─────────────────────────────────────────────────────────────────────
def try_onvif_creds(ip, timeout, creds=None):
    """
    Probe ONVIF device service with credentials.
    Uses WS-Security PasswordDigest auth — the standard ONVIF auth method.
    Returns (user, password, model_info) or None.

    This is a valuable parallel path to RTSP probing because:
    - Works even when RTSP stream paths are non-standard
    - ONVIF auth is completely independent of RTSP auth
    - All cameras that responded to WS-Discovery support this endpoint
    """
    if not HAS_REQUESTS:
        return None
    if creds is None:
        creds = DEFAULT_CREDS

    import base64 as _b64, hashlib as _hl, os as _os
    from datetime import datetime, timezone

    url = f"http://{ip}:{80}/onvif/device_service"
    # Also try port 8080 if 80 fails
    urls_to_try = [
        f"http://{ip}:80/onvif/device_service",
        f"http://{ip}:8080/onvif/device_service",
    ]

    def make_onvif_auth_body(user, password):
        """Build WS-Security PasswordDigest auth envelope."""
        raw_nonce   = _os.urandom(16)
        nonce_b64   = _b64.b64encode(raw_nonce).decode()
        created     = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        # PasswordDigest = Base64(SHA1(nonce + created + password))
        digest_raw  = raw_nonce + created.encode() + password.encode()
        digest_b64  = _b64.b64encode(_hl.sha1(digest_raw).digest()).decode()
        return ONVIF_GETDEVICEINFO_AUTH.format(
            username=user,
            password_digest=digest_b64,
            nonce=nonce_b64,
            created=created,
        )

    headers = {
        "Content-Type": "application/soap+xml; charset=utf-8",
        "User-Agent":   "CameraScanner/2.0",
    }

    # First check if the endpoint exists at all (unauthenticated)
    endpoint = None
    for url in urls_to_try:
        try:
            r = requests.post(url, data=ONVIF_GETDEVICEINFO,
                              headers=headers, timeout=timeout, verify=False)
            # 200 (open), 400 (needs auth but responded), 401/403 all mean endpoint exists
            if r.status_code in (200, 400, 401, 403):
                endpoint = url
                if r.status_code == 200:
                    # Open ONVIF — extract model info and return
                    model = _extract_onvif_model(r.text)
                    return ("", "", model or "open (no auth)")
                break
        except Exception:
            continue

    if endpoint is None:
        return None   # ONVIF device service not reachable on this host

    # Brute-force credentials
    for user, pw in creds:
        try:
            body = make_onvif_auth_body(user, pw)
            r = requests.post(endpoint, data=body, headers=headers,
                              timeout=timeout, verify=False)
            if r.status_code == 200 and "GetDeviceInformationResponse" in r.text:
                model = _extract_onvif_model(r.text)
                return (user, pw, model or "unknown model")
        except Exception:
            continue

    return None


def _extract_onvif_model(xml_text):
    """Pull Manufacturer + Model from ONVIF GetDeviceInformationResponse."""
    mfr = re.search(r"<[^>]*Manufacturer[^>]*>([^<]+)<", xml_text)
    mdl = re.search(r"<[^>]*Model[^>]*>([^<]+)<", xml_text)
    parts = [m.group(1).strip() for m in [mfr, mdl] if m]
    return " / ".join(parts) if parts else None


def try_http_creds(ip, port, timeout, creds=None):
    """Try credentials on HTTP. Return (user, pass, url) or None."""
    if not HAS_REQUESTS:
        return None
    if creds is None:
        creds = DEFAULT_CREDS
    scheme = "https" if port in (443, 8443) else "http"
    base = f"{scheme}://{ip}:{port}"
    # Paths that camera login APIs commonly sit on
    login_paths = ["/", "/login", "/web/login", "/cgi-bin/hi3510/param.cgi"]
    for user, pw in creds:
        for path in login_paths:
            url = base + path
            try:
                r = requests.get(url, auth=(user, pw), timeout=timeout,
                                 verify=False, allow_redirects=True)
                # Success if we got past auth (not 401/403) and looks like camera UI
                if r.status_code in (200, 302) and r.status_code != 401:
                    body = r.text.lower()
                    hit = any(kw in body for kw in CAMERA_KEYWORDS_BODY)
                    # Also check: were we previously getting 401 without creds?
                    if hit:
                        return (user, pw, url)
            except Exception:
                pass
    return None


def try_rtsp_creds(ip, port, timeout, creds=None):
    """
    Smart RTSP credential prober.

    Returns one of:
      ("found",   user, pw, path, result_str)  — working credentials found
      ("open",    "",   "",  path, result_str)  — stream open, no auth needed
      ("noauth",  ...)                          — paths exist but no creds worked
      ("noconn",  ...)                          — could not connect at all
      ("nopaths", ...)                          — connected but no valid paths found

    Phase 1 — path discovery on a SINGLE persistent TCP connection.
      All DESCRIBE requests are pipelined through one socket so rate-limiting
      cameras only see one connection, not one-per-path.
      Collects: open paths (200), auth-required paths (401/403).

    Phase 2 — credential brute-force, one connection per candidate credential.
      Only runs against the confirmed-existing paths from Phase 1.
      Uses the same-connection nonce trick (CSeq 1 = challenge, CSeq 2 = auth).
    """
    if creds is None:
        creds = DEFAULT_CREDS

    valid_paths  = []   # paths that returned 401/403
    got_any      = False
    saved_challenge = None   # reuse the first challenge for Phase 2

    # ── Phase 1: probe all paths, reconnecting if camera closes connection ──
    # Some cameras close the TCP connection after every response (even 401).
    # We detect this (empty/error response) and transparently reconnect so we
    # probe every path — not just the first one before the camera closes.
    conn = None
    cseq = 0

    for path in RTSP_PATHS:
        cseq += 1
        url = f"rtsp://{ip}:{port}{path}"
        req = (
            f"DESCRIBE {url} RTSP/1.0\r\nCSeq: {cseq}\r\n"
            f"User-Agent: CameraScanner/2.0\r\nAccept: application/sdp\r\n\r\n"
        ).encode()

        # Try each path up to 2 times: once on the existing connection,
        # and if the camera closed it, reconnect and retry THE SAME PATH.
        # Without this, a camera that closes after every response would cause
        # every odd-numbered path to be silently skipped.
        for attempt in range(2):
            if conn is None:
                try:
                    conn = socket.create_connection((ip, port), timeout=timeout)
                except OSError:
                    break   # truly unreachable — stop all probing

            resp = None
            try:
                resp = _rtsp_recv_on(conn, req)
            except OSError:
                try: conn.close()
                except Exception: pass
                conn = None

            if not resp:
                # Camera closed connection after previous response.
                # Discard socket and retry THIS SAME PATH on a new connection.
                try: conn.close()
                except Exception: pass
                conn = None
                continue   # attempt 2: reconnect and retry same path

            # Got a real response — process and move to next path
            got_any = True
            status = _rtsp_status(resp)
            if status == 200:
                try: conn.close()
                except Exception: pass
                return ("open", "", "", path, "200 OK - stream accessible")
            elif status in (401, 403):
                valid_paths.append(path)
                if saved_challenge is None:
                    saved_challenge = _parse_www_authenticate(resp)
            # other status (404 etc. or 461) — path absent on this camera
            # Small delay after each response to avoid rate-limiting on
            # cameras that allow only one connection per N milliseconds
            time.sleep(0.1)
            break   # done with this path regardless of status

    if conn is not None:
        try: conn.close()
        except Exception: pass



    if not got_any:
        return ("noconn", "", "", "", "")
    if not valid_paths:
        return ("nopaths", "", "", "", "")

    # Brief pause between Phase 1 and Phase 2 to let the camera's
    # rate limiter reset before we start credential attempts
    time.sleep(0.5)

    # ── Phase 2: brute-force credentials on confirmed paths ──────────
    #
    # We handle three firmware behaviours seen in the wild:
    #
    # Type A — Standard Digest (e.g. .194):
    #   Unauthenticated DESCRIBE → 401 + nonce → auth on same connection → 200
    #
    # Type B — One-response-per-connection Digest (e.g. .148):
    #   Unauthenticated DESCRIBE → 401 → camera closes socket
    #   Must open a 2nd connection, get fresh 401+nonce, send auth → 200
    #
    # Type C — Silent unless credentials sent upfront (e.g. .234, .252):
    #   Unauthenticated DESCRIBE → silence (camera ignores it)
    #   Must send DESCRIBE with Basic auth on first request → 200 or 401
    #
    # Strategy per credential attempt:
    #   Step 1: try unauthenticated → if 401, do Type A then Type B
    #   Step 2: if silence, try Basic auth upfront (Type C)

    paths_to_try = valid_paths if valid_paths else RTSP_PATHS

    for path in paths_to_try:
        url = f"rtsp://{ip}:{port}{path}"
        for user, pw in creds:
            try:
                # ── Step 1: unauthenticated probe (Type A / B detection) ──
                connA = socket.create_connection((ip, port), timeout=timeout)
                req_unauth = (
                    f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\n"
                    f"User-Agent: CameraScanner/2.0\r\nAccept: application/sdp\r\n\r\n"
                ).encode()
                try:
                    resp_unauth = _rtsp_recv_on(connA, req_unauth)
                except OSError:
                    resp_unauth = None

                status_unauth = _rtsp_status(resp_unauth) if resp_unauth else None

                if status_unauth == 200:
                    try: connA.close()
                    except Exception: pass
                    return ("open", "", "", path, "200 OK - stream accessible")

                if status_unauth == 401:
                    # Type A: try auth on same connection first
                    challenge = _parse_www_authenticate(resp_unauth)
                    if challenge and challenge[0] == "digest":
                        auth_hdr = _make_digest_auth(user, pw, "DESCRIBE", url, challenge[1])
                    else:
                        auth_hdr = _make_basic_auth(user, pw)

                    req_auth = (
                        f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 2\r\n"
                        f"User-Agent: CameraScanner/2.0\r\nAccept: application/sdp\r\n"
                        f"{auth_hdr}\r\n"
                    ).encode()
                    try:
                        resp_auth = _rtsp_recv_on(connA, req_auth)
                        if _rtsp_status(resp_auth) == 200:
                            try: connA.close()
                            except Exception: pass
                            return ("found", user, pw, path, "200 OK - stream accessible")
                    except OSError:
                        pass   # camera closed — fall through to Type B

                    # Type B: open fresh connection, get new nonce, send auth
                    try: connA.close()
                    except Exception: pass

                    try:
                        connB = socket.create_connection((ip, port), timeout=timeout)
                        try:
                            resp_b1 = _rtsp_recv_on(connB, req_unauth)
                            if resp_b1 and _rtsp_status(resp_b1) == 401:
                                challenge_b = _parse_www_authenticate(resp_b1)
                                if challenge_b and challenge_b[0] == "digest":
                                    auth_hdr_b = _make_digest_auth(user, pw, "DESCRIBE", url, challenge_b[1])
                                else:
                                    auth_hdr_b = _make_basic_auth(user, pw)
                                req_b2 = (
                                    f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 2\r\n"
                                    f"User-Agent: CameraScanner/2.0\r\nAccept: application/sdp\r\n"
                                    f"{auth_hdr_b}\r\n"
                                ).encode()
                                resp_b2 = _rtsp_recv_on(connB, req_b2)
                                if _rtsp_status(resp_b2) == 200:
                                    try: connB.close()
                                    except Exception: pass
                                    return ("found", user, pw, path, "200 OK - stream accessible")
                        except OSError:
                            pass
                        finally:
                            try: connB.close()
                            except Exception: pass
                    except OSError:
                        pass

                else:
                    # Type C: silence — camera ignores unauthenticated requests.
                    # Send Basic auth upfront on the same connection.
                    try: connA.close()
                    except Exception: pass

                    auth_hdr = _make_basic_auth(user, pw)
                    try:
                        connC = socket.create_connection((ip, port), timeout=timeout)
                        req_basic = (
                            f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\n"
                            f"User-Agent: CameraScanner/2.0\r\nAccept: application/sdp\r\n"
                            f"{auth_hdr}\r\n"
                        ).encode()
                        try:
                            resp_c = _rtsp_recv_on(connC, req_basic)
                            status_c = _rtsp_status(resp_c) if resp_c else None
                            if status_c == 200:
                                try: connC.close()
                                except Exception: pass
                                return ("found", user, pw, path, "200 OK - stream accessible")
                            elif status_c == 401:
                                # Camera wants Digest — get nonce and retry on same conn
                                challenge_c = _parse_www_authenticate(resp_c)
                                if challenge_c and challenge_c[0] == "digest":
                                    auth_hdr_d = _make_digest_auth(user, pw, "DESCRIBE", url, challenge_c[1])
                                    req_d = (
                                        f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 2\r\n"
                                        f"User-Agent: CameraScanner/2.0\r\nAccept: application/sdp\r\n"
                                        f"{auth_hdr_d}\r\n"
                                    ).encode()
                                    resp_d = _rtsp_recv_on(connC, req_d)
                                    if _rtsp_status(resp_d) == 200:
                                        try: connC.close()
                                        except Exception: pass
                                        return ("found", user, pw, path, "200 OK - stream accessible")
                        except OSError:
                            pass
                        finally:
                            try: connC.close()
                            except Exception: pass
                    except OSError:
                        pass

            except OSError:
                pass

            time.sleep(0.3)

    return ("noauth", "", "", paths_to_try[0] if paths_to_try else "/", "")






# ─────────────────────────────────────────────────────────────────────
#  Per-host scan
# ─────────────────────────────────────────────────────────────────────
def scan_host(ip, timeout):
    open_ports = {}
    rtsp_confirmed = None
    rtsp_port_used = None
    http_infos = []
    score = 0
    reasons = []
    blocked = False
    block_reason = ""

    # 1. Check all camera ports
    for port, label in CAMERA_PORTS.items():
        if check_port(ip, port, timeout):
            open_ports[port] = label

    if not open_ports:
        return None

    # 2. HTTP probing — do this first so we can blocklist early
    for port in [80, 8080, 8081, 443, 8443, 5000]:
        if port in open_ports:
            hinfo = probe_http(ip, port, timeout)
            if hinfo.get("blocked"):
                blocked = True
                block_reason = hinfo["block_reason"]
                break
            http_infos.append(hinfo)
            if hinfo["camera_hit"]:
                score += 30
                reasons.append(
                    f"Camera keyword in HTTP on :{port} "
                    f"(title='{hinfo['title']}' server='{hinfo['server']}')"
                )

    if blocked:
        return {
            "ip": ip, "open_ports": open_ports, "score": -999,
            "blocked": True, "block_reason": block_reason,
            "reasons": [], "rtsp": None, "http": [],
            "creds_http": None, "creds_rtsp": None, "creds_onvif": None,
        }

    # 3. RTSP probing — try multiple paths
    for port in [554, 8554]:
        if port in open_ports:
            for path in RTSP_PATHS[:6]:   # try top 6 paths during discovery
                result = probe_rtsp(ip, port, timeout, path)
                if result:
                    rtsp_confirmed = f"Port {port} path '{path}': {result}"
                    rtsp_port_used = port
                    score += 40
                    reasons.append(f"RTSP confirmed on :{port} path {path}")
                    break
        if rtsp_confirmed:
            break

    # Port-based scoring
    if 34567 in open_ports:
        score += 25
        reasons.append("Port 34567 open (Chinese DVR/IPC)")
    if 37777 in open_ports:
        score += 20
        reasons.append("Port 37777 open (Dahua)")
    if 9527 in open_ports:
        score += 15
        reasons.append("Port 9527 open (Chinese IPC)")
    if 8000 in open_ports:
        score += 10
        reasons.append("Port 8000 open (Hikvision SDK)")
    if 554 in open_ports and not rtsp_confirmed:
        score += 10
        reasons.append("Port 554 open (RTSP, unconfirmed)")
    if 8554 in open_ports and not rtsp_confirmed:
        score += 10
        reasons.append("Port 8554 open (RTSP-alt, unconfirmed)")
    if any(p in open_ports for p in [80, 8080]):
        score += 3

    return {
        "ip": ip,
        "open_ports": open_ports,
        "rtsp": rtsp_confirmed,
        "rtsp_port": rtsp_port_used,
        "http": http_infos,
        "score": score,
        "reasons": reasons,
        "blocked": False,
        "block_reason": "",
        "creds_http": None,
        "creds_rtsp": None,
        "creds_onvif": None,
        "creds_onvif": None,
    }


# ─────────────────────────────────────────────────────────────────────
#  ONVIF WS-Discovery
# ─────────────────────────────────────────────────────────────────────
def onvif_discovery(timeout=3.0):
    found = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        sock.sendto(WSD_PROBE.encode(), ("239.255.255.250", 3702))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                if ip not in found:
                    found.append(ip)
            except socket.timeout:
                break
        sock.close()
    except Exception as e:
        log(f"[!] ONVIF error: {e}")
    return found


# ─────────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="IP Camera Scanner v2")
    parser.add_argument("--network",     default="192.168.1")
    parser.add_argument("--timeout",     type=float, default=0.8)
    parser.add_argument("--workers",     type=int,   default=60)
    parser.add_argument("--skip-onvif",  action="store_true")
    parser.add_argument("--skip-creds",  action="store_true")
    parser.add_argument("--top",         type=int,   default=20,
                        help="Only probe creds on top N candidates (default: 20)")
    parser.add_argument("--wordlist",    default=None,
                        help="Path to a wordlist file. "
                             "Each line: 'password' or 'user:password'. "
                             "These are tried IN ADDITION TO the built-in defaults.")
    parser.add_argument("--wordlist-only", action="store_true",
                        help="Use ONLY the wordlist, skip built-in default credentials")
    parser.add_argument("--user",        default=None,
                        help="Fix the username for wordlist entries that have no 'user:' prefix "
                             "(default: try all built-in usernames)")
    args = parser.parse_args()

    network = args.network.rstrip(".")
    hosts = [f"{network}.{i}" for i in range(1, 255)]

    # ── Build effective credential list ──────────────────────────────
    extra_creds = []
    if args.wordlist:
        try:
            with open(args.wordlist, "r", encoding="utf-8", errors="replace") as wf:
                for line in wf:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line:
                        u, p = line.split(":", 1)
                        extra_creds.append((u.strip(), p.strip()))
                    else:
                        # No username given — use --user if specified, else try common usernames
                        if args.user:
                            extra_creds.append((args.user, line))
                        else:
                            for u in ("admin", "root", "user", "guest"):
                                extra_creds.append((u, line))
            print(f"[+] Loaded {len(extra_creds)} credential(s) from wordlist: {args.wordlist}")
        except FileNotFoundError:
            print(f"[!] Wordlist file not found: {args.wordlist}")
            return
        except Exception as e:
            print(f"[!] Error reading wordlist: {e}")
            return

    if args.wordlist_only:
        effective_creds = extra_creds
        creds_source = f"wordlist only ({len(effective_creds)} entries)"
    elif extra_creds:
        # Wordlist entries go FIRST so user-supplied guesses are tried before defaults
        effective_creds = extra_creds + [c for c in DEFAULT_CREDS if c not in extra_creds]
        creds_source = f"wordlist ({len(extra_creds)}) + built-in defaults ({len(DEFAULT_CREDS)})"
    else:
        effective_creds = DEFAULT_CREDS
        creds_source = f"built-in defaults ({len(DEFAULT_CREDS)} entries)"

    print("=" * 65)
    print("  IP Camera Scanner v2")
    print("=" * 65)
    print(f"  Network : {network}.0/24  |  Timeout: {args.timeout}s  |  Workers: {args.workers}")
    print(f"  Credentials : {creds_source}")
    print(f"  Blocklist active for: unifi, shelly, synology, routers, NAS ...")
    print("=" * 65)

    # ONVIF discovery
    onvif_ips = []
    if not args.skip_onvif:
        print("\n[*] ONVIF WS-Discovery multicast probe ...")
        onvif_ips = onvif_discovery(timeout=3.0)
        if onvif_ips:
            print(f"[+] ONVIF responses: {', '.join(onvif_ips)}")
        else:
            print("[-] No ONVIF responses received")

    # Port scan
    print(f"\n[*] Scanning {len(hosts)} hosts ...\n")
    all_results = []
    completed = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(scan_host, ip, args.timeout): ip for ip in hosts}
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            bar = int(40 * completed / len(hosts))
            sys.stdout.write(
                f"\r  [{('#' * bar).ljust(40)}] {completed}/{len(hosts)}"
            )
            sys.stdout.flush()
            r = future.result()
            if r:
                if r["ip"] in onvif_ips and not r["blocked"]:
                    r["score"] += 35
                    r["reasons"].append("Responded to ONVIF WS-Discovery")
                all_results.append(r)

    print("\n")

    # Separate blocked from candidates
    blocked_devices = [r for r in all_results if r["blocked"]]
    candidates = sorted(
        [r for r in all_results if not r["blocked"]],
        key=lambda x: x["score"], reverse=True
    )

    # Credential probing
    if not args.skip_creds:
        top_candidates = [c for c in candidates if c["score"] >= 20][:args.top]
        if top_candidates:
            print(f"[*] Probing credentials on {len(top_candidates)} candidate(s)...")
            print(f"    (Phase 1: discover valid RTSP paths → Phase 2: brute-force creds)\n")
            for r in top_candidates:
                ip = r["ip"]
                print(f"    → {ip} ...", end="", flush=True)

                # Brief pause before probing each camera to let rate limiters reset
                time.sleep(2.0)

                # HTTP creds
                for port in [80, 8080, 8081]:
                    if port in r["open_ports"]:
                        cred = try_http_creds(ip, port, args.timeout + 0.5, effective_creds)
                        if cred:
                            r["creds_http"] = cred
                            break

                # RTSP creds — find the right port
                rtsp_port = r.get("rtsp_port")
                if not rtsp_port:
                    for p in [554, 8554]:
                        if p in r["open_ports"]:
                            rtsp_port = p
                            break
                if rtsp_port:
                    cred = try_rtsp_creds(ip, rtsp_port, args.timeout + 0.5, effective_creds)
                    r["rtsp_port"] = rtsp_port
                    status = cred[0] if cred else "noconn"
                    if status == "found":
                        r["creds_rtsp"] = cred   # ("found", user, pw, path, res)
                    elif status == "open":
                        r["creds_rtsp"] = cred   # ("open", "", "", path, res)
                    r["rtsp_probe_status"] = status
                else:
                    r["rtsp_probe_status"] = "noport"

                # ONVIF creds — try for all ONVIF-responding cameras
                if ip in onvif_ips and not r.get("creds_rtsp"):
                    cred = try_onvif_creds(ip, args.timeout + 0.5, effective_creds)
                    if cred:
                        r["creds_onvif"] = cred

                # Print outcome
                status = r.get("rtsp_probe_status", "noport")
                if r.get("creds_rtsp"):
                    kind = r["creds_rtsp"][0]
                    if kind == "found":
                        _, u, pw, path, _ = r["creds_rtsp"]
                        print(f" ✅ RTSP stream: {u}/{pw} on {path}")
                    else:
                        _, _, _, path, _ = r["creds_rtsp"]
                        print(f" ✅ RTSP open (no auth): {path}")
                elif r.get("creds_onvif"):
                    u, pw, model = r["creds_onvif"]
                    if u:
                        print(f" ✅ ONVIF: {u}/{pw} ({model})")
                    else:
                        print(f" ✅ ONVIF open (no auth): {model}")
                elif r.get("creds_http"):
                    u, pw, _ = r["creds_http"]
                    print(f" ✅ HTTP: {u}/{pw}")
                elif status == "noconn":
                    print(f" ⚠️  could not connect to RTSP port {rtsp_port}")
                elif status == "nopaths":
                    print(f" ⚠️  RTSP: non-standard paths — but check ONVIF result above")
                elif status == "noauth":
                    print(f" ❌ RTSP paths found but no default credentials worked")
                else:
                    print(f" ℹ️  no RTSP port open to probe")

    # ── Print results ──────────────────────────────────────────────
    print("=" * 65)
    print("  SCAN RESULTS")
    print("=" * 65)

    cameras  = [r for r in candidates if r["score"] >= 20]
    maybes   = [r for r in candidates if 5 <= r["score"] < 20]

    if not cameras and not maybes:
        print("\n  No camera candidates found.\n")
        print("  Suggestions:")
        print("  • Try --timeout 2 for slower networks")
        print("  • Verify the camera is powered on and connected")
        print("  • Try a different subnet with --network 192.168.0")
    else:
        if cameras:
            print(f"\n  🎥  LIKELY CAMERAS  ({len(cameras)} found)\n")
            for r in cameras:
                _print_result(r)

        if maybes:
            print(f"\n  ❓  POSSIBLE / LOW-CONFIDENCE  ({len(maybes)} found)\n")
            for r in maybes:
                _print_result(r)

    if blocked_devices:
        print(f"\n  🚫  BLOCKLISTED (not cameras, {len(blocked_devices)} devices)\n")
        for r in blocked_devices:
            ports_str = ", ".join(f"{p}/{l}" for p, l in r["open_ports"].items())
            print(f"  • {r['ip']}  [{r['block_reason']}]  ports: {ports_str}")

    # Quick access summary
    print("\n" + "=" * 65)
    print("  QUICK ACCESS URLS")
    print("=" * 65)
    for r in cameras:
        ip = r["ip"]
        # Determine best RTSP port
        rtsp_port = r.get("rtsp_port")
        if not rtsp_port:
            for p in [554, 8554]:
                if p in r["open_ports"]:
                    rtsp_port = p
                    break

        print(f"\n  ── {ip} " + "─" * (45 - len(ip)))

        for port in [80, 8080, 8081]:
            if port in r["open_ports"]:
                print(f"    Browser  →  http://{ip}:{port}/")

        if r.get("creds_rtsp"):
            kind = r["creds_rtsp"][0]
            if kind == "found":
                _, u, pw, path, _ = r["creds_rtsp"]
                cred_str = f"{u}:{pw}@"
            else:  # open
                _, _, _, path, _ = r["creds_rtsp"]
                cred_str = ""
            full_url = f"rtsp://{cred_str}{ip}:{rtsp_port}{path}"
            print(f"    ✅ CONFIRMED STREAM  →  {full_url}")
            print(f"       VLC  : vlc \"{full_url}\"")
            print(f"       ffmpeg: ffmpeg -rtsp_transport tcp -i \"{full_url}\" ...")
        elif rtsp_port:
            status = r.get("rtsp_probe_status", "")
            if status == "noconn":
                print(f"    ⚠️  RTSP port {rtsp_port} open but could not connect during probe")
                print(f"    Try: rtsp://{ip}:{rtsp_port}/Streaming/Channels/101")
            elif status == "nopaths":
                print(f"    ⚠️  RTSP connected but no known paths answered — try manually:")
                print(f"    Try: rtsp://{ip}:{rtsp_port}/  or  rtsp://{ip}:{rtsp_port}/stream")
            elif status == "noauth":
                print(f"    ❌ RTSP stream found but default credentials failed")
                print(f"    Try: rtsp://admin:<yourpassword>@{ip}:{rtsp_port}/Streaming/Channels/101")
            else:
                print(f"    RTSP →  rtsp://{ip}:{rtsp_port}/")

        if r.get("creds_onvif"):
            u, pw, model = r["creds_onvif"]
            if u:
                print(f"    ✅ ONVIF confirmed  →  user: '{u}'  pass: '{pw}'  ({model})")
                print(f"       These credentials should also work for RTSP streams on this camera")
        if r.get("creds_http"):
            u, pw, url = r["creds_http"]
            print(f"    ✅ HTTP login  →  {url}  (user: '{u}'  pass: '{pw}')")

    print()


def _print_result(r):
    ports_str = ", ".join(f"{p}/{l}" for p, l in r["open_ports"].items())
    print(f"  ┌─ IP: {r['ip']}  (score: {r['score']})")
    print(f"  │  Ports   : {ports_str}")
    if r["rtsp"]:
        print(f"  │  RTSP    : {r['rtsp']}")
    for h in r["http"]:
        if h.get("url"):
            print(f"  │  Web UI  : {h['url']}")
        if h.get("title"):
            print(f"  │  Title   : {h['title']}")
        if h.get("server"):
            print(f"  │  Server  : {h['server']}")
    for reason in r["reasons"]:
        print(f"  │  ✔ {reason}")
    if r.get("creds_onvif"):
        u, pw, model = r["creds_onvif"]
        if u:
            print(f"  │  🔑 ONVIF: user='{u}' pass='{pw}' — {model}")
        else:
            print(f"  │  🔓 ONVIF open (no auth) — {model}")
    if r.get("creds_http"):
        u, pw, url = r["creds_http"]
        print(f"  │  🔑 HTTP: user='{u}' pass='{pw}' at {url}")
    if r.get("creds_rtsp"):
        kind = r["creds_rtsp"][0]
        if kind == "found":
            _, u, pw, path, _ = r["creds_rtsp"]
            rtsp_port = r.get("rtsp_port", 554)
            print(f"  │  🔑 RTSP: user='{u}' pass='{pw}' → rtsp://{u}:{pw}@{r['ip']}:{rtsp_port}{path}")
        elif kind == "open":
            _, _, _, path, _ = r["creds_rtsp"]
            rtsp_port = r.get("rtsp_port", 554)
            print(f"  │  🔓 RTSP open (no auth): rtsp://{r['ip']}:{rtsp_port}{path}")
    else:
        status = r.get("rtsp_probe_status")
        if status == "noconn":
            print(f"  │  ⚠️  RTSP: could not connect during credential probe")
        elif status == "nopaths":
            print(f"  │  ⚠️  RTSP: no known stream paths found — try manually")
        elif status == "noauth":
            print(f"  │  ❌ RTSP: stream exists but no default credentials worked")
    print("  └" + "─" * 55)
    print()


if __name__ == "__main__":
    main()