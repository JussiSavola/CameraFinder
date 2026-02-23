#!/usr/bin/env python3
"""
Phase 2 Debugger
----------------
Runs exactly the same logic as the scanner's Phase 2 credential loop
against a single camera, printing every step verbosely.

Usage:
    python debug_phase2.py --ip 192.168.1.148 --port 554 --path /live/ch00_0 --user admin --password admin123
"""
import argparse
import hashlib
import re
import socket
import time

def rtsp_status(resp):
    m = re.search(r"RTSP/1\.[01]\s+(\d+)", resp or "")
    return int(m.group(1)) if m else None

def recv_full(sock, label=""):
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                print(f"  [{label}] recv got empty chunk — connection closed by camera")
                break
            data += chunk
    except OSError as e:
        print(f"  [{label}] recv OSError: {e}")
    return data.decode(errors="replace")

def parse_challenge(resp):
    m = re.search(r'WWW-Authenticate:\s*(\w+)\s*(.*)', resp, re.I)
    if not m:
        return None
    scheme = m.group(1).lower()
    rest = m.group(2)
    params = {}
    for key, val in re.findall(r'(\w+)="([^"]*)"', rest):
        params[key] = val
    for key, val in re.findall(r'(\w+)=([^",\s]+)', rest):
        if key not in params:
            params[key] = val
    return scheme, params

def make_digest(user, pw, method, uri, params):
    realm = params.get("realm", "")
    nonce = params.get("nonce", "")
    qop   = params.get("qop", "").strip()
    ha1   = hashlib.md5(f"{user}:{realm}:{pw}".encode()).hexdigest()
    ha2   = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    if qop == "auth":
        cnonce = "4b6f6172616e6d69"
        nc     = "00000001"
        resp_hash = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
        return (f'Authorization: Digest username="{user}", realm="{realm}", '
                f'nonce="{nonce}", uri="{uri}", qop={qop}, nc={nc}, '
                f'cnonce="{cnonce}", response="{resp_hash}"\r\n')
    else:
        resp_hash = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        return (f'Authorization: Digest username="{user}", realm="{realm}", '
                f'nonce="{nonce}", uri="{uri}", response="{resp_hash}"\r\n')

def make_basic(user, pw):
    import base64
    b64 = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return f"Authorization: Basic {b64}\r\n"

def describe(ip, port, timeout, url, cseq, auth_hdr="", label="", sock=None):
    req = (f"DESCRIBE {url} RTSP/1.0\r\nCSeq: {cseq}\r\n"
           f"User-Agent: Phase2Debug/1.0\r\nAccept: application/sdp\r\n"
           f"{auth_hdr}\r\n").encode()
    print(f"\n  [{label}] → DESCRIBE CSeq={cseq} {'(with auth)' if auth_hdr else '(no auth)'}")
    own_sock = sock is None
    try:
        if own_sock:
            sock = socket.create_connection((ip, port), timeout=timeout)
            print(f"  [{label}]   opened fresh TCP connection")
        else:
            print(f"  [{label}]   reusing existing TCP connection")
        sock.sendall(req)
        resp = recv_full(sock, label)
        status = rtsp_status(resp)
        # Show just the status line and WWW-Authenticate if present
        for line in resp.split("\r\n")[:6]:
            if line:
                print(f"  [{label}]   ← {line}")
        print(f"  [{label}]   STATUS: {status}")
        return sock if not own_sock else (status, resp, sock)
    except OSError as e:
        print(f"  [{label}]   OSError: {e}")
        if own_sock and sock:
            try: sock.close()
            except: pass
        return (None, "", None) if own_sock else sock

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip",       required=True)
    parser.add_argument("--port",     type=int, default=554)
    parser.add_argument("--path",     default="/live/ch00_0")
    parser.add_argument("--user",     default="admin")
    parser.add_argument("--password", default="admin123")
    parser.add_argument("--timeout",  type=float, default=3.0)
    args = parser.parse_args()

    ip, port, timeout = args.ip, args.port, args.timeout
    url = f"rtsp://{ip}:{port}{args.path}"
    user, pw = args.user, args.password

    print(f"\n  Phase 2 Debugger")
    print(f"  Target : {url}")
    print(f"  User   : {user}  Pass: {pw}")
    print(f"  Simulating exactly what the scanner's Phase 2 does\n")

    # ── Connection A: unauthenticated probe ──────────────────────────
    print("=" * 60)
    print("  CONNECTION A — unauthenticated probe")
    print("=" * 60)
    try:
        connA = socket.create_connection((ip, port), timeout=timeout)
        print("  Opened connection A")
    except OSError as e:
        print(f"  FAILED to open connection A: {e}")
        return

    req1 = (f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\n"
            f"User-Agent: Phase2Debug/1.0\r\nAccept: application/sdp\r\n\r\n").encode()
    connA.sendall(req1)
    print("  Sent CSeq 1 (no auth)")
    resp1 = recv_full(connA, "connA")
    status1 = rtsp_status(resp1)
    print(f"  Status: {status1}")
    for line in resp1.split("\r\n")[:8]:
        if line: print(f"    {line}")

    if status1 == 200:
        print("\n  ✅ Open stream — no auth needed!")
        connA.close()
        return
    if status1 != 401:
        print(f"\n  ⚠️  Unexpected status {status1} on connection A — cannot proceed")
        connA.close()
        return

    challenge = parse_challenge(resp1)
    print(f"\n  Challenge parsed: {challenge}")

    # Try Type A: auth on same connection
    print("\n" + "=" * 60)
    print("  TYPE A — auth on same connection (connA, CSeq 2)")
    print("=" * 60)
    if challenge and challenge[0] == "digest":
        auth_hdr = make_digest(user, pw, "DESCRIBE", url, challenge[1])
    else:
        auth_hdr = make_basic(user, pw)

    req2 = (f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 2\r\n"
            f"User-Agent: Phase2Debug/1.0\r\nAccept: application/sdp\r\n"
            f"{auth_hdr}\r\n").encode()
    print(f"  Auth header: {auth_hdr.strip()}")
    try:
        connA.sendall(req2)
        print("  Sent CSeq 2 (with auth) on connA")
        resp2 = recv_full(connA, "connA-auth")
        status2 = rtsp_status(resp2)
        print(f"  Status: {status2}")
        for line in resp2.split("\r\n")[:6]:
            if line: print(f"    {line}")
        if status2 == 200:
            print("\n  ✅ Type A SUCCESS — same-connection auth worked!")
            connA.close()
            return
        else:
            print(f"  Type A failed (status={status2}) — trying Type B")
    except OSError as e:
        print(f"  Type A OSError on CSeq 2: {e} — camera closed connection, trying Type B")
    finally:
        try: connA.close()
        except: pass

    time.sleep(0.1)

    # Type B: fresh connection, get new nonce, send auth
    print("\n" + "=" * 60)
    print("  TYPE B — fresh connection B, get new nonce, send auth")
    print("=" * 60)
    try:
        connB = socket.create_connection((ip, port), timeout=timeout)
        print("  Opened connection B")
    except OSError as e:
        print(f"  FAILED to open connection B: {e}")
        return

    connB.sendall(req1)  # reuse same unauthenticated req
    print("  Sent CSeq 1 (no auth) on connB")
    resp_b1 = recv_full(connB, "connB")
    status_b1 = rtsp_status(resp_b1)
    print(f"  Status: {status_b1}")
    for line in resp_b1.split("\r\n")[:8]:
        if line: print(f"    {line}")

    if status_b1 != 401:
        print(f"  ⚠️  connB did not return 401 (got {status_b1}) — cannot proceed")
        connB.close()
        return

    challenge_b = parse_challenge(resp_b1)
    print(f"\n  Fresh challenge: {challenge_b}")

    if challenge_b and challenge_b[0] == "digest":
        auth_hdr_b = make_digest(user, pw, "DESCRIBE", url, challenge_b[1])
    else:
        auth_hdr_b = make_basic(user, pw)

    req_b2 = (f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 2\r\n"
              f"User-Agent: Phase2Debug/1.0\r\nAccept: application/sdp\r\n"
              f"{auth_hdr_b}\r\n").encode()
    print(f"  Auth header: {auth_hdr_b.strip()}")
    try:
        connB.sendall(req_b2)
        print("  Sent CSeq 2 (with auth) on connB")
        resp_b2 = recv_full(connB, "connB-auth")
        status_b2 = rtsp_status(resp_b2)
        print(f"  Status: {status_b2}")
        for line in resp_b2.split("\r\n")[:6]:
            if line: print(f"    {line}")
        if status_b2 == 200:
            print(f"\n  ✅ Type B SUCCESS!")
            print(f"     rtsp://{user}:{pw}@{ip}:{port}{args.path}")
        else:
            print(f"\n  ❌ Type B also failed (status={status_b2})")
            print(f"     The credentials are wrong, OR the Digest computation is incorrect")
    except OSError as e:
        print(f"  Type B OSError on CSeq 2: {e}")
    finally:
        try: connB.close()
        except: pass

if __name__ == "__main__":
    main()