#!/usr/bin/env python3
"""
RTSP Auth Debugger
------------------
Probes a single camera's RTSP endpoint and prints every byte of the
exchange so you can see exactly what auth scheme the camera uses,
what parameters it sends, and whether credentials are accepted.

Usage:
    python debug_rtsp.py --ip 192.168.1.194 --port 554 \
                         --path /live/ch00_0 \
                         --user admin --password admin123
"""

import argparse
import base64
import hashlib
import re
import socket


def recv_full(sock):
    """Read until we have a complete RTSP response header block."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="replace")


def send_describe(ip, port, timeout, url, cseq, auth_header="", sock=None):
    """
    Send one RTSP DESCRIBE.
    If sock is provided, reuse it (same TCP connection).
    If sock is None, open a fresh TCP connection.
    """
    req = (
        f"DESCRIBE {url} RTSP/1.0\r\n"
        f"CSeq: {cseq}\r\n"
        f"User-Agent: RTSPDebugger/1.0\r\n"
        f"Accept: application/sdp\r\n"
        f"{auth_header}"
        f"\r\n"
    )
    conn_note = "reusing connection" if sock else "fresh TCP connection"
    print(f"\n{'='*60}")
    print(f"  REQUEST  (CSeq {cseq}, {conn_note})")
    print(f"{'='*60}")
    print(req.rstrip())

    if sock:
        sock.sendall(req.encode())
        resp = recv_full(sock)
    else:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(req.encode())
            resp = recv_full(s)

    print(f"\n{'='*60}")
    print(f"  RESPONSE (CSeq {cseq})")
    print(f"{'='*60}")
    print(resp.rstrip())
    return resp


def parse_www_authenticate(response):
    """Parse WWW-Authenticate header, return (scheme, params) or None."""
    m = re.search(r'WWW-Authenticate:\s*(\w+)\s*(.*)', response, re.I)
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


def make_digest_auth(user, password, method, uri, params):
    realm = params.get("realm", "")
    nonce = params.get("nonce", "")
    qop   = params.get("qop", "").strip()
    ha1   = hashlib.md5(f"{user}:{realm}:{password}".encode()).hexdigest()
    ha2   = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    print(f"\n  [Digest] realm  = {repr(realm)}")
    print(f"  [Digest] nonce  = {repr(nonce)}")
    print(f"  [Digest] qop    = {repr(qop)}")
    print(f"  [Digest] HA1    = MD5({user}:{realm}:{password}) = {ha1}")
    print(f"  [Digest] HA2    = MD5({method}:{uri}) = {ha2}")

    if qop == "auth":
        cnonce = "4b6f6172616e6d69"
        nc     = "00000001"
        resp_hash = hashlib.md5(
            f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()
        ).hexdigest()
        print(f"  [Digest] response = MD5({ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}) = {resp_hash}")
        return (
            f'Authorization: Digest username="{user}", realm="{realm}", '
            f'nonce="{nonce}", uri="{uri}", qop={qop}, nc={nc}, '
            f'cnonce="{cnonce}", response="{resp_hash}"\r\n'
        )
    else:
        resp_hash = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        print(f"  [Digest] response = MD5({ha1}:{nonce}:{ha2}) = {resp_hash}")
        return (
            f'Authorization: Digest username="{user}", realm="{realm}", '
            f'nonce="{nonce}", uri="{uri}", response="{resp_hash}"\r\n'
        )


def make_basic_auth(user, password):
    b64 = base64.b64encode(f"{user}:{password}".encode()).decode()
    print(f"\n  [Basic] base64({user}:{password}) = {b64}")
    return f"Authorization: Basic {b64}\r\n"


def main():
    parser = argparse.ArgumentParser(description="RTSP Auth Debugger")
    parser.add_argument("--ip",       required=True)
    parser.add_argument("--port",     type=int, default=554)
    parser.add_argument("--path",     default="/")
    parser.add_argument("--user",     default="admin")
    parser.add_argument("--password", default="admin")
    parser.add_argument("--timeout",  type=float, default=5.0)
    parser.add_argument("--preauth",  action="store_true",
                        help="Send Basic auth on first request without waiting for 401 challenge")
    args = parser.parse_args()

    url = f"rtsp://{args.ip}:{args.port}{args.path}"
    print(f"\n  RTSP Auth Debugger")
    print(f"  Target : {url}")
    print(f"  User   : {args.user}")
    print(f"  Pass   : {args.password}")

    # ── Step 1: open connection and send unauthenticated probe ──────────
    if args.preauth:
        print("\n  → --preauth mode: sending Basic auth on first request (no challenge)")
        import base64 as _b64
        b64 = _b64.b64encode(f"{args.user}:{args.password}".encode()).decode()
        auth_header_pre = f"Authorization: Basic {b64}\r\n"
        try:
            conn = socket.create_connection((args.ip, args.port), timeout=args.timeout)
            resp = send_describe(args.ip, args.port, args.timeout, url, cseq=1,
                                 auth_header=auth_header_pre, sock=conn)
            conn.close()
        except OSError as e:
            print(f"\n  ERROR: {e}")
            return
        print("\n" + "=" * 60)
        print("  VERDICT (preauth)")
        print("=" * 60)
        if "RTSP/1.0 200" in resp or "RTSP/1.1 200" in resp:
            print(f"  ✅ SUCCESS — Basic auth accepted on first request!")
            print(f"     Working URL: rtsp://{args.user}:{args.password}@{args.ip}:{args.port}{args.path}")
        elif "RTSP/1.0 401" in resp:
            print(f"  → Camera sent 401 challenge in response to Basic auth")
            print(f"     This camera requires Digest auth — run without --preauth")
        else:
            print(f"  ⚠️  Unexpected response — check output above")
        print()
        return

    try:
        conn = socket.create_connection((args.ip, args.port), timeout=args.timeout)
    except OSError as e:
        print(f"\n  ERROR: Could not connect — {e}")
        return

    try:
        resp1 = send_describe(args.ip, args.port, args.timeout, url, cseq=1, sock=conn)
    except OSError as e:
        print(f"\n  ERROR: Send failed — {e}")
        conn.close()
        return

    if "RTSP/1.0 200" in resp1 or "RTSP/1.1 200" in resp1:
        print("\n  ✅ Stream is OPEN — no authentication required!")
        conn.close()
        return

    if "RTSP/1.0 404" in resp1 or "RTSP/1.1 404" in resp1:
        print("\n  ❌ Path not found (404) — try a different --path")
        conn.close()
        return

    if "RTSP/1.0 401" not in resp1 and "RTSP/1.1 401" not in resp1:
        print("\n  ⚠️  Unexpected response — not 200, 401, or 404.")
        conn.close()
        return

    print("\n  → Got 401. Parsing WWW-Authenticate challenge ...")

    # ── Step 2: parse challenge ───────────────────────────────────────
    challenge = parse_www_authenticate(resp1)
    if challenge is None:
        print("  ⚠️  No WWW-Authenticate header found in 401 response!")
        print("  Falling back to Basic auth anyway ...")
        auth_header = make_basic_auth(args.user, args.password)
    else:
        scheme, params = challenge
        print(f"\n  Auth scheme : {scheme.upper()}")
        print(f"  Params      : {params}")
        if scheme == "digest":
            auth_header = make_digest_auth(
                args.user, args.password, "DESCRIBE", url, params
            )
        else:
            auth_header = make_basic_auth(args.user, args.password)

    # ── Step 3: try auth on the SAME connection first ─────────────────
    print(f"\n  → Attempt A: sending auth on SAME connection ...")
    resp2 = None
    try:
        resp2 = send_describe(args.ip, args.port, args.timeout, url,
                              cseq=2, auth_header=auth_header, sock=conn)
    except OSError as e:
        print(f"  Same-connection attempt failed: {e}")
    finally:
        conn.close()

    # ── Step 4: if same-connection gave empty/no response, try fresh conn ──
    if not resp2 or (
        "RTSP/1.0 200" not in resp2 and "RTSP/1.1 200" not in resp2 and
        "RTSP/1.0 401" not in resp2 and "RTSP/1.1 401" not in resp2
    ):
        print(f"\n  → Attempt B: same connection gave no useful response.")
        print(f"     Camera likely closed socket after 401.")
        print(f"     Retrying auth on a FRESH connection with the same nonce ...")
        try:
            resp2 = send_describe(args.ip, args.port, args.timeout, url,
                                  cseq=2, auth_header=auth_header)
        except OSError as e:
            print(f"\n  ERROR: Fresh connection also failed — {e}")
            return

    # ── Final verdict ─────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  VERDICT")
    print("=" * 60)
    if "RTSP/1.0 200" in resp2 or "RTSP/1.1 200" in resp2:
        print(f"  ✅ SUCCESS — credentials accepted!")
        print(f"     Working URL: rtsp://{args.user}:{args.password}@{args.ip}:{args.port}{args.path}")
    elif "RTSP/1.0 401" in resp2 or "RTSP/1.1 401" in resp2:
        print(f"  ❌ FAILED — credentials rejected (still 401 after auth attempt)")
        print(f"     This means the username/password is wrong, OR")
        print(f"     the auth hash was computed incorrectly.")
    elif "RTSP/1.0 403" in resp2:
        print(f"  ❌ FORBIDDEN (403) — credentials may be correct but access denied")
    else:
        print(f"  ⚠️  Unexpected final response — check the raw output above")
    print()


if __name__ == "__main__":
    main()