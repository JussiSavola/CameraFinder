#!/usr/bin/env python3
"""
RTSP Path Prober
----------------
Shows exactly what HTTP status code each known RTSP path returns
on a given camera, WITHOUT credentials. This reveals whether a camera
returns 404 for nonexistent paths (well-behaved) or 401 for everything
(common on cheap Chinese firmware — it authenticates before revealing
whether a path exists).

Usage:
    python rtsp_paths_probe.py --ip 192.168.1.148 --port 554
"""
import argparse
import re
import socket

RTSP_PATHS = [
    "/",
    "/live/ch00_0",
    "/live/ch00_1",
    "/live/ch01_0",
    "/Streaming/Channels/101",
    "/Streaming/Channels/102",
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
    "/cam/realmonitor?channel=1&subtype=0",
    "/cam/realmonitor?channel=1&subtype=1",
    "/h264/ch1/main/av_stream",
    "/h264/ch1/sub/av_stream",
    "/onvif/profile1/media.smp",
    "/onvif/profile2/media.smp",
    "/MediaInput/h264",
    "/11",
    "/12",
    "/1",
    "/0",
    "/nonexistent_path_xyz",   # control: should be 404 on well-behaved cameras
]

def rtsp_status(resp):
    m = re.search(r"RTSP/1\.[01]\s+(\d+)\s+(\w.*)", resp)
    if m:
        return int(m.group(1)), m.group(2).strip()
    return None, "no status"

def recv_full(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="replace")

def probe(ip, port, timeout, path, cseq):
    url = f"rtsp://{ip}:{port}{path}"
    req = (
        f"DESCRIBE {url} RTSP/1.0\r\n"
        f"CSeq: {cseq}\r\n"
        f"User-Agent: PathProber/1.0\r\n"
        f"Accept: application/sdp\r\n"
        f"\r\n"
    ).encode()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(req)
            resp = recv_full(s)
            code, text = rtsp_status(resp)
            return code, text
    except OSError as e:
        return None, f"connection error: {e}"

def main():
    parser = argparse.ArgumentParser(description="RTSP Path Prober")
    parser.add_argument("--ip",      required=True)
    parser.add_argument("--port",    type=int, default=554)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()

    print(f"\n  RTSP Path Prober — {args.ip}:{args.port}")
    print(f"  (probing {len(RTSP_PATHS)} paths without credentials)\n")
    print(f"  {'PATH':<45} {'STATUS'}")
    print(f"  {'-'*44} {'-'*20}")

    status_counts = {}
    for i, path in enumerate(RTSP_PATHS, start=1):
        code, text = probe(args.ip, args.port, args.timeout, path, i)
        marker = ""
        if code == 200:
            marker = " ← OPEN STREAM"
        elif code == 401:
            marker = " ← auth required (path EXISTS)"
        elif code == 404:
            marker = " ← not found"
        elif code is None:
            marker = ""

        print(f"  {path:<45} {code or '???'} {text}{marker}")
        status_counts[code] = status_counts.get(code, 0) + 1

    print(f"\n  Summary: {status_counts}")

    if status_counts.get(401, 0) == len(RTSP_PATHS):
        print("\n  ⚠️  Camera returns 401 for EVERY path including nonexistent ones.")
        print("     This firmware authenticates before revealing path existence.")
        print("     The scanner cannot use 401/404 to distinguish real paths.")
        print("     → Must brute-force credentials against ALL paths, not just 401s.")
    elif status_counts.get(404, 0) > 0:
        print("\n  ✅ Camera returns 404 for nonexistent paths — path discovery works correctly.")

if __name__ == "__main__":
    main()