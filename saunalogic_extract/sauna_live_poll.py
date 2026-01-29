#!/usr/bin/env python3
"""
Live polling of SaunaLogic/TyloHelo controller over LAN (Tuya/Thing 55aa framing).

Key idea (from docs/saunalogic-pcap-notes.md):
- The "handshake" Type-10 (cmd=10) request/response is effectively a DP_QUERY that returns a full DPS snapshot.
- So polling is: TCP connect -> send Type-10 request -> read Type-10 response -> decrypt JSON -> interpret DPS.

No Android/emulator required at runtime.

Usage:
  python3 saunalogic_extract/sauna_live_poll.py --host <DEVICE_IP> --key "<LOCAL_KEY>"
"""

from __future__ import annotations

import argparse
import binascii
import json
import socket
import subprocess
import time
from typing import Any


# Captured Type-10 request (cmd=10) from docs/saunalogic-pcap-notes.md (Seq 0x0595).
# This appears to be sufficient to trigger a DP snapshot response on connect.
DP_QUERY_REQ_HEX = (
    "000055aa000005950000000a00000048"
    "462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da222"
    "13e58805e31f87ed159506545b2366e98b06c2f6f0199f8a2f35996f580cd2bbab2eb66f"
    "0000aa55"
)


def openssl_aes_128_ecb_decrypt(ciphertext: bytes, key_ascii: str) -> bytes | None:
    key_hex = key_ascii.encode("utf-8").hex()
    p = subprocess.run(
        ["openssl", "enc", "-aes-128-ecb", "-d", "-K", key_hex, "-nosalt"],
        input=ciphertext,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return p.stdout if p.returncode == 0 else None


def parse_one_frame(buf: bytes) -> tuple[bytes | None, bytes]:
    """
    Returns (frame_or_none, remaining_buf).
    Frame layout: prefix 000055aa, then LL at bytes 12..15, total_len = 16 + LL (LL includes crc+tail).
    """
    i = buf.find(b"\x00\x00\x55\xaa")
    if i < 0:
        return None, b""
    if i > 0:
        buf = buf[i:]
    if len(buf) < 16:
        return None, buf
    ll = int.from_bytes(buf[12:16], "big")
    total_len = 16 + ll
    if len(buf) < total_len:
        return None, buf
    return buf[:total_len], buf[total_len:]


def decrypt_frame_json(frame: bytes, local_key: str) -> dict[str, Any] | None:
    """
    Brute-decrypt body slices (AES-128-ECB) until we find JSON containing 'dps'.
    Works for cmd=7/8/10 in our captures.
    """
    ll = int.from_bytes(frame[12:16], "big")
    body = frame[16 : 16 + ll]

    tail_trims = (0, 4, 8, 12, 16)
    for start in range(0, min(len(body), 256)):
        for trim in tail_trims:
            end = len(body) - trim
            if end <= start:
                continue
            ct = body[start:end]
            if len(ct) == 0 or len(ct) % 16 != 0:
                continue
            pt = openssl_aes_128_ecb_decrypt(ct, local_key)
            if not pt:
                continue
            pt2 = pt.strip(b"\x00").strip()
            if b"{" not in pt2 or b"}" not in pt2:
                continue
            try:
                j = json.loads(pt2.decode("utf-8", "ignore"))
            except Exception:
                continue
            if isinstance(j, dict) and "dps" in j:
                return j
    return None


def dps_get(dps: dict[str, Any], key: str) -> Any:
    # DPS keys sometimes come as strings in JSON; normalize to str lookups.
    return dps.get(key)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.1.100")
    ap.add_argument("--port", type=int, default=6668)
    ap.add_argument("--key", required=True, help="Tuya/Thing localKey (ASCII; typically 16 chars)")
    ap.add_argument("--timeout", type=float, default=2.0)
    args = ap.parse_args()

    req = binascii.unhexlify(DP_QUERY_REQ_HEX)

    s = socket.socket()
    s.settimeout(args.timeout)
    s.connect((args.host, args.port))
    s.sendall(req)

    buf = b""
    deadline = time.time() + args.timeout
    got = None
    while time.time() < deadline and got is None:
        try:
            data = s.recv(4096)
            if not data:
                break
            buf += data
        except socket.timeout:
            break
        while True:
            frame, buf = parse_one_frame(buf)
            if frame is None:
                break
            cmd = int.from_bytes(frame[8:12], "big")
            if cmd != 10:
                # DP snapshot is usually cmd=10 response; ignore others.
                continue
            j = decrypt_frame_json(frame, args.key)
            if j:
                got = j
                break

    s.close()

    if not got:
        print("No decryptable DP snapshot received.")
        return 2

    dps = got.get("dps", {})
    heater = dps_get(dps, "1")
    setpoint = dps_get(dps, "2")
    temp = dps_get(dps, "3")

    print("devId:", got.get("devId"))
    print("heater_on(dps1):", heater)
    print("setpoint(dps2):", setpoint)
    print("temp(dps3):", temp)
    print("raw_dps:", dps)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

