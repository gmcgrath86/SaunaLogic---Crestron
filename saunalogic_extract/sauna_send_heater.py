#!/usr/bin/env python3
"""
Send a heater on/off command to the SaunaLogic controller over LAN (Tuya 55aa framing).
"""

from __future__ import annotations

import argparse
import binascii
import socket
import subprocess
import time


DP_QUERY_REQ_HEX = (
    "000055aa000005950000000a00000048"
    "462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da222"
    "13e58805e31f87ed159506545b2366e98b06c2f6f0199f8a2f35996f580cd2bbab2eb66f"
    "0000aa55"
)

TYPE7_PREFIX_15 = binascii.unhexlify("332e33000000000000000300000000")


def write_u32_be(buf: bytearray, offset: int, value: int) -> None:
    buf[offset + 0] = (value >> 24) & 0xFF
    buf[offset + 1] = (value >> 16) & 0xFF
    buf[offset + 2] = (value >> 8) & 0xFF
    buf[offset + 3] = value & 0xFF


def crc32_ieee(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


def openssl_aes_128_ecb_encrypt(plaintext: bytes, key_ascii: str) -> bytes:
    key_hex = key_ascii.encode("utf-8").hex()
    p = subprocess.run(
        ["openssl", "enc", "-aes-128-ecb", "-e", "-K", key_hex, "-nosalt"],
        input=plaintext,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if p.returncode != 0:
        raise RuntimeError("openssl encrypt failed: " + p.stderr.decode("utf-8", "ignore"))
    return p.stdout


def build_frame(cmd: int, payload: bytes, payload_prefix: bytes) -> bytes:
    payload_len = len(payload_prefix) + len(payload)
    len_field = payload_len + 8  # crc + tail
    total_len = 16 + len_field

    frame = bytearray(total_len)
    write_u32_be(frame, 0, 0x000055AA)
    seq = int(time.time() * 1000) & 0xFFFFFFFF
    write_u32_be(frame, 4, seq)
    write_u32_be(frame, 8, cmd)
    write_u32_be(frame, 12, len_field)

    frame[16 : 16 + len(payload_prefix)] = payload_prefix
    frame[16 + len(payload_prefix) : 16 + len(payload_prefix) + len(payload)] = payload

    crc = crc32_ieee(bytes(frame[:-8]))
    write_u32_be(frame, len(frame) - 8, crc)
    write_u32_be(frame, len(frame) - 4, 0x0000AA55)
    return bytes(frame)


def parse_one_frame(buf: bytes) -> tuple[bytes | None, bytes]:
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


def build_dps_write_json(dev_id: str, uid: str | None, dps_key: str, value: str) -> str:
    t = int(time.time())
    if uid:
        return f'{{"devId":"{dev_id}","dps":{{"{dps_key}":{value}}},"t":{t},"uid":"{uid}"}}'
    return f'{{"devId":"{dev_id}","dps":{{"{dps_key}":{value}}},"t":{t}}}'


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.1.60")
    ap.add_argument("--port", type=int, default=6668)
    ap.add_argument("--key", required=True)
    ap.add_argument("--devid", required=True)
    ap.add_argument("--uid", default="")
    ap.add_argument("--mode", choices=["wait10", "fast"], default="wait10", help="wait10=wait for cmd=10 before cmd=7; fast=send cmd=7 immediately after Type-10")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--on", action="store_true")
    g.add_argument("--off", action="store_true")
    args = ap.parse_args()

    val = "true" if args.on else "false"
    json_body = build_dps_write_json(args.devid, args.uid or None, "1", val)
    ct = openssl_aes_128_ecb_encrypt(json_body.encode("utf-8"), args.key)

    prefix = bytearray(TYPE7_PREFIX_15)
    counter = int(time.time() * 1000) & 0xFFFFFFFF
    write_u32_be(prefix, 11, counter)

    frame = build_frame(7, ct, bytes(prefix))
    dp_query = binascii.unhexlify(DP_QUERY_REQ_HEX)

    s = socket.socket()
    s.settimeout(2.0)
    s.connect((args.host, args.port))
    s.sendall(dp_query)
    if args.mode == "wait10":
        # Read Type-10 response before sending command.
        buf = b""
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                data = s.recv(4096)
                if not data:
                    break
                buf += data
            except Exception:
                break
            while True:
                f, buf = parse_one_frame(buf)
                if f is None:
                    break
                cmd = int.from_bytes(f[8:12], "big")
                if cmd == 10:
                    deadline = 0  # stop waiting
                    break
    try:
        s.sendall(frame)
        try:
            s.recv(4096)
        except Exception:
            pass
        s.close()
    except BrokenPipeError:
        try:
            s.close()
        except Exception:
            pass
        # Reconnect and send command without waiting for response.
        s2 = socket.socket()
        s2.settimeout(2.0)
        s2.connect((args.host, args.port))
        s2.sendall(dp_query)
        s2.sendall(frame)
        try:
            s2.recv(4096)
        except Exception:
            pass
        s2.close()

    print("sent heater " + ("ON" if args.on else "OFF"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
