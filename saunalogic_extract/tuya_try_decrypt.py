#!/usr/bin/env python3
"""
Try to decrypt Tuya/Thing "3.3" LAN packets (55aa...aa55 framing) using a known localKey.

This is a pragmatic brute-force helper:
- verifies CRC32 (as observed in docs/saunalogic-pcap-notes.md)
- locates the "3.3" marker inside the payload
- tries common offsets to find an AES-128-ECB + PKCS7 plaintext that parses as JSON

Dependencies:
- Python stdlib only
- `openssl` available on PATH

Usage:
  python3 saunalogic_extract/tuya_try_decrypt.py --key "HSt;vM1?ZKRvG9u'" --hex "<packethex>"
"""

from __future__ import annotations

import argparse
import binascii
import json
import subprocess
import sys
import textwrap
import zlib


def eprint(*a: object) -> None:
    print(*a, file=sys.stderr)


def openssl_aes_128_ecb_decrypt(ciphertext: bytes, key_ascii: str) -> bytes | None:
    # openssl requires hex key with -K
    key_hex = key_ascii.encode("utf-8").hex()
    try:
        p = subprocess.run(
            [
                "openssl",
                "enc",
                "-aes-128-ecb",
                "-d",
                "-K",
                key_hex,
                "-nosalt",
            ],
            input=ciphertext,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError:
        raise SystemExit("openssl not found on PATH")
    if p.returncode != 0:
        return None
    return p.stdout


def parse_packet(hex_str: str) -> bytes:
    s = hex_str.strip().replace(" ", "").replace("\n", "").replace("\t", "")
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    try:
        return binascii.unhexlify(s)
    except Exception as ex:
        raise SystemExit(f"Invalid hex: {ex}")


def crc32_be(data: bytes) -> bytes:
    # CRC32 as big-endian bytes (matches notes: f39f406f)
    v = zlib.crc32(data) & 0xFFFFFFFF
    return v.to_bytes(4, "big")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True, help="Tuya/Thing localKey (ASCII; typically 16 chars)")
    ap.add_argument("--hex", required=True, help="Full packet hex including 55aa prefix and aa55 tail")
    args = ap.parse_args()

    pkt = parse_packet(args.hex)
    if len(pkt) < 24:
        eprint("Packet too short")
        return 2

    if pkt[0:4] != b"\x00\x00\x55\xaa":
        eprint(f"Unexpected prefix: {pkt[0:4].hex()}")
    if pkt[-4:] != b"\x00\x00\xaa\x55":
        eprint(f"Unexpected suffix: {pkt[-4:].hex()}")

    # Verify CRC: bytes [-8:-4] are CRC32(packet[:-8])
    expected_crc = pkt[-8:-4]
    actual_crc = crc32_be(pkt[:-8])
    if expected_crc != actual_crc:
        eprint(f"CRC mismatch: expected={expected_crc.hex()} actual={actual_crc.hex()}")
    else:
        print(f"[ok] CRC32 matches: {expected_crc.hex()}")

    # Tuya header is 16 bytes, body length is stored at bytes 12..15 (big-endian)
    body_len = int.from_bytes(pkt[12:16], "big")
    body = pkt[16 : 16 + body_len]
    print(f"[info] body_len={body_len} actual_body_bytes={len(body)}")

    # Find version marker (optional; some message types do not include it)
    idx = body.find(b"3.3")
    if idx >= 0:
        print(f"[info] found '3.3' at body offset {idx}")
    else:
        print("[info] no '3.3' marker found in body (this is normal for some message types, e.g. cmd=10).")

    def score_plaintext(pt: bytes) -> float:
        if not pt:
            return 0.0
        printable = sum(1 for b in pt if b in b"\r\n\t" or (32 <= b < 127))
        return printable / float(len(pt))

    def looks_zlib(pt: bytes) -> bool:
        return len(pt) >= 2 and pt[0] == 0x78 and pt[1] in (0x01, 0x9C, 0xDA)

    # Brute offsets and also tolerate a few trailing bytes (some formats append fields).
    # We search for:
    # - valid JSON plaintext (best)
    # - zlib-like plaintext header
    # - otherwise: high printable ratio (weak signal)
    candidates: list[tuple[str, int, int, float, object | None, bytes]] = []
    tail_trims = [0, 1, 2, 3, 4, 8, 12, 16]
    # If we have a marker, bias search near it; otherwise search broadly.
    if idx >= 0:
        start_min = max(0, idx - 8)
        start_max = min(len(body), idx + 3 + 12 + 80)
    else:
        start_min = 0
        start_max = min(len(body), 256)
    for start in range(start_min, start_max):
        for trim in tail_trims:
            end = len(body) - trim
            if end <= start:
                continue
            ct = body[start:end]
            if len(ct) % 16 != 0:
                continue
            pt = openssl_aes_128_ecb_decrypt(ct, args.key)
            if not pt:
                continue
            pt2 = pt.strip(b"\x00").strip()

            # Try JSON
            j = None
            if b"{" in pt2 and b"}" in pt2:
                try:
                    j = json.loads(pt2.decode("utf-8", "ignore"))
                    candidates.append(("json", start, end, 1.0, j, pt2[:300]))
                    continue
                except Exception:
                    pass

            # Try zlib header detection
            if looks_zlib(pt2):
                candidates.append(("zlib", start, end, 0.9, None, pt2[:64]))
                continue

            # Fallback: printable ratio
            s = score_plaintext(pt2)
            if s >= 0.70:
                candidates.append(("printable", start, end, s, None, pt2[:200]))

    if not candidates:
        print(
            textwrap.dedent(
                """\
                [miss] No plausible plaintext found via AES-128-ECB brute offsets.
                This can mean:
                - wrong localKey for this device
                - payload is not AES-ECB (or has an IV / different mode)
                - plaintext is compressed/packed and doesn't look like JSON/plaintext
                - the encrypted region is embedded (not a clean [start:end] slice)
                """
            ).rstrip()
        )
        return 0

    # Prefer json > zlib > printable, and longest ciphertext.
    kind_rank = {"json": 3, "zlib": 2, "printable": 1}
    candidates.sort(key=lambda x: (kind_rank.get(x[0], 0), x[3], x[2] - x[1]), reverse=True)

    kind, start, end, score, j, preview = candidates[0]
    print(f"[hit] kind={kind} start={start} end={end} ct_len={end-start} score={score:.2f}")
    if kind == "json" and isinstance(j, dict):
        print("[hit] JSON keys:", ", ".join(sorted(map(str, j.keys()))[:30]))
    print("[hit] preview (utf-8-ish):", preview.decode("utf-8", "ignore"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

