#!/usr/bin/env python3
"""
Diagnostic script to compare Python vs C# Type-7 frame generation.
This replicates the EXACT C# logic to identify differences.
"""

import binascii
import struct
import time

# ==== C# CRC32 REPLICATION (initial=0, no final XOR) ====
def build_crc32_table():
    poly = 0xEDB88320
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            if c & 1:
                c = poly ^ (c >> 1)
            else:
                c = c >> 1
        table.append(c)
    return table

CRC32_TABLE = build_crc32_table()

def crc32_csharp_style(data: bytes) -> int:
    """Replicates the C# SaunaCrc32.Compute - initial=0, no final XOR"""
    crc = 0x00000000
    for b in data:
        crc = CRC32_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc

def crc32_python_style(data: bytes) -> int:
    """Standard CRC32 (zlib/IEEE) - what Python binascii.crc32 uses"""
    return binascii.crc32(data) & 0xFFFFFFFF


# ==== Frame building ====
def write_u32_be(buf: bytearray, offset: int, value: int):
    buf[offset:offset+4] = struct.pack(">I", value)

def build_frame(cmd: int, payload: bytes, prefix: bytes, use_csharp_crc: bool) -> bytes:
    payload_len = len(prefix) + len(payload)
    len_field = payload_len + 8
    total_len = 16 + len_field
    
    frame = bytearray(total_len)
    write_u32_be(frame, 0, 0x000055AA)
    seq = int(time.time() * 1000) & 0xFFFFFFFF
    write_u32_be(frame, 4, seq)
    write_u32_be(frame, 8, cmd)
    write_u32_be(frame, 12, len_field)
    
    frame[16:16+len(prefix)] = prefix
    frame[16+len(prefix):16+len(prefix)+len(payload)] = payload
    
    # CRC computation - the key difference!
    if use_csharp_crc:
        crc = crc32_csharp_style(bytes(frame[:-8]))
    else:
        crc = crc32_python_style(bytes(frame[:-8]))
    
    write_u32_be(frame, len(frame) - 8, crc)
    write_u32_be(frame, len(frame) - 4, 0x0000AA55)
    return bytes(frame)


def main():
    print("=" * 60)
    print("DIAGNOSTIC: Comparing Python vs C# CRC32 implementations")
    print("=" * 60)
    
    # Test data (the Type-10 query payload without CRC/tail)
    test_frame_hex = (
        "000055aa000005950000000a00000048"
        "462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da222"
        "13e58805e31f87ed159506545b2366e98b06c2f6f0199f8a2f35996f580cd2bb"
    )
    test_data = binascii.unhexlify(test_frame_hex)
    
    # The known good CRC from the captured frame
    known_crc_hex = "ab2eb66f"
    known_crc = int(known_crc_hex, 16)
    
    crc_python = crc32_python_style(test_data)
    crc_csharp = crc32_csharp_style(test_data)
    
    print(f"\nTest data ({len(test_data)} bytes): frame[:-8] from Type-10 query")
    print(f"Known good CRC from PCAP:  0x{known_crc:08X}")
    print(f"Python CRC32 (standard):   0x{crc_python:08X}  {'✓ MATCH' if crc_python == known_crc else '✗ WRONG'}")
    print(f"C# CRC32 (init=0, no XOR): 0x{crc_csharp:08X}  {'✓ MATCH' if crc_csharp == known_crc else '✗ WRONG'}")
    
    if crc_python != crc_csharp:
        print("\n" + "!" * 60)
        print("!!! CRC32 MISMATCH - This is likely why C# commands fail !!!")
        print("!" * 60)
        print("\nThe C# SaunaCrc32 implementation uses:")
        print("  - Initial value: 0x00000000  (should be 0xFFFFFFFF)")
        print("  - Final XOR: none            (should be 0xFFFFFFFF)")
    
    # Now test with a simple known value
    print("\n" + "-" * 60)
    print("Additional CRC test with simple data:")
    simple_data = b"hello"
    print(f"  Data: {simple_data}")
    print(f"  Python CRC32: 0x{crc32_python_style(simple_data):08X}")
    print(f"  C# CRC32:     0x{crc32_csharp_style(simple_data):08X}")
    
    # Show what the fix should be
    print("\n" + "=" * 60)
    print("RECOMMENDED FIX for SaunaCrc32.cs:")
    print("=" * 60)
    print("""
Change SaunaCrc32.Compute() from:

    uint crc = 0x00000000u;           // WRONG
    for (int i = 0; i < count; i++)
    {
        var b = data[offset + i];
        crc = Table[(crc ^ b) & 0xFFu] ^ (crc >> 8);
    }
    return crc;                       // WRONG - missing final XOR

To:

    uint crc = 0xFFFFFFFFu;           // CORRECT initial value
    for (int i = 0; i < count; i++)
    {
        var b = data[offset + i];
        crc = Table[(crc ^ b) & 0xFFu] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;         // CORRECT final XOR
""")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
