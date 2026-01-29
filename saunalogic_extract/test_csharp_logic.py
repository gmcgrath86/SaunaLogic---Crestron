#!/usr/bin/env python3
"""
This script EXACTLY replicates the C# SaunaLogicClient logic with the fixes applied.
It tests whether the C# code changes will work against the real device.

This is a 1:1 port of the C# code, NOT the original Python helper.
"""

import socket
import time
import struct

# ============================================================================
# EXACT PORT OF SaunaCrc32.cs (WITH FIX APPLIED)
# ============================================================================
class SaunaCrc32:
    """Exact port of C# SaunaCrc32 class with the fix applied"""
    
    _table = None
    
    @classmethod
    def _build_table(cls):
        table = []
        poly = 0xEDB88320
        for i in range(256):
            c = i
            for _ in range(8):
                if c & 1:
                    c = poly ^ (c >> 1)
                else:
                    c = c >> 1
            table.append(c)
        return table
    
    @classmethod
    def compute(cls, data: bytes, offset: int, count: int) -> int:
        """Exact port of SaunaCrc32.Compute() WITH THE FIX"""
        if cls._table is None:
            cls._table = cls._build_table()
        
        # FIX APPLIED: Changed from 0x00000000 to 0xFFFFFFFF
        crc = 0xFFFFFFFF
        
        for i in range(count):
            b = data[offset + i]
            crc = cls._table[(crc ^ b) & 0xFF] ^ (crc >> 8)
        
        # FIX APPLIED: Added final XOR with 0xFFFFFFFF
        return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF


# ============================================================================
# EXACT PORT OF SaunaTuyaFrame.cs
# ============================================================================
class SaunaTuyaFrame:
    """Exact port of C# SaunaTuyaFrame class"""
    
    PREFIX = 0x000055AA
    TAIL = 0x0000AA55
    
    @staticmethod
    def write_u32_be(buf: bytearray, offset: int, value: int):
        """Exact port of WriteU32BE"""
        buf[offset + 0] = (value >> 24) & 0xFF
        buf[offset + 1] = (value >> 16) & 0xFF
        buf[offset + 2] = (value >> 8) & 0xFF
        buf[offset + 3] = value & 0xFF
    
    @staticmethod
    def read_u32_be(buf: bytes, offset: int) -> int:
        """Exact port of ReadU32BE"""
        return (
            (buf[offset + 0] << 24) |
            (buf[offset + 1] << 16) |
            (buf[offset + 2] << 8) |
            buf[offset + 3]
        )
    
    @classmethod
    def build_frame(cls, seq: int, cmd: int, payload: bytes, payload_prefix: bytes) -> bytes:
        """Exact port of BuildFrame"""
        if payload is None:
            payload = b''
        if payload_prefix is None:
            payload_prefix = b''
        
        payload_len = len(payload_prefix) + len(payload)
        len_field = payload_len + 8  # crc32 + tail
        total_len = 16 + len_field
        
        frame = bytearray(total_len)
        cls.write_u32_be(frame, 0, cls.PREFIX)
        cls.write_u32_be(frame, 4, seq & 0xFFFFFFFF)
        cls.write_u32_be(frame, 8, cmd & 0xFFFFFFFF)
        cls.write_u32_be(frame, 12, len_field)
        
        # payload
        frame[16:16+len(payload_prefix)] = payload_prefix
        frame[16+len(payload_prefix):16+len(payload_prefix)+len(payload)] = payload
        
        # CRC32(frame[:-8]) big-endian
        crc = SaunaCrc32.compute(bytes(frame), 0, len(frame) - 8)
        cls.write_u32_be(frame, len(frame) - 8, crc)
        
        # tail
        cls.write_u32_be(frame, len(frame) - 4, cls.TAIL)
        return bytes(frame)
    
    @classmethod
    def try_parse_one_frame(cls, buffer: bytes, offset: int, count: int):
        """Exact port of TryParseOneFrame - returns (success, frame_start, frame_len)"""
        if buffer is None or count < 16:
            return False, -1, 0
        
        for i in range(offset, offset + count - 15):
            if (buffer[i] == 0x00 and buffer[i+1] == 0x00 and 
                buffer[i+2] == 0x55 and buffer[i+3] == 0xAA):
                len_field = cls.read_u32_be(buffer, i + 12)
                total = 16 + len_field
                if total <= 0:
                    continue
                if i + total <= offset + count:
                    return True, i, total
        return False, -1, 0


# ============================================================================
# EXACT PORT OF SaunaCrypto.cs + SaunaAes128EcbPkcs7.cs
# ============================================================================
import subprocess

class SaunaCrypto:
    """Exact port of C# SaunaCrypto class - uses openssl for AES"""
    
    @staticmethod
    def aes_128_ecb_encrypt(local_key_ascii: str, plaintext: bytes) -> bytes:
        """Exact port of Aes128EcbEncrypt with PKCS7 padding (via openssl)"""
        key = local_key_ascii.encode('ascii')
        if len(key) != 16:
            raise ValueError("localKey must be 16 ASCII bytes")
        
        key_hex = key.hex()
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
    
    @staticmethod
    def aes_128_ecb_decrypt(local_key_ascii: str, ciphertext: bytes) -> bytes:
        """Exact port of Aes128EcbDecrypt with PKCS7 unpadding (via openssl)"""
        key = local_key_ascii.encode('ascii')
        if len(key) != 16:
            raise ValueError("localKey must be 16 ASCII bytes")
        
        key_hex = key.hex()
        p = subprocess.run(
            ["openssl", "enc", "-aes-128-ecb", "-d", "-K", key_hex, "-nosalt"],
            input=ciphertext,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if p.returncode != 0:
            raise RuntimeError("openssl decrypt failed: " + p.stderr.decode("utf-8", "ignore"))
        return p.stdout


# ============================================================================
# EXACT PORT OF SaunaLogicClient.cs (WITH FIXES APPLIED)
# ============================================================================
class SaunaLogicClient:
    """Exact port of C# SaunaLogicClient class with fixes applied"""
    
    # Captured Type-10 DP snapshot query
    TYPE10_DP_SNAPSHOT_QUERY = bytes.fromhex(
        "000055aa000005950000000a00000048"
        "462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da222"
        "13e58805e31f87ed159506545b2366e98b06c2f6f0199f8a2f35996f580cd2bbab2eb66f"
        "0000aa55"
    )
    
    # Type-7 payload prefix - exact same as C#
    TYPE7_PREFIX_15 = bytes.fromhex("332e33000000000000000300000000")
    
    def __init__(self):
        self.host = ""
        self.port = 6668
        self.local_key = ""
        self.dev_id = ""
        self.uid = ""
    
    def _build_dps_write_json(self, dps_key: str, raw_value: str) -> str:
        """Exact port of BuildDpsWriteJson"""
        t = int(time.time())
        
        result = '{"devId":"' + (self.dev_id or "") + '","dps":{'
        result += '"' + dps_key + '":' + raw_value
        result += '},"t":' + str(t)
        if self.uid:
            result += ',"uid":"' + self.uid + '"'
        result += '}'
        return result
    
    def _build_dps_write_json_with_mode(self, dps_key: str, raw_value: str, 
                                         mode_key: str, mode_value: str) -> str:
        """Exact port of BuildDpsWriteJsonWithMode"""
        t = int(time.time())
        
        result = '{"devId":"' + (self.dev_id or "") + '","dps":{'
        result += '"' + dps_key + '":' + raw_value
        result += ',"' + mode_key + '":"' + mode_value + '"'
        result += '},"t":' + str(t)
        if self.uid:
            result += ',"uid":"' + self.uid + '"'
        result += '}'
        return result
    
    def _wait_for_cmd10(self, sock: socket.socket, timeout_ms: int) -> bool:
        """Exact port of WaitForCmd10"""
        buf = bytearray(4096)
        have = 0
        deadline = time.time() + (timeout_ms / 1000.0)
        
        sock.setblocking(False)
        
        while time.time() < deadline:
            try:
                data = sock.recv(4096)
                if data:
                    buf[have:have+len(data)] = data
                    have += len(data)
            except BlockingIOError:
                time.sleep(0.01)
                continue
            except Exception:
                time.sleep(0.01)
                continue
            
            success, start, length = SaunaTuyaFrame.try_parse_one_frame(bytes(buf), 0, have)
            if success:
                cmd = SaunaTuyaFrame.read_u32_be(buf, start + 8)
                if cmd == 10:
                    return True
                # Drop consumed frame
                remaining = have - (start + length)
                if remaining > 0:
                    buf[0:remaining] = buf[start+length:start+length+remaining]
                have = max(0, remaining)
        
        return False
    
    def _send_type7_with_handshake(self, ct: bytes, prefix: bytes) -> tuple:
        """Exact port of SendType7WithHandshakeAndRetry"""
        last_error = None
        
        for attempt in range(2):
            sock = None
            try:
                seq = int(time.time() * 1000) & 0xFFFFFFFF
                frame = SaunaTuyaFrame.build_frame(seq, 7, ct, prefix)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((self.host, self.port))
                
                # Type-10 snapshot query first (mirrors app behavior)
                sock.sendall(self.TYPE10_DP_SNAPSHOT_QUERY)
                
                # Wait for cmd=10 response
                got10 = self._wait_for_cmd10(sock, 4000)
                if not got10:
                    raise Exception("Handshake timeout: no cmd=10 response.")
                
                # Send command frame
                sock.setblocking(True)
                sock.settimeout(2.0)
                sock.sendall(frame)
                
                # Best-effort read response
                try:
                    sock.recv(4096)
                except:
                    pass
                
                sock.close()
                return True, None
                
            except Exception as ex:
                last_error = str(ex)
                if sock:
                    try:
                        sock.close()
                    except:
                        pass
        
        return False, last_error or "SendType7 failed."
    
    def _send_type7_json(self, json_str: str) -> tuple:
        """Exact port of SendType7Json WITH THE OFFSET FIX"""
        if not self.local_key or len(self.local_key) != 16:
            return False, "LocalKey must be 16 chars."
        if not self.host:
            return False, "Host empty."
        if not self.dev_id:
            return False, "DevId empty."
        
        # Encrypt JSON with AES-128-ECB
        pt = json_str.encode('utf-8')
        ct = SaunaCrypto.aes_128_ecb_encrypt(self.local_key, pt)
        
        # Build prefix - exact same as C#
        prefix = bytearray(self.TYPE7_PREFIX_15)
        
        # FIX APPLIED: Changed from offset 12 to offset 11
        counter = int(time.time() * 1000) & 0xFFFFFFFF
        SaunaTuyaFrame.write_u32_be(prefix, 11, counter)  # <-- THE FIX: was 12, now 11
        
        return self._send_type7_with_handshake(ct, bytes(prefix))
    
    def send_heater_on(self, on: bool) -> tuple:
        """Exact port of SendHeaterOn"""
        json_str = self._build_dps_write_json_with_mode(
            "1", "true" if on else "false",
            "4", "ONLY_TRAD"
        )
        print(f"[C# Logic] JSON payload: {json_str}")
        return self._send_type7_json(json_str)


# ============================================================================
# TEST HARNESS
# ============================================================================
def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Test C# logic against real device")
    parser.add_argument("--host", default="192.168.1.100")
    parser.add_argument("--key", required=True)
    parser.add_argument("--devid", required=True)
    parser.add_argument("--uid", default="")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--on", action="store_true")
    group.add_argument("--off", action="store_true")
    args = parser.parse_args()
    
    print("=" * 60)
    print("TESTING EXACT C# LOGIC WITH FIXES APPLIED")
    print("=" * 60)
    print(f"Host: {args.host}")
    print(f"DevId: {args.devid}")
    print(f"Action: {'ON' if args.on else 'OFF'}")
    print()
    
    # Create client exactly like C# would
    client = SaunaLogicClient()
    client.host = args.host
    client.port = 6668
    client.local_key = args.key
    client.dev_id = args.devid
    client.uid = args.uid
    
    # Send command using exact C# logic
    success, error = client.send_heater_on(args.on)
    
    if success:
        print(f"\n✓ SUCCESS: Heater {'ON' if args.on else 'OFF'} command sent!")
    else:
        print(f"\n✗ FAILED: {error}")
    
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
