# Testing C# Code Without .NET Runtime

This document describes a method for validating C# code changes against a real device when no .NET runtime (dotnet CLI, Mono, or Crestron processor) is available.

## The Problem

When developing Crestron SIMPL# modules on macOS/Linux:
- The code runs on a Crestron processor (proprietary .NET-like runtime)
- No local .NET runtime may be available for testing
- Deploying to hardware for every test is slow and impractical
- You need to validate fixes before rebuilding the `.clz` library

## The Solution: 1:1 Python Port

Create a Python script that **exactly replicates** the C# logic:
- Same class structure
- Same method signatures  
- Same byte-level operations
- Same algorithms

This allows testing the C# logic against real hardware without compilation.

## Implementation Steps

### 1. Port Each C# Class to Python

For each C# class, create an equivalent Python class with identical logic:

```python
# C# Original:
# public static void WriteU32BE(byte[] buf, int offset, uint value)
# {
#     buf[offset + 0] = (byte)((value >> 24) & 0xFF);
#     buf[offset + 1] = (byte)((value >> 16) & 0xFF);
#     buf[offset + 2] = (byte)((value >> 8) & 0xFF);
#     buf[offset + 3] = (byte)(value & 0xFF);
# }

# Python Port (exact same logic):
@staticmethod
def write_u32_be(buf: bytearray, offset: int, value: int):
    buf[offset + 0] = (value >> 24) & 0xFF
    buf[offset + 1] = (value >> 16) & 0xFF
    buf[offset + 2] = (value >> 8) & 0xFF
    buf[offset + 3] = value & 0xFF
```

### 2. Preserve Exact Behavior

Key principles:
- **Same byte operations**: Use `bytearray` for mutable byte buffers
- **Same integer handling**: Be explicit about masking (`& 0xFF`, `& 0xFFFFFFFF`)
- **Same control flow**: Mirror if/else, loops, try/catch structure
- **Same external calls**: Use equivalent libraries (e.g., `openssl` CLI for AES)

### 3. Test Against Real Device

Run the Python port against the actual hardware to verify the C# logic works:

```bash
python3 test_csharp_logic.py --host <DEVICE_IP> --key "<LOCAL_KEY>" --devid "<DEV_ID>" --on
```

If the Python port works, the C# code will work (assuming the port is accurate).

## Example: SaunaLogic Module

### Files Created

1. **`test_csharp_logic.py`** - Complete 1:1 port of:
   - `SaunaCrc32.cs` → `class SaunaCrc32`
   - `SaunaTuyaFrame.cs` → `class SaunaTuyaFrame`
   - `SaunaCrypto.cs` → `class SaunaCrypto`
   - `SaunaLogicClient.cs` → `class SaunaLogicClient`

2. **`diagnose_csharp_vs_python.py`** - Diagnostic comparing C# vs Python CRC32

### C# Class → Python Port Example

```python
class SaunaCrc32:
    """Exact port of C# SaunaCrc32 class"""
    
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
        """Exact port of SaunaCrc32.Compute()"""
        if cls._table is None:
            cls._table = cls._build_table()
        
        crc = 0xFFFFFFFF  # Same as C#: uint crc = 0xFFFFFFFFu
        for i in range(count):
            b = data[offset + i]
            crc = cls._table[(crc ^ b) & 0xFF] ^ (crc >> 8)
        
        return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF
```

### Handling External Dependencies

For AES encryption (C# uses `System.Security.Cryptography`), use `openssl` CLI:

```python
class SaunaCrypto:
    @staticmethod
    def aes_128_ecb_encrypt(local_key_ascii: str, plaintext: bytes) -> bytes:
        key_hex = local_key_ascii.encode('ascii').hex()
        p = subprocess.run(
            ["openssl", "enc", "-aes-128-ecb", "-e", "-K", key_hex, "-nosalt"],
            input=plaintext,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return p.stdout
```

## Debugging Workflow

### 1. Identify Suspected Bug
```
C# commands fail, Python commands work
→ Something differs between implementations
```

### 2. Create Diagnostic Script
Compare specific functions between C# logic and working Python:

```python
# diagnose_csharp_vs_python.py
def crc32_csharp_style(data):
    """Replicate EXACT C# implementation (bugs included)"""
    crc = 0x00000000  # Bug: wrong initial value
    for b in data:
        crc = TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc  # Bug: missing final XOR

def crc32_python_style(data):
    """Standard CRC32 (what Python uses)"""
    return binascii.crc32(data) & 0xFFFFFFFF

# Compare outputs
print(f"C# produces:     0x{crc32_csharp_style(test_data):08X}")
print(f"Python produces: 0x{crc32_python_style(test_data):08X}")
```

### 3. Fix and Verify
Apply fix to Python port, test against device, then apply same fix to C#.

## Benefits

1. **Fast iteration**: Test changes in seconds without recompiling
2. **Real device validation**: Confirms fix works before deployment
3. **Clear debugging**: Compare byte-for-byte outputs
4. **Documentation**: Python port serves as readable reference implementation
5. **Cross-platform**: Works on macOS/Linux without .NET

## Limitations

1. **Manual sync**: C# and Python must be kept in sync manually
2. **Subtle differences**: Some C# behaviors may not port exactly (overflow, threading)
3. **Not a replacement**: Still need to test on actual Crestron hardware before production

## Files in This Repo

- `saunalogic_extract/test_csharp_logic.py` - Full C# logic port
- `saunalogic_extract/diagnose_csharp_vs_python.py` - CRC32 diagnostic

Run tests:
```bash
# Test heater ON using exact C# logic
python3 saunalogic_extract/test_csharp_logic.py \
  --host <DEVICE_IP> \
  --key "<LOCAL_KEY>" \
  --devid "<DEV_ID>" \
  --uid "<UID>" \
  --on

# Diagnose CRC32 differences
python3 saunalogic_extract/diagnose_csharp_vs_python.py
```
