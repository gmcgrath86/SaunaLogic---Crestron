# SaunaLogic Crestron Module (Tuya/Thing LAN control)

This repo contains a working Crestron SIMPL# module for controlling a **SaunaLogic / TyloHelo SL-2** controller locally on LAN (no cloud).

## Current status
- ✅ **Polling** works: TCP to `:6668`, Type‑10 DP snapshot query, AES‑128‑ECB decrypt
- ✅ **Commands (Type‑7 DPS writes)** work: Heater ON/OFF, setpoint changes

## Repo contents
- `crestron/SaunaLogic/` — SIMPL# module source, wrapper, and import ZIP artifacts.
- `docs/saunalogic-pcap-notes.md` — reverse‑engineering notes and packet capture analysis.
- `saunalogic_extract/` — Python helper scripts for testing and validation.
- `PCAPdroid_*.pcap` — LAN packet captures from the mobile app (handshake + ON/OFF + setpoint).
- `SaunaLogic 1.0.clz` — compiled SIMPL# library artifact.
- `.frida/sauna_key.js` and logs — Frida scripts used to extract `localKey` and `uid`.

## Device parameters (example from our device)
- `Host`: `192.168.1.60`
- `LocalKey`: `HSt;vM1?ZKRvG9u'` (16 bytes)
- `DevId`: `27703180e868e7eda84a`
- `Uid`: `az1721268754042F6CBR`

## Protocol summary (Tuya/Thing LAN style)
Full details are in `docs/saunalogic-pcap-notes.md`. Highlights:

- Frame header:
  - Prefix `0x000055AA`
  - Sequence ID (u32 BE)
  - Command (u32 BE): `7` for writes, `10` for snapshot
  - Length field (payload + CRC + tail)
  - CRC32 (IEEE/zlib standard) over frame bytes excluding CRC+tail
  - Tail `0x0000AA55`
- Payload:
  - Starts with ASCII `"3.3"` plus a 12-byte header region
  - AES‑128‑ECB encrypted JSON body

## DPS mapping (known)
From decrypted DP snapshot:
- `1`: heater on/off (bool)
- `2`: setpoint (int)
- `3`: current temp (int)
- `4`: mode (string, e.g. `"ONLY_TRAD"`)
- `107`: units (`"F"`)

## Crestron module
Source is in `crestron/SaunaLogic/src/`:
- `SaunaLogicClient.cs` — LAN protocol, encryption, Type‑7 writes
- `SaunaLogicSimplPlusFacade.cs` — SIMPL+‑friendly API + polling cache
- `SaunaTuyaFrame.cs` — framing + CRC
- `SaunaCrypto.cs` — AES ECB wrappers

SIMPL Windows import instructions and join details are in:
- `crestron/SaunaLogic/README.md`
- `crestron/SaunaLogic/Module-Import-Zip/README.md`

## Python + Frida tooling
Scripts in `saunalogic_extract/`:
- `sauna_live_poll.py` — live snapshot polling + decrypt
- `sauna_send_heater.py` — send heater on/off commands from Python
- `tuya_try_decrypt.py` — decrypt captured frames
- `frida_localkey.js` — Frida hooks to extract `localKey` and `uid`
- `test_csharp_logic.py` — exact port of C# logic for testing
- `diagnose_csharp_vs_python.py` — diagnostic tool comparing CRC implementations

---

## Bug Fixes (January 2026)

Two critical bugs were identified and fixed that prevented Type‑7 write commands from working:

### Bug #1: CRC32 Implementation (Primary Issue)

**File:** `crestron/SaunaLogic/src/SaunaCrc32.cs`

**Problem:** The CRC32 implementation used incorrect initial value and was missing the final XOR, producing completely wrong checksums. Every Type‑7 frame had an invalid CRC, causing the device to silently reject commands.

| Parameter | Wrong (Before) | Correct (After) |
|-----------|----------------|-----------------|
| Initial value | `0x00000000` | `0xFFFFFFFF` |
| Final XOR | none | `^ 0xFFFFFFFF` |

**Example CRC mismatch:**
- Known good CRC from capture: `0xAB2EB66F`
- Old C# implementation produced: `0x250DAE89` ❌
- Fixed implementation produces: `0xAB2EB66F` ✓

**Fix:**
```csharp
// Before (WRONG):
uint crc = 0x00000000u;
// ... loop ...
return crc;

// After (CORRECT - standard IEEE/zlib CRC32):
uint crc = 0xFFFFFFFFu;
// ... loop ...
return crc ^ 0xFFFFFFFFu;
```

### Bug #2: Type‑7 Prefix Offset

**File:** `crestron/SaunaLogic/src/SaunaLogicClient.cs`

**Problem:** The code wrote a 4-byte counter at offset 12 in a 15-byte array, which would:
1. Cause an `IndexOutOfRangeException` (writing to index 15 of a 15-element array)
2. Even if it didn't crash, offset 12 was wrong — the captured frames show the field is at offset 11

**Fix:**
```csharp
// Before (WRONG - offset 12, also causes array overflow):
SaunaTuyaFrame.WriteU32BE(prefix, 12, counter);

// After (CORRECT - offset 11):
SaunaTuyaFrame.WriteU32BE(prefix, 11, counter);
```

### Type‑7 Prefix Structure (for reference)
```
Offset  Size  Description
------  ----  -----------
0-2     3     "3.3" version string
3-9     7     Zeros (padding)
10      1     Request counter (increments per command)
11-14   4     Session/counter field (written by WriteU32BE)
```

### Verification
Both fixes were verified against the real device:
- Python script using standard CRC32: ✅ Works
- C# logic (ported to Python) with fixes: ✅ Works
- Heater ON/OFF commands confirmed functional

---

## Building
After applying fixes, rebuild the SIMPL# library (`.clz`) and redeploy to your Crestron processor.

