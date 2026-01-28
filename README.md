# SaunaLogic Crestron Module (Tuya/Thing LAN control)

This repo contains all work to date for controlling a **SaunaLogic / TyloHelo SL-2** controller locally on LAN (no cloud) from Crestron SIMPL#.
Polling works reliably; **heater ON/OFF commands are still not being accepted by the device** from Crestron.

## Repo contents
- `crestron/SaunaLogic/` — SIMPL# module source, wrapper, and import ZIP artifacts.
- `docs/saunalogic-pcap-notes.md` — reverse‑engineering notes and packet capture analysis.
- `saunalogic_extract/` — Python and Frida helper scripts used to validate encryption and live polling.
- `PCAPdroid_*.pcap` — LAN packet captures from the mobile app (handshake + ON/OFF + setpoint).
- `SaunaLogic.apk` — app APK used for reverse‑engineering (excluded from git due to GitHub size limits; keep locally or add via Git LFS).
- `SaunaLogic 1.0.clz` — compiled SIMPL# library artifact (duplicate to module ZIP).
- `.frida/sauna_key.js` and logs — Frida scripts used to extract `localKey` and `uid`.

## Current status
- ✅ **Polling** works:
  - TCP to `:6668`
  - Type‑10 DP snapshot query (captured)
  - AES‑128‑ECB decrypt with `localKey`
  - DPS mapping for temp/setpoint/heater is correct
- ❌ **Commands (Type‑7 DPS writes)** are sent but **device state does not change**.

The primary open issue is why Type‑7 writes from Crestron are not accepted, despite matching the captured framing and encryption.

## Device parameters (from our device)
These are the parameters used by the module and the scripts:
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
  - CRC32 over frame bytes excluding CRC+tail
  - Tail `0x0000AA55`
- Payload:
  - Starts with ASCII `"3.3"` plus a fixed header-like region
  - AES‑128‑ECB encrypted JSON body

Captured examples:
- Type‑10 handshake request/response (used for polling)
- Type‑7 heater ON / OFF payloads (len 135) from PCAPdroid captures

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
- `sauna_send_heater.py` — attempt heater on/off write from Python
- `tuya_try_decrypt.py` — decrypt captured frames
- `frida_localkey.js` — Frida hooks to extract `localKey` and `uid`

These scripts helped confirm:
- AES‑128‑ECB with the extracted `localKey` decrypts snapshots correctly.
- The JSON write format appears correct, but commands still fail from Crestron.

## Remaining issue: Type‑7 writes not accepted
Symptoms:
- Crestron sends write (cmd=7), receives no error, but heater state does not change.
- Polling immediately after still shows `dps["1"]` unchanged.

Hypotheses to explore:
1. **Write payload must include additional DPS fields** in the same JSON (e.g., mode `"4":"ONLY_TRAD"`).
2. **`t` timestamp** may need to be string vs numeric.
3. **Other hidden fields** or signatures required by this firmware for writes.
4. **Request‑id or prefix details** still slightly different than app.

Recent code changes:
- Corrected requestId offset in the `"3.3"` prefix (now written at byte 12).
- Heater write now includes `"4":"ONLY_TRAD"` alongside `"1": true/false`.

## Help wanted
We’re looking for assistance validating or reproducing the **exact** Type‑7 payloads from the app,
and/or confirming if the device expects a multi‑DPS write or extra fields beyond `devId`, `dps`, `t`, `uid`.

If you can:
- diff the app’s write JSON before encryption,
- or replay the captured cmd=7 frames verbatim,
it would likely solve the final ON/OFF issue.

