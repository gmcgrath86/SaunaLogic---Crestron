### SaunaLogic / TyloHelo SL-2 — PCAP notes (local vs cloud)

Last updated: 2026-01-15

These notes are from analyzing:
- `~/Desktop/PCAPdroid_14_Mar_21_01_39.pcap`
- `~/Desktop/PCAPdroid_14_Mar_21_10_09.pcap`

### Key findings
- The phone/app communicated with a **local LAN device**:
  - **IP**: `192.168.1.71`
  - **TCP port**: `6668`
  - This strongly suggests the SaunaLogic app has a **LAN-local control path** (at least when the phone is on the same network).

- The phone/app also communicated with **cloud endpoints** (AWS IPs):
  - `a1-us.iotbing.com` (seen via TLS SNI / DNS)
  - `m1-us.iotbing.com` (seen via TLS SNI / DNS)
  - Ports observed:
    - **TCP/8883** (commonly MQTT over TLS)
    - **TCP/443**

- There was also **UDP broadcast** traffic:
  - Destination: `255.255.255.255:7000`
  - Likely discovery / presence / keepalive.

### Local protocol characteristics (TCP/6668)
- Traffic appears **binary**, not HTTP/JSON.
- Packets show framing markers:
  - Prefix: `55 aa`
  - Suffix: `aa 55`
- A plain-text version-like string appears in some frames: `3.3`
- Payload otherwise looks like encrypted/compressed/proprietary binary.

#### Additional inspection (from PCAPs now in repo)
- TCP payloads on `:6668` start with a **binary header** that includes `55 aa` and length-like fields.
- No TLS handshake is present on the LAN link; this is a **custom binary protocol**.
- Printable text is sparse, but **`3.3`** appears repeatedly inside payloads.
- Entropy is **moderate** (not fully random): some frames look structured, others more opaque.
  - This suggests **either** partial encryption/compression **or** a binary protocol with mixed fields.
  - We cannot identify a specific cipher/mode from these PCAPs alone.

#### Header structure hypothesis (based on payloads in `PCAPdroid_14_Mar_21_*.pcap`)
Observed payloads always start with a 16‑byte header:

```
00 00 55 aa  00 00 XX XX  00 00 00 TT  00 00 00 LL  [body...]
```

- `55 aa` is a constant marker.
- `LL` matches **(total_length - 16)** in every sampled frame (length of body).
  - Example: total `88` → `LL=72`; total `188` → `LL=172`.
- `TT` looks like a **message type** (values seen: `7`, `8`, `9`, `10`).
- `XX XX` increments across requests; likely a **sequence/correlation id**.

#### Message types + lengths (from `PCAPdroid_14_Mar_21_01_39.pcap`)
Type → counts, lengths, direction:
- **Type 7**: 43 frames
  - lengths: `135` (6), `28` (33), `842` (1), `977` (3)
  - direction: mostly **device → client** for `28` byte responses; larger requests are **client → device**
- **Type 8**: 43 frames
  - lengths: `123` (25), `107` (18)
  - direction: **device → client** (all)
- **Type 9**: 12 frames
  - lengths: `24` (6), `28` (6)
  - direction: both ways (likely keepalive/handshake)
- **Type 10**: 2 frames
  - lengths: `88` (1), `188` (1)
  - direction: request/response pair

#### Request/response pairing (by sequence id)
Sequences with paired request/response show:
- **Type 10**: `88` (client → device) → `188` (device → client)
- **Type 7**: `135/842/977` (client → device) → `28` (device → client)

This suggests:
- Type **7** = command/request with a short ACK response.
- Type **10** = handshake or session init (larger response).
- Type **8** = periodic status/telemetry pushed by device.
- Type **9** = keepalive (small and symmetric).

#### Trailer marker
Every captured frame ends with **`0000aa55`** (4 bytes).
This looks like a **frame terminator** rather than a checksum.

#### Checksum tests (simple)
Tried simple checksums on the body (sum8/sum16 over body bytes):
- **No matches found** for common checksum heuristics.
This does not rule out checksums, but suggests either:
- a more complex checksum/CRC, or
- encrypted/compressed body where checksums are computed pre‑encryption.

#### CRC32 confirmed (Tuya-style framing)
The 4 bytes **before** the `0000aa55` tail are a **CRC32** of the packet
excluding the last 8 bytes (CRC + tail).

Example (handshake request from `PCAPdroid_15_Jan_21_43_36.pcap`):
- Packet ends with `f39f406f0000aa55`
- `CRC32(packet[:-8]) = f39f406f`

This means we can synthesize new packets by:
1) Updating the **sequence id** (bytes 4–7)
2) Recomputing **CRC32(packet[:-8])**
3) Writing CRC into the 4 bytes before the tail

---

## Deep‑dive analysis (steps 1–3)

### 1) Grouped message bodies (type + length)
Type 7 client→device requests are not identical:
- There are **6 distinct 135‑byte requests** in the capture.
- They share a common header and version string (`3.3`), but the body changes in a large contiguous region.
  - Indicates **per‑command payloads**, not just timestamps.

Type 7 larger requests:
- One `842`‑byte request, three `977`‑byte requests (all unique).
- These likely represent higher‑level operations (e.g., state sync or batch config).

Type 8 device→client responses:
- Two lengths (`107`, `123`) with modest variance in some byte ranges.
- These look like **status/telemetry frames** but need mapping to actions.

### 2) Request/response pairing (seq id)
Sequence IDs allow reliable pairing:
- **Type 10**: `88` (request) → `188` (response)
- **Type 7**: `135/842/977` (request) → `28` (ACK)

### 3) Checksum hints
No simple checksum detected on body tail bytes.
All frames end with the same **`aa55`** terminator.
This suggests either:
- a checksum embedded elsewhere, or
- encrypted/compressed body content.

---

## What we still need (to extract exact ON/OFF/TEMP/LIGHTS commands)
The current PCAPs don’t label actions, so we **cannot map a payload to “heater on”** without a new capture.
To get exact commands, we need a **fresh LAN capture** with single, time‑isolated actions:

1. Start capture on the LAN (or on the phone with PCAPdroid if on the same subnet).
2. Perform only one action at a time, with 10–15 seconds between:
   - Heater ON
   - Heater OFF
   - Set temp to a specific value (e.g., 100°F / 38°C)
   - Lights ON
   - Lights OFF
   - Set light color (distinct value)
3. Stop capture and save PCAP.

With that, we can diff the **Type 7 request bodies** and pinpoint:
- command ID,
- parameter bytes (temperature, color),
- and any checksums/encryption patterns.

---

## New capture mapping (Jan 15, 2026 — ON then OFF)
Capture: `PCAPdroid_15_Jan_17_46_44.pcap`

Based on the provided sequence (ON → wait ~30s → OFF), the two **Type 7** client→device requests map as:

### Heater ON (first action)
- **Seq**: `0x0763` (1891)
- **Frame/time**: `512` @ `17:47:01.548` PST
- **ACK**: frame `514` (len 28)
- **Payload (hex)**:
```
000055aa000007630000000700000077332e330000000000000003000482ee462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da2220629f319eac976cc9cac614a6978ba68beeb36753184d7b1b48fe3740aef8d26cc25757f4bbd227eb2a6d680d4c6f931f816f274c808c87153245479a47ec8ab6c0a592b0000aa55
```

### Heater OFF (second action)
- **Seq**: `0x0764` (1892)
- **Frame/time**: `542` @ `17:47:21.978` PST
- **ACK**: frame `544` (len 28)
- **Payload (hex)**:
```
000055aa000007640000000700000077332e330000000000000004000482ee462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da222e5aa8b005e19995c84ffdc3cf3bc514eee3d47ed0baa272a030e38a881a1444670c8248ebe1b703f95dbb923fc3169368db96f8305bec618f8dd10591d8aa646433858d0000aa55
```

---

## New capture mapping (Jan 15, 2026 — app open + ON)
Capture: `PCAPdroid_15_Jan_21_33_01.pcap`

This capture includes the **handshake** and a single **ON** command.

### Handshake request (Type 10)
- **Seq**: `0x0595` (1429)
- **Payload**:
```
000055aa000005950000000a00000048462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da22213e58805e31f87ed159506545b2366e98b06c2f6f0199f8a2f35996f580cd2bbab2eb66f0000aa55
```

### Handshake response (Type 10)
- **Seq**: `0x0595` (1429)
- **Payload**:
```
000055aa000005950000000a000000ac00000000462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da222e5aa8b005e19995c84ffdc3cf3bc514e80f731cb8dd1c57e1c8a7af1bed2881e5537f240f076275e470018a360183f1a63d2dfdcc42ad416028278be28fac7e3a34436b674e9c4b907e0c534cd6f6fa34d29a905656cbca4c5cc1118f17ad6d1273492c384901a5db9d37aea8281463f0cb8b1dfd5285f9187587575548e4a0155fb10fa0000aa55
```

### Heater ON (Type 7)
- **Seq**: `0x0596` (1430)
- **Payload**:
```
000055aa000005960000000700000077332e3300000000000000030009fac9462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da2220629f319eac976cc9cac614a6978ba68aa0f3bd6c6bf8bcbacfbc6aec6853a76cc25757f4bbd227eb2a6d680d4c6f931f816f274c808c87153245479a47ec8ab77ff0eab0000aa55
```

---

## Heater ON/OFF commands (from `PCAPdroid_15_Jan_17_46_44.pcap`)
Action order: capture → **ON** → wait ~30s → **OFF**.

Two distinct **Type 7 client→device** commands (len=135) were observed:

### Heater ON (first command after capture start)
```
000055aa000007630000000700000077332e330000000000000003000482ee462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da2220629f319eac976cc9cac614a6978ba68beeb36753184d7b1b48fe3740aef8d26cc25757f4bbd227eb2a6d680d4c6f931f816f274c808c87153245479a47ec8ab6c0a592b0000aa55
```

### Heater OFF (second command ~30s later)
```
000055aa000007640000000700000077332e330000000000000004000482ee462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da222e5aa8b005e19995c84ffdc3cf3bc514eee3d47ed0baa272a030e38a881a1444670c8248ebe1b703f95dbb923fc3169368db96f8305bec618f8dd10591d8aa646433858d0000aa55
```

Notes:
- The **sequence id** increments (`0x0763` → `0x0764`).
- A small 4‑byte field in the body increments from `00000003` → `00000004` just after the `3.3` string.
- The bulk of the body differs (likely encrypted/obfuscated), but the full payloads above can be replay‑tested once we implement the handshake and seq handling.

#### Direction + size patterns
In `PCAPdroid_14_Mar_21_01_39.pcap`:
- **Client → device** payload lengths: `24`, `88`, `135`, `842`, `977`
- **Device → client** payload lengths: `28`, `107`, `123`, `188`
- Repeated fixed messages:
  - `len=24` with header type `9` repeats 6x
  - `len=28` with header type `9` repeats 6x

This looks like a **request/response protocol** with:
- small fixed **keepalive/handshake** frames (type `9`),
- larger request frames (type `7`/`10`),
- and status/response frames (type `8`).

### Practical implications for automation
- **Best case (true LAN control)**:
  - If we can locate the sauna controller on the ER-4 LAN and confirm it still listens on **TCP/6668** (and/or uses **UDP/7000**), we can potentially build a Crestron SIMPL#/C# integration by implementing this protocol.
  - This likely requires additional reverse-engineering (message types, auth, possible encryption).

- **Cloud involvement exists**:
  - The app also talks to `*.iotbing.com` over TLS (incl MQTT-like 8883), which could mean:
    - remote control is cloud-backed, OR
    - the system uses cloud for account/auth/telemetry even when local control exists.

### Suggested next steps (when ready)
1. Get the sauna controller onto the UniFi/ER-4 LAN (so we can see it in ARP/DHCP).
2. Identify its IP by MAC and test for:
   - `tcp/6668` open
   - `udp/7000` discovery responses (if any)
3. Capture a fresh pcap on the LAN while pressing:
   - power on/off
   - set temp
   - lights on/off and color
   This will let us map which message patterns correspond to which actions.

---

## New capture mapping (Jan 15, 2026 — set temp 194 → 190)
Capture: `PCAPdroid_15_Jan_22_28_54.pcap`

Observed **two** Type 7 client→device commands (len=135). First is **heater ON** (matches known ON); second is **set‑temp OK**.

### Command 1 (heater ON)
```
000055aa000005840000000700000077332e33000000000000000300053745462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da2220629f319eac976cc9cac614a6978ba682a38795becf29863cac62fe6e9fd1d82cc25757f4bbd227eb2a6d680d4c6f931f816f274c808c87153245479a47ec8ab9e893d780000aa55
```

### Command 2 (set temp to 190, then OK)
```
000055aa000005850000000700000077332e33000000000000000400053745462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da2226d0d2105b1a84664fe67089ab2d6a0b4e56b485e76249209f07d830ae98d4d87b67c4a4cbd9ea0223aa8affea28b2bd579588ae010cbd6613df555902e818bd21a065a980000aa55
```

### Telemetry (Type 8)
Three unique device→client frames were seen (len 123 and 107). Payloads differ in a large contiguous region, consistent with encrypted/obfuscated telemetry.

---

## New capture mapping (Jan 15, 2026 — set temp 190 → 185 → 190)
Capture: `PCAPdroid_15_Jan_22_37_55.pcap`

Observed **one** Type 7 client→device command (len=135) which appears to be the **final set‑temp OK** after the incremental changes.

### Command 1 (set‑temp OK)
```
000055aa0000075a0000000700000077332e330000000000000003000c92b4462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da2226d0d2105b1a84664fe67089ab2d6a0b40ea446ffd2e0c035a68db5f9f3d616c2b67c4a4cbd9ea0223aa8affea28b2bd579588ae010cbd6613df555902e818bd27c61083f0000aa55
```

### Telemetry (Type 8)
Four unique device→client frames were seen (all len 107). The changing region remains opaque without decryption.

---

## New capture mapping (Jan 15, 2026 — current temp rising ~156 → 161)
Capture: `PCAPdroid_15_Jan_22_43_37.pcap`

Observed **six** unique Type 8 telemetry frames (len=107). No Type 7 commands were present during this idle period.

Telemetry frames:
```
000055aa00000000000000080000005b00000000332e33000000000000ddac00000001462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da222089baf36ecb86c059f0165d3e244f7ad9f7ae1542b07bff423a6fb5ee587c653b5a25f3f0000aa55
000055aa00000000000000080000005b00000000332e33000000000000ddad00000001462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da222514ae85447c35c7dcf112065120887350e18d75ec94e08ee4d0e3efb01dd19f560e4f85b0000aa55
000055aa00000000000000080000005b00000000332e33000000000000ddae00000001462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da22216d1a4d23ce0cec4f1347f3580905b9b5d26711696d04a69b65023cd52e111068d8941ee0000aa55
000055aa00000000000000080000005b00000000332e33000000000000ddaf00000001462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da2222c2b74275fc3fe44a430d903ff21e4e50d9b11d0b7aab710ed168accdf26211df62a08780000aa55
000055aa00000000000000080000005b00000000332e33000000000000ddb000000001462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da222880ba36a634ccf24c1071633d945d9e73152c0c9febc05bdde3ac5d6caface947fab37880000aa55
000055aa00000000000000080000005b00000000332e33000000000000ddb100000001462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da2227e46d73e505edaa01f0a5e44bee0a1f4276a23829c4d6a3f03a62dfeaa7313fd4d32389a0000aa55
```

The differing bytes are consistent with prior captures (offsets ~67–90), suggesting the **current temperature** is embedded in the encrypted payload. We still need the **localKey** to decrypt these fields.

## APK deep‑dive (localKey + AES parsing)
The SaunaLogic app uses Thing/Tuya SDK primitives for LAN control:

- Local control uses `ThingLocalNormalControlBean` and includes a **localKey** retrieved from the device record.
- Incoming LAN responses are parsed using `ThingNetworkApi.parseAesData(...)` with that **localKey**.
- The AES parse/encrypt routines live in the native library **`network-android`** (JNI), so the exact cipher mode/keying is not visible in Java.

Relevant references:
- `com.thingclips.sdk.hardware.qddbbpb` builds `ThingLocalNormalControlBean` with `deviceBean.getLocalKey()` for LAN control.
- `com.thingclips.sdk.hardware.dpppdpq` calls `ThingNetworkApi.parseAesData(hResponse.getDataBinary(), localKey)` for LAN response parsing.
- `com.thingclips.smart.android.device.ThingNetworkApi` exposes `parseAesData` and `encryptAesData` as **native** methods.

**Implication:** to decode Type 8 telemetry (current temp), we likely need the device **localKey** from the app/cloud. Without it, telemetry payloads remain opaque.

---

## ✅ localKey extracted (Android emulator + Frida)

We extracted the Tuya/Thing **`localKey`** directly from the running SaunaLogic app in the Android emulator by hooking `DeviceBean.getLocalKey()` at runtime.

### Environment
- **Emulator**: Android 14 arm64 (`sdk_gphone64_arm64`)
- **Package**: `com.tyloheloinc.saunalogic`

### Steps (reproducible)
1) Ensure ADB sees the emulator:
   - `adb devices -l`

2) Start `frida-server` on the emulator (arm64 build):
   - Push: `adb -s emulator-5554 push .frida/frida-server /data/local/tmp/frida-server`
   - Perms: `adb -s emulator-5554 shell chmod 755 /data/local/tmp/frida-server`
   - Run: `adb -s emulator-5554 shell /data/local/tmp/frida-server &`

3) Attach Frida to SaunaLogic and print `localKey`:
   - Script: `saunalogic_extract/frida_localkey.js`
   - Attach with a timeout (so it’s non-interactive):
     - `PID=$(frida-ps -U | awk '$2=="SaunaLogic" {print $1; exit}')`
     - `frida -U -p "$PID" -l saunalogic_extract/frida_localkey.js -q -t 180`

### Extracted values
- **localKey**: `HSt;vM1?ZKRvG9u'` (16 bytes)
- **uid**: `az1721268754042F6CBR`

### Proof: decrypted Type-8 telemetry → JSON
With the key above, we can decrypt Type‑8 packets (cmd=8, len=107 frames) using AES-128-ECB and recover JSON.

Example (from `PCAPdroid_15_Jan_22_43_37.pcap`, first telemetry frame):
- Packet hex:
  - `000055aa00000000000000080000005b00000000332e33000000000000ddac00000001462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da222089baf36ecb86c059f0165d3e244f7ad9f7ae1542b07bff423a6fb5ee587c653b5a25f3f0000aa55`
- Decrypt helper:
  - `python3 saunalogic_extract/tuya_try_decrypt.py --key "HSt;vM1?ZKRvG9u'" --hex "<packethex>"`
- Output JSON:
  - `{"devId":"27703180e868e7eda84a","dps":{"3":156},"t":1768545835}`

Notes:
- `devId` contains the device MAC (`e868e7eda84a` → `e8:68:e7:ed:a8:4a`, matches `docs/ip-table.md` sauna controller MAC).
- `dps["3"]` appears to be the **current temp** (e.g., `156` during warm-up capture).

---

## ✅ Production polling (no app/emulator): Type-10 DP snapshot

Key discovery: the so-called “handshake” **Type 10 (cmd=10)** exchange is effectively a **DP snapshot query**.

That means reliable polling does **not** require waiting for Type‑8 push telemetry. Instead:

1) Open TCP connection to the controller (`tcp/6668`)
2) Send the captured **Type‑10 request** (DP snapshot query)
3) Read the **Type‑10 response**
4) Decrypt it (AES‑128‑ECB using `localKey`) → JSON containing **full `dps`**

### Captured DP snapshot query (Type 10 request)
From `PCAPdroid_15_Jan_21_33_01.pcap`:

```
000055aa000005950000000a00000048462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da22213e58805e31f87ed159506545b2366e98b06c2f6f0199f8a2f35996f580cd2bbab2eb66f0000aa55
```

### Captured DP snapshot response (Type 10 response)
Also from `PCAPdroid_15_Jan_21_33_01.pcap`:

```
000055aa000005950000000a000000ac00000000462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da222e5aa8b005e19995c84ffdc3cf3bc514e80f731cb8dd1c57e1c8a7af1bed2881e5537f240f076275e470018a360183f1a63d2dfdcc42ad416028278be28fac7e3a34436b674e9c4b907e0c534cd6f6fa34d29a905656cbca4c5cc1118f17ad6d1273492c384901a5db9d37aea8281463f0cb8b1dfd5285f9187587575548e4a0155fb10fa0000aa55
```

Decryption result (JSON DPS snapshot):

```
{"devId":"27703180e868e7eda84a","dps":{"1":false,"2":194,"3":73,"4":"ONLY_TRAD","9":"1","10":0,"11":0,"101":"0","103":false,"105":"1","106":0,"107":"F"}}
```

### DPS field mapping (confirmed)
- **`dps["1"]`**: **heater on/off** (bool)
- **`dps["2"]`**: **setpoint temp** (int; e.g. 190)
- **`dps["3"]`**: **current temp** (int; varies over time)
- **`dps["107"]`**: temperature unit (`"F"` observed)

### Live polling proof (direct-to-device)
We validated end-to-end polling on the LAN (no emulator) by connecting to `192.168.1.60:6668`, sending the Type‑10 query, decrypting the response, and parsing DPS.

Reference script:
- `saunalogic_extract/sauna_live_poll.py`

Example output:

```
devId: 27703180e868e7eda84a
heater_on(dps1): True
setpoint(dps2): 190
temp(dps3): 188
raw_dps: {'1': True, '2': 190, '3': 188, '4': 'ONLY_TRAD', '9': '1', '10': 29, '11': 0, '101': '0', '103': False, '105': '1', '106': 0, '107': 'F'}
```

---

## Future improvements (do alongside lighting controls)

### Retry on contention (phone app vs Crestron)
When the SaunaLogic phone app is open/active, it may intermittently “win” the session and cause occasional poll/command failures from Crestron.

**Planned improvement:** add a small retry loop to reduce visible errors:
- On **poll** and on **commands** (heater on/off, setpoint, and later lighting):
  - attempt up to **2–3 tries**
  - with a short delay **200–500ms** between tries
  - treat first failure as transient unless all tries fail

This should make Crestron “fall back” to the default control path more smoothly after app usage, without surfacing false-negative errors.



