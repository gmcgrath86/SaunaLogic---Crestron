# Getting LocalKey / DevId / Uid

This module requires four parameters:
- `Host` (device IP)
- `LocalKey` (16 ASCII bytes)
- `DevId`
- `Uid` (optional but recommended)

`Host` is just the sauna controller IP on your LAN.  
The tricky parts are `LocalKey`, `DevId`, and `Uid`.

This guide focuses on **extracting keys from the SaunaLogic app** using Frida.

---

## Overview of methods

There are two practical paths:

1) **Android emulator** (easiest for many users)
   - Run the SaunaLogic app in an emulator.
   - Use Frida to hook the app and print `LocalKey` + `Uid`.

2) **Rooted Android phone** (no emulator required)
   - Run the SaunaLogic app on a rooted device.
   - Use Frida Server on-device and the same script.

Both use the exact same Frida script:
`saunalogic_extract/frida_localkey.js`

---

## Step-by-step: Emulator (recommended)

### 1) Install the SaunaLogic app
Install the app into the emulator and log in with your account.

### 2) Start Frida Server inside the emulator
You need an **arm64** Frida server build that matches your Frida version.

```bash
# Example for emulator-5554 (adjust if your device ID differs)
adb -s emulator-5554 push .frida/frida-server /data/local/tmp/frida-server
adb -s emulator-5554 shell chmod 755 /data/local/tmp/frida-server
adb -s emulator-5554 shell /data/local/tmp/frida-server &
```

### 3) Attach Frida to the running app
With the app running in the emulator:

```bash
PID=$(frida-ps -U | awk '$2=="SaunaLogic" {print $1; exit}')
frida -U -p "$PID" -l saunalogic_extract/frida_localkey.js -q -t 180
```

Now open the **sauna device page** in the app and trigger any action (e.g., refresh, tap power).

You should see log lines like:
```
[localKey] ThingNetworkApi.parseAesData key="..." (len=16)
[localKey] ...getLocalKey() -> "..." (len=16)
```

Record the LocalKey and (if printed) Uid.

---

## Step-by-step: Rooted Android device

### 1) Install Frida Server on the phone
Push the correct Frida server binary to the device:

```bash
adb push frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell su -c /data/local/tmp/frida-server &
```

### 2) Run Frida against the running app
Open the SaunaLogic app, then:

```bash
PID=$(frida-ps -U | awk '$2=="SaunaLogic" {print $1; exit}')
frida -U -p "$PID" -l saunalogic_extract/frida_localkey.js -q -t 180
```

Interact with the device page until you see `localKey` output.

---

## How to find DevId

Once you have the `LocalKey`, you can decrypt any DP snapshot to reveal the `devId`:

1) Capture a packet or use the live poll script:

```bash
python3 saunalogic_extract/sauna_live_poll.py --host <DEVICE_IP> --key "<LOCAL_KEY>"
```

The output includes a `devId` field. Use that as your module’s `DevId`.

---

## Where Uid comes from

Uid is usually printed by the Frida hooks (it is used in DPS writes).  
If you don’t see it immediately:
- keep the Frida session open and interact with the device page a few times
- try toggling a setting so the app performs a write

If you still cannot retrieve Uid, you can try leaving it blank; some firmware accepts writes without it.

---

## Troubleshooting

- **No output from Frida**: the app may be obfuscated or not calling the hooked functions yet. Open the device page and trigger actions.
- **Frida cannot attach**: ensure Frida Server version matches your client and device architecture (arm64).
- **LocalKey not 16 bytes**: discard and wait for another call; the correct key is exactly 16 ASCII bytes.
- **DevId missing**: use `sauna_live_poll.py` to get a full decrypted snapshot.

---

## Next step

Once you have `Host`, `LocalKey`, `DevId`, and `Uid`, configure the Crestron module and test:
- `POLL_NOW` should populate temp + heater status
- `HEATER_ON` / `HEATER_OFF` should toggle the sauna

