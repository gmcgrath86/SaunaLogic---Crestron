# SaunaLogic Crestron Module (SIMPL Windows)

Goal: control + poll a SaunaLogic / TyloHelo SL-2 controller locally over LAN (no cloud, no app dependency).

## What this module does
- **Polling (reliable)**: opens TCP to the controller on `tcp/6668`, sends the captured **Type-10 DP snapshot query**, decrypts the response using `localKey`, and exposes:
  - Heater on/off (`dps["1"]`)
  - Setpoint (`dps["2"]`)
  - Current temperature (`dps["3"]`)
  - Units (`dps["107"]` like `"F"`)
- **Commands**: sends Type-7 DPS writes (heater on/off, setpoint). (See `src/`.)

## Status
Source code is provided in `src/`. Building `.clz/.config` requires Crestron SIMPL# tooling (same workflow as `crestron/GeistRpdu/`).

## SIMPL Windows import
Once built, package these into a flat ZIP for Usrsplus:
- `SaunaLogic_SimplPlusWrapper.usp`
- `SaunaLogic 1.0.clz`
- `SaunaLogic 1.0.config`
- `README.md`

Then copy/import into:
`C:\\Users\\Public\\Documents\\Crestron\\SIMPL\\Usrsplus\\`

## Parameters you will need
- `Host$`: sauna controller IP (default `192.168.1.60`)
- `LocalKey$`: 16-byte Tuya/Thing localKey (ASCII)
- `DevId$`: device id string (from DP snapshot `devId`)
- `Uid$`: uid string used by the app in DPS writes (optional; can be left empty if your device accepts uid-less writes)

See `docs/saunalogic-pcap-notes.md` for protocol details and DPS mapping.

