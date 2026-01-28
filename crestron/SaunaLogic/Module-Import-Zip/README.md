# SaunaLogic Module Import (SIMPL Windows)

This folder is structured to become a **flat import ZIP** for SIMPL Windows `Usrsplus`, matching the Geist module workflow.

## Files that will be in the ZIP
- `SaunaLogic_SimplPlusWrapper.usp` (SIMPL+ symbol wrapper)
- `SaunaLogic 1.0.clz` (compiled SIMPL# library)  ← built on Windows with Crestron tooling
- `SaunaLogic 1.0.config` (module config)          ← emitted alongside the `.clz`
- `README.md` (this file)

## Build the `.clz` (Windows + Crestron tools)
1) Open `crestron/SaunaLogic/SaunaLogic.csproj` in your Crestron-supported Visual Studio environment.
2) Build using the SIMPL# library tooling so it outputs:
   - `SaunaLogic 1.0.clz`
   - `SaunaLogic 1.0.config`

## Make the flat ZIP
Create `SaunaLogic-Module-Import.zip` containing **only** the 4 files above at the ZIP root (no nested directories).

## Install into SIMPL Windows
Copy/import the ZIP into:

`C:\Users\Public\Documents\Crestron\SIMPL\Usrsplus\`

Then restart SIMPL Windows if the symbol doesn’t appear.

## Required parameter values (typical)
- `Host`: `192.168.1.60`
- `LocalKey`: `HSt;vM1?ZKRvG9u'` (16 chars)
- `DevId`: `27703180e868e7eda84a`
- `Uid`: `az1721268754042F6CBR` (optional, but recommended for writes)

## Minimal SIMPL test
Wire:
- Pulse `POLL_NOW` (and set `POLL_ENABLE=1`)
  - Expect `ONLINE_FB=1`, `CURRENT_TEMP` updates, `HEATER_ON_FB` updates.
- Pulse `HEATER_ON` and `HEATER_OFF`
  - Expect `HEATER_ON_FB` follows.

If it fails, check `LAST_ERROR$` and clear SIMPL caches (see `docs/crestron-module-development-playbook.md`).

