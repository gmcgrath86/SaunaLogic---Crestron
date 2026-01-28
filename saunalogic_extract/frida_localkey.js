// Frida script: extract Tuya/Thing "localKey" from SaunaLogic (Android)
//
// Usage:
//   frida -U -f com.tyloheloinc.saunalogic -l saunalogic_extract/frida_localkey.js --no-pause
//
// Then, inside the app: open the sauna device page / trigger an action so LAN packets flow.

'use strict';

function safeString(x) {
  try {
    if (x === null || x === undefined) return '' + x;
    return '' + x;
  } catch (e) {
    return '<toString failed>';
  }
}

function hookIfExists(className, methodName, onCall) {
  try {
    const C = Java.use(className);
    const m = C[methodName];
    if (!m || !m.overloads) return false;
    m.overloads.forEach((ovl) => {
      ovl.implementation = function () {
        try {
          onCall.call(this, ovl, arguments);
        } catch (e) {
          console.log(`[!] hook error ${className}.${methodName}: ${e}`);
        }
        return ovl.apply(this, arguments);
      };
    });
    console.log(`[+] hooked ${className}.${methodName} (${m.overloads.length} overloads)`);
    return true;
  } catch (e) {
    return false;
  }
}

Java.perform(() => {
  console.log('[*] SaunaLogic localKey extraction hooks starting...');

  // Most reliable per our notes: parseAesData(dataBinary, localKey)
  hookIfExists('com.thingclips.smart.android.device.ThingNetworkApi', 'parseAesData', function (_ovl, args) {
    // expected: (byte[] data, String localKey)
    if (args.length >= 2) {
      const key = safeString(args[1]);
      if (key && key.length >= 6) {
        console.log(`[localKey] ThingNetworkApi.parseAesData key="${key}" (len=${key.length})`);
      }
    }
  });

  hookIfExists('com.thingclips.smart.android.device.ThingNetworkApi', 'encryptAesData', function (_ovl, args) {
    if (args.length >= 2) {
      const key = safeString(args[1]);
      if (key && key.length >= 6) {
        console.log(`[localKey] ThingNetworkApi.encryptAesData key="${key}" (len=${key.length})`);
      }
    }
  });

  // Also print the *decrypted* payload returned by parseAesData (often JSON bytes/string).
  // We only print when it looks like JSON containing "dps".
  try {
    const Api = Java.use('com.thingclips.smart.android.device.ThingNetworkApi');
    Api.parseAesData.overloads.forEach((ovl) => {
      ovl.implementation = function () {
        const ret = ovl.apply(this, arguments);
        try {
          let s = null;
          // ret may be byte[] or String
          if (ret && ret.$className === 'java.lang.String') {
            s = '' + ret;
          } else if (ret) {
            // assume byte[]
            const JString = Java.use('java.lang.String');
            s = JString.$new(ret);
          }
          if (s && s.indexOf('"dps"') !== -1) {
            console.log(`[telemetry] ${s}`);
            try {
              const j = JSON.parse(s);
              const dps = j && j.dps ? j.dps : null;
              if (dps) {
                const temp = dps["3"];
                const heater = dps["1"];
                const maybeSetpoint = dps["10"];
                const parts = [];
                if (temp !== undefined) parts.push(`TEMP(dps3)=${temp}`);
                if (heater !== undefined) parts.push(`HEATER_ON(dps1)=${heater}`);
                if (maybeSetpoint !== undefined) parts.push(`DPS10=${maybeSetpoint}`);
                if (parts.length) console.log(`[state] ${parts.join(' ')}`);
              }
            } catch (e) {
              // ignore JSON parse failures
            }
          }
        } catch (e) {
          // ignore
        }
        return ret;
      };
    });
    console.log('[+] hooked ThingNetworkApi.parseAesData return value for telemetry');
  } catch (e) {
    // ignore
  }

  // Generic hook: anything named getLocalKey() on loaded *DeviceBean* classes.
  const candidates = [];
  Java.enumerateLoadedClasses({
    onMatch: function (name) {
      if (name.indexOf('DeviceBean') !== -1) candidates.push(name);
    },
    onComplete: function () {
      console.log(`[*] Loaded DeviceBean-like classes: ${candidates.length}`);
      let hooked = 0;
      candidates.forEach((cls) => {
        if (hookIfExists(cls, 'getLocalKey', function (_ovl, _args) {
          const v = this.getLocalKey();
          const key = safeString(v);
          if (key && key.length >= 6) {
            console.log(`[localKey] ${cls}.getLocalKey() -> "${key}" (len=${key.length})`);
          }
        })) hooked++;
      });
      console.log(`[*] Hooked getLocalKey() on ${hooked} classes`);
      console.log('[*] Ready. Now interact with SaunaLogic app to trigger calls.');
    }
  });
});

