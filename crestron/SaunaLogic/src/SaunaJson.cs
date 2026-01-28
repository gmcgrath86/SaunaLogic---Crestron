using System;

namespace SunValleyHQ.Sauna
{
    /// <summary>
    /// Minimal JSON extraction helpers (no external deps) for the small Tuya DPS snapshots.
    /// This is intentionally not a general JSON parser.
    /// </summary>
    internal static class SaunaJson
    {
        public static bool TryGetTopLevelString(string json, string key, out string value)
        {
            value = null;
            if (string.IsNullOrEmpty(json) || string.IsNullOrEmpty(key)) return false;

            var idx = json.IndexOf("\"" + key + "\"", StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return false;
            idx = json.IndexOf(':', idx);
            if (idx < 0) return false;
            idx++;
            while (idx < json.Length && char.IsWhiteSpace(json[idx])) idx++;
            if (idx >= json.Length || json[idx] != '"') return false;
            idx++;
            var start = idx;
            while (idx < json.Length)
            {
                var c = json[idx++];
                if (c == '\\') { idx++; continue; }
                if (c == '"') break;
            }
            if (idx <= start) return false;
            value = json.Substring(start, idx - start - 1);
            return true;
        }

        public static bool TryGetDpsValueRaw(string json, string dpsKey, out string raw)
        {
            raw = null;
            if (string.IsNullOrEmpty(json) || string.IsNullOrEmpty(dpsKey)) return false;
            var dpsIdx = json.IndexOf("\"dps\"", StringComparison.OrdinalIgnoreCase);
            if (dpsIdx < 0) return false;
            dpsIdx = json.IndexOf('{', dpsIdx);
            if (dpsIdx < 0) return false;

            var keyIdx = json.IndexOf("\"" + dpsKey + "\"", dpsIdx, StringComparison.OrdinalIgnoreCase);
            if (keyIdx < 0) return false;
            keyIdx = json.IndexOf(':', keyIdx);
            if (keyIdx < 0) return false;
            keyIdx++;
            while (keyIdx < json.Length && char.IsWhiteSpace(json[keyIdx])) keyIdx++;
            if (keyIdx >= json.Length) return false;

            // value can be true/false/number/"string"
            if (json[keyIdx] == '"')
            {
                keyIdx++;
                var start = keyIdx;
                while (keyIdx < json.Length)
                {
                    var c = json[keyIdx++];
                    if (c == '\\') { keyIdx++; continue; }
                    if (c == '"') break;
                }
                raw = json.Substring(start, keyIdx - start - 1);
                return true;
            }

            var end = keyIdx;
            while (end < json.Length && json[end] != ',' && json[end] != '}') end++;
            raw = json.Substring(keyIdx, end - keyIdx).Trim();
            return true;
        }

        public static bool TryGetDpsBool(string json, string dpsKey, out bool value)
        {
            value = false;
            string raw;
            if (!TryGetDpsValueRaw(json, dpsKey, out raw)) return false;
            if (string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase)) { value = true; return true; }
            if (string.Equals(raw, "false", StringComparison.OrdinalIgnoreCase)) { value = false; return true; }
            return false;
        }

        public static bool TryGetDpsInt(string json, string dpsKey, out int value)
        {
            value = 0;
            string raw;
            if (!TryGetDpsValueRaw(json, dpsKey, out raw)) return false;
            int v;
            // Crestron SIMPL# toolchains sometimes lack Int32.TryParse; use Parse() guarded by try/catch.
            try { v = Int32.Parse(raw); }
            catch { return false; }
            value = v;
            return true;
        }
    }
}

