using System;
using System.Text;

namespace SunValleyHQ.Sauna
{
    internal sealed class SaunaLogicClient
    {
        // Captured Type-10 DP snapshot query (cmd=10) from docs/saunalogic-pcap-notes.md.
        // We reuse this exact request bytes because it is known-good and does not require building a nonce.
        private static readonly byte[] Type10DpSnapshotQuery = HexToBytes(
            "000055aa000005950000000a00000048" +
            "462ebb16e2667b75b5c3eefed6886d5610fffe31bb2a4954da937633eb4da222" +
            "13e58805e31f87ed159506545b2366e98b06c2f6f0199f8a2f35996f580cd2bbab2eb66f" +
            "0000aa55");

        // Type-7 payload prefix observed in working command frames:
        // "3.3" + 12 bytes of header-like fields before ciphertext.
        private static readonly byte[] Type7Prefix15 = HexToBytes("332e33000000000000000300000000");

        public string Host { get; set; }
        public int Port { get; set; }
        public string LocalKey { get; set; } // 16 ASCII chars
        public string DevId { get; set; }
        public string Uid { get; set; } // optional (some devices accept without)

        public SaunaLogicClient()
        {
            Port = 6668;
        }

        public string PollDpSnapshotJson(out string lastError)
        {
            lastError = null;
            // Retry once on no-response, as the controller can be finicky with back-to-back sockets.
            for (int attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    // NOTE: Crestron SIMPL# sandbox blocks System.Net.Sockets; use CrestronSockets TCPClient instead.
                    // This file is intended to be compiled under Crestron SIMPL# Library tooling where CrestronSockets is available.
                    var buf = new byte[4096];
                    var have = 0;
                    var deadline = DateTime.UtcNow.AddMilliseconds(3000);

                    // Crestron socket client (namespace: Crestron.SimplSharp.CrestronSockets)
                    // Expected common API:
                    //   var c = new TCPClient(host, port, bufferSize);
                    //   var status = c.ConnectToServer();
                    //   c.SendData(byte[] data, int len);
                    //   int n = c.ReceiveData();
                    //   byte[] rx = c.IncomingDataBuffer;
                    //   c.DisconnectFromServer();
                    Crestron.SimplSharp.CrestronSockets.TCPClient c =
                        new Crestron.SimplSharp.CrestronSockets.TCPClient(Host, Port, 4096);

                    var status = c.ConnectToServer();
                    if (status != 0)
                    {
                        lastError = "ConnectToServer failed: " + status;
                        return null;
                    }

                    var sent = c.SendData(Type10DpSnapshotQuery, Type10DpSnapshotQuery.Length);
                    if (!IsSocketOk(sent))
                    {
                        try { c.DisconnectFromServer(); } catch { }
                        lastError = "SendData(Type10) failed: " + sent;
                        return null;
                    }

                    while (DateTime.UtcNow < deadline)
                    {
                        var n = c.ReceiveData();
                        if (n > 0)
                        {
                            var rx = c.IncomingDataBuffer;
                            var toCopy = Math.Min(n, buf.Length - have);
                            Buffer.BlockCopy(rx, 0, buf, have, toCopy);
                            have += toCopy;
                        }

                        int start, len;
                        if (SaunaTuyaFrame.TryParseOneFrame(buf, 0, have, out start, out len))
                        {
                            var frame = new byte[len];
                            Buffer.BlockCopy(buf, start, frame, 0, len);
                            var cmd = SaunaTuyaFrame.ReadU32BE(frame, 8);
                            // Drop the consumed frame from the buffer so we can keep scanning (cmd=9 keepalive can appear).
                            var remaining = have - (start + len);
                            if (remaining > 0) Buffer.BlockCopy(buf, start + len, buf, 0, remaining);
                            have = Math.Max(0, remaining);

                            if (cmd == 10)
                            {
                                var json = TryDecryptFrameToJson(frame);
                                if (!string.IsNullOrEmpty(json))
                                {
                                    try { c.DisconnectFromServer(); } catch { }
                                    return json;
                                }
                            }
                        }
                    }

                    try { c.DisconnectFromServer(); } catch { }
                    lastError = "No DP snapshot response received.";
                }
                catch (Exception ex)
                {
                    lastError = ex.Message;
                }
            }

            return null;
        }

        public bool SendHeaterOn(bool on, out string lastError)
        {
            // Some firmwares require mode to be included with heater writes.
            return SendDpsWriteBoolWithMode("1", on, "4", "ONLY_TRAD", out lastError);
        }

        public bool SendSetpoint(int setpoint, out string lastError)
        {
            return SendDpsWriteInt("2", setpoint, out lastError);
        }

        private bool SendDpsWriteBool(string dpsKey, bool value, out string lastError)
        {
            lastError = null;
            try
            {
                var json = BuildDpsWriteJson(dpsKey, value ? "true" : "false");
                return SendType7Json(json, out lastError);
            }
            catch (Exception ex)
            {
                lastError = ex.Message;
                return false;
            }
        }

        private bool SendDpsWriteBoolWithMode(string dpsKey, bool value, string modeKey, string modeValue, out string lastError)
        {
            lastError = null;
            try
            {
                var json = BuildDpsWriteJsonWithMode(dpsKey, value ? "true" : "false", modeKey, modeValue);
                return SendType7Json(json, out lastError);
            }
            catch (Exception ex)
            {
                lastError = ex.Message;
                return false;
            }
        }

        private bool SendDpsWriteInt(string dpsKey, int value, out string lastError)
        {
            lastError = null;
            try
            {
                var json = BuildDpsWriteJson(dpsKey, value.ToString());
                return SendType7Json(json, out lastError);
            }
            catch (Exception ex)
            {
                lastError = ex.Message;
                return false;
            }
        }

        private string BuildDpsWriteJson(string dpsKey, string rawValue)
        {
            // RawValue is already json literal (true/false/number/"string").
            // Include uid if provided; some firmware expects it.
            var t = (int)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            var sb = new StringBuilder();
            sb.Append("{\"devId\":\"").Append(DevId ?? "").Append("\",\"dps\":{");
            sb.Append("\"").Append(dpsKey).Append("\":").Append(rawValue);
            sb.Append("},\"t\":").Append(t);
            if (!string.IsNullOrEmpty(Uid))
            {
                sb.Append(",\"uid\":\"").Append(Uid).Append("\"");
            }
            sb.Append("}");
            return sb.ToString();
        }

        private string BuildDpsWriteJsonWithMode(string dpsKey, string rawValue, string modeKey, string modeValue)
        {
            // RawValue is already json literal (true/false/number/"string").
            // ModeValue is treated as string literal.
            var t = (int)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            var sb = new StringBuilder();
            sb.Append("{\"devId\":\"").Append(DevId ?? "").Append("\",\"dps\":{");
            sb.Append("\"").Append(dpsKey).Append("\":").Append(rawValue);
            sb.Append(",\"").Append(modeKey).Append("\":\"").Append(modeValue).Append("\"");
            sb.Append("},\"t\":").Append(t);
            if (!string.IsNullOrEmpty(Uid))
            {
                sb.Append(",\"uid\":\"").Append(Uid).Append("\"");
            }
            sb.Append("}");
            return sb.ToString();
        }

        private bool SendType7Json(string json, out string lastError)
        {
            lastError = null;
            if (string.IsNullOrEmpty(LocalKey) || LocalKey.Length != 16) { lastError = "LocalKey must be 16 chars."; return false; }
            if (string.IsNullOrEmpty(Host)) { lastError = "Host empty."; return false; }
            if (string.IsNullOrEmpty(DevId)) { lastError = "DevId empty."; return false; }

            // Encrypt JSON (PKCS7 padded) with AES-128-ECB
            var pt = Encoding.UTF8.GetBytes(json);
            var ct = SaunaCrypto.Aes128EcbEncrypt(LocalKey, pt);

            // Build a Type-7 frame.
            // For simplicity we reuse the observed 15-byte prefix template, but update the 4-byte counter:
            // last 4 bytes of prefix represent an incrementing request id in captures (00000003/00000004).
            // We'll use a monotonic counter.
            var prefix = new byte[Type7Prefix15.Length];
            Buffer.BlockCopy(Type7Prefix15, 0, prefix, 0, prefix.Length);
            // prefix bytes (from pcap): "3.3" + 6x00 + 000003 + <requestId u32>
            // We overwrite the 4 bytes starting at index 11 with a counter/requestId.
            var counter = unchecked((uint)Environment.TickCount);
            SaunaTuyaFrame.WriteU32BE(prefix, 11, counter);

            // Build and send the command frame. Empirically the device is more reliable if we:
            //  - connect
            //  - send Type-10 snapshot query
            //  - read until we see the cmd=10 response (or timeout)
            //  - then send cmd=7 write
            // Some devices will drop the socket if we send cmd=7 too early; if that happens, retry once.
            return SendType7WithHandshakeAndRetry(ct, prefix, out lastError);
        }

        private bool SendType7WithHandshakeAndRetry(byte[] ct, byte[] prefix, out string lastError)
        {
            lastError = null;

            for (int attempt = 0; attempt < 2; attempt++)
            {
                Crestron.SimplSharp.CrestronSockets.TCPClient c = null;
                try
                {
                    var seq = unchecked((uint)Environment.TickCount);
                    var frame = SaunaTuyaFrame.BuildFrame(seq, 7, ct, prefix);

                    c = new Crestron.SimplSharp.CrestronSockets.TCPClient(Host, Port, 4096);
                    var status = c.ConnectToServer();
                    if (status != 0)
                    {
                        lastError = "ConnectToServer failed: " + status;
                        return false;
                    }

                    // Type-10 snapshot query first (mirrors app open).
                    var sent = c.SendData(Type10DpSnapshotQuery, Type10DpSnapshotQuery.Length);
                    if (!IsSocketOk(sent)) throw new Exception("SendData(Type10) failed: " + sent);

                    // Wait for cmd=10 response (do not decrypt; just consume so device is "ready").
                    var got10 = WaitForCmd10(c, 4000);
                    if (!got10)
                    {
                        // If we never saw cmd=10, don't send cmd=7 on this socket. Retry with fresh connection.
                        throw new Exception("Handshake timeout: no cmd=10 response.");
                    }

                    // Send command frame
                    sent = c.SendData(frame, frame.Length);
                    if (!IsSocketOk(sent)) throw new Exception("SendData(cmd7) failed: " + sent);

                    // Best-effort read/ignore (some firmwares respond; others don't)
                    try { c.ReceiveData(); } catch { }
                    try { c.DisconnectFromServer(); } catch { }
                    return true;
                }
                catch (Exception ex)
                {
                    // If the socket gets dropped (BrokenPipe-like), retry once with a fresh connection.
                    lastError = ex.Message;
                    try { if (c != null) c.DisconnectFromServer(); } catch { }
                }
            }

            if (string.IsNullOrEmpty(lastError)) lastError = "SendType7 failed.";
            return false;
        }

        private static bool IsSocketOk(object status)
        {
            if (status == null) return false;

            // Crestron socket APIs sometimes return enums like "SOCKET_OK" rather than byte counts.
            var s = status.ToString() ?? "";
            if (string.Equals(s, "SOCKET_OK", StringComparison.OrdinalIgnoreCase)) return true;

            try
            {
                // 0 is commonly "OK" for status-returning APIs.
                return Convert.ToInt32(status) == 0;
            }
            catch
            {
                return false;
            }
        }

        private static bool WaitForCmd10(Crestron.SimplSharp.CrestronSockets.TCPClient c, int timeoutMs)
        {
            if (c == null) return false;

            var buf = new byte[4096];
            var have = 0;
            var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs < 100 ? 100 : timeoutMs);

            while (DateTime.UtcNow < deadline)
            {
                int n = 0;
                try { n = c.ReceiveData(); } catch { n = 0; }
                if (n > 0)
                {
                    var rx = c.IncomingDataBuffer;
                    var toCopy = Math.Min(n, buf.Length - have);
                    if (toCopy > 0)
                    {
                        Buffer.BlockCopy(rx, 0, buf, have, toCopy);
                        have += toCopy;
                    }
                }

                int start, len;
                if (SaunaTuyaFrame.TryParseOneFrame(buf, 0, have, out start, out len))
                {
                    // cmd is u32 BE at offset 8
                    var cmd = SaunaTuyaFrame.ReadU32BE(buf, start + 8);
                    if (cmd == 10) return true;

                    // Drop the consumed frame from the buffer and keep going.
                    var remaining = have - (start + len);
                    if (remaining > 0) Buffer.BlockCopy(buf, start + len, buf, 0, remaining);
                    have = Math.Max(0, remaining);
                }
            }

            return false;
        }

        private string TryDecryptFrameToJson(byte[] frame)
        {
            try
            {
                var ll = (int)SaunaTuyaFrame.ReadU32BE(frame, 12);
                if (ll <= 8 || ll > 2000) return null;
                // Body includes crc+tail; ciphertext is embedded. Brute like our python helper.
                var body = new byte[ll];
                Buffer.BlockCopy(frame, 16, body, 0, ll);

                // Try common slices; for cmd=10 response the correct slice is [4 : ll-8].
                var tailTrims = new int[] { 8, 12, 16, 0, 4 };
                for (int start = 0; start < Math.Min(256, body.Length); start++)
                {
                    for (int tt = 0; tt < tailTrims.Length; tt++)
                    {
                        var trim = tailTrims[tt];
                        var end = body.Length - trim;
                        if (end <= start) continue;
                        var len = end - start;
                        if (len <= 0 || (len % 16) != 0) continue;

                        var ct = new byte[len];
                        Buffer.BlockCopy(body, start, ct, 0, len);
                        byte[] pt;
                        try
                        {
                            pt = SaunaCrypto.Aes128EcbDecrypt(LocalKey, ct);
                        }
                        catch
                        {
                            continue;
                        }
                        // Some Crestron SDK builds only expose GetString(byte[], int, int).
                        var s = Encoding.UTF8.GetString(pt, 0, pt.Length).Trim('\0', ' ', '\r', '\n', '\t');
                        if (s.IndexOf("\"dps\"", StringComparison.OrdinalIgnoreCase) >= 0 && s.IndexOf('{') >= 0)
                        {
                            return s;
                        }
                    }
                }
            }
            catch { }
            return null;
        }

        private static byte[] HexToBytes(string hex)
        {
            if (hex == null) return new byte[0];
            hex = hex.Replace(" ", "").Replace("\r", "").Replace("\n", "").Replace("\t", "");
            if ((hex.Length % 2) != 0) throw new ArgumentException("Odd-length hex");
            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
    }
}

