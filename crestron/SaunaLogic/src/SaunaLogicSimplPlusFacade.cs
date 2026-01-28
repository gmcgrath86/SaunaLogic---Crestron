using System;

namespace SunValleyHQ.Sauna
{
    /// <summary>
    /// SIMPL+-friendly facade:
    /// - no exceptions escape
    /// - returns ushort success flags
    /// - provides pull-style getters for the last polled snapshot
    /// </summary>
    public sealed class SaunaLogicSimplPlusFacade
    {
        private readonly SaunaLogicClient _client = new SaunaLogicClient();

        private string _lastError = "";
        private ushort _onlineFb = 0;

        private ushort _heaterOnFb = 0;
        private ushort _temp = 0;
        private ushort _setpoint = 0;
        private string _unit = "";
        private string _lastSnapshotJson = "";

        private const int RetryCount = 3;
        private const int FailureThresholdForBackoff = 2;
        private const int BackoffMs = 10000;

        private int _consecutiveFailures;
        private DateTime _backoffUntilUtc = DateTime.MinValue;

        public ushort Configure(string host, string localKey, string devId, string uid)
        {
            try
            {
                _client.Host = host;
                _client.LocalKey = localKey;
                _client.DevId = devId;
                _client.Uid = uid;
                _lastError = "";
                _onlineFb = 1;
                return 1;
            }
            catch (Exception ex)
            {
                _lastError = ex.Message;
                _onlineFb = 0;
                return 0;
            }
        }

        public ushort PollSnapshot()
        {
            try
            {
                string err;
                if (!PollSnapshotInternal(false, out err))
                {
                    _lastError = err ?? "Poll failed.";
                    _onlineFb = 0;
                    NoteFailure();
                    return 0;
                }
                NoteSuccess();
                return 1;
            }
            catch (Exception ex)
            {
                _lastError = ex.Message;
                _onlineFb = 0;
                return 0;
            }
        }

        public ushort HeaterOn()
        {
            try
            {
                string busyError;
                if (IsInBackoff(out busyError))
                {
                    _lastError = busyError;
                    _onlineFb = 0;
                    return 0;
                }

                string err;
                if (!RetryHeaterOn(true, out err))
                {
                    _lastError = err ?? "HeaterOn failed.";
                    _onlineFb = 0;
                    NoteFailure();
                    return 0;
                }
                if (!VerifyHeaterState(true, out err))
                {
                    _lastError = err ?? "HeaterOn sent, but state not updated.";
                    _onlineFb = 1;
                    return 0;
                }
                NoteSuccess();
                _lastError = "";
                _onlineFb = 1;
                return 1;
            }
            catch (Exception ex)
            {
                _lastError = ex.Message;
                _onlineFb = 0;
                return 0;
            }
        }

        public ushort HeaterOff()
        {
            try
            {
                string busyError;
                if (IsInBackoff(out busyError))
                {
                    _lastError = busyError;
                    _onlineFb = 0;
                    return 0;
                }

                string err;
                if (!RetryHeaterOn(false, out err))
                {
                    _lastError = err ?? "HeaterOff failed.";
                    _onlineFb = 0;
                    NoteFailure();
                    return 0;
                }
                if (!VerifyHeaterState(false, out err))
                {
                    _lastError = err ?? "HeaterOff sent, but state not updated.";
                    _onlineFb = 1;
                    return 0;
                }
                NoteSuccess();
                _lastError = "";
                _onlineFb = 1;
                return 1;
            }
            catch (Exception ex)
            {
                _lastError = ex.Message;
                _onlineFb = 0;
                return 0;
            }
        }

        public ushort SetSetpoint(ushort setpoint)
        {
            try
            {
                string busyError;
                if (IsInBackoff(out busyError))
                {
                    _lastError = busyError;
                    _onlineFb = 0;
                    return 0;
                }

                string err;
                if (!RetrySetpoint(setpoint, out err))
                {
                    _lastError = err ?? "SetSetpoint failed.";
                    _onlineFb = 0;
                    NoteFailure();
                    return 0;
                }
                if (!VerifySetpoint(setpoint, out err))
                {
                    _lastError = err ?? "SetSetpoint sent, but value not updated.";
                    _onlineFb = 1;
                    return 0;
                }
                NoteSuccess();
                _lastError = "";
                _onlineFb = 1;
                return 1;
            }
            catch (Exception ex)
            {
                _lastError = ex.Message;
                _onlineFb = 0;
                return 0;
            }
        }

        public ushort GetOnlineFb() { return _onlineFb; }
        public string GetLastError() { return _lastError ?? ""; }
        public ushort GetHeaterOnFb() { return _heaterOnFb; }
        public ushort GetTemp() { return _temp; }
        public ushort GetSetpoint() { return _setpoint; }
        public string GetUnit() { return _unit ?? ""; }
        public string GetLastSnapshotJson() { return _lastSnapshotJson ?? ""; }

        private bool RetryPollSnapshot(out string json, out string lastError)
        {
            json = null;
            lastError = null;
            for (int i = 0; i < RetryCount; i++)
            {
                string err;
                var result = _client.PollDpSnapshotJson(out err);
                if (!string.IsNullOrEmpty(result))
                {
                    json = result;
                    lastError = null;
                    return true;
                }
                lastError = err ?? "Poll failed.";
                // No sleep here; Crestron sandbox blocks System.Threading.Thread.Sleep.
            }
            return false;
        }

        private bool RetryHeaterOn(bool on, out string lastError)
        {
            lastError = null;
            for (int i = 0; i < RetryCount; i++)
            {
                string err;
                if (_client.SendHeaterOn(on, out err))
                {
                    lastError = null;
                    return true;
                }
                lastError = err ?? (on ? "HeaterOn failed." : "HeaterOff failed.");
                // No sleep here; Crestron sandbox blocks System.Threading.Thread.Sleep.
            }
            return false;
        }

        private bool RetrySetpoint(ushort setpoint, out string lastError)
        {
            lastError = null;
            for (int i = 0; i < RetryCount; i++)
            {
                string err;
                if (_client.SendSetpoint(setpoint, out err))
                {
                    lastError = null;
                    return true;
                }
                lastError = err ?? "SetSetpoint failed.";
                // No sleep here; Crestron sandbox blocks System.Threading.Thread.Sleep.
            }
            return false;
        }

        private bool IsInBackoff(out string lastError)
        {
            lastError = null;
            if (DateTime.UtcNow < _backoffUntilUtc)
            {
                lastError = "Controller busy; waiting for other session to release.";
                return true;
            }
            return false;
        }

        private bool PollSnapshotInternal(bool ignoreBackoff, out string lastError)
        {
            lastError = null;
            if (!ignoreBackoff)
            {
                string busyError;
                if (IsInBackoff(out busyError))
                {
                    lastError = busyError;
                    return false;
                }
            }

            string err;
            string json;
            if (!RetryPollSnapshot(out json, out err))
            {
                lastError = err ?? "Poll failed.";
                return false;
            }

            _lastSnapshotJson = json;
            _onlineFb = 1;
            _lastError = "";

            bool heater;
            int v;
            if (SaunaJson.TryGetDpsBool(json, "1", out heater)) _heaterOnFb = (ushort)(heater ? 1 : 0);
            if (SaunaJson.TryGetDpsInt(json, "2", out v)) _setpoint = (ushort)Math.Max(0, Math.Min(65535, v));
            if (SaunaJson.TryGetDpsInt(json, "3", out v)) _temp = (ushort)Math.Max(0, Math.Min(65535, v));
            string unit;
            if (SaunaJson.TryGetDpsValueRaw(json, "107", out unit)) _unit = unit ?? "";
            return true;
        }

        private bool VerifyHeaterState(bool expectedOn, out string lastError)
        {
            lastError = null;
            string err;
            if (!PollSnapshotInternal(true, out err))
            {
                lastError = "Verify poll failed: " + (err ?? "unknown");
                return false;
            }
            var actualOn = _heaterOnFb > 0;
            if (actualOn != expectedOn)
            {
                lastError = "Command sent but heater state unchanged.";
                return false;
            }
            return true;
        }

        private bool VerifySetpoint(ushort expected, out string lastError)
        {
            lastError = null;
            string err;
            if (!PollSnapshotInternal(true, out err))
            {
                lastError = "Verify poll failed: " + (err ?? "unknown");
                return false;
            }
            if (_setpoint != expected)
            {
                lastError = "Command sent but setpoint unchanged.";
                return false;
            }
            return true;
        }

        private void NoteFailure()
        {
            _consecutiveFailures++;
            if (_consecutiveFailures >= FailureThresholdForBackoff)
            {
                _backoffUntilUtc = DateTime.UtcNow.AddMilliseconds(BackoffMs);
            }
        }

        private void NoteSuccess()
        {
            _consecutiveFailures = 0;
            _backoffUntilUtc = DateTime.MinValue;
        }
    }
}

