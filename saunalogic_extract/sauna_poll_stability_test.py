#!/usr/bin/env python3
"""
Quick stability test for SaunaLogic LAN polling.

Runs N polls back-to-back using the Type-10 DP snapshot query and reports success rate and timings.

Usage:
  python3 saunalogic_extract/sauna_poll_stability_test.py --host <DEVICE_IP> --key "<LOCAL_KEY>" --count 50
"""

from __future__ import annotations

import argparse
import subprocess
import time


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.1.100")
    ap.add_argument("--key", required=True)
    ap.add_argument("--count", type=int, default=20)
    args = ap.parse_args()

    ok = 0
    fail = 0
    times = []
    last = None

    for i in range(1, args.count + 1):
        t0 = time.time()
        p = subprocess.run(
            [
                "python3",
                "saunalogic_extract/sauna_live_poll.py",
                "--host",
                args.host,
                "--key",
                args.key,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        dt = (time.time() - t0) * 1000.0
        times.append(dt)
        if p.returncode == 0 and "temp(dps3):" in p.stdout:
            ok += 1
            last = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else None
            print(f"[{i:02d}/{args.count}] ok {dt:.0f}ms")
        else:
            fail += 1
            print(f"[{i:02d}/{args.count}] FAIL {dt:.0f}ms")
            print(p.stdout.strip()[:500])

    if times:
        times_sorted = sorted(times)
        p50 = times_sorted[int(0.50 * (len(times_sorted) - 1))]
        p95 = times_sorted[int(0.95 * (len(times_sorted) - 1))]
        mx = times_sorted[-1]
    else:
        p50 = p95 = mx = 0

    print("---")
    print("ok:", ok, "fail:", fail)
    print(f"latency_ms p50={p50:.0f} p95={p95:.0f} max={mx:.0f}")
    if last:
        print("last_raw_dps_line:", last)
    return 0 if fail == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())

