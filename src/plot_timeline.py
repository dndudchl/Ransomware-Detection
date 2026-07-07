#!/usr/bin/env python3
"""
plot_timeline.py - Visualize the timeline CSV produced by correlate.py.

Plots file writes and crypto calls on the same time axis to show:
  - whether the two signals rise and fall together (consistency axis)
  - which windows have writes but no crypto (asymmetry axis)

Usage
-----
  python3 plot_timeline.py <timeline.csv>
  e.g. python3 plot_timeline.py 37_report_timeline_1.0s.csv

Requires matplotlib: pip install matplotlib
"""

import sys
import csv


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 plot_timeline.py <timeline.csv>")
        sys.exit(1)
    csv_path = sys.argv[1]

    try:
        import matplotlib
        matplotlib.use("Agg")  # works on headless servers too
        import matplotlib.pyplot as plt
    except ImportError:
        print("[!] matplotlib not found. Install with: pip install matplotlib")
        sys.exit(1)

    t, writes, crypto_calls, crypto_bytes = [], [], [], []
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            t.append(float(row["t_start_sec"]))
            writes.append(int(row["file_writes"]))
            crypto_calls.append(int(row["crypto_calls"]))
            crypto_bytes.append(int(row["crypto_bytes"]))

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 8), sharex=True)

    # top: overlay write vs crypto over time
    ax1.plot(t, writes, label="file writes", linewidth=1.2)
    ax1.plot(t, crypto_calls, label="crypto calls", linewidth=1.2, alpha=0.8)
    # shade asymmetric windows (write > 0, crypto == 0)
    window_width = t[1] - t[0] if len(t) > 1 else 1
    for i in range(len(t)):
        if writes[i] > 0 and crypto_calls[i] == 0:
            ax1.axvspan(t[i], t[i] + window_width, color="red", alpha=0.12)
    ax1.set_ylabel("events per window")
    ax1.set_title("File writes vs Crypto calls over time\n"
                   "(red band = write present, crypto absent = asymmetry)")
    ax1.legend()
    ax1.grid(alpha=0.3)

    # bottom: scatter to visualize correlation
    ax2.scatter(writes, crypto_calls, s=12, alpha=0.5)
    ax2.set_xlabel("file writes (per window)")
    ax2.set_ylabel("crypto calls (per window)")
    ax2.set_title("Correlation scatter: each dot = one time window")
    ax2.grid(alpha=0.3)

    plt.tight_layout()
    out_path = csv_path.rsplit(".", 1)[0] + "_plot.png"
    plt.savefig(out_path, dpi=130)
    print(f"[saved] plot -> {out_path}")


if __name__ == "__main__":
    main()
