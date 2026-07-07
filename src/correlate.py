#!/usr/bin/env python3
"""
correlate.py - Extract API-I/O correlation features from a CAPE report.

What it does
------------
  1. Extracts a file-write timeline from behavior.enhanced (timestamp, extension)
  2. Extracts a crypto-call timeline from behavior.processes[].calls
     (timestamp, buffer length, buffer entropy)
  3. Buckets the whole execution into fixed-size time windows and counts
     writes / crypto calls per window
  4. Computes a Pearson correlation between the two per-window time series,
     plus a few asymmetry statistics, and saves the windowed timeline as CSV

Usage
-----
  python3 correlate.py <report.json> [window_seconds]
  e.g. python3 correlate.py 37_report.json 1.0
"""

import sys
import json
import math
import csv
from datetime import datetime
from collections import defaultdict

# ---------- Helpers ----------

TS_FORMAT = "%Y-%m-%d %H:%M:%S,%f"


def parse_ts(ts):
    """Parse a CAPE timestamp string like '2026-03-23 16:00:46,004' into a datetime.
    Returns None if parsing fails."""
    if not ts:
        return None
    try:
        return datetime.strptime(ts.strip(), TS_FORMAT)
    except (ValueError, TypeError):
        return None


def shannon_entropy(byte_values):
    """Shannon entropy of a list of byte values (0-8). Encrypted data tends
    toward 8."""
    if not byte_values:
        return 0.0
    freq = defaultdict(int)
    for b in byte_values:
        freq[b] += 1
    n = len(byte_values)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def decode_buffer(raw):
    """
    Approximately decode a CAPE buffer string (e.g. '\\xba\\xe1...') into a
    list of byte values. This is a best-effort approximation for entropy
    estimation, not a byte-exact decoder.
    """
    if not raw:
        return []
    out = []
    i = 0
    s = raw
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt == 'x' and i + 3 < len(s):
                try:
                    out.append(int(s[i + 2:i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            # approximate escapes like \n \r \t \v
            escape_map = {'n': 10, 'r': 13, 't': 9, 'v': 11, '\\': 92}
            out.append(escape_map.get(nxt, ord(nxt)))
            i += 2
            continue
        out.append(ord(s[i]) & 0xff)
        i += 1
    return out


def get_extension(path):
    if not path or '.' not in path.split('\\')[-1]:
        return "(none)"
    return path.split('.')[-1].lower()


# ---------- Extraction ----------

def extract_file_writes(report):
    """Extract file write events from behavior.enhanced.
    Returns a list of (datetime, extension, path)."""
    writes = []
    for event in report.get("behavior", {}).get("enhanced", []):
        if event.get("object") == "file" and event.get("event") == "write":
            ts = parse_ts(event.get("timestamp"))
            path = event.get("data", {}).get("file", "")
            if ts:
                writes.append((ts, get_extension(path), path))
    return writes


def extract_crypto_calls(report):
    """Extract crypto API calls from behavior.processes[].calls.
    Returns a list of (datetime, length_bytes, entropy, api_name)."""
    events = []
    for process in report.get("behavior", {}).get("processes", []):
        for call in process.get("calls", []):
            if call.get("category") != "crypto":
                continue
            ts = parse_ts(call.get("timestamp"))
            if not ts:
                continue
            length = 0
            buf = None
            for arg in call.get("arguments", []):
                if arg.get("name") == "Length":
                    try:
                        length = int(arg.get("value", 0))
                    except (ValueError, TypeError):
                        length = 0
                if arg.get("name") == "Buffer":
                    buf = arg.get("value")
            entropy = shannon_entropy(decode_buffer(buf)) if buf else 0.0
            events.append((ts, length, entropy, call.get("api", "?")))
    return events


# ---------- Windowing ----------

def windowize(writes, crypto_events, window_sec):
    """Bucket events into fixed-size time windows starting from the earliest
    event, counting writes / crypto calls / crypto bytes per window."""
    all_ts = [w[0] for w in writes] + [c[0] for c in crypto_events]
    if not all_ts:
        return [], None, None
    t0 = min(all_ts)
    t_end = max(all_ts)

    def bucket_index(ts):
        return int((ts - t0).total_seconds() // window_sec)

    n_buckets = bucket_index(t_end) + 1
    write_counts = [0] * n_buckets
    crypto_counts = [0] * n_buckets
    crypto_bytes = [0] * n_buckets

    for ts, _ext, _path in writes:
        write_counts[bucket_index(ts)] += 1
    for ts, length, _entropy, _api in crypto_events:
        idx = bucket_index(ts)
        crypto_counts[idx] += 1
        crypto_bytes[idx] += length

    rows = []
    for i in range(n_buckets):
        rows.append({
            "window": i,
            "t_start_sec": round(i * window_sec, 3),
            "file_writes": write_counts[i],
            "crypto_calls": crypto_counts[i],
            "crypto_bytes": crypto_bytes[i],
        })
    return rows, t0, t_end


def pearson(xs, ys):
    n = len(xs)
    if n == 0:
        return None
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    numerator = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    denom_x = math.sqrt(sum((x - mean_x) ** 2 for x in xs))
    denom_y = math.sqrt(sum((y - mean_y) ** 2 for y in ys))
    if denom_x == 0 or denom_y == 0:
        return None  # correlation undefined when one series is constant
    return numerator / (denom_x * denom_y)


# ---------- Main ----------

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 correlate.py <report.json> [window_seconds]")
        sys.exit(1)
    path = sys.argv[1]
    window_sec = float(sys.argv[2]) if len(sys.argv) > 2 else 1.0

    with open(path, "r", errors="replace") as f:
        report = json.load(f)

    writes = extract_file_writes(report)
    crypto_events = extract_crypto_calls(report)

    print("=" * 60)
    print(f"File: {path}")
    print(f"Window size: {window_sec}s")
    print("=" * 60)
    print(f"File write events : {len(writes)}")
    print(f"Crypto events      : {len(crypto_events)}")

    if not writes and not crypto_events:
        print("\n[!] No writes and no crypto events found. Sample likely did not execute.")
        return

    # extension distribution (top 10)
    ext_counts = defaultdict(int)
    for _ts, ext, _path in writes:
        ext_counts[ext] += 1
    top_extensions = sorted(ext_counts.items(), key=lambda x: -x[1])[:10]
    print(f"\n[Top write extensions]")
    for ext, count in top_extensions:
        print(f"   .{ext:<12} {count}")

    # crypto API distribution + entropy
    if crypto_events:
        api_counts = defaultdict(int)
        entropies = [c[2] for c in crypto_events if c[2] > 0]
        for _ts, _len, _ent, api in crypto_events:
            api_counts[api] += 1
        print(f"\n[Crypto API distribution]")
        for api, count in sorted(api_counts.items(), key=lambda x: -x[1]):
            print(f"   {api:<20} {count}")
        if entropies:
            print(f"\n[Encrypted buffer entropy] mean {sum(entropies)/len(entropies):.3f} / "
                  f"min {min(entropies):.3f} / max {max(entropies):.3f}  (closer to 8.0 = more encrypted)")

    # windowing + correlation
    rows, t0, t_end = windowize(writes, crypto_events, window_sec)
    duration = (t_end - t0).total_seconds() if t0 and t_end else 0
    print(f"\n[Timeline] total {duration:.1f}s, {len(rows)} windows")

    xs = [r["file_writes"] for r in rows]
    ys = [r["crypto_calls"] for r in rows]
    r = pearson(xs, ys)
    active_windows = [row for row in rows if row["file_writes"] or row["crypto_calls"]]
    both_windows = [row for row in rows if row["file_writes"] and row["crypto_calls"]]

    print(f"\n[Correlation metrics]")
    if r is None:
        print("   Pearson correlation: undefined (one series is all zero - possible asymmetry signal)")
    else:
        print(f"   Pearson correlation (write vs crypto, per window): {r:.3f}")
    print(f"   Windows with write or crypto activity : {len(active_windows)}")
    print(f"   Windows with BOTH (co-occurrence)      : {len(both_windows)}")
    if active_windows:
        print(f"   Co-occurrence ratio                    : {len(both_windows)/len(active_windows):.2%}")

    # asymmetry signal: writes present but no crypto in the same window
    write_only_windows = [row for row in rows if row["file_writes"] and not row["crypto_calls"]]
    print(f"   Windows with writes but no crypto      : {len(write_only_windows)}  (asymmetry axis candidate)")

    # save CSV
    out_csv = path.rsplit(".", 1)[0] + f"_timeline_{window_sec}s.csv"
    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["window", "t_start_sec", "file_writes", "crypto_calls", "crypto_bytes"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"\n[saved] windowed timeline -> {out_csv}")
    print("        (plot this CSV to see whether writes/crypto move together over time)")


if __name__ == "__main__":
    main()
