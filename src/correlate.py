#!/usr/bin/env python3
"""
correlate.py - Extract API-I/O and file-lifecycle correlation features
from a CAPE sandbox report.

Background
----------
Early analysis (WannaCry vs a benign 7-Zip AES-encryption run) showed that
a single feature is not enough to separate ransomware from benign encryption
tools:
  - write<->crypto-API correlation is undermined by ransomware that uses a
    statically-linked / custom crypto implementation (no Windows crypto API
    calls at all), which looks identical to a benign program that also
    avoids the crypto API (e.g. 7-Zip).
  - A "write-heavy" signal alone is undermined by any benign program that
    writes a lot of data (backup tools, archivers, sync clients).

What reliably separated the two cases we've observed so far is the file
LIFECYCLE: ransomware reads an original file, writes an encrypted/renamed
version, and then deletes or moves (renames) the original -- a destructive
read -> write -> delete/move chain. Benign encryption tools (e.g. 7-Zip)
read originals and write a new archive, but do not delete or rename the
originals.

This script computes both:
  (a) the original write<->crypto-API correlation (kept for reference /
      comparison, since it is still informative when the crypto API IS used)
  (b) file lifecycle features: per-event-type counts, destructive ratios,
      and a windowed "chain" metric that counts how many time windows show
      read+write+delete occurring together (destructive chain) versus
      read+write only (non-destructive, e.g. archiving).

Usage
-----
  python3 correlate.py <report.json> [window_seconds]
  python3 correlate.py <report.json> [window_seconds] --features-out <features.csv> --label ransomware --sample-id 37

  --features-out   Append a single summary row (one row per sample) to a
                    feature table CSV. Useful for building a dataset across
                    many samples for later model comparison.
  --label          Optional label to store in the feature row (e.g.
                    "ransomware" / "benign"). Purely informational, not
                    used in the correlation math.
  --sample-id      Optional identifier to store in the feature row
                    (e.g. the CAPE task id). Defaults to the report filename.
"""

import sys
import json
import math
import csv
import argparse
from datetime import datetime
from collections import defaultdict

# ---------- Helpers ----------

TS_FORMAT = "%Y-%m-%d %H:%M:%S,%f"

FILE_EVENT_TYPES = ["read", "write", "delete", "move", "copy", "execute"]
# Events considered "destructive" to the original file (i.e. the kind of
# activity a ransomware encryption pass produces on top of a write).
DESTRUCTIVE_EVENT_TYPES = ["delete", "move"]


def parse_ts(ts):
    """Parse a CAPE timestamp string like '2026-03-23 16:00:46,004' into a
    datetime object. Returns None if parsing fails."""
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
    list of byte values. Best-effort approximation for entropy estimation,
    not a byte-exact decoder.
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


# ---------- Extraction: crypto correlation (original analysis) ----------

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


# ---------- Extraction: file lifecycle events (NEW) ----------

def extract_file_lifecycle_events(report):
    """
    Extract ALL file object events from behavior.enhanced (not just writes).
    Returns a list of (datetime, event_type, extension, path) for event
    types in FILE_EVENT_TYPES.
    """
    events = []
    for event in report.get("behavior", {}).get("enhanced", []):
        if event.get("object") != "file":
            continue
        event_type = event.get("event")
        if event_type not in FILE_EVENT_TYPES:
            continue
        ts = parse_ts(event.get("timestamp"))
        if not ts:
            continue
        path = event.get("data", {}).get("file", "")
        events.append((ts, event_type, get_extension(path), path))
    return events


def compute_lifecycle_counts(lifecycle_events):
    """Count file lifecycle events by type."""
    counts = {event_type: 0 for event_type in FILE_EVENT_TYPES}
    for _ts, event_type, _ext, _path in lifecycle_events:
        counts[event_type] += 1
    return counts


def compute_lifecycle_ratios(counts):
    """
    Compute destructive ratios relative to write count.
    A ransomware-style destructive-replace pattern (read original -> write
    encrypted version -> delete/rename original) should show delete/write
    and move/write ratios well above zero. A benign archiving tool (reads
    originals, writes a new archive, does not touch the originals) should
    show these ratios near zero.
    """
    writes = counts.get("write", 0)
    if writes == 0:
        return {"delete_to_write_ratio": None, "move_to_write_ratio": None}
    return {
        "delete_to_write_ratio": counts.get("delete", 0) / writes,
        "move_to_write_ratio": counts.get("move", 0) / writes,
    }


# ---------- Windowing ----------

def windowize_crypto(writes, crypto_events, window_sec):
    """Bucket write and crypto events into fixed-size time windows.
    Returns rows with file_writes / crypto_calls / crypto_bytes per window,
    plus the window start/end datetimes."""
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


def windowize_lifecycle(lifecycle_events, window_sec):
    """
    Bucket file lifecycle events (read/write/delete/move/copy/execute) into
    fixed-size time windows. Returns a list of dicts, one per window, with
    a count for each event type.
    """
    if not lifecycle_events:
        return []
    all_ts = [e[0] for e in lifecycle_events]
    t0 = min(all_ts)
    t_end = max(all_ts)

    def bucket_index(ts):
        return int((ts - t0).total_seconds() // window_sec)

    n_buckets = bucket_index(t_end) + 1
    counts_per_window = [
        {event_type: 0 for event_type in FILE_EVENT_TYPES}
        for _ in range(n_buckets)
    ]

    for ts, event_type, _ext, _path in lifecycle_events:
        counts_per_window[bucket_index(ts)][event_type] += 1

    rows = []
    for i in range(n_buckets):
        row = {"window": i, "t_start_sec": round(i * window_sec, 3)}
        row.update(counts_per_window[i])
        rows.append(row)
    return rows


def compute_chain_metric(lifecycle_windows):
    """
    Classify each window into one of:
      - "destructive_chain": read + write + (delete or move) all present
        (matches the ransomware pattern: read original, write encrypted
        version, remove/rename original)
      - "write_only_nondestructive": write present, but no delete/move
        (matches benign archiving: write new data, originals untouched)
      - "other": any other combination (read-only, delete-only, etc.)

    Returns counts for each category plus the total number of active
    windows (windows with at least one file event).
    """
    destructive_chain = 0
    write_only_nondestructive = 0
    other = 0
    active = 0

    for row in lifecycle_windows:
        has_read = row["read"] > 0
        has_write = row["write"] > 0
        has_destructive = row["delete"] > 0 or row["move"] > 0
        any_activity = any(row[t] > 0 for t in FILE_EVENT_TYPES)

        if not any_activity:
            continue
        active += 1

        if has_read and has_write and has_destructive:
            destructive_chain += 1
        elif has_write and not has_destructive:
            write_only_nondestructive += 1
        else:
            other += 1

    return {
        "active_windows": active,
        "destructive_chain_windows": destructive_chain,
        "write_only_nondestructive_windows": write_only_nondestructive,
        "other_windows": other,
    }


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


# ---------- Feature row (for building a multi-sample dataset) ----------

def build_feature_row(sample_id, label, writes, crypto_events, lifecycle_events,
                       crypto_correlation, chain_metrics, lifecycle_counts, lifecycle_ratios):
    """Assemble a single flat dict summarizing one sample, suitable for
    appending to a cross-sample feature CSV."""
    return {
        "sample_id": sample_id,
        "label": label,
        "n_file_writes": len(writes),
        "n_crypto_calls": len(crypto_events),
        "write_crypto_pearson": crypto_correlation if crypto_correlation is not None else "",
        "n_read": lifecycle_counts.get("read", 0),
        "n_write": lifecycle_counts.get("write", 0),
        "n_delete": lifecycle_counts.get("delete", 0),
        "n_move": lifecycle_counts.get("move", 0),
        "n_copy": lifecycle_counts.get("copy", 0),
        "n_execute": lifecycle_counts.get("execute", 0),
        "delete_to_write_ratio": lifecycle_ratios.get("delete_to_write_ratio")
            if lifecycle_ratios.get("delete_to_write_ratio") is not None else "",
        "move_to_write_ratio": lifecycle_ratios.get("move_to_write_ratio")
            if lifecycle_ratios.get("move_to_write_ratio") is not None else "",
        "active_windows": chain_metrics.get("active_windows", 0),
        "destructive_chain_windows": chain_metrics.get("destructive_chain_windows", 0),
        "write_only_nondestructive_windows": chain_metrics.get("write_only_nondestructive_windows", 0),
    }


FEATURE_FIELDNAMES = [
    "sample_id", "label", "n_file_writes", "n_crypto_calls", "write_crypto_pearson",
    "n_read", "n_write", "n_delete", "n_move", "n_copy", "n_execute",
    "delete_to_write_ratio", "move_to_write_ratio",
    "active_windows", "destructive_chain_windows", "write_only_nondestructive_windows",
]


def append_feature_row(features_out_path, row):
    """Append a feature row to the CSV, writing a header if the file
    doesn't exist yet."""
    import os
    file_exists = os.path.exists(features_out_path)
    with open(features_out_path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FEATURE_FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


# ---------- Main ----------

def main():
    parser = argparse.ArgumentParser(description="Extract API-I/O and file-lifecycle features from a CAPE report.")
    parser.add_argument("report_path", help="Path to report.json")
    parser.add_argument("window_seconds", nargs="?", type=float, default=1.0,
                         help="Time window size in seconds (default: 1.0)")
    parser.add_argument("--features-out", default=None,
                         help="If set, append a one-row feature summary to this CSV")
    parser.add_argument("--label", default="",
                         help="Optional label to store in the feature row (e.g. ransomware/benign)")
    parser.add_argument("--sample-id", default=None,
                         help="Optional sample identifier for the feature row (defaults to filename)")
    args = parser.parse_args()

    with open(args.report_path, "r", errors="replace") as f:
        report = json.load(f)

    writes = extract_file_writes(report)
    crypto_events = extract_crypto_calls(report)
    lifecycle_events = extract_file_lifecycle_events(report)

    print("=" * 60)
    print(f"File: {args.report_path}")
    print(f"Window size: {args.window_seconds}s")
    print("=" * 60)
    print(f"File write events : {len(writes)}")
    print(f"Crypto events      : {len(crypto_events)}")
    print(f"Lifecycle events   : {len(lifecycle_events)} (read/write/delete/move/copy/execute)")

    if not writes and not crypto_events and not lifecycle_events:
        print("\n[!] No file or crypto activity found. Sample likely did not execute meaningfully.")
        return

    # ---- extension distribution ----
    ext_counts = defaultdict(int)
    for _ts, ext, _path in writes:
        ext_counts[ext] += 1
    top_extensions = sorted(ext_counts.items(), key=lambda x: -x[1])[:10]
    print(f"\n[Top write extensions]")
    for ext, count in top_extensions:
        print(f"   .{ext:<12} {count}")

    # ---- crypto API distribution + entropy ----
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
    else:
        print(f"\n[Crypto API distribution] none observed "
              f"(sample may use a statically-linked / custom crypto implementation)")

    # ---- write<->crypto correlation (original analysis) ----
    crypto_rows, t0, t_end = windowize_crypto(writes, crypto_events, args.window_seconds)
    duration = (t_end - t0).total_seconds() if t0 and t_end else 0
    xs = [r["file_writes"] for r in crypto_rows]
    ys = [r["crypto_calls"] for r in crypto_rows]
    crypto_correlation = pearson(xs, ys)
    active_windows = [row for row in crypto_rows if row["file_writes"] or row["crypto_calls"]]
    both_windows = [row for row in crypto_rows if row["file_writes"] and row["crypto_calls"]]
    write_only_crypto_windows = [row for row in crypto_rows if row["file_writes"] and not row["crypto_calls"]]

    print(f"\n[Write<->Crypto correlation] (duration {duration:.1f}s, {len(crypto_rows)} windows)")
    if crypto_correlation is None:
        print("   Pearson correlation: undefined (one series is all zero)")
    else:
        print(f"   Pearson correlation: {crypto_correlation:.3f}")
    print(f"   Windows with write or crypto : {len(active_windows)}")
    print(f"   Windows with BOTH            : {len(both_windows)}")
    print(f"   Windows with write, no crypto: {len(write_only_crypto_windows)}")

    # ---- file lifecycle features (NEW) ----
    lifecycle_counts = compute_lifecycle_counts(lifecycle_events)
    lifecycle_ratios = compute_lifecycle_ratios(lifecycle_counts)
    lifecycle_windows = windowize_lifecycle(lifecycle_events, args.window_seconds)
    chain_metrics = compute_chain_metric(lifecycle_windows)

    print(f"\n[File lifecycle event counts]")
    for event_type in FILE_EVENT_TYPES:
        print(f"   {event_type:<10} {lifecycle_counts.get(event_type, 0)}")

    print(f"\n[Destructive ratios] (relative to write count)")
    dtw = lifecycle_ratios.get("delete_to_write_ratio")
    mtw = lifecycle_ratios.get("move_to_write_ratio")
    print(f"   delete / write : {dtw:.3f}" if dtw is not None else "   delete / write : n/a (no writes)")
    print(f"   move   / write : {mtw:.3f}" if mtw is not None else "   move   / write : n/a (no writes)")

    print(f"\n[Lifecycle chain analysis] (per {args.window_seconds}s window)")
    print(f"   Active windows (any file event)                     : {chain_metrics['active_windows']}")
    print(f"   Destructive chain windows (read+write+delete/move)  : {chain_metrics['destructive_chain_windows']}")
    print(f"   Write-only, non-destructive windows (e.g. archiving): {chain_metrics['write_only_nondestructive_windows']}")
    print(f"   Other windows                                       : {chain_metrics['other_windows']}")

    # ---- save windowed CSVs ----
    out_prefix = args.report_path.rsplit(".", 1)[0]

    crypto_csv = f"{out_prefix}_timeline_{args.window_seconds}s.csv"
    with open(crypto_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["window", "t_start_sec", "file_writes", "crypto_calls", "crypto_bytes"])
        writer.writeheader()
        writer.writerows(crypto_rows)
    print(f"\n[saved] write/crypto timeline -> {crypto_csv}")

    if lifecycle_windows:
        lifecycle_csv = f"{out_prefix}_lifecycle_{args.window_seconds}s.csv"
        with open(lifecycle_csv, "w", newline="") as f:
            fieldnames = ["window", "t_start_sec"] + FILE_EVENT_TYPES
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(lifecycle_windows)
        print(f"[saved] file lifecycle timeline -> {lifecycle_csv}")

    # ---- optional: append feature row to a cross-sample feature table ----
    if args.features_out:
        sample_id = args.sample_id or args.report_path
        row = build_feature_row(
            sample_id=sample_id,
            label=args.label,
            writes=writes,
            crypto_events=crypto_events,
            lifecycle_events=lifecycle_events,
            crypto_correlation=crypto_correlation,
            chain_metrics=chain_metrics,
            lifecycle_counts=lifecycle_counts,
            lifecycle_ratios=lifecycle_ratios,
        )
        append_feature_row(args.features_out, row)
        print(f"\n[saved] feature row for sample '{sample_id}' -> {args.features_out}")


if __name__ == "__main__":
    main()
