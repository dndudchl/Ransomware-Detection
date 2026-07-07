#!/usr/bin/env python3
"""
triage.py - Batch triage tool for CAPE sandbox analysis results.

Purpose
-------
When submitting many malware samples to CAPE, a large fraction never
exhibit the behavior we care about (ransomware-style file destruction):
some crash immediately, some detect the sandbox and exit early, some
require command-line arguments or a C2 connection to activate.

This script scans a batch of CAPE analysis folders, extracts a small
set of cheap signals from each report.json, and classifies each sample
as SUCCESS / AMBIGUOUS / FAILED so that only usable samples are kept
for downstream feature extraction (see correlate.py).

Classification thresholds are derived empirically from three reference
cases observed during manual analysis:
  - WannaCry (task 37): total_calls in the tens of thousands,
    destructive_events (write+delete+move) = 7369  -> SUCCESS
  - Unknown/Cicada variant (task 53): total_calls = 117,
    almost no file activity                        -> FAILED (exited immediately)
  - Unknown sample (task 54): total_calls = 3598,
    destructive_events = 2                          -> AMBIGUOUS (ran, but did
    not perform bulk file destruction)

These thresholds are intentionally simple and conservative. They are a
first pass filter, not a final ground-truth label -- always spot check
a few SUCCESS and AMBIGUOUS results manually before trusting them at
scale.

Usage
-----
  # Dry run: scan all analyses under CAPE storage, print a table, write CSV
  python3 triage.py --analyses-dir /opt/CAPEv2/storage/analyses --out triage_results.csv

  # Also clean up disk space: delete FAILED analysis folders and gzip
  # report.json for SUCCESS/AMBIGUOUS samples into --archive-dir
  python3 triage.py --analyses-dir /opt/CAPEv2/storage/analyses \\
      --out triage_results.csv --archive-dir ~/ransomware_reports \\
      --cleanup

Cleanup is OFF by default (dry run / report-only) to avoid accidental
data loss. Pass --cleanup explicitly to actually delete/compress files.
"""

import argparse
import csv
import gzip
import json
import shutil
import sys
from pathlib import Path

# ---------- Thresholds (see module docstring for derivation) ----------

MIN_TOTAL_CALLS_TO_BE_ALIVE = 500     # below this: sample exited almost immediately
MIN_DESTRUCTIVE_EVENTS_FOR_SUCCESS = 50  # write+delete+move events required for SUCCESS

FILE_EVENT_TYPES = ["read", "write", "delete", "move", "copy", "execute"]
DESTRUCTIVE_EVENT_TYPES = ["write", "delete", "move"]


# ---------- Metric extraction ----------

def load_report(report_path):
    with open(report_path, "r", errors="replace") as f:
        return json.load(f)


def count_total_calls(report):
    """Sum of API call counts across all processes."""
    total = 0
    for proc in report.get("behavior", {}).get("processes", []):
        total += len(proc.get("calls", []))
    return total


def count_file_events(report):
    """Count enhanced-timeline file events by type."""
    counts = {event_type: 0 for event_type in FILE_EVENT_TYPES}
    for ev in report.get("behavior", {}).get("enhanced", []):
        if ev.get("object") == "file":
            event_type = ev.get("event")
            if event_type in counts:
                counts[event_type] += 1
    return counts


def get_malscore(report):
    return report.get("malscore", None)


def get_family(report):
    detections = report.get("detections", [])
    if detections and isinstance(detections, list):
        return detections[0].get("family", "unknown")
    return "unknown"


def classify(total_calls, destructive_events):
    """
    Classify a sample based on activity level.

    FAILED     - exited almost immediately, likely sandbox detection,
                 missing required arguments, or a crash.
    AMBIGUOUS  - ran for a while but did not perform bulk file
                 destruction (write/delete/move). May require specific
                 trigger conditions (C2, arguments, target files) to
                 activate ransomware behavior.
    SUCCESS    - performed enough destructive file activity to be
                 usable for feature extraction.
    """
    if total_calls < MIN_TOTAL_CALLS_TO_BE_ALIVE:
        return "FAILED"
    if destructive_events < MIN_DESTRUCTIVE_EVENTS_FOR_SUCCESS:
        return "AMBIGUOUS"
    return "SUCCESS"


def analyze_one(analysis_dir):
    """Extract triage metrics for a single CAPE analysis folder."""
    report_path = analysis_dir / "reports" / "report.json"
    if not report_path.exists():
        return {
            "task_id": analysis_dir.name,
            "status": "NO_REPORT",
            "total_calls": 0,
            "read": 0, "write": 0, "delete": 0, "move": 0, "copy": 0, "execute": 0,
            "destructive_events": 0,
            "malscore": None,
            "family": "n/a",
            "report_path": str(report_path),
        }

    try:
        report = load_report(report_path)
    except (json.JSONDecodeError, OSError) as e:
        return {
            "task_id": analysis_dir.name,
            "status": f"READ_ERROR: {e}",
            "total_calls": 0,
            "read": 0, "write": 0, "delete": 0, "move": 0, "copy": 0, "execute": 0,
            "destructive_events": 0,
            "malscore": None,
            "family": "n/a",
            "report_path": str(report_path),
        }

    total_calls = count_total_calls(report)
    file_events = count_file_events(report)
    destructive_events = sum(file_events[t] for t in DESTRUCTIVE_EVENT_TYPES)
    status = classify(total_calls, destructive_events)

    row = {
        "task_id": analysis_dir.name,
        "status": status,
        "total_calls": total_calls,
        "destructive_events": destructive_events,
        "malscore": get_malscore(report),
        "family": get_family(report),
        "report_path": str(report_path),
    }
    row.update(file_events)
    return row


# ---------- Cleanup actions ----------

def archive_report(row, archive_dir):
    """Gzip-compress report.json into archive_dir, named by task_id."""
    src = Path(row["report_path"])
    if not src.exists():
        return None
    archive_dir.mkdir(parents=True, exist_ok=True)
    dest = archive_dir / f"task_{row['task_id']}_report.json.gz"
    with open(src, "rb") as f_in, gzip.open(dest, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    return dest


def delete_analysis_folder(analysis_dir):
    shutil.rmtree(analysis_dir, ignore_errors=True)


# ---------- Main ----------

def main():
    parser = argparse.ArgumentParser(description="Triage CAPE analysis results in bulk.")
    parser.add_argument("--analyses-dir", required=True,
                         help="Path to CAPE storage/analyses directory")
    parser.add_argument("--out", default="triage_results.csv",
                         help="CSV file to write triage summary to")
    parser.add_argument("--archive-dir", default=None,
                         help="Directory to store gzip-compressed report.json "
                              "for SUCCESS/AMBIGUOUS samples")
    parser.add_argument("--cleanup", action="store_true",
                         help="Actually delete FAILED analysis folders and archive "
                              "SUCCESS/AMBIGUOUS reports. Without this flag, the "
                              "script only reports what it WOULD do (dry run).")
    args = parser.parse_args()

    analyses_root = Path(args.analyses_dir)
    if not analyses_root.is_dir():
        print(f"[!] Not a directory: {analyses_root}")
        sys.exit(1)

    task_dirs = sorted(
        [p for p in analyses_root.iterdir() if p.is_dir() and p.name.isdigit()],
        key=lambda p: int(p.name),
    )

    if not task_dirs:
        print(f"[!] No numeric task folders found under {analyses_root}")
        sys.exit(1)

    rows = []
    for task_dir in task_dirs:
        row = analyze_one(task_dir)
        rows.append(row)

    # ---- print summary table ----
    header = f"{'task':>6} {'status':<10} {'calls':>8} {'destr.':>7} {'read':>6} {'write':>6} {'del':>6} {'move':>6} {'malscore':>9} {'family':<15}"
    print(header)
    print("-" * len(header))
    for r in rows:
        print(f"{r['task_id']:>6} {r['status']:<10} {r.get('total_calls', 0):>8} "
              f"{r.get('destructive_events', 0):>7} {r.get('read', 0):>6} "
              f"{r.get('write', 0):>6} {r.get('delete', 0):>6} {r.get('move', 0):>6} "
              f"{str(r.get('malscore', '-')):>9} {str(r.get('family', '-')):<15}")

    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print("\n[summary]", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    # ---- write CSV ----
    fieldnames = ["task_id", "status", "total_calls", "destructive_events",
                  "read", "write", "delete", "move", "copy", "execute",
                  "malscore", "family", "report_path"]
    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in fieldnames})
    print(f"\n[saved] triage summary -> {args.out}")

    # ---- cleanup ----
    if args.cleanup:
        archive_dir = Path(args.archive_dir).expanduser() if args.archive_dir else None
        n_archived, n_deleted = 0, 0
        for r in rows:
            task_dir = analyses_root / r["task_id"]
            if r["status"] == "FAILED" or r["status"] in ("NO_REPORT",):
                delete_analysis_folder(task_dir)
                n_deleted += 1
            elif r["status"] in ("SUCCESS", "AMBIGUOUS") and archive_dir:
                archive_report(r, archive_dir)
                delete_analysis_folder(task_dir)
                n_archived += 1
        print(f"[cleanup] deleted {n_deleted} failed analysis folders, "
              f"archived {n_archived} reports to {archive_dir}")
    else:
        print("\n[dry run] No files were deleted or archived. "
              "Re-run with --cleanup (and --archive-dir) to actually clean up disk space.")


if __name__ == "__main__":
    main()

