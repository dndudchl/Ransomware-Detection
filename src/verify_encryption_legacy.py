#!/usr/bin/env python3
"""
verify_encryption_legacy.py - Verify victim-file attacks in legacy Cuckoo
Sandbox reports (older report format, distinct from CAPE's report.json).

Background
----------
This project's main tooling (triage.py, verify_encryption.py, correlate.py)
was built against CAPE Sandbox's report.json, which includes a
behavior.enhanced timeline: one entry per file event, with a millisecond
timestamp, an event type (read/write/delete/move/copy), and a file path.

A separate batch of ~450 older reports (Cuckoo Sandbox, single analysis VM,
collected ~4 years prior) uses a different report structure:
  - No behavior.enhanced field at all.
  - File activity instead lives in behavior.summary as flat lists of file
    paths per event type: file_written, file_deleted, file_moved,
    file_read, file_copied. These lists have NO timestamps -- just paths,
    possibly with duplicates.
  - Low-level file API calls (GetFileType, NtQueryInformationFile, etc.)
    exist in behavior.processes[].calls with a numeric "time" (unix epoch)
    field, but they operate on file HANDLES, not paths, so they cannot be
    directly correlated to a specific file without extra handle-tracking
    work.

Consequence: for this legacy dataset we can determine WHICH files were
read/written/deleted/moved, and HOW MANY events of each type occurred,
but NOT the timing/windowed correlation analysis that correlate.py does
for CAPE reports. This script is therefore a triage/verification step
only (equivalent in purpose to verify_encryption.py), not a feature
extractor.

A naive count of file_written/file_deleted/file_moved is misleading: this
particular analysis VM has software installed (Python27, various Program
Files apps) whose self-installation or runtime activity dominates the raw
counts (e.g. one sample showed 5153 "written" files that were almost
entirely Python standard library files, not user documents). To avoid
this, this script restricts attention to files under the analysis user's
profile directory (default: Users\\IEUser\\) that also look like ordinary
user documents (by extension), and explicitly excludes known noisy
subpaths (Python installs, Program Files, Windows system dirs, temp
folders).

Usage
-----
  # Single file
  python3 verify_encryption_legacy.py <report.json>

  # Batch mode: scan a directory of *.json reports, write a summary CSV
  python3 verify_encryption_legacy.py --batch <directory> --out legacy_verify_results.csv
"""

import sys
import json
import argparse
import csv
from pathlib import Path
from collections import defaultdict

# Extensions that represent ordinary user documents (decoy-like files).
# NOTE: "docm" (macro-enabled Word doc) and "rtf" were added after
# inspecting real file_read entries from this dataset's decoy set
# (C:\Users\IEUser\Desktop\test.rtf, Documents\*.docm), which the original
# CAPE-derived extension list did not include.
VICTIM_FILE_EXTENSIONS = {
    "docx", "doc", "docm", "pptx", "ppt", "xlsx", "xls", "csv", "pdf",
    "txt", "rtf", "py", "pyw", "ipynb", "rmd", "png", "jpg", "jpeg", "zip",
}

# Default victim path fragment: files under the analysis user's profile.
DEFAULT_VICTIM_PATH_FRAGMENT = "Users\\IEUser\\"

# Path fragments that indicate self-installation / system noise rather
# than genuine victim-document activity, even if they fall under the
# user profile (e.g. AppData\Local\Temp is technically under Users\IEUser\
# but is where installers/self-extractors dump files).
NOISE_PATH_FRAGMENTS = [
    "python27", "program files", "windows\\", "appdata\\local\\temp",
    "appdata\\roaming\\microsoft", "\\config", ".net\\framework",
]

SUMMARY_EVENT_KEYS = {
    "read": "file_read",
    "write": "file_written",
    "delete": "file_deleted",
    "move": "file_moved",
    "copy": "file_copied",
}
DESTRUCTIVE_EVENT_TYPES = ["write", "delete", "move"]

# NOTE: this threshold was originally set to 20, matching verify_encryption.py,
# which was calibrated against a CAPE analysis VM seeded with ~40 decoy files.
# This legacy Cuckoo dataset appears to have a much smaller decoy set (a
# handful of test.* files on the Desktop plus a couple of Documents files),
# so 20 destructive events may be too high a bar and could produce false
# NO_VICTIM_ACTIVITY verdicts for samples that did encrypt the (small) decoy
# set. Lowered to 5 as a starting point; re-calibrate after looking at the
# actual distribution of destructive_victim_events across the batch.
MIN_DESTRUCTIVE_VICTIM_EVENTS = 5


def get_extension(path):
    if not path or '.' not in path.split('\\')[-1]:
        return "(none)"
    return path.split('.')[-1].lower()


def is_victim_path(path, victim_fragment):
    if not path:
        return False
    lowered = path.lower()
    if victim_fragment.lower() not in lowered:
        return False
    if any(noise in lowered for noise in NOISE_PATH_FRAGMENTS):
        return False
    return True


def analyze_report(report, victim_fragment):
    """
    Returns:
      victim_counts: dict event_type -> count (paths matching victim
                     criteria: under victim_fragment, document extension,
                     not in a noise subpath)
      victim_paths: set of distinct victim paths touched (any event type)
      raw_counts: dict event_type -> total count in summary (unfiltered,
                  for context / sanity-checking how much noise was excluded)
    """
    summary = report.get("behavior", {}).get("summary", {})

    victim_counts = defaultdict(int)
    victim_paths = set()
    raw_counts = defaultdict(int)

    for event_type, summary_key in SUMMARY_EVENT_KEYS.items():
        paths = summary.get(summary_key, []) or []
        raw_counts[event_type] = len(paths)
        for path in paths:
            if not isinstance(path, str):
                continue
            if is_victim_path(path, victim_fragment) and get_extension(path) in VICTIM_FILE_EXTENSIONS:
                victim_counts[event_type] += 1
                victim_paths.add(path)

    return victim_counts, victim_paths, raw_counts


def classify(victim_counts):
    destructive = sum(victim_counts.get(t, 0) for t in DESTRUCTIVE_EVENT_TYPES)
    if destructive >= MIN_DESTRUCTIVE_VICTIM_EVENTS:
        return "TRUE_ENCRYPTION", destructive
    if destructive > 0:
        return "WEAK_VICTIM_ACTIVITY", destructive
    return "NO_VICTIM_ACTIVITY", destructive


def analyze_one_file(report_path, victim_fragment):
    try:
        with open(report_path, "r", errors="replace") as f:
            report = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        return {
            "file": report_path.name,
            "verdict": f"READ_ERROR: {e}",
            "destructive_victim_events": 0,
            "distinct_victim_files": 0,
            "raw_written": 0, "raw_deleted": 0, "raw_moved": 0, "raw_read": 0, "raw_copied": 0,
        }

    victim_counts, victim_paths, raw_counts = analyze_report(report, victim_fragment)
    verdict, destructive = classify(victim_counts)

    return {
        "file": report_path.name,
        "verdict": verdict,
        "destructive_victim_events": destructive,
        "distinct_victim_files": len(victim_paths),
        "raw_written": raw_counts.get("write", 0),
        "raw_deleted": raw_counts.get("delete", 0),
        "raw_moved": raw_counts.get("move", 0),
        "raw_read": raw_counts.get("read", 0),
        "raw_copied": raw_counts.get("copy", 0),
    }


def print_single_report(report_path, victim_fragment):
    with open(report_path, "r", errors="replace") as f:
        report = json.load(f)

    victim_counts, victim_paths, raw_counts = analyze_report(report, victim_fragment)
    verdict, destructive = classify(victim_counts)

    print("=" * 60)
    print(f"File: {report_path}")
    print(f"Victim path fragment: {victim_fragment}")
    print("=" * 60)

    print(f"\n[Raw summary counts] (before filtering out system/self-install noise)")
    for event_type in SUMMARY_EVENT_KEYS:
        print(f"   {event_type:<8} {raw_counts.get(event_type, 0)}")

    print(f"\n[Victim-file activity] (user-profile documents, noise excluded)")
    for event_type in SUMMARY_EVENT_KEYS:
        print(f"   {event_type:<8} {victim_counts.get(event_type, 0)}")
    print(f"   distinct victim files touched: {len(victim_paths)}")

    if victim_paths:
        print(f"\n[Sample victim files touched]")
        for path in list(victim_paths)[:10]:
            print(f"   {path}")

    print(f"\n[Verdict] {verdict}")
    print(f"   destructive victim events: {destructive} "
          f"(threshold for TRUE_ENCRYPTION: {MIN_DESTRUCTIVE_VICTIM_EVENTS})")


def run_batch(directory, victim_fragment, out_csv):
    json_files = sorted(Path(directory).glob("*.json"))
    if not json_files:
        print(f"[!] No .json files found in {directory}")
        sys.exit(1)

    rows = []
    for report_path in json_files:
        row = analyze_one_file(report_path, victim_fragment)
        rows.append(row)

    header = f"{'file':<70} {'verdict':<20} {'destr.':>7} {'distinct':>9} {'raw_write':>10} {'raw_del':>8} {'raw_move':>9}"
    print(header)
    print("-" * len(header))
    for r in rows:
        fname = r["file"] if len(r["file"]) <= 68 else r["file"][:65] + "..."
        print(f"{fname:<70} {r['verdict']:<20} {r['destructive_victim_events']:>7} "
              f"{r['distinct_victim_files']:>9} {r['raw_written']:>10} {r['raw_deleted']:>8} {r['raw_moved']:>9}")

    counts = defaultdict(int)
    for r in rows:
        counts[r["verdict"]] += 1
    print("\n[summary]", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    fieldnames = ["file", "verdict", "destructive_victim_events", "distinct_victim_files",
                  "raw_written", "raw_deleted", "raw_moved", "raw_read", "raw_copied"]
    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in fieldnames})
    print(f"\n[saved] batch verification results -> {out_csv}")
    print("        Filter for verdict == TRUE_ENCRYPTION to get samples worth")
    print("        keeping for further feature extraction.")


def main():
    parser = argparse.ArgumentParser(
        description="Verify victim-file attacks in legacy Cuckoo Sandbox reports.")
    parser.add_argument("report_path", nargs="?", help="Path to a single report.json (single-file mode)")
    parser.add_argument("--batch", metavar="DIRECTORY",
                         help="Directory of *.json reports to scan in batch mode")
    parser.add_argument("--out", default="legacy_verify_results.csv",
                         help="CSV output path for batch mode (default: legacy_verify_results.csv)")
    parser.add_argument("--victim-path", default=DEFAULT_VICTIM_PATH_FRAGMENT,
                         help=f"Path fragment identifying the analysis user's profile "
                              f"(default: '{DEFAULT_VICTIM_PATH_FRAGMENT}')")
    args = parser.parse_args()

    if args.batch:
        run_batch(args.batch, args.victim_path, args.out)
    elif args.report_path:
        print_single_report(Path(args.report_path), args.victim_path)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()