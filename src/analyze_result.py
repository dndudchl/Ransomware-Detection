#!/usr/bin/env python3
"""
analyze_result.py - Decide whether a CAPE analysis is usable, in one step.

This merges what used to be two separate tools:
  1. triage.py            -- did the sample execute at all?
  2. verify_encryption.py -- did it actually attack the planted decoy files?

They were always run in this fixed order, so they are merged here into a
single staged verdict. The staging is preserved internally: if a sample
never really executed, there is no point inspecting victim files, so the
second stage is skipped and the sample is reported as FAILED.

Verdicts
--------
  FAILED               - too little activity; the sample did not run
                         meaningfully (evasion, crash, missing args)
  NO_VICTIM_ACTIVITY   - it ran, but never touched the planted decoy files
                         (e.g. only unpacked itself into %TEMP%)
  WEAK_VICTIM_ACTIVITY - some decoy-file damage, but below threshold;
                         worth a manual look
  TRUE_ENCRYPTION      - genuinely attacked the planted decoy files;
                         this is the only verdict that proceeds to feature
                         extraction

Manifest integration
--------------------
If --manifest is given and the analysis can be matched to a sample (via
the sha256 recorded by CAPE, or via --sha256), the verdict is written back
to the manifest automatically. No manual bookkeeping is needed.

Usage
-----
  # Single analysis directory or report
  python3 analyze_result.py /opt/CAPEv2/storage/analyses/61
  python3 analyze_result.py /opt/CAPEv2/storage/analyses/61/reports/report.json

  # Every analysis under the CAPE storage directory, writing a summary CSV
  python3 analyze_result.py --batch /opt/CAPEv2/storage/analyses \\
      --out analysis_results.csv --manifest ../data/manifest.csv

  # Only print the sample ids that passed, for scripting
  python3 analyze_result.py --batch /opt/CAPEv2/storage/analyses --list-passed
"""

import os
import sys
import json
import csv
import argparse
from pathlib import Path
from collections import defaultdict

# ---------------- Stage 1 config: did it execute? ----------------

# Below this many total API calls, the sample effectively did not run.
MIN_TOTAL_CALLS = 500
# Below this many destructive file events anywhere, execution is doubtful.
MIN_DESTRUCTIVE_EVENTS = 50

# ---------------- Stage 2 config: did it attack the decoys? ----------------

# Decoy folders seeded in the CAPE guest (analysis user "admin").
DEFAULT_VICTIM_DIRS = [
    "\\Users\\admin\\Desktop",
    "\\Users\\admin\\Documents",
    "\\Users\\admin\\Downloads",
]

# Extensions of the planted decoy documents.
VICTIM_FILE_EXTENSIONS = {
    "docx", "doc", "docm", "pptx", "ppt", "xlsx", "xls", "csv", "pdf",
    "txt", "rtf", "py", "pyw", "ipynb", "rmd", "png", "jpg", "jpeg", "zip",
}

FILE_EVENT_TYPES = ["read", "write", "delete", "move", "copy", "execute"]
DESTRUCTIVE_EVENT_TYPES = ["write", "delete", "move"]

# Destructive events on decoy documents required to call it real encryption.
MIN_DESTRUCTIVE_VICTIM_EVENTS = 20

MANIFEST_FIELDNAMES = [
    "sha256", "original_filename", "family", "source", "label",
    "added_date", "status", "cape_task_id", "result", "notes",
]


# ---------------- Report loading ----------------

def resolve_report_path(path):
    """Accept either an analysis directory or a report.json path."""
    p = Path(path)
    if p.is_dir():
        candidate = p / "reports" / "report.json"
        if candidate.exists():
            return candidate
        return None
    if p.is_file():
        return p
    return None


def load_report(report_path):
    try:
        with open(report_path, "r", errors="replace") as f:
            return json.load(f), None
    except (json.JSONDecodeError, OSError) as e:
        return None, str(e)


# ---------------- Stage 1: execution check ----------------

def count_total_calls(report):
    total = 0
    for process in report.get("behavior", {}).get("processes", []) or []:
        total += len(process.get("calls", []) or [])
    return total


def count_file_events(report):
    """Count file events by type across the whole analysis (not decoy-limited)."""
    counts = defaultdict(int)
    for event in report.get("behavior", {}).get("enhanced", []) or []:
        if event.get("object") != "file":
            continue
        event_type = event.get("event")
        if event_type in FILE_EVENT_TYPES:
            counts[event_type] += 1
    return counts


def stage1_execution_check(report):
    """Returns (executed: bool, stats: dict)."""
    total_calls = count_total_calls(report)
    file_counts = count_file_events(report)
    destructive = sum(file_counts.get(t, 0) for t in DESTRUCTIVE_EVENT_TYPES)

    stats = {
        "total_calls": total_calls,
        "destructive_events": destructive,
        "file_reads": file_counts.get("read", 0),
        "file_writes": file_counts.get("write", 0),
        "file_deletes": file_counts.get("delete", 0),
        "file_moves": file_counts.get("move", 0),
    }

    executed = total_calls >= MIN_TOTAL_CALLS and destructive >= MIN_DESTRUCTIVE_EVENTS
    return executed, stats


# ---------------- Stage 2: victim-file check ----------------

def get_extension(path):
    if not path or "." not in path.split("\\")[-1]:
        return "(none)"
    return path.split(".")[-1].lower()


def path_in_victim_dirs(path, victim_dirs):
    if not path:
        return False
    lowered = path.lower()
    return any(v.lower() in lowered for v in victim_dirs)


def stage2_victim_check(report, victim_dirs):
    """Returns (destructive_victim_events, distinct_victim_files, per_type_counts)."""
    victim_counts = defaultdict(int)
    victim_paths = set()

    for event in report.get("behavior", {}).get("enhanced", []) or []:
        if event.get("object") != "file":
            continue
        event_type = event.get("event")
        if event_type not in FILE_EVENT_TYPES:
            continue
        path = event.get("data", {}).get("file", "")
        if not path_in_victim_dirs(path, victim_dirs):
            continue
        if get_extension(path) not in VICTIM_FILE_EXTENSIONS:
            continue
        victim_counts[event_type] += 1
        victim_paths.add(path)

    destructive = sum(victim_counts.get(t, 0) for t in DESTRUCTIVE_EVENT_TYPES)
    return destructive, len(victim_paths), dict(victim_counts)


# ---------------- Combined verdict ----------------

def analyze(report, victim_dirs):
    """Run both stages and return a result dict."""
    executed, stats = stage1_execution_check(report)

    if not executed:
        # Stage 2 is meaningless if the sample never really ran.
        return {
            "verdict": "FAILED",
            "reason": (f"insufficient execution "
                       f"(calls={stats['total_calls']}, "
                       f"destructive_events={stats['destructive_events']})"),
            **stats,
            "destructive_victim_events": 0,
            "distinct_victim_files": 0,
        }

    destructive_victim, distinct_victim, victim_counts = stage2_victim_check(report, victim_dirs)

    if destructive_victim >= MIN_DESTRUCTIVE_VICTIM_EVENTS:
        verdict = "TRUE_ENCRYPTION"
        reason = f"attacked {distinct_victim} decoy files"
    elif destructive_victim > 0:
        verdict = "WEAK_VICTIM_ACTIVITY"
        reason = f"only {destructive_victim} destructive events on decoys"
    else:
        verdict = "NO_VICTIM_ACTIVITY"
        reason = "ran but never touched decoy files (self-unpack / evasion)"

    return {
        "verdict": verdict,
        "reason": reason,
        **stats,
        "destructive_victim_events": destructive_victim,
        "distinct_victim_files": distinct_victim,
        "victim_reads": victim_counts.get("read", 0),
        "victim_writes": victim_counts.get("write", 0),
        "victim_deletes": victim_counts.get("delete", 0),
        "victim_moves": victim_counts.get("move", 0),
    }


# ---------------- Sample identity (for manifest linking) ----------------

def get_sample_sha256(report):
    """CAPE records the submitted file's hashes under target.file."""
    target = report.get("target", {}) or {}
    file_info = target.get("file", {}) or {}
    return file_info.get("sha256", "")


def get_cape_metadata(report):
    """
    CAPE's own assessment of the sample, which is independent of our
    behavioural verdict and worth recording alongside it:
      - malscore: CAPE's aggregate maliciousness score
      - family: the family CAPE's signature set attributed the sample to
    """
    malscore = report.get("malscore")
    family = "unknown"
    detections = report.get("detections", [])
    if isinstance(detections, list) and detections:
        first = detections[0]
        if isinstance(first, dict):
            family = first.get("family", "unknown")
    return {
        "malscore": malscore if malscore is not None else "",
        "cape_family": family,
    }


def get_task_id(report, fallback_path):
    """CAPE records the analysis id under info.id; fall back to directory name."""
    info = report.get("info", {}) or {}
    task_id = info.get("id")
    if task_id:
        return str(task_id)
    # .../analyses/<id>/reports/report.json
    parts = Path(fallback_path).parts
    if "analyses" in parts:
        idx = parts.index("analyses")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return ""


# ---------------- Manifest update ----------------

def load_manifest(manifest_path):
    if not manifest_path or not os.path.exists(manifest_path):
        return {}
    entries = {}
    with open(manifest_path, newline="") as f:
        for row in csv.DictReader(f):
            entries[row["sha256"]] = row
    return entries


def save_manifest(manifest_path, entries):
    with open(manifest_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=MANIFEST_FIELDNAMES)
        writer.writeheader()
        for _sha, row in sorted(entries.items(), key=lambda kv: kv[1].get("added_date", "")):
            writer.writerow({k: row.get(k, "") for k in MANIFEST_FIELDNAMES})


def update_manifest(manifest_path, sha256, task_id, verdict):
    """Record the verdict against the sample. Returns True if updated."""
    if not manifest_path or not sha256:
        return False
    entries = load_manifest(manifest_path)
    if sha256 not in entries:
        return False
    entries[sha256]["status"] = "analyzed"
    entries[sha256]["result"] = verdict
    if task_id and not entries[sha256].get("cape_task_id"):
        entries[sha256]["cape_task_id"] = task_id
    save_manifest(manifest_path, entries)
    return True


# ---------------- Runners ----------------

RESULT_FIELDNAMES = [
    "task_id", "sha256", "verdict", "reason",
    "malscore", "cape_family",
    "total_calls", "destructive_events",
    "file_reads", "file_writes", "file_deletes", "file_moves",
    "destructive_victim_events", "distinct_victim_files",
]


def analyze_one(path, victim_dirs, manifest_path=None, quiet=False):
    report_path = resolve_report_path(path)
    if not report_path:
        if not quiet:
            print(f"[!] no report.json found at {path}")
        return None

    report, err = load_report(report_path)
    if err:
        if not quiet:
            print(f"[!] {report_path}: {err}")
        return None

    result = analyze(report, victim_dirs)
    result["sha256"] = get_sample_sha256(report)
    result["task_id"] = get_task_id(report, report_path)
    result.update(get_cape_metadata(report))

    if manifest_path:
        update_manifest(manifest_path, result["sha256"], result["task_id"], result["verdict"])

    return result


def print_single(result):
    print("=" * 60)
    print(f"Task {result['task_id']}  sha256={result['sha256'][:16] or '(unknown)'}...")
    print(f"CAPE malscore={result.get('malscore', '')}  "
          f"family={result.get('cape_family', 'unknown')}")
    print("=" * 60)
    print(f"\n[Stage 1: execution]")
    print(f"   total API calls     : {result['total_calls']}")
    print(f"   destructive events  : {result['destructive_events']}")
    print(f"   read/write/del/move : {result['file_reads']}/{result['file_writes']}"
          f"/{result['file_deletes']}/{result['file_moves']}")

    if result["verdict"] != "FAILED":
        print(f"\n[Stage 2: decoy files]")
        print(f"   destructive events on decoys : {result['destructive_victim_events']}"
              f" (threshold {MIN_DESTRUCTIVE_VICTIM_EVENTS})")
        print(f"   distinct decoy files touched : {result['distinct_victim_files']}")
    else:
        print(f"\n[Stage 2: decoy files] skipped (sample did not execute)")

    print(f"\n[Verdict] {result['verdict']}")
    print(f"   {result['reason']}")
    if result["verdict"] == "TRUE_ENCRYPTION":
        print(f"   -> proceed to feature extraction")
    else:
        print(f"   -> not usable for feature extraction")


def run_batch(analyses_dir, victim_dirs, out_csv, manifest_path, list_passed):
    base = Path(analyses_dir)
    if not base.is_dir():
        print(f"[!] not a directory: {analyses_dir}")
        sys.exit(1)

    # analysis dirs are numeric task ids
    subdirs = sorted((d for d in base.iterdir() if d.is_dir()),
                     key=lambda d: int(d.name) if d.name.isdigit() else 0)

    results = []
    for d in subdirs:
        r = analyze_one(d, victim_dirs, manifest_path, quiet=True)
        if r:
            results.append(r)

    if list_passed:
        for r in results:
            if r["verdict"] == "TRUE_ENCRYPTION":
                print(r["task_id"])
        return results

    header = (f"{'task':<7} {'sha256':<18} {'verdict':<22} {'calls':>7} "
              f"{'destr':>7} {'victim':>7} {'files':>6}")
    print(header)
    print("-" * len(header))
    for r in results:
        print(f"{r['task_id']:<7} {r['sha256'][:16]:<18} {r['verdict']:<22} "
              f"{r['total_calls']:>7} {r['destructive_events']:>7} "
              f"{r['destructive_victim_events']:>7} {r['distinct_victim_files']:>6}")

    counts = defaultdict(int)
    for r in results:
        counts[r["verdict"]] += 1
    print("\n[summary] " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    passed = [r for r in results if r["verdict"] == "TRUE_ENCRYPTION"]
    print(f"[usable]  {len(passed)} of {len(results)} analyses proceed to feature extraction")

    if out_csv:
        with open(out_csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=RESULT_FIELDNAMES)
            writer.writeheader()
            for r in results:
                writer.writerow({k: r.get(k, "") for k in RESULT_FIELDNAMES})
        print(f"[saved]   {out_csv}")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Combined execution + encryption verdict for CAPE analyses.")
    parser.add_argument("path", nargs="?",
                         help="An analysis directory or a report.json")
    parser.add_argument("--batch", metavar="ANALYSES_DIR",
                         help="Process every analysis under this directory")
    parser.add_argument("--out", default=None, help="CSV output for batch mode")
    parser.add_argument("--manifest", default=None,
                         help="Manifest CSV to update with verdicts automatically")
    parser.add_argument("--victim-dirs", nargs="+", default=DEFAULT_VICTIM_DIRS,
                         help="Decoy folder path fragments in the guest")
    parser.add_argument("--list-passed", action="store_true",
                         help="Print only the task ids that reached TRUE_ENCRYPTION")
    args = parser.parse_args()

    if args.batch:
        run_batch(args.batch, args.victim_dirs, args.out, args.manifest, args.list_passed)
    elif args.path:
        result = analyze_one(args.path, args.victim_dirs, args.manifest)
        if result:
            print_single(result)
            sys.exit(0 if result["verdict"] == "TRUE_ENCRYPTION" else 1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
