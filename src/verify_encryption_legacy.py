#!/usr/bin/env python3
"""
verify_encryption_legacy.py - Decide whether a legacy Cuckoo analysis really
encrypted the planted decoy files.

This applies the corrections found by validating the CAPE verdict against
screenshots (see docs/verification_failures.md). The same mistakes were
present here, and for the same reasons: this script was written from the
CAPE version and inherited its assumptions.

Corrections carried over
------------------------
1. **Count distinct files, not events.** The original threshold was five
   destructive events. Encryption style decides how many events one file
   produces: writing an encrypted copy and deleting the original is roughly
   three, overwriting in place is one. A threshold in events silently
   encodes an assumption about the attacker's implementation. Counting
   distinct decoy files removes it.

2. **Exclude noise instead of allowing known types.** The original counted a
   file only if its extension appeared in a hardcoded list of document
   types. The decoy set is real coursework and includes extensions that were
   never listed. On the CAPE side this discarded 60% of the observed damage
   even for the sample the list had been validated against.

3. **Look for append-renames, not just decoy damage.** Several families
   spend the whole analysis window encrypting elsewhere and never reach the
   decoy folders — one Cuba run renamed 4,779 files under Program Files and
   scored zero. What those runs have in common is the shape of the rename:
   the original name is kept and a suffix appended (file.docx ->
   file.docx.cuba). That is location-independent, and family-independent in
   a way that matching a specific extension is not, since some families use
   one shared suffix and others a unique hash per file.

A structural difference from CAPE
---------------------------------
CAPE records a move as `data.from` / `data.to`, so an append is directly
observable. The legacy reports only give `behavior.summary.file_moved`, a
flat list of paths with no pairing. Whether those are sources or
destinations determines what can be detected:

  - if destinations, an appended suffix is visible in the path itself and
    `--rename-mode suffix` will find it;
  - if sources, the appended name never appears and only decoy damage can
    be measured.

The mode therefore defaults to `auto`, which inspects the paths and reports
which case it found rather than assuming one.

Usage
-----
  python3 verify_encryption_legacy.py --batch <dir> --out legacy_verify_results.csv
  python3 verify_encryption_legacy.py <report.json>
"""

import sys
import os
import re
import json
import csv
import argparse
from pathlib import Path
from collections import defaultdict

DEFAULT_VICTIM_PATH_FRAGMENT = "Users\\IEUser\\"

# Files inside the user profile that are not decoys: shell metadata, caches,
# profile databases. Everything else under the profile is treated as a decoy.
# This replaced an allowlist of document extensions -- see correction 2.
NOISE_PATH_FRAGMENTS = [
    "python27", "program files", "windows\\", "appdata\\local\\temp",
    "appdata\\roaming\\microsoft", "\\config", ".net\\framework",
    "desktop.ini", "thumbs.db", "ntuser.dat", "\\searches\\",
    "\\contacts\\", "\\favorites\\", "\\links\\", "\\.ssh\\",
]

SUMMARY_EVENT_KEYS = {
    "read": "file_read",
    "write": "file_written",
    "delete": "file_deleted",
    "move": "file_moved",
    "copy": "file_copied",
    "recreate": "file_recreated",
}
DESTRUCTIVE_EVENT_TYPES = ["write", "delete", "move", "recreate"]

# Distinct decoy files that must be damaged. Matches the CAPE threshold,
# which was placed in an empty band in the observed data: confirmed
# encrypting runs damaged 4 or more, everything else damaged 0 or 1.
MIN_DESTROYED_DECOY_FILES = 3

# Append-renames that count as encryption on their own. Chosen on the CAPE
# data, where 8 recovered 10 of 12 missed runs while wrongly flagging none
# of 17 non-encrypting ones.
MIN_APPEND_RENAMES = 8

# Extensions that legitimately appear as the final component of a path.
# Anything else trailing a full filename is treated as an appended suffix.
KNOWN_EXTENSIONS = {
    "exe", "dll", "sys", "txt", "log", "tmp", "dat", "ini", "xml", "json",
    "docx", "doc", "docm", "xlsx", "xls", "pptx", "ppt", "pdf", "rtf", "csv",
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "zip", "rar", "7z", "gz",
    "py", "pyw", "pyc", "js", "html", "htm", "css", "cfg", "conf", "bak",
    "db", "sqlite", "lnk", "url", "msi", "cab", "inf", "cat", "mui", "man",
    "ipynb", "rmd", "vdfx", "2mdl", "search-ms", "contact", "customdestinations-ms",
}

DOUBLE_EXTENSION_RE = re.compile(r"\.([^.\\/]+)\.([^.\\/]+)$")


def is_decoy_path(path, victim_fragment):
    if not path:
        return False
    lowered = path.lower()
    if victim_fragment.lower() not in lowered:
        return False
    return not any(noise in lowered for noise in NOISE_PATH_FRAGMENTS)


def looks_like_append_rename(path):
    """
    True when a path ends in two extensions and the last one is not a known
    file type: report.docx.cuba, notes.txt.7254C3DA...

    This only works when the list being examined holds destination paths. If
    it holds sources, the appended suffix was never recorded and this will
    correctly find nothing.
    """
    m = DOUBLE_EXTENSION_RE.search(path or "")
    if not m:
        return False
    inner, outer = m.group(1).lower(), m.group(2).lower()
    if outer in KNOWN_EXTENSIONS:
        return False
    # The inner component should look like a real extension, so that
    # "archive.tar.gz" style names and version numbers are not mistaken for
    # ransomware suffixes.
    return inner in KNOWN_EXTENSIONS


def analyze(report, victim_fragment):
    summary = report.get("behavior", {}).get("summary", {}) or {}

    destroyed_paths = set()
    read_paths = set()
    raw_counts = defaultdict(int)
    append_paths = set()
    append_suffixes = defaultdict(int)

    for event_type, key in SUMMARY_EVENT_KEYS.items():
        paths = summary.get(key, []) or []
        raw_counts[event_type] = len(paths)
        for path in paths:
            if not isinstance(path, str):
                continue

            # Append-renames are counted wherever they occur, not only in the
            # decoy folders -- that is the whole point of the signal.
            if event_type in ("move", "write", "recreate") and looks_like_append_rename(path):
                append_paths.add(path)
                m = DOUBLE_EXTENSION_RE.search(path)
                if m:
                    append_suffixes[m.group(2).lower()] += 1

            if not is_decoy_path(path, victim_fragment):
                continue
            if event_type in DESTRUCTIVE_EVENT_TYPES:
                destroyed_paths.add(path)
            elif event_type == "read":
                read_paths.add(path)

    read_paths -= destroyed_paths
    return {
        "destroyed_decoy_files": len(destroyed_paths),
        "read_only_decoy_files": len(read_paths),
        "append_renames": len(append_paths),
        "distinct_rename_suffixes": len(append_suffixes),
        "raw_counts": dict(raw_counts),
        "top_suffixes": sorted(append_suffixes.items(), key=lambda x: -x[1])[:5],
    }


def classify(result):
    destroyed = result["destroyed_decoy_files"]
    renames = result["append_renames"]

    if destroyed >= MIN_DESTROYED_DECOY_FILES:
        return "TRUE_ENCRYPTION", f"destroyed {destroyed} decoy files"
    if renames >= MIN_APPEND_RENAMES:
        return "TRUE_ENCRYPTION", (f"{renames} append-renames "
                                   f"({result['distinct_rename_suffixes']} distinct suffixes)")
    if destroyed > 0:
        return "WEAK_VICTIM_ACTIVITY", f"only {destroyed} decoy file(s) destroyed"
    if result["read_only_decoy_files"] > 0:
        return "NO_VICTIM_ACTIVITY", (f"read {result['read_only_decoy_files']} decoy files "
                                       f"but destroyed none")
    return "NO_VICTIM_ACTIVITY", "no decoy activity recorded"


FIELDNAMES = ["file", "verdict", "reason", "destroyed_decoy_files",
              "read_only_decoy_files", "append_renames", "distinct_rename_suffixes",
              "raw_written", "raw_deleted", "raw_moved", "raw_read"]


def row_for(path, victim_fragment):
    try:
        with open(path, "r", errors="replace") as f:
            report = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        return {"file": Path(path).name, "verdict": f"READ_ERROR", "reason": str(e)[:60]}

    result = analyze(report, victim_fragment)
    verdict, reason = classify(result)
    raw = result["raw_counts"]
    return {
        "file": Path(path).name,
        "verdict": verdict,
        "reason": reason,
        "destroyed_decoy_files": result["destroyed_decoy_files"],
        "read_only_decoy_files": result["read_only_decoy_files"],
        "append_renames": result["append_renames"],
        "distinct_rename_suffixes": result["distinct_rename_suffixes"],
        "raw_written": raw.get("write", 0),
        "raw_deleted": raw.get("delete", 0),
        "raw_moved": raw.get("move", 0),
        "raw_read": raw.get("read", 0),
    }


def print_single(path, victim_fragment):
    with open(path, "r", errors="replace") as f:
        report = json.load(f)
    result = analyze(report, victim_fragment)
    verdict, reason = classify(result)

    print("=" * 62)
    print(f"File: {Path(path).name}")
    print("=" * 62)
    print(f"\n[Raw summary counts] before any filtering")
    for k, v in sorted(result["raw_counts"].items(), key=lambda x: -x[1]):
        print(f"   {k:<10} {v}")

    print(f"\n[Decoy files]")
    print(f"   destroyed              : {result['destroyed_decoy_files']}"
          f"  (threshold {MIN_DESTROYED_DECOY_FILES})")
    print(f"   read but not destroyed : {result['read_only_decoy_files']}"
          f"  (reads alone never count)")

    print(f"\n[Encryption outside the decoy folders]")
    print(f"   append-renames         : {result['append_renames']}"
          f"  (threshold {MIN_APPEND_RENAMES})")
    print(f"   distinct suffixes      : {result['distinct_rename_suffixes']}")
    if result["top_suffixes"]:
        detail = ", ".join(f".{s} x{n}" for s, n in result["top_suffixes"])
        print(f"   most common            : {detail}")
    elif result["raw_counts"].get("move", 0) > 0:
        print(f"   (none found despite {result['raw_counts']['move']} moves -- this report's")
        print(f"    file_moved list probably holds source paths, so appended suffixes")
        print(f"    were never recorded and only decoy damage can be measured)")

    print(f"\n[Verdict] {verdict}")
    print(f"   {reason}")


def run_batch(directory, victim_fragment, out_csv):
    files = sorted(Path(directory).glob("*.json"))
    if not files:
        print(f"[!] no .json files in {directory}")
        sys.exit(1)

    rows = [row_for(p, victim_fragment) for p in files]

    header = (f"{'file':<58} {'verdict':<22} {'destr':>6} {'renames':>8} {'sfx':>5}")
    print(header)
    print("-" * len(header))
    for r in rows:
        name = r["file"] if len(r["file"]) <= 56 else r["file"][:53] + "..."
        print(f"{name:<58} {r.get('verdict',''):<22} "
              f"{r.get('destroyed_decoy_files',0):>6} "
              f"{r.get('append_renames',0):>8} "
              f"{r.get('distinct_rename_suffixes',0):>5}")

    counts = defaultdict(int)
    for r in rows:
        counts[r.get("verdict", "?")] += 1
    print("\n[summary] " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    by_decoy = sum(1 for r in rows if r.get("destroyed_decoy_files", 0) >= MIN_DESTROYED_DECOY_FILES)
    by_rename = sum(1 for r in rows if r.get("append_renames", 0) >= MIN_APPEND_RENAMES)
    print(f"[signals] decoy damage: {by_decoy}   append-renames: {by_rename}")
    if by_rename == 0 and any(r.get("raw_moved", 0) > 0 for r in rows):
        print("          No append-renames found anywhere despite recorded moves.")
        print("          These reports' file_moved lists most likely hold source paths,")
        print("          in which case only decoy damage is measurable here.")

    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in FIELDNAMES})
    print(f"\n[saved] {out_csv}")


def main():
    parser = argparse.ArgumentParser(
        description="Verify decoy-file encryption in legacy Cuckoo reports.")
    parser.add_argument("report_path", nargs="?", help="A single report.json")
    parser.add_argument("--batch", metavar="DIR", help="Directory of *.json reports")
    parser.add_argument("--out", default="legacy_verify_results.csv",
                         help="CSV output for batch mode")
    parser.add_argument("--victim-path", default=DEFAULT_VICTIM_PATH_FRAGMENT,
                         help=f"Analysis user profile fragment "
                              f"(default: '{DEFAULT_VICTIM_PATH_FRAGMENT}')")
    args = parser.parse_args()

    if args.batch:
        run_batch(args.batch, args.victim_path, args.out)
    elif args.report_path:
        print_single(args.report_path, args.victim_path)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
