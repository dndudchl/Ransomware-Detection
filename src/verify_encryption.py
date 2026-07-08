#!/usr/bin/env python3
"""
verify_encryption.py - Verify whether a sample actually attacked the
planted decoy (victim) files, as opposed to only unpacking itself or
failing to trigger.

Motivation
----------
triage.py answers "did this sample perform enough file activity to be
worth analyzing?" but it cannot tell WHERE that activity happened. A
sample can pass triage as SUCCESS while only unpacking its own Python
runtime into %TEMP% (observed in task 45: hundreds of .pyd/.dll writes,
zero touches to the victim folders). That is not ransomware encryption.

Ground truth for "did it really encrypt?" is whether the known decoy
files -- the user documents we planted in Desktop / Documents / Downloads
-- were read, overwritten, deleted, or renamed. This script reproduces,
automatically, the manual check of looking at the CAPE desktop screenshot
to see whether the planted files got encrypted.

Classification
--------------
  TRUE_ENCRYPTION    - meaningful destructive/among activity on victim
                       files inside the decoy folders (read/write/delete/move)
  WEAK_VICTIM_ACTIVITY - some victim-folder activity but below threshold
                       (worth a manual look)
  NO_VICTIM_ACTIVITY - little or no activity in the decoy folders; the
                       sample likely failed to trigger, detected the
                       sandbox, or only unpacked itself elsewhere

NOTE: This is still a heuristic. It does not yet distinguish malicious
destruction from a benign program (or user) legitimately moving/deleting
files in those folders. That requires additional context (entropy of
written data, whether originals are replaced in place, extension changes,
ransom-note creation) and is left as future work.

Usage
-----
  python3 verify_encryption.py <report.json>
  python3 verify_encryption.py <report.json> --victim-dirs "\\Users\\admin\\Documents" "\\Users\\admin\\Desktop" "\\Users\\admin\\Downloads"

Defaults assume the guest user is "admin" and decoys live in
Desktop / Documents / Downloads.
"""

import sys
import json
import argparse
from collections import defaultdict

# File extensions that represent the kind of user documents we planted as
# decoys. Used to separate "victim document" activity from incidental
# system-file activity that may also occur inside a user folder.
VICTIM_FILE_EXTENSIONS = {
    "docx", "doc", "pptx", "ppt", "xlsx", "xls", "csv", "pdf",
    "txt", "py", "pyw", "ipynb", "rmd", "png", "jpg", "jpeg", "zip",
}

# Default decoy folders (case-insensitive substring match against the
# file path reported by CAPE). Backslashes match Windows-style paths.
DEFAULT_VICTIM_DIRS = [
    "\\Users\\admin\\Desktop",
    "\\Users\\admin\\Documents",
    "\\Users\\admin\\Downloads",
]

FILE_EVENT_TYPES = ["read", "write", "delete", "move", "copy"]
DESTRUCTIVE_EVENT_TYPES = ["write", "delete", "move"]

# Minimum number of destructive events on victim files to call it a real
# encryption run. Derived from observation: WannaCry produced thousands;
# self-installation / trigger-failure produced zero. Kept conservative.
MIN_DESTRUCTIVE_VICTIM_EVENTS = 20


def get_extension(path):
    if not path or '.' not in path.split('\\')[-1]:
        return "(none)"
    return path.split('.')[-1].lower()


def path_in_victim_dirs(path, victim_dirs):
    """Case-insensitive check whether a file path is inside any decoy dir."""
    if not path:
        return False
    lowered = path.lower()
    return any(victim_dir.lower() in lowered for victim_dir in victim_dirs)


def analyze(report, victim_dirs):
    """
    Walk behavior.enhanced file events and tally, separately:
      - activity on victim files inside the decoy folders
      - activity elsewhere (for context / self-installation detection)
    """
    victim_events = defaultdict(int)          # event_type -> count (victim docs)
    victim_paths = set()                      # distinct victim files touched
    elsewhere_events = defaultdict(int)       # event_type -> count (everything else)
    victim_ext_events = defaultdict(int)      # extension -> destructive count (victim)

    for event in report.get("behavior", {}).get("enhanced", []):
        if event.get("object") != "file":
            continue
        event_type = event.get("event")
        if event_type not in FILE_EVENT_TYPES:
            continue
        path = event.get("data", {}).get("file", "")

        if path_in_victim_dirs(path, victim_dirs):
            ext = get_extension(path)
            # Only count events on files that look like planted documents.
            if ext in VICTIM_FILE_EXTENSIONS:
                victim_events[event_type] += 1
                victim_paths.add(path)
                if event_type in DESTRUCTIVE_EVENT_TYPES:
                    victim_ext_events[ext] += 1
            else:
                # activity inside the folder but on a non-document file
                elsewhere_events[event_type] += 1
        else:
            elsewhere_events[event_type] += 1

    return victim_events, victim_paths, elsewhere_events, victim_ext_events


def classify(victim_events):
    destructive = sum(victim_events.get(t, 0) for t in DESTRUCTIVE_EVENT_TYPES)
    if destructive >= MIN_DESTRUCTIVE_VICTIM_EVENTS:
        return "TRUE_ENCRYPTION", destructive
    if destructive > 0:
        return "WEAK_VICTIM_ACTIVITY", destructive
    return "NO_VICTIM_ACTIVITY", destructive


def main():
    parser = argparse.ArgumentParser(
        description="Verify whether a sample actually attacked planted decoy files.")
    parser.add_argument("report_path", help="Path to report.json")
    parser.add_argument("--victim-dirs", nargs="+", default=DEFAULT_VICTIM_DIRS,
                         help="Decoy folder path fragments to match (Windows-style)")
    args = parser.parse_args()

    with open(args.report_path, "r", errors="replace") as f:
        report = json.load(f)

    victim_events, victim_paths, elsewhere_events, victim_ext_events = analyze(
        report, args.victim_dirs)

    verdict, destructive_count = classify(victim_events)

    print("=" * 60)
    print(f"File: {args.report_path}")
    print(f"Decoy folders: {', '.join(args.victim_dirs)}")
    print("=" * 60)

    print(f"\n[Victim-file activity] (planted documents in decoy folders)")
    for event_type in FILE_EVENT_TYPES:
        print(f"   {event_type:<8} {victim_events.get(event_type, 0)}")
    print(f"   distinct victim files touched: {len(victim_paths)}")

    if victim_ext_events:
        print(f"\n[Destructive activity by document type]")
        for ext, count in sorted(victim_ext_events.items(), key=lambda x: -x[1]):
            print(f"   .{ext:<8} {count}")

    print(f"\n[Activity elsewhere] (outside decoy folders / non-document files)")
    for event_type in FILE_EVENT_TYPES:
        print(f"   {event_type:<8} {elsewhere_events.get(event_type, 0)}")

    print(f"\n[Verdict] {verdict}")
    print(f"   destructive victim events: {destructive_count} "
          f"(threshold for TRUE_ENCRYPTION: {MIN_DESTRUCTIVE_VICTIM_EVENTS})")
    if verdict == "NO_VICTIM_ACTIVITY":
        print("   -> Sample did not touch the planted files. Likely trigger "
              "failure, sandbox evasion, or self-unpacking only.")
    elif verdict == "WEAK_VICTIM_ACTIVITY":
        print("   -> Some victim activity but low. Recommend manual review "
              "(screenshot / file listing).")
    else:
        print("   -> Sample attacked the planted files. Consistent with real "
              "ransomware encryption.")


if __name__ == "__main__":
    main()

