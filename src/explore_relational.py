#!/usr/bin/env python3
"""
explore_relational.py - Measure candidate relational features and report how
much they cover and how far they separate.

Why these candidates
--------------------
Removing every feature derived from the verdict left nothing that was both
relational and available for every run. The top survivors were plain counts
(n_write, n_read), and the two genuinely relational features were thin:
write_crypto_pearson covered 65% of runs, prep_overlaps_destroy 61%.

The API call sequence is untouched by any of that. Every run has one, they
run to fifty thousand calls at the median across 312 distinct APIs, and
nothing in the verdict logic reads them. Four things can be measured from it
that describe relations between events rather than counts of them.

  category transitions
      write_crypto_pearson correlates two per-window series, and fails
      whenever one of them is flat -- which is why a third of encrypting runs
      have no value: they never call a Windows crypto API, so that series is
      all zeros and its standard deviation is zero. Counting how often a
      filesystem call is immediately followed by a crypto call measures the
      same relation without that failure mode: zero transitions is a real
      observation rather than an undefined one.

  per-file operation chains
      What happened to one path, in order. read then write then delete is a
      different thing from read alone, even when both touch the same number
      of files. An archiver that read 56 decoy files and destroyed none
      produces chains of one shape; encryption produces another.

  sequence repetitiveness
      Encrypting a thousand files means running one short loop a thousand
      times. Compressing the API token stream measures that directly: a tight
      loop compresses far better than an installer doing many different
      things once each.

  transition entropy
      How predictable the next call is, given the current one. The same
      intuition as repetitiveness, measured on the transition distribution
      rather than the raw stream.

What this cannot tell you
-------------------------
It compares runs that encrypted against runs that executed and did not. Both
are ransomware. A feature that separates them is telling you what accompanies
reaching the encryption stage, not what distinguishes ransomware from
ordinary software -- and the counts already win on that comparison for the
uninteresting reason that runs which stopped short did less of everything.

The comparison that matters needs benign runs. Until those exist this script
answers a narrower question: which candidates are computable everywhere, and
which are worth carrying forward to that test.

Usage
-----
  python3 explore_relational.py --archives ~/reports_a ~/reports_b \\
      --results /tmp/res_all.csv --workers 6 --out /tmp/relational.csv
"""

import os
import re
import csv
import sys
import gzip
import json
import zlib
import math
import argparse
from pathlib import Path
from collections import Counter, defaultdict

# Event types that end a file's life as the user knew it.
DESTRUCTIVE = {"delete", "move"}


def load_report(path):
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", errors="replace") as f:
        return json.load(f)


def task_id_of(path):
    m = re.search(r"task[_-]?(\d+)", Path(path).name)
    return m.group(1) if m else Path(path).stem


def api_stream(behavior):
    """Every API call in order, as (api, category) pairs."""
    out = []
    for process in behavior.get("processes", []) or []:
        for call in process.get("calls", []) or []:
            out.append((call.get("api") or "?", call.get("category") or "?"))
    return out


def transition_features(stream):
    """
    Adjacency between consecutive calls, at two levels of detail.

    The category level is the interesting one: filesystem followed by crypto,
    and crypto followed by filesystem, are the two halves of "read a file,
    encrypt it, write it back". Counting them needs no variance in anything
    and so is defined for every run, including the ones that never call a
    crypto API at all -- those simply score zero.
    """
    f = {}
    if len(stream) < 2:
        return {k: 0 for k in (
            "api_distinct", "api_distinct_bigrams", "api_branching",
            "api_bigram_entropy", "api_top_bigram_share",
            "fs_to_crypto", "crypto_to_fs", "fs_crypto_interleave",
            "cat_distinct_bigrams", "cat_switch_rate")}

    apis = [a for a, _ in stream]
    cats = [c for _, c in stream]

    api_bigrams = Counter(zip(apis, apis[1:]))
    total = sum(api_bigrams.values())
    f["api_distinct"] = len(set(apis))
    f["api_distinct_bigrams"] = len(api_bigrams)
    f["api_branching"] = round(len(api_bigrams) / max(1, len(set(apis))), 3)

    # Shannon entropy over the transition distribution. A loop concentrates
    # its mass on a few pairs and scores low; varied work spreads out.
    ent = -sum((c / total) * math.log2(c / total) for c in api_bigrams.values())
    f["api_bigram_entropy"] = round(ent, 3)
    f["api_top_bigram_share"] = round(api_bigrams.most_common(1)[0][1] / total, 4)

    cat_bigrams = Counter(zip(cats, cats[1:]))
    f["cat_distinct_bigrams"] = len(cat_bigrams)
    f["fs_to_crypto"] = cat_bigrams.get(("filesystem", "crypto"), 0)
    f["crypto_to_fs"] = cat_bigrams.get(("crypto", "filesystem"), 0)
    # Both directions present means the two are interleaved rather than the
    # program doing all its crypto in one block and all its writing in
    # another. The minimum is the number of complete round trips.
    f["fs_crypto_interleave"] = min(f["fs_to_crypto"], f["crypto_to_fs"])
    switches = sum(c for (a, b), c in cat_bigrams.items() if a != b)
    f["cat_switch_rate"] = round(switches / total, 4)
    return f


def repetitiveness(stream, cap=200_000):
    """
    How much the API stream repeats itself.

    Encrypting a thousand files runs one loop a thousand times, which
    compresses to almost nothing. A program doing many different things once
    each does not. The ratio is a cheap stand-in for "is this a loop over
    many objects".
    """
    if not stream:
        return {"api_compress_ratio": ""}
    # One byte per distinct API keeps the compressor working on structure
    # rather than on the length of the names.
    index = {}
    buf = bytearray()
    for api, _ in stream[:cap]:
        if api not in index:
            index[api] = len(index) % 256
        buf.append(index[api])
    packed = zlib.compress(bytes(buf), 6)
    return {"api_compress_ratio": round(len(packed) / max(1, len(buf)), 5)}


def chain_features(behavior):
    """
    The ordered set of operations applied to each individual path.

    Counting files touched says how much happened. The shape of what happened
    to one file says what kind of thing it was: read-then-write-then-delete
    is encryption whatever the volume, and read-with-nothing-following is an
    archiver or a scanner however many files it covers.
    """
    seen = defaultdict(list)
    for event in behavior.get("enhanced", []) or []:
        if event.get("object") != "file":
            continue
        kind = event.get("event")
        data = event.get("data", {}) or {}
        path = data.get("file") or data.get("from")
        if not path or not kind:
            continue
        if not seen[path] or seen[path][-1] != kind:
            seen[path].append(kind)

    if not seen:
        return {k: "" for k in (
            "n_paths", "chain_read_only", "chain_write_only",
            "chain_read_write", "chain_read_destroy", "chain_write_destroy",
            "chain_full", "chain_distinct_shapes", "chain_top_shape_share")}

    shapes = Counter()
    for steps in seen.values():
        s = set(steps)
        has_r, has_w = "read" in s, "write" in s
        has_d = bool(s & DESTRUCTIVE)
        if has_r and has_w and has_d:
            shapes["full"] += 1
        elif has_r and has_w:
            shapes["read_write"] += 1
        elif has_r and has_d:
            shapes["read_destroy"] += 1
        elif has_w and has_d:
            shapes["write_destroy"] += 1
        elif has_r:
            shapes["read_only"] += 1
        elif has_w:
            shapes["write_only"] += 1
        else:
            shapes["other"] += 1

    n = sum(shapes.values())
    out = {"n_paths": n}
    for name in ("read_only", "write_only", "read_write",
                 "read_destroy", "write_destroy", "full"):
        out[f"chain_{name}"] = round(shapes.get(name, 0) / n, 4)
    out["chain_distinct_shapes"] = len(shapes)
    out["chain_top_shape_share"] = round(shapes.most_common(1)[0][1] / n, 4)
    return out


# Ransomware has to leave the machine usable. A victim who cannot boot
# cannot read the note, find the wallet, or pay, so families routinely
# restrict themselves to documents and media and step around executables,
# drivers and the Windows directory. That restraint is a relationship
# between what a file is and whether it was destroyed, and it is invisible
# to a count of how many extensions were touched.
EXT_GROUPS = {
    "document": {"doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf",
                 "odt", "ods", "txt", "csv", "xml", "json", "md"},
    "media": {"jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "svg",
              "mp3", "mp4", "avi", "mkv", "mov", "wav", "webm", "webp"},
    "archive": {"zip", "rar", "7z", "tar", "gz", "bz2", "iso", "cab"},
    "database": {"db", "sql", "mdb", "accdb", "sqlite", "bak", "dbf"},
    "code": {"c", "cpp", "h", "py", "java", "js", "cs", "php", "rb", "go"},
    "executable": {"exe", "dll", "sys", "drv", "ocx", "cpl", "scr", "msi",
                   "com", "bat", "cmd", "ps1", "efi"},
}
EXT_TO_GROUP = {e: g for g, exts in EXT_GROUPS.items() for e in exts}

# Paths a family sparing the machine would read but not wreck.
SYSTEM_MARKERS = ("\\windows\\", "\\program files", "\\programdata\\",
                  "\\system32\\", "\\syswow64\\")


def _ext_of(path):
    name = path.replace("/", "\\").split("\\")[-1]
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def selectivity_features(behavior):
    """
    Whether destruction tracked what the file was.

    Counting extensions says how widely a run ranged. It does not say whether
    the run chose. A disk cleaner and a wiper destroy whatever they find, so
    their destruction rate is flat across file types. A family that means to
    be paid destroys documents and leaves the executables that let the
    machine boot, and its rate varies sharply by type.

    Measured as rates per group and the spread between them, so none of it
    grows with how many files were involved.

    Only the source side of a rename is read: the extension a family appends
    to its output is already used by the verdict logic, and counting it here
    would make the feature partly a restatement of the label.
    """
    touched = Counter()
    destroyed = Counter()
    sys_touched = sys_destroyed = user_touched = user_destroyed = 0

    for event in behavior.get("enhanced", []) or []:
        if event.get("object") != "file":
            continue
        kind = event.get("event")
        data = event.get("data", {}) or {}
        path = data.get("file") or data.get("from")
        if not path or not kind:
            continue

        group = EXT_TO_GROUP.get(_ext_of(path), "other")
        touched[group] += 1
        low = path.lower()
        in_system = any(m in low for m in SYSTEM_MARKERS)
        if in_system:
            sys_touched += 1
        else:
            user_touched += 1
        if kind in DESTRUCTIVE:
            destroyed[group] += 1
            if in_system:
                sys_destroyed += 1
            else:
                user_destroyed += 1

    if not touched:
        return {k: "" for k in (
            "sel_rate_document", "sel_rate_media", "sel_rate_executable",
            "sel_rate_spread", "sel_doc_minus_exe",
            "sel_destroyed_exe_share", "sel_destroyed_doc_share",
            "sel_system_spared", "sel_system_touch_share")}

    out = {}
    rates = {}
    for group in ("document", "media", "executable", "archive", "database"):
        seen = touched.get(group, 0)
        if seen >= 3:
            rates[group] = destroyed.get(group, 0) / seen
    for group in ("document", "media", "executable"):
        out[f"sel_rate_{group}"] = round(rates[group], 4) if group in rates else ""

    # A flat profile means the run did not choose. A wide one means it did.
    out["sel_rate_spread"] = round(max(rates.values()) - min(rates.values()), 4) \
        if len(rates) >= 2 else ""
    out["sel_doc_minus_exe"] = round(rates["document"] - rates["executable"], 4) \
        if "document" in rates and "executable" in rates else ""

    total_destroyed = sum(destroyed.values())
    if total_destroyed:
        out["sel_destroyed_exe_share"] = round(
            destroyed.get("executable", 0) / total_destroyed, 4)
        out["sel_destroyed_doc_share"] = round(
            (destroyed.get("document", 0) + destroyed.get("media", 0))
            / total_destroyed, 4)
    else:
        out["sel_destroyed_exe_share"] = ""
        out["sel_destroyed_doc_share"] = ""

    # Reached into the system directories and left them alone, while
    # destroying elsewhere.
    out["sel_system_spared"] = int(
        sys_touched >= 5 and sys_destroyed == 0 and user_destroyed > 0)
    out["sel_system_touch_share"] = round(sys_touched / (sys_touched + user_touched), 4)
    return out


def extension_features(behavior):
    """
    How indiscriminate the file selection was, over every path touched.

    destructive_extension_variety already counts this, but only over the
    events the verdict also reads, which makes it circular. Counting across
    all file activity keeps the idea and drops the dependency.
    """
    exts = Counter()
    for event in behavior.get("enhanced", []) or []:
        if event.get("object") != "file":
            continue
        data = event.get("data", {}) or {}
        for path in (data.get("file"), data.get("from"), data.get("to")):
            if not path:
                continue
            name = path.replace("/", "\\").split("\\")[-1]
            exts["." + name.rsplit(".", 1)[-1].lower() if "." in name else "(none)"] += 1
    if not exts:
        return {"ext_variety_all": "", "ext_top_share": ""}
    total = sum(exts.values())
    return {"ext_variety_all": len(exts),
            "ext_top_share": round(exts.most_common(1)[0][1] / total, 4)}


# Each of these is something ordinary software does. Enumerating a
# directory is what a backup tool does. Writing a file is what every editor
# does. Stopping a service is what an installer does. None of them is
# evidence of anything on its own.
#
# What makes a run ransomware is doing most of them, to one purpose, inside
# one execution. So the thing to measure is not whether any single stage
# occurred but how many of them did, and whether they hang together in time.
#
# Stages the verdict already reads -- renaming, deleting, dropping a note --
# are tracked separately, so the count can be reported both with and without
# them. A feature that only works when the label's own inputs are included
# is not evidence about the label.
COMMAND_STAGES = {
    "shadow_delete":   ("vssadmin", "shadowcopy", "shadowstorage", "wmic shadow"),
    "recovery_off":    ("bcdedit", "wbadmin", "recoveryenabled", "bootstatuspolicy"),
    "service_stop":    ("net stop", "sc stop", "sc config", "taskkill /f"),
    "log_clear":       ("wevtutil", "cl system", "cl security"),
    "backup_delete":   ("delete catalog", "delete systemstatebackup"),
}

ENUMERATION_APIS = {
    "NtQueryDirectoryFile", "NtQueryDirectoryFileEx", "FindFirstFileExW",
    "FindNextFileW", "GetLogicalDriveStringsW", "NtQueryVolumeInformationFile",
    "SHGetFolderPathW", "GetDiskFreeSpaceExW",
}

PERSISTENCE_KEYS = ("currentversion\\run", "currentversion\\runonce",
                    "\\winlogon\\shell", "\\userinit")

WALLPAPER_MARKS = ("transcodedwallpaper", "\\themes\\", "wallpaper")

# Stages that feed the verdict, kept apart from the rest.
VERDICT_STAGES = {"rename", "delete", "note"}

NOTE_WORDS = ("readme", "decrypt", "recover", "restore", "howto", "unlock",
              "ransom", "yourfiles", "filesback")


def stage_features(report):
    """
    How many distinct stages of the attack the run performed, and how tightly
    they sit together.

    A tool that archives files reads and writes and deletes. It does not also
    enumerate every drive, stop services, clear logs, disable recovery and
    change the wallpaper. The count of stages is a count, but of things that
    are individually innocuous -- so unlike a count of write operations it
    does not simply grow with how busy the run was.
    """
    behavior = report.get("behavior", {}) or {}
    summary = behavior.get("summary", {}) or {}

    # first time each stage was seen, where a time is available
    seen_at = {}

    def mark(stage, ts=None):
        if stage not in seen_at or (ts and seen_at[stage] is None):
            seen_at[stage] = ts
        elif ts and seen_at[stage] and ts < seen_at[stage]:
            seen_at[stage] = ts

    for event in behavior.get("enhanced", []) or []:
        if event.get("object") != "file":
            continue
        kind = event.get("event")
        data = event.get("data", {}) or {}
        path = (data.get("file") or data.get("from") or "")
        ts = event.get("timestamp")
        low = path.lower()
        if kind == "read":
            mark("read", ts)
        elif kind == "write":
            mark("write", ts)
            if any(m in low for m in WALLPAPER_MARKS):
                mark("wallpaper", ts)
            base = low.replace("/", "\\").split("\\")[-1]
            flat = re.sub(r"[\s_\-\.!]+", "", base)
            if any(w in flat for w in NOTE_WORDS):
                mark("note", ts)
        elif kind == "move":
            mark("rename", ts)
        elif kind == "delete":
            mark("delete", ts)

    for process in behavior.get("processes", []) or []:
        for call in process.get("calls", []) or []:
            api = call.get("api")
            if api in ENUMERATION_APIS:
                mark("enumerate", call.get("timestamp"))
            elif api and api.startswith("Crypt") or (api or "").startswith("BCrypt"):
                mark("crypto", call.get("timestamp"))

    for key in (summary.get("write_keys") or []):
        if any(k in key.lower() for k in PERSISTENCE_KEYS):
            mark("persistence", None)
            break

    commands = " ".join(summary.get("executed_commands") or []).lower()
    for stage, marks in COMMAND_STAGES.items():
        if any(m in commands for m in marks):
            mark(stage, None)

    stages = set(seen_at)
    clean = stages - VERDICT_STAGES

    out = {
        "n_stages_all": len(stages),
        "n_stages_clean": len(clean),
        "stage_ground_clearing": len(stages & {"shadow_delete", "recovery_off",
                                                "service_stop", "log_clear",
                                                "backup_delete"}),
        "stage_has_enumerate": int("enumerate" in stages),
        "stage_has_wallpaper": int("wallpaper" in stages),
        "stage_has_persistence": int("persistence" in stages),
    }

    # How spread out in time the staging was. A run that does everything in
    # one burst looks different from one that unfolds over minutes.
    times = sorted(t for t in seen_at.values() if t)
    if len(times) >= 2:
        try:
            from datetime import datetime
            fmt = "%Y-%m-%d %H:%M:%S,%f"
            first = datetime.strptime(times[0], fmt)
            last = datetime.strptime(times[-1], fmt)
            out["stage_span_sec"] = round((last - first).total_seconds(), 2)
            out["stage_timed_count"] = len(times)
        except (ValueError, TypeError):
            out["stage_span_sec"] = ""
            out["stage_timed_count"] = len(times)
    else:
        out["stage_span_sec"] = ""
        out["stage_timed_count"] = len(times)
    return out


def set_relation_features(behavior):
    """
    How the set of files read overlaps the set written and the set destroyed.

    Counting reads and writes says how much happened. Comparing the sets says
    what kind of thing it was, and the comparison is a ratio of sets so it
    does not move with volume.

    An archiver reads many files and writes one: almost everything it read is
    outside what it wrote. Encryption in place reads and writes the same
    paths, so the two sets coincide. A dropper writes files it never read.
    These are three different shapes of the same read and write counts.
    """
    reads, writes, destroys = set(), set(), set()
    for event in behavior.get("enhanced", []) or []:
        if event.get("object") != "file":
            continue
        data = event.get("data", {}) or {}
        kind = event.get("event")
        path = data.get("file") or data.get("from")
        if not path:
            continue
        if kind == "read":
            reads.add(path)
        elif kind == "write":
            writes.add(path)
        elif kind in DESTRUCTIVE:
            destroys.add(path)

    if not (reads or writes or destroys):
        return {k: "" for k in (
            "rw_jaccard", "write_not_read", "read_not_write",
            "read_then_destroy", "write_then_destroy", "rw_size_ratio")}

    union = reads | writes
    return {
        # Same paths read and written: encryption over the original file.
        "rw_jaccard": round(len(reads & writes) / len(union), 4) if union else "",
        # Written without being read: notes, dropped payloads, new archives.
        "write_not_read": round(len(writes - reads) / len(writes), 4) if writes else "",
        # Read and left alone: scanning, or an archiver's inputs.
        "read_not_write": round(len(reads - writes) / len(reads), 4) if reads else "",
        # Read, then removed.
        "read_then_destroy": round(len(reads & destroys) / len(reads), 4) if reads else "",
        "write_then_destroy": round(len(writes & destroys) / len(writes), 4) if writes else "",
        # One output per input, or many inputs to one output.
        "rw_size_ratio": round(len(writes) / len(reads), 4) if reads else "",
    }


def process_one(path):
    try:
        report = load_report(path)
    except Exception as e:
        return {"task_id": task_id_of(path), "_error": f"{type(e).__name__}"}
    behavior = report.get("behavior", {}) or {}
    stream = api_stream(behavior)

    row = {"task_id": task_id_of(path), "n_calls": len(stream)}
    row.update(transition_features(stream))
    row.update(repetitiveness(stream))
    row.update(chain_features(behavior))
    row.update(extension_features(behavior))
    row.update(selectivity_features(behavior))
    row.update(set_relation_features(behavior))
    row.update(stage_features(report))
    return row


# ---------------- measurement ----------------

def auc(pos, neg):
    pos = [x for x in pos if x is not None]
    neg = [x for x in neg if x is not None]
    if not pos or not neg:
        return None, 0, 0
    allv = sorted([(v, 1) for v in pos] + [(v, 0) for v in neg])
    ranks = {}
    i = 0
    while i < len(allv):
        j = i
        while j + 1 < len(allv) and allv[j + 1][0] == allv[i][0]:
            j += 1
        r = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[k] = r
        i = j + 1
    rp = sum(ranks[i] for i, (_v, l) in enumerate(allv) if l == 1)
    return (rp - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)), len(pos), len(neg)


def num(row, key):
    v = row.get(key, "")
    if v is None or v == "":
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Measure candidate relational features.")
    parser.add_argument("--archives", nargs="+", required=True)
    parser.add_argument("--results", required=True,
                         help="analyze_result output, for the verdicts")
    parser.add_argument("--prefix", nargs="*", default=[],
                         help="Task id prefix per archive directory, in the same "
                              "order (use '' for none). Needed when two hosts "
                              "number their tasks from one.")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--out", default="/tmp/relational.csv")
    parser.add_argument("--limit", type=int, default=None,
                         help="Only read this many reports, for a quick look")
    args = parser.parse_args()

    targets = []
    for i, d in enumerate(args.archives):
        pre = args.prefix[i] if i < len(args.prefix) else ""
        base = Path(d).expanduser()
        files = sorted((p for p in base.iterdir()
                        if p.is_file() and (p.suffix == ".gz" or p.name.endswith(".json"))),
                       key=lambda p: (int(m.group(1))
                                      if (m := re.search(r"task[_-]?(\d+)", p.name))
                                      else 10**9, p.name))
        targets += [(str(p), pre) for p in files]
    if args.limit:
        targets = targets[:args.limit]

    print(f"reading {len(targets)} reports with {args.workers} workers\n")

    rows = []
    if args.workers > 1:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            done = 0
            for (path, pre), row in zip(targets,
                                         pool.map(process_one,
                                                  [t[0] for t in targets],
                                                  chunksize=4)):
                done += 1
                if done % 100 == 0 or done == len(targets):
                    print(f"\r   {done}/{len(targets)}", end="", flush=True)
                row["task_id"] = pre + row["task_id"]
                rows.append(row)
        print()
    else:
        for path, pre in targets:
            row = process_one(path)
            row["task_id"] = pre + row["task_id"]
            rows.append(row)

    errors = [r for r in rows if r.get("_error")]
    rows = [r for r in rows if not r.get("_error")]
    if errors:
        print(f"[!] {len(errors)} reports could not be read")

    fields = sorted({k for r in rows for k in r})
    fields = ["task_id", "n_calls"] + [f for f in fields if f not in ("task_id", "n_calls")]
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})
    print(f"[saved] {args.out}\n")

    verdicts = {}
    with open(args.results, newline="") as f:
        for r in csv.DictReader(f):
            verdicts[str(r.get("task_id", "")).strip()] = r.get("verdict", "")

    enc = [r for r in rows if verdicts.get(r["task_id"]) == "TRUE_ENCRYPTION"]
    non = [r for r in rows if verdicts.get(r["task_id"]) not in
           (None, "", "TRUE_ENCRYPTION")]
    print(f"matched to a verdict: encrypting {len(enc)}, other {len(non)}")
    if not enc or not non:
        print("[!] cannot compare")
        return

    candidates = [c for c in fields if c not in ("task_id", "_error")]
    print(f"\n{'feature':<28}{'coverage':>10}{'AUC':>8}   distribution (median enc / other)")
    print("-" * 82)

    scored = []
    for c in candidates:
        a, np_, nn = auc([num(r, c) for r in enc], [num(r, c) for r in non])
        if a is None:
            continue
        cov = np_ / len(enc) * 100
        pe = sorted(x for x in (num(r, c) for r in enc) if x is not None)
        po = sorted(x for x in (num(r, c) for r in non) if x is not None)
        me = pe[len(pe) // 2] if pe else float("nan")
        mo = po[len(po) // 2] if po else float("nan")
        scored.append((abs(a - 0.5), a, c, cov, me, mo))

    for _, a, c, cov, me, mo in sorted(scored, key=lambda x: -x[0]):
        print(f"{c:<28}{cov:>9.0f}%{a:>8.3f}   {me:>12.4g} / {mo:<12.4g}")

    print("\nBoth groups are ransomware, so a high AUC here means the feature")
    print("accompanies reaching the encryption stage -- not that it separates")
    print("ransomware from ordinary software. Coverage is the number to read")
    print("now: anything below 100% has the same weakness that made")
    print("write_crypto_pearson unusable.")


if __name__ == "__main__":
    main()
