#!/usr/bin/env python3
"""
relational_extra.py - Three families of relational features the current set
does not have, each of which is a relation between two events on the same
target rather than a count of one kind of event.

Why these three
---------------
The existing relation group pairs reads with writes on the same *file*, and
that is where the volume-shift result comes from. But "same target" can mean
three things a program acts on, and only one of them is covered:

  the same file       covered   rw_jaccard, rw_latency_*, byte_io_ratio
  the same process    missing   who spawned whom, and what the children do
  the same moment     missing   how the work is distributed over the run

And even on files, what is paired is *whether* the two events happened and
*how long apart*, not *how much data* each moved. Encryption is the one
operation that returns exactly as many bytes as it took, per file. Nothing
in the current table sees that.

So:

  1. per-file byte ratio    the read/write ratio computed inside each file
                            and then summarised, rather than summed over
                            the run. A loop encrypting a folder gives a
                            tight distribution at one; an archiver gives a
                            wide one well below one; an installer gives
                            writes with no read to pair against.

  2. process relations      the shape of the process tree and what the
                            children are. Ransomware spawns shells to run
                            vssadmin, or re-launches itself; an installer
                            spawns msiexec once. Also which process did the
                            file writing, and across how many threads.

  3. temporal phase         where in the run the writing happens. A family
                            reconnoitres, clears the ground and then writes
                            in a burst; an installer writes from the start.
                            The existing gap_* features describe spacing
                            between events, not their position in the run.

Every feature here is scale-free -- a ratio, a share, a depth or a rank --
because that is the property the volume-shift experiment showed matters:
counts learn thresholds that move with scale, ratios do not.

What it reads
-------------
CAPE's report.json:

  behavior.processes[]        process_id, parent_id, process_name,
                              first_seen, calls[]
  behavior.processes[].calls  api, timestamp, thread_id, arguments
                              (NtReadFile/NtWriteFile carry Length and a
                              FileHandle; NtCreateFile maps handle to path)
  behavior.enhanced[]         object=file, event=read/write/delete,
                              data.file, timestamp

Handles are per-process, so the handle-to-path map is rebuilt for each
process. NtWriteFile does not carry the path, only the handle, so per-file
byte accounting depends on catching the NtCreateFile/NtOpenFile that
produced the handle. Where that fails the byte lands in an "unpaired" bucket
and is reported as a coverage figure, not silently dropped.

Usage
-----
Import into explore_relational.py and call from process_one():

    from relational_extra import extra_features
    row.update(extra_features(report))

or run standalone on a batch to see the feature table with AUCs:

    python3 relational_extra.py --archives ~/hn4_reports/a \\
        --results ~/work/res_o_a.csv --out /tmp/extra_o_a.csv --workers 6
"""

import os
import re
import csv
import glob
import gzip
import json
import argparse
import statistics
from datetime import datetime
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor

# ----------------------------------------------------------------- helpers

def _ts(s):
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S,%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except (ValueError, TypeError):
            pass
    return None


def _args(call):
    a = call.get("arguments")
    if isinstance(a, list):
        return {x.get("name"): x.get("value") for x in a if isinstance(x, dict)}
    return a if isinstance(a, dict) else {}


def _int(v):
    try:
        return int(str(v), 0)
    except (TypeError, ValueError):
        return None


def _median(v):
    return statistics.median(v) if v else None


def _iqr(v):
    if len(v) < 4:
        return None
    s = sorted(v)
    n = len(s)
    return s[(3 * n) // 4] - s[n // 4]


def _round(v, nd=4):
    return "" if v is None else round(v, nd)


SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
          "cscript.exe", "mshta.exe", "wmic.exe", "rundll32.exe",
          "regsvr32.exe", "schtasks.exe", "sc.exe", "net.exe", "net1.exe",
          "vssadmin.exe", "bcdedit.exe", "wbadmin.exe", "taskkill.exe",
          "icacls.exe", "takeown.exe", "attrib.exe", "reg.exe"}

INSTALLER_HOSTS = {"msiexec.exe", "dllhost.exe", "setup.exe",
                   "vcredist_x64.exe", "vcredist_x86.exe"}


# ------------------------------------------------ 1. per-file byte ratio

def per_file_byte_features(behavior):
    """
    Bytes read against bytes written, inside each file, then summarised.

    The run-level byte_io_ratio says how much came out against how much
    went in overall. That is one number, and two very different programs can
    share it: an archiver that reads ten files and writes one large one has
    the same total ratio as an encryptor that rewrites each of the ten
    at its own size. Inside each file the two are nothing alike -- the
    encryptor's per-file ratio is one, ten times over; the archiver's is
    undefined for nine files and enormous for the tenth.

    So the ratio is taken per file and the *distribution* is what is kept:
    the median, the spread, and how many files sit inside a band around one.
    Files that were only read or only written are counted separately rather
    than forced into the ratio, because "written without ever being read" is
    itself the signature of an installer.

    Handles are per-process; the map from handle to path is rebuilt each
    time a process is entered. NtWriteFile does not carry the path.
    """
    read_by_path = Counter()
    write_by_path = Counter()
    unpaired_read = unpaired_write = 0

    for process in behavior.get("processes", []) or []:
        handle_to_path = {}
        for call in process.get("calls", []) or []:
            api = call.get("api", "")
            args = _args(call)
            if api in ("NtCreateFile", "NtOpenFile"):
                h = args.get("FileHandle") or args.get("Handle")
                p = args.get("FileName") or args.get("ObjectAttributes")
                if h and p:
                    handle_to_path[str(h)] = str(p)
            elif api in ("NtReadFile", "NtWriteFile", "ReadFile", "WriteFile"):
                n = _int(args.get("Length") or args.get("length")
                         or args.get("Buffer_Length"))
                if n is None or n <= 0 or n > (1 << 30):
                    continue
                h = args.get("FileHandle") or args.get("hFile") or args.get("Handle")
                path = handle_to_path.get(str(h)) if h else None
                if api in ("NtReadFile", "ReadFile"):
                    if path:
                        read_by_path[path] += n
                    else:
                        unpaired_read += n
                else:
                    if path:
                        write_by_path[path] += n
                    else:
                        unpaired_write += n
            elif api in ("NtClose", "CloseHandle"):
                h = args.get("Handle") or args.get("hObject")
                if h:
                    handle_to_path.pop(str(h), None)

    both = set(read_by_path) & set(write_by_path)
    ratios = [write_by_path[p] / read_by_path[p] for p in both
              if read_by_path[p] > 0]
    n_read_only = len(set(read_by_path) - set(write_by_path))
    n_write_only = len(set(write_by_path) - set(read_by_path))
    n_files = len(set(read_by_path) | set(write_by_path))

    total_read = sum(read_by_path.values()) + unpaired_read
    total_write = sum(write_by_path.values()) + unpaired_write
    paired_share = ((sum(read_by_path.values()) + sum(write_by_path.values()))
                    / (total_read + total_write)) if (total_read + total_write) else None

    out = {
        # Coverage first: how much of the byte traffic could be attributed to
        # a path at all. Low values mean the handle map failed, and every
        # other number in this block should be read with that in mind.
        "pf_byte_paired_share": _round(paired_share),
        "pf_n_files_both": len(both),
        # The signature. Median near one, narrow spread: encryption.
        "pf_ratio_median": _round(_median(ratios)),
        "pf_ratio_iqr": _round(_iqr(ratios)),
        # Share of rewritten files whose output is within a fifth of the input
        # size either way. Encryption pads by a few bytes; compression halves.
        "pf_ratio_near_one": _round(
            sum(1 for r in ratios if 0.8 <= r <= 1.25) / len(ratios)) if ratios else "",
        # An installer writes files it never read. An archiver reads files it
        # never writes. An encryptor does neither in quantity.
        "pf_write_only_share": _round(n_write_only / n_files) if n_files else "",
        "pf_read_only_share": _round(n_read_only / n_files) if n_files else "",
    }
    return out


# ------------------------------------------------- 2. process relations

def process_features(behavior):
    """
    The shape of the process tree and what the writing was distributed over.

    Two programs that touch the same files can differ entirely in how they
    were organised. Ransomware often re-launches itself, or launches a shell
    to run vssadmin and bcdedit, or spreads its encryption across many
    threads. An installer launches msiexec, or an elevated copy of itself,
    and writes from one or two threads. A backup tool is usually one process
    and one worker pool.

    None of that is in the current table beyond n_executed_commands, which
    is a count of command lines and says nothing about who ran them.

    Everything here is normalised by the number of processes or the number
    of writes, so it does not move with how long the run was.
    """
    procs = behavior.get("processes", []) or []
    if not procs:
        return {k: "" for k in (
            "proc_n", "proc_tree_depth", "proc_shell_child_share",
            "proc_self_spawn", "proc_installer_host",
            "proc_write_concentration", "proc_write_thread_n",
            "proc_write_thread_share_top")}

    by_pid = {p.get("process_id"): p for p in procs}
    names = {p.get("process_id"): (p.get("process_name") or "").lower()
             for p in procs}
    root = procs[0]
    root_name = (root.get("process_name") or "").lower()
    root_pid = root.get("process_id")

    # Depth of the tree from the root sample.
    def depth(pid, seen=None):
        seen = seen or set()
        if pid in seen:
            return 0
        seen.add(pid)
        kids = [p.get("process_id") for p in procs if p.get("parent_id") == pid]
        return 1 + max((depth(k, seen) for k in kids), default=0)

    tree_depth = depth(root_pid)

    others = [p for p in procs if p.get("process_id") != root_pid]
    shell_children = sum(1 for p in others if names[p.get("process_id")] in SHELLS)
    self_spawn = any(names[p.get("process_id")] == root_name and root_name
                     for p in others)
    installer_host = any(names[p.get("process_id")] in INSTALLER_HOSTS
                         for p in others)

    # Which process, and which thread, did the file writing.
    writes_by_pid = Counter()
    writes_by_thread = Counter()
    for p in procs:
        pid = p.get("process_id")
        for call in p.get("calls", []) or []:
            if call.get("api") in ("NtWriteFile", "WriteFile"):
                writes_by_pid[pid] += 1
                writes_by_thread[(pid, call.get("thread_id"))] += 1
    n_writes = sum(writes_by_pid.values())

    return {
        "proc_n": len(procs),
        "proc_tree_depth": tree_depth,
        # Share of child processes that are shells or system utilities. High
        # for ground-clearing ransomware, near zero for installers.
        "proc_shell_child_share": _round(shell_children / len(others)) if others else "",
        # The sample launched a copy of itself. Common in ransomware
        # (privilege escalation, or one process per drive), rare elsewhere.
        "proc_self_spawn": int(bool(self_spawn)),
        "proc_installer_host": int(bool(installer_host)),
        # Share of all file writes done by the busiest process. Encryption
        # in one loop gives one; a build system or installer with helpers
        # spreads it out. Also flags the MSI blind spot: msiexec's child does
        # the writing and is not hooked, so this reads as the parent doing
        # nothing.
        "proc_write_concentration": _round(
            writes_by_pid.most_common(1)[0][1] / n_writes) if n_writes else "",
        # How many threads wrote at all, and how much the busiest one did.
        # A single-threaded encryptor is one thread at one; a pool of eight
        # is eight threads at roughly one eighth each.
        "proc_write_thread_n": len(writes_by_thread) if n_writes else "",
        "proc_write_thread_share_top": _round(
            writes_by_thread.most_common(1)[0][1] / n_writes) if n_writes else "",
    }


# ------------------------------------------------- 3. temporal phase

def phase_features(behavior):
    """
    Where in the run the writing happened.

    gap_* and burst_share describe the spacing between consecutive events.
    They do not say *when* the writing started or how much of the run it
    occupied. A family that spends forty seconds enumerating and killing
    services and then writes a thousand files in the next twenty has a late,
    concentrated writing phase; an installer starts writing almost at once
    and keeps at it; a person editing a document writes a little, all over.

    Position is expressed as a fraction of the run so it does not depend on
    the timeout or on how long the program took.
    """
    events = []
    for e in behavior.get("enhanced", []) or []:
        if e.get("object") != "file":
            continue
        t = _ts(e.get("timestamp"))
        if t:
            events.append((t, e.get("event")))
    if len(events) < 10:
        return {k: "" for k in ("ph_first_write_pos", "ph_write_span_share",
                                 "ph_write_half_pos", "ph_reads_before_first_write",
                                 "ph_write_concentration_q")}

    events.sort()
    t0, t1 = events[0][0], events[-1][0]
    span = (t1 - t0).total_seconds()
    if span <= 0:
        return {k: "" for k in ("ph_first_write_pos", "ph_write_span_share",
                                 "ph_write_half_pos", "ph_reads_before_first_write",
                                 "ph_write_concentration_q")}

    pos = lambda t: (t - t0).total_seconds() / span
    writes = [pos(t) for t, k in events if k in ("write", "delete", "move")]
    reads_before = 0
    for t, k in events:
        if k in ("write", "delete", "move"):
            break
        if k == "read":
            reads_before += 1
    n_reads = sum(1 for _, k in events if k == "read")

    if not writes:
        return {"ph_first_write_pos": "", "ph_write_span_share": "",
                "ph_write_half_pos": "",
                "ph_reads_before_first_write": _round(reads_before / n_reads) if n_reads else "",
                "ph_write_concentration_q": ""}

    writes.sort()
    # Which quarter of the run holds the most writes, and what share of them.
    quarters = Counter(min(3, int(w * 4)) for w in writes)
    top_q_share = quarters.most_common(1)[0][1] / len(writes)

    return {
        # When the first destructive event happened, as a fraction of the
        # run. Near zero for installers, later for anything that prepares.
        "ph_first_write_pos": _round(writes[0]),
        # How much of the run the writing occupied. Short for a burst.
        "ph_write_span_share": _round(writes[-1] - writes[0]),
        # By what point half the writes were done.
        "ph_write_half_pos": _round(writes[len(writes) // 2]),
        # Share of the reads that happened before anything was written --
        # reconnaissance. Ransomware enumerates first; an installer does not.
        "ph_reads_before_first_write": _round(reads_before / n_reads) if n_reads else "",
        # Share of the writes falling in the busiest quarter of the run.
        "ph_write_concentration_q": _round(top_q_share),
    }


# ------------------------------------------------------------- assembly

def extra_features(report):
    behavior = report.get("behavior", {}) or {}
    row = {}
    row.update(per_file_byte_features(behavior))
    row.update(process_features(behavior))
    row.update(phase_features(behavior))
    return row


EXTRA_GROUPS = {
    # For train_model.py GROUPS: which group each new column belongs to.
    "relation": ["pf_ratio_median", "pf_ratio_iqr", "pf_ratio_near_one",
                 "pf_write_only_share", "pf_read_only_share",
                 "proc_write_concentration", "proc_write_thread_share_top",
                 "ph_reads_before_first_write"],
    "sequence": ["ph_first_write_pos", "ph_write_span_share",
                 "ph_write_half_pos", "ph_write_concentration_q"],
    "volume":   ["pf_n_files_both", "proc_n", "proc_tree_depth",
                 "proc_write_thread_n"],
    "indicator": ["proc_shell_child_share", "proc_self_spawn",
                  "proc_installer_host"],
    # Coverage diagnostics; not model input.
    "_diagnostic": ["pf_byte_paired_share"],
}


# --------------------------------------------------------- standalone

def _load(path):
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt", errors="replace") as f:
        return json.load(f)


def _task_id(path):
    m = re.search(r"task_(\d+)", os.path.basename(path))
    return m.group(1) if m else os.path.basename(path).split(".")[0]


def _one(path):
    try:
        r = _load(path)
    except Exception as e:
        return {"task_id": _task_id(path), "_error": type(e).__name__}
    row = {"task_id": _task_id(path)}
    row.update(extra_features(r))
    return row


def _auc(pos, neg):
    if not pos or not neg:
        return None
    ranked = sorted([(v, 1) for v in pos] + [(v, 0) for v in neg])
    rank_sum = 0.0
    i = 0
    while i < len(ranked):
        j = i
        while j + 1 < len(ranked) and ranked[j + 1][0] == ranked[i][0]:
            j += 1
        avg = (i + j + 2) / 2
        rank_sum += avg * sum(1 for k in range(i, j + 1) if ranked[k][1] == 1)
        i = j + 1
    n1, n0 = len(pos), len(neg)
    return (rank_sum - n1 * (n1 + 1) / 2) / (n1 * n0)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archives", required=True)
    p.add_argument("--results", help="analyze_result.py CSV, for AUC by verdict")
    p.add_argument("--out", required=True)
    p.add_argument("--workers", type=int, default=4)
    args = p.parse_args()

    files = sorted(glob.glob(os.path.join(os.path.expanduser(args.archives), "*.json*")))
    print(f"reading {len(files)} reports with {args.workers} workers")
    with ProcessPoolExecutor(args.workers) as ex:
        rows = list(ex.map(_one, files, chunksize=8))
    rows = [r for r in rows if "_error" not in r]

    keys = ["task_id"] + [k for k in rows[0] if k != "task_id"] if rows else ["task_id"]
    with open(os.path.expanduser(args.out), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)
    print(f"[saved] {args.out}  ({len(rows)} rows, {len(keys)-1} features)")

    if not args.results:
        return
    verdict = {}
    for r in csv.DictReader(open(os.path.expanduser(args.results))):
        verdict[r.get("task_id") or r.get("task")] = r.get("verdict", "")
    enc = [r for r in rows if verdict.get(r["task_id"]) == "TRUE_ENCRYPTION"]
    oth = [r for r in rows if verdict.get(r["task_id"], "") and
           verdict.get(r["task_id"]) != "TRUE_ENCRYPTION"]
    print(f"\nmatched: encrypting {len(enc)}, other {len(oth)}\n")
    print(f"{'feature':<32}{'cov':>6}{'AUC':>8}   median enc / other")
    print("-" * 70)
    def num(r, k):
        try:
            return float(r[k])
        except (ValueError, TypeError, KeyError):
            return None
    for k in keys[1:]:
        pv = [num(r, k) for r in enc]; pv = [v for v in pv if v is not None]
        nv = [num(r, k) for r in oth]; nv = [v for v in nv if v is not None]
        cov = (len(pv) + len(nv)) / max(1, len(enc) + len(oth))
        a = _auc(pv, nv)
        me = _median(pv); mo = _median(nv)
        a_s = f"{a:.3f}" if a is not None else "  -  "
        print(f"{k:<32}{cov:>5.0%} {a_s:>8}   "
              f"{'' if me is None else round(me,4)} / {'' if mo is None else round(mo,4)}")


if __name__ == "__main__":
    main()
