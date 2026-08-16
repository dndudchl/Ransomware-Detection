#!/usr/bin/env python3
"""
build_dataset.py - Join the feature tables into one and settle the decisions
that have to be made before any model sees the data.

Four decisions, each of which changes what the numbers afterwards mean:

positives
    Only runs the sandbox recorded as reaching encryption. Of 3,455
    ransomware analyses, 1,569 executed without encrypting anything -- the
    sample checked for a debugger, waited for a key that never came, or was
    a build that needed an argument. Their behaviour is not distinguishable
    from benign software because, in the recording, they did not do
    anything. Training on them teaches the model that doing nothing is
    ransomware, and the false positive rate follows.

    The cost is that the trained model only recognises ransomware that runs.
    It is the honest trade, but it has to be stated: nothing here says
    anything about detecting a sample before it triggers.

hard negatives held out
    Sixty-eight programs, each built to be as busy as ransomware while doing
    something a person asked for. Sixty-eight is far too few to train on --
    the model would memorise them -- but as a held-out set they answer the
    question the benign set cannot: what is the false positive rate on
    software that is active rather than inert.

duplicates
    The same binary was analysed more than once, from retries and from both
    hosts collecting it independently. Left in, the same file lands in a
    training fold and a test fold and the score goes up for no reason. Where
    the repeats disagree on the verdict, the run that got furthest is kept:
    a sample that encrypted once can encrypt, and the run where it did not
    was a run where conditions were wrong.

family groups
    Families that are the same lineage under different names, and the
    capitalisation variants, are merged so a leave-one-family-out split does
    not train on Sodinokibi and test on REvil.

Usage
-----
  python3 build_dataset.py --features-dir ../data/features \\
      --relational /tmp/rel_all.csv --out ../data/features/modelling.csv
"""

import os
import csv
import argparse
from collections import Counter, defaultdict

# Verdicts ordered by how far the run got. When one binary was analysed more
# than once and the runs disagree, the furthest is the one that says what the
# sample is capable of.
VERDICT_RANK = {
    "TRUE_ENCRYPTION": 3,
    "WEAK_VICTIM_ACTIVITY": 2,
    "NO_VICTIM_ACTIVITY": 1,
    "FAILED": 0,
    "": 0,
}

# Names that refer to one lineage. Splitting on family is meant to ask whether
# the model generalises to an implementation it has not seen; two names for
# one codebase in different folds defeats that.
FAMILY_ALIASES = {
    "revil": "Sodinokibi",
    "sodin": "Sodinokibi",
    "alphv": "BlackCat",
    "blackcat": "BlackCat",
    "noberus": "BlackCat",
    "rook": "Babuk",
    "nightsky": "Babuk",
    "night sky": "Babuk",
    "blackmatter": "DarkSide",
    "darkside": "DarkSide",
    "conti": "Conti",
    "ryuk": "Conti",
    "trigona": "Trigona",
    "global": "GLOBAL",
    "interlock": "Interlock",
}


def canon_family(name):
    if not name:
        return ""
    return FAMILY_ALIASES.get(name.strip().lower(), name.strip())


def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features-dir", default="../data/features")
    parser.add_argument("--relational", required=True)
    parser.add_argument("--out", default="../data/features/modelling.csv")
    parser.add_argument("--keep-nonencrypting", action="store_true",
                         help="Keep ransomware runs that executed without "
                              "encrypting, as positives. Off by default; see "
                              "the note at the top of this file.")
    args = parser.parse_args()

    d = args.features_dir
    ransom = read_csv(f"{d}/features.csv")
    benign = read_csv(f"{d}/features_benign.csv")
    hardneg = read_csv(f"{d}/features_hardneg.csv")
    print(f"read: ransomware {len(ransom)}, benign {len(benign)}, "
          f"hard negatives {len(hardneg)}")
    if not ransom:
        print("[!] no ransomware features found"); return

    rel = {r["task_id"]: r for r in read_csv(args.relational)}
    # n_calls is kept: the feature tables record total_calls only for rows
    # that were extracted with dynamic coverage, and the volume group and the
    # executed-only filter both need a call count that is present for every
    # row.
    rel_cols = [c for c in (next(iter(rel.values())).keys() if rel else [])
                if c != "task_id"]
    print(f"relational features: {len(rel_cols)} columns for {len(rel)} runs")

    rows = []
    for src, table in (("ransomware", ransom), ("benign", benign),
                       ("hardneg", hardneg)):
        for r in table:
            r["source"] = src
            rows.append(r)

    # --- attach relational features ---
    missing_rel = 0
    for r in rows:
        extra = rel.get(r["sample_id"])
        if extra is None:
            missing_rel += 1
            for c in rel_cols:
                r[c] = ""
        else:
            for c in rel_cols:
                r[c] = extra.get(c, "")
    if missing_rel:
        print(f"[warn] {missing_rel} rows had no relational features")

    # --- label ---
    kept, dropped_middle = [], 0
    for r in rows:
        if r["source"] == "ransomware":
            if r.get("verdict") == "TRUE_ENCRYPTION":
                r["y"] = "1"
            elif args.keep_nonencrypting:
                r["y"] = "1"
            else:
                dropped_middle += 1
                continue
        else:
            r["y"] = "0"
        kept.append(r)
    if dropped_middle:
        print(f"excluded {dropped_middle} ransomware runs that executed "
              f"without encrypting")

    # --- duplicates ---
    by_sha = defaultdict(list)
    for r in kept:
        sha = (r.get("sha256") or "").strip()
        by_sha[sha or f"__no_sha_{id(r)}"].append(r)

    deduped, removed, disagreed = [], 0, 0
    for sha, group in by_sha.items():
        if len(group) == 1:
            deduped.append(group[0]); continue
        if len({g.get("verdict", "") for g in group}) > 1:
            disagreed += 1
        best = max(group, key=lambda g: (VERDICT_RANK.get(g.get("verdict", ""), 0),
                                          int(g.get("n_calls") or 0)))
        deduped.append(best)
        removed += len(group) - 1
    print(f"removed {removed} duplicate analyses of the same binary "
          f"({disagreed} of the duplicated binaries disagreed on the verdict)")

    # --- family ---
    for r in deduped:
        r["family_group"] = canon_family(r.get("family", ""))

    pos = [r for r in deduped if r["y"] == "1"]
    fams = Counter(r["family_group"] or "(unknown)" for r in pos)
    big = [f for f, n in fams.items() if n >= 20 and f != "(unknown)"]
    print(f"\npositives {len(pos)}, families {len(fams)}, "
          f"with 20 or more members {len(big)}")
    for f, n in fams.most_common(12):
        print(f"   {f:<20}{n:>5}")

    counts = Counter((r["source"], r["y"]) for r in deduped)
    print(f"\nfinal table {len(deduped)} rows")
    for k in sorted(counts):
        print(f"   {k[0]:<12} y={k[1]}  {counts[k]:>5}")

    lead = ["sample_id", "sha256", "y", "source", "family_group", "coverage",
            "verdict", "label"]
    # Union across rows rather than the first row alone: the three sources
    # were extracted separately and a column present in one may be absent
    # from another, and the relational columns were attached afterwards.
    seen = list(lead)
    for r in deduped:
        for c in r:
            if c not in seen:
                seen.append(c)
    fields = seen
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in sorted(deduped, key=lambda x: (x["source"], x["sample_id"])):
            w.writerow({k: r.get(k, "") for k in fields})
    print(f"\n[saved] {args.out}")


if __name__ == "__main__":
    main()
