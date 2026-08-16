#!/usr/bin/env python3
"""
train_model.py - Train, and take the feature groups apart to see which of
them the performance actually rests on.

The number that is easy to produce
----------------------------------
Train on everything, test on a random split, report the AUC. It will be
high. Four fifths of the benign set never executed, so those rows are zero
on every dynamic feature and any count separates them. That number measures
the sandbox's ability to notice that a program ran.

So three things are done differently here.

Circular features are removed outright
    The positive label is the verdict, and the verdict is computed from
    decoy destruction, append-renames, ransom notes and shared extensions.
    A model given those features is being told the answer. They are dropped
    before anything else happens.

The split is by family, not at random
    Twenty-one families have twenty or more encrypting runs. Each becomes a
    fold: train on the other twenty, test on that one. This asks whether the
    model recognises ransomware it has not seen an example of, which is the
    only question a detector faces in deployment. Random splits put LockBit
    in both halves and answer nothing.

Three false positive rates are reported, not one
    On the whole benign set, on the benign runs that actually executed, and
    on the hard negatives -- sixty-eight programs built to be as busy as
    ransomware while doing something legitimate. The three differ by a lot,
    and the third is the one worth quoting.

Feature groups
--------------
Cumulative, so each line shows what the group above it added:

    static      the import table, available without running anything
    volume      how much happened: calls, paths, distinct APIs
    sequence    the shape of the API stream, independent of files
    relation    how reads relate to writes, without reference to destruction
    destruction features counting what was destroyed -- reported separately
                because they overlap with the verdict's own inputs, even
                though none of them restates one

Usage
-----
  python3 train_model.py --data ../data/features/modelling.csv
"""

import os
import csv
import math
import argparse
from collections import Counter, defaultdict

# Computed by the verdict logic itself. Including any of these hands the
# model the label for the positive class.
CIRCULAR = {
    "destroyed_decoy_files", "append_renames", "distinct_rename_suffixes",
    "shared_extension_renames", "ransom_note_dirs", "ransom_note_explicit",
    "ransom_note_candidates", "ransom_note_name", "corroborating_axes",
    "destructive_events", "destructive_extension_variety",
    "destructive_chain_windows", "replacement_extension",
    "extension_replacements", "distinct_target_extensions",
    "verdict", "reason", "malscore",
}

# Bookkeeping, not behaviour.
NON_FEATURES = {
    "sample_id", "sha256", "y", "source", "family_group", "family", "label",
    "coverage", "cape_family", "original_filename", "added_date", "notes",
    "source_dataset", "task_id", "_error",
}

GROUPS = {
    "static": [
        "total_imports", "indicative_category_count", "imp_crypto",
        "imp_file_unlock", "imp_network_spread", "imp_process_control",
        "imp_persistence", "imp_discovery", "imp_anti_analysis",
        "crypto_imported_not_called", "crypto_called_not_imported",
        "static_dynamic_agreement", "n_sections", "entropy_mean",
    ],
    "volume": [
        "n_calls", "n_paths", "n_read", "n_write", "n_copy", "n_execute",
        "n_file_writes", "n_registry_writes", "n_registry_deletes",
        "n_services_created", "n_services_started", "n_executed_commands",
        "active_windows", "other_windows", "write_only_nondestructive_windows",
        "ext_variety_all", "api_distinct", "api_distinct_bigrams",
        "cat_distinct_bigrams", "chain_distinct_shapes", "n_stages_all",
        "n_stages_clean", "stage_timed_count", "stage_span_sec",
    ],
    "sequence": [
        "api_branching", "api_bigram_entropy", "api_top_bigram_share",
        "api_compress_ratio", "cat_switch_rate",
        "fs_to_crypto", "crypto_to_fs", "fs_crypto_interleave",
        "n_crypto_calls", "crypto_buffer_entropy_mean",
    ],
    "relation": [
        "rw_jaccard", "write_not_read", "read_not_write", "rw_size_ratio",
        "chain_read_only", "chain_write_only", "chain_read_write",
        "chain_top_shape_share", "ext_top_share",
        "sel_rate_document", "sel_rate_media", "sel_rate_executable",
        "sel_rate_spread", "sel_system_touch_share", "sel_system_spared",
        "stage_ground_clearing", "stage_has_enumerate", "stage_has_wallpaper",
        "stage_has_persistence",
        "n_shadow_delete", "n_recovery_disable", "n_service_stop",
        "n_process_kill", "n_log_clear", "n_prep_categories",
    ],
    "destruction": [
        "chain_read_destroy", "chain_write_destroy", "chain_full",
        "read_then_destroy", "write_then_destroy",
        "sel_destroyed_doc_share", "sel_destroyed_exe_share",
        "sel_doc_minus_exe", "n_move", "n_delete",
        "move_to_write_ratio", "delete_to_write_ratio",
    ],
}

CUMULATIVE = [
    ("static", ["static"]),
    ("+ volume", ["static", "volume"]),
    ("+ sequence", ["static", "volume", "sequence"]),
    ("+ relation", ["static", "volume", "sequence", "relation"]),
    ("+ destruction", ["static", "volume", "sequence", "relation", "destruction"]),
]

# Also run each group on its own, which shows what it carries unaided.
ALONE = ["static", "volume", "sequence", "relation", "destruction"]


def to_float(v):
    if v is None or v == "":
        return float("nan")
    try:
        return float(v)
    except (TypeError, ValueError):
        return float("nan")


def auc_score(y_true, scores):
    pairs = sorted(zip(scores, y_true))
    n_pos = sum(y_true)
    n_neg = len(y_true) - n_pos
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    ranks, i = {}, 0
    while i < len(pairs):
        j = i
        while j + 1 < len(pairs) and pairs[j + 1][0] == pairs[i][0]:
            j += 1
        r = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[k] = r
        i = j + 1
    rp = sum(ranks[i] for i, (_s, y) in enumerate(pairs) if y == 1)
    return (rp - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", required=True)
    parser.add_argument("--min-family", type=int, default=20,
                         help="A family needs this many encrypting runs to be "
                              "its own fold")
    parser.add_argument("--min-calls", type=int, default=500)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--executed-only", action="store_true",
                         help="Drop rows the sandbox never saw run. Four fifths "
                              "of the benign set is inert, and a model given it "
                              "reaches a perfect score by learning to tell a "
                              "program that ran from one that did not. This "
                              "restricts both classes to runs with recorded "
                              "behaviour, which is a far harder and far more "
                              "meaningful comparison.")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", default="/tmp/ablation.csv")
    args = parser.parse_args()

    import numpy as np
    from xgboost import XGBClassifier

    rows = []
    with open(args.data, newline="") as f:
        for r in csv.DictReader(f):
            rows.append(r)
    print(f"{len(rows)} rows")
    if args.executed_only:
        before = len(rows)
        rows = [r for r in rows if r.get("coverage") == "full"]
        print(f"executed only: kept {len(rows)} of {before}")

    all_cols = list(rows[0].keys())
    grouped = {c for cols in GROUPS.values() for c in cols}
    known = grouped | CIRCULAR | NON_FEATURES
    unassigned = [c for c in all_cols if c not in known]
    if unassigned:
        print(f"[note] {len(unassigned)} columns are in no group and are unused:")
        print("       " + ", ".join(unassigned[:18])
              + (" ..." if len(unassigned) > 18 else ""))

    present = {g: [c for c in cols if c in all_cols] for g, cols in GROUPS.items()}
    print()
    for g, cols in present.items():
        print(f"   {g:<12}{len(cols):>3} features")

    y = np.array([int(r["y"]) for r in rows])
    source = [r["source"] for r in rows]
    family = [r["family_group"] or "(unknown)" for r in rows]
    calls = np.array([to_float(r.get("n_calls") or r.get("total_calls"))
                      for r in rows])
    # coverage is set during extraction from whether the sandbox saw the
    # sample run, and is present on every row, so it is the reliable way to
    # ask that question even when a call count is missing.
    executed = np.array([r.get("coverage") == "full" for r in rows])

    # Folds. Each family with enough members is held out in turn; the
    # negatives carry no family, so each is assigned to one fold at random and
    # tested exactly once. The hard negatives sit in the test set of every
    # fold, since there are too few to divide and they are never trained on.
    pos_fams = Counter(family[i] for i in range(len(rows))
                       if y[i] == 1 and family[i] != "(unknown)")
    fold_families = sorted(f for f, n in pos_fams.items() if n >= args.min_family)
    if not fold_families:
        print("[!] no family has enough members for a fold"); return
    print(f"\n{len(fold_families)} folds: " + ", ".join(fold_families))

    rng = np.random.default_rng(args.seed)
    benign_idx = [i for i in range(len(rows)) if source[i] == "benign"]
    hard_idx = [i for i in range(len(rows)) if source[i] == "hardneg"]
    benign_fold = {i: int(k) for i, k in
                   zip(benign_idx, rng.integers(0, len(fold_families), len(benign_idx)))}
    print(f"negatives: benign {len(benign_idx)} split across folds, "
          f"hard negatives {len(hard_idx)} held out of training entirely")

    def evaluate(feature_cols, tag):
        X = np.array([[to_float(r.get(c)) for c in feature_cols] for r in rows])
        per_fold = []
        hard_flagged = np.zeros(len(hard_idx))

        for k, fam in enumerate(fold_families):
            test_pos = [i for i in range(len(rows))
                        if y[i] == 1 and family[i] == fam]
            test_neg = [i for i in benign_idx if benign_fold[i] == k]
            test = test_pos + test_neg
            train = [i for i in range(len(rows))
                     if i not in set(test) and i not in set(hard_idx)
                     and not (y[i] == 1 and family[i] == fam)]
            if not test_pos or len(test_neg) < 5:
                continue

            model = XGBClassifier(
                n_estimators=300, max_depth=5, learning_rate=0.08,
                subsample=0.9, colsample_bytree=0.9,
                eval_metric="logloss", n_jobs=4,
                random_state=args.seed,
                scale_pos_weight=max(1.0, (y[train] == 0).sum() / max(1, (y[train] == 1).sum())),
            )
            model.fit(X[train], y[train])

            p_test = model.predict_proba(X[test])[:, 1]
            a = auc_score(list(y[test]), list(p_test))

            pt = model.predict_proba(X[test_pos])[:, 1]
            pn = model.predict_proba(X[test_neg])[:, 1]
            ph = model.predict_proba(X[hard_idx])[:, 1] if hard_idx else np.array([])

            ran = [i for i in test_neg if executed[i]]
            pr = model.predict_proba(X[ran])[:, 1] if ran else np.array([])

            hard_flagged += (ph >= args.threshold).astype(float)
            per_fold.append({
                "family": fam, "n_pos": len(test_pos), "auc": a,
                "tpr": float((pt >= args.threshold).mean()),
                "fpr_benign": float((pn >= args.threshold).mean()),
                "fpr_benign_ran": float((pr >= args.threshold).mean()) if len(pr) else float("nan"),
                "fpr_hard": float((ph >= args.threshold).mean()) if len(ph) else float("nan"),
            })

        def avg(key):
            vals = [f[key] for f in per_fold if not math.isnan(f[key])]
            return sum(vals) / len(vals) if vals else float("nan")

        return {
            "group": tag, "n_features": len(feature_cols),
            "auc": avg("auc"), "tpr": avg("tpr"),
            "fpr_benign": avg("fpr_benign"),
            "fpr_benign_ran": avg("fpr_benign_ran"),
            "fpr_hard": avg("fpr_hard"),
            "folds": per_fold,
            "hard_always": int((hard_flagged == len(per_fold)).sum()),
        }

    results = []
    print(f"\n{'':<16}{'feat':>5}{'AUC':>8}{'TPR':>8}"
          f"{'FP benign':>11}{'FP ran':>9}{'FP hard':>9}")
    print("-" * 66)

    for tag, groups in CUMULATIVE:
        cols = [c for g in groups for c in present[g]]
        if not cols:
            continue
        r = evaluate(cols, tag)
        results.append(r)
        print(f"{tag:<16}{r['n_features']:>5}{r['auc']:>8.3f}{r['tpr']:>8.3f}"
              f"{r['fpr_benign']:>11.3f}{r['fpr_benign_ran']:>9.3f}"
              f"{r['fpr_hard']:>9.3f}")

    print()
    for g in ALONE:
        cols = present[g]
        if not cols:
            continue
        r = evaluate(cols, f"{g} alone")
        results.append(r)
        print(f"{g + ' alone':<16}{r['n_features']:>5}{r['auc']:>8.3f}{r['tpr']:>8.3f}"
              f"{r['fpr_benign']:>11.3f}{r['fpr_benign_ran']:>9.3f}"
              f"{r['fpr_hard']:>9.3f}")

    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["group", "n_features", "auc", "tpr",
                    "fpr_benign", "fpr_benign_ran", "fpr_hard"])
        for r in results:
            w.writerow([r["group"], r["n_features"], f"{r['auc']:.4f}",
                        f"{r['tpr']:.4f}", f"{r['fpr_benign']:.4f}",
                        f"{r['fpr_benign_ran']:.4f}", f"{r['fpr_hard']:.4f}"])
    print(f"\n[saved] {args.out}")

    full = results[len(CUMULATIVE) - 1]
    print(f"\nper-family, using all groups:")
    print(f"   {'family':<18}{'n':>5}{'AUC':>8}{'TPR':>8}")
    for f_ in sorted(full["folds"], key=lambda x: x["auc"]):
        print(f"   {f_['family']:<18}{f_['n_pos']:>5}{f_['auc']:>8.3f}{f_['tpr']:>8.3f}")

    print(f"\n{full['hard_always']} of {len(hard_idx)} hard negatives were flagged "
          f"in every fold")
    print("\nThe benign column is the number that looks best and means least:")
    print("most of that set never executed. The hard negative column is the")
    print("one to quote -- those programs were as busy as the ransomware and")
    print("the model never saw them during training.")


if __name__ == "__main__":
    main()
