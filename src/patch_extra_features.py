#!/usr/bin/env python3
"""
patch_extra_features.py - Wire relational_extra.py into the pipeline.

Two edits, each backed up first:

  explore_relational.py   process_one() gains one line that merges the
                          extra features into the row. Nothing else changes,
                          so every existing column is computed exactly as
                          before.

  train_model.py          the GROUPS dict gains the new columns, each in the
                          group relational_extra.EXTRA_GROUPS assigns it to.
                          The diagnostic column pf_byte_paired_share is left
                          out of every group on purpose.

Run from the src directory:

    python3 patch_extra_features.py
    python3 patch_extra_features.py --revert     # restore the .bak files

The extractor then has to be rerun over every archive, since the new
columns are computed at extraction time. That is the expensive part; the
patch itself is instant.
"""

import os
import re
import sys
import shutil
import argparse

HERE = os.path.dirname(os.path.abspath(__file__))
EXPLORE = os.path.join(HERE, "explore_relational.py")
TRAIN = os.path.join(HERE, "train_model.py")

sys.path.insert(0, HERE)
from relational_extra import EXTRA_GROUPS  # noqa: E402


def patch_explore():
    s = open(EXPLORE).read()
    if "relational_extra" in s:
        print("explore_relational.py already patched")
        return
    shutil.copy(EXPLORE, EXPLORE + ".bak")

    # import, placed after the last top-level import
    imports = list(re.finditer(r"^(import|from) .+$", s, flags=re.M))
    at = imports[-1].end()
    s = s[:at] + "\nfrom relational_extra import extra_features" + s[at:]

    # the merge, placed after rhythm_features in process_one
    anchor = "    row.update(rhythm_features(behavior))\n"
    assert anchor in s, "process_one anchor not found"
    s = s.replace(anchor,
                  anchor +
                  "    # Per-file byte ratios, process-tree shape, and where in the\n"
                  "    # run the writing fell. Kept in a separate module so the three\n"
                  "    # families can be reviewed and dropped as a unit.\n"
                  "    row.update(extra_features(report))\n", 1)
    open(EXPLORE, "w").write(s)
    print("explore_relational.py patched (backup: .bak)")


def patch_train():
    s = open(TRAIN).read()
    if "pf_ratio_median" in s:
        print("train_model.py already patched")
        return
    shutil.copy(TRAIN, TRAIN + ".bak")

    for group, cols in EXTRA_GROUPS.items():
        if group.startswith("_"):
            continue
        # Find the closing bracket of this group's list and insert before it.
        m = re.search(rf'^    "{group}": \[', s, flags=re.M)
        assert m, f"group {group} not found in GROUPS"
        # walk to the matching close bracket
        i = m.end()
        depth = 1
        while depth and i < len(s):
            if s[i] == "[":
                depth += 1
            elif s[i] == "]":
                depth -= 1
            i += 1
        close = i - 1
        insert = ("        # from relational_extra.py\n        " +
                  ", ".join(f'"{c}"' for c in cols) + ",\n")
        s = s[:close] + insert + s[close:]
    open(TRAIN, "w").write(s)
    print("train_model.py patched (backup: .bak)")
    for group, cols in EXTRA_GROUPS.items():
        if not group.startswith("_"):
            print(f"   {group:<10} +{len(cols)}")


def revert():
    for p in (EXPLORE, TRAIN):
        if os.path.exists(p + ".bak"):
            shutil.move(p + ".bak", p)
            print(f"restored {os.path.basename(p)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--revert", action="store_true")
    a = ap.parse_args()
    if a.revert:
        revert()
        return
    patch_explore()
    patch_train()
    import ast
    for p in (EXPLORE, TRAIN):
        ast.parse(open(p).read())
    print("both files parse")


if __name__ == "__main__":
    main()
