#!/usr/bin/env python3
"""
screenshot_diff.py - Measure how much the guest desktop changed during each
analysis, and cross-check that against the behavioural verdict.

Why
---
The behavioural verdict comes from the same event log the detection features
come from, so validating it against that log is circular. Screenshots are
independent evidence: pixels, not API traces.

They have already caught a real error. AvosLocker samples encrypted the decoy
files, the screenshots showed it plainly, and the verdict said
WEAK_VICTIM_ACTIVITY -- because the verdict counted destructive events and
AvosLocker overwrites in place, one event per file instead of three. Nothing
inside the event data hinted at the mistake.

Reviewing screenshots by hand does not scale, but it does not have to. What
matters is finding the analyses where the two kinds of evidence disagree.

How the measurement works, and why it is built this way
------------------------------------------------------
Every design choice below was forced by measurements on real CAPE
screenshots. The obvious implementations do not work:

**Colour, not greyscale.** Encryption turns coloured file icons into blank
white document icons. In greyscale a green Excel icon and a white page have
similar luminance, so converting to greyscale destroyed almost the entire
signal: a fully encrypted desktop measured 2.0% changed, *less* than an
analysis where a tooltip had merely popped up. Comparing RGB channels
recovers it.

**Grid cells, not a whole-screen pixel fraction.** The wallpaper is most of
the screen and never changes, which dilutes everything. Measured across the
full frame, full encryption came out at only 3% of pixels -- indistinguishable
from noise. Counting how many cells of a 16x12 grid changed instead measures
*how widely* the screen changed, which is the real difference: encryption
alters every icon across the whole desktop, while UI noise alters one
contiguous blob.

**Masking the taskbar and the notification corner.** The taskbar clock ticks
over in every analysis. Windows also raises toast notifications in the
bottom-right corner, unprompted, and one of those alone moved the reading by
26 grid cells -- comparable to encryption itself. With both regions masked,
two analyses in the same encrypted end state measured 16.7% and 17.9%
regardless of whether a notification happened to appear, which is the
consistency the metric needs.

Observed signal levels on confirmed-encrypting runs:

    ransom note dropped, icons not yet rewritten   8.3% of cells
    all icons blank, .skynet appended to names    16.7% - 17.9% of cells

The threshold below is provisional. Setting it properly needs readings from
analyses where nothing happened, which means running this over a batch that
includes NO_VICTIM_ACTIVITY cases and looking at where the two groups fall.
Until then, treat the numbers as the output and the verdict as a suggestion.

Reading the output
------------------
    behaviour says encrypted  +  screen changed    -> agree, no review
    behaviour says nothing    +  screen unchanged   -> agree, no review
    behaviour says nothing    +  screen changed     -> possible false negative
    behaviour says encrypted  +  screen unchanged   -> possible false positive

Only the last two need human eyes.

A caveat: screenshots show the desktop, not Documents or Downloads, and
in-place overwriting leaves filenames unchanged. Visible change is strong
evidence something happened; its absence is weak evidence that nothing did.
This is a false-negative detector, not a labelling tool.

Usage
-----
  python3 screenshot_diff.py --analyses-dir /opt/CAPEv2/storage/analyses \\
      --results analysis_results.csv --out visual.csv \\
      --save-flagged ~/flagged_screenshots

  # Show the distribution, to calibrate the threshold
  python3 screenshot_diff.py --analyses-dir /opt/CAPEv2/storage/analyses \\
      --results analysis_results.csv --out visual.csv --calibrate

Requires Pillow:  pip install pillow
"""

import os
import sys
import csv
import shutil
import argparse
from pathlib import Path
from collections import defaultdict

# A pixel counts as changed when any RGB channel differs by more than this.
PIXEL_TOLERANCE = 40

# Grid used to measure how widely the screen changed.
GRID_X, GRID_Y = 16, 12

# A grid cell counts as changed when this fraction of its pixels changed.
CELL_CHANGE_FRACTION = 0.08

# Rows of the taskbar to ignore, in pixels from the bottom. Removes the clock.
TASKBAR_HEIGHT = 48

# Bottom-right region where Windows raises toast notifications, as fractions
# of width and height. Ignored because an unprompted notification shifted the
# reading as much as encryption did.
TOAST_X_FROM, TOAST_Y_FROM = 0.60, 0.66

# Provisional: see the module docstring. Confirmed encrypting runs measured
# 8.3% (partial) and 16.7-17.9% (complete), so this sits below the weakest
# observed positive. It has NOT been checked against analyses where nothing
# happened, so the false-positive rate is unknown.
CELL_CHANGE_THRESHOLD = 0.05


def list_shots(analysis_dir):
    """Screenshots in capture order. CAPE names them numerically."""
    shots_dir = Path(analysis_dir) / "shots"
    if not shots_dir.is_dir():
        return []
    shots = [p for p in shots_dir.iterdir()
             if p.suffix.lower() in (".png", ".jpg", ".jpeg", ".bmp")]

    def sort_key(p):
        return (0, int(p.stem)) if p.stem.isdigit() else (1, p.stem)

    return sorted(shots, key=sort_key)


def changed_pixel_mask(first_path, last_path):
    """
    Binary mask of changed pixels, built with Pillow's C-level operations
    rather than a Python loop -- a per-pixel loop over 786k pixels for every
    analysis in a batch is too slow to run from cron.
    """
    try:
        from PIL import Image, ImageChops
    except ImportError:
        print("[!] Pillow is required: pip install pillow")
        sys.exit(1)

    try:
        a = Image.open(first_path).convert("RGB")
        b = Image.open(last_path).convert("RGB")
    except Exception:
        return None

    if a.size != b.size:
        b = b.resize(a.size)

    diff = ImageChops.difference(a, b)
    r, g, bl = diff.split()
    # Max across channels: a colour change in any one channel counts.
    max_channel = ImageChops.lighter(ImageChops.lighter(r, g), bl)
    return max_channel.point(lambda v: 255 if v > PIXEL_TOLERANCE else 0), a.size


def cell_is_masked(x0, y0, x1, y1, w, h):
    """True for grid cells covering the taskbar or the notification corner."""
    if y0 >= h - TASKBAR_HEIGHT:
        return True
    if x0 >= int(w * TOAST_X_FROM) and y0 >= int(h * TOAST_Y_FROM):
        return True
    return False


def measure(first_path, last_path):
    """Fraction of usable grid cells that changed, plus supporting numbers."""
    result = changed_pixel_mask(first_path, last_path)
    if result is None:
        return None
    mask, (w, h) = result

    cw, ch = w // GRID_X, h // GRID_Y
    changed_cells = usable_cells = 0
    changed_pixels_total = usable_pixels_total = 0

    for gy in range(GRID_Y):
        for gx in range(GRID_X):
            x0, y0 = gx * cw, gy * ch
            x1, y1 = min(x0 + cw, w), min(y0 + ch, h)
            if cell_is_masked(x0, y0, x1, y1, w, h):
                continue
            usable_cells += 1
            cell = mask.crop((x0, y0, x1, y1))
            # histogram()[255] counts the changed pixels without a Python loop
            changed = cell.histogram()[255]
            area = (x1 - x0) * (y1 - y0)
            changed_pixels_total += changed
            usable_pixels_total += area
            if changed / area > CELL_CHANGE_FRACTION:
                changed_cells += 1

    if not usable_cells:
        return None

    return {
        "cell_change_fraction": changed_cells / usable_cells,
        "cells_changed": changed_cells,
        "cells_usable": usable_cells,
        "pixel_change_fraction": (changed_pixels_total / usable_pixels_total
                                   if usable_pixels_total else 0),
    }


def analyse_one(analysis_dir, threshold):
    shots = list_shots(analysis_dir)
    task = Path(analysis_dir).name
    blank = {
        "task_id": task, "n_shots": len(shots),
        "cells_changed": "", "cells_usable": "",
        "cell_change_fraction": "", "pixel_change_fraction": "",
        "visual_change": "unknown",
        "first_shot": str(shots[0]) if shots else "", "last_shot": "",
    }

    if len(shots) < 2:
        return blank

    m = measure(shots[0], shots[-1])
    if m is None:
        blank["visual_change"] = "unreadable"
        blank["last_shot"] = str(shots[-1])
        return blank

    return {
        "task_id": task,
        "n_shots": len(shots),
        "cells_changed": m["cells_changed"],
        "cells_usable": m["cells_usable"],
        "cell_change_fraction": round(m["cell_change_fraction"], 4),
        "pixel_change_fraction": round(m["pixel_change_fraction"], 4),
        "visual_change": "yes" if m["cell_change_fraction"] >= threshold else "no",
        "first_shot": str(shots[0]),
        "last_shot": str(shots[-1]),
    }


def load_verdicts(results_csv):
    if not results_csv or not os.path.exists(results_csv):
        return {}
    verdicts = {}
    with open(results_csv, newline="") as f:
        for row in csv.DictReader(f):
            tid = str(row.get("task_id", "")).strip()
            if tid:
                verdicts[tid] = {
                    "verdict": row.get("verdict", ""),
                    "destroyed": row.get("destroyed_decoy_files", ""),
                }
    return verdicts


def classify_agreement(verdict, visual_change):
    if not verdict or visual_change in ("unknown", "unreadable"):
        return ""
    claims_encryption = verdict == "TRUE_ENCRYPTION"
    changed = visual_change == "yes"
    if claims_encryption == changed:
        return "agree"
    if changed:
        return "REVIEW: screen changed but verdict says no encryption"
    return "REVIEW: verdict says encryption but screen unchanged"


FIELDNAMES = ["task_id", "n_shots", "cells_changed", "cells_usable",
              "cell_change_fraction", "pixel_change_fraction", "visual_change",
              "verdict", "destroyed_decoy_files", "agreement",
              "first_shot", "last_shot"]


def print_calibration(rows):
    """
    Show where each verdict group falls, which is what a threshold has to
    separate. Without readings from analyses where nothing happened, any
    threshold is guesswork.
    """
    by_verdict = defaultdict(list)
    for r in rows:
        if r["cell_change_fraction"] == "" or not r["verdict"]:
            continue
        by_verdict[r["verdict"]].append(r["cell_change_fraction"])

    if not by_verdict:
        print("\n[calibration] no verdicts available to compare against")
        return

    print("\n[calibration] cell-change fraction by verdict")
    print(f"   {'verdict':<24} {'n':>4} {'min':>8} {'median':>8} {'max':>8}")
    print("   " + "-" * 56)
    for verdict in sorted(by_verdict):
        vals = sorted(by_verdict[verdict])
        median = vals[len(vals) // 2]
        print(f"   {verdict:<24} {len(vals):>4} {vals[0]*100:>7.1f}% "
              f"{median*100:>7.1f}% {vals[-1]*100:>7.1f}%")

    positives = by_verdict.get("TRUE_ENCRYPTION", [])
    negatives = [v for k, vals in by_verdict.items()
                 if k != "TRUE_ENCRYPTION" for v in vals]
    if positives and negatives:
        print(f"\n   highest non-encrypting reading : {max(negatives)*100:.1f}%")
        print(f"   lowest encrypting reading      : {min(positives)*100:.1f}%")
        if max(negatives) < min(positives):
            midpoint = (max(negatives) + min(positives)) / 2
            print(f"   the two groups separate cleanly; a threshold near "
                  f"{midpoint*100:.1f}% would divide them")
        else:
            print("   the groups overlap, so no single threshold separates them --")
            print("   inspect the overlapping analyses before trusting either signal")


def main():
    parser = argparse.ArgumentParser(
        description="Measure desktop change per analysis and cross-check verdicts.")
    parser.add_argument("--analyses-dir", required=True,
                         help="CAPE storage/analyses directory")
    parser.add_argument("--results", default=None,
                         help="analyze_result.py output CSV, to cross-check verdicts")
    parser.add_argument("--out", default="visual.csv", help="CSV output path")
    parser.add_argument("--save-flagged", default=None, metavar="DIR",
                         help="Copy the first and last screenshot of every disagreeing "
                              "analysis here, so they outlive the cleanup stage")
    parser.add_argument("--threshold", type=float, default=CELL_CHANGE_THRESHOLD,
                         help=f"Cell-change fraction above which the desktop counts as "
                              f"changed (default: {CELL_CHANGE_THRESHOLD}, provisional)")
    parser.add_argument("--calibrate", action="store_true",
                         help="Print the distribution of readings per verdict, to choose "
                              "a threshold from data instead of guessing")
    args = parser.parse_args()

    base = Path(args.analyses_dir)
    if not base.is_dir():
        print(f"[!] not a directory: {args.analyses_dir}")
        sys.exit(1)

    verdicts = load_verdicts(args.results)
    dirs = sorted((p for p in base.iterdir() if p.is_dir() and p.name.isdigit()),
                   key=lambda p: int(p.name))
    if not dirs:
        print(f"[!] no analysis directories under {args.analyses_dir}")
        sys.exit(1)

    print(f"Comparing first and last screenshot of {len(dirs)} analyses")
    print(f"(threshold: {args.threshold} of grid cells; taskbar and notification "
          f"corner ignored)\n")

    header = (f"{'task':<7} {'shots':>6} {'cells':>8} {'changed':>9} {'visual':<9} "
              f"{'verdict':<22} {'files':>6} agreement")
    print(header)
    print("-" * (len(header) + 20))

    rows = []
    for d in dirs:
        row = analyse_one(d, args.threshold)
        info = verdicts.get(row["task_id"], {})
        row["verdict"] = info.get("verdict", "")
        row["destroyed_decoy_files"] = info.get("destroyed", "")
        row["agreement"] = classify_agreement(row["verdict"], row["visual_change"])
        rows.append(row)

        frac = row["cell_change_fraction"]
        pct = f"{frac*100:.1f}%" if frac != "" else "-"
        cells = (f"{row['cells_changed']}/{row['cells_usable']}"
                 if row["cells_changed"] != "" else "-")
        mark = row["agreement"] if row["agreement"] != "agree" else ""
        print(f"{row['task_id']:<7} {row['n_shots']:>6} {cells:>8} {pct:>9} "
              f"{row['visual_change']:<9} {row['verdict'][:20]:<22} "
              f"{str(row['destroyed_decoy_files']):>6} {mark}")

    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in FIELDNAMES})
    print(f"\n[saved] {args.out}")

    changed = sum(1 for r in rows if r["visual_change"] == "yes")
    unmeasurable = sum(1 for r in rows if r["visual_change"] in ("unknown", "unreadable"))
    flagged = [r for r in rows if r["agreement"].startswith("REVIEW")]

    print(f"\nvisibly changed : {changed}/{len(rows)}")
    if unmeasurable:
        print(f"not measurable  : {unmeasurable} (fewer than two screenshots, or unreadable)")
    if verdicts:
        print(f"agree with verdict : {sum(1 for r in rows if r['agreement'] == 'agree')}")
        print(f"NEED REVIEW        : {len(flagged)}")
        for r in flagged:
            frac = r["cell_change_fraction"]
            pct = f"{frac*100:.1f}%" if frac != "" else "-"
            print(f"   task {r['task_id']:<6} changed={pct:<7} verdict={r['verdict']}")

    if args.calibrate:
        print_calibration(rows)

    if args.save_flagged and flagged:
        dest = Path(args.save_flagged).expanduser()
        dest.mkdir(parents=True, exist_ok=True)
        n = 0
        for r in flagged:
            for label, path in (("first", r["first_shot"]), ("last", r["last_shot"])):
                if path and os.path.exists(path):
                    shutil.copyfile(path, dest / f"task{r['task_id']}_{label}{Path(path).suffix}")
                    n += 1
        print(f"\n[saved] {n} screenshots from {len(flagged)} flagged analyses -> {dest}")
        print("        These survive cleanup; review them to decide whether the")
        print("        verdict logic needs adjusting.")


if __name__ == "__main__":
    main()
