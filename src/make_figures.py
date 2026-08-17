#!/usr/bin/env python3
"""
make_figures.py - The four figures, drawn from the CSVs the experiments left.

Each one exists to carry a claim that is hard to make in a sentence:

  1  ablation      the AUC and the false positive rate rise together. One
                   line going up while the other goes up is the whole
                   argument, and a table makes the reader do the work of
                   noticing.

  2  breakdown     "forty-four of sixty-eight" is not a false positive rate.
                   Four bars, split by whether flagging was correct, shows
                   what the single number was hiding.

  3  per family    leave-one-family-out with every ransomware run as a
                   positive. Most families are near 1.0; two are at 0.09.
                   Sorted, that is a cliff, and the cliff is the point.

  4  three splits  each feature placed by how well it separates ransomware
                   from inert benign software against how well it separates
                   ransomware from software that is busy. Everything far
                   below the diagonal was measuring activity.

Usage
-----
  python3 make_figures.py --ablation /tmp/abl_enc.csv \\
      --hard-scores /tmp/hn_scores.csv --hard-map ~/hardneg_map.csv \\
      --relational /tmp/rel_all.csv --results /tmp/res_all_v2.csv \\
      --outdir ../results/figures
"""

import os
import csv
import argparse

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Print, not screen. Greys carry the structure so the figures survive being
# photocopied, and the one colour is reserved for the thing being argued.
INK = "#1a1a1a"
MID = "#8a8a8a"
LIGHT = "#d4d4d4"
ACCENT = "#b03030"
ACCENT2 = "#2f5d8a"

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 9,
    "axes.edgecolor": MID,
    "axes.linewidth": 0.8,
    "axes.labelcolor": INK,
    "text.color": INK,
    "xtick.color": INK,
    "ytick.color": INK,
    "xtick.direction": "out",
    "ytick.direction": "out",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "figure.dpi": 150,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
})


def read(path):
    with open(os.path.expanduser(path), newline="") as f:
        return list(csv.DictReader(f))


def fig_ablation(ablation_path, outdir):
    rows = [r for r in read(ablation_path) if not r["group"].endswith("alone")]
    if not rows:
        return None
    labels = [r["group"] for r in rows]
    auc = [float(r["auc"]) for r in rows]
    fp = [float(r["fpr_hard"]) for r in rows]
    x = range(len(rows))

    fig, ax = plt.subplots(figsize=(6.2, 3.4))
    ax.plot(x, auc, "-o", color=ACCENT2, lw=1.6, ms=5, label="AUC")
    lo = min(auc)
    ax.set_ylim(min(0.94, lo - 0.01), 1.005)
    ax.set_ylabel("AUC, 21-fold leave-one-family-out", color=ACCENT2)
    ax.tick_params(axis="y", labelcolor=ACCENT2)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=15, ha="right")

    ax2 = ax.twinx()
    ax2.spines["top"].set_visible(False)
    ax2.plot(x, fp, "-s", color=ACCENT, lw=1.6, ms=5,
             label="false positives on hard negatives")
    ax2.set_ylim(0, 1.0)
    ax2.set_ylabel("false positive rate, hard negatives", color=ACCENT)
    ax2.tick_params(axis="y", labelcolor=ACCENT)

    # Whichever step moves the two lines furthest apart is the finding, and
    # it is not always the same step: with a larger hard negative set the
    # rise in false positives arrives with volume, while the AUC saturates
    # there too. Locating it from the data rather than naming it in advance
    # keeps the figure honest when the numbers change.
    jump = max(range(1, len(rows)), key=lambda i: fp[i] - fp[i - 1])
    ax2.annotate(f"{labels[jump]} takes the score to {auc[jump]:.3f}\n"
                 f"and the false positive rate to {fp[jump]:.2f}",
                 xy=(jump, fp[jump]),
                 xytext=(jump + 0.1, max(0.08, fp[jump] - 0.28)),
                 fontsize=7.5, color=INK,
                 arrowprops=dict(arrowstyle="-", color=MID, lw=0.7))

    # The title follows the data. With a benign set that mostly does not
    # run, the false positive rate climbs alongside the AUC and the point is
    # that they move together. With a hard negative set large enough to
    # matter, the AUC saturates while the false positive rate barely shifts,
    # and the point becomes that ninety features bought almost nothing --
    # which is the same finding seen from the other side.
    span = max(fp) - min(fp)
    gain = max(auc) - min(auc)
    if fp[-1] > fp[0] + 0.05:
        title = "Accuracy and false positives rise in the same step"
    elif span < 0.2:
        title = (f"The score goes from {min(auc):.3f} to {max(auc):.3f}; "
                 f"the false positive\nrate moves {abs(fp[-1] - fp[0]):.3f}")
    else:
        title = "What each group of features changes"
    ax.set_title(title, loc="left", fontsize=10, pad=10)
    out = os.path.join(outdir, "fig1_ablation.png")
    fig.savefig(out)
    plt.close(fig)
    return out


INTENT_ORDER = ["harmless", "ambiguous", "invisible", "destroys"]
INTENT_LABEL = {
    "harmless": "touched nothing\nthat existed",
    "ambiguous": "same trail,\ndifferent reason",
    "invisible": "destroyed but\nunrecorded",
    "destroys": "the files\nare gone",
}
# Correct behaviour in grey, the genuine failure in the accent colour.
INTENT_COLOUR = {
    "harmless": ACCENT, "ambiguous": MID,
    "invisible": ACCENT, "destroys": MID,
}


def fig_breakdown(counts, outdir):
    """counts: {category: (flagged, total)}"""
    cats = [c for c in INTENT_ORDER if c in counts]
    if not cats:
        return None
    flagged = [counts[c][0] for c in cats]
    total = [counts[c][1] for c in cats]

    fig, ax = plt.subplots(figsize=(6.4, 3.2))
    y = range(len(cats))
    ax.barh(list(y), total, color=LIGHT, height=0.58)
    ax.barh(list(y), flagged, color=[INTENT_COLOUR[c] for c in cats], height=0.58)
    ax.set_yticks(list(y))
    ax.set_yticklabels([INTENT_LABEL[c] for c in cats], fontsize=8)
    ax.invert_yaxis()
    ax.set_xlabel("hard negatives")
    ax.set_xlim(0, max(total) * 1.32)
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="y", length=0)

    # Counts sit past the end of the full bar, so they never land on top of
    # a filled segment whatever the proportion happens to be.
    for i, c in enumerate(cats):
        f, t = counts[c]
        ax.text(t + max(total) * 0.03, i, f"{f} of {t}",
                va="center", fontsize=8, color=INK)

    from matplotlib.patches import Patch
    ax.legend(handles=[
        Patch(facecolor=ACCENT, label="flagged, and the detector was wrong"),
        Patch(facecolor=MID, label="flagged, and it was not"),
        Patch(facecolor=LIGHT, label="not flagged"),
    ], frameon=False, fontsize=7.5, loc="lower right",
        bbox_to_anchor=(1.0, -0.42), ncol=1)
    ax.set_title("What the flagged programs had actually done",
                 loc="left", fontsize=10, pad=10)
    out = os.path.join(outdir, "fig2_breakdown.png")
    fig.savefig(out)
    plt.close(fig)
    return out


def fig_families(rows, outdir, show=14):
    """rows: list of (family, n, auc, tpr, ran_frac or None)"""
    if not rows:
        return None
    rows = sorted(rows, key=lambda r: r[3])
    hidden = max(0, len(rows) - show)
    rest_min = rows[show][3] if hidden else None
    # Thirty-eight bars in one column crushes the labels into each other and
    # the top two thirds are all near 1.0 anyway. The tail is the finding.
    rows = rows[:show]
    names = [r[0] for r in rows]
    tpr = [r[3] for r in rows]
    ran = [r[4] if len(r) > 4 else None for r in rows]
    colours = [ACCENT if t < 0.5 else MID for t in tpr]

    fig, ax = plt.subplots(figsize=(6.2, 3.8))
    y = range(len(rows))
    ax.barh(list(y), tpr, color=colours, height=0.62)
    ax.set_yticks(list(y))
    ax.set_yticklabels([f"{n}  ({r[1]})" for n, r in zip(names, rows)], fontsize=7.5)
    ax.set_xlabel("true positive rate on the held-out family")
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="y", length=0)
    # The rate on its own invites the wrong reading. A family whose samples
    # mostly never ran has no behaviour to recognise, and the low score is
    # the label definition showing through rather than the model failing, so
    # the proportion that executed goes on the same line as the score.
    for i, (t, frac) in enumerate(zip(tpr, ran)):
        label = f"{t:.2f}"
        if frac is not None:
            label += f"    {frac:.0%} ran"
        ax.text(t + 0.015, i, label, va="center", fontsize=7,
                color=INK if frac is None or frac > 0.3 else ACCENT)
    ax.set_xlim(0, 1.28)
    if hidden:
        ax.text(0.99, -0.20,
                f"the remaining {hidden} families are all at {rest_min:.2f} or above",
                transform=ax.transAxes, ha="right", fontsize=7.5, color=MID)
    ax.set_title("Held out one family at a time, with every ransomware run\n"
                 "counted as a positive whether or not it did anything",
                 loc="left", fontsize=10, pad=10)
    out = os.path.join(outdir, "fig3_families.png")
    fig.savefig(out)
    plt.close(fig)
    return out


def fig_three_splits(points, outdir):
    """points: list of (feature, auc_vs_benign, auc_vs_hard, bounded)"""
    if not points:
        return None
    fig, ax = plt.subplots(figsize=(5.4, 5.0))
    ax.plot([0.3, 1.0], [0.3, 1.0], "-", color=LIGHT, lw=1, zorder=0)

    for name, a_b, a_h, bounded in points:
        gap = a_b - a_h
        colour = ACCENT if gap > 0.15 else MID
        ax.scatter(a_b, a_h, s=22, facecolor="none" if bounded else colour,
                   edgecolor=colour, linewidth=1.0, zorder=3)

    # Only the extremes get labels; a scatter with forty-six names on it is
    # a wall of text, and the ones that matter are the outliers.
    # Three groups get named: the features that fall furthest below the
    # diagonal (they were measuring activity), the ones that hold up on both
    # (they describe behaviour), and the ones that do better against the
    # harder negative than the easier one, which is the surprising corner.
    worst = sorted(points, key=lambda p: -(p[1] - p[2]))[:4]
    best = sorted(points, key=lambda p: -min(p[1], p[2]))[:3]
    above = sorted([p for p in points if p[2] > p[1]],
                   key=lambda p: -(p[2] - p[1]))[:3]
    best = best + [p for p in above if p not in best]
    # Nudge each label off the last one placed nearby, so that features with
    # near-identical scores stay legible instead of printing on top of
    # each other.
    placed = []
    for name, a_b, a_h, _ in worst + best:
        dy = -3
        while any(abs(a_b - px) < 0.09 and abs(a_h + dy / 250 - py) < 0.024
                  for px, py in placed):
            dy -= 12
        ax.annotate(name, (a_b, a_h), textcoords="offset points",
                    xytext=(6, dy), fontsize=6.8, color=INK)
        placed.append((a_b, a_h + dy / 250))

    ax.set_xlabel("separates ransomware from inert benign software")
    ax.set_ylabel("separates ransomware from busy legitimate software")
    ax.set_xlim(0.45, 1.10)
    ax.set_ylim(0.45, 1.02)
    ax.text(0.52, 0.98, "on the line: the feature describes behaviour\n"
                        "below it: the feature was measuring activity",
            fontsize=7.5, color=MID, va="top")
    ax.text(0.99, -0.13, "hollow: bounded by construction",
            transform=ax.transAxes, ha="right", fontsize=7, color=MID)
    ax.set_title("The same feature, measured against two kinds of negative",
                 loc="left", fontsize=10, pad=10)
    out = os.path.join(outdir, "fig4_three_splits.png")
    fig.savefig(out)
    plt.close(fig)
    return out


def fig_threshold(bands, ransomware_median, outdir):
    """
    bands: list of (label, lower, upper, n, flagged)

    Where the detector starts calling legitimate software ransomware.

    The single false positive rate over a set of hard negatives is a
    property of how that set was assembled. Half of ours are Sysinternals
    tools run without arguments, which print their usage and exit; adding
    more of those drives the figure towards zero while the model does
    nothing differently. Split by how many distinct files each program
    opened, the number stops describing the sample and starts describing the
    detector.

    It also does what no single figure can, which is locate the boundary.
    """
    if not bands:
        return None
    labels = [b[0] for b in bands]
    ns = [b[3] for b in bands]
    rates = [b[4] / b[3] if b[3] else 0 for b in bands]

    fig, ax = plt.subplots(figsize=(6.2, 3.6))
    x = range(len(bands))
    colours = [ACCENT if r >= 0.5 else MID for r in rates]
    ax.bar(list(x), rates, color=colours, width=0.6)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("classified as ransomware")
    ax.set_xlabel("distinct files the program opened")

    # The count goes inside the bar where there is room and just above the
    # axis where there is not, so it never lands on the tick label.
    for i, (r, n) in enumerate(zip(rates, ns)):
        ax.text(i, r + 0.03, f"{r:.2f}", ha="center", fontsize=8.5, color=INK)
        if r > 0.18:
            ax.text(i, r / 2, f"n={n}", ha="center", va="center",
                    fontsize=8, color="white")
        else:
            ax.text(i, r + 0.10, f"n={n}", ha="center", fontsize=8, color=MID)

    # Where the ransomware sits, so the reader can see that the line falls a
    # long way short of it.
    ax.text(0.99, 0.93,
            f"ransomware median: {ransomware_median} files",
            transform=ax.transAxes, ha="right", fontsize=8, color=MID)
    ax.set_title("Legitimate software crosses the line at a few dozen files",
                 loc="left", fontsize=10, pad=10)
    out = os.path.join(outdir, "fig5_threshold.png")
    fig.savefig(out)
    plt.close(fig)
    return out


# ---------- data assembly ----------

def load_breakdown(scores_path, map_path):
    try:
        from classify_failures import INTENT
    except ImportError:
        print("[!] classify_failures.py must be importable for figure 2")
        return {}
    variant = {"H" + r["task_id"]: r["variant"].replace(".exe", "")
               for r in read(map_path)}
    counts = {}
    for r in read(scores_path):
        name = variant.get(r["sample_id"], "?")
        cat = INTENT.get(name, ("unclassified", ""))[0]
        if cat == "unclassified":
            continue
        f, t = counts.get(cat, (0, 0))
        counts[cat] = (f + (1 if float(r["flag_rate"]) >= 0.5 else 0), t + 1)
    return counts


def load_bands(scores_path, modelling_path, threshold=0.5):
    """Group the hard negatives by how many distinct paths each one opened."""
    rate = {}
    for r in read(scores_path):
        try:
            rate[r["sample_id"]] = float(r["flag_rate"])
        except (KeyError, ValueError):
            continue
    rows = [r for r in read(modelling_path) if r.get("source") == "hardneg"]

    edges = [(0, 10, "under 10"), (10, 50, "10-49"),
             (50, 200, "50-199"), (200, 10 ** 9, "200+")]
    out = []
    for lo, hi, label in edges:
        sel = []
        for r in rows:
            try:
                v = float(r.get("n_paths") or 0)
            except ValueError:
                v = 0.0
            if lo <= v < hi and r["sample_id"] in rate:
                sel.append(r["sample_id"])
        if sel:
            hits = sum(1 for s in sel if rate[s] >= threshold)
            out.append((label, lo, hi, len(sel), hits))

    pos = [r for r in read(modelling_path) if r.get("y") == "1"]
    vals = sorted(float(r["n_paths"]) for r in pos
                  if (r.get("n_paths") or "").strip()
                  and r["n_paths"].replace(".", "", 1).isdigit())
    median = int(vals[len(vals) // 2]) if vals else 0
    return out, median


def load_three_splits(relational_path, results_path):
    from compare_sources import source_of, num, auc, BOUNDED
    meta = {str(r.get("task_id", "")).strip(): r for r in read(results_path)}
    rows = []
    for r in read(relational_path):
        r["_src"] = source_of(r["task_id"])
        rows.append(r)
    ran = [r for r in rows if r["_src"] == "ransomware"]
    ben = [r for r in rows if r["_src"] == "benign"]
    hard = [r for r in rows if r["_src"] == "hardneg"]
    features = [c for c in rows[0] if not c.startswith("_") and c != "task_id"]

    points = []
    for c in features:
        pos = [num(r, c) for r in ran]
        a_b, _ = auc(pos, [num(r, c) for r in ben])
        a_h, _ = auc(pos, [num(r, c) for r in hard])
        if a_b is None or a_h is None:
            continue
        # A feature that runs the other way is just as informative; fold it
        # so the axes read as "how well does it separate", not "which way".
        points.append((c, max(a_b, 1 - a_b), max(a_h, 1 - a_h), c in BOUNDED))
    return points


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ablation")
    parser.add_argument("--hard-scores")
    parser.add_argument("--hard-map")
    parser.add_argument("--families", help="CSV with family,n,auc,tpr")
    parser.add_argument("--relational")
    parser.add_argument("--results")
    parser.add_argument("--modelling",
                         help="modelling.csv, for the file-count bands")
    parser.add_argument("--outdir", default="../results/figures")
    args = parser.parse_args()

    os.makedirs(os.path.expanduser(args.outdir), exist_ok=True)
    outdir = os.path.expanduser(args.outdir)
    made = []

    if args.ablation:
        p = fig_ablation(args.ablation, outdir)
        if p: made.append(p)

    if args.hard_scores and args.hard_map:
        counts = load_breakdown(args.hard_scores, args.hard_map)
        if counts:
            p = fig_breakdown(counts, outdir)
            if p: made.append(p)

    if args.families:
        rows = []
        for r in read(args.families):
            frac = float(r["ran"]) if r.get("ran") not in (None, "") else None
            rows.append((r["family"], int(r["n"]), float(r["auc"]),
                         float(r["tpr"]), frac))
        p = fig_families(rows, outdir)
        if p: made.append(p)

    if args.hard_scores and args.modelling:
        bands, median = load_bands(args.hard_scores, args.modelling)
        p = fig_threshold(bands, median, outdir)
        if p: made.append(p)

    if args.relational and args.results:
        points = load_three_splits(args.relational, args.results)
        p = fig_three_splits(points, outdir)
        if p: made.append(p)

    for p in made:
        print(f"[saved] {p}")
    if not made:
        print("nothing to draw; pass at least one input")


if __name__ == "__main__":
    main()
