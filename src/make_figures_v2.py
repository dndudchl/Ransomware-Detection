#!/usr/bin/env python3
"""
make_figures_v2.py - The figures the corrected results need.

Why these and not the earlier four
----------------------------------
The first set was drawn when the false positive rate was 0.794 and would not
move. Three of those figures argued that the detector was measuring activity
rather than encryption, and the fourth showed the rate rising with the number
of files a program opened. Both claims are now false, so the figures cannot
be reused with new numbers -- they carry the wrong argument.

What replaced them:

  1  saturation    the rate falls from 0.794 to 0.010 as active negatives
                   enter training, and flattens at about 1,500. What moves
                   it is how many *kinds* are present, not how many copies,
                   which is the practical prescription the study can offer.

  2  volume shift  train on runs opening under 300 files, measure on runs
                   opening 300 or more. Counts learn a threshold that moves
                   when scale moves; ratios between events do not. This is
                   the strongest evidence for the relational thesis and the
                   figure exists to carry it alone.

  3  by kind       the single false positive rate over the held-out negatives
                   describes how that set was assembled. The constructed
                   variants are flagged at zero under every feature set, so
                   they contribute nothing to any comparison; the signed
                   software other people wrote is the only live measurement,
                   and it is the smallest group. The figure shows the
                   intervals so the reader can see which numbers are thin.

  4  ablation      what each group of features adds, cumulatively. Kept from
                   the earlier set because the claim survived; redrawn
                   because the numbers did not.

Usage
-----
  python3 make_figures_v2.py \\
      --ablation ~/work/abl_final.csv \\
      --shift ~/work/abl_shift.csv \\
      --hard-scores ~/work/hn_final.csv \\
      --names ~/work/hardneg_names.csv \\
      --modelling ~/work/modelling_simple.csv \\
      --outdir ~/work/figures

The saturation points are not in any one CSV -- each is a separate run -- so
they are passed on the command line, or the defaults below are used.
"""

import os
import re
import csv
import math
import argparse

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Print, not screen. Greys carry the structure so the figures survive being
# photocopied, and colour is reserved for the thing being argued.
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

# negatives in training : kinds : false positive rate, one run each
DEFAULT_SATURATION = "0:0:0.794,317:163:0.245,1114:279:0.085,1757:279:0.012"


def read(path):
    with open(os.path.expanduser(path), newline="") as f:
        return list(csv.DictReader(f))


def wilson(hits, n, z=1.96):
    """
    An interval that stays inside nought and one and behaves at the edges.

    Several groups here are at nought, where the normal approximation reports
    plus or minus nothing and hides that a group of two says almost nothing.
    """
    if n == 0:
        return 0.0, 0.0, 0.0
    p = hits / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, centre - half), min(1.0, centre + half)


# ----------------------------------------------------------------- figure 1

def fig_saturation(points, outdir):
    """points: [(negatives, kinds, fp), ...]"""
    if len(points) < 3:
        return None
    points = sorted(points)
    xs = [p[0] for p in points]
    ks = [p[1] for p in points]
    ys = [p[2] for p in points]

    fig, ax = plt.subplots(figsize=(6.2, 3.6))
    ax.plot(xs, ys, "-o", color=ACCENT, lw=1.6, ms=6)
    for x, k, y in points:
        label = f"{y:.3f}" + (f"\n{k} kinds" if k else "\nnone")
        ax.annotate(label, xy=(x, y), xytext=(6, 8),
                    textcoords="offset points", fontsize=7.5, color=INK)

    ax.set_xlabel("active negatives in training")
    ax.set_ylabel("false positives, held-out negatives")
    ax.set_ylim(-0.03, max(ys) * 1.15)
    ax.set_title("The rate is a property of the training set, not the model",
                 loc="left", fontsize=10, pad=10)

    # Where the curve flattens is the practical claim -- beyond it, collecting
    # more buys nothing -- but four points cannot establish it. The marker is
    # drawn only when the split sweep has been passed in as well, since that
    # is the run that measured the flat section.
    flat = [p for p in points if p[2] < 0.03]
    if flat and len(points) >= 5:
        ax.axvline(flat[0][0], color=MID, lw=0.8, ls=":")
        ax.annotate(f"flat beyond ~{flat[0][0]:,}",
                    xy=(flat[0][0], max(ys) * 0.55),
                    xytext=(-8, 0), textcoords="offset points",
                    fontsize=7.5, color=MID, ha="right")

    out = os.path.join(outdir, "fig1_saturation.png")
    fig.savefig(out)
    plt.close(fig)
    return out


# ----------------------------------------------------------------- figure 2

def fig_volume_shift(shift_path, outdir):
    rows = read(shift_path)
    cum = [r for r in rows if not r["group"].endswith("alone")]
    alone = [r for r in rows if r["group"].endswith("alone")]
    if not cum or not alone:
        return None

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.6, 3.4),
                                   gridspec_kw={"width_ratios": [1.25, 1]})

    labels = [r["group"] for r in cum]
    fp = [float(r["fpr_hard"]) for r in cum]
    x = range(len(cum))
    ax1.plot(x, fp, "-o", color=ACCENT, lw=1.6, ms=5)
    ax1.set_xticks(list(x))
    ax1.set_xticklabels(labels, rotation=20, ha="right", fontsize=8)
    ax1.set_ylabel("false positives")
    ax1.set_ylim(0, max(fp) * 1.25)
    ax1.set_title("Adding counts costs; adding relations repays",
                  loc="left", fontsize=9.5, pad=8)

    peak = max(range(len(fp)), key=lambda i: fp[i])
    ax1.annotate(f"{fp[peak]:.3f}", xy=(peak, fp[peak]), xytext=(4, 6),
                 textcoords="offset points", fontsize=8, color=ACCENT)
    # The recovery point is often the last one, where a label placed to the
    # right lands outside the axes and on top of the second panel.
    low = min(range(peak, len(fp)), key=lambda i: fp[i])
    ax1.annotate(f"{fp[low]:.3f}", xy=(low, fp[low]), xytext=(-4, 10),
                 textcoords="offset points", fontsize=8, color=INK,
                 ha="right")

    order = ["volume alone", "sequence alone", "relation alone",
             "static alone", "destruction alone", "indicator alone"]
    have = {r["group"]: float(r["fpr_hard"]) for r in alone}
    names = [g for g in order if g in have]
    vals = [have[g] for g in names]
    colours = [ACCENT if g == "volume alone"
               else ACCENT2 if g == "relation alone" else LIGHT
               for g in names]
    y = range(len(names))
    ax2.barh(list(y), vals, color=colours, height=0.62)
    ax2.set_yticks(list(y))
    ax2.set_yticklabels([g.replace(" alone", "") for g in names], fontsize=8)
    ax2.invert_yaxis()
    ax2.set_xlabel("false positives, each group alone")
    top = max(vals)
    # A bar at 0.001 is a sliver, and a label placed just past it lands on
    # top of the tick label. Push every label out to a floor instead.
    ax2.set_xlim(-top * 0.02, top * 1.32)
    for i, v in enumerate(vals):
        ax2.text(max(v, top * 0.03) + top * 0.03, i, f"{v:.3f}",
                 va="center", fontsize=8, color=INK)
    ax2.set_title("Under a shift in scale", loc="left", fontsize=9.5, pad=8)

    fig.suptitle("Trained on runs opening under 300 files, "
                 "measured on runs opening 300 or more",
                 x=0.02, ha="left", fontsize=10)
    fig.subplots_adjust(top=0.80)
    out = os.path.join(outdir, "fig2_volume_shift.png")
    fig.savefig(out)
    plt.close(fig)
    return out


# ----------------------------------------------------------------- figure 3

FIRST_ROUND = re.compile(r"^(m\d|f\d|s\d|g\d|e\d|v\d|b\d|r\d|t\d|w_|x_)")


def kind_of(sample_id, names, modelling):
    """
    What a held-out negative is, which the rate on its own does not say.

    The benign rows have no entry in the name table, so they have to be
    identified from the modelling table instead; without that they fall
    through to "real software" and inflate it several-fold.
    """
    if (modelling.get(sample_id) or {}).get("source") == "benign":
        return "benign corpus"
    fn = names.get(sample_id, "")
    if not fn:
        return "unresolved"
    if fn.startswith(("xc_", "xgo_", "xrust_")):
        return "designed grid"
    if fn.startswith("v_"):
        return "earlier matrix"
    if fn.startswith("s_"):
        return "scripts"
    if fn.startswith("doc_"):
        return "documents"
    if fn.startswith("tool_"):
        return "tool wrappers"
    if fn.startswith("stage") or FIRST_ROUND.match(fn):
        return "first-round variants"
    return "real signed software"


def load_kinds(scores_path, names_path, modelling_path):
    names = {r["sample_id"]: r["filename"] for r in read(names_path)}
    modelling = {r["sample_id"]: r for r in read(modelling_path)}
    counts = {}
    for r in read(scores_path):
        k = kind_of(r["sample_id"], names, modelling)
        hit, n = counts.get(k, (0, 0))
        counts[k] = (hit + (1 if float(r["flag_rate"]) >= 0.5 else 0), n + 1)
    return counts


def fig_by_kind(counts, outdir):
    if not counts:
        return None
    items = sorted(counts.items(), key=lambda kv: -kv[1][1])
    names = [k for k, _ in items]
    rates, los, his, ns = [], [], [], []
    for _, (h, n) in items:
        p, lo, hi = wilson(h, n)
        rates.append(p); los.append(lo); his.append(hi); ns.append(n)

    fig, ax = plt.subplots(figsize=(6.6, 3.6))
    y = list(range(len(names)))
    for i, (r, lo, hi) in enumerate(zip(rates, los, his)):
        live = names[i] == "real signed software"
        ax.plot([lo, hi], [i, i], color=ACCENT if live else LIGHT, lw=2.4,
                solid_capstyle="butt")
        ax.plot([r], [i], "o", color=ACCENT if live else MID, ms=5)
        ax.text(hi + 0.012, i, f"{items[i][1][0]} of {ns[i]}",
                va="center", fontsize=7.5,
                color=INK if live else MID)

    ax.set_yticks(y)
    ax.set_yticklabels(names, fontsize=8.5)
    ax.invert_yaxis()
    ax.set_xlabel("false positive rate, with 95% interval")
    ax.set_xlim(-0.01, min(1.0, max(his) * 1.25))
    ax.set_title("One rate over the whole set describes how the set was built",
                 loc="left", fontsize=10, pad=10)

    out = os.path.join(outdir, "fig3_by_kind.png")
    fig.savefig(out)
    plt.close(fig)
    return out


# ----------------------------------------------------------------- figure 4

def fig_ablation(ablation_path, outdir):
    rows = [r for r in read(ablation_path) if not r["group"].endswith("alone")]
    if not rows:
        return None
    labels = [r["group"] for r in rows]
    auc = [float(r["auc"]) for r in rows]
    tpr = [float(r["tpr"]) for r in rows]
    fp = [float(r["fpr_hard"]) for r in rows]
    x = range(len(rows))

    fig, ax = plt.subplots(figsize=(6.4, 3.5))
    ax.plot(x, auc, "-o", color=ACCENT2, lw=1.6, ms=5, label="AUC")
    ax.plot(x, tpr, "--^", color=MID, lw=1.3, ms=5, label="recall")
    ax.set_ylim(min(min(auc), min(tpr)) - 0.03, 1.01)
    ax.set_ylabel("AUC and recall", color=ACCENT2)
    ax.tick_params(axis="y", labelcolor=ACCENT2)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=18, ha="right")
    ax.legend(loc="lower right", frameon=False, fontsize=8)

    ax2 = ax.twinx()
    ax2.spines["top"].set_visible(False)
    ax2.plot(x, fp, "-s", color=ACCENT, lw=1.6, ms=5)
    ax2.set_ylim(0, max(fp) * 1.4)
    ax2.set_ylabel("false positives", color=ACCENT)
    ax2.tick_params(axis="y", labelcolor=ACCENT)

    # Which step matters is read off the data rather than named in advance,
    # because it has changed twice already as the negative set grew.
    step = max(range(1, len(rows)), key=lambda i: auc[i] - auc[i - 1])
    ax.annotate(f"{labels[step]}: {auc[step]:.3f} at {fp[step]:.3f}",
                xy=(step, auc[step]), xytext=(6, -22),
                textcoords="offset points", fontsize=7.5, color=INK,
                arrowprops=dict(arrowstyle="-", color=MID, lw=0.7))

    ax.set_title("What each group adds, cumulatively",
                 loc="left", fontsize=10, pad=10)
    out = os.path.join(outdir, "fig4_ablation.png")
    fig.savefig(out)
    plt.close(fig)
    return out


# ---------------------------------------------------------------------- main

def parse_saturation(spec):
    points = []
    for part in spec.split(","):
        bits = part.split(":")
        if len(bits) != 3:
            continue
        points.append((int(bits[0]), int(bits[1]), float(bits[2])))
    return points


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ablation", help="abl_final.csv")
    p.add_argument("--shift", help="abl_shift.csv from --volume-shift")
    p.add_argument("--hard-scores", help="hn_final.csv")
    p.add_argument("--names", help="hardneg_names.csv")
    p.add_argument("--modelling", help="modelling_simple.csv")
    p.add_argument("--saturation", default=DEFAULT_SATURATION,
                   help="negatives:kinds:fp, comma separated")
    p.add_argument("--outdir", default="~/work/figures")
    args = p.parse_args()

    outdir = os.path.expanduser(args.outdir)
    os.makedirs(outdir, exist_ok=True)
    made = []

    pts = parse_saturation(args.saturation)
    if pts:
        f = fig_saturation(pts, outdir)
        if f:
            made.append(f)

    if args.shift and os.path.exists(os.path.expanduser(args.shift)):
        f = fig_volume_shift(args.shift, outdir)
        if f:
            made.append(f)

    if args.hard_scores and args.names and args.modelling:
        counts = load_kinds(args.hard_scores, args.names, args.modelling)
        print("held-out negatives by kind:")
        for k, (h, n) in sorted(counts.items(), key=lambda kv: -kv[1][1]):
            rate, lo, hi = wilson(h, n)
            print(f"   {k:<24}{n:>5}{h:>6}  {rate:.3f}  [{lo:.3f}, {hi:.3f}]")
        f = fig_by_kind(counts, outdir)
        if f:
            made.append(f)

    if args.ablation:
        f = fig_ablation(args.ablation, outdir)
        if f:
            made.append(f)

    for f in made:
        print(f"[saved] {f}")
    if not made:
        print("nothing to draw; pass at least one input")


if __name__ == "__main__":
    main()
