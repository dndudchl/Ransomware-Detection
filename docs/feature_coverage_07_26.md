# Feature Coverage Design

How the feature table handles samples for which only part of the data is
available, and why rows are kept rather than discarded.

## The problem

Most ransomware samples do not detonate in the sandbox. In the legacy Cuckoo
dataset of 447 analyses, only 34 (~7.6%) genuinely encrypted the planted
decoy files. An earlier version of the pipeline extracted features only from
those 34 and discarded the rest.

That threw away most of the dataset for no good reason. Static features come
from the binary's import table, which does not depend on whether the sample
executed. Of the same 447 analyses, 324 had a readable import table --
roughly ten times as many samples as the dynamic path could supply. The
label ("this binary is ransomware") is equally true for all of them.

The fix is to stop treating "did it run?" as a single gate on the whole
feature set, and instead record, per sample, which feature groups are
actually supported by evidence.

## Two independent axes

These are separate questions and they do not imply one another:

| Column | Question | Determined by |
|---|---|---|
| `coverage` | Are the dynamic features meaningful? | The analysis verdict (did it attack the decoy files?) |
| `static_readable` | Are the static features meaningful? | Whether the import table could be parsed (packing) |

Crossing them gives four cases:

|  | `static_readable = 1` | `static_readable = 0` (packed) |
|---|---|---|
| **`coverage = full`** | dynamic + static available | dynamic only |
| **`coverage = static_only`** | **static only** — the large recovered group | neither — no information |

Expected distribution on the legacy Cuckoo dataset (447 analyses):

| Combination | Approx. count |
|---|---|
| `full` + readable | ~34 |
| `static_only` + readable | ~290 |
| `static_only` + not readable | ~123 |

## Blank vs zero

Static-only rows leave the dynamic columns **blank**, not zero. This
distinction is load-bearing.

A sample that never executed has no delete count. Writing `n_delete = 0`
would assert "this ransomware deleted nothing", which is false — nothing was
observed either way. A model trained on that would learn that ransomware
frequently deletes nothing, from samples that simply never ran.

- **blank** = not observed
- **0** = observed to be zero

Tree-based models (RF, XGBoost) handle missing values natively, so blanks
are consumed correctly without imputation.

## Why unreadable-static rows are still written

Rows where both axes fail (`static_only` + `static_readable = 0`) carry no
usable features at all: every dynamic column is blank and every static
column is zero. They are still written to the CSV, for two reasons:

1. **Honest reporting.** The dataset should record how many samples were
   unanalysable, not silently omit them. "123 of 447 were packed beyond
   static analysis" is a finding worth stating in the thesis.
2. **Future recovery.** If a new feature axis is added later (entropy of
   written data, YARA matches, memory-dump imports), these samples may
   become usable without re-running the sandbox.

They must be **excluded before model training**, filtered on
`static_readable == 1`.

## The packing bias, and why it is flagged rather than exploited

`total_imports = 0` would be a strong predictor of ransomware in this
dataset — but that is an artefact, not a finding.

The benign control set (1,621 samples: Windows System32, common desktop
tools, DikeDataset) contains no packed programs, because ordinary software
is not distributed packed the way malware is. So "unreadable imports" is
perfectly correlated with the ransomware label here purely because of how
the two sides were collected. In reality, commercial protectors and some
installers are packed too.

Rather than hide this, `static_readable` makes it explicit. It can then be
used deliberately: excluded from the feature set to avoid learning the
artefact, or used as a filter, and either choice can be stated plainly in
the methodology.

## Consequences for modelling

| Model | Rows used | Filter |
|---|---|---|
| Tree-based (RF / XGBoost) | full + static-only, readable only | `static_readable == 1` |
| Sequence (LSTM / 1D-CNN) | full only | `coverage == "full"` |

The sequence model needs a real event sequence; a sample that never executed
has none, and padding an empty sequence would be inventing data. The tree
model tolerates missing columns, so it can use the much larger pool.

This also means the two models are evaluated on different sample sets, which
must be stated when comparing their results — they are not competing on
identical data.

## Consequence for archiving

Because non-qualifying analyses now contribute static features, their raw
reports must be preserved: if the static feature definitions change later
(new import categories, new library fingerprints), re-extraction needs the
original report.

The cleanup stage therefore archives **every** analysed report as gzip
before deleting the analysis directory, including FAILED ones. Compressed
reports are roughly 100MB -> 10-20MB, so keeping everything is cheap
relative to the cost of losing the ability to re-extract.

## Usage

```bash
# Full features for qualifying analyses, static-only rows for the rest
python3 run_pipeline.py \
    --analyses-dir /opt/CAPEv2/storage/analyses \
    --features-out ../data/features/features.csv \
    --manifest ../data/manifest.csv \
    --static-for-all

# Or directly
python3 extract_features.py --batch /opt/CAPEv2/storage/analyses \
    --results analysis_results.csv --static-for-all \
    --features-out ../data/features/features.csv
```

Without `--static-for-all` the pipeline keeps its previous behaviour and
emits full rows only, which remains useful when only dynamic data is wanted.

## Fairness note on the benign side

Ransomware rows are now included regardless of execution success. The benign
control set must be treated the same way, or the comparison is biased: if
every benign sample had to execute successfully to be included while
ransomware did not, the two groups would have passed through different
filters.

The current benign set satisfies this — it was extracted with pefile from
raw executables, with no execution requirement at all. When benign samples
are later run through CAPE for dynamic features, they should be recorded
with the same `coverage` / `static_readable` flags so the same filters apply
to both classes.
