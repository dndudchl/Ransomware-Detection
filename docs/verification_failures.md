# Verification Failures Found by Independent Ground Truth

A record of four bugs in the encryption-verification logic, all of which
looked correct from inside the data and were only exposed by evidence from
outside it.

This extends `encryption_style_finding.md`, which covered the first of them.

## Why this document exists

The behavioural verdict decides whether a sandbox run genuinely encrypted the
planted decoy files. It reads the same event log that the detection features
are built from. Checking it against that log is therefore circular: a
systematic misreading of the log produces a wrong verdict and a matching
wrong justification.

Screenshots of the guest desktop are independent evidence — pixels rather
than API traces. Comparing 101 hand-labelled screenshot outcomes against the
verdict revealed that **67% of genuinely encrypting runs were being reported
as harmless**.

| Manual label from screenshots | TRUE_ENCRYPTION | WEAK | NO_VICTIM | FAILED | total |
|---|---|---|---|---|---|
| A — files encrypted | 17 | 4 | **49** | 3 | 73 |
| B — nothing changed | 2 | 0 | 2 | 13 | 17 |
| C — console activity, unclear | 2 | 4 | 3 | 2 | 11 |

Nothing in the event data hinted at this. The 49 missed analyses averaged
170,000 API calls and 455 destructive file events each; they looked busy and
healthy.

After the fixes described below, detection on the confirmed-encrypting set
rose from 17 of 73 to 111 of 116.

## Failure 1 — counting events instead of files

Covered in detail in `encryption_style_finding.md`. In short: WannaCry writes
an encrypted copy and deletes the original, roughly three events per file.
AvosLocker overwrites the file in place, one event per file. An event-count
threshold calibrated on the first misses the second entirely, even though
both encrypt the same decoys.

Fix: count distinct decoy files touched destructively, not events.

## Failure 2 — an extension allowlist

Decoy files were only counted if their extension appeared in a hardcoded
list of document types. The decoy set is real coursework and includes
extensions that were never listed (`.vdfx`, `.2mdl`). Re-measuring WannaCry
without the allowlist raised the count of damaged files from 57 to 147: the
list had been discarding 60% of the observed damage even for the sample it
was validated against.

Fix: an exclusion list of known non-decoy files (shell metadata, caches)
instead of an allowlist of expected types. An unanticipated noise file
inflates the count slightly; an unanticipated decoy type made real attacks
invisible.

## Failure 3 — reading the wrong field for move events

This was the largest, and it accounted for most of the 49 missed analyses.

Most file events in CAPE's `behavior.enhanced` carry their path in
`data.file`. A **move** does not:

```json
{ "event": "move",
  "data": { "from": "C:\\Users\\admin\\Desktop\\report.docx",
            "to":   "C:\\Users\\admin\\Desktop\\report.docx.cipher4" } }
```

The extraction code read `data.file` only, so every move event resolved to an
empty path and was discarded. In one analysis this silently dropped 240
events — visible in a folder tally as 240 events attributed to a blank path.

Renaming the original to an encrypted counterpart is exactly how the family
in question encrypts. Its ransom note (`!-Recovery_Instructions-!.html`) and
its encrypted-file suffix (`.cipher4`) were both present in the log. The
evidence was complete; the parser was looking in the wrong place.

The signature of the failure, comparing the missed group with the caught one:

| | missed (label A, verdict NO_VICTIM) | caught (label A, verdict TRUE) |
|---|---|---|
| total API calls, median | 170,000 | 37,000 |
| destructive events, median | 455 | 1,683 |
| **decoy files destroyed** | **0 for every one** | 7 - 95 |
| **decoy files read** | **~104** | ~7 |

Reading a hundred decoy files and destroying none is not a plausible
description of ransomware. It is a description of a parser that cannot see
renames.

Fix: resolve paths from `data.file`, or from `data.from` when `data.file` is
absent. The source path is used for a move, since that is the file which
ceased to exist under its own name; counting the destination as well would
double the tally for one file.

## Failure 4 — the execution gate blocked the decoy check

The verdict ran in two stages: first decide whether the sample executed at
all, then, only if it did, check whether it damaged the decoy files. The
first stage failed a run whose total destructive file events fell below 50.

That ordering discarded evidence. One run recorded 44 destructive events in
total — below the gate — of which **21 landed on decoy files**. It was
reported as never having executed.

The gate was measuring volume as a proxy for significance. A sample that goes
straight for the user's documents and touches nothing else is precise, not
inactive; it produces few events and all of them matter. Meanwhile a sample
that unpacks a Python runtime into %TEMP% clears the gate easily while doing
nothing of interest.

Fix: compute both stages unconditionally and let the evidence decide. The
execution check now only explains *why* a run produced nothing, rather than
deciding in advance that it did.

Recovering this cost nothing and reclassified two runs immediately.

## Failure 5 — an in-flight count that depended on another process

Not a verification bug, but the same shape of mistake, so it belongs here.

The submission tool tops the sandbox queue up to a target depth, and counted
work already in flight as "manifest entries marked submitted with no verdict
recorded yet". A verdict is only written when the pipeline is run with
`--manifest`. During tuning the pipeline was deliberately run without it, so
the count only ever grew: it reached 113 against a target of 20, and
submission stopped entirely while the sandbox sat idle.

Fix: determine completion from something directly observable. CAPE writes
`<analyses>/<task_id>/reports/report.json` when an analysis finishes, so an
entry is in flight exactly while that file is absent — true for queued tasks
(no directory yet) and running ones alike, regardless of what any other
process has or has not recorded.

## The common shape

Every one of the four assumed that the world would arrive in a particular
form:

| # | Assumption | What broke it |
|---|---|---|
| 1 | encryption writes then deletes | in-place overwriting |
| 2 | decoy types are known in advance | real coursework file formats |
| 3 | every event carries `data.file` | move events carry `from`/`to` |
| 4 | volume of activity implies significance | a precise sample touches little |
| 5 | another process will record completion | it was not being run that way |

None produced an error. Each silently returned a plausible-looking answer,
which is why they survived until an independent source of truth contradicted
them.

## A structural limit, and the second signal added for it

Fixing the four bugs above still left runs that had visibly encrypted
reporting nothing. These were not parsing errors. The verification design
itself assumed the sample would reach the decoy folders, and several families
do not within the analysis window:

| Family | Where it spent the run | Decoy files damaged |
|---|---|---|
| Cuba | `Program Files\Adobe\Acrobat DC` — 4,779 files renamed | 0 |
| Clop | `Users\admin\AppData` — 239 destructive events | 0 |
| SunCrypt | `Windows\System32`, `MSOCache` | 0 |

The Adobe directory alone holds thousands of files. Cuba worked through it
for the entire window and never reached the Desktop. Raising the timeout does
not fix this, because the ordering of the filesystem walk is not something
the analysis window controls.

What these runs have in common is not a location but the **shape of the
rename** they perform:

```
Cuba      file.png  ->  file.png.cuba
Clop      file.ps1  ->  file.ps1.Clop
SunCrypt  file.xxx  ->  file.xxx.7254C3DA...  (a different hash per file)
```

Each keeps the original filename intact and appends a suffix. Matching on the
extension string would not work — Cuba and Clop share one suffix across every
file, while SunCrypt generates a unique 64-character suffix per file, so
counting files that share a new extension finds Cuba and misses SunCrypt
entirely. The invariant is the append itself.

Normal software rarely appends to a full filename. Temporary files are
renamed to a different name, and backup tools tend to insert rather than
append. Log rotation is the exception (`app.log` -> `app.log.1`), which is why
the count matters rather than the mere presence.

The threshold was set from the labelled batch — 12 confirmed-encrypting runs
the decoy check had missed, against 17 runs where nothing happened:

| Threshold | Encrypting runs recovered | Non-encrypting runs wrongly flagged |
|---|---|---|
| 3 | 11 / 12 | 1 / 17 |
| **8** | **10 / 12** | **0 / 17** |
| 20 | 8 / 12 | 0 / 17 |

Eight recovers the most at no cost. The two it still misses are genuinely
ambiguous on this signal: one encrypting run made 4 append-renames while a
non-encrypting one made 5, so no threshold separates them.

### The two signals are complementary, and measurably so

Across 116 hand-confirmed encrypting runs, 111 are now detected. Which signal
found them:

| | Runs |
|---|---|
| decoy damage only | 24 |
| append-renames only | 11 |
| both | 76 |
| **decoy check alone would find** | **100 / 111** |
| **rename check alone would find** | **87 / 111** |
| **together** | **111 / 111** |

Neither axis is sufficient. Netwalker never renames anything — it overwrites
decoy files in place, so only the decoy check sees it. Cuba never reaches the
decoys, so only the rename check sees it. Each family is invisible to one of
the two axes and visible to the other.

This is the project's central claim, measured on its own verification code
rather than argued in the abstract: a single indicator sees one
implementation strategy, and coverage comes from combining indicators that
fail in different directions.

## What this means for the detection features

The same reasoning applies directly to the features, not just to the
verification code.

`delete_to_write_ratio` carries the identical assumption as Failure 1: it is
near zero for an in-place overwriter, and — before Failure 3 was fixed — it
was also near zero for a family that encrypts by renaming, because those
events were being dropped. A single ratio inherits every blind spot of the
parser and the encryption style it was calibrated on.

This is the concrete argument for treating such ratios as inputs to a
multi-signal model rather than as decision rules, which is the project's
central claim. It is worth stating in the thesis with these numbers
attached: a single-metric verifier, calibrated on one family, was wrong about
two thirds of the dataset while appearing to work.

## Methodological note on the labels

The 101 manual labels are the most reliable ground truth available and were
what exposed all of this. They have limits worth recording:

- Screenshots show the desktop, not Documents or Downloads.
- In-place overwriting leaves filenames unchanged, so encryption is only
  visible indirectly (icons failing to render, ransom notes appearing).
- Visible change is therefore strong evidence that something happened, while
  its absence is weak evidence that nothing did. The labels are reliable for
  finding false negatives and weaker for confirming true negatives.

Because thresholds were tuned against these labels, reporting accuracy on the
same labels would be circular. Some labelled analyses should be held back
from tuning so that a final figure can be quoted on data that played no part
in setting the thresholds.
