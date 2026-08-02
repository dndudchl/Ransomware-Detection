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

After the fixes described below, detection on the first confirmed-encrypting
set rose from 17 of 73 to 111 of 116. A second batch of 200 analyses was then
labelled independently, and the same process repeated: 47 of 57 at the start,
54 of 57 once three further failures were fixed and a corroboration rule
added.

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

## Failure 6 — treating a missing log line as damage

A tool for separating sandbox failures from sample failures decided that an
analysis whose guest-side log did not end with "Analysis completed" had been
cut short.

That line is written when the analyzer shuts itself down, having watched the
sample exit. Ransomware does not exit -- it runs until the analysis timeout,
at which point CAPE stops the guest and the line is never written. Its
absence is the normal outcome for exactly the samples that worked.

The classifier consequently marked successful runs for re-submission: 163,000
API calls, 41 screenshots, 110 decoy files destroyed, flagged as needing to
be run again.

Fix: ask whether the run produced data, not how its log ended.

## Failure 7 — reading quiet as broken

The same tool then used a call-count threshold of 500, borrowed from the
"did the sample do anything" gate elsewhere in the pipeline. That is a
different question.

One sample opened a socket, initialised Windows CNG, and waited for a
connection that never came. 263 API calls, correctly monitored, nothing
wrong with the analysis -- and classified as an infrastructure failure.

What matters is whether the sandbox observed the guest, not whether the
guest was busy. The fix reads CAPE's own statement instead: it logs "Agent
is dead" when the guest stops answering, which distinguishes a sample that
ran quietly from one whose guest was lost after recording a few calls.

## Failure 8 — an extension allowlist, again

Ransom note detection was added, matching filenames against a list of
plausible note extensions: txt, html, hta, rtf, url, lnk, bmp, jpg.

Three analyses dropped a note named `readme.md`. The list did not contain
`md`, so they registered nothing.

This is Failure 2 repeated, in code written after Failure 2 had been
documented. Knowing that allowlists fail this way was not enough to avoid
writing another one. The fix is the same: exclude what a note cannot be
(executables, drivers, logs) rather than list what it might be.

## Failure 9 — assuming a rename is logged as a rename

Append-renaming -- keeping the original filename and adding a suffix -- was
detected by reading move events for a destination that extends the source.

One family produces no move events at all. It writes `X.exe` and separately
deletes `X`. Structurally this is the same operation, and it was applied to
45 files with every original deleted, but with no move event to read it
scored zero.

Fix: reconstruct the pairs from the summary lists as well. A written path
that extends a deleted path in the same directory is a rename regardless of
how the sandbox chose to record it.

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
| 6 | a finished log means a healthy run | ransomware runs until the timeout |
| 7 | few API calls means a broken analysis | a sample can wait on a socket |
| 8 | note extensions are known in advance | `readme.md` |
| 9 | a rename is logged as a move | write plus delete does the same thing |

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

On the second labelled batch, with the ransom note axis and the
corroboration rule added, detection went from 47 of 57 to 54 of 57. The
three that remain undetected recorded no file events at all: the sample
killed the sandbox agent before anything was written down, which is a
measurement failure rather than a detection failure.

Neither axis is sufficient. Netwalker never renames anything — it overwrites
decoy files in place, so only the decoy check sees it. Cuba never reaches the
decoys, so only the rename check sees it. Each family is invisible to one of
the two axes and visible to the other.

This is the project's central claim, measured on its own verification code
rather than argued in the abstract: a single indicator sees one
implementation strategy, and coverage comes from combining indicators that
fail in different directions.

## A third axis: the demand itself

Ransomware announces itself. Whatever it does to the files, it leaves a note
telling the victim how to pay, and it leaves one wherever the victim might
look.

That last part is what makes the note detectable without a list of known
filenames. Plenty of software ships a `readme`; almost none writes an
identically-named file into every directory it touched. Observed spreads in
this dataset:

| Note name | Directories |
|---|---|
| `readmefordecrypt.txt` | 1,442 |
| `e76b3b-readme.txt` | 423 |
| `restore-my-files.txt` | 309 |
| `how to restore your files.txt` | 2 - 72, across 12 analyses |
| `og5iasxf4.readme.txt` | 6 |

Names vary far too much to enumerate: random prefixes (`cmfmxqq8w.readme.txt`),
embedded victim identifiers
(`readme.md.id[ec4dac17-2822].[<address>].eight`), and ordinary words. What
does not vary is that the same file appears in many places at once.

Two rules follow, and both were set from the labelled data:

- A name that states the purpose -- decrypt, recover, restore, unlock,
  ransom, how-to -- counts on its own, because some families leave a single
  copy and would otherwise be invisible. No benign file in the labelled set
  carries such a name.
- Any other note-like name needs two or more directories.

Measured against the labels, notes appeared in two or more directories in 36
of 57 confirmed encrypting runs and in 1 of 79 runs where nothing was
encrypted -- and that one turned out to be encryption the manual pass had
missed.

One caveat found the hard way: matching filenames alone produces false
positives. Three analyses were credited with a ransom note that was really a
`README.md` belonging to a `sysmon-config` project sitting in the recycle
bin. Those analyses were encrypting, but for an unrelated reason, and the
note detection had been right by accident.

## Corroboration: what the thresholds cannot see individually

Each axis has a threshold chosen so that the axis is safe alone: three
destroyed decoy files, eight append-renames, a note in two directories. That
safety creates a blind spot immediately below each line. Two destroyed files
is not enough. Four append-renames is not enough. A note in one directory is
not enough.

Two analyses sat precisely there:

| | decoy files | append-renames | note directories |
|---|---|---|---|
| one | 2 (needs 3) | 1 (needs 8) | 0 |
| other | 0 | 4 (needs 8) | 1 (needs 2) |

Both had encrypted. Neither could be seen by any single rule.

What makes them recoverable is how sharply the negative set behaves.
Counting how many of the three axes show *anything at all*, regardless of
magnitude:

| Axes showing anything | Confirmed encryption | No encryption |
|---|---|---|
| 0 | 3 | **79** |
| 1 | 5 | 0 |
| 2 | 22 | 0 |
| 3 | 29 | 0 |

Not one of the 79 non-encrypting runs registered on any axis. That includes
ten that were thoroughly active -- one made 71,822 API calls and wrote 921
files -- and still showed zero destroyed decoys, zero append-renames, zero
notes. Ordinary file activity and ransomware-shaped file activity separate
completely.

So a run showing faint traces on two independent axes is not two
coincidences. The rule added is simply that: **two or more axes non-zero
counts as encryption, even when no single one reaches its threshold.** It
recovered both analyses and flagged none of the 79 negatives.

This is the project's central claim appearing in its own verification code.
The thresholds are single-feature rules, and each is blind in its own way.
What sees past them is not a better threshold but the observation that the
signals occur together.

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
