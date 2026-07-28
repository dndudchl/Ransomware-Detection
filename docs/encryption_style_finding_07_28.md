# Encryption Style Breaks Event-Based Detection

A verification bug that turned into a result worth reporting.

## What happened

The sandbox verdict stage decides whether a run genuinely encrypted the
planted decoy files. It originally did this by counting **destructive
events** (write / delete / move) on decoy documents, and calling anything
above 20 events a real encryption run.

That threshold was calibrated on WannaCry, the only confirmed encrypting run
available at the time. When AvosLocker samples were analysed, the desktop
screenshots clearly showed encrypted files, yet the verdict came back
`WEAK_VICTIM_ACTIVITY` or `NO_VICTIM_ACTIVITY`. The classifier was wrong, not
the screenshots.

## Why the event count failed

The two families encrypt in structurally different ways:

| | WannaCry | AvosLocker |
|---|---|---|
| Method | read original → write encrypted copy under a new name → delete original | open the file and overwrite it where it sits |
| Events per file | ~3 | **1** |
| Original filename | replaced (`.WNCRY` appended) | unchanged |

Measured on the same decoy set:

| Run | Destructive events on decoys | Decoy files damaged |
|---|---|---|
| WannaCry (task 37) | 613 | 147 |
| AvosLocker (task 70) | 18 | 17 |
| AvosLocker (task 68) | 16 | 16 |

The event counts differ by roughly 35x. The file counts differ by 8x, and
more importantly both sit far above zero. **A threshold expressed in events
encodes an assumption about encryption style**: it silently assumes the
attacker writes a second copy and deletes the first. In-place overwriters
produce one event per file and fall straight through it.

## A second, independent bug: the extension allowlist

Decoy files were only counted if their extension appeared in a hardcoded
list of document types (`.docx`, `.xlsx`, `.pdf`, ...). The decoy set is made
of real coursework, and some of it has extensions that were never listed
(`.vdfx`, `.2mdl`). Those attacks were discarded silently.

This was not a minor edge case. Re-measuring WannaCry without the allowlist:

| | Files counted |
|---|---|
| With extension allowlist | 57 |
| Without | **147** |

The allowlist was discarding about 60% of the observed damage even for the
sample it had been validated against. It only escaped notice because
WannaCry's event count cleared the threshold anyway.

An allowlist fails in the dangerous direction: an unanticipated decoy type
becomes invisible. The replacement is an exclusion list of known non-decoy
files inside those folders (shell metadata, caches, profile data). An
unanticipated *noise* file inflates the count slightly, which is the safer
failure.

## The fix

Count **distinct decoy files touched destructively**, not events, and treat
everything in the decoy folders as a decoy unless explicitly excluded.

Reads are counted separately and never contribute to the verdict. This is
what keeps a benign archiver out: the 7-Zip run read 56 decoy files and
destroyed none, because compressing a document does not modify it. A metric
that counted "files touched" rather than "files damaged" would classify
7-Zip as ransomware.

Observed distribution after the change:

| Category | Decoy files destroyed |
|---|---|
| Confirmed encrypting runs | 4, 13, 16, 17, 147, 147 |
| Everything else | 0, or 1 |

The empty band between 1 and 4 is where the new threshold sits (3). It rests
on six positive examples and should be revisited as more confirmed runs
accumulate.

## Timeouts distort the measurement

All four AvosLocker analyses hit their timeout while still encrypting
(`info.timeout: true`, durations 418-453s). The same binary produced
different damage counts on different runs:

| Sample | Run A | Run B |
|---|---|---|
| `bff12a83...` | 16 files | 17 files |
| `0b1f19ba...` | 13 files | **4 files** |

The 4-file run is not a less dangerous sample; it is the same sample cut off
earlier in its encryption pass. With a threshold of 3 it barely qualified,
and a slightly earlier cutoff would have produced a false negative.

WannaCry shows the same pattern from the other direction: 90% of its
destruction occurred within 181 seconds, but it was still encrypting when
the analysis ended at 347s.

Practical consequence: analysis timeout should be generous enough that the
verdict reflects the sample rather than the cutoff. Runs that hit the
timeout should be treated as lower bounds on the damage.

## Why this belongs in the thesis

This is a concrete, measured instance of the weakness the project argues
against. A single-metric detector was tuned on one ransomware family, looked
correct, and failed on the next family it met — not because that family was
stealthier, but because it wrote to disk in a different shape.

Two properties of the failure are worth stating:

1. **It was invisible from inside the data.** The event counts looked
   healthy: task 70 recorded 4,782 destructive events overall. Only 18 of
   them landed on decoys, and nothing in the aggregate hinted that the
   classifier was reading the wrong signal. It took an external ground truth
   — screenshots of the guest desktop — to expose it.

2. **The fix is a shift in what is being related.** Counting files rather
   than events removes the implicit dependency on how many operations a
   given implementation happens to use per file. The signal survives a
   change in encryption style because it no longer encodes one.

The same reasoning applies to the detection features themselves.
`delete_to_write_ratio`, taken alone, carries the identical assumption: it
is near zero for an in-place overwriter that never deletes anything, exactly
as the event threshold was. That is the argument for treating such ratios as
inputs to a multi-signal model rather than as decision rules.

## Limits of screenshot ground truth

Screenshots were what caught this, but they are partial evidence:

- They show the desktop, not Documents or Downloads.
- In-place overwriting leaves filenames unchanged, so encryption is only
  visible indirectly (icons failing to render, ransom notes appearing).
- They confirm that encryption happened, not how much.

They are therefore useful for detecting **false negatives** — cases the
classifier missed — but weak for confirming true negatives. A run with no
visible desktop change may still have encrypted files elsewhere.
