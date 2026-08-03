# Preparation Behaviour: What Holds Up

Ransomware clears the ground before it encrypts. This is what measuring that
actually produced -- including two results that contradicted the assumption
they were built on.

## The comparison, and its limits

Both groups compared here are ransomware: 287 runs that reached encryption
and 82 that executed without encrypting. So nothing below says what separates
ransomware from ordinary software. That needs benign programs run through the
same sandbox, which has not been done.

What it can say is narrower: among samples that ran, which behaviours
accompany reaching the encryption stage.

### Activity has to be held constant

The obvious comparison misleads. Runs that did not encrypt are, on average,
runs that did less of everything -- some barely got going. Any behaviour then
looks commoner among the encrypting group simply because that group was
busier.

Compared within bands of similar API-call volume, some gaps survive and some
collapse. The difference between the two tables is the point of doing it.

## What held up: shadow-copy deletion

| | encrypting | stopped short | gap |
|---|---|---|---|
| whole set | 65.9% | 12.2% | 53.7 |
| 5k-25k calls | 45.2% | 23.1% | 22.1 |
| **25k-75k calls** | **63.1%** | **5.0%** | **58.1** |

The gap survives, and in the largest comparable band it is wider than across
the whole set. This is not an artefact of one group being busier.

It also makes sense on its own terms: a ransom demand is worthless if the
victim can roll the files back, so deleting shadow copies is not optional in
the way that killing processes or stopping services is.

One implementation detail worth recording. The command line for this is often
obfuscated:

```
"C:\fqkq\..\Windows\yaxq\qp\d\..\..\..\system32\lu\n\..\..\wbem\cl\oj\..\..\wmic.exe" shadowcopy delete
```

Fake directories and traversals padding the path, to defeat exact matching.
Substring matching survives it; so does matching on the process name, which
is what the timing features use.

## What did not hold up: the assumption of ordering

The relational feature was built expecting a sequence -- clear the ground,
then begin encrypting -- and measuring the delay between the two.

Measured across runs that did both:

| | |
|---|---|
| median gap, first preparation tool to first destroyed file | **1.7 s** |
| range | 0.0 - 321.9 s |
| encrypting runs that launched a preparation tool | 208 |
| of those, launched it **before** destruction began | **40 (19%)** |

So preparation does not precede encryption. They happen at the same time, and
in four cases out of five the first file is already gone before the first
preparation tool starts. Separate threads, running concurrently.

`prep_precedes_destroy` was therefore measuring something close to a coin
toss. It was replaced by `prep_overlaps_destroy`: whether preparation falls
inside the window during which files are being destroyed. That holds for both
orderings, and still excludes the case it was meant to exclude -- a backup
tool touches shadow copies but has no destruction window for anything to fall
inside.

`prep_position_in_destroy` records where in that window preparation sits, as
a fraction from 0 to 1.

## What turned out to be an artefact: killing processes

The starting observation looked strong and pointed the wrong way. Among runs
of comparable activity, samples that launched `taskkill` reached encryption
**29%** of the time against **80%** for those that did not.

Killing processes is preparation. It should accompany encryption, not replace
it. Three explanations were tested.

### Not a measurement failure

The sandbox agent runs as `python.exe`, and ransomware freeing file locks
kills processes in bulk. This was observed directly elsewhere: in one
analysis the agent stopped responding one second after `bcdedit` ran. If the
agent dies mid-run, everything afterwards is unrecorded and the sample looks
like it prepared and stopped.

| | |
|---|---|
| CAPE reported the agent dead | **0 / 14** |
| used the full analysis window | **14 / 14** (669-733 s) |

They had the time and the instrument was working. Ruled out.

### Not family confounding, exactly

Seven of the fourteen were the same family, Kitty, which would explain the
gap if that family simply does not detonate here. It does:

| Kitty runs | n | encrypted |
|---|---|---|
| killed processes | 7 | **0** |
| did not | 8 | **8** |

A complete split, inside one family. So not confounding in the simple sense.

### It is two builds

All fifteen Kitty runs are different binaries. The two groups separate on
figures that have nothing to do with the runtime decision:

| | encrypting | killing |
|---|---|---|
| static imports | 122 (six of seven) | 119, 119, 119, 119, 119, 118, 105 |
| API calls | 88,055 - 136,348 | 37,299 - 51,512 |

Neither range overlaps. These are two builds of Kitty, and one of them both
kills processes and does not encrypt. The two behaviours travel together in
that build; neither causes the other.

Removing Kitty leaves the effect thin:

| | runs | encrypted |
|---|---|---|
| killed processes, excluding Kitty | 7 | 4 (57%) |
| did not kill | 355 | 283 (80%) |

Seven runs and a 23-point difference is not a finding. The original 29%
against 80% was almost entirely seven samples of one Kitty build.

### A useful side effect

The import counts predicted the behavioural split before anything was run:
122 for the builds that encrypt, 119 for those that do not. That is the
static-dynamic correspondence the feature set is meant to capture, appearing
without being looked for.

## Method note

Three findings, three different fates:

| Claim | Outcome |
|---|---|
| shadow deletion accompanies encryption | held, and strengthened, under activity control |
| preparation precedes encryption | false; they are concurrent |
| killing processes predicts failure to encrypt | artefact of two builds in one family |

The second and third were both produced by measuring something real and
reading a relationship into it that the data did not support. Ordering was
assumed rather than checked; the process-kill gap was aggregated across
families that behave differently.

The checks that caught them were cheap: measure the delay instead of assuming
its sign, and split by family before believing a rate. Both are worth running
by default on anything the counts appear to show.
