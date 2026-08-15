# Preparation Behaviour: What Holds Up

Ransomware clears the ground before it encrypts. This is what measuring that
actually produced -- including two results that contradicted the assumption
they were built on.

> **Rerun on 3,455 analyses.** Everything below was first measured on 1,492
> runs from one host. Adding the second host more than doubled the set, and
> two of the three conclusions changed. The original numbers are kept
> alongside the new ones, because which findings survived a larger sample and
> which did not is itself the useful part.

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
| whole set | 47.5% | 8.5% | 39.0 |
| 500 - 5k calls | 18.8% | 6.1% | 12.6 |
| 5k - 25k calls | 27.7% | 4.9% | 22.8 |
| **25k - 75k calls** | **37.8%** | **11.9%** | **25.9** |
| **75k+ calls** | **61.6%** | **18.5%** | **43.1** |

The gap survives in every band, and widens as the runs get busier. The
individual figures are lower than the first measurement (58.1 in the middle
band), but they now rest on 809 and 873 runs in the two largest bands rather
than a few dozen, and the consistency across four bands is worth more than
the size of any one of them.

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

| | first measurement | rerun |
|---|---|---|
| median gap, first preparation tool to first destroyed file | 1.7 s | **6.9 s** |
| encrypting runs that launched a preparation tool | 208 | **943** |
| of those, launched it **before** destruction began | 40 (19%) | **366 (39%)** |

Preparation still does not reliably precede encryption -- three runs in five
have already destroyed a file before the first preparation tool starts, and
the gap where it does precede is seconds rather than minutes. Encryption and
ground-clearing run concurrently on separate threads.

What changed is that the ordering turns out to be discriminative after all,
in the opposite direction to the one assumed:

| band | encrypting | stopped short | gap |
|---|---|---|---|
| 5k - 25k | 30.0% | 37.5% | -7.5 |
| **25k - 75k** | **22.9%** | **69.2%** | **-46.3** |

Runs that failed to encrypt are three times more likely to have prepared
first. Across 1,035 runs in that band, a 46-point difference is not noise.

The reason follows from the concurrency. A run that encrypts is destroying
files from the outset, so whatever preparation it does lands in the middle of
that. A run that stops short spends its time on preparation and destroys only
incidentally -- a handful of files, and those necessarily come afterwards. So
the feature is not measuring "did it prepare first" so much as "was
destruction incidental", which is close to the thing being predicted.

That makes it usable but easy to misread. Taken at face value it says
preparation-first predicts *not* encrypting, which inverts the intuition it
was built on.

`prep_overlaps_destroy` and `prep_position_in_destroy` were added to describe
the concurrent case directly rather than through precedence.

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

Removing Kitty left the effect thin:

| | runs | encrypted |
|---|---|---|
| killed processes, excluding Kitty | 7 | 4 (57%) |
| did not kill | 355 | 283 (80%) |

Seven runs and a 23-point difference was not a finding, and the conclusion at
the time was that the whole effect had been seven samples of one Kitty build.

**The rerun does not support that.** On 3,455 analyses the reversal is still
there, and stronger where the runs are busiest:

| band | encrypting | stopped short | gap |
|---|---|---|---|
| 25k - 75k | 3.2% | 8.0% | -4.8 |
| **75k+** | **8.8%** | **35.2%** | **-26.4** |

Stopping services shows the same pattern, consistently, in every band:

| band | encrypting | stopped short | gap |
|---|---|---|---|
| 5k - 25k | 1.9% | 6.0% | -4.1 |
| 25k - 75k | 1.7% | 16.8% | -15.1 |
| 75k+ | 3.8% | 13.0% | -9.2 |

So killing processes and stopping services genuinely accompany *failing* to
encrypt. Two readings fit. A sample that spends its time dismantling the
machine may run out of the analysis window before it starts; or the families
that bother with this are the ones with the most demanding preconditions, and
those are the ones that check, find something missing, and stop.

Either way the direction is the opposite of what preparation was expected to
indicate, and the feature is discriminative because of that rather than in
spite of it.

The Kitty finding stands on its own regardless: two builds of one family,
separable by static import count before either was run, one of which both
kills processes and does not encrypt.

### A useful side effect

The import counts predicted the behavioural split before anything was run:
122 for the builds that encrypt, 119 for those that do not. That is the
static-dynamic correspondence the feature set is meant to capture, appearing
without being looked for.

## Method note

Three findings, three different fates:

| Claim | On 1,492 runs | On 3,455 runs |
|---|---|---|
| shadow deletion accompanies encryption | held under activity control | held, consistent across four bands |
| preparation precedes encryption | false; they are concurrent | still concurrent, but precedence predicts the opposite of what was assumed |
| killing processes predicts failure to encrypt | dismissed as an artefact of two builds in one family | real, and stronger at high activity |

The third row is the uncomfortable one. The artefact explanation was reached
honestly -- seven runs, one family, a complete split inside it -- and it was
wrong because seven runs cannot settle anything. Doubling the sample was what
showed it.

The second and third were both produced by measuring something real and
reading a relationship into it that the data did not support. Ordering was
assumed rather than checked; the process-kill gap was aggregated across
families that behave differently.

The checks that caught them were cheap: measure the delay instead of assuming
its sign, and split by family before believing a rate. Both are worth running
by default on anything the counts appear to show.
