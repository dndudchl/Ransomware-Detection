# Hard negatives: what a detector cannot tell apart from ransomware

## Why they had to be built

Every measurement before this one compared ransomware against ransomware.
Of 3,455 analyses, 1,886 reached encryption and 1,569 executed without doing
anything, and asking which features separated those two answered a narrower
question than it appeared to: what accompanies reaching the encryption stage.
The answer was dominated by activity, because runs that stopped short did
less of everything.

Benign software was supposed to fix that. It did not. Of 1,563 programs from
DikeDataset, 1,262 never executed at all -- they were libraries, they wanted
an argument, they printed usage and exited. On the dynamic features those
rows are zero, so any feature that counts anything separates them perfectly,
and a model trained against them learns to recognise a program that ran.

Raising the count would not help, and the distribution shows why. Across a
sample of 150:

| API calls recorded | programs |
|---|---|
| none -- no process at all | 78 |
| 1 - 99 | 13 |
| 100 - 499 | 27 |
| 500 - 4,999 | 20 |
| 5,000 or more | **12** |

The median encrypting run makes about 36,000 API calls. Eight percent of the
benign set reaches five thousand. Lowering the threshold that decides whether
a sample executed would move a few dozen rows from one column to another
without making any of them a harder comparison: a program that made two
hundred calls touched almost no files, and is as trivially separable as one
that made none.

Collecting more of the same would reproduce the same distribution. The
negatives this study needs do not exist in a corpus of executables run
without arguments, which is what led to building them.

That is measurable. On the benign set, leave-one-family-out across 21
families gives an AUC of 1.000, and restricting to the 301 benign runs the
sandbox actually recorded activity for does not change it. The comparison is
not hard enough to be informative in either form.

So sixty-eight programs were written to be hard: touching the same decoy
files as the ransomware does, in the same folders, and doing something a
person would ask for.

They did not turn out to be as active as ransomware, and the gap matters
enough to state before anything else. Measured afterwards:

| | API calls (median) | distinct paths (median) |
|---|---|---|
| ransomware, encrypting | 70,788 | 578 |
| hard negatives | 1,305 | 95 |
| benign that executed | 1,182 | 3 |

By call count the hard negatives sit with the benign programs, not the
ransomware -- fifty times quieter than what they were meant to be compared
against. A small C program that reads a file and writes it back makes few
API calls; a ransomware family also enumerates drives, queries the registry,
checks for a debugger, spawns helpers and calls cryptographic routines, and
most of the fifty-fold difference is that.

What separates the hard negatives from the benign set is not how much they
did but how many files they did it to: 95 distinct paths against 3. That
turns out to be the whole story of the false positive rate, and is picked up
again below.

## What was built

Three families of variant, each isolating a different thing.

**Staged binaries (7).** The same work cut off at a different point each
time, so that each does everything the one below it does and one thing more:
enumerate and read, then write each file back, then delete the original,
then rename onto a shared extension, then drop a note in every folder, then
change the wallpaper, then remove shadow copies. Every one of those, on its
own, is something ordinary software does. The question is how many can be
combined before the combination is indistinguishable from ransomware.

**A behaviour matrix (37).** Each variant differs from one baseline in
exactly one respect -- the method of transformation, the scope, the volume,
the file types targeted, the timing, the naming rule -- so that a feature
which responds to that change is the feature measuring it. Including the
pair the whole exercise turned on: `m6_crypto` reads, encrypts with
`CryptEncrypt`, writes and deletes; `m2_nocrypt` does the identical sequence
without the encryption step.

**Wrappers around installed tools (24).** Nothing written for the
experiment: 7-Zip, `cipher`, `compact`, `robocopy`, `certutil`, `findstr`,
`takeown`, Defender, Chrome, Word and Acrobat. 7-Zip appeared in 681 of the
ransomware analyses and Adobe in 694, so the guest genuinely has them, and a
detector that fires on these is producing a false positive on software an
administrator runs deliberately.

## The verdict logic against them

Before any model, the rule-based verdict was run on all sixty-eight.

| | count |
|---|---|
| correctly judged | **62 of 68** |
| false positives | 1 |
| variants whose own decoy names caused the alarm | 2 |
| failed to execute | 2 |
| reclassified after inspection | 1 |

The single genuine false positive is `e1_note_only`, which writes a file
named `RESTORE_INSTRUCTIONS.txt` into twelve directories and touches nothing
else. It is called encryption because the note axis, on a name that states
its purpose across that many folders, is sufficient on its own. A licensing
tool or a backup notice would do the same thing.

Two others -- `m5_drop` and `m8_keep` -- fired because a decoy file happened
to be named `read me.txt`, and the copies they made were therefore called
`read me.txt.matrix`. That is a flaw in the decoy set, not the verdict.

`tool_certutil` was recorded as a miss and then reclassified: `certutil
-encode` writes a new `.b64` file and leaves the original in place, so it
destroys nothing and the verdict was right.

## The model against them

Trained with 21-fold leave-one-family-out on 1,849 encrypting runs against
1,563 benign, with the hard negatives held out of training entirely.

| feature groups | features | AUC | TPR | FP benign | FP hard |
|---|---|---|---|---|---|
| static | 9 | 0.975 | 0.899 | 0.060 | 0.060 |
| + volume | 33 | **1.000** | 1.000 | 0.006 | **0.779** |
| + sequence | 43 | 1.000 | 0.999 | 0.007 | 0.777 |
| + relation | 68 | 1.000 | 1.000 | 0.005 | 0.738 |
| + destruction | 80 | 1.000 | 1.000 | 0.006 | 0.718 |
| | | | | | |
| volume alone | 24 | 1.000 | 0.997 | 0.009 | 0.788 |
| sequence alone | 10 | 0.993 | 0.974 | 0.044 | 0.226 |
| relation alone | 25 | 0.999 | 0.972 | 0.006 | 0.741 |
| destruction alone | 12 | 0.999 | 0.963 | 0.006 | 0.645 |

The second and third columns come from the same model. Adding the volume
features takes the AUC to 1.000 and the hard negative rate to 0.78 in the
same step, and volume alone reproduces both. Whatever the model learned when
its score became perfect is also what makes it call three quarters of the
hard negatives ransomware.

The relational features lower that rate by 4 to 8 points depending on the
configuration. The direction is consistent across every variant of the
experiment, and on sixty-eight samples it is five programs. It is a real
effect and it is a small one, and both halves of that should be said.

## Taking the number apart

"Forty-four of sixty-eight were classified as ransomware" is not a false
positive rate. The sixty-eight do not fail in the same way, and three of the
four ways they fail are not failures.

| category | flagged | what it means |
|---|---|---|
| **destroys** — the files are gone | 35 of 38 | correct; a detector is meant to fire |
| **ambiguous** — same trail, different reason | 3 of 3 | defensible; consent leaves no trace |
| **invisible** — destroyed but unrecorded | 0 of 2 | the serious result, in the other direction |
| **harmless** — touched nothing that existed | **9 of 24** | the only genuine false positives |

Nine of sixty-eight, or thirteen percent.

### The nine

| variant | score | what it did |
|---|---|---|
| `tool_open_docs` | 1.00 | opened documents in Word and Acrobat |
| `tool_session` | 1.00 | three rounds of opening, reading, closing |
| `w_progfiles_read` | 1.00 | read Program Files, wrote nothing |
| `m8_keep` | 0.99 | wrote a copy beside each document |
| `tool_apps` | 0.98 | notepad, mspaint, 7zFM, calculator |
| `e28_prep_only` | 0.87 | shadow copies, recovery, services |
| `tool_ie_wmp` | 0.78 | Internet Explorer and Media Player |
| `tool_ps_zip` | 0.78 | PowerShell `Compress-Archive` |
| `e1_note_only` | 0.51 | a note in every folder |

Eight of the nine changed no file that already existed. Five did nothing but
read files and start processes. `w_progfiles_read` scores 1.00 for reading
Program Files and writing nothing at all.

`tool_ps_zip` is worth separating out: the rule-based verdict got it right
(`WEAK_VICTIM_ACTIVITY`, one decoy) and the model got it wrong. The two
disagree, and the model is the one that is wrong.

### The two it cannot see

`cipher /e` and `compact /c` rewrite every byte of every document in the
decoy folders. Both are signed by Microsoft. Neither produces a single file
event the sandbox records, because the work is done by the filesystem
driver rather than through the file API the monitor hooks.

Detection rate: zero, under every feature configuration tried, including the
ones with an AUC of 1.000.

This is the same shape as the BlackBasta sample that set `bcdedit
/set safeboot`, rebooted, and encrypted in safe mode outside the analysis
window. The detector is not wrong about what it saw. The behaviour did not
happen where it was looking.

### The one that cannot be separated

`stage2` reads each decoy file and writes the same bytes back to the same
path. So does an editor saving an unchanged document. So does AvosLocker,
which encrypts in place and leaves the filename alone -- and which an earlier
version of the verdict missed for precisely this reason, until `write` was
added to the destructive event list.

There is no file event that distinguishes them. What distinguishes them is
whether the user asked, and that is not in the recording.

## The pair the experiment was built around

`m6_crypto` and `m2_nocrypt` perform an identical sequence of file
operations. One encrypts the buffer with `CryptEncrypt` between reading and
writing; the other does not.

Both scored **1.00**. The model cannot tell them apart, and neither can any
crypto feature in the set.

This is the fourth and final result on that axis. `write_crypto_pearson`
correlated writes against crypto calls per window and was undefined for a
third of encrypting runs, because they never called a Windows crypto API at
all. `fs_crypto_interleave` counted adjacent filesystem-crypto transitions
and had a median of zero on both sides. Buffer entropy was present in 22% of
runs. Each of those was a coverage argument -- the feature could not be
computed often enough to be useful.

This is not a coverage argument. Both members of the pair are fully
observed, they differ in exactly one respect, and the difference makes no
difference. Families implement their own cryptography, link it statically,
or call it through paths the monitor does not hook, and the crypto axis
should be reported as closed.

## Where the destruction actually happens

The decoy set is 176 files across Desktop, Documents and Downloads, and the
first axis of the verdict asks how many of them were destroyed. Measured
across 400 ransomware analyses, that axis is looking at a minority of the
damage.

Totalling every destructive event:

| location | share of all events |
|---|---|
| C:\Program Files | 66.8% |
| AppData | 12.9% |
| elsewhere | 11.6% |
| **the decoy folders** | **4.6%** |
| elsewhere under Users | 2.4% |
| C:\Windows | 1.7% |

That total is misleading on its own, and the correction is worth making
because the obvious reading of it is wrong. Per run, among the 244 analyses
with at least twenty destructive events, the median share landing in Program
Files is **0.0%**. More than half of the runs barely touch it. The 66.8% is
produced by a small number of very active analyses -- one Phobos sample
destroyed 6,354 files inside Acrobat DC on its own -- and says more about
those than about the set.

Per run, the destruction has no single home:

| where the run concentrated its destruction | runs |
|---|---|
| Program Files | 37% |
| elsewhere | 30% |
| the decoy folders | 17% |
| AppData | 16% |

And of the 270 analyses with any file activity, 143 never touched a decoy
and 127 did.

### Why, is not established

The natural explanation is the analysis window. A run that walks C:\
alphabetically meets Program Files long before Users, and ten minutes is not
long enough to finish, so the decoys are never reached. That would make the
distribution an artefact of the timeout rather than a property of the
malware.

The data does not support it. Comparing the two groups:

| | analyses | destructive events (median) | run length (median) |
|---|---|---|---|
| reached a decoy | 127 | 749 | 677 s |
| never reached one | 143 | 441 | 676 s |

If the timeout were cutting runs off mid-traversal, the group that failed to
arrive should have been the busier one -- occupied elsewhere until the clock
ran out. It is the quieter one, by a factor of nearly two, and both groups
ran for the same length of time. Nothing was truncated; the runs that missed
the decoys simply did less.

Traversal order, family-specific targeting and the sheer size of Program
Files relative to the decoy folders are all plausible and none is tested
here. What can be said is the observation itself.

### What follows from it either way

The corroboration design is vindicated by this more than by anything else in
the project. The other three axes -- append-renames, the ransom note, the
shared replacement extension -- take no account of path, so they see the
whole disk. Had the verdict rested on decoy destruction alone, as its first
version did, it would have been blind to the 143 runs that destroyed things
somewhere else. Those axes were each added in response to a particular miss;
this is the first measurement of how much they carry.

And the limitation of the decoy set is not the one previously recorded.
"Only 176 files" suggests the fix is more files. The distribution suggests
otherwise: the decoys are in the folders that ransomware, in this
environment, reaches least often. Seeding decoys where the destruction goes
would be the useful change, and an awkward one, since those directories
belong to installed software.

The hard negative variants were extended to match once this was measured.
Scopes now cover the user profile, Program Files, an alphabetical walk from
the root, AppData, and a spread across several roots at once, rather than
the first three alone.

## Three limits of the decoy set, seen from here

The decoy set is 176 files across Desktop and Documents, with no executables
in it. Three consequences turned up in this experiment:

- selectivity by file type could only be tested against Program Files,
  because there is nothing else with an executable in it;
- a file named `read me.txt` in the decoy set caused two false positives on
  its own;
- runs that walk `C:\` alphabetically exhaust their ten minutes inside
  `C:\Program Files\Adobe` and never reach the decoys at all. 694 of the
  ransomware analyses touched Adobe; 86 dropped a ransom note into
  `C:\Program Files` itself.

A larger and more realistic decoy set is the single change that would most
improve this work, and it requires rebuilding the guest image and reanalysing
everything, which is why it is future work rather than a fix.

## What the label definition does to two families

Training with every ransomware run as a positive, rather than only those that
encrypted, drops the AUC from 1.000 to 0.980 and raises the hard negative
false positive rate from 0.78 to 0.90. Averages conceal where that comes
from. Per family:

| family | runs | TPR | executed |
|---|---|---|---|
| Qilin | 55 | **0.09** | 11% |
| WannaCry | 33 | **0.09** | 9% |
| GandCrab | 30 | 0.60 | 57% |
| Conti | 169 | 0.78 | 80% |
| LockBit | 179 | 0.99 | 90% |

Two families are almost entirely missed, and the third column explains it.
Of the 55 Qilin samples, 49 never executed; of the 33 WannaCry samples, 30
did not. Median API call counts were 406 and 199, below the five hundred the
verdict logic uses to decide a sample ran at all, and the median number of
file paths touched was one.

The model did not fail to generalise to these families. It was asked to
identify, from behaviour, samples whose behaviour was not recorded. Among
the six Qilin runs that did execute, five were detected.

WannaCry has a specific reason: it queries a hardcoded domain on startup and
exits if the domain resolves. The sandbox has internet access, the domain has
been sinkholed since 2017, and so the sample terminates. Qilin's failures are
less specific -- packing, missing arguments, or waiting on a command server
that no longer answers.

This is the cost of the broader label. Including runs that executed without
doing anything puts 1,505 positives into the training set whose dynamic
features are indistinguishable from the 1,262 benign programs that also did
nothing, and the model's threshold moves to accommodate them. The narrower
label avoids that and buys a perfect score by only ever being asked about
samples that ran.

Neither is the correct choice. A detector deployed in the world has to handle
ransomware that has not triggered yet; a study of what encryption looks like
cannot learn it from runs where no encryption occurred. Both are reported
here because the gap between them is larger than the gap between any two
feature sets tried.

## Changing the classifier does not change the result

An AUC of 1.000 alongside a false positive rate of 0.78 invites the question
of whether gradient boosting is at fault. Four classifiers and two anomaly
detectors, all under the same 21-fold family split:

| approach | AUC | FP benign | FP hard | precision at 0.1% |
|---|---|---|---|---|
| XGBoost | 1.000 | 0.006 | 0.716 | 0.0014 |
| random forest | 1.000 | 0.007 | 0.704 | 0.0014 |
| logistic regression | 0.998 | 0.004 | 0.603 | 0.0017 |
| k-nearest neighbours | 0.998 | 0.005 | 0.571 | 0.0017 |
| one-class, fitted on benign | 0.996 | 0.050 | 0.686 | -- |
| one-class, fitted on ransomware | 0.195 | 1.000 | 1.000 | -- |

Three things follow.

**k-nearest neighbours reaches 0.998.** It fits nothing; it finds the closest
training example and copies its label. A problem solvable that way did not
require a model, and the 1.000 from gradient boosting is a property of the
data rather than an achievement of the algorithm.

**Every classifier flags most of the hard negatives**, between 57 and 72
percent. Linear, ensemble and instance-based methods agree, so the false
positives are not an artefact of any one inductive bias.

And the comparison with the benign programs that executed makes the boundary
precise. The two groups make almost the same number of API calls -- a median
of 1,182 against 1,305 -- and are classified completely differently: 0.6%
against 72%. The one thing separating them is the number of distinct files
touched, 3 against 95.

So the model is not thresholding on how much a program did. It is
thresholding on how many files it did it to, and the line sits at somewhere
under a hundred. Ransomware in this set touches a median of 578. A backup
script, a bulk rename, an archiver, an indexer -- anything that opens a
folder's worth of documents -- is on the wrong side of it.

This is the same conclusion the feature importances point at from the other
direction: n_paths alone accounts for 45% of the gain across 80 features.
Two independent measurements agree on which column is making the decision.

**The simpler models do better on them.** k-nearest neighbours is at 0.571
against XGBoost's 0.716. The stronger learner fits the activity signal more
sharply and pays for it on software that is active for legitimate reasons --
the opposite of what a leaderboard would reward.

**Fitting on benign alone reaches 0.996** without seeing a single ransomware
sample. Whatever the labels contributed, it was not much: separating the two
sets did not require knowing which was which.

The last column is the one to sit with. At a base rate of one program in a
thousand, and using the false positive rate on software that actually runs,
precision is 0.0014. Roughly seven hundred alerts for each true detection,
from a model with an AUC of 1.000.

## What to take from it

The headline figure and the false positive rate came from the same model in
the same run. An AUC of 1.000 across 21 unseen families, and thirteen
percent of harmless software classified as ransomware, are not in tension.
The model learned to recognise a program that opens many distinct files.
That is sufficient for a benign set which mostly does not run, and it fires
on legitimate software that does.

The boundary can be located. Benign programs that executed and hard
negatives make the same number of API calls, 1,182 against 1,305 at the
median, and are classified at 0.6% and 72%. The only thing between them is
how many files each touched: 3 against 95. Ransomware touches 578. Whatever
the model is measuring, the line falls closer to a backup script than to
encryption.

Nothing in the standard evaluation would show this. The benign set gives
0.006 and an AUC of 1.000, and both numbers are true. Finding the boundary
took negatives that touch a folder's worth of files for an ordinary reason,
and the count of how many were flagged is not enough on its own either --
most of what was flagged had in fact destroyed the user's files, and a
detector is supposed to fire on that. The number worth reporting is what
remains after separating the cases where the detector was right, the cases
where no detector could be right, and the cases where it could see nothing
at all.
