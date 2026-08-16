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

That is measurable. On the benign set, leave-one-family-out across 21
families gives an AUC of 1.000, and restricting to the 301 benign runs the
sandbox actually recorded activity for does not change it. The comparison is
not hard enough to be informative in either form.

So sixty-eight programs were written to be hard: as active as ransomware,
touching the same decoy files, and doing something a person would ask for.

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

## What the eight failures of the decoy set look like from here

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

## What to take from it

The headline figure and the false positive rate came from the same model in
the same run. An AUC of 1.000 across 21 unseen families, and thirteen
percent of active legitimate software classified as ransomware, are not in
tension: the model learned to recognise a program that touches many files,
which is sufficient for a benign set that mostly does not run, and which
fires on every legitimate program that does.

Nothing in the standard evaluation would show this. The benign set gives
0.006. It takes negatives built to be as busy as the positives, and the
count on its own is not enough either -- most of what was flagged had in
fact destroyed the user's files. The number worth reporting is what remains
after separating the cases where the detector was right, the cases where no
detector could be right, and the cases where it could see nothing at all.
