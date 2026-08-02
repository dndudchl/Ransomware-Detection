# Labelling Scheme and Sandbox Reliability

How runs are labelled by hand, why the scheme ended up this shape, and what
had to be fixed in the sandbox before the labels meant anything.

## The labels

| Label | Meaning |
|---|---|
| **A** | Encryption visible on screen |
| **A2** | Not visible on screen, but confirmed from the analysis summary — a ransom note, an appended extension |
| **N** | No encryption observed |
| **X** | Not an encrypting program at all; the `ransomware` label is wrong |
| **F** | The analysis did not stand up — determined automatically, not by eye |

Four earlier drafts were discarded. The reasons are worth keeping, because
each one was a way of asking the labeller a question they could not answer.

### Why N is a single label

An earlier scheme split the negatives:

- **B** — very little activity (a decryptor, an architecture mismatch, a C2
  connection attempt and nothing more)
- **C** — activity, but only preparation (registry edits, services stopped)

The split kept failing on real cases. A sample that requested a key from its
C2 and stopped: preparation, or nothing? A sample that tried to reach
`\\10.10.3.42\c$` with hardcoded credentials and gave up: which?

The distinction being attempted — *is there anything here worth extracting
features from?* — is a measurement, not a judgement. The pipeline already
counts shadow-copy deletions, service stops, process kills, registry writes,
and the delay between preparation and first destruction. Splitting N by eye
duplicated that measurement less accurately, and the criteria drifted between
sessions: the definition of C changed between the first and second batch
without anyone deciding to change it.

So the negatives collapsed to one label, and the sub-structure is recovered
afterwards from the features:

```
N with preparation indicators > 0   -> prepared but did not encrypt
N with all indicators zero          -> did nothing
```

That is reproducible, catches preparation the screen never showed, and does
not need a new label each time a new kind of failure appears.

### Why N does not claim certainty

`N` means *no encryption was observed*, not *no encryption occurred*. The
distinction matters because screenshots are partial evidence: they show the
desktop, not Documents or Downloads, and in-place overwriting leaves
filenames unchanged.

The labeller is therefore never asked to certify an absence. Corroboration
comes from the code, which checks each analysis for ransom notes,
append-renames and decoy damage independently. Where the two disagree, the
analysis is worth a second look; where both find nothing, the negative is
supported by two sources rather than one person's attention.

This turned out to matter. Two runs labelled `N` were found by the code to
have 42 and 48 append-renames respectively. Both were encryption the manual
pass had missed.

### Why X is narrow

`X` exists for one purpose: the `ransomware` label came from MalwareBazaar's
tagging and was not verified. Where a sample is plainly not an encrypting
program, leaving it in teaches the model that ransomware sometimes does
nothing.

The obvious candidate was the decryptor — but a decryptor is not obviously
outside the category. It uses the same cryptographic APIs, enumerates files
the same way, and is built by the same people from the same code. On imports
alone it is indistinguishable from the ransomware it undoes. Excluding it
while keeping every other unverified label would have been inconsistent.

So `X` narrowed to **clear misclassification**: a program with no connection
to ransomware at all. It should be rare. Everything uncertain goes to `N`.

### Why F is not assigned by eye

The tempting rule was "few or no screenshots means the analysis failed". The
data says the opposite.

CAPE's screenshots are captured by the guest-side analyzer and uploaded when
the analysis ends. Behavioural events stream to the host as they happen. So
when a sample kills the analyzer process — which ransomware does routinely,
sweeping up anything not on a whitelist while freeing file locks — the
behavioural record survives and the screenshots do not.

Three runs recorded 3 screenshots each. They had destroyed 98, 97 and 107
decoy files. A screenshot-count rule would have discarded the most
successful runs in the batch.

`F` is therefore determined from evidence the sample cannot suppress:

- an OOM kill of the guest process in the kernel log, timed against the
  analysis window
- CAPE's own "Agent is dead" report
- whether any behavioural data was recorded at all

The separation matters for the numbers, not just for tidiness. `F` runs are
measurement failures — the sample was never tested. Counting them in the
denominator of a trigger rate would report the host's memory pressure as a
property of the malware.

### Why A and A2 stay separate

Both are confirmed encryption, so a model would treat them identically. The
split is kept because **A2's share is a measurement**: it is the fraction of
encryption that a screenshot-only check would have missed.

On the second batch that was 20 of 57, or 35%. The causes are known and
documented: in-place overwriting leaves filenames unchanged, and several
families never reach the decoy folders at all. The number is the evidence for
those claims.

It costs nothing to record — the summary has already been read by the time
the distinction can be made — and cannot be reconstructed later.

## Sandbox reliability

Before the labels were trustworthy, three failure modes had to be found.
Each looked like a property of the samples until it was traced.

### The host ran out of memory

Analyses began failing in runs — tasks 99-101, 247-249, 410-414 — with the
guest unreachable and CAPE reporting a machine it could not stop because it
was already stopped.

The kernel log had the answer:

```
Out of memory: Killed process 133805 (qemu-system-x86)
Out of memory: Killed process 134229 (qemu-system-x86)
Out of memory: Killed process 134365 (qemu-system-x86)
```

Three kills in half an hour. The host had 7.7 GB with 4 GB allocated to the
guest, leaving CAPE, the OS, and the parsing of 100 MB report files to share
the rest; swap was 92% consumed. Raising the host to 10 GB ended it — a full
night of analysis with no failures.

The consecutive-failure pattern is what identified it. Random sample
problems do not arrive in blocks; sustained memory pressure does.

### CAPE lost its machine registration

Separately, CAPE would reach a state where it believed no analysis machine
existed, and failed every queued task in milliseconds:

```
Task #171: Failing unserviceable task because no matching machine could be
found. Requested tags: 'x86'. Available machine tags: {}
```

The empty tag dictionary is the point: not a mismatch, no machine at all. The
service stayed `active` throughout — it ran for 33 hours across the incident
— so service health was useless as a signal. Restarting re-registered the
machine.

This cost 42 samples in one night. Because failures take milliseconds rather
than minutes, an overnight queue is consumed almost instantly. A health check
now watches the log for that signature every ten minutes, restarts CAPE,
confirms the machine re-registered, and returns the affected samples to
pending.

### Ransomware kills the monitoring agent

The remaining failures are caused by the samples, but not deliberately. The
sequence in one analysis:

```
14:33:23  bcdedit.exe x2          disable recovery
14:33:24  Agent unreachable       one second later
14:33:24  vssadmin.exe            delete shadow copies
14:33:25  WMIC.exe                shadowcopy delete
```

The agent runs as `python.exe`. Ransomware freeing file locks kills processes
in bulk, and the agent is not on anybody's whitelist. `Connection refused`
rather than `No route to host` confirms the guest is alive and only the agent
is gone.

Data already streamed to the host is kept, so these runs are usually still
classifiable — the thresholds are low enough that a few seconds of encryption
registers. What is lost is the screenshots and everything after the agent
died, which means the recorded damage is a lower bound.

## Retrying what should be retried

Distinguishing "this sample does nothing" from "this analysis never happened"
decides whether re-submission is worth the sandbox time. The rules, in order:

1. CAPE reported the guest agent dead -> retry, whatever else is true.
2. Behavioural data was recorded -> do not retry; the sandbox worked and the
   sample was simply quiet.
3. An OOM kill falls inside the analysis window -> retry.
4. The analyzer said it could not launch the file -> do not retry; wrong
   architecture or a corrupt PE will fail again.
5. No data and the analyzer log stops mid-run -> retry.

Rule 2 is placed above the rest deliberately. Earlier versions asked whether
the log ended cleanly, then whether the call count cleared a threshold; both
misread quiet successes as failures. What the question actually needs is
whether the sandbox observed the guest — not whether the guest was busy.

A simpler heuristic was implemented alongside for comparison: retry anything
with no screenshots. Across 345 analyses the two agreed 337 times. The eight
disagreements were all cases where the guest died after producing
screenshots — runs the simpler rule would have silently kept.
