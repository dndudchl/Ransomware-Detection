# Results as they stand — 19 August

Written because the experiment count has passed the point where the picture
holds in one head. Every run below is real and reported with the condition it
was measured under, because several of them appear to contradict each other
and only the condition explains why.

---

## 1. The data

### Collected

| archive | prefix | n | what |
|---|---|---|---|
| reports_a / reports_b | — / B | 3,455 | ransomware, MalwareBazaar |
| benign_a / benign_b | NA / NB | 1,563 | DikeDataset |
| grid_reports a/b | G / GB | 993 | designed grid, 10 shapes × 5 volumes × 2 orders × 3 toolchains |
| hn4_reports a/b | O / OB | 300 | traversal-order re-run, control repaired |
| hn2_reports a | HN2 | 203 | Sysinternals, PortableApps, documents |
| hn2_reports b | HN3 | 273 | installers (first round), scripts |
| inst_reports a/b | I / IB | 135 | installers (second round, silent flags) |
| hardneg | H | 68 | first-round variants |
| wintools_reports | W | 27 | robocopy, xcopy, takeown, icacls, forfiles |

About 7,000 reports.

### Ransomware verdicts

| verdict | n | meaning |
|---|---|---|
| TRUE_ENCRYPTION | 1,886 | attacked the planted decoys |
| NO_VICTIM_ACTIVITY | 737 | ran but did not touch the decoys — 552 of these destroyed files elsewhere |
| WEAK_VICTIM_ACTIVITY | 13 | some decoy damage, below threshold |
| FAILED | 819 | too little activity to have run; 421 under 100 calls |

Only 58 of the non-encrypting runs have a corroborating axis, which is why
the extended-positive experiment uses all 750 rather than a filtered subset.

### Sample classes

`source` records which pipeline a row arrived through, which is not the same
question as who wrote the program. `klass` answers the second:

| klass | n | of which open 50+ files | composition |
|---|---|---|---|
| ransomware | 1,849 | 1,776 (96%) | encryption-reaching only |
| benign_active | 1,034 | 115 (11%) | DikeDataset 716 + real software 318 |
| constructed | 1,657 | 1,495 (90%) | grid, order re-run, matrix, first-round, our scripts and wrappers |
| benign_inert | 847 | — | never executed, excluded |

The 115 figure was 6 before the second installer batch. It is the reason
that batch mattered.

### Features

| group | n | note |
|---|---|---|
| static | 9 | 5 more are in the code but absent from the CSV; 3 of the 9 need the run |
| volume | 22 | |
| sequence | 13 | |
| relation | 28 | |
| indicator | 10 | |
| destruction | 12 | |
| **subtotal** | **94** | five redundant columns removed (r ≥ 0.94) |
| has_* | 20 | behaviour presence, MITRE-checked vocabulary |
| ord_* | 36 | behaviour-pair order, coverage ≥ 10% (187 exist) |
| **total** | **150** | |

The 200-column API transition matrix is still in the CSV but in no group.

Two cross-cutting axes over the same 150 columns:

- **individual (A)** 87 — what happened and how much
- **sequence (S)** 63 — anything that depends on the order of two events
- **A_generic** 42 — individual with every ransomware-specific column removed
  (imp_*, n_shadow_delete, has_ransom_note, …), selected by documented design
  intent rather than by measured class overlap, so the label plays no part
- **A_reduced** 64 — individual minus the aggregate ratios and read-write set
  relations

---

## 2. Evaluation conditions — the thing that explains the contradictions

| tag | training negatives | measured negatives | held-out n |
|---|---|---|---|
| `cov` | all 2,691 | fixed 20% | 555 |
| `cov` + negative CV | 4/5 rotating | **all 2,691** | 2,691 |
| `cov_noconstructed` | benign_active only | benign_active only | 1,034 (with CV) |
| `cov_heldout` | benign_active only | + all 1,657 constructed | 1,861 |
| `volume shift` | runs under 300 files | runs at 300+ files | 961 |
| `wide2` | positives extended to 2,584 | fixed 20% | 555 |

**A rate quoted without its condition is meaningless here.** The same model
scores 0.003, 0.011 and 0.373 depending on which row above applies.

Negative cross-validation was added because a fixed 20% split measures only
about 210 negatives, so a rate of 0.005 rests on one flagged program and
cannot be distinguished from 0.010. Rotating five ways scores every negative
exactly once, by a model that did not train on it.

---

## 3. Results, ranked by strength of evidence

### 3.1 Volume shift — strongest

Train on runs opening under 300 files (478 positive / 1,730 negative),
measure on runs opening 300 or more (1,371 positive / 961 negative). In that
band every sample is high-activity, so a count cannot separate the classes,
and the threshold learnt from low-volume data is in the wrong place.

| group alone | n feat | recall | FP overall | FP benign_active (51) | FP constructed (910) |
|---|---|---|---|---|---|
| static | 9 | 0.716 | 0.003 | 0.059 | 0.000 |
| volume | 22 | 0.957 | **0.311** | 0.333 | 0.310 |
| sequence | 13 | 0.773 | 0.021 | 0.314 | 0.004 |
| relation | 28 | 0.960 | **0.030** | 0.059 | 0.029 |
| behaviour presence | 20 | 0.963 | 0.045 | 0.275 | 0.032 |
| order (behaviour) | 36 | 0.963 | 0.015 | 0.098 | 0.010 |
| A + relation | — | — | 0.006 | 0.059 | 0.003 |

Paired, on the same 961 programs:

| comparison | only 1st | only 2nd | p |
|---|---|---|---|
| volume vs relation | 275 | 5 | 1.5e-74 |
| volume vs order | 295 | 10 | 5.3e-74 |
| volume vs behaviour presence | 286 | 30 | 1.5e-53 |
| relation vs order | 27 | 12 | 0.024 |
| A(behaviour) vs A + relation | 39 | 2 | 7.8e-10 |

**What this supports.** Count-valued features learn a threshold that moves
with scale; ratios between events on the same target do not. The effect is
55:1 with a mechanism, not a few samples.

**What it cannot support.** 910 of the 961 measured negatives are our own
constructed samples; only 51 are software someone else wrote. The
order-beats-relation result (p = 0.024) reverses on those 51 (relation flags
3, order flags 5), so it is a fact about the imitations. And static alone
scores 0.003, better than relation, because it does not use volume at all —
so the honest claim is "volume is fragile under scale shift", not "ratios are
uniquely robust". Static cannot stand alone at recall 0.716.

### 3.2 Negative-set composition — largest effect, no statistics needed

The false positive rate moved from 0.794 to 0.003 with the feature set
unchanged. What moved it was the diversity of behavioural kinds in training,
not the number of copies: 0 negatives 0.794, 163 kinds 0.245, 279 kinds
0.085, full set 0.012. Saturation flattens around 1,500 training negatives.

The same model, three conditions:

| condition | FP |
|---|---|
| constructed in training and in evaluation | 0.003 |
| constructed removed entirely | 0.011 |
| constructed in evaluation only | 0.373 |

**What this supports.** A single false positive rate over a hard-negative set
describes how that set was assembled. Constructed variants are flagged at
zero under every feature group, so they enter the denominator and never the
numerator: building more of them lowers the reported rate without the
detector having changed.

### 3.3 M1 — negative cross-validation, relation's contribution

`cov`, 5 rotations, every one of 2,691 negatives scored once.

| group | benign_active (1,034) | constructed (1,657) | overall |
|---|---|---|---|
| A (behaviour presence, 20) | 0.0174 | 0.0115 | 0.0137 |
| S1 (relation, 28) | 0.0193 | 0.0054 | 0.0108 |
| S2 (order, 36) | 0.0155 | 0.0205 | 0.0186 |
| S1 + S2 | 0.0077 | 0.0060 | 0.0067 |
| A + S1 | 0.0097 | 0.0048 | 0.0067 |
| A + S2 | 0.0174 | 0.0109 | 0.0134 |
| A + S1 + S2 | 0.0087 | 0.0054 | 0.0067 |
| A_generic (42) | 0.0116 | 0.0024 | 0.0059 |
| A_generic + S1 + S2 | 0.0077 | 0.0030 | 0.0048 |

Paired:

| comparison | only 1st | only 2nd | p |
|---|---|---|---|
| A vs A + S1 | 30 | 11 | **0.004** |
| A vs A + S1 + S2 | 31 | 12 | 0.005 |
| A vs S1 + S2 | 31 | 12 | 0.005 |
| A vs A + S2 | 7 | 6 | 1.000 |
| A_generic vs A_generic + S1 | 1 | 1 | 1.000 |
| A_generic vs A_generic + S1 + S2 | 5 | 2 | 0.453 |
| A vs A + S1, benign_active only | 13 | 5 | 0.096 |
| A vs S1 + S2, benign_active only | 15 | 5 | 0.041 |

**What this supports.** Relation adds information to behaviour presence,
significantly. A + S1 and A + S1 + S2 are indistinguishable from each other,
so the whole gain is relation.

**What it cannot support.** The same comparison on `cov_noconstructed` gave
p = 0.824. The significance depends on constructed samples being in
training. And A_generic is already strong enough that nothing improves it,
so experiment 2 failed as a stage for measuring S.

### 3.4 S2 — extended positive class, shortcut learning

Positives extended to 2,584 (1,849 encryption-reaching + 735 that executed
without reaching it; FAILED excluded). Recall by verdict:

| group | TRUE_ENCRYPTION | NO_VICTIM_ACTIVITY |
|---|---|---|
| A (behaviour presence) | 0.977 | 0.560 |
| S1 + S2 | 0.995 | 0.621 |
| A + S1 + S2 | 0.995 | 0.615 |
| A_generic | 0.998 | **0.734** |
| A_generic + S2 | 0.998 | 0.746 |

**What this supports.** The model relies partly on encryption as a shortcut:
it catches 98% of runs that reached encryption and 56% of runs that did not.
Removing the ransomware-specific columns raises the latter to 0.73, which
quantifies where the shortcut comes from.

**What it cannot support.** The negative side of this run used a fixed split
with 204 benign_active held out, and there A_generic's false positives rose
to 0.108 from A's 0.025 — the opposite of M1. With 204 samples and no
cross-validation that column is not usable for comparing groups. Read S2 on
the positive side only.

### 3.5 S1 — unseen constructed

Constructed forced out of training, kept in evaluation. Fixed split.

| group | benign_active (204) | constructed (1,657) |
|---|---|---|
| A (behaviour presence) | 0.0147 | 0.577 |
| S1 (relation) | 0.0196 | 0.493 |
| S2 (order) | 0.0049 | 0.502 |
| A + S1 | 0.0147 | 0.472 |
| A + S1 + S2 | 0.0196 | 0.458 |
| A_generic | 0.0049 | 0.425 |
| A_generic + S1 + S2 | 0.0098 | **0.375** |

**What this supports.** An imitation the model has never seen is flagged
about half the time whatever the feature set. Adding S reduces it (0.577 →
0.458), and removing the ransomware-specific columns reduces it more (0.425),
which is consistent with 3.4: those columns are what the imitations copied.

**What it cannot support.** This is a rate on samples we wrote. Low means the
imitations were poor as much as it means the detector generalises. It belongs
in the limitations, not the headline.

### 3.6 Order — a negative result, and why

Order features do not add to individual features. Five separate attempts:

| test | condition | result |
|---|---|---|
| A vs A + order | cov, negative CV | 7 vs 6, p = 1.000 |
| A_reduced vs + order | noconstructed, CV | 4 vs 4, p = 1.000 |
| A_generic vs + order | cov, CV | 4 vs 2, p = 0.688 |
| individual vs + order | noconstructed, CV | 1 vs 3, p = 0.625 |
| three abstraction levels | noconstructed, CV | api 0.127, file 0.029, behaviour 0.022 |

Only the API level separates from everything else, and it separates as the
*worst*, which is consistent with the 200-column transition matrix having
failed.

**The structural reason, which is the actual finding.** A pairwise order
feature is defined only when both behaviours occurred. Of 86 pairs measurable
in 10% or more of ransomware, exactly **one** is measurable in 10% or more of
active benign software:

| pair | ransomware | active benign |
|---|---|---|
| WALLPAPER_SET → REGISTRY_WRITE | 28% | 16% |
| DIR_ENUMERATE → FILE_RENAME | 87% | 1% |
| DIR_ENUMERATE → FILE_ENCRYPT | 84% | 4% |
| FILE_ENCRYPT → RANSOM_NOTE | 73% | 0% |
| … 82 more | | ≤ 9% |

Ordinary software does not perform the behaviour *combinations* ransomware
performs, so there is no sample left in which to ask about their order. The
combination has already separated the classes. An order feature over such a
pair degenerates into `has_A AND has_B`, which is why it matches presence
features and adds nothing to them.

**One exception worth stating.** On the single pair measurable in both
classes, the order does differ sharply: WALLPAPER_SET → REGISTRY_WRITE is
0.35 in ransomware and 0.98 in benign. And presence gets four behaviours
backwards where order does not — WALLPAPER_SET is present in 92% of active
benign against 52% of ransomware, but DIR_ENUMERATE → WALLPAPER_SET is 0.78
against 0.02. So order carries information in principle; there is just
almost nowhere to measure it.

### 3.7 Behaviour vocabulary

Twenty tokens, derived by reading eight ransomware reports and then checked
against MITRE ATT&CK ransomware techniques for omissions.

Kept: SHADOW_DELETE, RECOVERY_DISABLE, BACKUP_DELETE, FIREWALL_DISABLE,
EVENTLOG_CLEAR, PROCESS_ENUM, PROCESS_KILL, SERVICE_ACCESS, RM_SESSION,
DIR_ENUMERATE, FILE_ENCRYPT, FILE_RENAME, FILE_DELETE, CRYPTO_API,
RANSOM_NOTE, WALLPAPER_SET, REGISTRY_WRITE, PERSIST_SCHTASK, SELF_COPY,
NETWORK.

Dropped after checking twelve reports, because CAPE records nothing for them:
SHEmptyRecycleBin, CreateService, GetLogicalDrives, WNetOpenEnum, self-delete
via cmd, and NtDelayExecution (present in everything, therefore noise).

**Two names are wrong and must be changed in the thesis.** `FILE_ENCRYPT`
detects 20 or more files read and written under the same stem — it checks no
entropy and no crypto call, and 30% of active benign software triggers it.
`RANSOM_NOTE` detects one file name written into five or more directories,
with no string matching. Calling them what they are — same-file rewrite, and
multi-directory document — avoids a circular claim.

### 3.8 Eight families, four mechanisms

Reading eight encrypting families by hand: no API appears within three calls
of a write in all eight. They implement read-transform-replace through at
least four mechanisms — stream read/write with a seek, mapped section,
write-to-temp then MoveFile, and CryptEncrypt. This is why no API-level order
generalises across families, and it is the mechanistic reason behind 3.6.

### 3.9 A measurement bug worth reporting

`explore_relational.api_stream()` concatenates every process in the report.
explorer.exe — the desktop shell reacting to file-change notifications, the
same pid in every run, started before the sample — is 50–77% of the call
count. Restricting to the sample's own process tree moves the category switch
rate in opposite directions for the two classes (installer 0.38 → 0.46,
ransomware 0.38 → 0.20). The bystander noise had been making them look alike.
The existing sequence features were measuring the shell as much as the
sample. **Not yet fixed in the pipeline.**

---

## 4. What the thesis can claim

Ordered by how well the data supports it.

1. **A false positive rate describes the negative set as much as the
   detector.** 0.794 → 0.003 with features unchanged; the same model at
   0.003, 0.011 and 0.373 across three conditions; constructed variants
   flagged at zero under every feature group.

2. **Count-valued features are fragile under a shift in scale, and features
   describing relations between events on the same target are not.**
   p = 1.5e-74, effect 55:1, with a mechanism.

3. **Relations between events add information beyond the presence of the
   events.** A → A + relation, p = 0.004 on 2,691 negatives, p = 0.041 on
   active benign alone. Order does not, five ways.

4. **Order cannot be measured where the combination already separates.**
   85 of 86 pairs are undefined in more than 90% of active benign software.
   This is a property of the problem, not of the sample size.

5. **Features derived from knowing what ransomware does cost recall on
   ransomware that does not do it.** Removing them raises recall on
   non-encrypting runs from 0.560 to 0.734.

The anchor — relations between events rather than individual events — holds,
narrowed from "A then B" to "events on the same target".

---

## 5. Known gaps

- 51 real programs open 300+ files, so the volume-shift result rests on
  constructed samples for 95% of its measured negatives.
- The behaviour vocabulary was fixed by reading eight reports; if those eight
  families fall in an evaluation fold there is a small leakage.
- Order pairs were selected by coverage over the whole corpus, which does not
  use the label but is not fold-internal either.
- Negatives are split at random in cross-validation, so two versions of the
  same program can land on opposite sides. `kind_of()` grouping prevents this
  in the fixed split but was not carried into the rotations.
- `api_stream` still includes explorer.exe (3.9).
- static is reported as 9 features; 5 named in the code never reach the CSV.
