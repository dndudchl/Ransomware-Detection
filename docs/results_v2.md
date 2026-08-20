# Results — consolidated, 19 August

Structured as it will appear in the thesis: four main results, three
robustness checks that bound them, and an appendix of everything else. Each
result carries the condition it was measured under, because several appear to
contradict one another and only the condition explains why.

---

# Part I — Data and conditions

## 1. The corpus

### Collected

| archive | prefix | n | what |
|---|---|---|---|
| reports_a / reports_b | — / B | 3,455 | ransomware, MalwareBazaar |
| benign_a / benign_b | NA / NB | 1,563 | DikeDataset |
| grid_reports a/b | G / GB | 993 | designed grid: 10 shapes × 5 volumes × 2 orders × 3 toolchains |
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
| NO_VICTIM_ACTIVITY | 737 | ran but did not touch the decoys; 552 destroyed files elsewhere |
| WEAK_VICTIM_ACTIVITY | 13 | some decoy damage, below threshold |
| FAILED | 819 | too little activity to have run; 421 under 100 calls |

Only 58 of the non-encrypting runs have a corroborating axis, which is why
the extended-positive experiment uses all 750 rather than a filtered subset.

### Sample classes

`source` records which pipeline a row arrived through, which is not the same
question as who wrote the program. `klass` answers the second:

| klass | n | opens 50+ files | composition |
|---|---|---|---|
| ransomware | 1,849 | 1,776 (96%) | encryption-reaching only |
| benign_active | 1,034 | 115 (11%) | DikeDataset 716 + real software 318 |
| constructed | 1,657 | 1,495 (90%) | grid, order re-run, matrix, first-round, our scripts and wrappers |
| benign_inert | 847 | — | never executed, excluded |

The 115 was 6 before the second installer batch. That is why the batch
mattered.

### Features

| group | n | note |
|---|---|---|
| static | 9 | 5 more named in code never reach the CSV; 3 of the 9 need the run |
| volume | 22 | |
| sequence | 13 | |
| relation | 28 | |
| indicator | 10 | |
| destruction | 12 | |
| **subtotal** | **94** | five redundant columns removed (r ≥ 0.94) |
| has_* | 20 | behaviour presence |
| ord_* | 36 | behaviour-pair order, coverage ≥ 10% of 187 that exist |
| **total** | **150** | |

Cross-cutting sets over the same columns:

- **A** 87 — individual: what happened and how much
- **S** 63 — anything depending on the order of two events
- **S1** 28 — the relation group specifically
- **S2** 36 — behaviour-pair order specifically
- **A_generic** 42 — individual minus every ransomware-specific column
  (imp_*, n_shadow_delete, has_ransom_note …), chosen by documented design
  intent rather than measured class overlap, so the label plays no part
- **A_reduced** 64 — individual minus aggregate ratios and read-write set
  relations

The 200-column API transition matrix remains in the CSV but in no group.

## 2. Evaluation conditions

| tag | training negatives | measured negatives | measured n |
|---|---|---|---|
| `cov` | all 2,691 | fixed 20% | 555 |
| `cov` + negative CV | 4/5 rotating | **all 2,691** | 2,691 |
| `cov_noconstructed` | benign_active only | benign_active only | 1,034 |
| `cov_heldout` | benign_active only | + all 1,657 constructed | 1,861 |
| volume shift | runs under the cut | runs at or above the cut | 574–1,289 |
| `wide2` | positives extended to 2,584 | as above | varies |

**A rate quoted without its condition is meaningless here.** The same model
scores 0.003, 0.011 and 0.373 depending on which row applies.

Negative cross-validation exists because a fixed 20% split measures about 210
negatives, so a rate of 0.005 rests on one flagged program and cannot be
distinguished from 0.010. Five rotations score every negative exactly once,
by a model that did not train on it. Where cross-validation is not used —
the held-out and volume-shift conditions, whose definitions require a fixed
partition — the measured n is stated.

---

# Part II — Main results

## R1. The false positive rate is a property of the negative set

Training negatives were varied from none to all; the feature set never
changed.

| active negatives in training | kinds | measured | FP | 95% interval |
|---|---|---|---|---|
| 0 | 0 | 1,975 | **0.667** | [0.646, 0.688] |
| 285 | 129 | 2,406 | 0.180 | [0.165, 0.196] |
| 782 | 408 | 1,909 | 0.017 | [0.012, 0.024] |
| 1,403 | 676 | 1,288 | 0.005 | [0.002, 0.011] |
| 1,901 | 985 | 790 | 0.002 | [0.001, 0.008] |
| 2,381 | 1,253 | 310 | **0.000** | [0.000, 0.012] |

A factor of 330, with the model untouched. Most of it happens in the first
step; the curve is flat past about 1,400.

The same model under three treatments of the constructed samples:

| treatment | FP |
|---|---|
| in training and in evaluation | 0.003 |
| removed entirely | 0.011 |
| in evaluation only | 0.373 |

**Two things to state alongside.** The held-out set shrinks as the training
set grows, so the right-hand interval is wide (0 of 310). And "0 active
negatives" means no *active* negative: 572 DikeDataset rows, median one file
opened, were still in training.

**What this supports.** A single false positive rate over a hard-negative set
describes how that set was assembled. Constructed variants are flagged at
zero under every feature group, so they enter the denominator and never the
numerator: building more of them lowers the reported rate without the
detector having changed.

**What it cannot support.** Training count and kind count rise together here,
so this design cannot separate "more negatives" from "more kinds of
negative". An earlier run suggested kinds mattered more; that comparison is
not reproduced with the enlarged corpus and is not claimed.

## R2. Count-valued features are fragile under a shift in scale

Train only on runs opening fewer than *k* files; measure only on runs opening
*k* or more. Above the cut every sample is high-activity, so a count cannot
separate the classes, and the threshold learnt below the cut is in the wrong
place.

At k = 300 (train 478 positive / 1,730 negative; measure 1,371 positive / 961
negative, of which 910 constructed and 51 real software):

| group alone | n | recall | FP overall | FP real sw (51) | FP constructed (910) |
|---|---|---|---|---|---|
| static | 9 | 0.716 | 0.003 | 0.059 | 0.000 |
| volume | 22 | 0.957 | **0.311** | 0.333 | 0.310 |
| sequence | 13 | 0.773 | 0.021 | 0.314 | 0.004 |
| relation (S1) | 28 | 0.960 | **0.030** | 0.059 | 0.029 |
| behaviour presence (A) | 20 | 0.963 | 0.045 | 0.275 | 0.032 |
| order (S2) | 36 | 0.963 | 0.015 | 0.098 | 0.010 |
| A + S1 | 48 | 0.998 | 0.006 | 0.059 | 0.003 |

Paired, on the 51 programs other people wrote:

| comparison | only 1st | only 2nd | p |
|---|---|---|---|
| volume vs relation | 17 | 3 | 0.0026 |
| volume vs order | 16 | 4 | 0.012 |
| volume vs behaviour presence | 10 | 7 | 0.63 |
| relation vs order | 1 | 3 | 0.63 |
| **A vs A + relation** | **11** | **0** | **0.00098** |
| A vs A + relation + order | 10 | 0 | 0.0020 |

And on the 910 constructed, for comparison: volume vs relation 258 to 2
(p = 3.7e-74), relation vs order 26 to 9 (p = 0.006).

The eleven programs relation rescues are not one kind: procexp and procexp64,
sdelete, PeaZip, Git for Windows, Ghostscript, SiYuan, VSCodium, Geany,
TreeMap, ungoogled-chromium — Sysinternals tools, an archiver, a disk
analyser and five installers. **sdelete is the sharpest case**: it overwrites
and deletes files, the closest legitimate behaviour to encryption, and
relation is what saves it.

**What this supports.** Counts learn a threshold that moves with scale;
relations between events on the same target do not. It holds on software we
did not write, at 11 to 0.

**What it cannot support.** Static also scores 0.003, better than relation,
because it uses no volume at all — so the claim is that *volume is fragile*,
not that ratios are uniquely robust. Static cannot stand alone at recall
0.716. And order beats relation only on the constructed samples (26 to 9);
on the 51 real programs the direction reverses (1 to 3, p = 0.63).

## R3. Order cannot be measured where the combination already separates

Order features do not add to individual features. Five attempts:

| test | condition | result |
|---|---|---|
| A vs A + order | cov, negative CV | 7 vs 6, p = 1.000 |
| A_reduced vs + order | noconstructed, CV | 4 vs 4, p = 1.000 |
| A_generic vs + order | cov, CV | 4 vs 2, p = 0.688 |
| individual vs + order | noconstructed, CV | 1 vs 3, p = 0.625 |
| abstraction levels | noconstructed, CV | api 0.127, file 0.029, behaviour 0.022 |

Only the API level separates from the others, and it separates as the worst —
consistent with the 200-column transition matrix having failed earlier for
the same reason.

**The structural finding.** A pairwise order feature is defined only when
both behaviours occurred. Of 86 pairs measurable in 10% or more of
ransomware, exactly **one** is measurable in 10% or more of active benign:

| pair | ransomware | active benign |
|---|---|---|
| WALLPAPER_SET → REGISTRY_WRITE | 28% | **16%** |
| DIR_ENUMERATE → FILE_RENAME | 87% | 1% |
| DIR_ENUMERATE → FILE_ENCRYPT | 84% | 4% |
| FILE_ENCRYPT → RANSOM_NOTE | 73% | 0% |
| (82 others) | 10–74% | ≤ 9% |

Ordinary software does not perform the behaviour *combinations* ransomware
performs. There is no sample left in which to ask about their order: the
combination has already separated the classes, and an order feature over such
a pair degenerates into `has_A AND has_B`, which is why it matches presence
features and adds nothing to them.

**Order does carry information where it can be measured.** On the one pair
present in both classes the direction differs sharply — WALLPAPER_SET →
REGISTRY_WRITE is 0.35 in ransomware and 0.98 in benign. And presence gets
four behaviours backwards where order does not: WALLPAPER_SET is present in
92% of active benign against 52% of ransomware, but DIR_ENUMERATE →
WALLPAPER_SET is 0.78 against 0.02.

**Why this is a property of the problem, not the sample.** Collecting more
benign software does not help: the reason those pairs are undefined is that
backup tools do not enumerate processes and installers do not rewrite files
they read. The scarcity is the signal.

A mechanistic corroboration: reading eight encrypting families by hand, no
API appears within three calls of a write in all eight. They implement
read-transform-replace through at least four mechanisms — stream read/write
with a seek, mapped section, write-to-temp then MoveFile, and CryptEncrypt.
No API-level order generalises across families.

## R4. Domain-knowledge features cost recall on atypical ransomware

Positives extended to 2,584 (1,849 encryption-reaching plus 735 that executed
without reaching it; FAILED excluded). Recall by verdict, negative
cross-validation:

| group | TRUE_ENCRYPTION | NO_VICTIM_ACTIVITY (722) |
|---|---|---|
| A (behaviour presence) | 0.976 | 0.546 |
| A + S1 | 0.992 | 0.613 |
| A + S2 | 0.978 | 0.558 |
| A + S1 + S2 | 0.995 | 0.619 |
| A_generic | 0.999 | **0.742** |
| A_generic + S2 | 0.998 | 0.753 |
| A_generic + S1 + S2 | 0.997 | **0.765** |

**What this supports.** The model relies partly on encryption as a shortcut:
98% of runs that reached it, 55% of runs that did not. Removing the
ransomware-specific columns raises the latter to 0.74, and adding relation
and order raises it to 0.77 — so the shortcut is located in the
domain-knowledge features.

**What it cannot support.** WEAK_VICTIM_ACTIVITY moves 0.400 → 1.000 but has
13 members; it is not quoted. And this recall gain is not free — see B3.

---

# Part III — Robustness and bounds

## B1. The volume-shift result does not depend on the cut

| cut | train / measure | static | volume | relation | order | A | A+S1 |
|---|---|---|---|---|---|---|---|
| 150 | 1,649 / 2,891 | 0.008 | 0.280 | 0.168 | 0.044 | 0.056 | 0.062 |
| 200 | 1,809 / 2,731 | 0.006 | 0.271 | 0.113 | 0.042 | 0.042 | 0.036 |
| 300 | 2,208 / 2,332 | 0.004 | 0.300 | 0.034 | 0.018 | 0.046 | 0.006 |
| 500 | 2,710 / 1,830 | 0.003 | 0.179 | 0.003 | 0.011 | 0.011 | 0.003 |
| 800 | 3,196 / 1,344 | 0.004 | 0.154 | 0.002 | 0.011 | 0.005 | 0.007 |

The cut-300 column reads 0.300 here and 0.311 in R2 because this table takes
the rate the ablation prints over the negatives it counts as benign, while
R2 recomputes it per sample over all 961 measured negatives. Same run, two
denominators; the thesis should quote one of them throughout.

**Volume never recovers.** Every other group improves by an order of
magnitude or more as the cut rises and the training set grows; volume
improves by a factor of two and remains the worst at every cut.

**But relation's marginal contribution is not monotone.** A → A+S1 helps at
200, 300 and 500, and does nothing at 150 (too little training data) or 800
(the other features already reach 0.005). The effect is real in the middle
band and should be reported as band-dependent rather than universal.

## B2. Relation's contribution depends on constructed samples being trained on

Same protocol both columns (negative cross-validation), measured on the 1,034
programs other people wrote:

| feature set | constructed in training | constructed out |
|---|---|---|
| A | 0.0174 | 0.0203 |
| A + S1 | 0.0097 | 0.0184 |
| A + S2 | 0.0174 | 0.0242 |
| A + S1 + S2 | 0.0087 | 0.0135 |

Paired, within each column:

| comparison | constructed in | constructed out |
|---|---|---|
| A vs A + S1 | 13 vs 5, p = 0.096 | 11 vs 9, p = 0.824 |
| A vs A + S2 | 4 vs 4, p = 1.000 | 1 vs 5, p = 0.219 |
| A vs A + S1 + S2 | 14 vs 5, p = 0.064 | 13 vs 6, p = 0.167 |

The two effects interact: removing constructed samples from training costs
0.003 for A and 0.009 for A + S1, three times as much. Relation is the
feature set that most depends on having seen the imitations.

**Consequence for R2.** The 2,691-negative result reported earlier as
p = 0.004 pools constructed with real software. On real software alone it is
p = 0.096. R2's 11-to-0 stands because it is measured on real software in the
shifted band; the ordinary-split claim does not.

## B3. Recall on atypical ransomware trades against false positives

The same runs behind R4, negative side, cross-validated:

| group | FP real sw (1,034) | FP constructed (1,657) | recall NO_VICTIM |
|---|---|---|---|
| A | 0.048 | 0.036 | 0.546 |
| A + S1 | **0.071** | 0.010 | 0.613 |
| A + S1 + S2 | 0.073 | 0.009 | 0.619 |
| A_generic | **0.086** | 0.005 | 0.742 |
| A_generic + S1 + S2 | 0.079 | 0.005 | 0.765 |

Paired on real software: A vs A + S1 is 20 to 43, **p = 0.005 in the wrong
direction** — adding relation flags 43 programs it had not, and rescues 20.

The pooled rate falls (0.041 → 0.033) only because constructed is 62% of the
denominator. Split by kind the signal reverses.

**Reading.** Widening the positive class to include ransomware that did not
encrypt loosens the boundary. Recall on those runs rises from 0.55 to 0.77;
false positives on real software rise from 0.048 to 0.079. Both directions
are real and they are the same effect seen twice.

**Consequence for R2 and R4.** R2 measures relation under a scale shift with
the narrow positive class; R4 measures recall under the wide one. B3 shows
they cannot both be optimised. The thesis reports the trade rather than
choosing a side.

---

# Part IV — Discussion points these results force

**Why R2 and B3 disagree.** In R2 (narrow positives, 300+ band, 51 real
programs) relation rescues 11 and costs 0. In B3 (wide positives, all bands,
1,034 real programs) it rescues 20 and costs 43. Two things differ: the
positive definition and the activity band. The consistent reading is that
relation sharpens the boundary where the classes are hard to separate by
volume, and loosens it where the positive class itself has been loosened.

**What the anchor becomes.** Relations between events rather than individual
events — held, and narrowed from "A then B" to "events on the same target".
R3 is why the narrowing is forced rather than chosen.

**What this says about the field's reporting.** A detector's false positive
rate is reported as a property of the detector. R1 shows it is at least as
much a property of the negative set, and B2 shows that even a feature group's
apparent contribution depends on what the negatives were. Neither is
detectable from a single number.

---

# Part V — Appendix material

Reported as tables without discussion:

- M1 full grid: all eleven feature combinations × three negative kinds
- S1 unseen constructed: A 0.577 → A_generic + S1 + S2 0.375. **Not
  "generalisation": a rate on samples we wrote, where low may mean the
  imitations were poor.** Belongs with limitations.
- A/S axis and A_reduced: the individual set already contains order-derived
  columns (rw_latency_*, chain_*, api bigrams), which is why an explicit
  order group added to it measures order against order
- Information-level split: static / count / presence / aggregate / relation
- The 200-column API transition matrix: FP 0.030 → 0.074, removed
- Behaviour vocabulary: 20 tokens, derived from eight reports and checked
  against MITRE ATT&CK; six literature candidates dropped because CAPE
  records nothing for them (SHEmptyRecycleBin, CreateService,
  GetLogicalDrives, WNetOpenEnum, self-delete via cmd, NtDelayExecution)

**Two token names must change in the thesis.** `FILE_ENCRYPT` detects 20 or
more files read and written under the same stem — no entropy, no crypto call,
and 30% of active benign software triggers it. `RANSOM_NOTE` detects one file
name written into five or more directories, with no string matching. Naming
them same-file-rewrite and multi-directory-document avoids a circular claim.

---

# Part VI — Known gaps

- Only 51 real programs open 300+ files, so 95% of R2's measured negatives
  are constructed. The 11-to-0 subset result is what carries that claim.
- The behaviour vocabulary was fixed by reading eight reports; if those eight
  families fall in an evaluation fold there is a small leakage.
- Order pairs were selected by coverage over the whole corpus — no label
  involved, but not fold-internal either.
- Negatives are split at random in cross-validation, so two versions of one
  program can land on opposite sides. `kind_of()` grouping prevents this in
  the fixed split and was not carried into the rotations.
- `explore_relational.api_stream()` concatenates every process, and
  explorer.exe — the desktop shell reacting to file-change notifications, the
  same pid every run, started before the sample — is 50–77% of the call
  count. Restricting to the sample's own tree moves the category switch rate
  in opposite directions for the two classes (installer 0.38 → 0.46,
  ransomware 0.38 → 0.20). **Not fixed.** Every sequence-group feature is
  affected.
- static is reported as 9 features; 5 named in the code never reach the CSV.
- Three of the 9 static features need the run, so "static" overstates what
  the import table alone achieves (0.926 without them against 0.941 with).
