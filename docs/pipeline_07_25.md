# Pipeline Overview

This document describes the current data collection and analysis pipeline
for the ransomware detection project. It shows where each tool sits and what
flows between them.

## Main pipeline (CAPE — new sample collection & analysis)

```
[1] Collect + dedupe + register
    collect_samples.py
    - Query MalwareBazaar API per family (get_siginfo)
    - Check each sha256 against manifest.csv -> skip if already known
    - Download new ones (get_file; password-protected zip, "infected")
    - Register in manifest.csv (status=pending)
        |
        v
[2] Static screening (prioritise before spending sandbox time)
    static_imports.py --pe-batch
    - Extract PE import categories from downloaded executables
    - High indicative_category_count -> stronger ransomware fingerprint,
      submit these first
        |
        v
[3] Submit to CAPE
    (CAPE's own utils/submit.py, run as the cape user via poetry)
    - CAPE assigns a task id
    - manifest.py mark-submitted (status=submitted, records task_id)
        |
        v
[4] Execution filter (did it run at all?)
    triage.py
    - SUCCESS / AMBIGUOUS / FAILED based on call counts and file events
        |
        v
[5] Encryption filter (did it actually attack victim files? — key gate)
    verify_encryption.py
    - Checks whether planted decoy files (Desktop/Documents/Downloads)
      were read/written/deleted/moved
    - TRUE_ENCRYPTION / WEAK_VICTIM_ACTIVITY / NO_VICTIM_ACTIVITY
        |
        v (TRUE_ENCRYPTION only)
[6] Dynamic feature extraction
    correlate.py
    - File-lifecycle features (read/write/delete/move counts + ratios)
    - write<->crypto time correlation (Pearson, windowed chain metrics)
    - Appends a row to features.csv
    - manifest.py mark-result (status=analyzed, records result)
        |
        v
[7] Archive originals (last, to preserve raw reports cheaply)
    triage.py --cleanup
    - Delete FAILED analyses; gzip SUCCESS/AMBIGUOUS report.json to archive
```

## Secondary pipeline (Legacy Cuckoo — 447 old reports, completed)

```
[L1] Encryption filter
     verify_encryption_legacy.py --batch
     - 447 reports -> 34 TRUE_ENCRYPTION selected
     - legacy_verify_results.csv
        |
        v (TRUE_ENCRYPTION only)
[L2] Dynamic feature extraction (time-independent common features only)
     correlate_legacy.py --from-verify
     - Lifecycle counts/ratios only (legacy reports have no timestamps)
     - Joins features.csv (source=cuckoo; CAPE-only columns blank)
```

## Static feature pipeline (both sources, separate axis)

```
[S1-ransomware] static_imports.py --batch   (report.json input)
     - 447 ransomware reports -> static_features.csv (324 with imports)

[S1-benign]     static_imports.py --pe-batch (raw exe input, via pefile)
     - System32 (652) + confusing tools (7) + DikeDataset (962)
     - benign_*.csv
        |
        v (combine)
[S2] Validation (completed)
     - indicative_category_count separates ransomware from benign
     - ~48% ransomware at 4-5/5 vs 0.1% benign false-positive rate
```

## Where data accumulates

```
features.csv          Dynamic features (CAPE + Legacy Cuckoo combined)
static_features.csv   Static features (ransomware)
benign_*.csv          Static features (benign control set)
manifest.csv          Collection/analysis status tracking (master ledger)
```

## One-line summary

```
collect_samples -> static_imports (screen) -> CAPE submit
 -> triage (ran?) -> verify_encryption (encrypted?)
 -> correlate (features) -> triage --cleanup (archive)

manifest.py tracks status across the whole flow.
```

## Not yet built (next phase)

```
features.csv + static_features.csv + benign
        |
        v
[TODO] Feature integration (static + dynamic into one table,
       with source/coverage markers for asymmetric availability)
        |
        v
[TODO] Model training & comparison (RF/XGBoost + LSTM/1D-CNN)
       - single-feature vs relationship-feature: the project's core claim
```

## Tool reference

| Tool | Input | Output | Role |
|---|---|---|---|
| `collect_samples.py` | family names | samples + manifest rows | Download + dedupe |
| `manifest.py` | sha256 / metadata | manifest.csv | Status tracking |
| `static_imports.py` | report.json OR exe | static features CSV | Static import features |
| `triage.py` | analyses dir | triage CSV | Execution success filter |
| `verify_encryption.py` | report.json (CAPE) | verdict | Real-encryption filter |
| `verify_encryption_legacy.py` | report.json (Cuckoo) | verdict + CSV | Real-encryption filter (legacy) |
| `correlate.py` | report.json (CAPE) | features.csv row | Dynamic features (timed) |
| `correlate_legacy.py` | report.json (Cuckoo) | features.csv row | Dynamic features (untimed) |
| `plot_timeline.py` | timeline CSV | plot | Visualization |
```
