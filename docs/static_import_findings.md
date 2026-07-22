# Static PE-Import Analysis — Findings Log

## Motivation

Dynamic (behavioral) sandbox analysis only yields data when a sample
actually executes its payload. In this project, most modern ransomware
samples fail to trigger (sandbox evasion, missing arguments, C2
dependence, environment fingerprinting). Out of the 447 legacy Cuckoo
Sandbox reports, only 34 samples (~7.6%) showed confirmed attacks on
planted victim files (`verify_encryption_legacy.py`, TRUE_ENCRYPTION
verdict).

Static analysis (PE import table, embedded strings) is available even for
samples whose payload never ran, since it is derived from the binary
itself rather than from execution. This makes it a candidate for
recovering usable data from otherwise "wasted" (non-triggering) samples.

## Discovery: AvosLocker case study

Manually inspecting one AvosLocker report's `static` section revealed:

- **ADVAPI32.dll imports**: `CryptEncrypt`, `CryptGenRandom`,
  `CryptAcquireContextA`, `CryptImportKey` — dynamically-linked Windows
  crypto API usage.
- **strings**: fingerprints of a statically-linked **Crypto++ 8.5**
  library (`cryptopp850`, `rijndael_simd.cpp`, `CryptoPP::` C++ symbols),
  including an unstripped developer build path
  (`C:\Users\pc\source\repos\cryptopp850\...`).
- This is a **hybrid crypto implementation**: dynamic Windows API calls
  (likely key management / RSA) alongside a statically-linked library
  (likely bulk AES encryption).
- Other ransomware-indicative imports present: `RstrtMgr.DLL`
  (`RmStartSession` — Restart Manager, used to unlock in-use files before
  encrypting them), `MPR.dll` (`WNetOpenEnumA`, `WNetAddConnection2A` —
  network share enumeration/spread), `Toolhelp32`/`Process32Next`
  (process enumeration), and volume enumeration APIs
  (`FindFirstVolumeW`, `GetDriveTypeW`).

Key implication: contrary to initial concern, real-world ransomware
samples frequently do **not** strip debug strings or obfuscate library
fingerprints, making statically-linked crypto libraries identifiable via
the sandbox's default `strings` output — no custom disassembly / crypto
function signature (CFS) analysis needed.

## Feature design: `static_imports.py`

Built a tool that categorizes PE imports into ransomware-indicative
groups and counts co-occurrence, rather than relying on any single
import (avoiding the single-feature trap this project explicitly argues
against):

- `crypto` — CryptEncrypt, CryptGenRandom, BCryptEncrypt, etc.
- `random` — CryptGenRandom, BCryptGenRandom (PRNG consumption; a
  candidate signal for custom/statically-linked crypto that bypasses the
  Windows crypto API, since strong encryption still needs a random source)
- `file_ops` — CreateFile, WriteFile, DeleteFile, MoveFile, etc.
- `volume_enum` — FindFirstVolumeW, GetDriveTypeW, etc.
- `network_spread` — WNetOpenEnum, WNetAddConnection, etc.
- `file_unlock` — Restart Manager APIs (RmStartSession, etc.)
- `process_enum` — Toolhelp32/Process32Next (kill AV/DB/backup processes)
- `shadow_service` — service control APIs (best-effort signal)
- `anti_analysis` — IsDebuggerPresent, etc.

The tool supports two input paths producing identical feature columns:
1. Sandbox `report.json` → `static.pe_imports` (for the ransomware set)
2. Raw PE files (`.exe`) via `pefile` → same categories (for a benign
   control set, since executing benign software is unnecessary — the
   import table is static)

## Benign control set

To test whether these static features actually separate ransomware from
goodware (not just "many samples have crypto imports"), a benign control
set was built:

- **652 Windows System32 executables** — bulk, guaranteed-benign baseline
- **7 "confusing" programs** deliberately chosen because they share
  surface-level behavior with ransomware: 7-Zip (7z.exe, 7zFM.exe,
  7zG.exe — encryption + heavy file I/O), WinRAR (Rar.exe, UnRAR.exe,
  WinRAR.exe — same), VLC (vlc.exe — heavy file I/O, no crypto, negative
  control)

## Results

Comparing `indicative_category_count` (how many of the 5 ransomware
-indicative import categories are present) across groups:

| Group | 0/5 | 1/5 | 2/5 | 3/5 | 4/5 | 5/5 |
|---|---|---|---|---|---|---|
| Ransomware (n=324, imports>20) | 26.9% | 9.0% | 5.2% | 10.8% | **33.6%** | **14.5%** |
| Benign System32 (n=652) | **62.3%** | **27.9%** | 8.0% | 1.5% | 0.3% | 0.0% |
| Benign confusing tools (n=7) | 0.0% | 42.9% | 42.9% | 14.3% | 0.0% | 0.0% |

**~48% of ransomware samples show 4 or more indicative categories
simultaneously, versus 0.3% of System32 benign and 0% of the confusing
tool set.** The confusing tools (7-Zip, WinRAR, VLC), despite importing
crypto and/or heavy file I/O, never exceed 3/5 categories.

### Per-category discrimination (% of samples with the import present)

| Category | Ransomware | Benign System32 | Confusing tools | Verdict |
|---|---|---|---|---|
| `file_unlock` | 44.1% | 0.2% | 0.0% | **Strong discriminator** |
| `network_spread` | 27.5% | 1.8% | 0.0% | **Strong discriminator** |
| `crypto` | 61.1% | 8.3% | 28.6% | Moderate (confusing tools overlap) |
| `random` | 44.8% | 5.2% | 28.6% | Moderate |
| `process_enum` | 64.2% | 31.3% | 71.4% | Weak alone |
| `volume_enum` | 62.0% | 8.1% | **71.4%** | Weak / misleading alone (VeraCrypt-like tools score higher than ransomware) |
| `file_ops` | 97.8% | 50.3% | 100.0% | No discrimination (nearly universal) |
| `anti_analysis` | 74.1% | **96.8%** | 85.7% | Inverse signal — do not use alone |

**Takeaway**: single imports (crypto, file_ops) are shared with benign
software and would reproduce the single-feature weakness this project
critiques. `file_unlock` (Restart Manager) and `network_spread` (network
share enumeration) are close to ransomware-exclusive on this data and are
the strongest individual signals. The real strength of this feature axis
is in the **co-occurrence count**, consistent with the project's
"semantic correlation between events" anchor rather than any single
import's presence.

### Limitation: packed / import-obfuscated families

87 of 324 ransomware samples (26.9%) scored 0/5. Their average import
count (87) is roughly half that of the scoring group (157), and the
family breakdown is dominated by **Conti (42/87)**, a family known for
resolving APIs dynamically at runtime rather than exposing them in the
static import table. This means static import analysis is blind to
samples that hide their API usage this way.

This is not a dead end — it is evidence for **why static and dynamic
analysis are complementary rather than redundant**: a sample invisible to
static import analysis (Conti) may still be caught by dynamic file
-lifecycle analysis if it actually executes, and vice versa (samples that
fail to trigger dynamically may still be identifiable statically). This
motivates treating static-only, dynamic-only, and static+dynamic samples
as distinct but combinable evidence sources during modeling (see open
question below).

## Open question: asymmetric static/dynamic coverage in modeling

Not all samples have both static and dynamic features:
- Static only: samples with unreadable/unexecuted payloads (majority of
  the legacy dataset)
- Dynamic only: samples analyzed before static extraction was added
- Both: samples with confirmed TRUE_ENCRYPTION verdicts (currently 34,
  growing)

Proposed approach (not yet implemented):
- **Tree-based model (RF/XGBoost)**: use the full feature table
  (static + dynamic columns) across all samples; tree models handle
  missing values natively, so static-only and dynamic-only rows can both
  contribute.
- **Sequence model (LSTM/1D-CNN)**: restrict to samples with a genuine
  dynamic event sequence (i.e. the "both" group plus any dynamic-only
  CAPE samples); do not force samples with no execution trace into a
  sequence model.
- **Static<->dynamic interaction features** (e.g. "imports CryptEncrypt
  but never calls it at runtime" as a trigger-failure/evasion flag) are
  computed only for the "both" group and left blank elsewhere, to be
  used as bonus columns for the tree-based model.

## Next steps

1. Expand the "confusing" benign set (only 7 samples currently) with
   tools more likely to overlap with ransomware signatures: VeraCrypt
   (volume + crypto), backup/sync tools, disk utilities. Current
   `volume_enum` result (confusing tools score *higher* than ransomware)
   is based on too few samples to trust yet.
2. Integrate static features into the main feature table (`features.csv`)
   alongside dynamic lifecycle features, with a `source`/coverage marker
   per sample.
3. Investigate whether the `random` (PRNG) category correlates with
   samples that lack Windows crypto API calls at runtime but still show
   file-write entropy consistent with encryption (hypothesis from
   literature review: PRNG API consumption survives custom/static crypto
   implementations).
