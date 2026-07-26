#!/usr/bin/env python3
"""
extract_features.py - Extract dynamic AND static features from a CAPE
analysis in one pass, writing a single row per sample.

This merges what used to be two separate tools:
  1. correlate.py      -- dynamic behavioral features (file lifecycle,
                          write<->crypto time correlation)
  2. static_imports.py -- static PE import categories

They are merged because a single CAPE report.json already contains both:
`behavior` (what the sample did) and `static` (what the binary is). Reading
the report once and emitting one combined row keeps the feature table
consistent and avoids re-parsing large reports twice.

Merging also unlocks a feature class that neither tool could compute
alone: static<->dynamic interaction. For example, a sample that imports
CryptEncrypt but never calls it at runtime either failed to trigger or
bypassed the Windows crypto API with its own implementation. That
disagreement between "what it was built to do" and "what it actually did"
is itself a signal, and it is only visible when both views are combined.

Feature groups emitted
----------------------
  identity   : sample_id, sha256, label, family, source
  dynamic    : file lifecycle counts and ratios, windowed chain metrics,
               write<->crypto Pearson correlation
  static     : PE import category counts, indicative_category_count,
               statically-linked crypto library fingerprints
  interaction: agreement/disagreement between static intent and dynamic
               behavior

Usage
-----
  # Single analysis
  python3 extract_features.py /opt/CAPEv2/storage/analyses/37 \\
      --features-out ../data/features/features.csv --label ransomware

  # Every analysis that passed analyze_result.py
  python3 extract_features.py --batch /opt/CAPEv2/storage/analyses \\
      --results analysis_results.csv --keep-verdict TRUE_ENCRYPTION \\
      --features-out ../data/features/features.csv \\
      --manifest ../data/manifest.csv
"""

import os
import sys
import json
import csv
import math
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# ---------------- Dynamic config ----------------

TS_FORMAT = "%Y-%m-%d %H:%M:%S,%f"
FILE_EVENT_TYPES = ["read", "write", "delete", "move", "copy", "execute"]
DESTRUCTIVE_EVENT_TYPES = ["delete", "move"]

# ---------------- Static config ----------------

IMPORT_CATEGORIES = {
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptImportKey",
        "CryptExportKey", "CryptAcquireContext", "CryptDestroyKey",
        "CryptReleaseContext", "CryptGenRandom", "BCryptEncrypt",
        "BCryptGenRandom", "CryptStringToBinary", "CryptImportPublicKeyInfo",
    ],
    "random": ["CryptGenRandom", "BCryptGenRandom", "RtlGenRandom", "rand_s"],
    "file_ops": [
        "CreateFileW", "CreateFileA", "WriteFile", "ReadFile",
        "DeleteFileW", "MoveFileW", "MoveFileExW", "CopyFileW",
        "SetFilePointerEx", "FindFirstFileExW", "FindNextFileW",
    ],
    "volume_enum": [
        "FindFirstVolumeW", "FindNextVolumeW", "GetDriveTypeW",
        "GetVolumePathNamesForVolumeNameW", "SetVolumeMountPointW",
    ],
    "network_spread": [
        "WNetOpenEnum", "WNetAddConnection", "WNetEnumResource", "WNetCloseEnum",
    ],
    "file_unlock": ["RmStartSession", "RmRegisterResources", "RmGetList", "RmEndSession"],
    "process_enum": [
        "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
        "OpenProcessToken", "AdjustTokenPrivileges",
    ],
    "shadow_service": ["DeleteFileW", "ControlService", "OpenSCManager", "OpenServiceW"],
    "anti_analysis": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "SetUnhandledExceptionFilter", "NtQueryInformationProcess",
    ],
}

CRYPTO_LIB_FINGERPRINTS = {
    "cryptopp": ["cryptopp", "CryptoPP", "rijndael_simd", "Crypto++"],
    "openssl": ["OpenSSL", "libcrypto", "SSLeay"],
    "mbedtls": ["mbedtls", "mbed TLS"],
    "libsodium": ["libsodium", "sodium_"],
    "wolfssl": ["wolfSSL", "wolfssl"],
    "boost": ["boost"],
}

INDICATIVE_CATEGORIES = ("crypto", "volume_enum", "network_spread",
                          "file_unlock", "process_enum")


# ---------------- Shared helpers ----------------

def parse_ts(ts):
    if not ts:
        return None
    try:
        return datetime.strptime(ts.strip(), TS_FORMAT)
    except (ValueError, TypeError):
        return None


def get_extension(path):
    if not path or "." not in path.split("\\")[-1]:
        return "(none)"
    return path.split(".")[-1].lower()


def pearson(xs, ys):
    n = len(xs)
    if n == 0:
        return None
    mean_x, mean_y = sum(xs) / n, sum(ys) / n
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    dx = math.sqrt(sum((x - mean_x) ** 2 for x in xs))
    dy = math.sqrt(sum((y - mean_y) ** 2 for y in ys))
    if dx == 0 or dy == 0:
        return None
    return num / (dx * dy)


def shannon_entropy(byte_values):
    """
    Shannon entropy of a list of byte values, in bits (0-8).

    Encrypted output approaches 8.0 because every byte value becomes
    roughly equally likely. This matters beyond the crypto-API axis: a
    sample that encrypts without calling the Windows crypto API still
    produces high-entropy data, so entropy is a signal that survives
    custom / statically-linked crypto implementations.
    """
    if not byte_values:
        return 0.0
    freq = defaultdict(int)
    for b in byte_values:
        freq[b] += 1
    n = len(byte_values)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def decode_buffer(raw):
    """
    Approximately decode a CAPE buffer string (e.g. '\\xba\\xe1...') into a
    list of byte values. Best-effort approximation for entropy estimation,
    not a byte-exact decoder.
    """
    if not raw:
        return []
    out = []
    i = 0
    s = raw
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt == "x" and i + 3 < len(s):
                try:
                    out.append(int(s[i + 2:i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            escape_map = {"n": 10, "r": 13, "t": 9, "v": 11, "\\": 92}
            out.append(escape_map.get(nxt, ord(nxt)))
            i += 2
            continue
        out.append(ord(s[i]) & 0xff)
        i += 1
    return out


# ---------------- Dynamic extraction ----------------

def extract_lifecycle_events(report):
    """(datetime, event_type, extension, path) for every file event."""
    events = []
    for event in report.get("behavior", {}).get("enhanced", []) or []:
        if event.get("object") != "file":
            continue
        event_type = event.get("event")
        if event_type not in FILE_EVENT_TYPES:
            continue
        ts = parse_ts(event.get("timestamp"))
        if not ts:
            continue
        path = event.get("data", {}).get("file", "")
        events.append((ts, event_type, get_extension(path), path))
    return events


def extract_crypto_calls(report):
    """(datetime, length, entropy, api_name) for crypto-category API calls.

    The Buffer argument, when present, holds the data passed to the crypto
    API. Its entropy tells us whether real encryption output is flowing
    through, as opposed to the API merely being touched.
    """
    events = []
    for process in report.get("behavior", {}).get("processes", []) or []:
        for call in process.get("calls", []) or []:
            if call.get("category") != "crypto":
                continue
            ts = parse_ts(call.get("timestamp"))
            if not ts:
                continue
            length = 0
            buf = None
            args = call.get("arguments", [])
            if isinstance(args, list):
                for arg in args:
                    if arg.get("name") == "Length":
                        try:
                            length = int(arg.get("value", 0))
                        except (ValueError, TypeError):
                            length = 0
                    if arg.get("name") == "Buffer":
                        buf = arg.get("value")
            entropy = shannon_entropy(decode_buffer(buf)) if buf else 0.0
            events.append((ts, length, entropy, call.get("api", "?")))
    return events


def windowize(lifecycle_events, crypto_events, window_sec):
    """Bucket events into fixed windows. Returns (lifecycle_windows, write_series, crypto_series)."""
    all_ts = [e[0] for e in lifecycle_events] + [c[0] for c in crypto_events]
    if not all_ts:
        return [], [], []
    t0, t_end = min(all_ts), max(all_ts)
    n_buckets = int((t_end - t0).total_seconds() // window_sec) + 1

    lifecycle_windows = [{t: 0 for t in FILE_EVENT_TYPES} for _ in range(n_buckets)]
    write_series = [0] * n_buckets
    crypto_series = [0] * n_buckets

    for ts, event_type, _ext, _path in lifecycle_events:
        idx = int((ts - t0).total_seconds() // window_sec)
        lifecycle_windows[idx][event_type] += 1
        if event_type == "write":
            write_series[idx] += 1

    for ts, _length, _entropy, _api in crypto_events:
        idx = int((ts - t0).total_seconds() // window_sec)
        crypto_series[idx] += 1

    return lifecycle_windows, write_series, crypto_series


def compute_chain_metrics(lifecycle_windows):
    """
    Classify each active window:
      destructive_chain          - read + write + (delete or move) together
                                   (ransomware: read original, write encrypted,
                                   remove original)
      write_only_nondestructive  - writes without any delete/move
                                   (benign archiving: originals untouched)
    """
    active = destructive = write_only = other = 0
    for row in lifecycle_windows:
        if not any(row[t] > 0 for t in FILE_EVENT_TYPES):
            continue
        active += 1
        has_read = row["read"] > 0
        has_write = row["write"] > 0
        has_destructive = row["delete"] > 0 or row["move"] > 0
        if has_read and has_write and has_destructive:
            destructive += 1
        elif has_write and not has_destructive:
            write_only += 1
        else:
            other += 1
    return {
        "active_windows": active,
        "destructive_chain_windows": destructive,
        "write_only_nondestructive_windows": write_only,
        "other_windows": other,
    }


def extract_dynamic_features(report, window_sec):
    lifecycle_events = extract_lifecycle_events(report)
    crypto_events = extract_crypto_calls(report)

    counts = {t: 0 for t in FILE_EVENT_TYPES}
    for _ts, event_type, _ext, _path in lifecycle_events:
        counts[event_type] += 1

    writes = counts["write"]
    delete_ratio = counts["delete"] / writes if writes else ""
    move_ratio = counts["move"] / writes if writes else ""

    lifecycle_windows, write_series, crypto_series = windowize(
        lifecycle_events, crypto_events, window_sec)
    chain = compute_chain_metrics(lifecycle_windows)
    corr = pearson(write_series, crypto_series)

    # Entropy of data passed through the crypto API. High values (near 8)
    # indicate genuine encryption output rather than incidental API use.
    entropies = [e for _ts, _len, e, _api in crypto_events if e > 0]
    entropy_mean = sum(entropies) / len(entropies) if entropies else ""
    entropy_max = max(entropies) if entropies else ""

    # Distinct extensions attacked -- a broad spread suggests indiscriminate
    # encryption rather than a program working with one file type.
    destructive_exts = {ext for _ts, et, ext, _p in lifecycle_events
                        if et in DESTRUCTIVE_EVENT_TYPES}

    return {
        "n_crypto_calls": len(crypto_events),
        "write_crypto_pearson": corr if corr is not None else "",
        "crypto_buffer_entropy_mean": entropy_mean,
        "crypto_buffer_entropy_max": entropy_max,
        "n_read": counts["read"],
        "n_write": counts["write"],
        "n_delete": counts["delete"],
        "n_move": counts["move"],
        "n_copy": counts["copy"],
        "n_execute": counts["execute"],
        "delete_to_write_ratio": delete_ratio,
        "move_to_write_ratio": move_ratio,
        "destructive_extension_variety": len(destructive_exts),
        **chain,
    }


# ---------------- Static extraction ----------------

def get_imports(report):
    names = []
    static = report.get("static", {}) or {}
    for dll_entry in static.get("pe_imports", []) or []:
        for imp in dll_entry.get("imports", []) or []:
            name = imp.get("name")
            if name:
                names.append(name)
    return names


def get_strings(report):
    s = report.get("strings", [])
    return [x for x in s if isinstance(x, str)] if isinstance(s, list) else []


def categorize_imports(import_names):
    lowered = {n.lower() for n in import_names}
    hits = {}
    for category, keywords in IMPORT_CATEGORIES.items():
        found = set()
        for kw in keywords:
            kw_l = kw.lower()
            if any(kw_l in name for name in lowered):
                found.add(kw)
        hits[category] = len(found)
    return hits


def detect_crypto_libs(strings):
    joined = "\n".join(strings).lower()
    return {lib for lib, fps in CRYPTO_LIB_FINGERPRINTS.items()
            if any(fp.lower() in joined for fp in fps)}


def extract_static_features(report):
    import_names = get_imports(report)
    category_hits = categorize_imports(import_names)
    crypto_libs = detect_crypto_libs(get_strings(report))
    indicative = [c for c in INDICATIVE_CATEGORIES if category_hits.get(c, 0) > 0]

    features = {"total_imports": len(import_names)}
    for category in IMPORT_CATEGORIES:
        features[f"imp_{category}"] = category_hits.get(category, 0)
    features["indicative_category_count"] = len(indicative)
    features["static_crypto_libs"] = ";".join(sorted(crypto_libs)) if crypto_libs else ""
    return features


# ---------------- Static <-> dynamic interaction ----------------

def compute_interaction_features(static_features, dynamic_features):
    """
    Relationships between what the binary was built to do (imports) and what
    it actually did at runtime. Only meaningful when both views exist.

    - crypto_imported_not_called: the binary imports Windows crypto APIs but
      made no crypto call at runtime. Indicates either a trigger failure or
      that encryption was done through a statically-linked / custom
      implementation instead.
    - crypto_called_not_imported: crypto calls observed without matching
      imports, which suggests runtime API resolution (GetProcAddress) --
      a known evasion technique.
    - static_dynamic_agreement: both views agree that crypto is in play.
    """
    imported_crypto = static_features.get("imp_crypto", 0) > 0
    called_crypto = dynamic_features.get("n_crypto_calls", 0) > 0
    has_static = static_features.get("total_imports", 0) > 0

    if not has_static:
        # No import table (packed / unreadable): interaction is undefined.
        return {
            "crypto_imported_not_called": "",
            "crypto_called_not_imported": "",
            "static_dynamic_agreement": "",
        }

    return {
        "crypto_imported_not_called": int(imported_crypto and not called_crypto),
        "crypto_called_not_imported": int(called_crypto and not imported_crypto),
        "static_dynamic_agreement": int(imported_crypto == called_crypto),
    }


# ---------------- Feature row assembly ----------------

IDENTITY_FIELDS = ["sample_id", "sha256", "label", "family", "source",
                    "malscore", "cape_family"]
DYNAMIC_FIELDS = [
    "n_crypto_calls", "write_crypto_pearson",
    "crypto_buffer_entropy_mean", "crypto_buffer_entropy_max",
    "n_read", "n_write", "n_delete", "n_move", "n_copy", "n_execute",
    "delete_to_write_ratio", "move_to_write_ratio",
    "destructive_extension_variety",
    "active_windows", "destructive_chain_windows",
    "write_only_nondestructive_windows", "other_windows",
]
STATIC_FIELDS = (["total_imports"] + [f"imp_{c}" for c in IMPORT_CATEGORIES] +
                  ["indicative_category_count", "static_crypto_libs"])
INTERACTION_FIELDS = ["crypto_imported_not_called", "crypto_called_not_imported",
                       "static_dynamic_agreement"]

FEATURE_FIELDNAMES = IDENTITY_FIELDS + DYNAMIC_FIELDS + STATIC_FIELDS + INTERACTION_FIELDS


def get_cape_metadata(report):
    """
    Metadata CAPE produces that no other source gives us:
      - malscore: CAPE's own aggregate maliciousness score
      - cape_family: the family CAPE's signatures attributed the sample to,
        which is independent of the family label we recorded at download
        time. Disagreement between the two is worth knowing about.
    """
    malscore = report.get("malscore", "")
    cape_family = ""
    detections = report.get("detections", [])
    if isinstance(detections, list) and detections:
        first = detections[0]
        if isinstance(first, dict):
            cape_family = first.get("family", "")
    return {
        "malscore": malscore if malscore is not None else "",
        "cape_family": cape_family,
    }


def build_feature_row(report, sample_id, label, family, source, window_sec):
    dynamic = extract_dynamic_features(report, window_sec)
    static = extract_static_features(report)
    interaction = compute_interaction_features(static, dynamic)
    cape_meta = get_cape_metadata(report)

    sha256 = (report.get("target", {}) or {}).get("file", {}).get("sha256", "")

    row = {
        "sample_id": sample_id,
        "sha256": sha256,
        "label": label,
        "family": family or "",
        "source": source,
    }
    row.update(cape_meta)
    row.update(dynamic)
    row.update(static)
    row.update(interaction)
    return row


def append_feature_row(features_out, row):
    file_exists = os.path.exists(features_out)
    with open(features_out, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FEATURE_FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in FEATURE_FIELDNAMES})


# ---------------- Manifest lookup (for family metadata) ----------------

def load_manifest_by_sha(manifest_path):
    if not manifest_path or not os.path.exists(manifest_path):
        return {}
    entries = {}
    with open(manifest_path, newline="") as f:
        for row in csv.DictReader(f):
            entries[row["sha256"]] = row
    return entries


# ---------------- Report loading ----------------

def resolve_report_path(path):
    p = Path(path)
    if p.is_dir():
        candidate = p / "reports" / "report.json"
        return candidate if candidate.exists() else None
    return p if p.is_file() else None


def process_one(path, label, source, window_sec, features_out, manifest_by_sha, quiet=False):
    report_path = resolve_report_path(path)
    if not report_path:
        if not quiet:
            print(f"[!] no report.json at {path}")
        return None

    try:
        with open(report_path, "r", errors="replace") as f:
            report = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        if not quiet:
            print(f"[!] {report_path}: {e}")
        return None

    info = report.get("info", {}) or {}
    sample_id = str(info.get("id", Path(report_path).parent.parent.name))
    sha256 = (report.get("target", {}) or {}).get("file", {}).get("sha256", "")

    # Enrich with family from the manifest when available.
    family = ""
    if sha256 and sha256 in manifest_by_sha:
        family = manifest_by_sha[sha256].get("family", "")

    row = build_feature_row(report, sample_id, label, family, source, window_sec)

    if features_out:
        append_feature_row(features_out, row)

    if not quiet:
        print(f"{sample_id:<8} {family[:14]:<15} "
              f"read={row['n_read']:<5} write={row['n_write']:<5} "
              f"del={row['n_delete']:<5} crypto={row['n_crypto_calls']:<5} "
              f"imports={row['total_imports']:<5} ind={row['indicative_category_count']}/5")
    return row


def main():
    parser = argparse.ArgumentParser(
        description="Extract combined dynamic + static features from CAPE analyses.")
    parser.add_argument("path", nargs="?", help="An analysis directory or report.json")
    parser.add_argument("--batch", metavar="ANALYSES_DIR",
                         help="Process analyses under this directory")
    parser.add_argument("--results", metavar="CSV",
                         help="analyze_result.py output; restricts batch to matching verdicts")
    parser.add_argument("--keep-verdict", default="TRUE_ENCRYPTION",
                         help="With --results, which verdict to process (default: TRUE_ENCRYPTION)")
    parser.add_argument("--features-out", default=None, help="Feature table CSV to append to")
    parser.add_argument("--label", default="ransomware", help="Label for these samples")
    parser.add_argument("--source", default="cape", help="Data source tag (default: cape)")
    parser.add_argument("--manifest", default=None,
                         help="Manifest CSV, used to enrich rows with family metadata")
    parser.add_argument("--window", type=float, default=1.0,
                         help="Time window in seconds for correlation features (default: 1.0)")
    args = parser.parse_args()

    manifest_by_sha = load_manifest_by_sha(args.manifest)

    if args.batch:
        base = Path(args.batch)
        if not base.is_dir():
            print(f"[!] not a directory: {args.batch}")
            sys.exit(1)

        # Restrict to analyses that passed, if a results CSV was given.
        allowed_ids = None
        if args.results:
            allowed_ids = set()
            with open(args.results, newline="") as f:
                for r in csv.DictReader(f):
                    if r.get("verdict") == args.keep_verdict:
                        allowed_ids.add(str(r.get("task_id", "")).strip())
            print(f"Restricting to {len(allowed_ids)} analyses with verdict "
                  f"{args.keep_verdict}\n")

        subdirs = sorted((d for d in base.iterdir() if d.is_dir()),
                          key=lambda d: int(d.name) if d.name.isdigit() else 0)
        if allowed_ids is not None:
            subdirs = [d for d in subdirs if d.name in allowed_ids]

        header = (f"{'task':<8} {'family':<15} {'dynamic':<40} {'static'}")
        print(header)
        print("-" * 90)

        processed = 0
        for d in subdirs:
            if process_one(d, args.label, args.source, args.window,
                           args.features_out, manifest_by_sha):
                processed += 1

        print(f"\n[done] extracted features from {processed} analyses")
        if args.features_out:
            print(f"[saved] {args.features_out}")

    elif args.path:
        row = process_one(args.path, args.label, args.source, args.window,
                          args.features_out, manifest_by_sha)
        if row and args.features_out:
            print(f"[saved] feature row -> {args.features_out}")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
