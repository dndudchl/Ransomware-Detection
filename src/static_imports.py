#!/usr/bin/env python3
"""
static_imports.py - Extract ransomware-indicative static features (PE
imports + crypto-library string fingerprints) from Cuckoo/CAPE reports.

Motivation
----------
Dynamic (behavioral) analysis only yields data when a sample actually
executes its payload. In this project most modern samples fail to trigger
(sandbox evasion, missing args, C2 dependence), so behavioral data is
scarce. However, the sandbox's STATIC analysis (static.pe_imports,
strings) is available even for samples that never ran their payload,
because it is derived from the binary itself.

Inspecting a real AvosLocker sample showed the static section is rich:
  - ADVAPI32 imports: CryptEncrypt, CryptGenRandom, CryptAcquireContextA,
    CryptImportKey ... (encryption intent)
  - MPR.dll: WNetOpenEnumA / WNetAddConnection2A (network-share spread)
  - RstrtMgr.DLL: RmStartSession (Restart Manager -- unlock in-use files
    so they can be encrypted; a hallmark ransomware technique)
  - Toolhelp32 / Process32Next (process enumeration; kill AV / DB)
  - Volume enumeration: FindFirstVolumeW, GetDriveTypeW (whole-disk sweep)
  - strings revealed statically-linked Crypto++ 8.5 (cryptopp850,
    rijndael_simd.cpp) even though CryptEncrypt was ALSO imported
    dynamically -- i.e. a hybrid crypto implementation.

This script groups imports into ransomware-indicative categories and
counts them, and scans strings for known crypto-library fingerprints.
The point is NOT that any single import proves ransomware -- that would be
the same single-feature trap this project criticizes. Rather, it is the
CO-OCCURRENCE across categories (crypto + spread + file-unlock + process
enumeration) that is meaningful, and the static<->dynamic relationship
(e.g. imports CryptEncrypt but never called it at runtime = trigger
failure or custom-crypto bypass).

Usage
-----
  python3 static_imports.py <report.json>
  python3 static_imports.py --batch <dir> --out static_features.csv
"""

import sys
import json
import csv
import argparse
from pathlib import Path
from collections import defaultdict

# Import name -> category. Matching is case-insensitive substring on the
# import name, so e.g. "Crypt" catches CryptEncrypt, CryptGenRandom, etc.
# Categories chosen to reflect distinct ransomware behaviors so that
# CO-OCCURRENCE across categories can be measured.
IMPORT_CATEGORIES = {
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptImportKey",
        "CryptExportKey", "CryptAcquireContext", "CryptDestroyKey",
        "CryptReleaseContext", "CryptGenRandom", "BCryptEncrypt",
        "BCryptGenRandom", "CryptStringToBinary", "CryptImportPublicKeyInfo",
    ],
    "random": [
        "CryptGenRandom", "BCryptGenRandom", "RtlGenRandom", "rand_s",
    ],
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
        "WNetOpenEnum", "WNetAddConnection", "WNetEnumResource",
        "WNetCloseEnum",
    ],
    "file_unlock": [  # Restart Manager: unlock in-use files to encrypt them
        "RmStartSession", "RmRegisterResources", "RmGetList", "RmEndSession",
    ],
    "process_enum": [  # enumerate/kill AV, databases, backup services
        "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
        "OpenProcessToken", "AdjustTokenPrivileges",
    ],
    "shadow_service": [  # delete shadow copies / stop services (best-effort)
        "DeleteFileW", "ControlService", "OpenSCManager", "OpenServiceW",
    ],
    "anti_analysis": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "SetUnhandledExceptionFilter", "NtQueryInformationProcess",
    ],
}

# Crypto-library fingerprints to look for in strings (indicates static
# linking of a known crypto library).
CRYPTO_LIB_FINGERPRINTS = {
    "cryptopp": ["cryptopp", "CryptoPP", "rijndael_simd", "Crypto++"],
    "openssl": ["OpenSSL", "libcrypto", "SSLeay"],
    "mbedtls": ["mbedtls", "mbed TLS"],
    "libsodium": ["libsodium", "sodium_"],
    "wolfssl": ["wolfSSL", "wolfssl"],
    "boost": ["boost"],
}


def get_imports(report):
    """Return a flat list of imported function names from static.pe_imports.
    Handles the Cuckoo structure: static.pe_imports = [ {dll, imports:[{name}]} ]."""
    names = []
    static = report.get("static", {}) or {}
    pe_imports = static.get("pe_imports", []) or []
    for dll_entry in pe_imports:
        for imp in dll_entry.get("imports", []) or []:
            name = imp.get("name")
            if name:
                names.append(name)
    return names


def get_strings(report):
    """Return the list of strings. In this dataset strings is top-level."""
    s = report.get("strings", [])
    if isinstance(s, list):
        return [x for x in s if isinstance(x, str)]
    return []


def categorize_imports(import_names):
    """Count, per category, how many DISTINCT indicative imports are present."""
    lowered = {n.lower() for n in import_names}
    category_hits = {}
    for category, keywords in IMPORT_CATEGORIES.items():
        hits = set()
        for kw in keywords:
            kw_l = kw.lower()
            for name in lowered:
                if kw_l in name:
                    hits.add(kw)
                    break
        category_hits[category] = len(hits)
    return category_hits


def detect_crypto_libs(strings):
    """Return set of crypto libraries whose fingerprints appear in strings."""
    found = set()
    joined_lower = "\n".join(strings).lower()
    for lib, fps in CRYPTO_LIB_FINGERPRINTS.items():
        if any(fp.lower() in joined_lower for fp in fps):
            found.add(lib)
    return found


def analyze_one(report_path):
    try:
        with open(report_path, "r", errors="replace") as f:
            report = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        return {"file": Path(report_path).name, "error": str(e)}

    import_names = get_imports(report)
    strings = get_strings(report)
    category_hits = categorize_imports(import_names)
    crypto_libs = detect_crypto_libs(strings)

    # count how many distinct ransomware-indicative categories are present
    indicative_categories = [c for c in ("crypto", "volume_enum", "network_spread",
                                          "file_unlock", "process_enum")
                             if category_hits.get(c, 0) > 0]

    row = {
        "file": Path(report_path).name,
        "total_imports": len(import_names),
    }
    for category in IMPORT_CATEGORIES:
        row[f"imp_{category}"] = category_hits.get(category, 0)
    row["indicative_category_count"] = len(indicative_categories)
    row["static_crypto_libs"] = ";".join(sorted(crypto_libs)) if crypto_libs else ""
    return row


def print_single(report_path):
    row = analyze_one(report_path)
    if "error" in row:
        print(f"[!] {row['file']}: {row['error']}")
        return
    print("=" * 60)
    print(f"File: {row['file']}")
    print("=" * 60)
    print(f"Total imports: {row['total_imports']}")
    print(f"\n[Import categories] (distinct indicative imports per category)")
    for category in IMPORT_CATEGORIES:
        count = row[f"imp_{category}"]
        marker = " <--" if count > 0 and category in ("crypto", "volume_enum",
                                                       "network_spread", "file_unlock",
                                                       "process_enum") else ""
        print(f"   {category:<16} {count}{marker}")
    print(f"\n[Ransomware-indicative categories present]: {row['indicative_category_count']} / 5")
    print(f"[Statically-linked crypto libs in strings]: {row['static_crypto_libs'] or '(none detected)'}")


def run_batch(directory, out_csv):
    json_files = sorted(Path(directory).glob("*.json"))
    if not json_files:
        print(f"[!] No .json files in {directory}")
        sys.exit(1)

    rows = []
    for report_path in json_files:
        row = analyze_one(report_path)
        if "error" not in row:
            rows.append(row)

    # print compact table
    header = (f"{'file':<58} {'imports':>7} {'crypto':>6} {'rand':>4} {'vol':>4} "
              f"{'net':>4} {'unlock':>6} {'proc':>4} {'ind/5':>5} {'static_libs':<20}")
    print(header)
    print("-" * len(header))
    for r in rows:
        fname = r["file"] if len(r["file"]) <= 56 else r["file"][:53] + "..."
        print(f"{fname:<58} {r['total_imports']:>7} {r['imp_crypto']:>6} "
              f"{r['imp_random']:>4} {r['imp_volume_enum']:>4} {r['imp_network_spread']:>4} "
              f"{r['imp_file_unlock']:>6} {r['imp_process_enum']:>4} "
              f"{r['indicative_category_count']:>5} {r['static_crypto_libs']:<20}")

    fieldnames = ["file", "total_imports"] + [f"imp_{c}" for c in IMPORT_CATEGORIES] + \
                 ["indicative_category_count", "static_crypto_libs"]
    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"\n[saved] static features -> {out_csv}")


def main():
    parser = argparse.ArgumentParser(description="Extract static PE-import ransomware features.")
    parser.add_argument("report_path", nargs="?", help="Single report.json")
    parser.add_argument("--batch", metavar="DIR", help="Directory of *.json to scan")
    parser.add_argument("--out", default="static_features.csv", help="CSV output (batch mode)")
    args = parser.parse_args()

    if args.batch:
        run_batch(args.batch, args.out)
    elif args.report_path:
        print_single(args.report_path)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()