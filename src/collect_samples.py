#!/usr/bin/env python3
"""
collect_samples.py - Automated ransomware sample collection from
MalwareBazaar, with manifest-based duplicate prevention.

What it does
------------
For each malware family given:
  1. Query MalwareBazaar's API for recent samples of that family
     (query=get_siginfo).
  2. Check each returned sha256 against the local manifest CSV. Samples
     already collected (or already submitted/analyzed) are skipped, so we
     never re-download or re-submit the same binary. This addresses a real
     problem from earlier in the project, where three legacy reports turned
     out to be the same sample and it was only noticed by accident.
  3. Download the new ones (query=get_file). MalwareBazaar serves samples
     as ZIP archives password-protected with "infected" to prevent
     accidental execution.
  4. Extract each archive into the samples directory, named by sha256.
  5. Register the sample in the manifest with family/source metadata and
     status=pending, ready for CAPE submission.

Family prioritisation
---------------------
Empirically, the families most likely to actually detonate in our sandbox
are the ones we have already observed detonating: Cuba, Babuk, RansomEXX,
AvosLocker, SunCrypt (all confirmed TRUE_ENCRYPTION in the legacy Cuckoo
dataset). Families known to be heavily packed or to resolve APIs at
runtime (notably Conti) have a much lower success rate and are lower
priority. Pass whichever families you want as arguments.

Security notes
--------------
- The Auth-Key is read from the MB_AUTH_KEY environment variable and is
  NEVER written to disk or committed. Do not hardcode it.
- Downloaded files are real malware. Keep the samples directory outside
  any synced/backed-up folder, exclude it from antivirus, and never mark
  the files executable on the host. They exist only to be submitted to
  the sandbox VM.
- The manifest contains only hashes and metadata, so it is safe to commit.

Requirements
------------
  pip install requests pyzipper
(pyzipper is needed because MalwareBazaar's archives use AES encryption,
which Python's built-in zipfile module cannot decrypt.)

Usage
-----
  export MB_AUTH_KEY="your-key-here"

  # List what's available without downloading (safe dry run)
  python3 collect_samples.py --families Cuba Babuk --limit 10 --dry-run

  # Actually download new samples
  python3 collect_samples.py --families Cuba Babuk RansomEXX \\
      --limit 10 --samples-dir ~/samples --manifest manifest.csv

  # Restrict to a file type (recommended: exe, since our CAPE pipeline
  # submits with --package exe)
  python3 collect_samples.py --families Cuba --limit 20 --file-type exe
"""

import os
import sys
import csv
import time
import argparse
from pathlib import Path
from datetime import datetime, timezone

API_URL = "https://mb-api.abuse.ch/api/v1/"
ZIP_PASSWORD = b"infected"

# Manifest schema must stay in sync with manifest.py
FIELDNAMES = [
    "sha256", "original_filename", "family", "source", "label",
    "added_date", "status", "cape_task_id", "result", "notes",
]

# Families we have empirically observed detonating successfully.
SUGGESTED_FAMILIES = ["Cuba", "Babuk", "RansomEXX", "AvosLocker", "SunCrypt"]


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def load_manifest(manifest_path):
    if not os.path.exists(manifest_path):
        return {}
    entries = {}
    with open(manifest_path, newline="") as f:
        for row in csv.DictReader(f):
            entries[row["sha256"]] = row
    return entries


def save_manifest(manifest_path, entries):
    with open(manifest_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for sha, row in sorted(entries.items(), key=lambda kv: kv[1].get("added_date", "")):
            writer.writerow({k: row.get(k, "") for k in FIELDNAMES})


def get_auth_key():
    key = os.environ.get("MB_AUTH_KEY")
    if not key:
        print("[!] MB_AUTH_KEY environment variable is not set.")
        print("    Get a free key at https://auth.abuse.ch/ then run:")
        print('      export MB_AUTH_KEY="your-key-here"')
        sys.exit(1)
    return key


def query_family(session, auth_key, family, limit):
    """Query MalwareBazaar for recent samples of a given family signature."""
    try:
        response = session.post(
            API_URL,
            data={"query": "get_siginfo", "signature": family, "limit": str(limit)},
            headers={"Auth-Key": auth_key},
            timeout=30,
        )
    except Exception as e:
        print(f"   [!] request failed for {family}: {e}")
        return []

    if response.status_code != 200:
        print(f"   [!] HTTP {response.status_code} for {family}")
        return []

    try:
        payload = response.json()
    except ValueError:
        print(f"   [!] non-JSON response for {family}")
        return []

    status = payload.get("query_status")
    if status != "ok":
        # Common statuses: no_results, signature_not_found, illegal_signature
        print(f"   [!] query_status={status} for {family}")
        return []

    return payload.get("data", []) or []


def download_sample(session, auth_key, sha256):
    """Download one sample by sha256. Returns raw zip bytes, or None."""
    try:
        response = session.post(
            API_URL,
            data={"query": "get_file", "sha256_hash": sha256},
            headers={"Auth-Key": auth_key},
            timeout=60,
        )
    except Exception as e:
        print(f"      [!] download failed: {e}")
        return None

    if response.status_code != 200:
        print(f"      [!] HTTP {response.status_code}")
        return None

    content = response.content
    # An error is returned as JSON; a real sample is a binary zip.
    if content[:2] != b"PK":
        try:
            import json
            err = json.loads(content.decode("utf-8", "ignore"))
            print(f"      [!] API error: {err.get('query_status', content[:100])}")
        except Exception:
            print(f"      [!] unexpected response (not a zip)")
        return None

    return content


def extract_sample(zip_bytes, sha256, samples_dir):
    """Extract the password-protected archive. Returns extracted path or None."""
    try:
        import pyzipper
    except ImportError:
        print("      [!] pyzipper not installed (pip install pyzipper)")
        return None

    import io
    tmp_zip = samples_dir / f"{sha256}.zip"
    tmp_zip.write_bytes(zip_bytes)

    try:
        with pyzipper.AESZipFile(io.BytesIO(zip_bytes)) as zf:
            zf.setpassword(ZIP_PASSWORD)
            names = zf.namelist()
            if not names:
                print("      [!] archive is empty")
                return None
            # MalwareBazaar archives contain a single file named by hash
            data = zf.read(names[0])
    except Exception as e:
        print(f"      [!] extraction failed: {e}")
        return None
    finally:
        tmp_zip.unlink(missing_ok=True)

    out_path = samples_dir / sha256
    out_path.write_bytes(data)
    # Ensure it is not executable on the host; it is only for sandbox submission.
    os.chmod(out_path, 0o600)
    return out_path


def main():
    parser = argparse.ArgumentParser(
        description="Collect ransomware samples from MalwareBazaar with duplicate prevention.")
    parser.add_argument("--families", nargs="+", default=SUGGESTED_FAMILIES,
                         help=f"Family signatures to query (default: {' '.join(SUGGESTED_FAMILIES)})")
    parser.add_argument("--limit", type=int, default=10,
                         help="Max samples to request per family (default: 10)")
    parser.add_argument("--samples-dir", default="./samples",
                         help="Directory to store downloaded samples (default: ./samples)")
    parser.add_argument("--manifest", default="manifest.csv",
                         help="Manifest CSV path (default: manifest.csv)")
    parser.add_argument("--file-type", default=None,
                         help="Only take samples whose file_type matches (e.g. exe)")
    parser.add_argument("--dry-run", action="store_true",
                         help="Query and report what would be downloaded, but download nothing")
    parser.add_argument("--delay", type=float, default=1.0,
                         help="Seconds to wait between downloads (be polite to the API)")
    args = parser.parse_args()

    try:
        import requests
    except ImportError:
        print("[!] requests not installed (pip install requests)")
        sys.exit(1)

    auth_key = get_auth_key()
    samples_dir = Path(args.samples_dir)
    if not args.dry_run:
        samples_dir.mkdir(parents=True, exist_ok=True)

    manifest = load_manifest(args.manifest)
    print(f"Manifest: {args.manifest} ({len(manifest)} known hashes)")
    print(f"Families: {', '.join(args.families)}   limit/family: {args.limit}")
    if args.file_type:
        print(f"Filtering to file_type == {args.file_type}")
    if args.dry_run:
        print("DRY RUN -- nothing will be downloaded\n")
    else:
        print(f"Samples dir: {samples_dir.resolve()}\n")

    session = requests.Session()
    total_new = total_dupe = total_downloaded = total_failed = 0

    for family in args.families:
        print(f"[{family}]")
        entries = query_family(session, auth_key, family, args.limit)
        if not entries:
            print("   (no results)\n")
            continue

        if args.file_type:
            entries = [e for e in entries
                       if (e.get("file_type") or "").lower() == args.file_type.lower()]

        new_entries, dupe_count = [], 0
        for entry in entries:
            sha = entry.get("sha256_hash")
            if not sha:
                continue
            if sha in manifest:
                dupe_count += 1
            else:
                new_entries.append(entry)

        total_new += len(new_entries)
        total_dupe += dupe_count
        print(f"   {len(entries)} returned | {len(new_entries)} new | {dupe_count} already known")

        for entry in new_entries:
            sha = entry["sha256_hash"]
            fname = entry.get("file_name", "")
            ftype = entry.get("file_type", "")
            print(f"   - {sha[:16]}... {fname[:36]:<38} type={ftype}")

            if args.dry_run:
                continue

            zip_bytes = download_sample(session, auth_key, sha)
            if not zip_bytes:
                total_failed += 1
                continue

            out_path = extract_sample(zip_bytes, sha, samples_dir)
            if not out_path:
                total_failed += 1
                continue

            manifest[sha] = {
                "sha256": sha,
                "original_filename": fname,
                "family": family,
                "source": "malwarebazaar",
                "label": "ransomware",
                "added_date": now_iso(),
                "status": "pending",
                "cape_task_id": "",
                "result": "",
                "notes": f"file_type={ftype}",
            }
            save_manifest(args.manifest, manifest)
            total_downloaded += 1
            print(f"      -> saved {out_path.name} and registered in manifest")
            time.sleep(args.delay)

        print()

    print("=" * 60)
    print(f"New samples found:  {total_new}")
    print(f"Already in manifest: {total_dupe}")
    if not args.dry_run:
        print(f"Downloaded:          {total_downloaded}")
        print(f"Failed:              {total_failed}")
        print(f"\nNext: submit pending samples to CAPE, then record results:")
        print(f"   python3 manifest.py list --status pending")
        print(f"   python3 manifest.py mark-submitted <sha256> --task-id <N>")
        print(f"   python3 manifest.py mark-result <sha256> --result TRUE_ENCRYPTION")


if __name__ == "__main__":
    main()
