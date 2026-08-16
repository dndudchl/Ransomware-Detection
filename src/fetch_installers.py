#!/usr/bin/env python3
"""
fetch_installers.py - Download real installers to submit as benign samples.

Why these are the samples the set is short of
---------------------------------------------
A PortableApps installer, run, unpacks several hundred to several thousand
files onto disk. That is ransomware-scale file activity produced by signed
software doing exactly what the user asked, and it is the case the benign set
does not contain: of 1,563 DikeDataset programs, 1,262 never executed and the
301 that did were mostly small.

It also answers the objection the constructed hard negatives cannot. Those
were written for this experiment, and a reviewer is entitled to discount
them on that basis. An installer downloaded from its publisher was not.

How the list is obtained
------------------------
PortableApps publishes its catalogue as an index page of application entries,
each linking to a SourceForge download. Rather than hardcode URLs that rot,
this reads the index and follows the links, checking that what comes back is
actually a PE file before keeping it. Anything that fails is reported rather
than silently skipped, because a directory of half-downloaded files submitted
to a sandbox produces analyses that fail for reasons nothing to do with the
experiment.

If the site layout has changed and nothing is found, pass --url-file with one
download URL per line; the download, verification and manifest steps are the
same either way.

Usage
-----
  python3 fetch_installers.py --count 150 --outdir ~/installers
  python3 fetch_installers.py --url-file urls.txt --outdir ~/installers
"""

import os
import re
import csv
import time
import hashlib
import argparse
import urllib.request
import urllib.error

INDEX = "https://portableapps.com/apps"

# Microsoft publishes the whole Sysinternals set as one archive at a stable
# address, so this needs no scraping and cannot pick up a repackaged
# installer by accident.
#
# These are the most relevant benign samples available. Every one is signed
# by Microsoft, and several do precisely what the threat model describes:
# sdelete overwrites a file repeatedly and then removes it, which is the
# shape m7_wipe was written to imitate; du, accesschk, streams and sigcheck
# walk a directory tree opening everything in it; handle and pslist enumerate
# processes. A detector that fires on these is firing on the administrator's
# toolkit.
SYSINTERNALS = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
UA = "Mozilla/5.0 (compatible; research-sample-collection)"
PE_MAGIC = b"MZ"


def get(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def discover(limit):
    """Follow the catalogue to the download links."""
    try:
        html = get(INDEX).decode("utf-8", "replace")
    except Exception as e:
        print(f"[!] could not read {INDEX}: {type(e).__name__}: {e}")
        return []

    # Two shapes appear: direct links to .paf.exe on the download host, and
    # links to per-application pages that carry one.
    direct = re.findall(r'https?://[^\s"\']+?\.paf\.exe', html)
    if direct:
        seen, out = set(), []
        for u in direct:
            if u not in seen:
                seen.add(u); out.append(u)
        return out[:limit]

    pages = re.findall(r'href="(/apps/[^"#?]+)"', html)
    seen, out = set(), []
    for page in pages:
        if len(out) >= limit:
            break
        url = "https://portableapps.com" + page
        if url in seen:
            continue
        seen.add(url)
        try:
            body = get(url).decode("utf-8", "replace")
        except Exception:
            continue
        found = re.findall(r'https?://[^\s"\']+?\.paf\.exe', body)
        if found:
            out.append(found[0])
        time.sleep(0.4)   # the catalogue is a volunteer-run site
    return out


def download(url, outdir, index):
    name = url.rsplit("/", 1)[-1].split("?")[0]
    if not name.lower().endswith(".exe"):
        name = f"installer_{index:04d}.exe"
    path = os.path.join(outdir, name)
    if os.path.exists(path) and os.path.getsize(path) > 1024:
        return path, os.path.getsize(path), "already present"
    try:
        blob = get(url, timeout=180)
    except Exception as e:
        return None, 0, f"{type(e).__name__}"
    if not blob.startswith(PE_MAGIC):
        # Usually an HTML error page served with a 200, which would otherwise
        # end up in the sandbox as a sample that cannot run.
        return None, len(blob), "not a PE file"
    with open(path, "wb") as f:
        f.write(blob)
    return path, len(blob), "ok"


def fetch_sysinternals(outdir):
    """Unpack the suite and keep the executables."""
    import io
    import zipfile

    print(f"downloading {SYSINTERNALS}")
    try:
        blob = get(SYSINTERNALS, timeout=300)
    except Exception as e:
        print(f"[!] {type(e).__name__}: {e}")
        print("    If this host cannot reach the address, download the archive")
        print("    elsewhere and unzip it into the output directory; the rest")
        print("    of the pipeline only needs the .exe files.")
        return

    rows = []
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        names = [n for n in z.namelist() if n.lower().endswith(".exe")]
        print(f"{len(names)} executables in the archive")
        for n in names:
            data = z.read(n)
            if not data.startswith(PE_MAGIC):
                continue
            # The suite ships 32- and 64-bit builds of the same tool under
            # names differing by a suffix. Both are kept: they are distinct
            # binaries with distinct hashes, and the analysis treats them as
            # separate samples, which is what they are.
            base = os.path.basename(n)
            path = os.path.join(outdir, base)
            with open(path, "wb") as f:
                f.write(data)
            rows.append({"filename": base, "bytes": len(data),
                          "sha256": hashlib.sha256(data).hexdigest(),
                          "url": SYSINTERNALS})

    manifest = os.path.join(outdir, "installer_manifest.csv")
    with open(manifest, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["filename", "bytes", "sha256", "url"])
        w.writeheader(); w.writerows(rows)

    total = sum(r["bytes"] for r in rows)
    print(f"\n{len(rows)} signed utilities, {total / 1e6:.0f} MB")
    print(f"[saved] {manifest}")
    print("\nWorth watching in the results: sdelete overwrites and removes,")
    print("du and accesschk walk the whole tree, and all of them are signed by")
    print("Microsoft. Any of them classified as ransomware is a false positive")
    print("on a tool that ships with the operating system's own support kit.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=150)
    parser.add_argument("--outdir", default="./installers")
    parser.add_argument("--url-file",
                         help="One download URL per line, used instead of "
                              "reading the catalogue")
    parser.add_argument("--sysinternals", action="store_true",
                         help="Fetch the Sysinternals Suite instead of the "
                              "PortableApps catalogue. One archive, around "
                              "seventy signed Microsoft utilities.")
    parser.add_argument("--max-mb", type=float, default=60,
                         help="Skip anything larger; a 400 MB office suite "
                              "spends the analysis window decompressing")
    args = parser.parse_args()

    outdir = os.path.expanduser(args.outdir)
    os.makedirs(outdir, exist_ok=True)

    if args.sysinternals:
        fetch_sysinternals(outdir)
        return

    if args.url_file:
        with open(os.path.expanduser(args.url_file)) as f:
            urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        print(f"{len(urls)} URLs from {args.url_file}")
    else:
        print(f"reading the catalogue for up to {args.count} applications")
        urls = discover(args.count)
        print(f"found {len(urls)} download links")

    if not urls:
        print("\nNothing found. The catalogue layout may have changed.")
        print("Collect the download links by hand into a file, one per line,")
        print("and pass --url-file. Everything after this point is the same.")
        return

    rows, failed = [], []
    for i, url in enumerate(urls[:args.count], 1):
        path, size, status = download(url, outdir, i)
        if path is None:
            failed.append((url.rsplit("/", 1)[-1], status, size))
        elif size > args.max_mb * 1e6:
            os.remove(path)
            failed.append((os.path.basename(path), "too large", size))
        else:
            with open(path, "rb") as f:
                sha = hashlib.sha256(f.read()).hexdigest()
            rows.append({"filename": os.path.basename(path), "bytes": size,
                          "sha256": sha, "url": url})
        if i % 10 == 0 or i == len(urls[:args.count]):
            print(f"\r   {i}/{min(args.count, len(urls))}  kept {len(rows)}",
                  end="", flush=True)
        time.sleep(0.3)
    print()

    if failed:
        print(f"\n[!] {len(failed)} not kept")
        for n, why, sz in failed[:8]:
            print(f"    {n:<44}{why} ({sz:,} bytes)")

    manifest = os.path.join(outdir, "installer_manifest.csv")
    with open(manifest, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["filename", "bytes", "sha256", "url"])
        w.writeheader(); w.writerows(rows)

    total = sum(r["bytes"] for r in rows)
    print(f"\n{len(rows)} installers, {total / 1e6:.0f} MB")
    print(f"[saved] {manifest}")
    print("\nThese unpack hundreds to thousands of files when run, which is")
    print("the level of activity the benign set is missing, from software")
    print("that was not written for this experiment.")


if __name__ == "__main__":
    main()
