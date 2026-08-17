#!/usr/bin/env python3
"""
fetch_github_installers.py - Collect Windows installers from GitHub releases.

Why this source
---------------
The PortableApps catalogue yielded twelve usable downloads out of a hundred
attempts, whatever the count asked for: most of its links go through an
interstitial that does not resolve to a file, and raising the request count
does not find more of them.

GitHub releases have none of those problems. The API lists assets directly,
the download URLs are permanent, and the projects are open source with
published build pipelines -- which matters for a set that will be described
in a thesis as benign software. SourceForge was considered and rejected: its
history of bundling adware into third-party installers means a sample from
there cannot be asserted to be clean without checking each one.

What is collected
-----------------
Installers, not archives. A .exe or .msi that unpacks hundreds of files into
Program Files is the behaviour the benign set is missing; a .zip of the same
program is just a file the sandbox will not open.

Projects are named explicitly rather than discovered, because "popular
Windows software on GitHub" is not a reproducible selection and a thesis
should be able to say exactly what was in the set. The list below is
recognisable desktop software with Windows installers, and can be extended
by anyone repeating this.

Usage
-----
  python3 fetch_github_installers.py --outdir ~/installers
  python3 fetch_github_installers.py --outdir ~/installers --extra owner/repo
"""

import os
import re
import csv
import json
import time
import hashlib
import argparse
import urllib.request
import urllib.error

API = "https://api.github.com/repos/{repo}/releases/latest"
UA = "research-sample-collection"

# Desktop applications with Windows installers. Chosen for being widely used,
# open source, and packaged with a real installer rather than a zip.
PROJECTS = [
    # Confirmed to publish a Windows .exe or .msi installer as a release
    # asset. Projects that ship only a zip are omitted: an archive is not an
    # installer and the sandbox will not unpack one on its own.
    "notepad-plus-plus/notepad-plus-plus",
    "microsoft/PowerToys",
    "PowerShell/PowerShell",
    "ShareX/ShareX",
    "keepassxreboot/keepassxc",
    "obsproject/obs-studio",
    "HandBrake/HandBrake",
    "audacity/audacity",
    "jgraph/drawio-desktop",
    "Zettlr/Zettlr",
    "marktext/marktext",
    "rustdesk/rustdesk",
    "QL-Win/QuickLook",
    "peazip/PeaZip",
    "git-for-windows/git",
    "neovim/neovim",
    "mumble-voip/mumble",
    "gitextensions/gitextensions",
    "openscad/openscad",
    "OpenRCT2/OpenRCT2",
    "ImageMagick/ImageMagick",
    "cli/cli",
    "sqlitebrowser/sqlitebrowser",
    "AutoHotkey/AutoHotkey",
    "srwi/EverythingToolbar",
    "WinMerge/winmerge",
    "greenshot/greenshot",
    "flameshot-org/flameshot",
    "espanso/espanso",
    "ImageGlass/ImageGlass",
    "SubtitleEdit/subtitleedit",
    "MediaArea/MediaInfo",
    "transmission/transmission",
    "ArtifexSoftware/ghostpdl-downloads",
    "pbatard/rufus",
    "TortoiseGit/TortoiseGit",
    "Maximus5/ConEmu",
    "dail8859/NotepadNext",
    "lostindark/DriverStoreExplorer",
    "microsoft/winget-cli",
]

INSTALLER = re.compile(r"(?i)\.(exe|msi)$")
# Debug symbols and portable zips carry the same extension in some projects
# but are not installers.
SKIP = re.compile(r"(?i)(symbols|pdb|debug|portable|\.zip\.exe$|sha256|\.sig$)")


def get(url, timeout=60, token=None):
    headers = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def assets_for(repo, token, max_mb):
    try:
        data = json.loads(get(API.format(repo=repo), token=token))
    except urllib.error.HTTPError as e:
        return [], f"HTTP {e.code}"
    except Exception as e:
        return [], type(e).__name__

    out = []
    for a in data.get("assets", []):
        name = a.get("name", "")
        if not INSTALLER.search(name) or SKIP.search(name):
            continue
        size = a.get("size", 0)
        if size > max_mb * 1e6 or size < 50_000:
            continue
        out.append((name, a.get("browser_download_url"), size))
    # One per project: several architectures of the same installer behave
    # identically and would only inflate the count.
    out.sort(key=lambda x: x[2])
    return out[:1], data.get("tag_name", "")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outdir", default="./github_installers")
    parser.add_argument("--max-mb", type=float, default=80)
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN"),
                         help="Optional. Without one the API allows 60 "
                              "requests an hour, which is enough for this list.")
    parser.add_argument("--extra", nargs="*", default=[],
                         help="Additional owner/repo entries")
    parser.add_argument("--list-only", action="store_true")
    args = parser.parse_args()

    outdir = os.path.expanduser(args.outdir)
    os.makedirs(outdir, exist_ok=True)

    repos = PROJECTS + list(args.extra)
    print(f"querying {len(repos)} projects")

    found, missing = [], []
    for i, repo in enumerate(repos, 1):
        assets, tag = assets_for(repo, args.token, args.max_mb)
        if assets:
            for name, url, size in assets:
                found.append((repo, name, url, size, tag))
        else:
            missing.append((repo, tag))
        if i % 10 == 0:
            print(f"\r   {i}/{len(repos)}  found {len(found)}", end="", flush=True)
        time.sleep(0.25)
    print(f"\r   {len(repos)}/{len(repos)}  found {len(found)}")

    if missing:
        print(f"\n{len(missing)} projects had no installer asset:")
        for repo, why in missing[:10]:
            print(f"   {repo:<40}{why}")

    if args.list_only:
        print()
        for repo, name, _u, size, tag in found:
            print(f"   {size/1e6:>7.1f} MB  {repo:<38}{name}")
        return

    rows, failed = [], []
    for i, (repo, name, url, size, tag) in enumerate(found, 1):
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)
        path = os.path.join(outdir, safe)
        if os.path.exists(path) and os.path.getsize(path) > 50_000:
            blob = None
        else:
            try:
                blob = get(url, timeout=300)
            except Exception as e:
                failed.append((name, type(e).__name__)); continue
            if not blob.startswith(b"MZ") and not safe.lower().endswith(".msi"):
                failed.append((name, "not a PE file")); continue
            with open(path, "wb") as f:
                f.write(blob)
        with open(path, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        rows.append({"filename": safe, "repo": repo, "tag": tag,
                      "bytes": os.path.getsize(path), "sha256": sha, "url": url})
        print(f"\r   downloaded {i}/{len(found)}", end="", flush=True)
        time.sleep(0.2)
    print()

    if failed:
        print(f"\n{len(failed)} failed")
        for n, why in failed[:8]:
            print(f"   {n:<44}{why}")

    manifest = os.path.join(outdir, "github_manifest.csv")
    with open(manifest, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["filename", "repo", "tag",
                                           "bytes", "sha256", "url"])
        w.writeheader(); w.writerows(rows)

    total = sum(r["bytes"] for r in rows)
    print(f"\n{len(rows)} installers, {total/1e6:.0f} MB")
    print(f"[saved] {manifest}")
    print("\nSubmit with a silent-install argument where the packaging supports")
    print("one -- /S for NSIS, /quiet /norestart for MSI, /VERYSILENT for Inno")
    print("Setup -- and without one otherwise. An installer that stops at its")
    print("first dialog is still a data point: signed software that ran and")
    print("did almost nothing.")


if __name__ == "__main__":
    main()
