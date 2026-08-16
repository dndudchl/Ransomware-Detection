#!/usr/bin/env python3
"""
make_scripts.py - Generate benign scripts that manipulate files.

Why scripts, when the matrix already covers the behaviours
----------------------------------------------------------
Every hard negative so far is a C binary compiled by the same toolchain, run
as a single process. That makes them uniform in ways the experiment did not
intend: around sixty imports each against a hundred or more for the
ransomware, the same compiler artefacts throughout, and one process in the
tree.

A script has none of that. The sample the sandbox records is powershell.exe
or wscript.exe or cmd.exe -- signed by Microsoft, with an import table that
says nothing whatever about what the script does. The file work happens in a
process the static features cannot see into, and it happens through the
interpreter's own API usage rather than direct calls.

That separates two things the C variants confound. If a variant that copies
and deletes every document is detected, is it because of the file operations
or because of what the binary looked like? The same operations written in
PowerShell answer that: the binary is now powershell.exe, and it is the same
powershell.exe for the script that only reads.

There is a second reason. Administrators automate exactly this. A backup
script, a bulk rename, a cleanup of old temporary files -- these are written
in PowerShell and scheduled, and if a detector fires on them it fires on
routine operations work.

What is generated
-----------------
Four languages against five methods against three scopes and three volumes,
which is the same factorial the C matrix uses, so the two sets can be
compared directly.

Nothing here is obfuscated or evasive. Every script is readable and does
what it says.

Usage
-----
  python3 make_scripts.py --count 60 --outdir ~/scripts
"""

import os
import csv
import random
import argparse
from collections import Counter

SCOPES = {
    "documents": (r"$env:USERPROFILE\Documents", r"%USERPROFILE%\Documents"),
    "desktop":   (r"$env:USERPROFILE\Desktop",   r"%USERPROFILE%\Desktop"),
    "profile":   (r"$env:USERPROFILE",           r"%USERPROFILE%"),
    "appdata":   (r"$env:LOCALAPPDATA",          r"%LOCALAPPDATA%"),
}

METHODS = {
    "read":      "read every file, change nothing",
    "copy":      "write a copy beside each, originals kept",
    "copydel":   "write a copy, then remove the original",
    "rename":    "rename onto a shared extension",
    "scratch":   "write temporary files, then remove them",
}

LIMITS = [10, 50, 0]     # 0 means no limit


# ---------------------------------------------------------------- PowerShell

def ps1(method, scope, limit):
    root = SCOPES[scope][0]
    take = f"| Select-Object -First {limit} " if limit else ""
    head = f'''# Routine file maintenance.
$root = "{root}"
$files = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue {take}
Write-Host "found $($files.Count) files under $root"
'''
    body = {
        "read": '''
foreach ($f in $files) {
    try { [System.IO.File]::ReadAllBytes($f.FullName) | Out-Null } catch { }
}
Write-Host "read complete"
''',
        "copy": '''
foreach ($f in $files) {
    try { Copy-Item $f.FullName "$($f.FullName).bak" -ErrorAction Stop } catch { }
}
Write-Host "copies written"
''',
        "copydel": '''
foreach ($f in $files) {
    try {
        Copy-Item $f.FullName "$($f.FullName).archived" -ErrorAction Stop
        Remove-Item $f.FullName -Force -ErrorAction Stop
    } catch { }
}
Write-Host "archived and removed"
''',
        "rename": '''
foreach ($f in $files) {
    try { Rename-Item $f.FullName "$($f.Name).processed" -ErrorAction Stop } catch { }
}
Write-Host "renamed"
''',
        "scratch": '''
# Stage each file's contents to a temporary copy and clean up, the way a
# converter or a build step does.
foreach ($f in $files) {
    $tmp = "$($f.FullName).tmp"
    try {
        Copy-Item $f.FullName $tmp -ErrorAction Stop
        Remove-Item $tmp -Force -ErrorAction Stop
    } catch { }
}
Write-Host "scratch files cleaned up"
''',
    }[method]
    return head + body


# ---------------------------------------------------------------------- VBS

def vbs(method, scope, limit):
    root = SCOPES[scope][1]
    cap = f"    If n >= {limit} Then Exit Sub" if limit else ""
    action = {
        "read": '''      Set st = fso.OpenTextFile(f.Path, 1, False)
      On Error Resume Next
      junk = st.ReadAll
      st.Close
      On Error GoTo 0''',
        "copy": '''      On Error Resume Next
      fso.CopyFile f.Path, f.Path & ".bak"
      On Error GoTo 0''',
        "copydel": '''      On Error Resume Next
      fso.CopyFile f.Path, f.Path & ".archived"
      fso.DeleteFile f.Path, True
      On Error GoTo 0''',
        "rename": '''      On Error Resume Next
      f.Name = f.Name & ".processed"
      On Error GoTo 0''',
        "scratch": '''      On Error Resume Next
      fso.CopyFile f.Path, f.Path & ".tmp"
      fso.DeleteFile f.Path & ".tmp", True
      On Error GoTo 0''',
    }[method]
    return f''' ' Routine file maintenance.
Dim fso, n
Set fso = CreateObject("Scripting.FileSystemObject")
n = 0

Sub Walk(path)
  Dim folder, f, sub_
  On Error Resume Next
  Set folder = fso.GetFolder(path)
  If Err.Number <> 0 Then Exit Sub
  On Error GoTo 0
  For Each f In folder.Files
{cap}
{action}
    n = n + 1
  Next
  For Each sub_ In folder.SubFolders
    Walk sub_.Path
  Next
End Sub

Walk fso.GetAbsolutePathName(CreateObject("WScript.Shell").ExpandEnvironmentStrings("{root}"))
WScript.Echo "processed " & n & " files"
'''


# ---------------------------------------------------------------------- Batch

def bat(method, scope, limit):
    root = SCOPES[scope][1]
    action = {
        "read": 'type "%%f" > nul 2>&1',
        "copy": 'copy /y "%%f" "%%f.bak" > nul 2>&1',
        "copydel": 'copy /y "%%f" "%%f.archived" > nul 2>&1 && del /f /q "%%f" > nul 2>&1',
        "rename": 'ren "%%f" "%%~nxf.processed" > nul 2>&1',
        "scratch": 'copy /y "%%f" "%%f.tmp" > nul 2>&1 && del /f /q "%%f.tmp" > nul 2>&1',
    }[method]
    # A goto out of a parenthesised for body does not reliably stop the
    # loop in cmd, so the limit is enforced by guarding the work instead:
    # the loop still walks every path but stops acting after the cap.
    guard = (f"  if !n! lss {limit} ({action}& set /a n+=1)"
             if limit else f"  {action}& set /a n+=1")
    return f'''@echo off
rem Routine file maintenance.
setlocal enabledelayedexpansion
set n=0
for /r "{root}" %%f in (*) do (
{guard}
)
echo processed !n! files
'''


# ------------------------------------------------------------------------ JS

def js(method, scope, limit):
    root = SCOPES[scope][1]
    action = {
        "read": '''      try { var st = fso.OpenTextFile(f.Path, 1, false); st.ReadAll(); st.Close(); }
      catch (e) { }''',
        "copy": '''      try { fso.CopyFile(f.Path, f.Path + ".bak"); } catch (e) { }''',
        "copydel": '''      try { fso.CopyFile(f.Path, f.Path + ".archived");
                   fso.DeleteFile(f.Path, true); } catch (e) { }''',
        "rename": '''      try { f.Name = f.Name + ".processed"; } catch (e) { }''',
        "scratch": '''      try { fso.CopyFile(f.Path, f.Path + ".tmp");
                   fso.DeleteFile(f.Path + ".tmp", true); } catch (e) { }''',
    }[method]
    cap = f"      if (n >= {limit}) return;" if limit else ""
    return f'''// Routine file maintenance.
var fso = new ActiveXObject("Scripting.FileSystemObject");
var shell = new ActiveXObject("WScript.Shell");
var n = 0;

function walk(path) {{
  var folder;
  try {{ folder = fso.GetFolder(path); }} catch (e) {{ return; }}
  var it = new Enumerator(folder.files);
  for (; !it.atEnd(); it.moveNext()) {{
    var f = it.item();
{cap}
{action}
    n++;
  }}
  var sub = new Enumerator(folder.SubFolders);
  for (; !sub.atEnd(); sub.moveNext()) walk(sub.item().Path);
}}

walk(shell.ExpandEnvironmentStrings("{root}"));
WScript.Echo("processed " + n + " files");
'''


LANGUAGES = {"ps1": ps1, "vbs": vbs, "bat": bat, "js": js}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=60)
    parser.add_argument("--outdir", default="./scripts")
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    outdir = os.path.expanduser(args.outdir)
    os.makedirs(outdir, exist_ok=True)
    rng = random.Random(args.seed)

    # Enumerate the full grid and sample from it, so that the four languages
    # stay balanced against each other -- the point of the set is comparing
    # them, which needs the other factors to match across languages.
    grid = [(lang, m, s, l)
            for lang in LANGUAGES
            for m in METHODS
            for s in SCOPES
            for l in LIMITS]
    rng.shuffle(grid)
    chosen = grid[:args.count]

    rows = []
    for lang, method, scope, limit in chosen:
        tag = f"{limit if limit else 'all'}"
        name = f"s_{lang}_{method}_{scope}_{tag}.{lang}"
        path = os.path.join(outdir, name)
        with open(path, "w", newline="\r\n") as f:
            f.write(LANGUAGES[lang](method, scope, limit))
        rows.append({"filename": name, "language": lang, "method": method,
                      "scope": scope, "limit": limit,
                      "description": f"{METHODS[method]}, under {scope}, "
                                     f"{'all files' if not limit else str(limit) + ' files'}",
                      "bytes": os.path.getsize(path)})

    manifest = os.path.join(outdir, "script_manifest.csv")
    with open(manifest, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["filename", "language", "method",
                                           "scope", "limit", "description", "bytes"])
        w.writeheader(); w.writerows(rows)

    print(f"{len(rows)} scripts in {outdir}")
    for k in ("language", "method", "scope"):
        print(f"   {k:<10}{dict(sorted(Counter(r[k] for r in rows).items()))}")
    print(f"[saved] {manifest}")
    print()
    print("Submit without naming a package; the extension picks the handler.")
    print("The process the sandbox records will be powershell.exe, wscript.exe")
    print("or cmd.exe, which is the point: the static features describe the")
    print("interpreter and say nothing about what the script does with files.")


if __name__ == "__main__":
    main()
