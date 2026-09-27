# File Origin Scan

Point it at a messy folder. It tells you which installed program every loose `.exe` / `.dll` belongs to — **before** you delete anything.

Windows only. One PowerShell script, no dependencies, nothing to install. Strictly read-only: it never deletes, moves or modifies a file.

---

## The problem

A drive root or a downloads folder slowly fills with files nobody can identify:

```text
D:\
|-- iTunes.exe            which program is this?
|-- WebKit.dll
|-- vcruntime140_1.dll    can I delete this?
|-- gnsdk_musicid.dll
|-- setup.tmp
`-- pagefile.sys          deleting this breaks Windows
```

Guessing is expensive: the wrong deletion breaks an installed program, and deleting a Windows system file can destabilise the machine. This tool answers "who put this here?" with evidence instead of a guess.

## Quick start

```powershell
# Look at a drive root
.\FileOriginScan.ps1 -Path D:\

# Walk a whole folder tree, skip signature checks for speed
.\FileOriginScan.ps1 -Path "$env:USERPROFILE\Downloads" -Recurse -SkipSignature
```

Prefer clicking? Double-click `Run-FileOriginScan.cmd`, type a folder (or drag a folder onto the .cmd) and answer whether to include subfolders.

Every run writes three reports into `reports\` next to the script: an HTML report to read, JSON to script against, and CSV for Excel.

## How it works

Each file is matched against independent sources of evidence. The strongest match wins.

| Evidence | Meaning | Confidence |
| --- | --- | --- |
| **Install path** | The file lives inside an `InstallLocation` recorded in an installed program's uninstall registry key | High |
| **Product metadata** | The file's version resource (ProductName / FileDescription / OriginalFilename) names an installed program | Medium |
| **Vendor match** | The file's CompanyName or Authenticode signer matches an installed program's Publisher | Low |
| **Built-in component table** | The filename matches a known shared library (VC++ runtime, Bonjour, WebKit, ICU, SQLite, DirectX, ...) | Reference |

On top of the matching:

- **PE header parsing** — every executable is inspected to report its real architecture (`x86` / `x64` / `ARM64`), so 32/64-bit mixing is visible at a glance.
- **Authenticode status** — files without a valid signature are counted and listed. Unsigned is not automatically bad; it is a lead.
- **Unknown-origin detection** — an executable with no version resource, no signature and no matching installed program is flagged separately. That is the classic "leftover, or part of a portable app?" case.
- **System file protection** — `pagefile.sys`, `hiberfil.sys`, `swapfile.sys` and friends are recognised and explicitly marked do-not-delete, with the supported way to adjust them instead.

Installed programs are read from `HKLM` (including `WOW6432Node`) and `HKCU` uninstall keys. A file that lives in a drive root while the registry says the program is installed *in that drive root* is reported as exactly that — the most common cause of a root folder full of program files.

## Output

| File | Purpose |
| --- | --- |
| `*.html` | Report to read: overview, conclusions, attribution table, full file list, unknown-origin list, suggested actions |
| `*.json` | Same data for scripting (English property names, stable shape) |
| `*.csv` | File list for Excel or further filtering |

Console summary for a small folder:

```text
  文件总数    : 5
  占用空间    : 2.1 MB
  已归属      : 2
  未归属      : 1
  来源不明    : 1
  未签名      : 1
  来源数量    : 1
  架构分布    : x64 2
```

See [examples/sample-report.html](examples/sample-report.html) for a full rendered report (open it in a browser).

Report text is Chinese (the maintainer's first language); the JSON keys and CSV headers are English, so downstream scripting stays language-neutral. A `-Language en` switch is on the roadmap.

## Parameters

| Parameter | Effect |
| --- | --- |
| `-Path <folder>` | Folder to scan. Asked interactively if omitted |
| `-Recurse` | Include subfolders |
| `-MaxFiles <n>` | Cap the number of analysed files (default 5000); truncation is reported |
| `-SkipSignature` | Do not check Authenticode signatures (faster, slightly less precise) |
| `-ForceSignature` | Check signatures even when more than 500 files are found (slower) |
| `-OutDir <folder>` | Where to write reports (default: `reports\` next to the script) |
| `-OutFile <file>` | Explicit path of the HTML report; JSON/CSV land beside it |
| `-Quiet` | Print only the report paths |

## Requirements

- Windows 10 / 11 (or Windows Server 2016+)
- Windows PowerShell 5.1 (built into Windows) or PowerShell 7+
- No admin rights needed: the tool only reads file metadata, PE headers, signatures and the current user's registry hives

## Safety

The tool is read-only by design. It has no delete, move or cleanup mode, and it tells you why it thinks a file belongs to something rather than acting on it. Removing files stays a human decision.

## Limitations

- Only software registered in the uninstall registry can be identified, so portable apps and leftovers of already-uninstalled software fall into *unknown origin* by definition.
- Signature checks are skipped by default above 500 files (`-ForceSignature` overrides).
- Publisher matching is token-based and works for Latin-script company names; Chinese product names are matched through product metadata instead.
- Heuristics are confidence-ranked, not proof. The report states its reasoning for every file so you can judge it.

## Testing

```powershell
./tests/Test-FileOriginScan.ps1
```

The suite is black-box: it builds a throwaway folder tree plus a temporary uninstall-registry entry, runs the tool the way a user would, and asserts on the JSON, HTML and CSV it produces (23 checks covering attribution, component table, system files, unknown-origin detection, recursion, `-MaxFiles`, `-SkipSignature`, empty folders and real PE architecture). It runs on both Windows PowerShell 5.1 and PowerShell 7 — see `.github/workflows/ci.yml`.

## License

MIT — see [LICENSE](LICENSE).
