# Windows Forensics Artifacts — SOC / DFIR Field Guide

A practical reference for **offline Windows artifact triage**: where evidence is stored, what a finding can (and cannot) prove, and how to examine it using Eric Zimmerman's tools. Intended for SOC analysts and incident responders investigating a copied Windows filesystem or a KAPE collection.

> **Scope:** This is an analyst-oriented reference, not a TryHackMe answer sheet. Examples use illustrative local paths. Work on **copies**, preserve originals, and document timezone and collection context. Artifact availability and format vary by Windows version, configuration, and collection method.

## Quick Reference — Where to Look First

| Investigation question | Artifact / hive | Typical offline location (relative to a collected `C:`) | Suggested tool | Evidence limitation |
|---|---|---|---|---|
| Which local accounts exist? | SAM | `Windows/System32/config/SAM` | Registry Explorer | Does not establish who performed an action |
| What was the hostname and time zone? | SYSTEM | `Windows/System32/config/SYSTEM` | Registry Explorer | `CurrentControlSet` is resolved from `Select` when offline |
| What programs start automatically? | Run / RunOnce | `SOFTWARE` and user `NTUSER.DAT` | Registry Explorer, Autoruns (live systems) | Entry existence does not prove it ran |
| What USB storage has been seen? | USBSTOR / USB / Portable Devices | `SYSTEM`, `SOFTWARE` | Registry Explorer | Connection ≠ file transfer |
| What did the user launch from Explorer? | UserAssist | `Users/<user>/NTUSER.DAT` | Registry Explorer / RECmd | Not a complete process-execution history |
| What applications are recorded as compatible? | ShimCache (AppCompatCache) | `SYSTEM` | AppCompatCacheParser | **Not standalone proof of execution** |
| What executable metadata was inventoried? | Amcache | `Windows/AppCompat/Programs/Amcache.hve` | AmcacheParser | Presence ≠ execution |
| Which binaries were executed, if Prefetch is enabled? | Prefetch `.pf` | `Windows/Prefetch/` | PECmd | Can be absent/disabled, and timestamps need context |
| Which files/paths existed? | NTFS `$MFT` | `C/$MFT` | MFTECmd | File metadata alone does not prove user access |
| What filesystem changes were journaled? | `$UsnJrnl`, `$LogFile` | `C/$Extend/$UsnJrnl:$J`, `C/$LogFile` | MFTECmd / appropriate NTFS tools | Historical coverage is limited/rotating |
| Which files did a user open recently? | LNK, Jump Lists, RecentDocs | User profile and `NTUSER.DAT` | LECmd, JLECmd, Registry Explorer | Often proves interaction/knowledge, not file contents |
| Which apps were in focus? | Windows Timeline | `Users/<user>/AppData/Local/ConnectedDevicesPlatform/L.<profile>/ActivitiesCache.db` | WxTCmd | Data may be missing/limited on newer systems |
| What was browsed/downloaded? | Browser history | Browser profile databases | Browser-specific parsers | Private browsing / deletion may reduce evidence |
| What does the event timeline say? | `.evtx` logs | `Windows/System32/winevt/Logs/` | Event Viewer, `Get-WinEvent` | Only collected and retained events are available |

**Interpretation rule:** *One artifact suggests; multiple independent artifacts corroborate.* Prefer a timeline combining process evidence, user activity, filesystem metadata, and event logs.

---

## 1. Start with the Evidence Collection

A common KAPE-derived folder layout:

```text
triage/
├── C/
│   ├── $MFT
│   ├── $LogFile
│   ├── $Extend/
│   ├── Windows/
│   ├── Users/
│   └── ProgramData/
├── <timestamp>_ConsoleLog.txt
├── <timestamp>_CopyLog.csv
└── <timestamp>_SkipLog.csv
```

- `C/` maps collected artifacts from the **source machine's** system drive; it is **not** the current analyst workstation's live `C:`.
- `CopyLog.csv` and `SkipLog.csv` help establish collection coverage and missing files.
- Record **source hostname**, acquisition method, analyst VM time zone, target time zone, and any collection limitations.
- Do **not** execute unknown binaries from the evidence directory. Handle raw malware samples in an isolated, approved lab if needed.

### Initial triage workflow

1. Check copy/skip logs and note missing artifacts.
2. Identify the operating system, computer name, users, and relevant times.
3. Establish a time window from the alert, report, or suspicious activity.
4. Pick artifacts that answer specific investigative questions.
5. Correlate independent evidence; preserve source paths and timestamps in notes.

---

## 2. Registry Hives — What Belongs Where?

| Hive | Common offline path | Main investigative uses |
|---|---|---|
| `SYSTEM` | `Windows/System32/config/SYSTEM` | Control sets, services, USB device history, system configuration |
| `SOFTWARE` | `Windows/System32/config/SOFTWARE` | Installed software, machine-wide Run keys, Portable Devices |
| `SAM` | `Windows/System32/config/SAM` | Local accounts and account metadata |
| `SECURITY` | `Windows/System32/config/SECURITY` | Local security policy and sensitive system data — restricted handling |
| `NTUSER.DAT` | `Users/<user>/NTUSER.DAT` | Per-user Run keys, UserAssist, RecentDocs, Explorer history |
| `UsrClass.dat` | `Users/<user>/AppData/Local/Microsoft/Windows/UsrClass.dat` | ShellBags and per-user shell associations |
| `Amcache.hve` | `Windows/AppCompat/Programs/Amcache.hve` | Application and file inventory metadata |

### Load a hive in Registry Explorer

1. Launch `RegistryExplorer.exe` from your tools directory.
2. Use **File → Load Hive** and choose the **collected** hive, such as `triage\C\Windows\System32\config\SOFTWARE`.
3. Navigate within the loaded hive; do **not** confuse a registry path with a folder in File Explorer.
4. Export or screenshot relevant keys and values, with their full paths.

**Offline `CurrentControlSet`:** In a loaded `SYSTEM` hive, inspect `Select\Current` (for example, `1` → `ControlSet001`) rather than assuming the live alias `CurrentControlSet` will exist in the exported file.

### Common registry investigation paths

```text
SAM\Domains\Account\Users
SYSTEM\ControlSet00X\Control\ComputerName\ComputerName
SYSTEM\ControlSet00X\Control\TimeZoneInformation
SYSTEM\ControlSet00X\Services\Tcpip\Parameters\Interfaces
SOFTWARE\Microsoft\Windows\CurrentVersion\Run
SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```

The hive name at the start indicates which **file** to load; it is not part of a Windows directory path. For per-user keys, load the particular user's `NTUSER.DAT`.

---

## 3. USB and External Storage Investigation

| Question | Registry location | What to inspect |
|---|---|---|
| What USB storage devices were recorded? | `SYSTEM\ControlSet00X\Enum\USBSTOR` | Vendor/product/instance subkeys |
| What USB devices were recorded more broadly? | `SYSTEM\ControlSet00X\Enum\USB` | Device IDs and instance IDs |
| What was a removable volume called? | `SOFTWARE\Microsoft\Windows Portable Devices\Devices` | Friendly names / volume labels, when present |
| When was a device installed? | `Windows/INF/setupapi.dev.log` | Installation records and time context |
| Did a user interact with files on a device? | LNK, Jump Lists, shell artifacts | Recent paths, volume references, supporting timestamps |

Certain USB device properties under `...\Properties\{83da6326-97a6-4088-9453-a19231573b29}\...` can contain connection-related timestamps (including first install, last arrival, and last removal on applicable Windows versions). **Do not assume all versions expose identical properties or interpret those timestamps without checking the actual property IDs and OS version.**

**Investigation note:** A detected USB device does **not** by itself prove exfiltration. Look for file copy activity, linked file paths, user context, and other corroboration.

---

## 4. Evidence of Execution: Strengths and Limits

### Prefetch

- Path: `Windows/Prefetch/*.pf`.
- Useful fields can include executable name, run count, and one or more recorded last-run times (format and count vary by OS).
- A missing `.pf` file does **not** prove the program never ran.

Parse with **PECmd**:

```cmd
PECmd.exe -d "C:\Cases\triage\C\Windows\Prefetch" --csv "C:\Cases\results"
```

For a single Prefetch file:

```cmd
PECmd.exe -f "C:\Cases\triage\C\Windows\Prefetch\EXAMPLE.EXE-12345678.pf" --csv "C:\Cases\results"
```

### UserAssist

- Hive: per-user `NTUSER.DAT`.
- Path: `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`.
- Values often use ROT13-obfuscated names. Registry Explorer or another forensic parser can decode them.
- Relevant to Explorer-driven application interaction, **not** every execution path.

### ShimCache / AppCompatCache

- Hive: `SYSTEM`.
- Path: `ControlSet00X\Control\Session Manager\AppCompatCache`.
- Contains application compatibility/cache information. **An entry alone is not proof an executable ran**; execution-related interpretation depends on Windows version and accompanying evidence.

### Amcache

- Hive: `Windows/AppCompat/Programs/Amcache.hve`.
- Contains application/file inventory metadata; key layout varies across versions.
- Useful for file names, paths, hashes or identifiers when present; **not sufficient alone to prove execution**.

**Better execution conclusion:** corroborate Prefetch (where available), Sysmon 1 / Security 4688, UserAssist, relevant application logs, and file activity.

---

## 5. NTFS Metadata — `$MFT`, `$LogFile`, `$UsnJrnl`

| Artifact | What it helps answer | Key caution |
|---|---|---|
| `$MFT` | File names, parent paths, timestamps, record metadata | Timestamps can be modified or affected by normal operations; access time is often unreliable as proof of a file being opened |
| `$LogFile` | NTFS transactional activity | Records are not a complete, permanent activity history |
| `$UsnJrnl:$J` | File create, rename, delete and other change notifications | Journal wraps and is subject to retention limits |

### Parse `$MFT` with MFTECmd

From **Command Prompt (`cmd.exe`)**:

```cmd
MFTECmd.exe -f "C:\Users\THM-4n6\Desktop\triage\C\$MFT" --csv "C:\Users\THM-4n6\Desktop\results"
```

In PowerShell, single-quote the source path so `$MFT` is not expanded as a variable:

```powershell
.\MFTECmd.exe -f 'C:\Users\THM-4n6\Desktop\triage\C\$MFT' --csv 'C:\Users\THM-4n6\Desktop\results'
```

> `-f` takes a **file**, not a folder. `--csv` takes an **output directory**. Make sure that output directory exists and that the exact collected `$MFT` file is present.

### Investigating a file such as `Changelog.txt`

1. Open the resulting CSV in EZViewer or a spreadsheet viewer.
2. Filter by filename and review the complete path and parent record.
3. Compare **SI** (`$STANDARD_INFORMATION`) and **FN** (`$FILE_NAME`) timestamp fields.
4. Confirm time-zone handling and whether the question means file metadata *access time* rather than proven human access.
5. Correlate with LNK, Jump Lists, UserAssist, and logs when possible.

**Do not equate a last-access timestamp to verified file reading.** NTFS last-access updates can be disabled, delayed, or triggered by non-user operations.

---

## 6. User Activity — Timeline, Jump Lists, LNK

### Windows Timeline (`ActivitiesCache.db`)

A commonly encountered older location:

```text
Users/<user>/AppData/Local/ConnectedDevicesPlatform/L.<profile>/ActivitiesCache.db
```

Parse with **WxTCmd**:

```cmd
WxTCmd.exe -f "C:\Cases\triage\C\Users\analyst\AppData\Local\ConnectedDevicesPlatform\L.profile\ActivitiesCache.db" --csv "C:\Cases\results"
```

- Search resulting records for application identifiers (for example, `notepad.exe`) and the reported date/time.
- For application focus questions, inspect the parser's duration/focus fields and convert seconds to `HH:MM:SS` if appropriate.
- Timeline availability and retention differ widely; **lack of an entry is not proof of inactivity**.

### Jump Lists

Typical location:

```text
Users/<user>/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/
Users/<user>/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/
```

Use **JLECmd** (single file shown; inspect tool help for directory-processing options in your installed version):

```cmd
JLECmd.exe -f "C:\Cases\example.automaticDestinations-ms" --csv "C:\Cases\results"
```

### Shortcut files (`.lnk`)

Typical location:

```text
Users/<user>/AppData/Roaming/Microsoft/Windows/Recent/
```

Use **LECmd**:

```cmd
LECmd.exe -f "C:\Cases\example.lnk" --csv "C:\Cases\results"
```

LNK and Jump Lists may preserve original target paths, volume data, and file metadata. They often support **file knowledge / interaction**, but cannot by themselves prove that a user read the entire file.

---

## 7. Browser and Recent-File Artifacts

| Artifact | Typical location | Investigation value |
|---|---|---|
| RecentDocs | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | Recently used documents/extensions |
| OpenSavePidlMRU | `...\Explorer\ComDlg32\OpenSavePidlMRU` | File-open/save dialog history |
| LastVisitedPidlMRU | `...\Explorer\ComDlg32\LastVisitedPidlMRU` | Applications/folders involved in dialogs |
| ShellBags | User `NTUSER.DAT` / `UsrClass.dat` | Explorer folder-navigation traces |
| Edge/IE WebCache (older builds) | `Users/<user>/AppData/Local/Microsoft/Windows/WebCache/WebCacheV*.dat` | Web activity in relevant Windows/browser versions |
| Modern Chromium browsers | Per-browser profile databases (often `History`, `Cookies`, `Downloads` records) | URLs, visits and downloads when retained |

**Do not assume `WebCacheV*.dat` is the authoritative source for modern Edge or Chrome.** Identify the browser and its profile first.

---

## 8. Mini SOC / DFIR Playbooks

### A. Suspicious installer was run

1. Locate executable path and hash in the alert or logs.
2. Review Prefetch (if enabled), Amcache, and UserAssist for corroboration.
3. Use `$MFT` to investigate file placement and timestamps.
4. Pivot to process creation (Sysmon 1 / Security 4688) and outbound connections (Sysmon 3 if configured).
5. Record **confidence** and which evidence actually proves execution.

### B. Suspected USB exfiltration

1. Review `SYSTEM` → USBSTOR/USB device instances.
2. Correlate installation/arrival data with `setupapi.dev.log` where applicable.
3. Look at `SOFTWARE` → Portable Devices for the volume name.
4. Search Jump Lists, LNK, and filesystem artifacts for removable drive paths.
5. Correlate user session and file-copy evidence before concluding exfiltration.

### C. Possible persistence

1. Inspect machine-wide and per-user Run/RunOnce entries.
2. Examine services in the relevant `SYSTEM` control set.
3. Look for scheduled-task and startup-folder evidence.
4. Connect the persistence artifact with the referenced binary, its metadata, and execution/connection evidence.
5. Distinguish an installed persistence mechanism from confirmed activation.

---

## 9. Common Mistakes and Fixes

| Problem | Likely cause | Fix |
|---|---|---|
| `MFTECmd` says source file not found | You passed a directory (`...\triage\C`) | Pass the **file** `...\triage\C\$MFT` |
| Parser error with a trailing path `\` | Quoting/argument parsing issue | Use the exact file path without a trailing slash |
| `$MFT` disappears from path in PowerShell | `$MFT` treated as a variable | Use **single quotes** or run from `cmd.exe` |
| `WxTCmd` fails on `triage\C` | Tool requires `ActivitiesCache.db` | Locate the database under the relevant user profile |
| Cannot locate `SOFTWARE\...` in Explorer | Registry key mistaken for a directory | Load the **SOFTWARE hive** in Registry Explorer |
| `CurrentControlSet` not visible offline | Offline hive stores numbered control sets | Resolve it via `SYSTEM\Select\Current` |
| No Prefetch or Timeline results | Artifact absent, disabled, or not collected | Check collection logs and corroborate elsewhere |
| Event timestamps disagree | Timezone, UTC conversion or clock inconsistency | Preserve raw timestamps; normalize in your timeline |

---

## 10. Investigation Notes Template

```text
Case / host:
Source collection and acquisition time:
Evidence file (full path):
Tool + version:
Question / hypothesis:
Artifact and field inspected:
Observed value / timestamp (with timezone):
Corroborating evidence:
Limitations / alternative explanation:
Conclusion and confidence:
```

---

## Further Reading and Sources

- TryHackMe — **Windows Forensics 1** (Registry Forensics) and **Windows Forensics 2** (File System / Activity Artifacts). These were the learning basis for this guide.
- TryHackMe — *Windows Forensics Cheatsheet* (registry locations supplied in the room materials; verify hive layout against the target OS).
- Eric Zimmerman — [EZ Tools](https://ericzimmerman.github.io/) for Registry Explorer, MFTECmd, PECmd, WxTCmd, JLECmd and LECmd. Run `<tool> --help` for installed-version flags.
- Microsoft Learn — Windows registry, Event Logging, and NTFS documentation for OS-specific behavior.

**Portfolio note:** This is an independently organized reference, not a reproduction of a room's solution or an assertion that every listed artifact was available in a particular challenge.
