# Sysmon Threat Hunting — Practical SOC Field Guide

> **Purpose:** A hands-on reference for interpreting Sysmon telemetry, building hunting hypotheses, and validating suspicious behavior. Designed for SOC L1/L2 investigations and Windows DFIR labs.
>
> **Scope:** This is an investigation and telemetry guide, **not** a production-ready Sysmon configuration or a set of high-confidence detection rules. Test the examples in a lab and tune them to your environment.

## Quick Reference

| Hunt question | Sysmon ID | Useful fields | What to look for |
|---|---:|---|---|
| What ran, and who launched it? | **1** | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `ProcessGuid`, `User` | Unusual parent/child relationships, script hosts, LOLBins |
| Did the process exit shortly afterward? | **5** | `ProcessGuid`, `Image`, `UtcTime` | Short-lived processes; reconstructing duration |
| Did it connect to a suspicious endpoint? | **3** | `Image`, `ProcessGuid`, `DestinationIp`, `DestinationPort` | Unusual outbound destinations, recurring connections |
| Did it resolve an unexpected domain? | **22** | `Image`, `ProcessGuid`, `QueryName`, `QueryResults` | Newly observed domains, possible C2 infrastructure |
| Did it load a suspicious DLL? | **7** | `Image`, `ImageLoaded`, `Signed`, `Signature`, `Hashes` | DLL loading from user-writable directories; side-loading |
| Did it create a thread in another process? | **8** | `SourceImage`, `TargetImage`, `StartAddress`, `StartModule` | Possible remote-thread injection |
| Did it access LSASS? | **10** | `SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace` | Potential credential access; account for EDR/backup tools |
| Did it drop or overwrite a file? | **11** | `Image`, `TargetFilename`, `ProcessGuid` | Payloads in Temp, Downloads, Startup |
| Did it change a persistence key? | **12–14** | `Image`, `TargetObject`, `Details`, `EventType` | Run/RunOnce and other startup changes |
| Did it create a named alternate data stream? | **15** | `Image`, `TargetFilename`, `Hashes` | ADS usage and download provenance |
| Did it create or contact a named pipe? | **17–18** | `Image`, `PipeName` | Unexpected IPC; possible malware communication |
| Did it register WMI persistence? | **19–21** | `Name`, `Query`, `Destination`, `User` | WMI event filter/consumer/binding |
| Was a process image altered? | **25** | `Image`, `Type`, `ProcessGuid` | Possible process hollowing or image tampering |
| Was a file deleted? | **23 / 26** | `Image`, `TargetFilename`, `Hashes` | Cleanup or file destruction; ID 23 archives, 26 does not |
| Did Sysmon configuration change? | **16** | Configuration change metadata | Unexpected reduction in telemetry coverage |

**Important distinctions:** Sysmon event IDs are **not interchangeable** with Windows Security event IDs. For example, process creation is Sysmon **1** but Security **4688**. Sysmon events are observational evidence, **not proof of malicious intent**. Some types (notably network Event ID 3 and image-load Event ID 7) can be disabled or filtered depending on configuration.

---

## 1. Where to Find Sysmon Logs

**Event Viewer** → `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`

Useful commands (run on a Windows host with access to the logs):

```powershell
# Last 20 Sysmon events
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 20

# Process creation events
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
} -MaxEvents 30

# Inspect a saved EVTX instead of the live machine
Get-WinEvent -Path 'C:\Evidence\Sysmon.evtx' -MaxEvents 20
```

**Investigative tip:** Inspect the event's XML (`Event Viewer > Details > XML View`) for the exact field names. SIEM field names are often normalized differently, so do not assume that `Image` in raw XML will always be called `process.executable` in your SIEM.

---

## 2. Core Investigation Method

1. **Write a hypothesis.** Example: “An Office document spawned a script host that contacted an uncommon external IP.”
2. **Identify required telemetry.** Typically Sysmon 1, 3, 22; perhaps 11 and 13.
3. **Start broad.** Search for the behavior across users and hosts, then narrow the time range.
4. **Pivot with `ProcessGuid`.** Correlate a process's creation, network activity, and file/registry changes. Do not rely on PID alone: PIDs can be reused.
5. **Validate context.** Examine full command lines, paths, signer information, the user, and known software activity.
6. **Record evidence.** Timestamp, host, event ID, process lineage, key fields, query used, and why the finding matters.
7. **Test alternative explanations.** Legitimate administration, software updates, backup, EDR, crash handling, and developer tools often resemble attack techniques.

### Timeline worksheet

| UTC time | Host | Event ID | Process / user | Finding | Next pivot |
|---|---|---:|---|---|---|
| `YYYY-MM-DD HH:MM:SS` | `HOST` | `1` | `parent → child` | Suspicious process launch | `ProcessGuid` |
| `...` | `HOST` | `22` | `child` | Unexpected DNS query | Domain, related network events |
| `...` | `HOST` | `3` | `child` | External connection | IP, port, frequency |

---

## 3. XML Configuration Fundamentals

Sysmon configuration controls **what gets logged**, not what raises a SIEM alert. Always inspect the installed version's supported schema before deploying rules.

```cmd
sysmon64.exe -s
sysmon64.exe -c
```

- `-s` prints the configuration schema for the installed Sysmon binary (the executable name may be `sysmon.exe`).
- `-c` displays the active configuration; `-c path\to\config.xml` updates it when run with suitable privileges.
- `onmatch="include"` retains events that match; `onmatch="exclude"` removes matching events. **Exclusions take precedence.**
- Within explicit rule groups, `groupRelation="and"` or `"or"` determines how predicates combine. Avoid depending on implicit logic: it is easy to write overly broad or overly narrow filters.
- When collecting telemetry for investigation, prefer preserving context over aggressively excluding events. Once excluded at collection time, missing evidence cannot be recovered from that log.

### Example: targeted process-creation telemetry

> A standalone **lab-only** configuration fragment. Insert it into an otherwise valid Sysmon XML configuration using the schema supported by your version.

```xml
<EventFiltering>
  <RuleGroup name="Office-script-host-processes" groupRelation="and">
    <ProcessCreate onmatch="include">
      <ParentImage condition="end with">\WINWORD.EXE</ParentImage>
      <Image condition="end with">\powershell.exe</Image>
    </ProcessCreate>
  </RuleGroup>
</EventFiltering>
```

This captures **one specific relationship**, not every possible malicious Office child process. It deliberately omits `EXCEL.EXE`, `OUTLOOK.EXE`, `mshta.exe`, `cmd.exe`, etc.; those require separate consideration. It is also **not** a security alert without downstream detection/triage logic.

### Example: suspicious network destination ports

```xml
<EventFiltering>
  <RuleGroup name="Interesting-network-ports" groupRelation="or">
    <NetworkConnect onmatch="include">
      <DestinationPort condition="is">4444</DestinationPort>
      <DestinationPort condition="is">5555</DestinationPort>
    </NetworkConnect>
  </RuleGroup>
</EventFiltering>
```

Ports are weak indicators by themselves: benign software may use them and attacks often use 80/443. Avoid deploying this as your sole network collection rule.

### Syntax and validation checklist

- Check **case and field spelling** against `sysmon64.exe -s`.
- Match paths as they appear in real events, including drive letters and backslashes.
- Test a known positive and several known benign events.
- Confirm the expected event appeared in Sysmon Operational after applying the configuration.
- Measure telemetry volume; ImageLoad and NetworkConnect can generate many events.
- Keep a copy of the configuration and document version changes.

---

## 4. Hunting Scenarios

### Hunt A — Suspicious Parent/Child Execution

**Hypothesis:** A document, browser, or user-facing application launches a script host or LOLBin unexpectedly.

**Primary evidence:** Event ID **1**. Inspect `ParentImage`, `ParentCommandLine`, `Image`, `CommandLine`, `User`, `ProcessGuid`, `ParentProcessGuid`.

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
} | Where-Object {
    $_.Message -match '(?i)(WINWORD|EXCEL|OUTLOOK)\.EXE' -and
    $_.Message -match '(?i)(powershell|cmd|mshta|wscript|cscript|rundll32|regsvr32)\.exe'
} | Select-Object TimeCreated, Id, Message
```

This is a **quick text-based triage example**, not a reliable production correlation: it does not prove which fields matched. For high-confidence hunting, extract XML fields or use normalized SIEM fields and explicitly compare parent/child values.

**Validate:** Could it be a corporate macro, installer, help-desk script, or Office add-in? Check child command-line switches, path, signature, recent documents, and whether the activity repeats across endpoints.

### Hunt B — Possible C2 Communication

**Hypothesis:** A process resolves an unusual domain and communicates with an unexpected destination shortly afterward.

**Evidence:** Event ID **22** (DNS), **3** (network), **1** (origin). Pivot using `ProcessGuid` and time proximity.

**Inspect:** `QueryName`, `QueryResults`, `DestinationIp`, `DestinationPort`, `Image`, `User`, process command line.

**Validate:** Corporate proxies and browser processes generate considerable noise. A DNS lookup does not guarantee a successful connection; a network event alone does not prove C2. Look for repeated periodic activity, suspicious process ancestry, and accompanying payload/file activity.

### Hunt C — LSASS Access / Potential Credential Dumping

**Hypothesis:** An unexpected process obtains access to `lsass.exe`.

**Evidence:** Event ID **10** (ProcessAccess), supported by Event ID **1** for the source process.

```xml
<EventFiltering>
  <RuleGroup name="LSASS-access-lab" groupRelation="or">
    <ProcessAccess onmatch="include">
      <TargetImage condition="end with">\lsass.exe</TargetImage>
    </ProcessAccess>
  </RuleGroup>
</EventFiltering>
```

**Inspect:** `SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace`, source process user, signer, and process lineage.

**Validate carefully:** EDR sensors, antivirus, crash handling (`WerFault.exe`), privileged-access management, and diagnostic software can legitimately access LSASS. There is no universal malicious `GrantedAccess` value. Do **not** suppress all LSASS events from a product merely because it usually behaves benignly; verify path, signer, parent process, version, and operating context.

### Hunt D — Registry Persistence

**Hypothesis:** A process creates or changes a Run/RunOnce autorun entry.

**Evidence:** Event IDs **12** (registry object creation/deletion), **13** (value set), **14** (rename).

```xml
<EventFiltering>
  <RuleGroup name="Run-key-changes" groupRelation="or">
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">\CurrentVersion\Run\</TargetObject>
      <TargetObject condition="contains">\CurrentVersion\RunOnce\</TargetObject>
    </RegistryEvent>
  </RuleGroup>
</EventFiltering>
```

**Important:** Confirm the filter tags and fields against the schema on the lab host. A Sysmon configuration may not include every form of registry persistence by default. The example targets two specific autorun locations, not scheduled tasks, services, WMI, or Startup-folder persistence.

**Validate:** Check the full value data/command, owning program, signed binaries, when it was written, and whether the path is user-writable. Legitimate installers often modify Run keys.

### Hunt E — Suspicious File Creation and Alternate Data Streams

**Hypothesis:** A process stages a payload in a user-writable directory or creates an unusual named stream.

**Evidence:** Event ID **11** (FileCreate), **15** (FileCreateStreamHash); optionally **23/26** for deletion.

```xml
<EventFiltering>
  <RuleGroup name="User-writable-file-staging" groupRelation="or">
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">\AppData\Local\Temp\</TargetFilename>
      <TargetFilename condition="contains">\Downloads\</TargetFilename>
    </FileCreate>
  </RuleGroup>
</EventFiltering>
```

**Validate:** Downloads and temporary paths contain legitimate installers and updates. Correlate created files with the creating process (Event ID 1) and any subsequent executions. `Zone.Identifier` is a common legitimate ADS and is not malware proof.

### Hunt F — Remote Thread / Process Injection Indicators

**Hypothesis:** One process creates a thread inside a different process.

**Evidence:** Event ID **8**, supported by Event IDs **1**, **7**, **10**, and **25** when available.

**Inspect:** `SourceImage`, `TargetImage`, `StartAddress`, `StartModule`, `StartFunction`, process context and signing information.

**Validate:** Accessibility tools, debuggers, EDR, and application instrumentation can produce similar activity. Event ID 8 is a useful investigative lead but is not definitive proof of malicious injection.

---

## 5. SIEM Pivots: Examples, Not Universal Field Names

Field mapping differs across raw XML, Splunk, Elastic, and custom ingest pipelines. Confirm the data model before copying a query.

### Splunk — raw Sysmon-style fields (example)

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| table _time host User Image CommandLine ParentImage ParentCommandLine ProcessGuid
| sort -_time
```

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID IN (1,3,22)
| search ProcessGuid="{PUT-GUID-HERE}"
| table _time EventID Image DestinationIp DestinationPort QueryName ProcessGuid
| sort _time
```

Your environment might use `EventCode` rather than `EventID`, different sourcetypes, or a normalized field set.

### Elastic KQL — ECS-style field mapping (example)

```kql
process.parent.name: (WINWORD.EXE or EXCEL.EXE or OUTLOOK.EXE) and
process.name: (powershell.exe or cmd.exe or mshta.exe)
```

```kql
process.name: powershell.exe and destination.port: (4444 or 5555)
```

These only work when the relevant fields have been mapped into ECS. A lab may instead expose raw fields such as `winlog.event_data.Image` or `winlog.event_data.ParentImage`.

---

## 6. False Positive Triage Checklist

Before elevating an event to an incident, ask:

- Is this action common for the host's **role** (developer workstation, DC, server, jump box)?
- Is the binary **signed**, and does the signature match the expected publisher?
- Is the **path** expected, or is a familiar binary name running from Temp/AppData?
- Is there a legitimate **change ticket**, software rollout, or backup job?
- Does the **parent process** and full command line explain the action?
- Is the activity present on many machines at predictable times?
- Does this event correlate with suspicious **DNS, network, file, registry**, or authentication activity?
- If you exclude a known benign pattern, can an attacker **imitate** it by reusing the filename/path?

**Prefer detection tuning with context** (verified signer, user, parent, arguments, expected asset group) rather than global exclusions based only on a filename.

---

## 7. Common Mistakes

| Mistake | Better approach |
|---|---|
| “An Event ID 10 means credential theft.” | It means a process accessed another process; check access rights, call trace, source, and context. |
| “Sysmon Event ID 3 exists on every host.” | Verify collection configuration; network events are often disabled or selectively filtered. |
| “The destination port proves C2.” | Combine with domain, process lineage, timing, and baseline behavior. |
| “All DLL loads should be logged forever.” | Event ID 7 is high-volume. Tune and measure before production deployment. |
| “Same PID means same process.” | Use `ProcessGuid` and timestamps to avoid PID reuse errors. |
| “The XML filter is my detection rule.” | XML governs telemetry collection; alerting requires separate detection and validation. |
| “An exclusion is always harmless.” | It can hide both benign and malicious activity. Test the risk of attacker mimicry. |
| “A suspicious event proves the full attack chain.” | Correlate multiple events and distinguish observation from inference. |

---

## 8. Minimal Investigation Report Template

```markdown
### Hypothesis
[Behavior we expected to find]

### Data sources
[Sysmon Operational / Windows Security / EDR / DNS / proxy]

### Evidence
- [UTC timestamp] [host] [Sysmon event ID] [process + key field]
- [UTC timestamp] [host] [related event] [correlation]

### Assessment
[Observed facts] vs. [hypotheses / unknowns]

### False positive considerations
[Known-good process, software deployment, user activity, signed tools]

### Next steps
[Containment escalation, additional logs, scope search, tuning proposals]
```

---

## 9. Further Reading and Source Notes

- [Microsoft Learn — Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [Microsoft Learn — Sysmon configuration files](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files)
- [Microsoft Sysmon/SysmonCommon repository](https://github.com/microsoft/SysmonCommon)
- [MITRE ATT&CK](https://attack.mitre.org/)

**Learning basis:** The practical hunting themes in this guide were developed from personal TryHackMe notes covering Windows Event Logs, Sysmon, Windows Forensics, and Sysinternals. Examples were rewritten as reusable defensive workflows and cross-checked against Microsoft documentation. They are intentionally not presented as verified production detections or as a complete reproduction of the training rooms.

**Reminder:** Keep lab datasets, credentials, personal information, and malware binaries out of public repositories. Publish sanitized findings and validated detection logic instead.
