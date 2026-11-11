# Windows Event Log Queries — SOC Quick Reference

> Practical Windows Event Log investigation with PowerShell `Get-WinEvent` and `wevtutil`. Designed for SOC triage, threat hunting, and offline EVTX analysis.
>
> **Scope:** This guide covers *how to query events*. For descriptions of Event IDs and logon types, use the separate `windows-event-ids.md` and `windows-logon-types.md` references.

## Quick Reference

| Goal | Command |
| --- | --- |
| List available event logs | `Get-WinEvent -ListLog *` |
| Inspect log metadata | `Get-WinEvent -ListLog Security` |
| List event providers | `Get-WinEvent -ListProvider *` |
| Last 10 Security events | `Get-WinEvent -LogName Security -MaxEvents 10` |
| Last 20 failed logons | `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20` |
| Successful and failed logons | `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625}` |
| Events after a specified time | `Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddHours(-1)}` |
| PowerShell script-block events | `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104}` |
| Query an offline EVTX | `Get-WinEvent -Path 'C:\Evidence\Security.evtx' -MaxEvents 20` |
| Query an offline EVTX by Event ID | `Get-WinEvent -FilterHashtable @{Path='C:\Evidence\Security.evtx'; Id=4625}` |
| List logs with `wevtutil` | `wevtutil el` |
| Show `wevtutil` event-query help | `wevtutil qe /?` |
| Five newest Security events | `wevtutil qe Security /c:5 /rd:true /f:text` |
| Five newest failed logons (XPath) | `wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:5 /rd:true /f:text` |
| Read saved EVTX with `wevtutil` | `wevtutil qe "C:\Evidence\Security.evtx" /lf:true /c:5 /rd:true /f:text` |

> **Environment notes:** Run the PowerShell commands in PowerShell and the `wevtutil` examples in either PowerShell or Command Prompt. Access to the Security log may require an elevated shell or suitable permissions. A query can return no events if the log or auditing feature is disabled, the time range is wrong, or the events have already rolled over.

---

## 1. Know Your Data Source

Windows records events in named channels, such as `Security`, `System`, `Application`, and `Microsoft-Windows-PowerShell/Operational`. Saved `.evtx` files can also be queried offline without examining the live machine's current logs.

| Data source | Common purpose | Example |
| --- | --- | --- |
| `Security` | Authentication, accounts, auditing, process creation when configured | 4624, 4625, 4688 |
| `System` | Windows services and operating-system events | 7045 |
| `Microsoft-Windows-PowerShell/Operational` | PowerShell module and script-block logging when enabled | 4103, 4104 |
| `Microsoft-Windows-Sysmon/Operational` | Sysmon endpoint telemetry when installed/configured | 1, 3, 10, 22 |
| Saved EVTX | Offline evidence from an image or triage collection | `Security.evtx` |

**Do not confuse Event IDs across providers.** The numeric ID alone is not enough; always retain the channel/provider, timestamp, hostname, and relevant fields.

### Inspect what is available

```powershell
Get-WinEvent -ListLog * | Select-Object LogName, RecordCount, IsEnabled
Get-WinEvent -ListProvider * | Select-Object Name
```

`-ListLog` discovers event channels; `-ListProvider` discovers publishers. To check specific metadata:

```powershell
Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' |
    Format-List LogName, RecordCount, IsEnabled, MaximumSizeInBytes
```

---

## 2. PowerShell: `Get-WinEvent`

### Query recent events

```powershell
Get-WinEvent -LogName Security -MaxEvents 20 |
    Select-Object TimeCreated, Id, ProviderName, MachineName, LevelDisplayName, Message
```

`-MaxEvents` limits the result set. `Select-Object` chooses useful fields for triage.

### Use `-FilterHashtable` (preferred for routine filtering)

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624, 4625
    StartTime = (Get-Date).AddHours(-24)
} | Select-Object TimeCreated, Id, MachineName, Message
```

The `@{ ... }` is a PowerShell hashtable, not JSON. Multiple values for `Id` are treated as alternatives (4624 **or** 4625). Keys such as `LogName`, `Id`, `ProviderName`, `StartTime`, and `EndTime` can narrow the query at the event-log API level.

### Filter by provider

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Application'
    ProviderName = 'MsiInstaller'
    Id = 11707
} -MaxEvents 20
```

Provider and Event ID filters are combined. The provider name and event ID must actually exist in the chosen log.

### Sort and export selected fields

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 100 |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, MachineName, Message |
    Export-Csv -Path 'C:\Evidence\failed-logons.csv' -NoTypeInformation -Encoding UTF8
```

> `Sort-Object` works on the events returned by the query; `-MaxEvents 100` does not mean *all* matching events. If you need a complete time window, query that window deliberately before exporting.

### Query an offline `.evtx` file

```powershell
Get-WinEvent -Path 'C:\Evidence\Security.evtx' -MaxEvents 20

Get-WinEvent -FilterHashtable @{
    Path = 'C:\Evidence\Security.evtx'
    Id = 4625
}
```

Use `Path`, not `LogName`, for an offline file in these examples. Preserve a read-only original and work on a copy when investigating collected evidence.

---

## 3. `wevtutil`: Fast Command-Line Queries

`wevtutil` works in Command Prompt and PowerShell, and is especially useful on a host where you want a quick command-line view.

```cmd
wevtutil el
wevtutil gl Security
wevtutil qe /?
```

| Option | Meaning |
| --- | --- |
| `qe` | Query events |
| `/c:5` | Return up to five events |
| `/rd:true` | Read newest events first |
| `/f:text` | Human-readable output (also `xml` or `RenderedXml`) |
| `/q:"..."` | XPath event filter |
| `/lf:true` | Treat the supplied path as an event-log file |
| `/sq:true` | Treat the supplied path as a structured-query XML file |

### Basic event query

```cmd
wevtutil qe Application /c:3 /rd:true /f:text
```

The first argument after `qe` identifies **what to read**. Writing only `wevtutil qe /f` is incomplete: `/f` sets output format and does not specify a log or a format value.

### Filter by Event ID with XPath

```cmd
wevtutil qe Security /q:"*[System[(EventID=4624 or EventID=4625)]]" /c:10 /rd:true /f:text
```

### Query an offline file

```cmd
wevtutil qe "C:\Evidence\Security.evtx" /lf:true /q:"*[System[(EventID=4625)]]" /c:10 /rd:true /f:text
```

In this form, `/lf:true` tells `wevtutil` that the path refers to a saved event-log **file**, not a named channel.

---

## 4. XPath: Filter Events by XML Fields

Windows Event Log XPath filters are applied against event XML. A basic query targets the `System` section:

```xml
*[System[(EventID=4625)]]
```

An `or` expression matches either event ID:

```xml
*[System[(EventID=4624 or EventID=4625)]]
```

PowerShell accepts XPath filters too:

```powershell
Get-WinEvent -LogName Security -FilterXPath '*[System[(EventID=4624 or EventID=4625)]]' -MaxEvents 30
```

### Inspect the actual XML first

```powershell
$event = Get-WinEvent -LogName Security -MaxEvents 1
$event.ToXml()
```

Use the XML to verify the provider, Event ID and named `EventData` fields before writing more complicated filters. Field availability differs by provider and event version.

> **Practical choice:** Start with `FilterHashtable` for everyday PowerShell triage. Use XPath when you need to express more specific XML-based conditions, or when using `wevtutil /q`.

---

## 5. SOC Investigation Mini-Recipes

These are **starting points**, not verdicts. Always investigate whether the behavior is expected in the environment.

### A. Failed authentication attempts

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = (Get-Date).AddHours(-2)
} | Select-Object TimeCreated, MachineName, Message
```

**Check next:** account, source address/workstation, logon type, failure status, and whether successful logons followed. Large numbers of failures can also come from stale credentials or misconfigured services.

### B. Process creation in Security logs

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
    StartTime = (Get-Date).AddHours(-2)
} | Select-Object TimeCreated, MachineName, Message
```

**Check next:** new process name, parent/creator, command line (if enabled), user, and surrounding events. Event 4688 requires the relevant audit policy; command-line inclusion requires additional configuration.

### C. PowerShell script blocks

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
} -MaxEvents 30 | Select-Object TimeCreated, Message
```

**Check next:** script text, script block ID, related 4103 entries, process context, encoded content, downloads, and follow-on activity. Script Block Logging may expose more readable code than the launching command line, but **does not guarantee full deobfuscation**.

### D. New service installations

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Id = 7045
} -MaxEvents 30 | Select-Object TimeCreated, Message
```

**Check next:** service name, executable path, account, installation context and whether a legitimate installer or management system caused it.

### E. Clearing a security audit log

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 1102
} -MaxEvents 20 | Select-Object TimeCreated, Message
```

**Check next:** who cleared it, when, whether it matches maintenance, and whether other evidence survived. System/Application log clearing is also visible as Event ID 104 from the Eventlog provider in those logs.

---

## 6. Common Mistakes & Troubleshooting

| Problem | Likely cause | What to do |
| --- | --- | --- |
| `wevtutil qe /f` fails | No log/path or value for `/f` | Specify a channel and format: `wevtutil qe Application /f:text` |
| `Get-WinEvent` returns nothing | Wrong channel, provider, ID, time range, or disabled auditing | Check `Get-WinEvent -ListLog ...` and inspect raw sample events |
| Access denied reading `Security` | Insufficient privileges | Use an authorized elevated shell or approved log-reader access |
| Missing PowerShell 4104 | Script Block Logging not enabled/available, retention gap, or no matching activity | Verify configuration and logs; do not interpret absence as no execution |
| Missing process command line in 4688 | Command-line auditing not enabled | Check Audit Process Creation and command-line inclusion policy |
| Querying the wrong host | Multiple machines or forwarded events | Keep `MachineName`, event timestamp, and source context |
| Unexpected event order | `wevtutil` defaults or UI sort direction | Specify `/rd:true`, or explicitly sort returned PowerShell events |
| No match in copied EVTX | Used `-LogName` instead of file path | Use `-Path` / `Path=` or `wevtutil ... /lf:true` |
| Too much noisy output | Wide query and verbose `Message` fields | Filter by channel, ID and time first; then select fields |
| Confusing IDs from different providers | Same numbers may mean different events | Verify channel and `ProviderName` along with the ID |

### Investigation checklist

- [ ] Confirm host, timezone, log source, provider and time range.
- [ ] Check logging/auditing coverage and known gaps.
- [ ] Filter to relevant events, but preserve adjacent context.
- [ ] Compare related events across providers and hosts.
- [ ] Separate facts from hypotheses and expected admin activity.
- [ ] Record the exact query and event identifiers used as evidence.

---

## 7. Related References

Within this repository:

- [`windows-event-ids.md`](windows-event-ids.md) — Windows, Sysmon and PowerShell event ID descriptions.
- [`windows-logon-types.md`](windows-logon-types.md) — interpreting Windows logon types.
- [`active-directory-monitoring.md`](active-directory-monitoring.md) — AD-related monitoring concepts.

Source material used to develop this guide:

- TryHackMe — *Windows Event Logs* (user's training notes, especially `Get-WinEvent`, `wevtutil`, `FilterHashtable` and XPath examples).
- Malware Archaeology — *Windows Logging Cheat Sheet*, October 2016 (historical supplementary reference; **do not treat its Windows 7 / Server 2012 configuration recommendations as current baselines**).

This guide intentionally does **not** reproduce the third-party PDFs or images. Example paths are illustrative; replace them with your authorized evidence paths.
