# 🚨 Windows Threat Detection: Initial Access Cheat Sheet

A technical reference guide focusing on detecting **Initial Access (TA0001)** vectors in Windows environments using Security Event Logs, Sysmon, and process execution monitoring.

---

## 1. RDP Threats & Brute-Force Detection

Remote Desktop Protocol (RDP) is a primary target for external access attempts and lateral movement.

### Key RDP Event IDs
| Event ID | Provider / Log Path | Description | Detection Use-Case |
| :--- | :--- | :--- | :--- |
| **4624** | Security | Successful Logon | Check for `Logon Type 10` (Remote Interactive) |
| **4625** | Security | Failed Logon Attempt | High volume from single IP = Brute-Force / Password Spraying |
| **4778** | TerminalServices-LocalSessionManager | RDP Session Reconnected | Session hijacking / re-established persistence |
| **4779** | TerminalServices-LocalSessionManager | RDP Session Disconnected | Abrupt disconnection after unauthorized action |

---

## 2. Phishing & Malicious Document Execution

Phishing attacks often rely on macro-enabled documents or malicious attachments to spawn command shells.

### Suspicious Parent-Child Process Chains
Monitor **Sysmon Event ID 1** or **Windows Event ID 4688** for abnormal execution paths:

| Parent Process (`ParentImage`) | Suspicious Child Process (`Image`) | Threat Indicator |
| :--- | :--- | :--- |
| `WINWORD.EXE` / `EXCEL.EXE` | `cmd.exe` / `powershell.exe` | Malicious Macro / Office Document Exploit |
| `OUTLOOK.EXE` | `wscript.exe` / `cscript.exe` | Direct execution of malicious script attachment |
| `msedge.exe` / `chrome.exe` | `powershell.exe` / `certutil.exe` | Drive-by download or user-executed payload |

---

## 3. USB & Removable Media Threats

Physical or mounted drive vectors are used to bypass perimeter controls.

| Indicator / Artifact | Source / Event ID | Detection Rule |
| :--- | :--- | :--- |
| **Device Arrival** | `Microsoft-Windows-Partition/Diagnostic` (Event ID 1006) | Detects when removable media is inserted |
| **Execution from USB** | Sysmon Event ID 1 | Command line launching binary from `D:\`, `E:\`, etc. |
| **LNK File Drops** | Sysmon Event ID 11 / 15 | Short-cut file creation pointing to payload scripts |

---

## 💡 SOC Analyst Quick Rules

1. **Filter Logon Type 10:** In Event ID **4624**, always inspect the `LogonType` field. Type `10` confirms an RDP session, while Type `3` indicates a network share/SMB connection.
2. **Office Spawning Shells:** Office applications should **never** spawn `powershell.exe` or `cmd.exe` under normal business operations. Mark any occurrence as high-severity.
3. **Encoded PowerShell Commands:** Look for process command lines containing `-e`, `-enc`, or `-EncodedCommand` triggered by document handlers.
