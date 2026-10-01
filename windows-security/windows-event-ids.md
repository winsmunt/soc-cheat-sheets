# Windows Logging & Event IDs Cheat Sheet

A practical reference guide covering Windows Event Logs, Sysmon Event IDs, and PowerShell auditing mechanisms used for threat detection in SOC environments.

---

## 1. Core Windows Security Log Event IDs

### 🔐 Authentication & Logon Events
| Event ID | Log Provider | Event Description | SOC Detection Focus |
| :--- | :--- | :--- | :--- |
| **4624** | Security | An account was successfully logged on | Baseline user access, lateral movement |
| **4625** | Security | An account failed to log on | Brute-force & password spraying attempts |
| **4634** | Security | An account was logged off | Session duration tracking |
| **4672** | Security | Special privileges assigned to new logon | Administrator & high-privilege account access |

### 👤 Account & Group Management
| Event ID | Log Provider | Event Description | SOC Detection Focus |
| :--- | :--- | :--- | :--- |
| **4720** | Security | A user account was created | Unauthorized persistence mechanism |
| **4726** | Security | A user account was deleted | Covering tracks or malicious cleanup |
| **4728** | Security | A member was added to a security group | Privilege escalation (e.g., Domain Admins) |
| **4732** | Security | A member was added to a local group | Local administrator group manipulation |

---

## 2. Sysmon (System Monitor) Key Events

| Event ID | Event Name | Description | Hunting Value |
| :--- | :--- | :--- | :--- |
| **Event ID 1** | Process Creation | Tracks newly created processes, command lines, and hashes | Detecting malicious execution, parent-child process anomalies |
| **Event ID 3** | Network Connection | Logs TCP/UDP connections initiated by processes | C2 communication, data exfiltration |
| **Event ID 7** | Image Loaded | Logs when a module/DLL is loaded by a process | DLL side-loading, process injection |
| **Event ID 11** | FileCreate | Logs when a file is created or overwritten | Dropped malware, web shells, staging files |

---

## 3. PowerShell Auditing & Logging

| Log / Feature | Event ID | Description |
| :--- | :--- | :--- |
| **Script Block Logging** | **4104** | Captures the entire content of code blocks executed by PowerShell (reveals obfuscated code) |
| **Module Logging** | **4103** | Records pipeline execution details and raw commands as modules execute |
| **Engine State** | **400** | Tracks when PowerShell sessions start and terminate |

---

## 💡 Blue Team Investigation Rules of Thumb

1. **Parent-Child Correlation (Sysmon 1):** Always check if non-standard processes spawn command shells (e.g., `word.exe` spawning `powershell.exe` or `cmd.exe`).
2. **Failed Logon Spikes (Event ID 4625):** Multiple failures within a short period from a single source indicate automated credential guessing.
3. **PowerShell De-obfuscation (Event ID 4104):** Even if a command is executed using `-EncodedCommand` or Base64, Event ID 4104 records the decoded raw execution block.
