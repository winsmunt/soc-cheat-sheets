# ⚓ Windows Threat Detection: Persistence & C2 Cheat Sheet

A practical reference guide for SOC analysts covering detection techniques for **Persistence (TA0003)**, **Command and Control (TA0011)**, and **Impact (TA0040)** in Windows environments.

---

## 1. Persistence Mechanisms (Maintaining Access)

Attackers leverage native Windows features to survive system reboots and credential changes.

### A. Scheduled Tasks & Windows Services
| Vector | Event ID / Log Source | Detection Focus |
| :--- | :--- | :--- |
| **Scheduled Task Created** | Security Event ID **4698** | Task creation events in `Microsoft-Windows-TaskScheduler/Operational` |
| **Scheduled Task Updated** | Security Event ID **4702** | Modifications to existing tasks pointing to payload paths |
| **New Service Installed** | System Event ID **7045** | Service installation triggering background binary execution |
| **Service Configuration** | Sysmon Event ID **13** | Registry changes under `HKLM\SYSTEM\CurrentControlSet\Services\` |

### B. Registry Run Keys & Startup Folder
| Vector | Registry Path / File Location | Event Artifacts |
| :--- | :--- | :--- |
| **Run / RunOnce Keys** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`<br>`HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | Sysmon Event ID **12** (Object create/delete)<br>Sysmon Event ID **13** (Value set) |
| **Startup Folder Drops** | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | Sysmon Event ID **11** (FileCreate in startup directories) |

---

## 2. Command and Control (C2) Activity

Detecting outbound communication channels established by C2 beacons or reverse shells.

### Key C2 Detection Indicators
| Artifact / Indicator | Source Log | SOC Hunting Rule |
| :--- | :--- | :--- |
| **Non-Standard Ports** | Sysmon Event ID **3** | Shells (`powershell.exe`, `cmd.exe`) making direct outbound network connections |
| **Beaconing Behavior** | Sysmon Event ID **3** / Firewall Logs | Periodic connection patterns to foreign external IPs at regular intervals |
| **DNS Tunneling** | DNS Server Logs / Sysmon **22** | High volume of subdomains queried for a single domain name |

---

## 3. Impact & System Destruction

Actions taken by threat actors to manipulate, interrupt, or destroy system availability and data.

| Threat Action | Technique / Command | Log Artifact |
| :--- | :--- | :--- |
| **Shadow Copy Deletion** | `vssadmin.exe delete shadows /all /quiet`<br>`wmic shadowcopy delete` | Sysmon Event ID **1** / Security Event ID **4688** (Ransomware pre-cursor) |
| **System Recovery Disabling**| `bcdedit /set {default} recoveryenabled No` | Execution of `bcdedit.exe` modifying boot settings |

---

## 💡 SOC Analyst Quick Rules

1. **VSSAdmin Execution:** Any invocation of `vssadmin.exe` or `wmic` attempting to delete shadow copies is a critical Ransomware indicator - raise an incident immediately.
2. **Persistence Monitoring:** Focus detection rules on Sysmon Event ID **13** targeting `\CurrentVersion\Run` registry keys, as this is the most frequent persistence mechanism for malware.
3. **Outbound Shells:** Native command interpreters (`cmd.exe`, `powershell.exe`, `rundll32.exe`) should rarely produce Network Connections (Sysmon Event ID **3**) directly to external IPs.
