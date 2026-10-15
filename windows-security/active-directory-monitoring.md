# Active Directory Monitoring Cheat Sheet

A practical reference for monitoring Active Directory using Windows Event Logs and Splunk.

---

## Quick Reference - Important Event IDs

| Event ID | Description | Where / Purpose |
|---|---|---|
| 4624 | Successful logon | Target system |
| 4625 | Failed logon | Target system |
| 4720 | User account created | Account management |
| 4722 | User account enabled | Account management |
| 4724 | Password reset attempted | Account management |
| 4725 | User account disabled | Account management |
| 4728 | Member added to global security group | Group management |
| 4732 | Member added to local security group | Group management |
| 4740 | User account locked out | Account management |
| 4756 | Member added to universal security group | Group management |
| 4768 | Kerberos TGT requested | Domain Controller |
| 4769 | Kerberos service ticket (TGS) requested | Domain Controller |
| 4776 | NTLM credential validation | Domain Controller |
| 5136 | Directory Service object modified | Useful for monitoring GPO changes |
| 5140 | Network share accessed | File share monitoring |
| 6272 | NPS granted network access | VPN / NPS authentication |
| 6273 | NPS denied network access | VPN / NPS authentication |
| 6274 | NPS discarded access request | VPN / NPS authentication |

---

## Common Active Directory Protocols

| Protocol | Port | Purpose | Normal Usage |
|---|---|---|---|
| Kerberos | 88 | Default authentication in AD | User logins, service access, ticket requests |
| LDAP | 389, 636, 3268, 3269 | Directory queries and modifications | User lookups, group membership checks, address book queries |
| SMB | 445 | File sharing and remote administration | Shared folders, printers, administrative tools |
| RDP | 3389 | Interactive remote desktop | Help desk support, server administration |
| NetBIOS / LLMNR | 137, 138, 5355 | Legacy name resolution | Used when DNS fails or by older applications |

---

# Authentication

## Kerberos Authentication

A normal Kerberos authentication sequence can generate several events.

| Step | Activity | Event ID | Logged On |
|---|---|---|---|
| 1 | User requests a TGT | 4768 | Domain Controller |
| 2 | User requests a TGS | 4769 | Domain Controller |
| 3 | User creates a session on the target | 4624 | Target server |

This is important because one user action can create events on different systems.

### Find TGT Requests

```spl
index=* EventCode=4768
| table _time, Account_Name, Client_Address, Ticket_Encryption_Type
```

---

## Kerberos Encryption Types

| Value | Algorithm | Typical Use |
|---|---|---|
| `0x12` | AES-256 | Modern systems, Windows 2008+ domain functional level |
| `0x17` | RC4-HMAC | Legacy systems, older applications, cross-forest trusts |

The encryption type can provide additional context when reviewing Kerberos authentication.

---

## NTLM Authentication

NTLM authentication creates events in different places.

| Step | Activity | Event ID | Logged On |
|---|---|---|---|
| 1 | Target server asks the DC to validate credentials | 4776 | Domain Controller |
| 2 | Session is created on the target | 4624 | Target server |

### Find NTLM Validation Events

```spl
index=* EventCode=4776
| table _time, Logon_Account, Source_Workstation
```

### Find NTLM Logons on a Target

```spl
index=* EventCode=4624 Account_Name=michelle.smith Authentication_Package=NTLM
| table _time, host, user, Workstation_Name, Source_Network_Address, Authentication_Package
```

---

# Domain vs Local Accounts

| User Type | Credentials Stored | Authentication Events |
|---|---|---|
| Domain user | NTDS.dit on the Domain Controller | Domain Controller |
| Local user | SAM on the local machine | Local machine only |

This distinction helps determine where authentication evidence should appear.

---

# Account Management

Account changes are important when monitoring Active Directory.

| Event ID | Activity |
|---|---|
| 4720 | Account created |
| 4722 | Account enabled |
| 4724 | Password reset attempted |
| 4725 | Account disabled |
| 4740 | Account locked out |

### Find Created Accounts

```spl
index=* EventCode=4720
| table _time, SAM_Account_Name, Subject_Account_Name
```

`Subject_Account_Name` can help identify which account performed the action.

---

# Security Group Changes

Changes to security groups can be important during an investigation.

| Event ID | Activity | Group Scope |
|---|---|---|
| 4728 | Member added to global security group | Domain-wide |
| 4732 | Member added to local security group | Machine-level / domain local on DCs |
| 4756 | Member added to universal security group | Entire forest |

### Find Group Membership Changes

```spl
index=* (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| table _time, Member_Account_Name, Group_Name, Subject_Account_Name
```

This allows us to see:

- which account was added;
- which group was modified;
- which account performed the change.

---

# Group Policy Changes

Event ID `5136` can be used to monitor changes to directory objects, including Group Policy Objects.

A GPO can affect many machines in a domain, so unexpected modifications are important to investigate.

### Find GPO Modifications

```spl
index=* EventCode=5136 Class="groupPolicyContainer"
| table _time, Subject_Account_Name, DN, LDAP_Display_Name, Value
| sort - _time
```

---

# Logon Monitoring

Two basic Windows logon events are:

| Event ID | Meaning |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |

The event alone is not enough. The `Logon_Type` field helps explain how the session was created.

---

## Important Logon Types

| Logon Type | Meaning | Example |
|---|---|---|
| 2 | Interactive | User logging in from the keyboard / physical console |
| 3 | Network | File share access, WMI queries, remote administration |
| 4 | Batch | Scheduled task running under a user account |
| 5 | Service | Windows service starting under a service account |
| 7 | Unlock | User unlocking a previously locked workstation |
| 10 | RemoteInteractive | RDP session |

Examples:

- **Type 2** → someone logged in directly at the machine.
- **Type 3** → the account accessed something over the network.
- **Type 10** → an RDP session was created.

The Logon Type should be interpreted together with the account and the context of the activity.

### Count Logon Types

```spl
index=* EventCode=4624
| stats count by Logon_Type
| sort -count
```

This can help identify which logon types are common or unusual in the environment.

---

# Kerberos Service Analysis

Event ID `4769` records Kerberos service ticket requests.

The `Service_Name` field can show which resource was accessed.

| Service Name Pattern | Represents |
|---|---|
| `krbtgt` | TGT renewal requests |
| `cifs/THM-SHR-SRV` | File share access |
| `ldap/THM-DC` | Directory queries |
| `http/THM-WEB-SRV` | Web application access |
| `MSSQLSvc/THM-SQL-SRV` | SQL Server access |
| `HOST/THM-IT-DESK` | General host services |

This makes Event 4769 useful for understanding what services an account is accessing.

---

# Expected Account Behaviour

Different account types normally have different activity patterns.

| Account Type | Expected Pattern |
|---|---|
| SQL service accounts | Access database servers from application servers |
| Backup service accounts | Access file shares from backup servers, typically overnight |
| Monitoring accounts | Query multiple systems at regular intervals |
| Admin accounts | Access from designated admin workstations during business hours |

An event may not be suspicious by itself. The activity becomes more useful when compared with the normal behaviour of the account.

---

# Event Volume

Active Directory environments generate large numbers of events.

Example numbers for a 500-user environment:

| Event | Typical Daily Volume |
|---|---|
| 4769 - TGS requests | 50,000–100,000+ |
| 4768 - TGT requests | 5,000–10,000+ |
| 4624 - Logons | Varies widely depending on server role |

Because of this volume, reviewing individual events one by one is not practical.

---

# Stack Counting

Stack counting, also called **long-tail analysis**, means grouping events by a field, counting how often each value appears, and looking at rare activity.

Instead of reviewing thousands of events individually, we can identify unusual accounts or services.

### Find Rare Accounts in Kerberos TGS Requests

```spl
index=* EventCode=4769 NOT Account_Name="*$*"
| stats count by Account_Name
| sort -count
```

`NOT Account_Name="*$*"` removes machine accounts, which normally end with `$`.

Rare accounts can then be investigated further.

### Find Rare Services

```spl
index=* EventCode=4769 NOT Account_Name="*$*"
| stats count by Service_Name
| sort -count
```

This groups Kerberos service ticket requests by service and makes less common services easier to identify.

Rare does not automatically mean malicious. It means the activity may deserve more investigation.

---

# Useful Audit Categories

For better Active Directory visibility, the following audit categories are useful:

| Category | Subcategory | Events |
|---|---|---|
| Account Logon | Credential Validation | 4776 |
| Account Logon | Kerberos Authentication Service | 4768, 4771 |
| Account Logon | Kerberos Service Ticket Operations | 4769 |
| Account Management | User Account Management | 4720, 4722, 4724, 4725 |
| Account Management | Security Group Management | 4728, 4732, 4756 |
| DS Access | Directory Service Changes | 5136 |
| Logon/Logoff | Logon | 4624, 4625 |
| Object Access | File Share | 5140 |

---

## Check Current Audit Policy

```cmd
auditpol /get /category:*
```

To check a specific subcategory:

```cmd
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
```

---

# Detecting Initial Access

Initial access attacks can leave evidence across different log sources.

For web-based attacks, IIS logs can help identify suspicious requests, while Windows and Sysmon logs can show what happened on the server after the request.

---

# IIS Log Analysis

IIS logs contain information about HTTP requests sent to a Windows web server.

## Important IIS Fields

| Field | Description |
|---|---|
| `c_ip` | IP address of the client |
| `cs_uri_stem` | Requested URI path |
| `cs_uri_query` | Query string sent with the request |
| `cs_method` | HTTP method such as GET or POST |
| `sc_status` | HTTP response status code |
| `cs(User-Agent)` | User-Agent used by the client |

These fields can help identify scanning, suspicious requests, web shells, and credential attacks.

---

# Detecting Web Scanning

Attackers may scan a web server to discover hidden files, directories, or applications.

A large number of `404` responses from the same IP address can be a useful starting point.

### Find IP Addresses Generating 404 Responses

```spl
index=iis sc_status=404
| stats count by c_ip
| sort - count
```

After identifying a suspicious IP, check which requests from that address were successful.

```spl
index=iis c_ip={SUSPICIOUS_IP} sc_status=200
| stats count by cs_uri_stem
| sort - count
```

This can help identify resources discovered during the scan.

A high number of failed requests does not automatically mean malicious activity. The source IP and requested resources should be investigated further.

---

# Detecting Web Shells

A web shell is a malicious script placed on a web server that allows an attacker to execute commands remotely.

IIS logs can show requests to the web shell and commands passed through the URL.

### Investigate Requests to a Suspicious File

```spl
index=iis cs_uri_stem="*/{WEBSHELL_FILENAME}"
| table _time, c_ip, cs_method, cs_uri_query, sc_status
| sort _time
```

The `cs_uri_query` field is especially useful because commands sent to a web shell may appear in the query string.

Example activity may look like:

```text
cmd=whoami
cmd=hostname
cmd=tasklist
```

---

## IIS and Sysmon Correlation

IIS worker processes normally run as:

```text
w3wp.exe
```

If a web shell executes operating system commands, `w3wp.exe` may create a command interpreter or another suspicious child process.

### Find Processes Started by IIS

```spl
index=win EventCode=1 ParentImage="*\\w3wp.exe"
| table _time, ParentImage, CommandLine
| sort _time
```

**Sysmon Event ID 1** records process creation.

A suspicious process chain can look like:

```text
w3wp.exe
   ↓
cmd.exe
   ↓
system command
```

This provides host-level evidence that activity seen in the IIS logs resulted in command execution on the server.

---

---

# Detecting OWA Credential Attacks

Outlook Web Access (OWA) can be targeted with password guessing or brute-force attacks.

Authentication requests can be identified in IIS logs by looking for POST requests to the OWA authentication endpoint.

### Detect High Numbers of OWA Login Requests

```spl
index=iis cs_uri_stem="/owa/auth.owa" cs_method=POST
| bin _time span=5m
| stats count by _time, c_ip
| where count > 10
| sort - count
```

This groups authentication requests into five-minute periods and helps identify IP addresses generating many login attempts.

After identifying suspicious activity in IIS, Windows authentication logs can be investigated.

---

## Investigating Failed Logons

Event ID `4625` records failed Windows logons.

```spl
index=win EventCode=4625
| stats count by user, Logon_Type
| sort - count
```

This can help identify accounts receiving a large number of failed authentication attempts.

Event ID `4624` can then be checked to determine whether authentication eventually succeeded.

```spl
index=win EventCode IN (4624,4625) user={SUSPICIOUS_USER}
| table _time, EventCode, user, Logon_Type, Source_Network_Address
| sort _time
```

---

# VPN and Network Policy Server Monitoring

Windows Network Policy Server (NPS) can provide useful authentication information for VPN connections.

## Important NPS Event IDs

| Event ID | Description |
|---|---|
| 6272 | Network Policy Server granted access |
| 6273 | Network Policy Server denied access |
| 6274 | Network Policy Server discarded the request |

These events can help identify repeated VPN authentication failures and successful access after multiple failed attempts.

---

## NPS Reason Codes

Event ID `6273` includes a reason code explaining why access was denied.

| Reason Code | Meaning |
|---|---|
| 16 | Unknown username or bad password |
| 48 | No matching network policy |
| 65 | RADIUS shared secret mismatch |

Reason codes provide important context.

For example, repeated failures with reason code `16` may indicate a credential attack, while other codes may be related to configuration problems.

---

# Detecting VPN Credential Attacks

Repeated NPS authentication failures can be grouped by account and source IP.

```spl
index=win EventCode=6273
| stats count by User_Account_Name, Client_IP_Address
| sort - count
```

After identifying a suspicious account, compare denied and successful authentication events.

```spl
index=win EventCode IN (6273,6272) User_Account_Name={SUSPICIOUS_USER}
| table _time, EventCode, User_Account_Name, Client_IP_Address
| sort _time
```

This can show a pattern such as:

```text
6273 - denied
6273 - denied
6273 - denied
        ↓
6272 - granted
```

A successful authentication after many failures should be investigated further.

---

# Correlating VPN and Windows Logons

After finding a successful VPN authentication, Windows logon events can provide additional information about the account's activity.

Useful events:

| Event ID | Meaning |
|---|---|
| 4624 | Successful Windows logon |
| 4625 | Failed Windows logon |
| 6272 | NPS granted access |
| 6273 | NPS denied access |

Example search:

```spl
index=win EventCode IN (4624,4625) user={SUSPICIOUS_USER}
| table _time, EventCode, user, Logon_Type, Source_Network_Address
| sort _time
```

---

# Initial Access Investigation Workflow

A useful approach when investigating web and credential-based initial access is:

```text
Web Server
├── IIS 404 responses
├── Suspicious source IP
├── Successful resource discovery
└── Suspicious web requests
        ↓
Endpoint
├── Sysmon Event ID 1
├── w3wp.exe child processes
└── Sysmon Event ID 11
        ↓
Authentication
├── 4625 failed logons
├── 4624 successful logons
├── 6273 NPS denied access
└── 6272 NPS granted access
        ↓
Further Investigation
```

---
