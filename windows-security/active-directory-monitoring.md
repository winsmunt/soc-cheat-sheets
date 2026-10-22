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

# AD Credential Attacks

Credential attacks in Active Directory can target Kerberos tickets, process memory, or the Active Directory database itself.

The table below provides a quick reference for the main detection signals.

## Quick Reference

| Technique | Event ID | Main Detection Signal | Log Source |
|---|---|---|---|
| Kerberoasting | 4769 | RC4 tickets (`0x17`) and multiple SPNs requested by one account | DC Security Log |
| AS-REP Roasting | 4768 | `Pre_Authentication_Type=0` with no normal follow-up authentication | DC Security Log |
| LSASS Dumping | Sysmon 10 | Access to `lsass.exe`, suspicious `GrantedAccess` and `CallTrace` | Endpoint Sysmon |
| DCSync | 4662 | `Access_Mask=0x100`, replication GUIDs, non-machine account | DC Security Log |
| NTDS.dit Extraction | Sysmon 1, 11 | `ntdsutil.exe` or `vssadmin.exe` with IFM / shadow copy activity | DC Sysmon |

---

# Kerberoasting

Kerberoasting involves requesting Kerberos service tickets for accounts that have Service Principal Names (SPNs).

Event ID `4769` records Kerberos service ticket requests and is the main event used for detecting this activity.

## Important Event 4769 Fields

| Field | What It Contains | Why It Matters |
|---|---|---|
| `Service_Name` | SPN being requested | Shows which service account is being targeted |
| `Ticket_Encryption_Type` | Ticket encryption type | RC4 requests can be an important Kerberoasting signal |
| `Account_Name` | Account requesting the ticket | Identifies the account performing the requests |
| `Client_Address` | Source IP of the request | Identifies the source machine |

## Kerberos Encryption Types

Two useful values when reviewing Event 4769 are:

| Value | Encryption |
|---|---|
| `0x12` | AES |
| `0x17` | RC4 |

RC4 (`0x17`) ticket requests are especially useful when looking for possible Kerberoasting activity.

## Find RC4 Service Ticket Requests

```spl
index=* EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$*" Service_Name!="krbtgt"
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
| sort _time
```

This search focuses on RC4 service tickets while excluding machine accounts and `krbtgt`.

## Look for Many SPNs Requested by One Account

A useful detection method is to identify accounts requesting tickets for many different services.

```spl
index=* EventCode=4769 Service_Name!="*$*" Service_Name!="krbtgt"
| bin _time span=5m
| stats dc(Service_Name) as unique_spns count by Account_Name, Client_Address, _time
| where unique_spns > 5
```

This groups requests into five-minute windows and counts how many unique SPNs were requested by each account.

A large number of different SPNs requested in a short period can be worth investigating.

---

# AS-REP Roasting

AS-REP Roasting targets accounts that do not require Kerberos pre-authentication.

Event ID `4768` records Kerberos TGT requests.

## Normal Authentication vs AS-REP Roasting

A normal authentication sequence may look like:

```text
4768 → 4769 → 4624
```

This represents:

```text
TGT request
    ↓
Service ticket request
    ↓
Successful logon
```

AS-REP Roasting may instead appear as:

```text
4768 → no follow-up authentication
```

The attacker requests authentication data but does not continue with the normal authentication process.

## Review TGT Requests

```spl
index=* EventCode=4768
| table _time, Account_Name, Pre_Authentication_Type, Ticket_Encryption_Type, Client_Address
| sort _time
```

## Find Accounts Without Pre-Authentication

```spl
index=* EventCode=4768 Pre_Authentication_Type=0
| table _time, Account_Name, Pre_Authentication_Type, Ticket_Encryption_Type, Client_Address
```

`Pre_Authentication_Type=0` is an important signal because it shows that Kerberos pre-authentication was not used.

## Check for Follow-Up Activity

After finding a suspicious account, check whether normal authentication continued:

```spl
index=* (EventCode=4624 OR EventCode=4769)
| search Account_Name="{ACCOUNT_NAME}"
| table _time, EventCode, Account_Name, Client_Address
```

If a `4768` event with `Pre_Authentication_Type=0` appears without normal follow-up authentication, the activity deserves further investigation.

---

# LSASS Credential Dumping

LSASS (`lsass.exe`) stores authentication-related information in memory.

Credential dumping tools may attempt to access the LSASS process to read credentials.

Sysmon Event ID `10` records process access and can be useful for detecting this behaviour.

## Important Sysmon Event 10 Fields

| Field | What It Contains | Why It Matters |
|---|---|---|
| `SourceImage` | Process accessing LSASS | Identifies the tool or process performing the access |
| `SourceUser` | User running the source process | Helps identify the account performing the activity |
| `TargetImage` | Target process | Confirms that `lsass.exe` was accessed |
| `GrantedAccess` | Requested process permissions | Shows what level of access was requested |
| `CallTrace` | DLL call stack | Can provide more information about the access method |

## Useful Access Rights

| Access Right | Hex Value | Purpose |
|---|---|---|
| `PROCESS_QUERY_LIMITED_INFORMATION` | `0x1000` | Query basic process information |
| `PROCESS_QUERY_INFORMATION` | `0x0400` | Query detailed process information |
| `PROCESS_VM_READ` | `0x0010` | Read process memory |
| `PROCESS_ALL_ACCESS` | `0x1FFFFF` | Full access to the process |

Memory-read or full-access permissions are especially useful when investigating suspicious access to LSASS.

## Find Processes Accessing LSASS

```spl
index=* EventCode=10 TargetImage="*\\lsass.exe"
| stats count by SourceImage, GrantedAccess
```

This provides a quick overview of which processes accessed LSASS and what permissions they requested.

## Investigate a Suspicious Process

```spl
index=* EventCode=10 TargetImage="*\\lsass.exe" SourceImage={SUSPICIOUS_PROCESS}
| table _time, SourceImage, SourceUser, GrantedAccess, CallTrace
```

When investigating, focus on:

- the process accessing LSASS;
- the user running that process;
- the requested access rights;
- the call trace.

---

# DCSync

DCSync abuses Active Directory replication functionality.

Event ID `4662` can provide evidence of directory replication activity.

## Find Replication Activity

```spl
index=* EventCode=4662 "1131f6ad" user!="*$"
| table _time, user, Access_Mask, Properties
| sort _time
```

The GUID `1131f6ad` is useful when looking for replication-related activity.

Machine accounts normally end with `$`, so:

```spl
user!="*$"
```

removes them from the results and helps focus on user accounts.

## Focus on Suspicious Replication Access

```spl
index=* EventCode=4662 Access_Mask=0x100 user={COMPROMISED_USER} "1131f6ad"
| table _time, host, user, Logon_ID
```

The `Logon_ID` can then be used to connect the replication activity with the logon session that generated it.

## Pivot to the Logon Session

```spl
index=* EventCode=4624 Logon_ID={LOGON_ID}
| table _time, host, user, Source_Network_Address, Logon_Type
```

This pivot can help identify:

- where the session originated;
- which account was used;
- what type of logon created the session.

---

# NTDS.dit Extraction

`NTDS.dit` is the Active Directory database.

Attackers with sufficient privileges may attempt to extract it to obtain credential information.

Two useful tools to monitor are:

```text
ntdsutil.exe
vssadmin.exe
```

## NTDSUtil

`ntdsutil.exe` can be used to create Active Directory installation media containing copies of important AD data.

An example command is:

```cmd
ntdsutil "ac i ntds" "ifm" "create full C:\temp" q q
```

## Detect NTDSUtil Execution

Sysmon Event ID `1` records process creation.

```spl
index=* EventCode=1 Image="*\\ntdsutil.exe"
| table _time, host, User, ParentImage, Image, CommandLine
```

Important fields include:

- `User`
- `ParentImage`
- `Image`
- `CommandLine`

The command line can show whether `ntdsutil.exe` was being used to create installation media.

## Detect NTDS.dit File Creation

Sysmon Event ID `11` records file creation.

```spl
index=* EventCode=11 TargetFilename="*ntds.dit" Image="*\\ntdsutil.exe"
| table _time, Image, TargetFilename
```

This can show `ntdsutil.exe` creating a copy of `ntds.dit`.

---

# Volume Shadow Copy Activity

Another method of accessing `NTDS.dit` is through Volume Shadow Copies.

An attacker may create a shadow copy using:

```cmd
vssadmin create shadow /for=C:
```

Then files such as `NTDS.dit` and the SYSTEM registry hive can be copied from the shadow copy.

## Detect Shadow Copy Creation

```spl
index=* EventCode=1 Image="*\\vssadmin.exe" CommandLine="*create shadow*"
| table _time, host, User, ParentImage, Image, CommandLine
```

## Detect Access to Shadow Copies

```spl
index=* EventCode=1 CommandLine="*HarddiskVolumeShadowCopy*" (CommandLine="*ntds*" OR CommandLine="*SYSTEM*")
| table _time, host, User, ParentImage, Image, CommandLine
```

This looks for commands accessing `NTDS.dit` or the SYSTEM hive through a Volume Shadow Copy path.

---

# Credential Attack Investigation Workflow

When investigating suspicious Active Directory credential activity, a useful workflow is:

```text
Identify the detection event
        ↓
Identify the account
        ↓
Identify the source host / IP
        ↓
Review related authentication events
        ↓
Review process or command-line activity
        ↓
Determine whether the behaviour matches the credential attack
```

Different techniques require different log sources:

| Technique | Main Log Source |
|---|---|
| Kerberoasting | Domain Controller Security Logs |
| AS-REP Roasting | Domain Controller Security Logs |
| LSASS Dumping | Endpoint Sysmon |
| DCSync | Domain Controller Security Logs |
| NTDS.dit Extraction | Domain Controller Sysmon |

The important point is not to rely on one event alone. Use the event as the starting point and then pivot to the account, source system, logon session, process, or related authentication activity.
