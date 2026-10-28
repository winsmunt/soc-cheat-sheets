# Microsoft 365 Security Monitoring

A practical SOC reference for monitoring Microsoft 365 environments using Entra ID, Exchange Online, SharePoint Online, Microsoft Intune, and Splunk.

---

## Quick Reference

### Important Log Sources

| Area | Sourcetype / Workload | Purpose |
|---|---|---|
| Entra ID Sign-ins | `azure:aad:signin` | Authentication activity |
| Entra ID Audit | `azure:aad:audit` | Administrative and directory changes |
| Entra ID Risk Detection | `azure:aad:identity_protection:riskdetection` | Identity Protection detections |
| Entra ID Risky Users | `azure:aad:identity_protection:risky_user` | Users identified as risky |
| M365 Audit | `o365:management:activity` | Microsoft 365 activity |
| Exchange Online | `Workload=Exchange` | Exchange administrative and mailbox activity |
| Message Trace | `o365:reporting:messagetrace` | Email delivery and message tracking |
| SharePoint Online | `Workload=SharePoint` | File access, sharing, and download activity |
| Intune | `azure:aad:signin` / custom `o365:graph:intune` | Device sign-ins and Intune activity |

---

## Entra ID Monitoring

Entra ID logs provide visibility into authentication, administrative actions, risky identities, Conditional Access, and account changes.

---

# Sign-in Monitoring

## List All Sign-in Events

```spl
index=<INDEX> sourcetype="azure:aad:signin"
```

Useful fields include:

- `userPrincipalName`
- `ipAddress`
- `appDisplayName`
- `status.errorCode`
- `location`
- `conditionalAccessStatus`

---

## Important Sign-in Error Codes

| Error Code | Meaning |
|---|---|
| `50126` | Invalid username or password |
| `50053` | Account locked due to too many failed attempts |
| `50074` | MFA required but not provided |
| `50055` | Password expired |

Repeated authentication errors can help identify brute-force attempts, MFA abuse, or problems affecting an account.

---

## Find Failed Sign-ins

```spl
index=<INDEX> sourcetype="azure:aad:signin" status.errorCode!=0
| stats count as event_count values(ipAddress) as ip_addresses values(appDisplayName) as applications values(location) as locations values(status.errorCode) as errorCodes by userPrincipalName
| sort - event_count
```

This helps identify users generating unusually large numbers of failed authentication attempts.

---

## Find Successful Sign-ins from an IP Address

```spl
index=<INDEX> sourcetype="azure:aad:signin" status.errorCode=0 ipAddress="<IP>"
| stats values(ipAddress) as ip_addresses values(appDisplayName) as applications by userPrincipalName
| table applications, userPrincipalName, ip_addresses
```

Useful when investigating whether a suspicious IP successfully authenticated to any accounts.

---

# Conditional Access

Conditional Access results can provide additional context during authentication investigations.

| Result | Meaning |
|---|---|
| `success` | Policy conditions were met and controls were satisfied |
| `failure` | Policy blocked the sign-in or required controls were not satisfied |
| `notApplied` | Policy conditions were not met or the user/app was not in scope |
| `reportOnly` | Policy would have applied but was not enforced |

A failed Conditional Access result should be investigated together with:

- user
- source IP
- application
- location
- authentication result

---

# Risky Sign-ins

Risk information can help identify authentication activity that Microsoft considers suspicious.

Useful fields include:

- `riskEventType`
- `riskLevel`
- `userPrincipalName`
- `ipAddress`
- `location.countryOrRegion`

Examples of risk events include:

```text
anonymizedIPAddress
impossibleTravel
```

---

## List Risk Detection Logs

```spl
index=<INDEX> sourcetype="azure:aad:identity_protection:riskdetection"
```

---

## Investigate a Risk Type

```spl
index=<INDEX> sourcetype="azure:aad:identity_protection:riskdetection"
| where riskEventType="<RISK_TYPE>"
| table _time, userPrincipalName, activity, ipAddress, location.countryOrRegion, riskLevel, riskEventType
| sort - _time
```

---

## List Risky Users

```spl
index=<INDEX> sourcetype="azure:aad:identity_protection:risky_user"
| table _time, userPrincipalName, riskLevel, riskState, riskDetail
| sort - _time
```

---

# MFA Abuse Detection

Repeated MFA activity against one account can indicate an MFA fatigue attack.

### Indicators

Look for:

- a high volume of MFA prompts against one account;
- repeated MFA-related error codes;
- authentication attempts from unusual IP addresses;
- successful authentication following many MFA failures.

Important error codes from the lab include:

```text
50074
50076
500121
```

If a user eventually authenticates successfully after many MFA failures, investigate the successful session carefully.

---

# Entra ID Audit Logs

Audit logs record administrative and directory changes.

```spl
index=<INDEX> sourcetype="azure:aad:audit"
```

Important fields include:

| Field | Purpose |
|---|---|
| `activityDisplayName` | Action performed by a user or application |
| `initiatedBy` | Account or application that performed the action |
| `targetResources` | Account or object affected by the action |

These fields are useful for determining:

```text
WHO performed the action
        ↓
WHAT action was performed
        ↓
WHICH object was affected
```

---

# Account and Role Changes

## Find User Creation Activity

```spl
index=<INDEX> sourcetype="azure:aad:audit" activityDisplayName="Add user"
```

Unexpected account creation can represent a persistence mechanism.

When investigating account creation, review:

- `initiatedBy`
- `activityDisplayName`
- newly created user
- time of creation

---

## Find Role Assignment Activity

Role changes can indicate privilege escalation or persistence.

Search audit activity for:

```text
Add member to role
```

Important investigation fields include:

- initiator;
- target user;
- assigned role;
- time of change.

---

# MFA Method Changes

Attackers with access to an account may attempt to register their own authentication method.

Search for activity related to:

```text
Update user authentication method
```

Important fields to review include:

- initiator;
- target user;
- application;
- result;
- modified properties.

An unexpected MFA method change should be correlated with recent sign-in activity.

---

# Application Consent

Application consent can grant applications access to Microsoft 365 resources.

Audit logs can be searched for consent-related activity.

Useful fields include:

- initiator;
- application name;
- permissions granted;
- target resources.

Unexpected consent grants can provide persistent access to cloud data.

---

# Microsoft 365 Audit Logs

Microsoft 365 activity can be searched using:

```spl
index=<INDEX> sourcetype="o365:management:activity"
```

To investigate activity performed by a specific user:

```spl
index=<INDEX> sourcetype="o365:management:activity" UserId="<USER>"
| sort - _time
| table _time, Operation, UserId, SourceIP, Workload, ObjectId
```

---

# Exchange Online Monitoring

Exchange Online investigations should combine sign-in activity with mailbox and message activity.

---

## Exchange Sign-ins

Exchange Online authentication can be identified through Entra ID sign-in logs using the application:

```text
Office 365 Exchange Online
```

Useful fields include:

- `userPrincipalName`
- `appDisplayName`
- `ipAddress`
- `location.city`
- `status.errorCode`

---

# Exchange Audit Logs

```spl
index=<INDEX> sourcetype="o365:management:activity" Workload=Exchange
| table _time, UserId, Operation, Workload
```

Important Exchange operations can reveal:

- inbox rule creation;
- mailbox forwarding;
- mailbox permission changes;
- email access;
- sent messages.

---

# Inbox Rule Creation

Attackers may create inbox rules after compromising a mailbox.

```spl
index=* Workload=Exchange Operation=New-InboxRule
| table _time, UserId, Name, DeleteMessage, ForwardTo, SubjectContainsWords
```

Important rule parameters include:

| Parameter | Purpose |
|---|---|
| `Name` | Name given to the rule |
| `SubjectContainsWords` | Condition that triggers when the subject contains specific words |
| `DeleteMessage` | Deletes matching emails |
| `ForwardTo` | Forwards matching emails to another address |

Suspicious rules may be used to hide security notifications or forward sensitive emails.

---

# Mailbox-Level Forwarding

Mailbox forwarding can be investigated with:

```spl
index=* Workload=Exchange Operation=Set-Mailbox
| table _time, UserId, ForwardingSmtpAddress, DeliverToMailboxAndForward
```

Unexpected forwarding addresses should be investigated.

---

# Mailbox Permission Changes

Delegate access changes can appear as:

```text
Add-MailboxPermission
```

Unexpected mailbox permissions may allow another account to access a victim's mailbox.

---

# Mail Items Accessed

```spl
index=* Workload=Exchange Operation=MailItemsAccessed
| table _time, UserId, ClientIPAddress, OperationCount
```

### Red Flags

Watch for:

- `MailItemsAccessed` from an unusual IP address or location;
- high `OperationCount`;
- access occurring outside normal business hours.

---

# Sent Email Investigation

Important fields include:

| Field | Description |
|---|---|
| `UserId` | Account that sent the email |
| `Item.Subject` | Email subject |
| `Item.SizeInBytes` | Email size |
| `ClientIP` | IP address from which the email was sent |
| `SaveToSentItems` | Whether the email was saved to Sent Items |

Search:

```spl
index=* Workload=Exchange Operation=Send
| table _time, UserId, Item.Subject, ClientIP, SaveToSentItems
```

### Red Flags

Look for:

- high volume of `Send` operations in a short time;
- `SaveToSentItems=False`;
- emails sent from an IP inconsistent with the user's normal sign-in activity;
- suspicious subjects such as invoice updates, password resets, or urgent requests.

---

# Message Trace

Message Trace logs provide visibility into email delivery.

```spl
index=* sourcetype="o365:reporting:messagetrace"
| table Received, SenderAddress, RecipientAddress, Subject, Status, FromIP
```

This is useful when tracking suspicious messages across Exchange Online.

---

# Exchange Investigation Flow

A useful investigation sequence is:

```text
Suspicious Account
        ↓
Review Entra ID Sign-ins
        ↓
Check Source IP / Location
        ↓
Review Exchange Audit Logs
        ↓
Check Inbox Rules / Forwarding
        ↓
Review MailItemsAccessed
        ↓
Review Sent Messages
        ↓
Use Message Trace
```

---

# SharePoint Online Monitoring

SharePoint logs provide visibility into file creation, sharing, access, and downloads.

---

## Important SharePoint Operations

| Operation | Purpose |
|---|---|
| `FileCreated` | Track file creation |
| `FileUploaded` | Track uploaded files |
| `FileDeleted` | Identify deleted files |
| `FileRecycled` | Identify files moved to recycle bin |
| `FileAccessed` | Track file access |
| `FileDownloaded` | Track file downloads |
| `AddedToSecureLink` | Track secure sharing |
| `AnonymousLinkCreated` | Track anonymous sharing |

---

# SharePoint Sharing Activity

Sharing events can be searched using operations such as:

```text
AddedToSecureLink
AnonymousLinkCreated
SecureLinkUsed
AnonymousLinkUsed
```

Unexpected anonymous or external sharing should be reviewed carefully.

---

# File Download Analysis

A useful way to detect unusual download activity is to count downloads by source and user.

```spl
index=<INDEX> Workload=SharePoint Operation=FileDownloaded
| stats count values(SourceFileName) by SiteUrl, SourceRelativeUrl, UserId
| where count >= 5
```

Large numbers of downloads may indicate data collection or exfiltration.

---

# Rclone Activity

When investigating possible Rclone usage, review `FileDownloaded` activity together with application and user-agent information.

```spl
index=* rclone Operation=FileDownloaded
| table _time, UserId, Operation, ApplicationDisplayName, ApplicationId, UserAgent
```

This can help distinguish normal browser activity from automated file collection.

---

# SharePoint Abuse Investigation

A useful workflow is:

```text
Identify Suspicious File
        ↓
Find FileUploaded / FileCreated
        ↓
Identify User and Upload Source
        ↓
Review Sharing Events
        ↓
Check Link Usage
        ↓
Review FileAccessed / FileDownloaded
        ↓
Identify Other Users Accessing the File
```

Useful searches can pivot on the suspicious `ObjectId`.

Examples:

```spl
index=<INDEX> Operation IN(FileUploaded, FileCreated) ObjectId="<FILE>"
| table _time, UserId, Operation, ObjectId
```

```spl
index=<INDEX> Operation IN(AddedToSecureLink, SharingSet) ObjectId="<FILE>"
| table _time, UserId, TargetUserOrGroupName, ObjectId
```

```spl
index=<INDEX> Operation IN(*LinkUsed, FileAccessed) ObjectId="<FILE>"
| stats values(UserId)
```

---

# Microsoft Intune Monitoring

Intune monitoring provides visibility into managed devices and administrative device actions.

---

# Device Sign-ins

Entra ID sign-in logs contain device information that can help distinguish managed from unmanaged systems.

Useful device fields include:

```text
deviceDetail
deviceDetail.isManaged
deviceDetail.isCompliant
deviceDetail.displayName
```

---

## Detect Sign-ins from Unmanaged Devices

```spl
index=<INDEX> sourcetype="azure:aad:signin"
| rename deviceDetail.* as deviceDetail_*
| table _time, appDisplayName, ipAddress, deviceDetail_isManaged, deviceDetail_isCompliant, user
```

Sign-ins from unmanaged or non-compliant devices can provide useful investigation context.

---

# Remote Wipe Detection

Intune activity can be monitored for device wipe actions.

```spl
index=<INDEX> sourcetype="o365:graph:intune" wipe
| eval deviceid=mvindex('resources{}.modifiedProperties{}.newValue', 0)
| table _time, activityType, actor.userPrincipalName, deviceid
```

A remote wipe action should be investigated to determine:

- who initiated it;
- which device was targeted;
- whether the action was expected.

---

# Device Management Scripts

Platform or device-management scripts can be investigated through Intune activity.

Relevant activity includes:

```text
DeviceManagementScript
```

Useful fields include:

- actor;
- user principal name;
- action;
- script target.

Unexpected device-management scripts can affect multiple managed endpoints.

---

# Application Events

Intune application activity can also be monitored through custom Intune logs.

Relevant activity includes:

```text
MobileApps
```

This provides visibility into application-related administrative actions.

---

# SOC Investigation Strategy

Microsoft 365 investigations often require correlating several different services.

A suspicious cloud account should not be investigated using only sign-in logs.

A useful workflow is:

```text
Entra ID Sign-in
        ↓
Authentication Result
        ↓
IP / Location / Device
        ↓
Risk Detection
        ↓
Conditional Access
        ↓
Entra ID Audit Changes
        ↓
M365 Workload Activity
        ↓
Exchange / SharePoint / Intune
```

---

# High-Value Red Flags

## Identity

- repeated failed authentication;
- repeated MFA errors;
- successful login after many MFA failures;
- unusual IP address or location;
- risky sign-in detection;
- unexpected user creation;
- unexpected role assignment;
- new MFA authentication method;
- suspicious application consent.

## Exchange

- suspicious inbox rule;
- external mailbox forwarding;
- unexpected mailbox permissions;
- unusual `MailItemsAccessed`;
- high-volume mailbox access;
- high-volume email sending;
- `SaveToSentItems=False`;
- sending from an unusual IP.

## SharePoint

- unexpected anonymous sharing;
- suspicious file uploads;
- large numbers of file downloads;
- automated download activity;
- unusual file access;
- suspicious sharing followed by external access.

## Intune

- authentication from unmanaged devices;
- authentication from non-compliant devices;
- unexpected remote wipe actions;
- suspicious device-management scripts;
- unusual application-management activity.

---

# Investigation Mindset

Microsoft 365 activity should be investigated as a chain of related events rather than isolated logs.

For example:

```text
Multiple MFA Failures
        ↓
Successful Authentication
        ↓
Unusual Source IP
        ↓
New Inbox Rule
        ↓
Mailbox Access
        ↓
External Forwarding
```

or:

```text
Suspicious Sign-in
        ↓
SharePoint File Access
        ↓
Large Number of Downloads
        ↓
Automated User-Agent / Application
```

The strongest indicator is often not one event, but the correlation between identity, audit, and workload activity.

---
