# AWS Security Monitoring

Practical SOC reference for investigating AWS environments using CloudTrail, VPC Flow Logs, Splunk, and workload telemetry.

---

# Quick Reference

## Important AWS Log Sources

| Log Source | What It Shows | Useful For |
|---|---|---|
| CloudTrail | AWS API activity | IAM activity, configuration changes, authentication, service abuse |
| VPC Flow Logs | Network connections | Suspicious traffic, unusual ports, rejected connections |
| GuardDuty | AWS security findings | Compromised credentials, malicious IPs, suspicious EC2 activity |
| SSM / CloudTrail | Remote management activity | `SendCommand`, `StartSession`, remote execution |
| Falco | Runtime / syscall activity | Process execution, containers, workload investigation |

---

## Important CloudTrail Fields

| Field | Meaning |
|---|---|
| `eventTime` | Time of the AWS API activity |
| `eventSource` | AWS service that received the request |
| `eventName` | API action that was performed |
| `userIdentity` | Identity responsible for the activity |
| `userIdentity.userName` | IAM username |
| `userIdentity.type` | Identity type |
| `userIdentity.accessKeyId` | Access key used for the request |
| `sourceIPAddress` | Source IP address |
| `userAgent` | Client or tool that made the request |
| `requestParameters` | Parameters supplied to the API |
| `responseElements` | Result of the API request |
| `readOnly` | Whether the operation changed AWS resources |
| `recipientAccountId` | AWS account receiving the request |
| `awsRegion` | AWS region where the activity occurred |
| `errorMessage` | Error returned by the request |

### Basic CloudTrail Search

```spl
index=aws
| table _time eventName eventSource userIdentity.userName sourceIPAddress userAgent
```

### Find AWS Changes

```spl
index=aws readOnly=false
| table _time userIdentity.userName eventSource eventName sourceIPAddress userAgent
| sort - _time
```

`readOnly=false` is particularly useful because it focuses the investigation on API calls that changed something.

---

# AWS Authentication Monitoring

## Console Login

AWS Console authentication appears in CloudTrail as:

```text
eventName = ConsoleLogin
```

Important fields:

```text
eventName
errorMessage
userIdentity.arn
userIdentity.userName
sourceIPAddress
userAgent
additionalEventData.MFAUsed
additionalEventData.MobileVersion
```

### Find Console Logins

```spl
index=aws eventName=ConsoleLogin
| table _time userIdentity.userName sourceIPAddress userAgent responseElements.ConsoleLogin additionalEventData.MFAUsed
```

### Failed Console Logins

```spl
index=aws eventName=ConsoleLogin errorMessage=*
| table _time userIdentity.userName sourceIPAddress errorMessage userAgent
| sort - _time
```

Investigate:

- repeated authentication failures;
- unusual source IPs;
- unfamiliar countries or networks;
- unusual user agents;
- successful authentication after multiple failures;
- logins without MFA.

---

# Console Login vs Access Key Activity

AWS activity can originate from interactive console sessions or programmatic access keys.

## Console Login

Common indicators:

```text
eventName = ConsoleLogin
userIdentity.type = IAMUser
userAgent = browser
```

## Access Key / API Activity

Access keys commonly appear as:

```text
userIdentity.accessKeyId = AKIA...
```

and API clients may appear in:

```text
userAgent
```

Examples include AWS CLI, SDKs, automation, and custom scripts.

### Find Access Key Activity

```spl
index=aws userIdentity.accessKeyId="AKIA*"
| table _time userIdentity.userName userIdentity.accessKeyId eventName sourceIPAddress userAgent
```

Another useful approach is excluding console-specific activity:

```spl
index=aws NOT userIdentity.sessionContext.attributes.creationDate=*
| table _time userIdentity.userName eventName sourceIPAddress userAgent
```

---

# IAM Monitoring

Identity changes are high-value SOC events.

Important activity includes:

| Activity | Why Investigate |
|---|---|
| Policy changes | Can grant new privileges |
| Group membership changes | Can provide additional permissions |
| MFA changes | Can weaken account protection |
| Access key creation | Can provide persistent programmatic access |
| Role assumption | Can allow privilege escalation or movement between roles |

---

## High-Risk IAM Events

Look for events such as:

```text
PutUserPolicy
PutRolePolicy
PutGroupPolicy

AttachUserPolicy
AttachRolePolicy
AddUserToGroup

DeleteVirtualMFADevice
DeactivateMFADevice

CreateAccessKey
UpdateAccessKey
```

### Search for IAM Changes

```spl
index=aws eventSource="iam.amazonaws.com"
(
    eventName=PutUserPolicy OR
    eventName=PutRolePolicy OR
    eventName=PutGroupPolicy OR
    eventName=AttachUserPolicy OR
    eventName=AttachRolePolicy OR
    eventName=AddUserToGroup OR
    eventName=DeleteVirtualMFADevice OR
    eventName=DeactivateMFADevice OR
    eventName=CreateAccessKey OR
    eventName=UpdateAccessKey
)
| table _time userIdentity.userName eventName sourceIPAddress userAgent requestParameters
| sort - _time
```

---

# AssumeRole Monitoring

AWS STS allows identities to assume roles.

Important event:

```text
AssumeRole
```

Important fields include:

```text
userIdentity
requestParameters.roleArn
requestParameters.roleSessionName
sourceIPAddress
userAgent
```

### Find AssumeRole Activity

```spl
index=aws eventSource="sts.amazonaws.com" eventName=AssumeRole
| table _time userIdentity.arn requestParameters.roleArn requestParameters.roleSessionName sourceIPAddress userAgent
| sort - _time
```

Investigate:

- unusual role assumptions;
- administrative roles used by normal users;
- unfamiliar source IP addresses;
- unexpected role session names;
- role assumptions followed by sensitive API activity.

---

# AWS Enumeration

Attackers with AWS credentials often enumerate the environment before performing further actions.

Useful AWS CLI commands seen during enumeration include:

## Identify Current Identity

```bash
aws sts get-caller-identity
```

This is effectively the AWS equivalent of asking:

```text
Who am I?
```

It returns information such as:

```text
UserId
Account
Arn
```

---

## Check Attached Policies

```bash
aws iam list-attached-user-policies --user-name <username>
```

This can reveal the permissions attached to the compromised account.

For example:

```text
AdministratorAccess
```

would indicate highly privileged access.

---

## Enumerate AWS Account Information

```bash
aws iam get-account-summary
```

This can reveal information such as:

```text
Policies
Users
Providers
AccountMFAEnabled
AccountAccessKeysPresent
AccountPasswordPresent
```

---

# Detecting Suspicious Enumeration

CloudTrail records AWS API enumeration.

Example:

```text
eventName = DescribeInstances
```

Important indicators can include:

```text
sourceIPAddress
userAgent
requestParameters
```

A single event may contain several detection opportunities.

Examples:

```text
Known malicious source IP
Kali Linux user agent
Suspicious search keywords
```

For example, an attacker may search EC2 tags for values such as:

```text
*vault*
*secret*
```

### Find Describe Activity

```spl
index=aws eventName="Describe*"
| table _time userIdentity.userName eventName sourceIPAddress userAgent requestParameters
| sort - _time
```

### Look for Suspicious User Agents

```spl
index=aws
| stats count by userAgent
| sort count
```

Rare user agents can be useful investigation leads.

---

# S3 Monitoring

S3 bucket policies can expose sensitive data if they are modified incorrectly or maliciously.

Important events include:

```text
PutBucketPolicy
PutBucketAcl
```

Example:

```text
eventSource = s3.amazonaws.com
eventName = PutBucketPolicy
```

Important fields:

```text
userIdentity.userName
requestParameters.bucketName
requestParameters.bucketPolicy
sourceIPAddress
```

---

## Understanding S3 Bucket Policies

Important policy fields include:

| Field | Meaning |
|---|---|
| `Effect` | Allow or Deny |
| `Principal` | Who receives access |
| `Action` | What action is allowed |
| `Resource` | Which resource is affected |
| `Condition` | Restrictions applied to the policy |

A particularly important value is:

```json
"Principal": "*"
```

This can indicate public/anonymous access depending on the rest of the policy.

Example action:

```json
"Action": "s3:GetObject"
```

allows objects to be read.

Conditions may restrict access, for example:

```json
"aws:SourceIp": ["67.55.61.83/32"]
```

---

## Search for S3 Policy Changes

```spl
index=aws eventSource="s3.amazonaws.com"
(eventName=PutBucketPolicy OR eventName=PutBucketAcl)
| table _time userIdentity.userName eventName sourceIPAddress requestParameters
| sort - _time
```

Investigate:

- `Principal: "*"`
- unexpected public access;
- unfamiliar source IP restrictions;
- changes to sensitive buckets;
- unusual users modifying policies.

---

# EC2 Security Group Monitoring

Security Groups act as network-level access controls around AWS resources.

Changes to Security Groups are therefore important SOC events.

Important event:

```text
AuthorizeSecurityGroupIngress
```

Important fields:

```text
requestParameters.groupId
requestParameters.ipPermissions
requestParameters.ipPermissions.items.ipProtocol
requestParameters.ipPermissions.items.fromPort
requestParameters.ipPermissions.items.toPort
requestParameters.ipPermissions.items.ipRanges
```

---

## Public Access

A CIDR range of:

```text
0.0.0.0/0
```

means traffic can originate from anywhere on the Internet.

For example:

```text
Port: 3389
CIDR: 0.0.0.0/0
```

can expose RDP publicly.

Other sensitive ports should also be reviewed carefully.

### Find Security Group Changes

```spl
index=aws eventName=AuthorizeSecurityGroupIngress
| table _time userIdentity.userName sourceIPAddress requestParameters
| sort - _time
```

### Hunt for Publicly Opened Rules

```spl
index=aws eventName=AuthorizeSecurityGroupIngress "0.0.0.0/0"
| table _time userIdentity.userName sourceIPAddress requestParameters
| sort - _time
```

---

# Tracking Security Groups Across Resources

A useful investigation technique is tracking a Security Group by its ID.

Example:

```text
sg-123456789
```

The same Security Group may appear when:

1. the group is created;
2. firewall rules are modified;
3. an EC2 instance is launched;
4. an RDS database is created;
5. another resource attaches the group.

### Search by Security Group ID

```spl
index=aws "sg-123456789"
| table _time userIdentity.userName eventSource eventName sourceIPAddress requestParameters
| sort _time
```

This can reconstruct how a risky network configuration propagated across AWS resources.

---

# RDS Monitoring

RDS databases may become exposed through configuration changes.

Important things to investigate include:

```text
CreateDBInstance
ModifyDBInstance
AuthorizeSecurityGroupIngress
```

Important configuration:

```text
publiclyAccessible
```

A suspicious sequence can be:

```text
Create RDS instance
        ↓
Enable public access
        ↓
Open database port
```

### Search RDS Changes

```spl
index=aws eventSource="rds.amazonaws.com" readOnly=false
| table _time userIdentity.userName eventName sourceIPAddress requestParameters
| sort _time
```

Look for:

- `publiclyAccessible=true`;
- unusual security groups;
- unexpected database creation;
- configuration changes followed by network exposure.

---

# VPC Flow Logs

VPC Flow Logs provide network visibility for AWS resources.

Important fields include:

| Field | Meaning |
|---|---|
| `srcaddr` | Source IP |
| `dstaddr` | Destination IP |
| `srcport` | Source port |
| `dstport` | Destination port |
| `protocol` | IP protocol number |
| `action` | `ACCEPT` or `REJECT` |
| `account-id` | AWS account |
| `interface-id` | Network interface |

Typical raw format:

```text
version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
```

---

## Useful VPC Flow Searches

### Connections by Source IP

```spl
index=aws sourcetype=*vpc*
| stats count by srcaddr
| sort -count
```

### Connections by Destination Port

```spl
index=aws sourcetype=*vpc*
| stats count by dstport
| sort -count
```

### Rejected Connections

```spl
index=aws sourcetype=*vpc* action=REJECT
| table _time srcaddr dstaddr srcport dstport protocol action
```

### Traffic From a Suspicious IP

```spl
index=aws sourcetype=*vpc* srcaddr="<IP>"
| table _time srcaddr dstaddr srcport dstport protocol action
```

---

# GuardDuty

GuardDuty provides AWS security findings.

Useful fields can include:

```text
service.action
resource
severity
title
type
updatedAt
```

Example finding categories include suspicious:

```text
EC2 activity
IAM activity
network connections
cryptocurrency mining
```

When investigating a GuardDuty finding, correlate it with:

```text
CloudTrail
VPC Flow Logs
EC2 activity
IAM activity
```

Do not stop at the GuardDuty alert itself.

---

# AWS Systems Manager (SSM)

AWS Systems Manager can remotely interact with EC2 systems.

Important CloudTrail activity includes:

```text
SendCommand
StartSession
```

`SendCommand` can execute commands remotely.

`StartSession` can create an interactive remote management session.

### Find SSM Activity

```spl
index=aws eventSource="ssm.amazonaws.com"
(eventName=SendCommand OR eventName=StartSession)
| table _time userIdentity.userName eventName sourceIPAddress userAgent requestParameters
| sort - _time
```

Investigate unexpected SSM activity because legitimate administration and attacker remote execution may use the same service.

---

# Workload Monitoring

CloudTrail tells us what happens through the AWS control plane.

It does not necessarily tell us everything happening inside an EC2 instance or container.

For workload visibility, host/runtime telemetry is also required.

One example is:

```text
Falco
```

---

# Falco Runtime Monitoring

Falco can record process and syscall activity from workloads and containers.

Useful fields include:

| Field | Meaning |
|---|---|
| `hostname` | Host where activity occurred |
| `container.id` | Container identifier |
| `container.image` | Container image |
| `container.name` | Container name |
| `proc.cmdline` | Executed command |
| `proc.cwd` | Working directory |
| `proc.exepath` | Executable path |
| `proc.pcmdline` | Parent command line |
| `proc.pexepath` | Parent executable |
| `proc.pid` | Process ID |
| `proc.ppid` | Parent PID |
| `proc.tty` | Terminal/session context |
| `user.name` | User executing the process |
| `priority` | Falco event priority |
| `rule` | Triggered rule |
| `source` | Event source |

Example activity:

```text
proc.cmdline = whoami
proc.exepath = /usr/bin/whoami
proc.pcmdline = bash
user.name = root
```

Falco can therefore provide context that CloudTrail alone cannot.

---

## Investigating Process Execution

Useful fields:

```text
user.name
proc.cmdline
proc.pid
proc.ppid
proc.pcmdline
proc.exepath
proc.pexepath
exit.code
```

Example Splunk workflow:

```spl
index=<workload-index>
| rename output_fields.* as *
| rename proc.tty as logon.session, evt.rawres as exit.code
| table _time user.name logon.session proc.pid proc.cmdline proc.ppid proc.pcmdline proc.pexepath exit.code
```

This makes it easier to reconstruct parent-child process relationships.

---

# Lambda Monitoring

AWS Lambda activity is also recorded through CloudTrail.

Important events include:

```text
CreateFunction*
UpdateFunctionConfiguration*
AddPermission*
PublishLayerVersion*
UpdateFunctionCode*
```

The `*` is useful because some Lambda event names contain version suffixes.

Example:

```text
UpdateFunctionConfiguration20150331v2
```

---

## Important Lambda Fields

```text
userIdentity.userName
eventSource
eventName
sourceIPAddress
userAgent
readOnly
requestParameters.functionName
requestParameters.role
responseElements.functionArn
responseElements.runtime
responseElements.role
```

### Search Lambda Changes

```spl
index=aws eventSource="lambda.amazonaws.com" readOnly=false
| table _time userIdentity.userName eventName sourceIPAddress userAgent requestParameters
| sort - _time
```

### Search High-Value Lambda Events

```spl
index=aws eventSource="lambda.amazonaws.com"
(
    eventName="CreateFunction*" OR
    eventName="UpdateFunctionConfiguration*" OR
    eventName="UpdateFunctionCode*" OR
    eventName="AddPermission*" OR
    eventName="PublishLayerVersion*"
)
| table _time userIdentity.userName eventName sourceIPAddress requestParameters
| sort - _time
```

Investigate unexpected:

- function creation;
- code modification;
- execution role changes;
- permissions;
- new layers;
- public or unusual invocation paths.

---

# SOC Investigation Workflow

When investigating suspicious AWS activity, a useful workflow is:

```text
1. Identify the user
        ↓
2. Identify the source IP
        ↓
3. Inspect the user agent
        ↓
4. Determine whether console or access keys were used
        ↓
5. Review authentication activity
        ↓
6. Check IAM / role changes
        ↓
7. Search readOnly=false activity
        ↓
8. Review resource modifications
        ↓
9. Correlate CloudTrail with VPC Flow Logs
        ↓
10. Investigate workload telemetry when needed
```

---

# Fast Investigation Queries

## What Did This User Do?

```spl
index=aws userIdentity.userName="<USER>"
| table _time eventSource eventName sourceIPAddress userAgent requestParameters
| sort _time
```

---

## What Came From This IP?

```spl
index=aws sourceIPAddress="<IP>"
| table _time userIdentity.userName eventSource eventName userAgent
| sort _time
```

---

## What Changed?

```spl
index=aws readOnly=false
| table _time userIdentity.userName eventSource eventName sourceIPAddress
| sort _time
```

---

## Most Active Users

```spl
index=aws
| stats count by userIdentity.userName
| sort -count
```

---

## Rare API Calls

```spl
index=aws
| stats count by eventName
| sort count
```

Rare does not automatically mean malicious, but unusual API calls are useful investigation leads.

---

## Activity by Source IP

```spl
index=aws
| stats count by sourceIPAddress
| sort -count
```

---

## Activity Timeline for a User

```spl
index=aws userIdentity.userName="<USER>"
| table _time eventName eventSource sourceIPAddress userAgent
| sort _time
```

---

# High-Value Detection Opportunities

During triage, prioritize combinations such as:

| Activity | Why It Matters |
|---|---|
| Console login without MFA | Weaker authentication |
| Login from unusual IP | Possible credential compromise |
| New access key | Potential persistence |
| MFA disabled | Account protection weakened |
| Admin policy attached | Possible privilege escalation |
| Administrative role assumed | Possible privilege escalation |
| `readOnly=false` activity | Resource modification |
| `Principal: "*"` in S3 policy | Possible public exposure |
| `0.0.0.0/0` Security Group rule | Internet exposure |
| RDS made publicly accessible | Database exposure |
| Kali / unusual CLI user agent | Possible attacker tooling |
| Enumeration followed by changes | Potential compromise progression |
| `SendCommand` / `StartSession` | Remote administration / execution |
| Lambda code or role modification | Possible persistence or code execution |
| Suspicious runtime process | Possible workload compromise |

---

# Key Investigation Principle

A single AWS event is often not enough.

Correlate:

```text
Identity
   +
Source IP
   +
User Agent
   +
API Calls
   +
Configuration Changes
   +
Network Traffic
   +
Workload Activity
```

For example:

```text
Unusual ConsoleLogin
        ↓
DescribeInstances
        ↓
AssumeRole
        ↓
Security Group modification
        ↓
SSM SendCommand
        ↓
Suspicious process on EC2
```

Together these events can reveal an attack chain that would be difficult to identify from one event alone.

---

# Final Quick Checklist

When investigating AWS activity, ask:

- **Who?** — `userIdentity`
- **When?** — `eventTime`
- **From where?** — `sourceIPAddress`
- **Using what?** — `userAgent`
- **What happened?** — `eventName`
- **Which AWS service?** — `eventSource`
- **What parameters?** — `requestParameters`
- **Did it change something?** — `readOnly=false`
- **Was authentication successful?** — `errorMessage`, `responseElements`
- **Was MFA used?** — `additionalEventData.MFAUsed`
- **Was a role assumed?** — `AssumeRole`
- **Were permissions changed?** — IAM events
- **Was something exposed publicly?** — S3, Security Groups, RDS
- **Was remote execution used?** — SSM
- **What happened inside the workload?** — Falco / host telemetry

---

## Summary

For AWS investigations, CloudTrail should usually be the starting point.

Focus first on:

```text
eventTime
eventName
eventSource
userIdentity
sourceIPAddress
userAgent
requestParameters
readOnly
```

Then correlate suspicious control-plane activity with:

```text
VPC Flow Logs
GuardDuty
SSM
Falco / workload telemetry
```

The objective is not simply to find a suspicious AWS event, but to reconstruct:

```text
WHO performed WHAT action,
FROM WHERE,
USING WHAT identity or credentials,
against WHICH resource,
and WHAT happened next.
```
