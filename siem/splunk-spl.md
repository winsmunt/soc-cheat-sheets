# Splunk SPL Cheat Sheet

A practical reference for Splunk Search Processing Language (SPL), focused on log analysis, SOC investigations, data transformation, and basic anomaly detection.

---

# 1. Basic SPL Search

The simplest SPL search can combine an index with free-text search.

```spl
index=windowslogs alice
```

This searches the `windowslogs` index for events containing the term `alice`.

A more targeted search uses fields:

```spl
index=windowslogs UserName="alice"
```

---

# 2. Relational Operators

Relational operators are used to compare field values.

| Operator | Meaning | Example |
|---|---|---|
| `=` | Equal | `UserName="Mark"` |
| `!=` | Not equal | `UserName!="Mark"` |
| `<` | Less than | `Age<10` |
| `<=` | Less than or equal | `Age<=10` |
| `>` | Greater than | `Outbound_Traffic>50` |
| `>=` | Greater than or equal | `Outbound_Traffic>=50` |

Example:

```spl
index=windowslogs EventID=4625
```

---

# 3. Logical Operators

Logical operators allow multiple search conditions to be combined.

## AND

Both conditions must match.

```spl
index=windowslogs UserName="David" AND IPAddress="10.10.10.10"
```

---

## OR

Either condition can match.

```spl
index=windowslogs UserName="David" OR UserName="John"
```

---

## NOT

Exclude matching events.

```spl
index=windowslogs NOT UserName="Mark"
```

---

## IN

Useful when searching for several possible values.

```spl
index=windowslogs UserName IN ("David", "John")
```

Instead of:

```spl
UserName="David" OR UserName="John"
```

---

# 4. Wildcards

The `*` wildcard matches multiple possible values.

Example:

```spl
status="fail*"
```

Can match values such as:

```text
failed
failure
appfail
```

Another example:

```spl
DestinationIp="172.*"
```

---

# 5. CIDR / Subnet Search

Splunk can search IP ranges using CIDR notation.

```spl
DestinationIp="172.18.0.0/16"
```

This searches for IP addresses belonging to the specified subnet.

Useful when investigating:

- internal network traffic;
- connections to a suspicious subnet;
- lateral movement;
- activity from a known network range.

---

# 6. SPL Pipeline

SPL commands are chained using the pipe:

```text
|
```

Example:

```spl
index=windowslogs
| fields EventID User Image Hostname SourceIp
| table _time EventID User Image Hostname SourceIp
```

Think of the pipeline as:

```text
Search events
    ↓
Filter / transform
    ↓
Calculate
    ↓
Format results
```

---

# 7. fields

`fields` controls which fields remain in the search results.

## Include Fields

```spl
index=windowslogs
| fields EventID User Image Hostname SourceIp
```

This keeps only the specified fields.

## Exclude Fields

Use `-` to remove fields.

```spl
index=windowslogs
| fields - host source sourcetype
```

### SOC Use

Useful when events contain many fields and you only need:

```text
User
Hostname
SourceIp
Image
EventID
```

---

# 8. table

`table` displays selected fields in a clean table.

```spl
index=windowslogs
| table _time EventID Hostname User SourceIp
```

This is especially useful when:

- building investigation timelines;
- comparing events;
- preparing readable results;
- answering a specific investigation question.

Example:

```spl
index=windowslogs EventID=4625
| table _time User SourceIp Hostname
```

---

# 9. dedup

`dedup` removes duplicate values.

Example:

```spl
index=windowslogs
| dedup SourceIp
```

Returns one event for each unique `SourceIp`.

Another example:

```spl
index=windowslogs
| dedup User
| table User
```

### SOC Use

Useful for questions such as:

```text
Which unique users appear?
Which unique IPs communicated with the host?
Which processes were executed?
```

---

# 10. rename

`rename` changes field names in the output.

```spl
index=windowslogs
| rename User AS Employee
```

Multiple fields:

```spl
index=windowslogs
| rename SourceIp AS "Source IP", Hostname AS Host
```

This does not change the original data.

It only improves how the results are displayed.

---

# 11. regex

`regex` filters events using regular expressions.

Example:

```spl
index=windowslogs
| regex Image=".*\.exe$"
```

This searches for values in `Image` ending in:

```text
.exe
```

### SOC Use

Useful when searching for patterns that cannot easily be represented with simple field filters.

Examples include:

```text
File extensions
IP patterns
Process names
Command-line patterns
```

---

# 12. head

Returns the first results.

```spl
index=windowslogs
| head 20
```

Useful when you only need a quick sample.

---

# 13. tail

Returns the last results.

```spl
index=windowslogs
| tail 20
```

---

# 14. sort

Sorts results by a field.

Ascending:

```spl
index=windowslogs
| sort User
```

Descending:

```spl
index=windowslogs
| sort - RiskScore
```

The `-` means descending order.

Example:

```spl
index=windowslogs
| stats count by User
| sort - count
```

This places the users with the highest event count first.

---

# 15. reverse

Reverses the current result order.

```spl
index=windowslogs
| reverse
```

---

# 16. top

`top` returns the most common values of a field.

```spl
index=windowslogs
| top User
```

Limit the number of results:

```spl
index=windowslogs
| top User limit=5
```

### SOC Use

Useful for quickly identifying:

```text
Most active users
Most common source IPs
Most frequently executed processes
Most common destination ports
```

Example:

```spl
index=windowslogs
| top SourceIp limit=10
```

---

# 17. rare

`rare` is the opposite of `top`.

It returns the least common values.

```spl
index=windowslogs
| rare User
```

Limit results:

```spl
index=windowslogs
| rare User limit=5
```

### SOC Use

Rare events can be very useful during threat hunting.

Examples:

```text
Rare process
Rare user
Rare destination IP
Rare executable
```

A rare value is not automatically malicious, but it can be a good investigation starting point.

---

# 18. stats

`stats` is one of the most important SPL commands.

It performs statistical calculations on search results.

## Count Events

```spl
index=windowslogs
| stats count
```

---

## Count by Field

```spl
index=windowslogs
| stats count by SourceIp
```

Example:

```spl
index=windowslogs EventID=4625
| stats count by User
| sort - count
```

This can help identify users with large numbers of failed authentication attempts.

---

## Average

```spl
| stats avg(ProcessCount)
```

---

## Maximum

```spl
| stats max(Price)
```

---

## Minimum

```spl
| stats min(Usage)
```

---

## Sum

```spl
| stats sum(Cost)
```

---

## Multiple Grouping Fields

```spl
index=windowslogs
| stats count by User Hostname
```

---

# 19. chart

`chart` creates tabular statistical results that can also be visualized.

Example:

```spl
index=windowslogs
| chart count by User
```

Useful when comparing values between categories.

---

# 20. timechart

`timechart` groups statistical results over time.

Example:

```spl
index=windowslogs Image!=" "
| timechart span=30m count by Image limit=5
```

This can show how frequently processes appear over time.

### SOC Use

Very useful for identifying:

```text
Traffic spikes
Authentication spikes
Process execution spikes
Beaconing patterns
Changes in activity over time
```

Example:

```spl
index=windowslogs EventID=4625
| timechart span=10m count
```

A sudden spike may indicate brute-force activity.

---

# 21. iplocation

`iplocation` enriches IP addresses with geographical information.

Example:

```spl
index=windowslogs
| iplocation SourceIp
```

It may add fields such as:

```text
City
Region
Country
```

Combine it with `stats`:

```spl
index=windowslogs
| iplocation SourceIp
| stats count by Country
```

### SOC Use

Useful when investigating:

```text
VPN logins
External authentication
Suspicious source IPs
Unusual login countries
```

Geolocation alone should not be treated as proof of malicious activity.

---

# 22. lookup

`lookup` enriches events using an external lookup table.

Example:

```spl
index=windowslogs
| lookup users_roles Hostname OUTPUT UserRole
| stats count by Hostname UserRole
```

Another example:

```spl
index=windowslogs
| lookup image_riskscore Image OUTPUT RiskScore
| stats count by Image RiskScore
| sort - RiskScore
```

This can add external context to events.

Possible uses:

```text
Asset criticality
User roles
Known malicious IPs
Process risk scores
Host ownership
```

---

# 23. eval

`eval` creates or modifies fields.

Example:

```spl
index=windowslogs
| eval LogonTypeDesc = case(
    LogonType==3, "Network Logon",
    LogonType==5, "Service"
)
```

Then:

```spl
| stats count by LogonType LogonTypeDesc
```

### SOC Use

`eval` is extremely useful for:

```text
Creating calculated fields
Renaming numerical values into readable descriptions
Risk calculations
Normalizing data
Creating conditions
```

---

# 24. eventstats

`eventstats` calculates statistics while preserving the original events.

Example:

```spl
index=vpnlogs
| eventstats count as logins_by_user by user
```

Each original event remains, but now receives an additional field:

```text
logins_by_user
```

This is useful when you need statistics for comparison without losing the underlying events.

---

# 25. where

`where` filters results using evaluated expressions.

Example:

```spl
| where country_freq < 0.1
```

Another example:

```spl
| where count > 10
```

This is especially useful after:

```text
stats
eventstats
eval
```

---

# 26. Anomaly Detection — Rare Login Country

A useful SOC example is identifying users logging in from countries they rarely use.

```spl
index=vpnlogs
| eventstats count as logins_by_user by user
| eventstats count as logins_by_user_country by user src_country
| eval country_freq=logins_by_user_country/logins_by_user
| where country_freq < 0.1
| table _time user src_ip src_country country_freq
```

## How It Works

### Step 1

```spl
eventstats count as logins_by_user by user
```

Counts all logins for each user.

---

### Step 2

```spl
eventstats count as logins_by_user_country by user src_country
```

Counts logins for each combination of:

```text
user + country
```

---

### Step 3

```spl
eval country_freq=logins_by_user_country/logins_by_user
```

Calculates how frequently the user logs in from that country.

---

### Step 4

```spl
where country_freq < 0.1
```

Keeps countries representing less than 10% of the user's login history.

This helps identify unusual geographic login behaviour.

---

# 27. Anomaly Detection — Unusual Login Time

Another useful approach is detecting logins occurring far outside a user's normal login time.

```spl
index=vpnlogs
| eval hour=tonumber(strftime(_time, "%H")) + tonumber(strftime(_time, "%M"))/60
| eventstats avg(hour) as typical_hour stdev(hour) as stdev_hour by user
| eval zscore=abs(hour - typical_hour) / stdev_hour
| where zscore > 3
| eval hour=round(hour, 2), typical_hour=round(typical_hour, 2)
| eval stdev_hour=round(stdev_hour, 2), zscore=round(zscore, 2)
| table _time user src_ip src_country hour typical_hour stdev_hour zscore
```

## How It Works

Convert the event timestamp into a numerical hour:

```spl
eval hour=tonumber(strftime(_time, "%H")) + tonumber(strftime(_time, "%M"))/60
```

Calculate the user's typical login hour:

```spl
eventstats avg(hour) as typical_hour stdev(hour) as stdev_hour by user
```

Calculate deviation from normal behaviour:

```spl
eval zscore=abs(hour - typical_hour) / stdev_hour
```

Keep significant outliers:

```spl
where zscore > 3
```

### SOC Interpretation

A login far outside a user's historical login pattern may deserve investigation.

However:

```text
Anomaly ≠ Attack
```

Always correlate it with:

```text
Source IP
Country
Device
Authentication method
Other user activity
```

---

# 28. Useful SOC Query Patterns

## Failed Logons by User

```spl
index=windowslogs EventID=4625
| stats count by User
| sort - count
```

---

## Failed Logons by Source IP

```spl
index=windowslogs EventID=4625
| stats count by SourceIp
| sort - count
```

---

## Unique Source IPs

```spl
index=windowslogs
| dedup SourceIp
| table SourceIp
```

---

## Most Active Users

```spl
index=windowslogs
| top User limit=10
```

---

## Rare Processes

```spl
index=windowslogs
| rare Image limit=10
```

---

## Process Activity Over Time

```spl
index=windowslogs
| timechart span=30m count by Image limit=5
```

---

## Login Countries

```spl
index=vpnlogs
| iplocation src_ip
| stats count by Country
| sort - count
```

---

# 29. Investigation Workflow

A useful way to approach SPL during an investigation:

```text
1. Start broad
        ↓
2. Identify interesting fields
        ↓
3. Filter noise
        ↓
4. Count / group events
        ↓
5. Identify anomalies
        ↓
6. Pivot on users, hosts, IPs, or processes
        ↓
7. Build a timeline
```

Example:

```spl
index=windowslogs
```

Then narrow it:

```spl
index=windowslogs EventID=4625
```

Group:

```spl
index=windowslogs EventID=4625
| stats count by User SourceIp
```

Sort:

```spl
index=windowslogs EventID=4625
| stats count by User SourceIp
| sort - count
```

Then investigate the interesting user or IP in more detail.

---

# 30. Quick Reference

| Command | Purpose |
|---|---|
| `fields` | Include or exclude fields |
| `table` | Display selected fields |
| `dedup` | Remove duplicates |
| `rename` | Rename fields |
| `regex` | Filter using regex |
| `head` | First results |
| `tail` | Last results |
| `sort` | Sort results |
| `reverse` | Reverse result order |
| `top` | Most common values |
| `rare` | Least common values |
| `stats` | Calculate statistics |
| `chart` | Create categorized statistics |
| `timechart` | Statistics over time |
| `iplocation` | Add geographic IP information |
| `lookup` | Enrich data from lookup tables |
| `eval` | Create or modify fields |
| `eventstats` | Add statistics without removing events |
| `where` | Filter evaluated results |

---

And the basic investigation pattern:

```spl
index=<index> <filter>
| stats count by <field>
| sort - count
```

---

## Key Takeaway

SPL becomes much easier when queries are treated as a pipeline.

Instead of trying to build a complicated query immediately:

```text
Find the data
    ↓
Reduce the data
    ↓
Transform the data
    ↓
Calculate statistics
    ↓
Display the useful fields
```

For SOC investigations, the goal is not to memorize every SPL command. The important skill is knowing how to progressively narrow a dataset until suspicious users, hosts, processes, IP addresses, or patterns become visible.
