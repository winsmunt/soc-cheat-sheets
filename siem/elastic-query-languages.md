# Elastic Query Languages Cheat Sheet

A practical reference for searching and investigating security data in **Elastic / Kibana**.

This cheat sheet covers common **KQL (Kibana Query Language)** and **Lucene** search techniques used during SOC investigations, including field searches, Boolean logic, wildcards, regular expressions, ranges, fuzzy searches, and proximity searches.

> **Note:** Some features, such as regular expressions, fuzzy searches, and proximity searches, are specific to Lucene.

---

# Quick Reference

| Goal | Syntax | Example |
|---|---|---|
| Search a field | `field:value` | `event.category:authentication` |
| Search exact text | `field:"exact value"` | `user.name:"John Smith"` |
| AND condition | `condition1 AND condition2` | `event.category:authentication AND event.outcome:failure` |
| OR condition | `condition1 OR condition2` | `event.action:login OR event.action:logon` |
| Exclude a value | `NOT field:value` | `NOT event.outcome:success` |
| Group conditions | `(condition1 OR condition2) AND condition3` | `(event.action:login OR event.action:logon) AND event.outcome:failure` |
| Multi-character wildcard | `field:prefix*` | `file.name:marketing_strategy*` |
| Single-character wildcard | `field:te?t` | `host.name:server-?` |
| Regex search - Lucene | `field:/regex/` | `file.name:/.*project.*/` |
| Regex prefix | `field:/prefix.*/` | `file.name:/client_list.*/` |
| Numeric comparison | `field:>=value` | `severity.level:>=9` |
| Numeric range | `field:[min TO max]` | `response.time:[100 TO 400]` |
| Date comparison | `@timestamp:>=date` | `@timestamp:>=2023-01-01` |
| Fuzzy search - Lucene | `field:term~N` | `host.name:server01~1` |
| Proximity search - Lucene | `field:"word1 word2"~N` | `log.message:"server error"~4` |

---

# 1. Basic Field Searches

The basic structure of an Elastic query is:

```text
field:value
```

Example:

```text
event.category:authentication
```

This searches for documents where the specified field contains the requested value.

For values containing spaces, use quotation marks:

```text
user.name:"John Smith"
```

Another example:

```text
log.message:"Authentication failed"
```

Quotation marks are useful when searching for an exact phrase or a value containing spaces.

---

# 2. Boolean Operators

Boolean operators allow multiple search conditions to be combined.

The main operators are:

```text
AND
OR
NOT
```

## AND

Both conditions must match.

```text
event.category:authentication AND event.outcome:failure
```

This can be useful when investigating failed authentication events.

Another example:

```text
affected_systems.system_type:"Web Server" AND incident_comments:"true positive"
```

---

## OR

At least one of the conditions must match.

```text
event.action:login OR event.action:logon
```

Multiple possible values can also be grouped:

```text
(event.action:login OR event.action:logon) AND event.outcome:failure
```

Parentheses make the logic of more complex queries easier to control.

---

## NOT

`NOT` excludes matching events.

```text
NOT event.outcome:success
```

It can also be combined with another condition:

```text
event.category:authentication AND NOT event.outcome:success
```

---

# 3. Wildcard Searches

Wildcards are useful when the complete value is unknown or when multiple values share the same pattern.

## Multi-character wildcard

The `*` wildcard represents zero or more characters.

```text
file.name:marketing_strategy*
```

This can match values such as:

```text
marketing_strategy.pdf
marketing_strategy_2023.docx
marketing_strategy_final.txt
```

Another useful example:

```text
file.name:client_list*
```

This is useful when filenames contain timestamps, versions, or other changing suffixes.

---

## Single-character wildcard

The `?` wildcard represents one character.

```text
host.name:server-?
```

Possible matches could include:

```text
server-1
server-2
server-A
```

---

# 4. Regular Expression Searches

> Regular expression searches are available when using **Lucene**.

The basic syntax is:

```text
field:/regex/
```

For example:

```text
affected_systems.affected_files.file_name:/.*project.*/
```

This searches for filenames containing the word:

```text
project
```

The expression:

```text
.*
```

means:

- `.` - any character
- `*` - zero or more repetitions

Therefore:

```text
.*project.*
```

means:

```text
anything + project + anything
```

---

## Prefix Search with Regex

```text
affected_systems.affected_files.file_name:/client_list.*/
```

This searches for values beginning with:

```text
client_list
```

Possible matches:

```text
client_list.csv
client_list_2023.csv
client_list_backup.txt
```

---

## Combining Regex with Other Conditions

Regex searches can be combined with Boolean operators.

```text
affected_systems.affected_files.file_name:/.*project.*/ AND team_members.name:"EVenis"
```

This searches for incidents:

1. involving a filename containing `project`
2. handled by `EVenis`

This type of query is useful when narrowing an investigation to both a specific artifact and an analyst/user.

---

# 5. Range Searches

Ranges are useful when investigating numerical values such as severity, response times, ports, or timestamps.

## Numeric Comparisons

Example:

```text
severity.level:>=9
```

This returns events with severity level 9 or higher.

Other comparison operators include:

```text
>
>=
<
<=
```

Examples:

```text
severity.level:>5
```

```text
severity.level:<=3
```

---

## Numeric Ranges

A bounded range can be written as:

```text
field:[minimum TO maximum]
```

Example:

```text
response.time:[100 TO 400]
```

This searches for values between `100` and `400`.

---

# 6. Date and Time Searches

Time-based filtering is especially useful during incident investigations.

Example:

```text
@timestamp:>=2023-01-01
```

A range can also be created using multiple conditions:

```text
@timestamp:>=2023-01-01 AND @timestamp:<2023-03-01
```

This limits the investigation to events occurring within the specified time period.

Time filters are useful when:

- investigating activity around an alert
- building an incident timeline
- narrowing large datasets
- correlating events from multiple sources

---

# 7. Fuzzy Searching

> Fuzzy searching is a **Lucene** feature.

Fuzzy searches help find terms that are similar but not identical.

Syntax:

```text
field:term~N
```

Where `N` represents the allowed **edit distance**.

Example:

```text
host.name:server01~1
```

The query allows values that differ from `server01` by approximately one character edit.

Character edits may include:

- insertion
- deletion
- substitution
- transposition

This can be useful when searching for:

- misspelled usernames
- hostname variations
- inconsistent log values
- slightly modified strings

---

## Security Investigation Example

```text
team_members.name:"JLim" AND incident_comments:true~1
```

The first condition limits the results to incidents handled by `JLim`.

The second performs a fuzzy search for values similar to:

```text
true
```

with an allowed edit distance of `1`.

---

# 8. Proximity Searching

> Proximity searching is available in **Lucene**.

A proximity search looks for words that appear within a specified distance from each other.

Syntax:

```text
field:"word1 word2"~N
```

Example:

```text
log.message:"server error"~4
```

This searches for documents where `server` and `error` occur close to each other.

The words do not necessarily have to appear directly next to one another.

This can help when log messages contain additional words between important terms.

For example, it may help identify variations of messages similar to:

```text
Server error
Server detected error
Server failed with an error
```

---

# 9. Fuzzy Search vs Proximity Search

Although both use the `~` symbol in Lucene, they perform different operations.

| Search Type | Syntax | Purpose |
|---|---|---|
| Fuzzy | `term~1` | Finds similar words |
| Proximity | `"word1 word2"~4` | Finds words near each other |

### Fuzzy

```text
host.name:server01~1
```

Think:

> "Find values similar to this word."

### Proximity

```text
log.message:"server error"~4
```

Think:

> "Find these words within this distance."

This distinction is important when investigating inconsistent or unstructured log data.

---

# 10. Combining Multiple Conditions

Real investigations usually require several filters rather than one simple search.

Example:

```text
affected_systems.system_type:"Web Server" AND incident_comments:"true positive"
```

Another example:

```text
affected_systems.affected_files.file_name:/.*project.*/ AND team_members.name:"EVenis"
```

Queries can also combine grouping:

```text
(event.action:login OR event.action:logon) AND event.outcome:failure
```

A useful workflow is to begin with a broad search and progressively add conditions:

```text
event.category:authentication
```

Then:

```text
event.category:authentication AND event.outcome:failure
```

Then:

```text
event.category:authentication AND event.outcome:failure AND user.name:"administrator"
```

This progressively reduces the dataset until only relevant events remain.

---

# 11. Useful SOC Investigation Patterns

## Find failed authentication events

```text
event.category:authentication AND event.outcome:failure
```

## Search for files with a known prefix

```text
file.name:client_list*
```

## Search for filenames containing a keyword

Lucene:

```text
file.name:/.*project.*/
```

## Search high-severity events

```text
severity.level:>=9
```

## Search activity related to a specific analyst or user

```text
team_members.name:"JLim"
```

## Search for slightly different terms

Lucene:

```text
incident_comments:true~1
```

## Search for related words appearing close together

Lucene:

```text
log.message:"server error"~4
```

---

# Key Takeaways

- Use `field:value` for basic field searches.
- Use quotation marks for exact phrases and values containing spaces.
- Combine conditions with `AND`, `OR`, and `NOT`.
- Use parentheses to control complex Boolean logic.
- Use `*` when only part of a value is known.
- Use Lucene regex `/.../` for more flexible pattern matching.
- Use comparison operators and ranges to investigate numeric and time-based data.
- Use fuzzy searches (`term~N`) to find similar values.
- Use proximity searches (`"word1 word2"~N`) to find related words near each other.
- Start investigations with broad queries and progressively narrow the results.

---

## Reference

Created as part of hands-on practice with **Elastic / Kibana query languages** for SOC analysis and security-event investigation.
