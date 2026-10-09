# Regular Expressions (Regex) Cheat Sheet

A practical Regex reference for log analysis, SIEM searches, field extraction, and security investigations.

> Regex syntax can vary slightly between engines and tools. This cheat sheet focuses on the core syntax and patterns covered during my practice.

---

# Quick Reference

## Character Sets

| Pattern | Meaning |
|---|---|
| `[abc]` | `a`, `b`, or `c` |
| `[a-z]` | Lowercase letter |
| `[A-Z]` | Uppercase letter |
| `[0-9]` | Digit |
| `[a-zA-Z]` | Any letter |
| `[^abc]` | Any character except `a`, `b`, or `c` |

## Metacharacters

| Pattern | Meaning |
|---|---|
| `.` | Any character except line break |
| `\d` | Digit |
| `\D` | Non-digit |
| `\w` | Word character: letter, digit, `_` |
| `\W` | Non-word character |
| `\s` | Whitespace |
| `\S` | Non-whitespace |

## Quantifiers

| Pattern | Meaning |
|---|---|
| `?` | 0 or 1 |
| `*` | 0 or more |
| `+` | 1 or more |
| `{3}` | Exactly 3 |
| `{1,5}` | Between 1 and 5 |
| `{2,}` | 2 or more |

## Anchors & Groups

| Pattern | Meaning |
|---|---|
| `^` | Start of line |
| `$` | End of line |
| `(...)` | Group / capture group |
| `a\|b` | `a` OR `b` |

## Escaping

| Pattern | Matches |
|---|---|
| `\.` | Literal `.` |
| `\$` | Literal `$` |
| `\?` | Literal `?` |
| `\+` | Literal `+` |
| `\*` | Literal `*` |

---

# Quick Practical Patterns

## IPv4-Like Address

```regex
(\d{1,3}\.){3}\d{1,3}
```

## Email with Username and Domain Capture Groups

```regex
(\w+)@(\w+)\.com
```

## File Ending in `.exe`

```regex
.*\.exe$
```

## Optional Leading Dot + Filename

```regex
^\.?\w+$
```

## Exactly 9 Characters, Not Ending in `!`

```regex
^.{8}[^!]$
```

## Two Non-Whitespace Strings Separated by Whitespace

```regex
\S*\s\S*
```

## One or More Digits

```regex
\d+
```

## One or More Word Characters

```regex
\w+
```

---

# Detailed Reference

Everything below explains the syntax from the quick reference in more detail.

---

# 1. Character Sets `[ ]`

Character sets match **one character** from the specified set.

```regex
[abc]
```

Matches:

```text
a
b
c
```

Example:

```regex
[abc]zz
```

Matches:

```text
azz
bzz
czz
```

---

# 2. Character Ranges

Use `-` inside a character set to define a range.

```regex
[a-c]
```

Equivalent to:

```regex
[abc]
```

Multiple ranges can be combined:

```regex
[a-cx-z]
```

### Any Letter

```regex
[a-zA-Z]
```

### Number Range

```regex
file[1-3]
```

Matches:

```text
file1
file2
file3
```

---

# 3. Negated Character Sets

Use `^` inside `[ ]` to exclude characters.

```regex
[^k]ing
```

Matches:

```text
ring
sing
$ing
```

Does not match:

```text
king
```

Another example:

```regex
[^a-c]at
```

Matches characters other than `a`, `b`, or `c` in the first position.

---

# 4. Wildcard `.`

The dot matches any single character except a line break.

```regex
a.c
```

Can match:

```text
aac
abc
a0c
a!c
```

To match a literal dot, escape it:

```regex
a\.c
```

This matches:

```text
a.c
```

---

# 5. Optional Character `?`

`?` means:

```text
0 or 1 occurrence
```

Example:

```regex
abc?
```

Matches:

```text
ab
abc
```

---

# 6. Metacharacters

## `\d` — Digit

```regex
\d
```

Matches:

```text
0-9
```

Example:

```regex
\d{4}
```

Matches exactly four digits.

---

## `\D` — Non-Digit

```regex
\D
```

Matches any character that is not a digit.

---

## `\w` — Word Character

```regex
\w
```

Includes:

```text
letters
digits
_
```

For example:

```regex
\w+
```

can match:

```text
administrator
user123
test_file
```

> `_` is included in `\w`.

---

## `\W` — Non-Word Character

```regex
\W
```

Examples include:

```text
!
@
#
space
```

---

## `\s` — Whitespace

```regex
\s
```

Matches whitespace such as spaces, tabs, and line breaks.

---

## `\S` — Non-Whitespace

```regex
\S
```

Matches anything that is not whitespace.

For example:

```regex
\S+
```

can match:

```text
administrator
10.10.10.5
P@ssw0rd!
```

---

# 7. Repetition / Quantifiers

## Exactly N Times

```regex
z{2}
```

Matches:

```text
zz
```

Another example:

```regex
\d{4}
```

matches exactly four digits.

---

## Range

```regex
[abc]{1,3}
```

Matches between one and three characters from the set.

Examples:

```text
a
ab
cba
```

---

## Minimum Number

```regex
\d{2,}
```

Matches two or more consecutive digits.

---

## Zero or More `*`

```regex
a*
```

Matches zero or more `a` characters.

---

## One or More `+`

```regex
\w+
```

Matches one or more word characters.

The important difference:

```text
* → zero or more
+ → one or more
```

---

# 8. Anchors

## Start of Line `^`

```regex
^abc
```

Matches lines beginning with `abc`.

---

## End of Line `$`

```regex
xyz$
```

Matches lines ending with `xyz`.

---

## Match an Entire Line

```regex
^admin$
```

Matches:

```text
admin
```

but not:

```text
administrator
admin123
domain\admin
```

### Important

Outside a character set:

```regex
^abc
```

means:

> starts with `abc`

Inside a character set:

```regex
[^abc]
```

means:

> any character except `a`, `b`, or `c`

---

# 9. Groups `( )`

Parentheses group patterns together.

```regex
(no){5}
```

Matches:

```text
nonononono
```

Groups can also capture parts of matched data.

For example:

```regex
(\w+)@(\w+)\.com
```

For:

```text
hello@tryhackme.com
```

the groups are:

```text
Group 1 → hello
Group 2 → tryhackme
```

This is especially useful for field extraction.

---

# 10. OR / Alternation `|`

The pipe means **OR**.

```regex
(day|night)
```

Matches either:

```text
day
night
```

Example:

```regex
during the (day|night)
```

matches:

```text
during the day
during the night
```

---

# 11. Practical Patterns

## Limited Character Sets

```regex
[abc]{1,3}[01]{4}
```

Matches:

```text
ab0001
bb0000
abc1000
cba0110
c0000
```

Breakdown:

```text
[abc]    → a, b, or c
{1,3}    → 1–3 times
[01]     → 0 or 1
{4}      → exactly 4 times
```

---

## Two Non-Whitespace Strings

```regex
\S*\s\S*
```

Example:

```text
2f0h@f0j0%! a)K!F49h!FFOK
```

Breakdown:

```text
\S* → zero or more non-whitespace characters
\s  → whitespace
\S* → zero or more non-whitespace characters
```

---

## Exactly 9 Characters, Not Ending in `!`

```regex
^.{8}[^!]$
```

Breakdown:

```text
^       → start
.{8}    → exactly 8 characters
[^!]    → any character except !
$       → end
```

---

## Filename with Optional Leading Dot

```regex
^\.?\w+$
```

Matches:

```text
.bash_rc
.unnecessarily_long_filename
note1
```

Breakdown:

```text
^      → start
\.     → literal .
?      → optional
\w+    → one or more word characters
$      → end
```

---

## Literal `$` at the End

To match:

```text
EOF$
```

at the end of a line:

```regex
EOF\$$
```

Breakdown:

```text
EOF → literal text
\$  → literal $
$   → end-of-line anchor
```

---

# 12. IPv4-Like Address

```regex
(\d{1,3}\.){3}\d{1,3}
```

Matches the general structure:

```text
192.168.1.10
10.10.10.10
172.16.0.1
```

Breakdown:

```text
\d{1,3}     → 1–3 digits
\.          → literal .
(...)       → group
{3}         → repeat group 3 times
\d{1,3}     → final number
```

Think of it as:

```text
(number.) × 3 + number
```

> This checks the general IPv4 format. It does not validate whether each octet is within `0–255`.

---

# 13. Email Capture Groups

```regex
(\w+)@(\w+)\.com
```

Examples:

```text
hello@tryhackme.com
username@domain.com
dummy_email@xyz.com
```

For:

```text
hello@tryhackme.com
```

we get:

```text
Group 1 → hello
Group 2 → tryhackme
```

Breakdown:

```text
(\w+) → username
@     → literal @
(\w+) → domain
\.    → literal .
com   → TLD
```

---

# 14. Password Pattern Example

Match `Password:` followed by exactly ten characters that are not `0`:

```regex
Password:[^0]{10}
```

Breakdown:

```text
Password: → literal text
[^0]      → any character except 0
{10}      → exactly 10 times
```

---

# 15. Security / SOC Examples

## Executables

```regex
.*\.exe$
```

Can match:

```text
powershell.exe
cmd.exe
rundll32.exe
mimikatz.exe
```

---

## Numeric Event IDs

```regex
\d+
```

Can match:

```text
4624
4625
4688
4104
```

---

## Non-Whitespace Value

```regex
\S+
```

Useful when a value continues until the next whitespace character.

---

## Simple `key=value` Data

```regex
(\w+)=(\w+)
```

Example:

```text
User=administrator
```

Produces:

```text
Group 1 → User
Group 2 → administrator
```

Real-world log values can require more flexible patterns, but this demonstrates the basic idea.

---
