# Snort Cheat Sheet

Quick reference for using Snort as an IDS/IPS, analysing PCAP files, and creating detection rules.

---

## 1. What is Snort?

Snort is a network intrusion detection and prevention system (IDS/IPS).

It can be used to:

- Monitor live network traffic
- Detect suspicious network activity
- Generate alerts based on detection rules
- Analyse captured traffic from PCAP files
- Inspect packet headers and payloads
- Create custom detection rules

---

# 2. Important Locations

Common Snort directories:

```bash
/etc/snort/
```

Configuration file:

```bash
/etc/snort/snort.lua
```

Rules directory:

```bash
/etc/snort/rules/
```

Custom rules:

```bash
/etc/snort/rules/local.rules
```

Default log directory:

```bash
/var/log/snort/
```

---

# 3. Basic Commands

## Check Snort Version

```bash
snort -V
```

or:

```bash
snort --version
```

---

## Test Configuration

Always useful after changing configuration or rules.

```bash
sudo snort -T -c /etc/snort/snort.lua
```

`-T` tests the configuration without starting normal monitoring.

---

## Start Snort

```bash
sudo snort -c /etc/snort/snort.lua
```

---

## Quiet Mode

```bash
sudo snort -q
```

Prevents Snort from displaying the startup banner and other default information.

---

# 4. Packet Inspection

Snort can display captured packet information directly in the terminal.

## Verbose Output

```bash
sudo snort -v
```

Displays TCP/IP packet information.

---

## Display Packet Payload

```bash
sudo snort -d
```

Displays packet payload data.

---

## Display Link-Layer Headers

```bash
sudo snort -e
```

Displays link-layer information.

---

## Display Packet Data in HEX

```bash
sudo snort -X
```

Displays packet data in hexadecimal format.

---

## Combine Parameters

Parameters can be combined.

```bash
sudo snort -vde
```

This provides more detailed packet information.

---

# 5. Selecting a Network Interface

Use:

```bash
sudo snort -i eth0
```

Example:

```bash
sudo snort -v -i eth0
```

This tells Snort which interface to monitor.

Check available interfaces with:

```bash
ip addr
```

or:

```bash
ip link
```

---

# 6. Logging Packets

Snort can save captured packets for later investigation.

## Log Traffic

```bash
sudo snort -l /var/log/snort
```

`-l` specifies the logging directory.

---

## ASCII Logging

```bash
sudo snort -K ASCII -l /var/log/snort
```

Stores packet logs in a human-readable format.

---

## Read Logged Traffic

```bash
sudo snort -r /var/log/snort/<log_file>
```

---

# 7. Analyse PCAP Files

One of the most useful features for SOC investigations.

## Read a PCAP

```bash
sudo snort -r capture.pcap
```

---

## Analyse PCAP with Rules

```bash
sudo snort -q -r capture.pcap -c /etc/snort/snort.lua
```

---

## Generate Fast Alerts

```bash
sudo snort -q -r capture.pcap -A alert_fast -c /etc/snort/snort.lua
```

This is useful when investigating recorded traffic and looking for rule matches.

---

## Multiple PCAP Files

Snort can also process multiple PCAP files.

Useful options include:

```text
--pcap-single
--pcap-list
--pcap-show
```

---

# 8. Berkeley Packet Filters (BPF)

BPF filters allow you to limit which packets Snort processes.

## ICMP Only

```bash
sudo snort -r capture.pcap icmp
```

## TCP Only

```bash
sudo snort -r capture.pcap tcp
```

## UDP Only

```bash
sudo snort -r capture.pcap udp
```

## Specific Port

```bash
sudo snort -r capture.pcap 'tcp and port 80'
```

## Specific Host

```bash
sudo snort -r capture.pcap 'host 192.168.1.10'
```

This is useful when a large PCAP contains lots of unrelated traffic.

---

# 9. Snort Rule Structure

Basic rule structure:

```text
ACTION PROTOCOL SOURCE_IP SOURCE_PORT DIRECTION DEST_IP DEST_PORT (OPTIONS)
```

Example:

```snort
alert icmp any any -> any any (msg:"ICMP Packet Detected"; sid:1000001; rev:1;)
```

Breaking it down:

```text
alert       → action
icmp        → protocol
any         → source IP
any         → source port
->          → direction
any         → destination IP
any         → destination port
(...)       → rule options
```

---

# 10. Rule Actions

Common actions:

```text
alert
drop
reject
```

### alert

Generates an alert when the rule matches.

```snort
alert tcp any any -> any 80 (...)
```

### drop

Drops matching traffic when Snort is operating inline as an IPS.

### reject

Blocks the traffic and sends a rejection response.

---

# 11. Protocols

Common protocols used in Snort rules:

```text
tcp
udp
icmp
ip
```

Example:

```snort
alert tcp any any -> any 80 (...)
```

---

# 12. Direction Operators

Traffic from source to destination:

```text
->
```

Bidirectional traffic:

```text
<>
```

Example:

```snort
alert tcp any any -> 192.168.1.10 80 (...)
```

means:

```text
ANY SOURCE → 192.168.1.10:80
```

---

# 13. IP Filtering

## Specific IP

```snort
alert icmp 192.168.1.56 any -> any any (...)
```

---

## Network Range

```snort
alert icmp 192.168.1.0/24 any -> any any (...)
```

---

## Multiple Networks

```snort
alert icmp [192.168.1.0/24,10.1.1.0/24] any -> any any (...)
```

---

## Exclude an IP or Network

Use `!`.

```snort
alert icmp !192.168.1.0/24 any -> any any (...)
```

---

# 14. Port Filtering

## Specific Port

```snort
alert tcp any any -> any 21 (...)
```

Detects traffic to TCP port 21.

---

## Exclude Port

```snort
alert tcp any any -> any !21 (...)
```

---

## Port Range

Ports up to 1024:

```text
:1024
```

Ports 1024 and above:

```text
1024:
```

Specific range:

```text
21:23
```

Example:

```snort
alert tcp any any -> any 21:23 (...)
```

---

# 15. Important Rule Options

## msg

Message displayed when the rule triggers.

```snort
msg:"Suspicious Traffic Detected";
```

Example:

```snort
alert icmp any any -> any any (msg:"ICMP Packet Detected"; sid:1000001; rev:1;)
```

---

## sid

Unique Snort rule identifier.

```snort
sid:1000001;
```

For custom rules, use unique high SID values.

Example:

```snort
sid:1000001;
```

Never reuse the same SID for different local rules.

---

## rev

Rule revision.

```snort
rev:1;
```

Increase the revision when modifying the rule.

Example:

```text
rev:1
rev:2
rev:3
```

---

## reference

Adds external information about the detected threat.

Example:

```snort
reference:cve,2021-12345;
```

Useful when connecting a rule to a CVE or other threat reference.

---

# 16. Payload Detection

## content

Search packet payload for a specific value.

Example:

```snort
alert tcp any any -> any 80 (
    msg:"HTTP GET Request";
    content:"GET";
    sid:1000001;
    rev:1;
)
```

Snort will alert when the specified content is found.

---

## HEX Content

Hexadecimal values can be placed between `| |`.

Example:

```snort
content:"|47 45 54|";
```

`47 45 54` represents:

```text
GET
```

---

## nocase

Makes content matching case-insensitive.

```snort
content:"GET"; nocase;
```

This can match different letter cases.

---

## fast_pattern

Marks a content pattern as the primary pattern Snort should use when searching traffic.

Example:

```snort
content:"GET"; fast_pattern;
```

This can help improve rule matching efficiency.

---

# 17. TCP Flags

Snort can inspect TCP flags.

Common flags:

```text
F = FIN
S = SYN
R = RST
P = PSH
A = ACK
U = URG
```

Example:

```snort
alert tcp any any -> any any (
    msg:"SYN Packet Detected";
    flags:S;
    sid:1000001;
    rev:1;
)
```

This can be useful when detecting unusual TCP behaviour or certain scan patterns.

---

# 18. Packet Size — dsize

`dsize` filters packets based on payload size.

Exact size:

```snort
dsize:100;
```

Greater than:

```snort
dsize:>100;
```

Less than:

```snort
dsize:<100;
```

Range:

```snort
dsize:100<>300;
```

Example:

```snort
alert ip any any -> any any (
    msg:"Large Payload";
    dsize:>1000;
    sid:1000001;
    rev:1;
)
```

---

# 19. sameip

Detects packets where the source and destination IP addresses are the same.

```snort
sameip;
```

Example:

```snort
alert ip any any -> any any (
    msg:"Same Source and Destination IP";
    sameip;
    sid:1000001;
    rev:1;
)
```

---

# 20. Network Variables

Important variables in Snort configuration include:

```text
HOME_NET
EXTERNAL_NET
RULE_PATH
SO_RULE_PATH
PREPROC_RULE_PATH
```

## HOME_NET

Defines the network being protected.

Example:

```text
192.168.1.0/24
```

Rules can then use:

```snort
$HOME_NET
```

---

## EXTERNAL_NET

Defines external networks.

Common logic:

```text
!$HOME_NET
```

Meaning:

```text
everything except the internal network
```

Example:

```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (...)
```

This reads as:

```text
External network → Internal network → TCP/80
```

---

# 21. Creating a Custom Rule

Edit:

```bash
sudo nano /etc/snort/rules/local.rules
```

Example ICMP detection rule:

```snort
alert icmp any any -> any any (
    msg:"ICMP Packet Detected";
    sid:1000001;
    rev:1;
)
```

Save the file and test the configuration:

```bash
sudo snort -T -c /etc/snort/snort.lua
```

Then run Snort:

```bash
sudo snort -q -i eth0 -A alert_fast -c /etc/snort/snort.lua
```

Generate ICMP traffic:

```bash
ping 127.0.0.1
```

If the rule works, Snort should generate an alert.

---

# 22. Example Detection Rules

## ICMP Traffic

```snort
alert icmp any any -> any any (
    msg:"ICMP Traffic Detected";
    sid:1000001;
    rev:1;
)
```

---

## FTP Traffic

```snort
alert tcp any any -> any 21 (
    msg:"FTP Traffic Detected";
    sid:1000002;
    rev:1;
)
```

---

## HTTP GET Request

```snort
alert tcp any any -> any 80 (
    msg:"HTTP GET Request";
    content:"GET";
    sid:1000003;
    rev:1;
)
```

---

## SYN Traffic

```snort
alert tcp any any -> any any (
    msg:"TCP SYN Detected";
    flags:S;
    sid:1000004;
    rev:1;
)
```

---

# 23. SOC Investigation Workflow

When investigating a suspicious PCAP with Snort:

```text
PCAP
  ↓
Run Snort
  ↓
Review alerts
  ↓
Identify SID / rule
  ↓
Identify source IP
  ↓
Identify destination IP + port
  ↓
Inspect suspicious traffic
  ↓
Pivot to Wireshark
  ↓
Confirm whether activity is malicious
```

Example:

```bash
sudo snort -q -r suspicious.pcap -A alert_fast -c /etc/snort/snort.lua
```

Then investigate the interesting conversation in Wireshark.

Snort answers:

> "Which traffic matched a detection rule?"

Wireshark helps answer:

> "What actually happened in that traffic?"

Using both together is much more useful than relying only on the IDS alert.

---

# 24. Quick Investigation Checklist

When a Snort alert fires, check:

1. What rule triggered?
2. What is the SID?
3. What is the source IP?
4. What is the destination IP?
5. What source/destination ports were used?
6. Which protocol was involved?
7. What timestamp did the alert occur at?
8. What payload or behaviour caused the match?
9. Are there multiple related alerts?
10. Does the PCAP confirm the detection?
11. Is the activity expected or suspicious?
12. Is it a true positive or false positive?

---

# 25. Commands I Will Use Most Often

```bash
# Version
snort -V

# Test configuration
sudo snort -T -c /etc/snort/snort.lua

# Monitor interface
sudo snort -i eth0 -c /etc/snort/snort.lua

# Verbose packet inspection
sudo snort -vde

# Read PCAP
sudo snort -r capture.pcap

# Analyse PCAP with detection rules
sudo snort -q -r capture.pcap -A alert_fast -c /etc/snort/snort.lua

# Edit local rules
sudo nano /etc/snort/rules/local.rules

# Read alerts
cat /var/log/snort/alert_fast.txt
```

---

# 26. Rule Template

Copy this when creating a new rule:

```snort
alert <protocol> <source_ip> <source_port> -> <destination_ip> <destination_port> (
    msg:"<description>";
    <detection_options>;
    sid:<unique_sid>;
    rev:1;
)
```

Example:

```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (
    msg:"Suspicious HTTP Traffic";
    content:"malicious";
    nocase;
    sid:1000010;
    rev:1;
)
```

---

# 27. Key Things to Remember

```text
-T              Test configuration
-c              Specify configuration file
-i              Select interface
-r              Read PCAP
-l              Log directory
-v              Verbose packet output
-d              Show payload
-e              Show link-layer headers
-X              Show packet data in HEX
-A alert_fast   Fast alert output
```

Rule structure:

```text
ACTION PROTOCOL SRC_IP SRC_PORT -> DST_IP DST_PORT (OPTIONS)
```

Important options:

```text
msg
sid
rev
reference
content
nocase
fast_pattern
flags
dsize
sameip
```

Most important SOC workflow:

```text
Alert → identify hosts → inspect rule → inspect traffic → correlate → determine TP/FP
```

---

## Final Note

Snort is most useful when treated as a detection tool rather than as the final answer.

An alert tells the analyst that traffic matched a rule. The analyst still needs to investigate the surrounding traffic and determine whether the activity represents a real threat.
