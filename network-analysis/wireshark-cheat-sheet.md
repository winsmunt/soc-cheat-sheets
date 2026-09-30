# Wireshark Cheat Sheet

A practical Wireshark reference for packet analysis, network investigations, and SOC work.

---

## Capture Filters vs Display Filters

Wireshark uses two main types of filters.

### Capture Filters

Capture filters define which packets are collected.

They are configured **before or during packet capture** and cannot be changed for packets that were not captured.

Example:

```text
tcp port 80
```

Capture filter syntax can use:

| Type | Values |
| --- | --- |
| Scope | `host`, `net`, `port`, `portrange` |
| Direction | `src`, `dst`, `src or dst`, `src and dst` |
| Protocol | `ether`, `wlan`, `ip`, `ip6`, `arp`, `rarp`, `tcp`, `udp` |

Examples:

```text
host 10.10.10.10
```

```text
src host 10.10.10.10
```

```text
dst host 10.10.10.10
```

```text
tcp port 80
```

```text
udp port 53
```

> Capture filters and display filters use different syntax.

### Display Filters

Display filters reduce the packets visible during analysis without removing them from the capture.

Example:

```text
ip.addr == 10.10.10.10
```

---

# Basic Display Filters

## Protocol Filters

Show all packets for a specific protocol.

```text
tcp
```

```text
udp
```

```text
arp
```

```text
icmp
```

```text
dns
```

```text
http
```

```text
ftp
```

```text
dhcp
```

```text
nbns
```

```text
kerberos
```

```text
tls
```

---

# IP Address Filtering

## Any Direction

Show packets where the IP appears as either source or destination:

```text
ip.addr == 10.10.10.111
```

## Source IP

```text
ip.src == 10.10.10.111
```

## Destination IP

```text
ip.dst == 10.10.10.111
```

## Subnet

```text
ip.addr == 10.10.10.0/24
```

### Important

`ip.addr` does not care about direction.

Use:

```text
ip.src
```

or:

```text
ip.dst
```

when direction matters.

---

# TCP and UDP Filtering

## TCP Port

```text
tcp.port == 80
```

Matches TCP packets where port `80` is either source or destination.

## TCP Source Port

```text
tcp.srcport == 1234
```

## TCP Destination Port

```text
tcp.dstport == 80
```

## UDP Port

```text
udp.port == 53
```

## UDP Source Port

```text
udp.srcport == 1234
```

## UDP Destination Port

```text
udp.dstport == 5353
```

---

# Comparison Operators

| Operator | Meaning |
| --- | --- |
| `==` / `eq` | Equal |
| `!=` / `ne` | Not equal |
| `>` / `gt` | Greater than |
| `<` / `lt` | Less than |
| `>=` / `ge` | Greater than or equal |
| `<=` / `le` | Less than or equal |

Example:

```text
ip.ttl > 250
```

---

# Logical Operators

## AND

Both conditions must be true.

```text
ip.src == 10.10.10.100 and ip.dst == 10.10.10.111
```

C-like syntax:

```text
ip.src == 10.10.10.100 && ip.dst == 10.10.10.111
```

## OR

At least one condition must be true.

```text
ip.src == 10.10.10.100 or ip.src == 10.10.10.111
```

C-like syntax:

```text
ip.src == 10.10.10.100 || ip.src == 10.10.10.111
```

## NOT

Exclude matching traffic.

```text
not ip.src == 10.10.10.222
```

---

# Advanced Filtering

## contains

Search inside a field.

```text
http.server contains "Apache"
```

Useful when you know only part of a value.

---

## matches

Search using a regular expression.

```text
http.host matches "\.(php|html)"
```

Useful for pattern-based searches.

---

## in

Check whether a value belongs to a set or range.

```text
tcp.port in {80 443 8080}
```

---

## upper()

Convert a string to uppercase before comparison.

```text
upper(http.server) contains "APACHE"
```

---

## lower()

Convert a string to lowercase before comparison.

```text
lower(http.server) contains "apache"
```

---

## string()

Convert a non-string field to a string.

Example:

```text
string(frame.number) matches "^[13579]$"
```

---

# TCP Flags

TCP flags are useful when investigating connections and network scanning.

## SYN

```text
tcp.flags.syn == 1
```

Only SYN flag:

```text
tcp.flags == 2
```

## SYN + ACK

```text
tcp.flags.syn == 1 and tcp.flags.ack == 1
```

or:

```text
tcp.flags == 18
```

## ACK

```text
tcp.flags.ack == 1
```

## RST

```text
tcp.flags.reset == 1
```

Only RST:

```text
tcp.flags == 4
```

## RST + ACK

```text
tcp.flags.reset == 1 and tcp.flags.ack == 1
```

## FIN

```text
tcp.flags.fin == 1
```

Only FIN:

```text
tcp.flags == 1
```

---

# Network Scan Investigation

## SYN Scan

Look for SYN packets without ACK:

```text
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

A larger TCP window was used in the training material as one pattern:

```text
tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.window_size > 1024
```

## TCP Connect Scan

The training material also used:

```text
tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.window_size <= 1024
```

> Treat window-size patterns as investigation clues rather than universal rules.

## UDP Scan

ICMP Destination Unreachable / Port Unreachable responses can help identify UDP scanning:

```text
icmp.type == 3 and icmp.code == 3
```

---

# ARP Analysis

Show all ARP traffic:

```text
arp
```

## ARP Requests

```text
arp.opcode == 1
```

## ARP Responses

```text
arp.opcode == 2
```

## Broadcast ARP

```text
arp.dst.hw_mac == 00:00:00:00:00:00
```

## Possible Duplicate Address / ARP Poisoning Indicators

```text
arp.duplicate-address-detected
```

```text
arp.duplicate-address-frame
```

Another useful investigation pattern from the material:

```text
(arp) && (arp.opcode == 1) && (arp.src.hw_mac == target-mac-address)
```

### What to investigate

Look for:

- one IP associated with multiple MAC addresses;
- unusual ARP replies;
- duplicate-address warnings;
- unexpected MAC address changes.

---

# DHCP Analysis

Show DHCP traffic:

```text
dhcp
```

or:

```text
bootp
```

## DHCP Request

```text
dhcp.option.dhcp == 3
```

## DHCP ACK

```text
dhcp.option.dhcp == 5
```

## DHCP NAK

```text
dhcp.option.dhcp == 6
```

## Search Hostname

```text
dhcp.option.hostname contains "keyword"
```

## Search Domain Name

```text
dhcp.option.domain_name contains "keyword"
```

DHCP traffic can help identify:

- hostnames;
- requested IP addresses;
- assigned IP addresses;
- domain information;
- lease information.

---

# NBNS Analysis

Show NetBIOS Name Service traffic:

```text
nbns
```

Search for a hostname:

```text
nbns.name contains "keyword"
```

NBNS can help identify:

- hostnames;
- IP associations;
- queried system names.

---

# Kerberos Analysis

Show Kerberos traffic:

```text
kerberos
```

## Search Username

```text
kerberos.CNameString contains "keyword"
```

Some captures may contain hostname information in the same field, so check the value carefully.

## Protocol Version

```text
kerberos.pvno == 5
```

## Realm

```text
kerberos.realm contains ".org"
```

## Service Name

```text
kerberos.SNameString == "krbtg"
```

Kerberos traffic can reveal useful information such as:

- usernames;
- realms/domains;
- requested services;
- authentication activity.

---

# ICMP Analysis

Show ICMP traffic:

```text
icmp
```

## Large ICMP Payloads

```text
data.len > 64 and icmp
```

Large or unusual ICMP payloads can be worth investigating for possible tunneling or data transfer.

---

# DNS Analysis

Show DNS traffic:

```text
dns
```

## DNS Queries

```text
dns.flags.response == 0
```

## DNS Responses

```text
dns.flags.response == 1
```

## A Records

```text
dns.qry.type == 1
```

## Search DNS Packet Contents

```text
dns contains "dnscat"
```

## Long DNS Queries

```text
dns.qry.name.len > 15 and !mdns
```

### Possible DNS tunneling indicators

Look for:

- unusually long DNS queries;
- encoded-looking subdomains;
- high volume of requests;
- repeated queries to the same domain;
- anomalous DNS traffic.

---

# FTP Analysis

Show FTP traffic:

```text
ftp
```

FTP is especially important because credentials may be transmitted in cleartext.

## Successful Login

```text
ftp.response.code == 230
```

## Username Commands

```text
ftp.request.command == "USER"
```

## Password Commands

```text
ftp.request.command == "PASS"
```

## Search Password Argument

```text
ftp.request.arg == "password"
```

## Failed Login

```text
ftp.response.code == 530
```

## Possible Brute Force

```text
ftp.response.code == 530
```

Repeated `530` responses can indicate repeated failed authentication attempts.

Search for failed attempts containing username information:

```text
ftp.response.code == 530 and ftp.response.arg contains "username"
```

### Useful FTP response codes

| Code | Meaning |
| --- | --- |
| `211` | System status |
| `212` | Directory status |
| `213` | File status |
| `220` | Service ready |
| `227` | Entering passive mode |
| `228` | Long passive mode |
| `229` | Extended passive mode |
| `230` | User login successful |
| `231` | User logout |
| `331` | Valid username |
| `430` | Invalid username or password |
| `530` | Not logged in / invalid password |

---

# HTTP Analysis

Show HTTP traffic:

```text
http
```

HTTP/2:

```text
http2
```

## All HTTP Requests

```text
http.request
```

## GET Requests

```text
http.request.method == "GET"
```

## POST Requests

```text
http.request.method == "POST"
```

---

# HTTP Response Codes

## Successful

```text
http.response.code == 200
```

## Unauthorized

```text
http.response.code == 401
```

## Forbidden

```text
http.response.code == 403
```

## Not Found

```text
http.response.code == 404
```

## Method Not Allowed

```text
http.response.code == 405
```

## Service Unavailable

```text
http.response.code == 503
```

Useful codes:

| Code | Meaning |
| --- | --- |
| `200` | OK |
| `301` | Moved Permanently |
| `302` | Temporary Redirect |
| `400` | Bad Request |
| `401` | Unauthorized |
| `403` | Forbidden |
| `404` | Not Found |
| `405` | Method Not Allowed |
| `408` | Request Timeout |
| `500` | Internal Server Error |
| `503` | Service Unavailable |

---

# HTTP Investigation Fields

## User Agent

```text
http.user_agent
```

Search user agent:

```text
http.user_agent contains "nmap"
```

## URL

```text
http.request.uri contains "admin"
```

## Full URL

```text
http.request.full_uri contains "admin"
```

## Server

```text
http.server contains "Apache"
```

## Host

```text
http.host contains "keyword"
```

or:

```text
http.host == "keyword"
```

## Connection

```text
http.connection == "Keep-Alive"
```

## Search Packet Data

```text
data-text-lines contains "keyword"
```

---

# User-Agent Investigation

User agents can provide clues about the software generating HTTP requests.

Look for:

- different user agents from the same host in a short period;
- unusual tools;
- command-line utilities;
- scanners;
- unexpected browser versions;
- suspicious or uncommon software.

Example:

```text
http.user_agent contains "Nmap"
```

Multiple possibilities can be combined:

```text
http.user_agent contains "Nmap" or
http.user_agent contains "Wget" or
http.user_agent contains "Nikto"
```

---

# Log4j Investigation

The training material included filters for investigating possible Log4j exploitation attempts.

Start with POST requests:

```text
http.request.method == "POST"
```

Search IP-related content:

```text
ip contains "jndi"
```

Search frame contents:

```text
frame contains "jndi"
```

Search for exploit-related strings:

```text
frame contains "Exploit"
```

User-agent search:

```text
http.user_agent contains "$"
```

or:

```text
http.user_agent contains "=="
```

> These are hunting filters for suspicious strings and should be interpreted together with packet context.

---

# TLS / HTTPS Analysis

Show TLS traffic:

```text
tls
```

## TLS Client Hello

```text
tls.handshake.type == 1
```

## TLS Server Hello

```text
tls.handshake.type == 2
```

A combined filter from the training material:

```text
(http.request or tls.handshake.type == 1) and !(ssdp)
```

Server-side variant:

```text
(http.request or tls.handshake.type == 2) and !(ssdp)
```

TLS traffic is encrypted, so payload analysis is limited unless the traffic can be decrypted.

---

# Useful Wireshark Investigation Workflow

When opening an unknown PCAP, avoid immediately searching random packets.

## 1. Understand the Capture

Start by checking:

```text
Statistics → Protocol Hierarchy
```

Identify which protocols are present.

Then check:

```text
Statistics → Endpoints
```

Identify active hosts.

Then:

```text
Statistics → Conversations
```

Identify which hosts communicate with each other.

---

## 2. Identify Interesting Hosts

Pivot on suspicious IP addresses:

```text
ip.addr == suspicious_ip
```

Then determine direction:

```text
ip.src == suspicious_ip
```

```text
ip.dst == suspicious_ip
```

---

## 3. Identify the Protocol

Check whether the activity involves:

```text
dns
http
ftp
arp
icmp
kerberos
```

or another protocol.

---

## 4. Narrow the Traffic

Combine filters:

```text
ip.addr == suspicious_ip and dns
```

```text
ip.addr == suspicious_ip and http
```

```text
ip.addr == suspicious_ip and tcp.port == 80
```

---

## 5. Investigate Related Artifacts

Depending on the protocol, look for:

- IP addresses;
- domains;
- hostnames;
- ports;
- URLs;
- URIs;
- user agents;
- usernames;
- credentials;
- requested files;
- unusual payloads.

---

## 6. Follow the Conversation

For TCP traffic:

```text
Right Click Packet
→ Follow
→ TCP Stream
```

This reconstructs communication belonging to the TCP stream and can make application activity easier to understand.

---

## 7. Build the Timeline

Do not investigate packets individually only.

Try to determine:

```text
What happened first?
        ↓
Which host initiated communication?
        ↓
What protocol was used?
        ↓
What resource was requested?
        ↓
What happened next?
```

This turns packet filtering into an investigation.

---

# SOC Quick Reference

| Goal | Filter |
| --- | --- |
| Find IP | `ip.addr == 10.10.10.10` |
| Source IP | `ip.src == 10.10.10.10` |
| Destination IP | `ip.dst == 10.10.10.10` |
| TCP port | `tcp.port == 80` |
| UDP port | `udp.port == 53` |
| DNS traffic | `dns` |
| DNS queries | `dns.flags.response == 0` |
| Long DNS names | `dns.qry.name.len > 15 and !mdns` |
| HTTP traffic | `http` |
| HTTP GET | `http.request.method == "GET"` |
| HTTP POST | `http.request.method == "POST"` |
| HTTP 200 | `http.response.code == 200` |
| HTTP 404 | `http.response.code == 404` |
| Search URL | `http.request.uri contains "keyword"` |
| Search user agent | `http.user_agent contains "keyword"` |
| FTP | `ftp` |
| FTP username | `ftp.request.command == "USER"` |
| FTP password | `ftp.request.command == "PASS"` |
| Failed FTP login | `ftp.response.code == 530` |
| ARP | `arp` |
| ARP request | `arp.opcode == 1` |
| ARP response | `arp.opcode == 2` |
| DHCP | `dhcp` |
| DHCP hostname | `dhcp.option.hostname contains "keyword"` |
| NBNS | `nbns` |
| Kerberos | `kerberos` |
| ICMP | `icmp` |
| Large ICMP payload | `data.len > 64 and icmp` |
| SYN packets | `tcp.flags.syn == 1` |
| SYN without ACK | `tcp.flags.syn == 1 and tcp.flags.ack == 0` |
| RST | `tcp.flags.reset == 1` |
| TLS | `tls` |
| TLS Client Hello | `tls.handshake.type == 1` |
| TLS Server Hello | `tls.handshake.type == 2` |

---

# Investigation Mindset

A Wireshark investigation should usually follow this pattern:

```text
Host
  ↓
IP
  ↓
Protocol
  ↓
Connection
  ↓
Request / Response
  ↓
Artifact
  ↓
Related Activity
  ↓
Timeline
  ↓
Conclusion
```

The goal is not just to find a packet.

The goal is to understand **what happened on the network and why the traffic is important**.
