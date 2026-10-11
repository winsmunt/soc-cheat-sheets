# Logstash Cheat Sheet

A practical reference for building Logstash pipelines, collecting logs, parsing and transforming events, and forwarding structured data to destinations such as Elasticsearch.

---

## Quick Reference

### Pipeline Structure

| Section | Purpose | Example |
|---|---|---|
| `input` | Defines where events come from | `file`, `tcp`, `beats`, `http` |
| `filter` | Parses, transforms, or removes data | `grok`, `mutate`, `date`, `json` |
| `output` | Defines where processed events are sent | `elasticsearch`, `file`, `stdout`, `syslog` |

```text
Input → Filter → Output
```

### Common Input Plugins

| Input | Purpose | Key Configuration |
|---|---|---|
| `file` | Read events from a file | `path => "/var/log/auth.log"` |
| `tcp` | Receive events over TCP | `port => 5000` |
| `beats` | Receive events from Beats | `port => 5044` |
| `http` | Receive events over HTTP | `port => 8080` |

### Common Filter Plugins

| Filter | Purpose | Example |
|---|---|---|
| `json` | Parse JSON from a field | `source => "message"` |
| `grok` | Extract structured fields from text | `%{IP:source_ip}` |
| `mutate` | Modify, add, or rename fields | `rename => { "src_ip" => "source_ip" }` |
| `date` | Parse an event timestamp | `match => ["timestamp", "ISO8601"]` |
| `prune` | Keep/remove selected fields | `whitelist_names => [...]` |
| `drop` | Discard matching events | `drop { }` |
| `kv` | Parse key-value data | `field_split => "&"` |

### Common Output Plugins

| Output | Purpose |
|---|---|
| `elasticsearch` | Send events to Elasticsearch |
| `file` | Write events to a local file |
| `stdout` | Print events to the terminal/output |
| `tcp` | Forward events over TCP |
| `logstash` | Send events to another Logstash instance |
| `syslog` | Forward events to a Syslog server |
| `rabbitmq` | Send events to RabbitMQ |

### Useful Grok Patterns

| Pattern | Matches |
|---|---|
| `%{TIMESTAMP_ISO8601:timestamp}` | ISO 8601 timestamp |
| `%{IP:source_ip}` | IP address |
| `%{NUMBER:pid}` | Numeric value / process ID |
| `%{WORD:program}` | Single word |
| `%{NOTSPACE:field}` | Non-whitespace text |
| `%{GREEDYDATA:msg}` | Remaining text |

### Useful Commands

| Task | Command |
|---|---|
| Check Logstash status | `systemctl status logstash` |
| Restart Logstash | `systemctl restart logstash` |
| Follow Logstash logs | `journalctl -u logstash -f` |
| View configuration files | `ls /etc/logstash/conf.d/` |
| Test configuration | `/usr/share/logstash/bin/logstash --path.settings /etc/logstash -t` |

---

# 1. Logstash Pipeline Structure

Logstash processes events through a pipeline consisting of three main stages:

```text
        INPUT
          ↓
        FILTER
          ↓
        OUTPUT
```

A basic configuration looks like this:

```conf
input {
    # Where data comes from
}

filter {
    # How data is processed
}

output {
    # Where data is sent
}
```

The `filter` stage is optional. Events can be sent directly from an input to an output if no transformation is required.

---

# 2. Inputs

Inputs define how Logstash receives data.

Different input plugins allow Logstash to collect events from files, network connections, Beats agents, HTTP requests, and other sources.

## File Input

Use the `file` plugin to read events from a file:

```conf
input {
    file {
        path => "/var/log/auth.log"
        start_position => "beginning"
        sincedb_path => "/dev/null"
    }
}
```

### Important Options

`path` defines the file that Logstash monitors:

```conf
path => "/var/log/auth.log"
```

`start_position` controls where Logstash starts reading a previously unseen file:

```conf
start_position => "beginning"
```

`sincedb_path` controls where Logstash stores its file-reading position.

```conf
sincedb_path => "/dev/null"
```

Using `/dev/null` prevents the reading position from being persistently stored. This can be useful in temporary labs and testing environments where the same file needs to be processed again.

---

## TCP Input

Logstash can listen for events over TCP:

```conf
input {
    tcp {
        port => 5456
    }
}
```

A codec can also be specified:

```conf
input {
    tcp {
        port => 5000
        codec => json
    }
}
```

The codec tells Logstash how incoming data should be interpreted.

Another example using plain text:

```conf
input {
    tcp {
        port => 514
        codec => "plain"
    }
}
```

---

## Beats Input

Logstash can receive events from Beats:

```conf
input {
    beats {
        port => 5044
    }
}
```

This can be used when Beats agents forward collected events to Logstash for additional processing.

---

## HTTP Input

Logstash can also receive events through HTTP:

```conf
input {
    http {
        port => 8080
    }
}
```

---

# 3. Filters

Filters process events after they enter Logstash but before they reach the output.

```text
Raw Event
    ↓
Filter
    ↓
Structured / Modified Event
```

Filters can:

- parse unstructured logs;
- extract fields;
- rename fields;
- add fields;
- remove unnecessary data;
- parse timestamps;
- discard unwanted events.

---

# 4. JSON Filter

The `json` filter parses JSON contained inside a field.

```conf
filter {
    json {
        source => "message"
    }
}
```

Here:

```text
source => "message"
```

means that Logstash attempts to parse JSON stored inside the `message` field.

For example, an incoming message such as:

```json
{"user":"alice","source_ip":"10.10.10.5"}
```

can be converted into separate structured fields such as:

```text
user
source_ip
```

---

# 5. Mutate Filter

The `mutate` filter is used to modify fields inside an event.

## Add a Field

```conf
filter {
    mutate {
        add_field => { "new_field" => "new_value" }
    }
}
```

This adds:

```text
new_field = new_value
```

to the event.

---

## Rename a Field

```conf
filter {
    mutate {
        rename => { "src_ip" => "source_ip" }
    }
}
```

The syntax follows:

```text
"old_field" => "new_field"
```

Result:

```text
src_ip
  ↓
source_ip
```

Renaming fields is useful when normalizing logs from different sources into a consistent schema.

---

# 6. Grok Filter

Grok is used to extract structured fields from unstructured text.

Basic syntax:

```conf
filter {
    grok {
        match => {
            "message" => "%{PATTERN:field_name}"
        }
    }
}
```

The structure is:

```text
%{PATTERN:field_name}
```

where:

- `PATTERN` defines what should be matched;
- `field_name` defines where the extracted value will be stored.

For example:

```text
%{IP:source_ip}
```

means:

```text
Find an IP address
        ↓
Store it in source_ip
```

---

## Common Grok Patterns

### Timestamp

```text
%{TIMESTAMP_ISO8601:timestamp}
```

### IP Address

```text
%{IP:source_ip}
```

### Number

```text
%{NUMBER:pid}
```

### Word

```text
%{WORD:program}
```

### Non-whitespace Data

```text
%{NOTSPACE:field}
```

### Remaining Text

```text
%{GREEDYDATA:msg}
```

---

# 7. Parsing Linux Authentication Logs

A practical Grok pattern for structured Linux authentication logs:

```conf
filter {
    grok {
        match => {
            "message" => "^%{TIMESTAMP_ISO8601:timestamp} %{NOTSPACE:[host][name]} %{WORD:program}(?:\[%{NUMBER:pid}\])?: %{GREEDYDATA:msg}"
        }
    }
}
```

This extracts fields such as:

```text
timestamp
host.name
program
pid
msg
```

Instead of keeping the entire log only as an unstructured `message`, Logstash creates fields that can later be searched and analyzed individually in Elasticsearch and Kibana.

---

# 8. Date Filter

Extracting a timestamp with Grok does not automatically make it the event's main timestamp.

The `date` filter can convert the extracted timestamp into `@timestamp`.

```conf
filter {
    date {
        match => ["timestamp", "ISO8601"]
        target => "@timestamp"
    }
}
```

Here:

```text
timestamp
```

is the source field.

```text
ISO8601
```

defines its expected format.

```text
@timestamp
```

becomes the timestamp used by Elasticsearch and Kibana.

The flow becomes:

```text
Original log timestamp
        ↓
Grok extracts "timestamp"
        ↓
Date parses timestamp
        ↓
@timestamp
```

This is especially important for chronological investigation in a SIEM.

---

# 9. Prune Filter

The `prune` filter can be used to keep only selected fields.

```conf
filter {
    prune {
        whitelist_names => ["field1", "field2"]
    }
}
```

This is useful when events contain many fields that are not needed for analysis or storage.

---

# 10. Drop Filter

The `drop` filter discards events that match a condition.

Example:

```conf
filter {
    if [status] == "error" {
        drop { }
    }
}
```

Events matching the condition will not continue through the pipeline.

Conceptually:

```text
Event
  ↓
Condition
  ├── match → DROP
  └── no match → continue
```

This can be useful for removing unwanted or irrelevant events before they are stored.

---

# 11. Key-Value Filter

The `kv` filter parses data stored as key-value pairs.

Example:

```conf
filter {
    kv {
        field_split => "&"
        value_split => "="
    }
}
```

For data such as:

```text
user=alice&action=login&status=success
```

`&` separates each pair:

```text
user=alice
action=login
status=success
```

and `=` separates each key from its value.

The resulting event can contain structured fields such as:

```text
user   → alice
action → login
status → success
```

---

# 12. Outputs

Outputs define where Logstash sends events after processing.

```text
Input
  ↓
Filter
  ↓
OUTPUT
  ├── Elasticsearch
  ├── File
  ├── TCP
  ├── Syslog
  └── Other destinations
```

---

# 13. Elasticsearch Output

A basic Elasticsearch output:

```conf
output {
    elasticsearch {
        hosts => ["hostname:9200"]
        data_stream => true
    }
}
```

Logstash can therefore process incoming logs and forward the resulting structured events directly into Elasticsearch.

---

## Custom Elasticsearch Index

An index can also be explicitly specified:

```conf
output {
    elasticsearch {
        hosts => ["https://localhost:9200"]
        index => "auth-logs-%{+YYYY.MM.dd}"
    }
}
```

The date expression:

```text
%{+YYYY.MM.dd}
```

allows Logstash to create date-based index names.

For example:

```text
auth-logs-2026.10.11
```

A Kibana Data View can then use:

```text
auth-logs-*
```

to match the related indices.

---

# 14. File Output

Events can be written to a file:

```conf
output {
    file {
        path => "/path/to/output.txt"
    }
}
```

This can be useful for testing or storing processed output locally.

---

# 15. Standard Output

The `stdout` output prints events to standard output:

```conf
output {
    stdout { }
}
```

This is particularly useful when testing and debugging pipelines because it allows processed events to be inspected before sending them to another system.

---

# 16. TCP Output

Events can be forwarded to another host over TCP:

```conf
output {
    tcp {
        host => "destination_host"
        port => 5000
    }
}
```

---

# 17. Logstash Output

Events can also be forwarded to another Logstash instance:

```conf
output {
    logstash {
        host => "destination_host"
        port => 5000
    }
}
```

This allows multiple Logstash instances to participate in a larger log-processing architecture.

---

# 18. Syslog Output

Logstash can forward events to a Syslog server:

```conf
output {
    syslog {
        host => "syslog_server"
        port => 514
        protocol => "udp"
    }
}
```

---

# 19. RabbitMQ Output

Events can also be forwarded to RabbitMQ:

```conf
output {
    rabbitmq {
        host => "localhost"
        exchange => "my_exchange"
        routing_key => "my_routing_key"
    }
}
```

---

# 20. Complete Authentication Log Pipeline

The following example combines file ingestion, Grok parsing, timestamp normalization, and Elasticsearch output.

```conf
input {
    file {
        path => "/var/log/auth.log"
        start_position => "beginning"
        sincedb_path => "/dev/null"
    }
}

filter {
    grok {
        match => {
            "message" => "^%{TIMESTAMP_ISO8601:timestamp} %{NOTSPACE:[host][name]} %{WORD:program}(?:\[%{NUMBER:pid}\])?: %{GREEDYDATA:msg}"
        }
    }

    date {
        match => ["timestamp", "ISO8601"]
        target => "@timestamp"
    }
}

output {
    elasticsearch {
        hosts => ["https://localhost:9200"]
        user => "elastic"
        password => "${ELASTIC_PASSWORD}"
        index => "auth-logs-%{+YYYY.MM.dd}"
        ssl_enabled => true
    }
}

```
## Check Service Status

```bash
systemctl status logstash
```

## Restart Logstash

After modifying a pipeline configuration:

```bash
systemctl restart logstash
```

## Validate Configuration

Before restarting Logstash, test the configuration:

```bash
/usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
```

A valid configuration should report that the configuration is OK.

## Check Logstash Logs

```bash
journalctl -u logstash -f
```

This is useful for identifying:

- configuration errors;
- plugin errors;
- connection failures;
- Elasticsearch output problems.

## Check Configuration Files

```bash
ls /etc/logstash/conf.d/
```

Remember that Logstash may load multiple configuration files from its configuration directory.

---
