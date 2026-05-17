```
       __
  ____/ /___  __________
 / __  / __ \/ ___/ ___/
/ /_/ / / / (__  ) /__
\__,_/_/ /_/____/\___/
 DNS Checker CLI Tool
```

`dnsc` is a lightweight DNS checker CLI written in Dart.
It lets you query common DNS record types (A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT) plus email-related helpers (SPF, DKIM, DMARC).  
It is based on [DNSolve](https://github.com/vsevex/dnsolve).

## Features

- Query multiple DNS record types from the command line
- Optional custom nameserver selection
- Configurable timeout for lookups
- Table output by default, with a simplified output mode
- Optional row numbering and full (non-truncated) output
- Advanced helper commands for SPF, DKIM, and DMARC checks

## Usage

```bash
dnsc <flags> [command] [domain]
```

## Global Flags

| Flag                 | Description                               |
| -------------------- | ----------------------------------------- |
| `-h`, `--help`       | Print usage information                   |
| `--version`          | Print the current version                 |
| `-c`, `--count`      | Prepend record number to each output line |
| `-f`, `--full`       | Print full values without truncation      |
| `-n`, `--nameserver` | Use a custom nameserver for lookups       |
| `--simple`           | Print simple output (no ASCII table)      |
| `-t`, `--timeout`    | Timeout in seconds (default: `1`)         |

## Commands

### Standard DNS Commands

- `a`
- `aaaa`
- `cname`
- `mx`
- `ns`
- `ptr`
- `soa`
- `srv`
- `txt`

### Advanced Commands

- `spf`: queries TXT records and filters entries containing `v=spf1`
- `dkim`: queries `TXT` on `<selector>._domainkey.<domain>` provided with `-s` or `--selector`
- `dmarc`: queries `TXT` on `_dmarc.<domain>`

## Output Modes

- Default: formatted ASCII table
- `--simple`: plain lines, easier for scripting
- `-c`, `--count`: adds a record index column/prefix
- `-f`, `--full`: disables truncation of long values

## Examples

```bash
# A record
dnsc a example.com

# MX record
dnsc mx example.com

# CNAME with simple output
dnsc --simple cname example.com

# CNAME with custom nameserver and timeout
dnsc -t 5 -n 1.1.1.1 cname example.com

# TXT with simple and full output
dnsc --simple --full txt example.com

# SPF check
dnsc spf example.com

# DKIM check
dnsc dkim example.com -s key1

# DMARC check
dnsc dmarc example.com
```
