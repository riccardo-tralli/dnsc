```
       __
  ____/ /___  __________
 / __  / __ \/ ___/ ___/
/ /_/ / / / (__  ) /__
\__,_/_/ /_/____/\___/
 DNS Checker CLI Tool
```

`dnsc` is a lightweight DNS checker CLI written in Dart.  
It lets you query common DNS record types (A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT) plus email-related helpers (SPF, DKIM, DMARC) and others.  
It's built on a [fork](https://github.com/riccardo-tralli/dnsolve) of [DNSolve](https://github.com/vsevex/dnsolve).

## Features

- Query multiple DNS record types from the command line
- Optional custom nameserver selection
- Configurable timeout for lookups
- Table output by default, with a simplified output mode
- Optional row numbering and full (non-truncated) output
- Advanced helper commands for SPF, DKIM, and DMARC checks
- Structured analysis of SPF, DKIM, and DMARC records with `--analyze`

## Usage

```bash
dnsc <flags> [command] [domain]
```

## Global Flags

| Flag                 | Description                               |
| -------------------- | ----------------------------------------- |
| `-h`, `--help`       | Print usage information                   |
| `--version`          | Print the current version                 |
| `-n`, `--nameserver` | Use a custom nameserver for lookups       |
| `-t`, `--timeout`    | Timeout in seconds (default: `5`)         |
| `-c`, `--count`      | Prepend record number to each output line |
| `-f`, `--full`       | Print full values without truncation      |
| `--simple`           | Print simple output (no ASCII table)      |
| `-r`, `--raw`        | Print raw output without formatting       |
| `-1`, `--first`      | Only print the first record               |
| `-9`, `--last`       | Only print the last record                |
| `-a`, `--analyze`    | Break down SPF, DKIM and DMARC records    |
| `-R`, `--recursive`  | Follow SPF includes and redirects         |

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
- `m365`: queries various records for Microsoft 365 implementation

### Record Analysis

With `-a`, `--analyze` the `spf`, `dkim` and `dmarc` commands break each record down into its terms or tags, describe what each one does and report common problems:

- `spf`: qualifiers and mechanisms, DNS lookup count (limit 10), `+all`/`?all`, missing `all`, terms after `all`, deprecated `ptr`, unknown mechanisms
- `dmarc`: policies, alignment, report addresses and options, `p=none`, `pct` below 100, missing `rua`, invalid values
- `dkim`: key type and size, revoked keys, weak RSA keys (below 2048 bits), testing mode, `sha1`-only hashes

Multiple records of the same kind are also reported, as receivers treat them as an error.

The `Check` column marks the rows with an issue, explained below the table:

- `ERROR`: the record is invalid or unsafe (e.g. syntax errors, `+all`, too many lookups, revoked or insecure keys)
- `WARN`: the record works but could be improved (e.g. `?all`, `p=none`, deprecated mechanisms, weak keys)

Issues about the record as a whole, such as a missing required tag, are only listed below the table.

The SPF lookup count only covers the queried record. With `-R`, `--recursive` (`spf` only, implies `--analyze`) every `include` and `redirect` is resolved recursively: a second table shows the include tree with the lookups of each record, and the count covers the whole evaluation. Included domains without an SPF record, with multiple SPF records, and include loops are reported, as receivers return a permerror.

## Output Modes

- Default: formatted ASCII table
- `--simple`: plain lines, easier for scripting
- `-c`, `--count`: adds a record index column/prefix
- `-f`, `--full`: disables truncation of long values
- `-r`, `--raw`: print raw output without formatting (equivalent to `--simple` and `--full`)
- `-1`, `--first`: only print the first record of the answer
- `-9`, `--last`: only print the last record of the answer

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
dnsc -r txt example.com

# SPF check
dnsc spf example.com

# DKIM check
dnsc dkim example.com -s key1

# SPF, DMARC and DKIM analysis
dnsc --analyze spf example.com
dnsc -a dmarc example.com
dnsc -a dkim example.com -s key1

# SPF analysis with recursive include resolution
dnsc -R spf example.com

# First MX record only
dnsc mx example.com --first

# DKIM check with raw output and last record only
dnsc -r9 dkim example.com -s keyX
```
