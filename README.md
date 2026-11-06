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
dnsc [flags] <command> <domain> [command options]
```

Run `dnsc` without arguments to start an interactive session, where each line is a command.

## Global Flags

| Flag                        | Description                                                                                   |
| --------------------------- | --------------------------------------------------------------------------------------------- |
| `-h`, `--help`              | Print the usage information                                                                   |
| `--version`                 | Print the version                                                                             |
| `-n`, `--nameserver=<ip>`   | Query this nameserver instead of the system one                                               |
| `-t`, `--timeout=<seconds>` | Timeout of each DNS query (default: `5`)                                                      |
| `-c`, `--count`             | Number the output rows                                                                        |
| `-f`, `--full`              | Print long values in full instead of truncating them                                          |
| `--simple`                  | Print plain lines instead of tables                                                           |
| `-r`, `--raw`               | Same as `--simple --full`                                                                     |
| `-1`, `--first`             | Print only the first record of the answer                                                     |
| `-9`, `--last`              | Print only the last record of the answer                                                      |
| `-a`, `--analyze`           | Break `spf`, `dkim` and `dmarc` records down into their terms or tags and check them          |
| `-R`, `--recursive`         | Follow SPF includes and redirects and count all DNS lookups (`spf` only, implies `--analyze`) |

## Commands

### Standard DNS Commands

- `a`: IPv4 addresses (A records)
- `aaaa`: IPv6 addresses (AAAA records)
- `cname`: canonical name (CNAME record)
- `mx`: mail servers, sorted by priority (MX records)
- `ns`: name servers (NS records)
- `ptr`: reverse lookup of an IP address (PTR records)
- `soa`: start of authority of the zone (SOA record)
- `srv`: services, sorted by priority (SRV records)
- `txt`: text records (TXT records)

### Advanced Commands

- `spf`: SPF policy, from the TXT records of the domain containing `v=spf1`
- `dkim`: DKIM key, from TXT on `<selector>._domainkey.<domain>`; the selector is required, with `-s`, `--selector=<selector>`
- `dmarc`: DMARC policy, from TXT on `_dmarc.<domain>`
- `m365`: Microsoft 365 records (MX, SPF, DKIM, DMARC, Autodiscover, Intune)

### Record Analysis

With `-a`, `--analyze` the `spf`, `dkim` and `dmarc` commands break each record down into its terms or tags, describe what each one does and report common problems:

- `spf`: qualifiers and mechanisms, DNS lookup count (limit 10), `+all`/`?all`, missing `all`, terms after `all`, deprecated `ptr`, unknown mechanisms, terms separated by characters other than spaces
- `dmarc`: policies, alignment, report addresses and options, `p=none`, `pct` below 100, missing `rua`, invalid values
- `dkim`: key type and size, revoked keys, weak RSA keys (below 2048 bits), testing mode, `sha1`-only hashes

Multiple records of the same kind are also reported, as receivers treat them as an error.

The `Check` column marks the rows with an issue, explained below the table:

- `ERROR`: the record is invalid or unsafe (e.g. syntax errors, `+all`, too many lookups, revoked or insecure keys)
- `WARN`: the record works but could be improved (e.g. `?all`, `p=none`, deprecated mechanisms, weak keys)

Issues about the record as a whole, such as a missing required tag, are only listed below the table.

The SPF lookup count only covers the queried record. With `-R`, `--recursive` (`spf` only, implies `--analyze`) every `include` and `redirect` is resolved recursively: a second table shows the include tree with the lookups of each record, and the count covers the whole evaluation. Included domains without an SPF record, with multiple SPF records, and include loops are reported, as receivers return a permerror.

## Output Modes

- Default: ASCII tables, with long values truncated
- `--simple`: plain lines instead of tables, easier for scripting
- `-c`, `--count`: numbers the output rows, as a `#` column or a `1)` prefix
- `-f`, `--full`: prints long values in full instead of truncating them
- `-r`, `--raw`: same as `--simple --full`
- `-1`, `--first`: prints only the first record of the answer
- `-9`, `--last`: prints only the last record of the answer

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
