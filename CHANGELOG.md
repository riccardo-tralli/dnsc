## 0.3.0

### Added

- `-a`, `--analyze` to break down `SPF`, `DKIM`, and `DMARC` records into their terms or tags, with a description of each one and checks for common problems.
- `-R`, `--recursive` to resolve `SPF` includes and redirects recursively, showing the include tree and counting the DNS lookups of the whole evaluation.
- A check column in analysis tables that marks the rows with errors and warnings, explained below the table.
- A warning for `SPF` terms separated by characters other than spaces (e.g. newlines), also in nested records.
- `-r`, `--raw` for unformatted output (`--simple` and `--full` together).
- Non-zero exit codes: `1` for lookup errors, `2` for usage errors.
- Validation of the domain, the timeout, and the `--first`/`--last` combination before running a lookup.

### Changed

- Lookup and unexpected errors are printed on stderr, and empty answers are told apart from failed lookups.
- Invalid arguments no longer end the interactive session, and interactive input is split on any whitespace.

### Fixed

- `MX` and `SRV` records not being sorted by priority before `--first`/`--last` selection.
- The table showing the queried type instead of each record's own type.
- `null` being printed for a missing `SRV` target in simple output.
- `m365` printing nothing when no records are found.

## 0.2.0

### Added

- The `m365` command to query the DNS records of a Microsoft 365 setup.
- `-1`, `--first` and `-9`, `--last` to print only the first or last record of the answer.
- An interactive mode when `dnsc` is run without arguments.
- A clear message for non-existent domains (NXDOMAIN).

### Changed

- Increased the default timeout from 1 to 5 seconds.

### Fixed

- `MX` records not being sorted by priority.

## 0.1.0

Initial version.

### Added

- DNS lookup commands for `A`, `AAAA`, `CNAME`, `MX`, `NS`, `PTR`, `SOA`, `SRV`, and `TXT` records.
- Advanced email-related checks for `SPF`, `DKIM`, and `DMARC`.
- Support for custom nameservers and configurable lookup timeouts.
- Table and simple output modes, with optional record counting and full non-truncated output.
