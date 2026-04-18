# Sniper

Check whether a domain can complete a TLS handshake from your current network using its real SNI.

`sniper` resolves the domain, tries every returned IP for each configured port, and considers a port **allowed** when one IP completes TLS on that port.

## Quick Start

Build:

```bash
go build -o sniper .
```

Create an input file with one domain per line:

```text
hcaptcha.com
google.com
letsencrypt.org
```

Run:

```bash
sniper -f domains.txt
```

See full help:

```bash
sniper -h
```

## Important Examples

Scan a file:

```bash
sniper -f domains.txt
```

Probe a different TLS port:

```bash
sniper -f domains.txt -port 8443
```

Probe several ports at once (comma-separated; overrides `-port` when set):

```bash
sniper -f domains.txt -ports 443,2053,8443
```

Use a shorter timeout:

```bash
sniper -f domains.txt -timeout 1s
```

Write results to a file:

```bash
sniper -f domains.txt -output results.txt
```

Scan domains against one fixed IP:

```bash
sniper -f domains.txt -target 104.19.229.21
```

Scan domains against IPs loaded from a file:

```bash
sniper -f domains.txt -target-file ips.txt
```

## Flags

- `-f string` input file with domains, one per line
- `-port int` TLS port when `-ports` is not set, default `443`
- `-ports string` comma-separated TLS ports (e.g. `443,2053`); when set, replaces `-port`
- `-timeout duration` per DNS lookup, TCP dial, and TLS handshake timeout, default `2s`
- `-output string` write result lines to a file
- `-workers int` number of concurrent workers, default `200`
- `-verbose` include domains where every port failed (see Output)
- `-retries int` retries per IP on failure, default `0`
- `-q` hide start and completion logs
- `-target string` override DNS and probe one IP for every domain
- `-target-file string` override DNS and probe IPs from a file for every domain

## Output

- One line per domain (first occurrence order in the file). Each line shows IP, max successful handshake latency (or `-` if none), then each port as `443 ✓` or `443 ✗` (Unicode marks; colored when stdout is a TTY).
- By default, domains with **no** successful port are omitted; pass `-verbose` to list those too.

Probing uses **TCP connect + TLS** (not ICMP ping).

## Notes

- If a domain resolves to multiple IPs, `sniper` tries all of them.
- If `-target` or `-target-file` is set, `sniper` skips DNS and uses those IPs instead.
- A port is counted as allowed if any resolved IP completes TLS on that port (see counts in the completion log).
- `-timeout` is per attempt, not a total cap for the whole domain.
- Result lines go to stdout, or to the file passed with `-output`.
- Start, completion, and error logs are written to stderr.
