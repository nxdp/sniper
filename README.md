# Sniper

Check whether a domain can complete a TLS handshake from your current network using its real SNI.

`sniper` resolves the domain, tries every returned IP, and marks it `allowed` as soon as one IP completes the handshake.

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

Use a shorter timeout:

```bash
sniper -f domains.txt -timeout 1s
```

Write results to a file:

```bash
sniper -f domains.txt -output results.txt
```

## Flags

- `-f string` input file with domains, one per line
- `-port int` TLS port to probe, default `443`
- `-timeout duration` per DNS lookup, TCP dial, and TLS handshake timeout, default `2s`
- `-output string` write result lines to a file
- `-workers int` number of concurrent workers, default `200`
- `-verbose` print blocked domains too
- `-retries int` retries per IP on failure, default `0`
- `-q` hide start and completion logs

## Notes

- If a domain resolves to multiple IPs, `sniper` tries all of them.
- A domain is `allowed` if any resolved IP completes the TLS handshake.
- `-timeout` is per attempt, not a total cap for the whole domain.
- Result lines go to stdout, or to the file passed with `-output`.
- Start, completion, and error logs are written to stderr.
