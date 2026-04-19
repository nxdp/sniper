# Sniper

`sniper` checks whether a domain can complete a TLS handshake from your network.

You give it a domain like `google.com`, and it tries a real TCP connection plus TLS handshake for that domain.

It tells you if the domain looks `allowed` or `blocked`.

This is useful when your network is restricted and you want a quick answer like:

- does this domain complete TLS from here?
- which domains still work?
- does this domain work on this specific IP?

## Download

Download the binary for your system from GitHub Releases:

[GitHub Releases](https://github.com/nxdp/sniper/releases)

Pick the file for your platform:

- Linux
- Windows
- macOS

Extract the archive, then run `sniper`.

## Quick Start

Check one domain:

```bash
sniper google.com
```

Check many domains from a file:

```bash
sniper -f domains.txt
```

Example `domains.txt`:

```text
google.com
hcaptcha.com
letsencrypt.org
```

Show blocked domains too:

```bash
sniper -f domains.txt -verbose
```

## What The Result Means

Example:

```text
google.com                     142.250.185.46     210ms allowed
```

This means:

- `google.com` is the domain you tested
- `142.250.185.46` is the IP that worked
- `210ms` is how long it took
- `allowed` means the TCP connection and TLS handshake worked

If it says `blocked`, the TCP connection or TLS handshake did not work.

## Common Examples

Check one domain with a shorter timeout:

```bash
sniper google.com -timeout 1s
```

Save results to a file:

```bash
sniper -f domains.txt -output results.txt
```

Check a domain on one specific IP:

```bash
sniper google.com -target 1.1.1.1
```

Check a list of domains on one specific IP:

```bash
sniper -f domains.txt -target 1.1.1.1
```

Check a list of domains on many IPs from a file:

```bash
sniper -f domains.txt -target-file ips.txt
```

Use a different HTTPS port:

```bash
sniper google.com -port 8443
```

## Main Flags

- `sniper google.com`
  Check one domain directly

- `-f domains.txt`
  Check many domains from a file

- `-verbose`
  Also print blocked domains

- `-timeout 1s`
  Change how long sniper waits before giving up

- `-output results.txt`
  Save result lines to a file

- `-target 1.1.1.1`
  Skip DNS and try that IP for every domain

- `-target-file ips.txt`
  Skip DNS and try IPs from a file

- `-ipv6`
  Also include IPv6 in DNS lookup

- `-port 443`
  Change the port

- `-q`
  Hide the start and end log lines

## Notes

- You can use either `sniper google.com` or `sniper -f domains.txt`
- Do not use both at the same time
- By default, DNS lookup uses IPv4 only
- If you want IPv6 too, use `-ipv6`
- If a domain has more than one matching IP, `sniper` tries all of them
- `allowed` does not mean the whole website will work, it only means the TCP connection and TLS handshake worked
- this tool does not send a full HTTP request after the handshake
- result lines can be saved with `-output`

## Need Full Help?

Run:

```bash
sniper -h
```
