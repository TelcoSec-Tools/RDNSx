---
layout: page
title: "RDNSx CLI Reference - Command Documentation"
description: "Complete command-line interface reference for RDNSx DNS toolkit. All commands, options, and usage examples for DNS enumeration, ASN lookup, and reverse DNS operations."
keywords: "RDNSx CLI, command reference, DNS commands, ASN enumeration, reverse DNS, command line interface, documentation"
og_image: /assets/images/logo.svg
twitter_card: summary_large_image
author: "TelcoSec"
lang: en-US
permalink: /api/cli-reference/
priority: 0.8
changefreq: monthly
---

# CLI Reference

## Global Options

All commands support these global options:

```
-c, --config <CONFIG>          Configuration file path (or RDNSX_CONFIG)
-o, --output <OUTPUT>          Output file
    --json                     JSON output format
    --silent                   Hide the banner and progress messages (results are still printed)
    --timeout <SECONDS>        Query timeout (overrides the config file)
-r, --resolvers <LIST>         Resolvers to use, comma-separated (overrides the config file)
    --rate-limit <QPS>         Maximum queries per second, 0 = unlimited
    --threads <N>              Number of concurrent queries
    --create-config <PATH>     Create example configuration file
-h, --help                     Print help
-V, --version                  Print version
```

Global options can be placed before or after the subcommand. The rate limit and
concurrency apply to every command (`query`, `bruteforce`, `ptr`, `enumerate`).

## Commands

### `rdnsx query`

Query domains from list/stdin for DNS records.

```
USAGE:
    rdnsx query [OPTIONS] [DOMAINS]...

ARGS:
    <DOMAINS>...    Domains to query

OPTIONS:
    -l, --list <LIST>                      Input file (default: stdin)
    -t, --record-type <TYPE>               DNS record types to query (can be repeated)
    -a, --a                                A records (default)
        --aaaa                             AAAA records
        --cname                            CNAME records
        --mx                               MX records
        --txt                              TXT records
        --ns                               NS records
        --soa                              SOA records
        --ptr                              PTR records
        --srv                              SRV records
        --caa                              CAA records
        --cert                             CERT records
        --dname                            DNAME records
        --dnskey                           DNSKEY records
        --ds                               DS records
        --hinfo                            HINFO records
        --https                            HTTPS records
        --key                              KEY records
        --loc                              LOC records
        --naptr                            NAPTR records
        --nsec                             NSEC records
        --nsec3                            NSEC3 records
        --afsdb                            AFSDB records
        --rrsig                            RRSIG records
        --sshfp                            SSHFP records
        --svcb                             SVCB records
        --tlsa                             TLSA records
        --uri                              URI records
        --asn                              Origin AS, prefix and registry country of each address (Team Cymru)
        --rcode <RCODE>                    Filter by response code (comma-separated, e.g. NXDOMAIN,SERVFAIL).
                                           Negative answers are printed as "name [NXDOMAIN]"
    -w, --wildcard-domain <DOMAIN>         Domain for wildcard detection
        --resp-only                        Response values only
```

### Supported DNS Record Types

RDNSx supports comprehensive DNS record type querying:

- **Address Records**: `A` (IPv4), `AAAA` (IPv6)
- **Name Records**: `CNAME` (alias), `DNAME` (redirection)
- **Mail Records**: `MX` (mail servers), `TXT` (SPF/DKIM/DMARC)
- **Server Records**: `NS` (name servers), `SOA` (zone authority)
- **Service Records**: `SRV` (service discovery), `NAPTR` (dynamic delegation)
- **Security Records**: `DNSKEY`, `DS`, `RRSIG`, `NSEC`, `NSEC3` (DNSSEC)
- **Certificate Records**: `CAA` (CA authorization), `TLSA` (DANE), `CERT`
- **Special Records**: `PTR` (reverse DNS), `LOC` (geolocation), `HINFO` (host info)
- **Modern Records**: `HTTPS`, `SVCB` (HTTP upgrades), `SSHFP` (SSH keys)
- **Legacy Records**: `AFSDB`, `KEY`

#### Examples

```bash
# Query A records for domains
rdnsx query example.com google.com

# Query from file
rdnsx query --list domains.txt

# Query specific record types
rdnsx query example.com --record-type A --record-type MX

# JSON output
rdnsx query example.com --json

# Silent mode
rdnsx query example.com --silent
```

### `rdnsx bruteforce`

Enumerate subdomains using bruteforce with wordlists.

```
USAGE:
    rdnsx bruteforce [OPTIONS] --domain <DOMAIN> --wordlist <WORDLIST>

OPTIONS:
    -d, --domain <DOMAIN>                  Target domain(s)
    -w, --wordlist <WORDLIST>              Wordlist file, comma-separated words, or - for stdin
        --placeholder <PLACEHOLDER>        Placeholder string (default: FUZZ)
        --record-type <TYPE>               Record type to query (default: A)
        --no-wildcard-filter               Keep answers that only come from a wildcard record
    (plus the global options: -r/--resolvers, --rate-limit, --timeout, --threads)
```

Wildcard DNS on the target is detected automatically and answers that match the
wildcard's addresses are dropped.

#### Examples

```bash
# Basic subdomain enumeration
rdnsx bruteforce --domain example.com --wordlist wordlist.txt

# Use custom resolvers
rdnsx bruteforce -d example.com -w wordlist.txt -r 8.8.8.8,1.1.1.1

# Different record types
rdnsx bruteforce -d example.com -w wordlist.txt --record-type CNAME
```

### `rdnsx ptr`

Reverse DNS lookups for IP ranges, individual IPs, or ASN.

```
USAGE:
    rdnsx ptr [OPTIONS] <INPUT>

ARGS:
    <INPUT>    IP address, CIDR range (capped at 10,000 IPs), or ASN (ASxxx)

OPTIONS:
    (the global options: -r/--resolvers, --rate-limit, --timeout, --threads)
```

ASN prefixes come from RIPEstat (falling back to BGPView).

#### Examples

```bash
# Reverse lookup single IP
rdnsx ptr 8.8.8.8

# Reverse lookup IP range
rdnsx ptr 192.168.1.0/24

# Reverse lookup ASN
rdnsx ptr AS15169

```

### `rdnsx enumerate`

Advanced DNS enumeration techniques for comprehensive reconnaissance.

```
USAGE:
    rdnsx enumerate [OPTIONS] --technique <TECHNIQUE> --target <TARGET>

OPTIONS:
    -t, --technique <TECHNIQUE>      zone-transfer, email-security, cdn-detection, ipv6-enumeration,
                                     server-fingerprint, dnssec-enumeration, dnssec-zone-walking,
                                     wildcard-analysis, passive-dns, asn-enumeration, comprehensive
        --target <TARGET>            Target domain, server (for server-fingerprint) or ASN
        --nameservers <LIST>         Recursive resolvers to use for lookups
        --axfr-servers <LIST>        Servers to try AXFR against (default: the zone's NS records)
        --fingerprint-servers <LIST> Servers to fingerprint (default: the target if it is a server,
                                     otherwise the zone's authoritative nameservers)
        --max-names <N>              Name limit for DNSSEC zone walking (default: 1000)
        --concurrent <N>             Maximum concurrent queries (default: --threads)
        --no-asn-lookup              CDN detection without Team Cymru lookups
    (plus the global options)
```

What each technique does:

- **zone-transfer**: AXFR over TCP against every address (IPv4 and IPv6) of each authoritative nameserver.
  Transfers that stop before the closing SOA are listed as incomplete.
- **email-security**: SPF, DMARC and DKIM (about 30 common selectors under `_domainkey`). SPF is checked
  for `+all`/`?all`, `ptr`, several records and the 10-lookup limit; DMARC falls back to parent domains and
  flags `p=none`.
- **server-fingerprint**: queries the server directly for `version.bind`, `hostname.bind`, `id.server`
  (CHAOS), open recursion, EDNS(0), DNSSEC signatures and TCP support (a real query over TCP).
- **dnssec-enumeration**: DNSKEY/DS records, RRSIGs and NSEC/NSEC3 from an authoritative server, a DS-to-DNSKEY
  match check, and full signature validation from the root trust anchor.
- **dnssec-zone-walking**: follows the NSEC chain from the apex on an authoritative server, including across
  delegations. NSEC3 zones and synthesized minimal NSEC ("black lies", compact denial) are detected and
  reported as not walkable.
- **cdn-detection**: reports a CDN only on direct evidence: a CNAME to a known CDN suffix, an address announced
  by a CDN edge AS (Team Cymru lookup), or an address in Cloudflare's or Fastly's published ranges. Cloud
  hosting (AWS, Google Cloud, Azure...) is reported as hosting, not as a CDN. The country is the RIR
  registration country of the prefix.
- **passive-dns**: Certificate Transparency names from crt.sh (with first/last logged dates). No DNS queries
  are sent for the target. Failed sources are listed.

#### Examples

```bash
# ASN enumeration
rdnsx enumerate --technique asn-enumeration --target AS15169
rdnsx enumerate --technique asn-enumeration --target 16509

# DNSSEC analysis
rdnsx enumerate --technique dnssec-enumeration --target example.com

# Email security analysis
rdnsx enumerate --technique email-security --target example.com

# Zone transfer attempt
rdnsx enumerate --technique zone-transfer --target example.com

# Comprehensive enumeration (all techniques)
rdnsx enumerate --technique comprehensive --target example.com

# CDN detection
rdnsx enumerate --technique cdn-detection --target example.com

# IPv6 enumeration
rdnsx enumerate --technique ipv6-enumeration --target example.com
```

## Configuration File

RDNSx can be configured using a TOML configuration file. Create an example config:

```bash
rdnsx --create-config config/rdnsx.toml
```

### Configuration Options

```toml
[resolvers]
servers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]
timeout = 5
retries = 3

[performance]
threads = 100
rate_limit = 0

[export]
batch_size = 1000

[export.elasticsearch]
enabled = false
url = "http://localhost:9200"
index = "dnsx-records"

[export.mongodb]
enabled = false
url = "mongodb://localhost:27017"
database = "dnsx"
collection = "records"

[export.cassandra]
enabled = false
contact_points = ["localhost:9042"]
username = ""
password = ""
keyspace = "dnsx"
table = "records"
```

## Environment Variables

RDNSx respects these environment variables:

- `RDNSX_CONFIG` - Path to configuration file
- `RDNSX_RESOLVERS` - Comma-separated list of DNS resolvers
- `RDNSX_TIMEOUT` - Query timeout in seconds
- `RDNSX_THREADS` - Number of concurrent threads

## Exit Codes

- `0` - Success
- `1` - Error occurred
- `2` - Invalid arguments

## Performance Tuning

### Memory Usage
- Default: ~50MB base memory
- Per thread: ~2MB additional
- Large wordlists: Consider increasing system memory

### Network Considerations
- Rate limiting prevents overwhelming DNS servers
- Timeout settings affect query completion time
- Resolver selection impacts performance and reliability

### File I/O
- Large output files benefit from buffered writing
- JSON output is more CPU intensive than plain text
- Database exports use batching to optimize performance