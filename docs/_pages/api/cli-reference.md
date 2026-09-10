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
-c, --config <CONFIG>          Configuration file path
-o, --output <OUTPUT>          Output file
    --json                     JSON output format
    --silent                   Silent mode (minimal output)
    --create-config <PATH>     Create example configuration file
-h, --help                     Print help
-V, --version                  Print version
```

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
        --opt                              OPT records
        --rrsig                            RRSIG records
        --sshfp                            SSHFP records
        --svcb                             SVCB records
        --tlsa                             TLSA records
        --uri                              URI records
        --asn                              ASN information
    -r, --rcode <RCODE>                    Filter by response code (comma-separated)
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
- **Legacy Records**: `AFSDB`, `KEY`, `OPT` (extensions)

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
    -w, --wordlist <WORDLIST>              Wordlist file or comma-separated words
    -p, --placeholder <PLACEHOLDER>        Placeholder string (default: FUZZ)
    -t, --record-type <TYPE>               Record type to query (default: A)
    -r, --resolvers <RESOLVERS>            Custom resolver list
        --rate-limit <RATE_LIMIT>          Rate limit (queries per second)
        --timeout <TIMEOUT>                Query timeout in seconds
        --retries <RETRIES>                Retry attempts
        --threads <THREADS>                Concurrency level
```

#### Examples

```bash
# Basic subdomain enumeration
rdnsx bruteforce --domain example.com --wordlist wordlist.txt

# Use custom resolvers
rdnsx bruteforce -d example.com -w wordlist.txt -r 8.8.8.8,1.1.1.1

# Different record types
rdnsx bruteforce -d example.com -w wordlist.txt -t CNAME
```

### `rdnsx ptr`

Reverse DNS lookups for IP ranges, individual IPs, or ASN.

```
USAGE:
    rdnsx ptr [OPTIONS] <TARGETS>...

ARGS:
    <TARGETS>...    IP addresses, CIDR ranges, or ASN (ASxxx)

OPTIONS:
    -r, --resolvers <RESOLVERS>            Custom resolver list
        --rate-limit <RATE_LIMIT>          Rate limit (queries per second)
        --timeout <TIMEOUT>                Query timeout in seconds
        --retries <RETRIES>                Retry attempts
        --threads <THREADS>                Concurrency level
        --asn                              ASN information
```

#### Examples

```bash
# Reverse lookup single IP
rdnsx ptr 8.8.8.8

# Reverse lookup IP range
rdnsx ptr 192.168.1.0/24

# Reverse lookup ASN
rdnsx ptr AS15169

# Multiple targets
rdnsx ptr 8.8.8.8 1.1.1.1 192.168.1.0/24
```

### `rdnsx enumerate`

Advanced DNS enumeration techniques for comprehensive reconnaissance.

```
USAGE:
    rdnsx enumerate [OPTIONS] --technique <TECHNIQUE> --target <TARGET>

ARGS:
    -t, --technique <TECHNIQUE>    Enumeration technique to use [possible values: zone-transfer, email-security, cdn-detection, ipv6-enumeration, server-fingerprint, dnssec-enumeration, dnssec-zone-walking, wildcard-analysis, passive-dns, asn-enumeration, comprehensive]
        --asn                              ASN information
        --zone-transfer                    DNS zone transfer (AXFR)
        --email-security                  SPF, DMARC, DKIM analysis
        --cdn-detection                   Content delivery network detection
        --ipv6-enumeration                IPv6 deployment analysis
        --dnssec-enumeration              DNSSEC configuration analysis
        --dnssec-zone-walking             DNSSEC NSEC enumeration
        --wildcard-analysis               Wildcard DNS analysis
        --passive-dns                     Historical DNS data enumeration
    -T, --target <TARGET>          Target domain or ASN for enumeration

OPTIONS:
    -r, --resolvers <RESOLVERS>    Custom resolver list
        --rate-limit <RATE_LIMIT>  Rate limit (queries per second)
        --timeout <TIMEOUT>        Query timeout in seconds
        --retries <RETRIES>        Retry attempts
    -c, --concurrent <CONCURRENT>  Maximum concurrent enumeration tasks
```

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