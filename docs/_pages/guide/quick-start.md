---
layout: page
title: "RDNSx Quick Start Guide"
description: "Get started with RDNSx DNS toolkit in minutes. Learn basic DNS queries, ASN enumeration, and advanced enumeration techniques."
keywords: "RDNSx quick start, DNS queries, ASN enumeration, reverse DNS, getting started, tutorial"
og_image: /assets/images/logo.svg
twitter_card: summary_large_image
author: "TelcoSec"
lang: en-US
permalink: /guide/quick-start/
priority: 0.9
changefreq: monthly
---

# Quick Start

This guide will get you up and running with RDNSx in just a few minutes.

## Basic DNS Queries

### Query A Records (Default)
```bash
rdnsx query example.com
```

Output:
```
██████╗ ██████╗ ███╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔══██╗████╗  ██║██╔════╝╚██╗██╔╝
██████╔╝██║  ██║██╔██╗ ██║███████╗ ╚███╔╝
██╔══██╗██║  ██║██║╚██╗██║╚════██║ ██╔██╗
██║  ██║██████╔╝██║ ╚████║███████║██╔╝ ██╗
╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝

              TelcoSec RDNSx
    Fast and multi-purpose DNS toolkit

example.com 300 IN A 93.184.216.34
```

### Query Multiple Record Types
```bash
rdnsx query example.com --record-type A --record-type MX
```

### Query All Record Types
```bash
rdnsx query example.com --record-type A --record-type AAAA --record-type MX --record-type TXT --record-type NS
```

## Working with Multiple Domains

### From Command Line
```bash
rdnsx query example.com google.com github.com
```

### From File
Create a file with domains:
```bash
echo -e "example.com\ngoogle.com\ngithub.com" > domains.txt
rdnsx query --list domains.txt
```

### From Standard Input
```bash
cat domains.txt | rdnsx query
```

## Subdomain Enumeration

### Basic Bruteforce
```bash
# Create a wordlist
echo -e "www\napi\nmail\ndev\nstaging" > wordlist.txt

# Run bruteforce
rdnsx bruteforce --domain example.com --wordlist wordlist.txt
```

## Reverse DNS Lookups

### PTR Lookup for IP Range
```bash
rdnsx ptr 192.168.1.0/24
```

### ASN Lookup
```bash
rdnsx ptr --asn AS15169
```

## Output Formats

### JSON Output
```bash
rdnsx query example.com --json
```

### Silent Mode (Minimal Output)
```bash
rdnsx query example.com --silent
```

### Response Values Only
```bash
rdnsx query example.com --resp-only
```

## Configuration

### Create Default Config
```bash
rdnsx --create-config config/rdnsx.toml
```

### Use Custom Config
```bash
rdnsx --config my-config.toml query example.com
```

## Performance Tuning

### Increase Concurrency
```bash
rdnsx query --threads 100 --list domains.txt
```

### Adjust Timeout
```bash
rdnsx query --timeout 10 --list domains.txt
```

### Rate Limiting
```bash
rdnsx query --rate-limit 50 --list domains.txt
```

## Advanced Enumeration

### ASN Enumeration
Discover IP ranges and network information for Autonomous Systems:

```bash
# Enumerate Google ASN
rdnsx enumerate --technique asn-enumeration --target AS15169

# Enumerate Amazon ASN
rdnsx enumerate --technique asn-enumeration --target 16509
```

### Enhanced PTR Lookups
Perform reverse DNS lookups with ASN integration:

```bash
# PTR lookup for Google ASN (uses ASN enumeration results)
rdnsx ptr AS15169

# Smart IP range handling (auto-limits large ranges)
rdnsx ptr 192.168.0.0/16

# Concurrent processing for better performance
rdnsx ptr 8.8.8.0/24
```

### Comprehensive DNS Analysis
Run all 11 enumeration techniques on a target for complete reconnaissance:

```bash
rdnsx enumerate --technique comprehensive --target example.com
```

**Available Techniques:**
- Zone transfers, DNSSEC analysis, CDN detection
- Email security (SPF/DMARC/DKIM), IPv6 enumeration
- Wildcard analysis, ASN enumeration, server fingerprinting
- And more advanced security research tools

## Next Steps

Now that you know the basics, explore:

- [DNS Record Types](dns-records) - Complete reference for all 27 supported record types
- [CLI Reference](../api/cli-reference) - Complete command documentation
- [Configuration](configuration) - Advanced configuration options
- [Database Exports](exports) - Export results to databases