---
layout: page
title: "DNS Record Types - Complete Reference"
description: "Comprehensive guide to all 27 DNS record types supported by RDNSx, including usage examples and technical details."
keywords: "DNS record types, DNS records reference, A record, AAAA record, MX record, CNAME, TXT record, DNSSEC, RDNSx"
og_image: /assets/images/logo.svg
twitter_card: summary_large_image
author: "TelcoSec"
lang: en-US
permalink: /guide/dns-records/
priority: 0.7
changefreq: monthly
---

# DNS Record Types Reference

This comprehensive guide covers all 27 DNS record types supported by RDNSx, providing technical details, use cases, and practical examples for each record type.

## Address Records

### A Record (IPv4 Address)
**Type Code:** 1
**Purpose:** Maps a domain name to an IPv4 address
**Example:**
```
example.com  300  IN  A  93.184.216.34
```

### AAAA Record (IPv6 Address)
**Type Code:** 28
**Purpose:** Maps a domain name to an IPv6 address
**Example:**
```
example.com  300  IN  AAAA  2606:2800:220:1:248:1893:25c8:1946
```

## Name Resolution Records

### CNAME Record (Canonical Name)
**Type Code:** 5
**Purpose:** Creates an alias for another domain name
**Example:**
```
www.example.com  300  IN  CNAME  example.com
```

### DNAME Record (Delegation Name)
**Type Code:** 39
**Purpose:** Redirects an entire subdomain tree
**Example:**
```
_subdomain.example.com  300  IN  DNAME  example.com
```

## Mail Records

### MX Record (Mail Exchange)
**Type Code:** 15
**Purpose:** Specifies mail servers for the domain
**Example:**
```
example.com  300  IN  MX  10 mail.example.com
```

### TXT Record (Text)
**Type Code:** 16
**Purpose:** Stores arbitrary text data (SPF, DKIM, DMARC)
**Examples:**
```
# SPF Record
example.com  300  IN  TXT  "v=spf1 mx -all"

# DKIM Record
default._domainkey.example.com  300  IN  TXT  "v=DKIM1; k=rsa; p=..."

# DMARC Record
_dmarc.example.com  300  IN  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
```

## Server Records

### NS Record (Name Server)
**Type Code:** 2
**Purpose:** Lists authoritative name servers for the domain
**Example:**
```
example.com  300  IN  NS  ns1.example.com
example.com  300  IN  NS  ns2.example.com
```

### SOA Record (Start of Authority)
**Type Code:** 6
**Purpose:** Contains administrative information about the zone
**Example:**
```
example.com  300  IN  SOA  ns1.example.com admin.example.com (
                          2023120101  ; Serial
                          3600        ; Refresh
                          1800        ; Retry
                          604800      ; Expire
                          86400       ; Minimum TTL
                          )
```

## Service Discovery Records

### SRV Record (Service Locator)
**Type Code:** 33
**Purpose:** Locates services within a domain
**Example:**
```
_sip._tcp.example.com  300  IN  SRV  10 5 5060 sip.example.com
```

### NAPTR Record (Name Authority Pointer)
**Type Code:** 35
**Purpose:** Enables dynamic delegation discovery
**Example:**
```
example.com  300  IN  NAPTR  10 100 "s" "SIP+D2U" "" _sip._udp.example.com
```

### HTTPS Record (HTTPS Service Binding)
**Type Code:** 65
**Purpose:** Provides HTTPS configuration and upgrade hints
**Example:**
```
example.com  300  IN  HTTPS  1 . alpn=h2,h3
```

### SVCB Record (Service Binding)
**Type Code:** 64
**Purpose:** General service parameter binding
**Example:**
```
example.com  300  IN  SVCB  1 example.com alpn=h2 key=value
```

## Security Records

### CAA Record (Certification Authority Authorization)
**Type Code:** 257
**Purpose:** Restricts which CAs can issue certificates
**Example:**
```
example.com  300  IN  CAA  0 issue "letsencrypt.org"
example.com  300  IN  CAA  0 issuewild "comodo.com"
```

### DNSKEY Record (DNSSEC Public Key)
**Type Code:** 48
**Purpose:** Stores DNSSEC public keys
**Example:**
```
example.com  300  IN  DNSKEY  256 3 8 AwEAAabc...
```

### DS Record (Delegation Signer)
**Type Code:** 43
**Purpose:** Verifies DNSSEC keys in parent zones
**Example:**
```
example.com  300  IN  DS  12345 8 2 abc123...
```

### RRSIG Record (DNSSEC Signature)
**Type Code:** 46
**Purpose:** Contains DNSSEC signatures for resource records
**Example:**
```
example.com  300  IN  RRSIG  A 8 2 3600 20240101000000 20231201000000 12345 example.com ...
```

### NSEC Record (Next Secure)
**Type Code:** 47
**Purpose:** DNSSEC proof of non-existence
**Example:**
```
a.example.com  300  IN  NSEC  b.example.com A NS SOA MX RRSIG NSEC DNSKEY
```

### NSEC3 Record (Hashed Next Secure)
**Type Code:** 50
**Purpose:** Privacy-preserving DNSSEC proof of non-existence
**Example:**
```
abc123.example.com  300  IN  NSEC3 1 1 10 ABCDEF abc456.example.com A RRSIG
```

### SSHFP Record (SSH Fingerprint)
**Type Code:** 44
**Purpose:** Stores SSH host key fingerprints
**Example:**
```
example.com  300  IN  SSHFP  2 1 abc123def456...
```

### TLSA Record (TLS Certificate Association)
**Type Code:** 52
**Purpose:** Associates certificates with domain names (DANE)
**Example:**
```
_443._tcp.example.com  300  IN  TLSA  3 0 1 abc123...
```

## Special Purpose Records

### PTR Record (Pointer)
**Type Code:** 12
**Purpose:** Reverse DNS (IP address to hostname)
**Example:**
```
34.216.184.93.in-addr.arpa  300  IN  PTR  example.com
```

### HINFO Record (Host Information)
**Type Code:** 13
**Purpose:** Describes hardware and software of a host
**Example:**
```
example.com  300  IN  HINFO  "Intel Xeon" "Ubuntu Linux"
```

### LOC Record (Location)
**Type Code:** 29
**Purpose:** Geographic location coordinates
**Example:**
```
example.com  300  IN  LOC  37 23 30.000 N 122 1 48.000 W 10.00m 1m 100m 1m
```

### URI Record (Uniform Resource Identifier)
**Type Code:** 256
**Purpose:** Stores URIs for redirection
**Example:**
```
example.com  300  IN  URI  10 1 "https://www.example.com/"
```

## Legacy Records

### AFSDB Record (AFS Database)
**Type Code:** 18
**Purpose:** Locates AFS database servers
**Example:**
```
example.com  300  IN  AFSDB  1 afsdb.example.com
```

### CERT Record (Certificate)
**Type Code:** 37
**Purpose:** Stores public key certificates
**Example:**
```
example.com  300  IN  CERT  1 1 1 abc123...
```

### KEY Record (Key)
**Type Code:** 25
**Purpose:** Stores public keys (legacy DNSSEC)
**Example:**
```
example.com  300  IN  KEY  512 3 1 abc123...
```

### OPT Record (Option)
**Type Code:** 41
**Purpose:** DNS extensions (EDNS)
**Example:**
```
.  0  IN  OPT  4096
```

## Record Type Usage Guide

### For Basic Domain Resolution
- **A** and **AAAA** records for IP addresses
- **CNAME** records for aliases

### For Email Configuration
- **MX** records for mail servers
- **TXT** records for SPF, DKIM, DMARC

### For Security Research
- **DNSKEY**, **DS**, **RRSIG** for DNSSEC analysis
- **NSEC**, **NSEC3** for zone enumeration
- **CAA** for certificate authority restrictions

### For Service Discovery
- **SRV** records for service location
- **NAPTR** for dynamic delegation
- **HTTPS**, **SVCB** for modern protocols

### For Reverse Engineering
- **PTR** records for reverse DNS
- **SOA** for zone administrative data
- **NS** for authoritative servers

This comprehensive reference covers all DNS record types supported by RDNSx, enabling thorough DNS analysis and security research.