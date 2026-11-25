# RDNSx

<div align="center">

**A fast, multi-purpose DNS toolkit written in Rust**

[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![GitHub Stars](https://img.shields.io/github/stars/TelcoSec-Tools/RDNSx?style=for-the-badge)](https://github.com/TelcoSec-Tools/RDNSx/stargazers)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)](https://github.com/TelcoSec-Tools/RDNSx/pkgs/container/rdnsx)

[Documentation](https://rdnsx.telcosec.net/) | [Quick Start](https://rdnsx.telcosec.net/guide/quick-start) | [Report an Issue](https://github.com/TelcoSec-Tools/RDNSx/issues)

</div>

RDNSx is a DNS enumeration, reconnaissance and analysis toolkit for security researchers, network administrators and developers. It is a Rust rewrite of [DNSx](https://github.com/projectdiscovery/dnsx), built on async I/O for high-concurrency resolution, and ships both as a CLI and as an embeddable library (`rdnsx-core`).

## Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Library Usage](#library-usage)
- [Reference](#reference)
- [Contributing](#contributing)
- [TelcoSec Academy](#telcosec-academy)
- [License](#license)

## Features

**Resolution**
- Async, concurrent DNS queries with configurable concurrency and a fixed queries-per-second rate limit
- Results are written as they arrive, so large input lists don't need to fit in memory
- 27 record types, including DNSSEC, DANE and service-binding records
- IPv4 and IPv6 resolution

**Reconnaissance**
- Subdomain bruteforcing from wordlists, with wildcard detection (A, AAAA and CNAME wildcards)
- ASN enumeration and ASN-driven reverse (PTR) lookups
- 11 enumeration techniques: zone transfer, email security (SPF, DMARC, DKIM), DNSSEC analysis and zone walking, passive DNS, server fingerprinting and more

**Integration**
- JSON output for pipelines
- Optional export to Elasticsearch, MongoDB and Cassandra (records from `query`, `bruteforce`, `ptr` and zone transfers)
- TOML configuration file
- Docker images and a Docker Compose stack

## Installation

Requires **Rust 1.94+** ([rustup.rs](https://rustup.rs/)) unless you use Docker.

**With cargo** (RDNSx is not published on crates.io yet)
```bash
cargo install --git https://github.com/TelcoSec-Tools/RDNSx rdnsx
```

**From source**
```bash
git clone https://github.com/TelcoSec-Tools/RDNSx.git
cd RDNSx
cargo build --release
# Binary: target/release/rdnsx (rdnsx.exe on Windows)
```

**Docker**
```bash
# Pre-built image (GitHub Container Registry)
docker run --rm ghcr.io/telcosec-tools/rdnsx:latest --help

# Build locally
docker build -f docker/Dockerfile -t rdnsx .

# Mount a config directory
docker run --rm -v $(pwd)/config:/app/config rdnsx --config /app/config/rdnsx.toml query example.com

# Full stack with databases
docker-compose -f docker/docker-compose.yml up
```

**Smaller builds.** The database exporters are optional Cargo features, all enabled by default in the CLI. To build without database drivers:

```bash
cargo build --release -p rdnsx --no-default-features
# or enable one: --features export-elasticsearch | export-mongodb | export-cassandra
```

Library users get no exporters unless they enable the `elasticsearch`, `mongodb` or `cassandra` features of `rdnsx-core`.

## Usage

### Query records

```bash
echo "example.com" | rdnsx query                                 # A records from stdin
rdnsx query --list domains.txt                                   # from a file
rdnsx query --list domains.txt --record-type MX --record-type TXT
rdnsx query example.com --asn                                    # add origin AS, prefix and registry country
rdnsx query --list domains.txt --rcode NXDOMAIN,SERVFAIL         # report negative answers too
```

`rdnsx` exits with a non-zero status when every query failed (no resolver answered), and errors are always printed to stderr, including with `--silent`.

### Bruteforce subdomains

```bash
rdnsx bruteforce --domain example.com --wordlist wordlist.txt
```

### Reverse DNS (PTR)

```bash
rdnsx ptr 192.168.1.0/24     # CIDR range
rdnsx ptr AS15169            # all prefixes announced by an ASN
```

Large ranges are capped to avoid runaway lookups: 10,000 IPs per CIDR and 1,000 IPs per ASN prefix. Up to 50 PTR queries run concurrently.

### Enumeration

```bash
rdnsx enumerate --technique asn-enumeration --target AS15169     # "AS" prefix optional
rdnsx enumerate --technique comprehensive --target example.com
```

| Technique | Description |
|-----------|-------------|
| `zone-transfer` | Attempt AXFR against the zone's authoritative nameservers (or `--axfr-servers`); partial transfers are flagged |
| `email-security` | Enumerate and check SPF, DMARC (with parent-domain fallback) and DKIM records |
| `cdn-detection` | Detect a CDN from the CNAME chain, the addresses' origin AS and published edge ranges |
| `ipv6-enumeration` | Enumerate IPv6 deployment and addresses |
| `dnssec-enumeration` | Analyze DNSSEC configuration |
| `dnssec-zone-walking` | Walk the zone via NSEC records (across delegations; stops on NSEC3 and synthesized NSEC) |
| `wildcard-analysis` | Detect wildcards and find record types that tell real names from wildcard matches |
| `passive-dns` | Certificate Transparency names from crt.sh; sends no DNS queries for the target |
| `server-fingerprint` | Query a server directly for version.bind, open recursion, EDNS, DNSSEC and TCP |
| `asn-enumeration` | Enumerate ASN information and associated IP ranges |
| `comprehensive` | Run all techniques |

**Third-party lookups.** `cdn-detection` and `query --asn` look up address owners with the [Team Cymru IP-to-ASN](https://www.team-cymru.com/ip-asn-mapping) DNS service, so the addresses are sent (as DNS names) through your resolvers to `asn.cymru.com`. The country it returns is the RIR registration country of the prefix, not where the server is. Use `enumerate --no-asn-lookup` to keep CDN detection local. `passive-dns` queries crt.sh, and `asn-enumeration` queries RIPEstat (BGPView as a fallback).

## Configuration

Create an example config, then pass it to any command:

```bash
rdnsx --create-config config/rdnsx.toml
rdnsx --config config/rdnsx.toml query example.com
```

The file covers resolvers, performance tuning and database exports. Exports run automatically for any backend marked `enabled`:

```toml
[resolvers]
servers = ["8.8.8.8", "1.1.1.1"]
timeout = 5
retries = 3

[performance]
threads = 100
rate_limit = 0

[export.elasticsearch]
enabled = true
url = "http://localhost:9200"
index = "dns-records"

[export.mongodb]
enabled = true
url = "mongodb://localhost:27017"
database = "dnsx"

[export.cassandra]
enabled = true
contact_points = ["127.0.0.1:9042"]
username = "cassandra"
password = "password"
```

## Library Usage

```rust
use rdnsx_core::{DnsxClient, RecordType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = DnsxClient::new()?;

    for record in client.query("example.com", RecordType::A).await? {
        println!("{}", record);
    }

    for ip in client.lookup_ipv4("example.com").await? {
        println!("{}", ip);
    }

    Ok(())
}
```

## Reference

### Global options

| Option | Description |
|--------|-------------|
| `-c, --config` | Configuration file path |
| `-o, --output` | Output file |
| `--json` | JSON output |
| `--silent` | Hide the banner and progress messages (results are still printed) |
| `--timeout`, `-r/--resolvers`, `--rate-limit`, `--threads` | Override the config file |
| `--create-config` | Write an example configuration file |

Run `rdnsx <command> --help` for command-specific options.

### Supported record types

| Category | Types |
|----------|-------|
| Addressing and aliases | A, AAAA, CNAME, DNAME, PTR |
| Zone and delegation | NS, SOA |
| Mail and text | MX, TXT |
| Services | SRV, NAPTR, URI, HTTPS, SVCB, AFSDB |
| Security and certificates | CAA, CERT, SSHFP, TLSA |
| DNSSEC | DNSKEY, DS, RRSIG, NSEC, NSEC3, KEY |
| Other | HINFO, LOC |

LOC and URI are decoded; AFSDB, CERT and DNAME answers are printed in RFC 3597 generic form.

### Performance

There are no published end-to-end benchmarks. Throughput depends mostly on the resolvers, the `--threads` setting and `--rate-limit`. `cargo bench -p rdnsx-core` runs micro-benchmarks of record parsing and caching.

Full documentation: [Installation](https://rdnsx.telcosec.net/guide/installation) | [Quick Start](https://rdnsx.telcosec.net/guide/quick-start) | [CLI Reference](https://rdnsx.telcosec.net/api/cli-reference) | [Record Types](https://rdnsx.telcosec.net/guide/dns-records) | [Configuration](https://rdnsx.telcosec.net/guide/configuration)

## Contributing

Bug reports, feature requests, documentation fixes and pull requests are welcome.

- [Open a bug report](https://github.com/TelcoSec-Tools/RDNSx/issues/new?template=bug_report.md)
- [Request a feature](https://github.com/TelcoSec-Tools/RDNSx/issues/new?template=feature_request.md)
- [Join the discussion](https://github.com/TelcoSec-Tools/RDNSx/discussions)

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. To set up a development build:

```bash
git clone https://github.com/TelcoSec-Tools/RDNSx.git
cd RDNSx
cargo build
cargo test --workspace                       # offline tests
cargo test --workspace -- --include-ignored  # plus tests that need public DNS
```

## TelcoSec Academy

RDNSx is maintained by TelcoSec. Want to go further with DNS reconnaissance and telecom security? **TelcoSec Academy** offers hands-on training for security researchers and network engineers.

## License

RDNSx is released under the [MIT License](LICENSE).

---

<div align="center">

Maintained by [TelcoSec](https://github.com/TelcoSec-Tools)

</div>
