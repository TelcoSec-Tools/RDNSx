<div align="center">

# RDNSx

**DNS reconnaissance and analysis toolkit for security research, written in Rust**

[![CI](https://github.com/TelcoSec-Tools/RDNSx/actions/workflows/ci.yml/badge.svg)](https://github.com/TelcoSec-Tools/RDNSx/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 1.94+](https://img.shields.io/badge/rust-1.94%2B-orange.svg)](https://www.rust-lang.org/)
[![Container](https://img.shields.io/badge/container-ghcr.io-2496ED.svg)](https://github.com/TelcoSec-Tools/RDNSx/pkgs/container/rdnsx)

[Documentation](https://rdnsx.telcosec.net/) · [Quick start](https://rdnsx.telcosec.net/guide/quick-start) · [CLI reference](https://rdnsx.telcosec.net/api/cli-reference) · [Report an issue](https://github.com/TelcoSec-Tools/RDNSx/issues)

</div>

---

RDNSx resolves, enumerates and analyses DNS at scale. It combines a high-concurrency resolver with research techniques that usually need several separate tools: zone transfer checks, DNSSEC analysis and NSEC zone walking, email-authentication audits, CDN and origin attribution, wildcard-aware subdomain bruteforcing, ASN-driven reverse DNS and direct server fingerprinting.

It ships as a single CLI (`rdnsx`) and as an embeddable library (`rdnsx-core`), and is maintained by [TelcoSec](https://github.com/TelcoSec-Tools) for telecom and DNS security research.

> **Use responsibly.** Run active techniques (zone transfers, bruteforcing, zone walking, fingerprinting) only against infrastructure you own or are authorised to test.

## Contents

- [Highlights](#highlights)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Enumeration techniques](#enumeration-techniques)
- [Output and exit codes](#output-and-exit-codes)
- [Configuration](#configuration)
- [Database export](#database-export)
- [Library usage](#library-usage)
- [Data sources and privacy](#data-sources-and-privacy)
- [Supported record types](#supported-record-types)
- [Development](#development)
- [Contributing and security](#contributing-and-security)
- [TelcoSec Academy](#telcosec-academy)
- [License](#license)

## Highlights

| Area | What RDNSx does |
|------|-----------------|
| Resolution | Async queries over UDP with TCP fallback, round-robin across resolvers, failover on SERVFAIL/REFUSED/timeouts, real response codes (NXDOMAIN, NODATA, SERVFAIL...), optional fixed queries-per-second rate limit and response cache |
| Scale | Input is read lazily and results are written as each name completes, so large lists don't need to fit in memory |
| Subdomains | Wordlist bruteforcing with `FUZZ` placeholders, and wildcard filtering for A, AAAA and CNAME wildcards |
| DNSSEC | DNSKEY/DS inventory, DS-to-DNSKEY matching, validation from the IANA root trust anchor, deprecated-algorithm checks, NSEC zone walking across delegations, NSEC3 and synthesized-NSEC detection |
| Zone transfer | AXFR against every address of every authoritative nameserver, with incomplete transfers flagged |
| Email security | SPF, DMARC and DKIM discovery and checks: `+all`/`?all`, `ptr`, multiple SPF records, the 10-lookup limit, `p=none`, DMARC parent-domain fallback |
| Attribution | CDN detection from CNAME chains, origin AS and published edge ranges; origin AS, prefix and registry country per address |
| Networks | ASN prefix enumeration (RIPEstat) and PTR sweeps over CIDR ranges or whole ASNs |
| Servers | Direct fingerprinting: CHAOS `version.bind`/`hostname.bind`/`id.server`, open recursion, EDNS(0), DNSSEC, TCP |
| Integration | JSON Lines output, Elasticsearch, MongoDB and Cassandra export, TOML config, environment overrides, container image |

## Installation

RDNSx needs **Rust 1.94 or newer** ([rustup.rs](https://rustup.rs/)) unless you use the container image.

**With Cargo** (RDNSx is not yet published on crates.io):

```bash
cargo install --git https://github.com/TelcoSec-Tools/RDNSx rdnsx
```

**From source:**

```bash
git clone https://github.com/TelcoSec-Tools/RDNSx.git
cd RDNSx
cargo build --release
./target/release/rdnsx --version
```

**Container (GitHub Container Registry):**

```bash
docker run --rm ghcr.io/telcosec-tools/rdnsx:latest --help

# With a configuration file
docker run --rm -v "$(pwd)/config:/app/config" \
  ghcr.io/telcosec-tools/rdnsx:latest --config /app/config/rdnsx.toml query example.com
```

`docker/docker-compose.yml` starts RDNSx together with Elasticsearch, MongoDB and Cassandra.

**Smaller builds.** The CLI enables all database exporters by default. To build without database drivers, or with just one:

```bash
cargo build --release -p rdnsx --no-default-features
cargo build --release -p rdnsx --no-default-features --features export-elasticsearch
# also: export-mongodb, export-cassandra
```

## Quick start

```bash
# A records for one name
rdnsx query example.com

# Several record types for a list of names, as JSON Lines
rdnsx --json query --list domains.txt -t A -t AAAA -t MX -t TXT

# Report NXDOMAIN and SERVFAIL answers instead of hiding them
rdnsx query --list domains.txt --rcode NXDOMAIN,SERVFAIL

# Add the origin AS, prefix and registry country of each address
rdnsx query example.com --asn

# Bruteforce subdomains (wildcard answers are filtered automatically)
rdnsx bruteforce -d example.com -w wordlist.txt

# Reverse DNS over a range, or over every prefix an ASN announces
rdnsx ptr 192.0.2.0/24
rdnsx ptr AS64500

# Run every enumeration technique against a domain
rdnsx enumerate -t comprehensive --target example.com
```

## Commands

| Command | Purpose |
|---------|---------|
| `query` | Resolve names from arguments, `--list <file>` or stdin, for any [supported record type](#supported-record-types) (`-t TYPE`, repeatable, or flags such as `--mx`) |
| `bruteforce` | Generate candidates from a wordlist (`-w file`, `-w a,b,c` or `-w -` for stdin); `--placeholder` positions the word, as in `FUZZ.dev.example.com` |
| `ptr` | PTR lookups for an IP, a CIDR range (capped at 10,000 addresses) or an ASN (capped at 1,000 addresses per prefix) |
| `enumerate` | The research techniques below (`-t <technique> --target <domain, server or ASN>`) |

Options that apply to every command:

| Option | Description |
|--------|-------------|
| `-r, --resolvers <LIST>` | Resolvers to use, comma-separated (`8.8.8.8`, `9.9.9.9:53`, `[2001:db8::53]:53`) |
| `--threads <N>` | Concurrent queries |
| `--rate-limit <QPS>` | Maximum queries per second (0 = unlimited) |
| `--timeout <SECONDS>` | Per-attempt query timeout |
| `-c, --config <FILE>` | Configuration file |
| `-o, --output <FILE>` | Write results to a file instead of stdout |
| `--json` | JSON output |
| `--silent` | Hide the banner and progress messages |
| `--create-config <FILE>` | Write an example configuration file and exit |

Useful `query` options: `--resp-only` (values only), `-w, --wildcard-domain <DOMAIN>` (drop wildcard answers under a zone), `--cache` (with `--cache-ttl` and `--cache-size`).

Run `rdnsx <command> --help` for the full list.

## Enumeration techniques

```bash
rdnsx enumerate -t <technique> --target <target> [options]
```

| Technique | What it does |
|-----------|--------------|
| `zone-transfer` | AXFR over TCP against each authoritative nameserver address (or `--axfr-servers`). Reports successful, refused and incomplete transfers |
| `dnssec-enumeration` | DNSKEY and DS records, RRSIGs and the denial-of-existence scheme from an authoritative server, DS-to-DNSKEY matching and full validation from the root trust anchor |
| `dnssec-zone-walking` | Follows the NSEC chain from the apex, including across delegations (`--max-names`, default 1000). Detects NSEC3 and synthesized minimal NSEC ("black lies", compact denial), which cannot be walked |
| `email-security` | SPF, DMARC (with parent-domain fallback) and about 30 common DKIM selectors, with findings and recommendations |
| `cdn-detection` | Reports a CDN only on direct evidence: a CNAME to a known CDN, an address announced by a CDN edge network, or an address in published edge ranges. Cloud hosting is reported as hosting, not as a CDN |
| `wildcard-analysis` | Detects wildcards and lists the record types the wildcard does not answer, which tell real names apart from wildcard matches |
| `passive-dns` | Subdomains from Certificate Transparency logs (crt.sh), with first and last logged dates. Sends no DNS queries for the target |
| `server-fingerprint` | Queries servers directly (`--fingerprint-servers`, or the zone's nameservers) for identity banners, open recursion, EDNS, DNSSEC and TCP |
| `ipv6-enumeration` | IPv4 and IPv6 addresses and the dual-stack status of a name |
| `asn-enumeration` | Announced IPv4 and IPv6 prefixes and the holder of an ASN (`--target AS15169` or `15169`) |
| `comprehensive` | All of the above for one domain |

Enumeration options: `--nameservers` (recursive resolvers for this run), `--axfr-servers`, `--fingerprint-servers`, `--max-names`, `--concurrent` (defaults to `--threads`) and `--no-asn-lookup`.

## Output and exit codes

Plain output prints one answer per line, as `name [value]`, or `name [NXDOMAIN]` for negative answers shown with `--rcode`. `--json` prints one JSON object per record (JSON Lines), and pretty-printed JSON documents for `enumerate`. Results go to stdout or `--output`. Progress messages and errors go to stderr, and errors are shown even with `--silent`.

`rdnsx` exits with status `0` on success and a non-zero status when the arguments are invalid or when every query failed because no resolver answered.

## Configuration

```bash
rdnsx --create-config config/rdnsx.toml
rdnsx --config config/rdnsx.toml query example.com
```

```toml
[resolvers]
servers = ["8.8.8.8", "1.1.1.1"]
timeout = 5        # seconds per attempt
retries = 3        # attempts per resolver

[performance]
threads = 100      # concurrent queries
rate_limit = 0     # queries per second, 0 = unlimited
```

Precedence, from highest to lowest: command-line options, `RDNSX_*` environment variables, the configuration file (`--config` or `RDNSX_CONFIG`), built-in defaults.

| Variable | Setting |
|----------|---------|
| `RDNSX_CONFIG` | Configuration file path |
| `RDNSX_RESOLVERS` | Resolvers, comma-separated |
| `RDNSX_TIMEOUT`, `RDNSX_RETRIES` | Timeout and attempts |
| `RDNSX_THREADS`, `RDNSX_RATE_LIMIT` | Concurrency and rate limit |
| `RDNSX_ES_URL`, `RDNSX_ES_INDEX` | Elasticsearch |
| `RDNSX_MONGODB_URL` | MongoDB |
| `RDNSX_CASSANDRA_CONTACT_POINTS`, `RDNSX_CASSANDRA_USERNAME`, `RDNSX_CASSANDRA_PASSWORD` | Cassandra |

## Database export

Every backend marked `enabled` in the configuration receives the records produced by `query`, `bruteforce`, `ptr` and zone transfers. Elasticsearch and MongoDB receive records in batches of `export.batch_size`. For Cassandra, `query` takes `--cassandra-batch-size` and `--cassandra-workers`.

```toml
[export]
batch_size = 1000

[export.elasticsearch]
enabled = true
url = "http://localhost:9200"
index = "dns-records"

[export.mongodb]
enabled = true
url = "mongodb://localhost:27017"
database = "dnsx"
collection = "records"

[export.cassandra]
enabled = true
contact_points = ["127.0.0.1:9042"]
keyspace = "dnsx"
table = "records"
# Prefer RDNSX_CASSANDRA_USERNAME / RDNSX_CASSANDRA_PASSWORD over storing credentials here
```

If a backend is enabled but the binary was built without its feature, RDNSx stops with an error instead of silently skipping the export.

## Library usage

```toml
[dependencies]
rdnsx-core = { git = "https://github.com/TelcoSec-Tools/RDNSx" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust
use rdnsx_core::{DnsxClient, RecordType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = DnsxClient::new()?;

    // Answers together with the response code and the resolver that answered
    let response = client.query_response("example.com", RecordType::Mx).await?;
    println!("{} via {}", response.response_code, response.resolver);
    for record in response.records {
        println!("{record}");
    }

    Ok(())
}
```

`DnsEnumerator` exposes every enumeration technique (`zone_transfer`, `dnssec_zone_walking`, `cdn_detection`, `email_security_enumeration`, ...), and `rdnsx_core::raw` sends single queries to a chosen server with full access to the response. Exporters are behind the `elasticsearch`, `mongodb` and `cassandra` features of `rdnsx-core`.

## Data sources and privacy

Some features send data to third parties. Keep this in mind for engagements where your targets must stay confidential.

| Feature | Service | What is sent |
|---------|---------|--------------|
| `query --asn`, `cdn-detection` | [Team Cymru IP-to-ASN](https://www.team-cymru.com/ip-asn-mapping) over DNS | Each address, as a name under `asn.cymru.com`, through your resolvers. Turn it off for CDN detection with `--no-asn-lookup` |
| `passive-dns` | [crt.sh](https://crt.sh/) | The target domain |
| `asn-enumeration`, `ptr AS...` | [RIPEstat](https://stat.ripe.net/), BGPView as a fallback | The ASN |

The country returned by Team Cymru is the RIR registration country of the prefix, not the physical location of the server, and anycast networks usually report a single country.

## Supported record types

| Category | Types |
|----------|-------|
| Addresses and aliases | A, AAAA, CNAME, DNAME, PTR |
| Zone and delegation | NS, SOA |
| Mail and text | MX, TXT |
| Services | SRV, NAPTR, URI, HTTPS, SVCB, AFSDB |
| Security and certificates | CAA, CERT, SSHFP, TLSA |
| DNSSEC | DNSKEY, DS, RRSIG, NSEC, NSEC3, KEY |
| Other | HINFO, LOC |

LOC and URI answers are decoded. AFSDB, CERT and DNAME answers are printed in the RFC 3597 generic format. RRSIG and NSEC answers depend on your resolver, so use `enumerate` for DNSSEC work, which queries authoritative servers directly.

## Development

```bash
cargo build --workspace
cargo test --workspace                        # offline tests against an in-process DNS server
cargo test --workspace -- --include-ignored   # plus tests that need public DNS
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all
cargo bench -p rdnsx-core                     # parsing and cache micro-benchmarks
```

The workspace has two crates: `rdnsx-core` (resolver pool, query engine, enumeration techniques, exporters) and `rdnsx` (the CLI). There are no published end-to-end throughput figures. Performance depends mostly on the resolvers, `--threads` and `--rate-limit`.

## Contributing and security

Bug reports, feature requests and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](.github/CODE_OF_CONDUCT.md), and use the [bug report](https://github.com/TelcoSec-Tools/RDNSx/issues/new?template=bug_report.md) or [feature request](https://github.com/TelcoSec-Tools/RDNSx/issues/new?template=feature_request.md) templates. Changes are listed in [CHANGELOG.md](CHANGELOG.md).

Please report security vulnerabilities in RDNSx privately through [GitHub security advisories](https://github.com/TelcoSec-Tools/RDNSx/security/advisories/new) rather than in public issues.

## TelcoSec Academy

RDNSx is developed by TelcoSec. **[TelcoSec Academy](https://app.telcosec.net/)** offers hands-on training in DNS reconnaissance and telecom security for security researchers and network engineers.

## License

RDNSx is released under the [MIT License](LICENSE).
