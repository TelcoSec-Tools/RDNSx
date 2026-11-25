# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- CDN detection reports a CDN only on direct evidence (CNAME suffix, CDN edge AS, published edge ranges); cloud hosting alone no longer counts, and the TTL and resolver-timing signals are gone
- The built-in provider IP table (which had wrong and overlapping ranges) is replaced by Cloudflare's and Fastly's published ranges, used only when the live ASN lookup is unavailable
- CNAME provider matching uses whole-label suffixes (S3, `googlehosted.com` and `azurewebsites.net` are no longer called CDNs)
- `retries` now works: the per-resolver timeout covers all attempts
- Zone walking continues across delegations and recognises synthesized minimal NSEC ("black lies"), which DNSSEC analysis no longer reports as walkable
- Zone transfers that stop before the closing SOA are flagged as incomplete; skipped record types are counted
- Wildcard filtering also drops wildcard CNAME chains; wildcard analysis reports which record types the wildcard does not answer instead of invalid-name "bypass" probes
- `query` streams: input is read lazily and results are written as each domain completes (`--stream` is now a no-op)
- `query` prints errors even with `--silent` and exits non-zero when every query failed; unknown `-t` types and `--rcode` names are errors
- `query --asn` is implemented (origin AS, prefix, registry country)
- `passive-dns` no longer sends active queries; SPF/DMARC analysis is run and reported (lookup count, `+all`, `?all`, `ptr`, several SPF records, `p=none`, DMARC parent-domain fallback)
- Exports work for `bruteforce`, `ptr` and zone transfers, not only `query`
- `enumerate` uses `--threads` unless `--concurrent` is given; `--no-asn-lookup` keeps CDN detection local
- Server fingerprinting tests TCP with a real DNS query; LOC and URI records are decoded; AFSDB can be queried; OPT is no longer offered as a query type
- Response codes YXDOMAIN, YXRRSET, NXRRSET, NOTAUTH, NOTZONE are reported by name instead of as SERVFAIL
- README and docs: install from git or GHCR (the crates.io and Docker Hub commands did not work), unsupported performance claims removed, third-party lookups documented; the CLI crate declares a version for its `rdnsx-core` dependency so it can be published
- Wildcard analysis detects wildcards served from round-robin pools (different IPs per name)
- Response codes are now reported: NXDOMAIN, NODATA and SERVFAIL are kept apart, and `--rcode` prints negative answers (`name [NXDOMAIN]`)
- Resolver failover: SERVFAIL, REFUSED and timeouts move on to the next resolver instead of failing the query
- CNAME chains: every record is labelled with its real owner name and type
- Zone transfer finds the zone's nameservers itself and tries every address of each one
- DNSSEC analysis queries DNSKEY/DS at the right names, checks that a DS matches a DNSKEY and runs real chain validation
- NSEC zone walking follows the chain from the apex, with a configurable limit and a stop reason
- DKIM checks query `<selector>._domainkey.<domain>` for about 30 common selectors
- Server fingerprinting really probes EDNS, CHAOS `version.bind`/`hostname.bind`/`id.server`, open recursion, DNSSEC and TCP
- ASN lookups use Team Cymru DNS and RIPEstat (BGPView as fallback); no more invented ASN or country data
- Wildcard detection only reports a wildcard when random names actually resolve, and filtering is per IP
- Bruteforce streams with bounded concurrency and filters wildcard answers by default (`--no-wildcard-filter` to turn off)
- PTR lookups use bounded concurrency and separate "no record" from "failed"
- The rate limit is enforced once, in the resolver pool
- `--silent` hides the banner and progress only; results are always printed
- Domains given as arguments no longer make the CLI wait on stdin
- A broken config file is an error instead of being silently replaced by defaults
- crt.sh errors are reported instead of hidden; passive results list `source_errors`

### Added
- Global `--timeout`, `-r/--resolvers`, `--rate-limit` and `--threads` options
- `RDNSX_*` environment variable overrides, including exporter credentials
- Cargo features for each exporter, so the library builds without database clients
- Offline tests against an in-process mock DNS server; network tests are `#[ignore]` and run in CI with `--include-ignored`
- `Cargo.lock` is committed and builds use `--locked`

### Changed
- Upgraded hickory-resolver to 0.26 (TLS/HTTPS via ring and webpki roots)
- Dependency updates: rand 0.10, toml 1, thiserror 2, dashmap 6, ipnetwork 0.21, criterion 0.8
- Minimum supported Rust version is 1.94
- CI: clippy on all targets, a `--no-default-features` check, MSRV check, fixed Docker paths, macOS builds on Apple Silicon
- Removed the duplicate `pages.yml` workflow and the stray `check_output.txt`

### Added
- Initial Rust rewrite of DNSx with all original features
- Async/await DNS resolution with tokio
- Support for all DNS record types (A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV)
- Custom DNS resolvers with failover and load balancing
- Subdomain bruteforcing with wordlist support
- Wildcard DNS detection and filtering
- Reverse DNS (PTR) queries for IP ranges
- Export to Elasticsearch with bulk indexing
- Export to MongoDB with bulk inserts
- CLI interface with comprehensive options
- Library API for embedding in other Rust projects
- GitHub Actions CI/CD pipeline
- Comprehensive documentation and examples

### Technical Improvements
- Zero unsafe code blocks (pure safe Rust)
- Type-safe DNS record handling
- Efficient memory usage with streaming I/O
- Configurable concurrency limits
- Connection pooling and reuse
- Batch processing for database exports
- Structured error handling with thiserror
- Comprehensive test coverage