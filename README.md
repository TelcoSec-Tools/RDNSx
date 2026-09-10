# RDNSx ⚡

<div align="center">

**Blazing Fast, Multi-Purpose DNS Toolkit in Rust**

[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![GitHub Stars](https://img.shields.io/github/stars/TelcoSec-Tools/RDNSx?style=for-the-badge)](https://github.com/TelcoSec-Tools/RDNSx/stargazers)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)](https://hub.docker.com/r/telcosec/rdnsx)

*High-performance DNS enumeration, reconnaissance, and analysis toolkit for security researchers and network administrators*

[📖 Documentation](https://rdnsx.telcosec.net/) • [🚀 Quick Start](https://rdnsx.telcosec.net/guide/quick-start) • [🐛 Report Issues](https://github.com/TelcoSec-Tools/RDNSx/issues)

</div>

---

RDNSx is a high-performance, feature-rich DNS toolkit written in Rust, designed for security researchers, network administrators, and developers. Leveraging Rust's memory safety and async capabilities, RDNSx delivers exceptional performance while maintaining type safety and reliability.

This project is a complete rewrite and enhancement of the popular [DNSx](https://github.com/projectdiscovery/dnsx) tool, optimized for modern async programming patterns and enterprise-grade DNS analysis.

## ✨ Key Features

### 🚀 Performance & Speed
- **⚡ Lightning Fast**: Async/await concurrency for maximum performance
- **🔄 Concurrent Processing**: Up to 50+ simultaneous DNS queries
- **🎯 Smart Rate Limiting**: Intelligent throttling to avoid blocking
- **💾 Memory Efficient**: Rust's ownership system ensures optimal memory usage

### 🔍 Comprehensive DNS Analysis
- **📊 27 DNS Record Types**: Complete support for all major record types
- **🏢 ASN Intelligence**: Discover networks for Google, Amazon, Cloudflare, and more
- **🔄 Reverse DNS**: Advanced PTR lookups with ASN integration
- **🌐 IPv4/IPv6 Support**: Full dual-stack DNS resolution

### 🛡️ Security Research Tools
- **🔎 Subdomain Enumeration**: Bruteforce discovery with wordlists
- **🛡️ Wildcard Detection**: Advanced filtering and bypass techniques
- **🔐 DNSSEC Analysis**: Security configuration and zone walking
- **📧 Email Security**: SPF, DMARC, DKIM enumeration

### 🏗️ Enterprise Ready
- **🐳 Container Support**: Docker images for easy deployment
- **🗄️ Database Integration**: Export to Elasticsearch, MongoDB, Cassandra
- **⚙️ Flexible Configuration**: TOML-based config with advanced options
- **📚 Library API**: Embeddable Rust library for custom applications

## 📈 Performance Benchmarks

RDNSx delivers exceptional performance through Rust's async runtime and optimized algorithms:

| Operation | Performance | Notes |
|-----------|-------------|--------|
| **DNS Query (A Record)** | ~2-5ms average | Async concurrent processing |
| **Bulk Resolution (1000 domains)** | <30 seconds | Configurable concurrency |
| **ASN Enumeration** | ~1-3 seconds | Network discovery |
| **Reverse DNS (PTR)** | ~50 concurrent lookups | Smart rate limiting |
| **Memory Usage** | <50MB baseline | Efficient resource utilization |

*Benchmarks performed on standard hardware with 1Gbps connection. Results may vary based on network conditions.*

## 🔧 DNS Record Types

RDNSx supports comprehensive DNS record type querying for thorough network analysis:

| Record Type | Description | Use Case |
|-------------|-------------|----------|
| **A** | IPv4 address record | Maps domain to IP address |
| **AAAA** | IPv6 address record | Maps domain to IPv6 address |
| **CNAME** | Canonical name record | Domain aliases and redirects |
| **MX** | Mail exchange record | Email server configuration |
| **TXT** | Text record | SPF, DKIM, DMARC, and custom data |
| **NS** | Name server record | Authoritative DNS servers |
| **SOA** | Start of authority | Zone administrative information |
| **PTR** | Pointer record | Reverse DNS (IP to hostname) |
| **SRV** | Service locator record | Service discovery (SIP, XMPP, etc.) |
| **CAA** | Certification authority authorization | SSL certificate restrictions |
| **DNSKEY** | DNSSEC public key | DNSSEC key storage |
| **DS** | Delegation signer | DNSSEC key verification |
| **RRSIG** | DNSSEC signature | Resource record signatures |
| **NSEC** | Next secure record | DNSSEC proof of non-existence |
| **NSEC3** | Hashed next secure record | DNSSEC privacy protection |
| **HINFO** | Host information | Hardware/software descriptions |
| **HTTPS** | HTTPS service binding | HTTP/2 and HTTPS configuration |
| **NAPTR** | Name authority pointer | Dynamic delegation discovery |
| **SSHFP** | SSH fingerprint | SSH host key verification |
| **SVCB** | Service binding | Service parameters (HTTPS upgrade) |
| **TLSA** | TLS certificate association | DANE (DNS-based Authentication) |
| **URI** | Uniform resource identifier | URI redirects |
| **AFSDB** | AFS database location | Andrew File System |
| **CERT** | Certificate record | Public key certificates |
| **DNAME** | Delegation name | Domain redirection |
| **KEY** | Key record | Public keys for DNSSEC |
| **LOC** | Location record | Geographic coordinates |
| **OPT** | Option record | EDNS extensions |

## 📚 Documentation

Complete documentation is available at **[https://rdnsx.telcosec.net/](https://rdnsx.telcosec.net/)**

### Quick Links
- [📦 Installation Guide](https://rdnsx.telcosec.net/guide/installation)
- [🚀 Quick Start Tutorial](https://rdnsx.telcosec.net/guide/quick-start)
- [📖 CLI Reference](https://rdnsx.telcosec.net/api/cli-reference)
- [🔍 DNS Record Types](https://rdnsx.telcosec.net/guide/dns-records)
- [⚙️ Configuration Guide](https://rdnsx.telcosec.net/guide/configuration)

## 📋 Prerequisites

- **Rust 1.70+** - Install from [rustup.rs](https://rustup.rs/)
- **Cargo** - Rust's package manager (comes with Rust)
- **Git** - For cloning the repository

### Quick Rust Installation

**Linux/macOS:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

**Windows (PowerShell):**
```powershell
Invoke-WebRequest -Uri https://win.rustup.rs/x86_64 -OutFile rustup-init.exe
.\rustup-init.exe
```

**Verify Installation:**
```bash
rustc --version  # Should show 1.70+
cargo --version  # Should show cargo version
```

## 🚀 Installation

Choose the installation method that best fits your needs:

### ⚡ Quick Install (Recommended)

Install globally from crates.io:
```bash
cargo install rdnsx
```

### 🔨 Build from Source

For the latest features and custom builds:

```bash
# Clone the repository
git clone https://github.com/TelcoSec-Tools/RDNSx.git
cd RDNSx

# Build optimized release binary
cargo build --release

# The binary will be at:
# Linux/macOS: target/release/rdnsx
# Windows: target/release/rdnsx.exe
```

### 🐳 Docker Installation

#### Quick Start with Docker
```bash
# Pull and run
docker run --rm telcosec/rdnsx --help

# Or use the latest version
docker pull telcosec/rdnsx:latest
```

#### Build Custom Docker Image
```bash
# Build from source
docker build -f docker/Dockerfile -t rdnsx .

# Run with volume mount for config
docker run --rm -v $(pwd)/config:/app/config rdnsx --help
```

### Docker Installation

#### Using Pre-built Images
```bash
# Pull from Docker Hub
docker pull telcosec/rdnsx:latest
docker run --rm telcosec/rdnsx --help
```

#### Building from Source
```bash
# Build using provided Dockerfile
docker build -f docker/Dockerfile -t rdnsx .
docker run --rm rdnsx --help
```

#### Docker Compose (Advanced)
For complex deployments with databases:
```bash
# Start full stack with databases
docker-compose -f docker/docker-compose.yml up

# Mount config for persistent settings
docker run --rm -v $(pwd)/config:/app/config rdnsx --config /app/config/rdnsx.toml query example.com
```

## Usage

### Query DNS Records

Query A records for domains from stdin:
```bash
echo "example.com" | rdnsx query
```

Query from a file:
```bash
rdnsx query --list domains.txt
```

Query specific record types:
```bash
rdnsx query --list domains.txt --record-type MX --record-type TXT
```

Use custom configuration:
```bash
rdnsx --config config/rdnsx.toml query example.com
```

### Advanced Enumeration

RDNSx supports comprehensive DNS enumeration techniques for security research and network analysis:

#### ASN Enumeration
Discover IP ranges and network information for Autonomous Systems:
```bash
# Enumerate Google ASN
rdnsx enumerate --technique asn-enumeration --target AS15169

# Works with or without "AS" prefix
rdnsx enumerate --technique asn-enumeration --target 16509
```

#### Comprehensive DNS Analysis
Perform complete DNS enumeration on a target:
```bash
rdnsx enumerate --technique comprehensive --target example.com
```

### Enumeration Techniques

RDNSx provides 11 specialized enumeration techniques for comprehensive DNS reconnaissance:

| Technique | Command | Description |
|-----------|---------|-------------|
| **Zone Transfer** | `zone-transfer` | Attempt DNS zone transfer (AXFR) to retrieve all records |
| **Email Security** | `email-security` | Enumerate SPF, DMARC, DKIM records for email authentication |
| **CDN Detection** | `cdn-detection` | Detect CDN usage and analyze configuration |
| **IPv6 Enumeration** | `ipv6-enumeration` | Enumerate IPv6 deployment and addresses |
| **DNSSEC Analysis** | `dnssec-enumeration` | Analyze DNSSEC configuration and security |
| **DNSSEC Zone Walking** | `dnssec-zone-walking` | Perform DNSSEC zone walking (NSEC enumeration) |
| **Wildcard Analysis** | `wildcard-analysis` | Analyze wildcard DNS configurations and bypass techniques |
| **Passive DNS** | `passive-dns` | Perform passive DNS enumeration using historical data |
| **Server Fingerprint** | `server-fingerprint` | Fingerprint DNS server capabilities and versions |
| **ASN Enumeration** | `asn-enumeration` | Enumerate ASN information and associated IP ranges |
| **Comprehensive** | `comprehensive` | Run all enumeration techniques combined |

### Enhanced Reverse DNS Lookups

RDNSx provides powerful PTR enumeration with ASN integration:

#### ASN-Based PTR Lookups
Use ASN enumeration results for targeted reverse DNS:
```bash
# Lookup PTR records for Google ASN
rdnsx ptr AS15169

# Results include IP ranges automatically discovered from ASN
```

#### Smart IP Range Handling
Large IP ranges are automatically limited to prevent excessive lookups:
```bash
# Large ranges are capped at 10,000 IPs
rdnsx ptr 192.168.0.0/16  # Limited to 10,000 IPs with warning

# Per-prefix limits for ASN ranges
rdnsx ptr AS16509         # Up to 1,000 IPs per prefix
```

#### Concurrent Processing
PTR lookups use concurrent processing for better performance:
```bash
# Up to 50 simultaneous PTR queries
rdnsx ptr 8.8.8.0/24
```

## Configuration

RDNSx uses a TOML configuration file for advanced settings. Configuration files are stored in the `config/` directory:

### Creating Configuration
```bash
# Create example configuration file
rdnsx --create-config config/rdnsx.toml
```

### Using Configuration
```bash
# Use custom configuration with any command
rdnsx --config config/rdnsx.toml query example.com

# Configuration includes resolver settings, performance tuning, and database exports
```

### Configuration Options

The config file supports:
- **DNS Resolvers**: Custom DNS servers with timeout/retry settings
- **Performance**: Concurrency limits and rate limiting
- **Database Exports**: Elasticsearch, MongoDB, and Cassandra configuration

**Example configuration:**
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
```

### Export to Databases

Configure exports in your `rdnsx.toml` config file:

```toml
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

Then run queries with export enabled:
```bash
rdnsx --config config/rdnsx.toml query example.com
```

### Bruteforce Subdomains

```bash
rdnsx bruteforce --domain example.com --wordlist wordlist.txt
```

### Reverse DNS Lookups

```bash
rdnsx ptr 192.168.1.0/24
```

## Library Usage

```rust
use rdnsx_core::{DnsxClient, RecordType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = DnsxClient::new()?;

    // Query A records
    let records = client.query("example.com", RecordType::A).await?;
    for record in records {
        println!("{}", record);
    }

    // Lookup IP addresses
    let ips = client.lookup_ipv4("example.com").await?;
    for ip in ips {
        println!("{}", ip);
    }

    Ok(())
}
```

## Command Line Options

Global options:
- `-c, --config`: Configuration file path
- `-o, --output`: Output file
- `--json`: JSON output format
- `--silent`: Minimal output
- `--create-config`: Create example configuration file

Command-specific options are documented in `--help` for each command.

## Performance

RDNSx is optimized for high-performance DNS resolution:
- Async/await throughout for non-blocking I/O
- Connection pooling and reuse
- Configurable concurrency limits
- Efficient batching for database exports

## 🤝 Community & Contributing

We welcome contributions from the community! Here's how you can get involved:

### Ways to Contribute
- 🐛 **Report Bugs**: Found an issue? [Open a bug report](https://github.com/TelcoSec-Tools/RDNSx/issues/new?template=bug_report.md)
- 💡 **Suggest Features**: Have an idea? [Submit a feature request](https://github.com/TelcoSec-Tools/RDNSx/issues/new?template=feature_request.md)
- 🔧 **Code Contributions**: Submit pull requests with improvements
- 📖 **Documentation**: Help improve docs and examples
- 🧪 **Testing**: Test on different platforms and report results

### Development Setup
```bash
git clone https://github.com/TelcoSec-Tools/RDNSx.git
cd RDNSx
cargo build
cargo test
```

### 📊 Project Stats
[![GitHub contributors](https://img.shields.io/github/contributors/TelcoSec-Tools/RDNSx?style=flat-square)](https://github.com/TelcoSec-Tools/RDNSx/graphs/contributors)
[![GitHub issues](https://img.shields.io/github/issues/TelcoSec-Tools/RDNSx?style=flat-square)](https://github.com/TelcoSec-Tools/RDNSx/issues)
[![GitHub pull requests](https://img.shields.io/github/issues-pr/TelcoSec-Tools/RDNSx?style=flat-square)](https://github.com/TelcoSec-Tools/RDNSx/pulls)

## 📄 License

**RDNSx** is released under the [MIT License](LICENSE). Feel free to use, modify, and distribute this software.

---

<div align="center">

**Built with ❤️ by the [TelcoSec](https://github.com/TelcoSec-Tools) community**

[⭐ Star us on GitHub](https://github.com/TelcoSec-Tools/RDNSx) • [🐛 Report Issues](https://github.com/TelcoSec-Tools/RDNSx/issues) • [💬 Discussions](https://github.com/TelcoSec-Tools/RDNSx/discussions)

</div>
