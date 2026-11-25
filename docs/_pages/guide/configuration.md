---
layout: page
title: Configuration Guide
description: "Advanced configuration options for RDNSx"
permalink: /guide/configuration/
---

# Configuration Guide

RDNSx supports extensive configuration through TOML files, command-line arguments, and environment variables.

## Configuration File

Create a configuration file:

```bash
rdnsx --create-config config/rdnsx.toml
```

## Configuration Sections

### Resolvers Configuration

```toml
[resolvers]
# DNS servers to use for queries
servers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]
# Query timeout in seconds
timeout = 5
# Number of retries for failed queries
retries = 3
```

#### Public DNS Servers

| Provider | IPv4 | IPv6 |
|----------|------|------|
| Google | 8.8.8.8, 8.8.4.4 | 2001:4860:4860::8888, 2001:4860:4860::8844 |
| Cloudflare | 1.1.1.1, 1.0.0.1 | 2606:4700:4700::1111, 2606:4700:4700::1001 |
| Quad9 | 9.9.9.9, 149.112.112.112 | 2620:fe::fe, 2620:fe::9 |
| OpenDNS | 208.67.222.222, 208.67.220.220 | 2620:119:35::35, 2620:119:53::53 |

### Performance Configuration

```toml
[performance]
# Maximum concurrent queries
threads = 100
# Rate limit (queries per second, 0 = unlimited)
rate_limit = 0
```

#### Performance Tuning

**High-throughput scanning:**
```toml
[performance]
threads = 1000
rate_limit = 0  # Unlimited
```

**Conservative scanning:**
```toml
[performance]
threads = 10
rate_limit = 50  # 50 queries/second
```

**CI/CD environments:**
```toml
[performance]
threads = 4
rate_limit = 10
```

### Export Configuration

#### Elasticsearch Export

```toml
[export]
batch_size = 1000

[export.elasticsearch]
enabled = true
url = "http://localhost:9200"
index = "dnsx-records"
```

#### MongoDB Export

```toml
[export.mongodb]
enabled = true
url = "mongodb://localhost:27017"
database = "dnsx"
collection = "records"
```

#### Cassandra Export

```toml
[export.cassandra]
enabled = true
contact_points = ["localhost:9042"]
username = "cassandra_user"
password = "cassandra_pass"
keyspace = "dnsx"
table = "records"
```

## Environment Variables

RDNSx respects these environment variables:

### Core Settings
- `RDNSX_CONFIG` - Path to configuration file
- `RDNSX_RESOLVERS` - Comma-separated DNS resolvers
- `RDNSX_TIMEOUT` - Query timeout in seconds
- `RDNSX_RETRIES` - Number of retry attempts

### Performance
- `RDNSX_THREADS` - Number of concurrent threads
- `RDNSX_RATE_LIMIT` - Queries per second (0 = unlimited)

### Database Exports
- `RDNSX_ES_URL` - Elasticsearch URL
- `RDNSX_ES_INDEX` - Elasticsearch index name
- `RDNSX_MONGODB_URL` - MongoDB connection URL
- `RDNSX_CASSANDRA_CONTACT_POINTS` - Cassandra contact points (comma-separated)
- `RDNSX_CASSANDRA_USERNAME` / `RDNSX_CASSANDRA_PASSWORD` - Cassandra credentials (keeps them out of the TOML file)

Precedence: command-line flags, then environment variables, then the config file.
A config file given with `--config` or `RDNSX_CONFIG` must exist and parse; RDNSx
stops with an error instead of silently using defaults.

## Command-Line Overrides

Command-line arguments override configuration file settings:

```bash
# Override resolvers
rdnsx --resolvers 1.1.1.1,8.8.8.8 query example.com

# Override performance settings
rdnsx --threads 50 --rate-limit 100 query domains.txt

# Override timeout
rdnsx --timeout 10 query example.com
```

## Advanced Configuration

### Custom Resolver Pools

For large-scale scanning, consider using multiple resolver pools:

```bash
# Use multiple resolver sets
rdnsx --resolvers "8.8.8.8,8.8.4.4" query domains.txt
rdnsx --resolvers "1.1.1.1,1.0.0.1" query domains.txt
```

### Load Balancing

RDNSx automatically load-balances across configured resolvers for improved performance and reliability.

### Error Handling

Configure retry logic for unreliable networks:

```toml
[resolvers]
retries = 5
timeout = 10
```

## Configuration Validation

RDNSx validates configuration on startup:

```bash
# Test configuration
rdnsx --config config/rdnsx.toml --help
```

Invalid configurations will display error messages with suggestions.

## Configuration Examples

### Development Environment
```toml
[resolvers]
servers = ["127.0.0.1:5353"]  # Local DNS server
timeout = 2
retries = 1

[performance]
threads = 4
rate_limit = 10
```

### Production Environment
```toml
[resolvers]
servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
timeout = 5
retries = 3

[performance]
threads = 100
rate_limit = 0

[export.elasticsearch]
enabled = true
url = "http://elasticsearch:9200"
index = "dns-scans"
```

### CI/CD Environment
```toml
[resolvers]
servers = ["1.1.1.1", "8.8.8.8"]
timeout = 10
retries = 5

[performance]
threads = 2
rate_limit = 5
```