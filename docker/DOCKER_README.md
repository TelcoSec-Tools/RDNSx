# RDNSx Docker Setup

This document explains how to build and run RDNSx using Docker.

## Quick Start

### Build the Docker Image

```bash
# Using the build script
./scripts/build-docker.sh

# Or manually
docker build -t rdnsx:latest .
```

### Run RDNSx

```bash
# Show help
docker run --rm rdnsx:latest --help

# Basic DNS query
docker run --rm rdnsx:latest query -d example.com

# Multiple domains from file
docker run --rm -v $(pwd)/domains.txt:/app/domains.txt rdnsx:latest query -l /app/domains.txt

# Subdomain enumeration with wordlist
docker run --rm -v $(pwd)/wordlists:/app/wordlists rdnsx:latest bruteforce -d example.com -w /app/wordlists/subdomains.txt

# Reverse DNS lookup
docker run --rm rdnsx:latest ptr -i 8.8.8.8

# Export results to JSON
docker run --rm -v $(pwd)/output:/app/output rdnsx:latest query -d example.com -o /app/results.json

# With custom DNS resolvers (recommended for containers)
docker run --rm rdnsx:latest query --resolvers "8.8.8.8,8.8.4.4" -d example.com
```

## Docker Compose (Full Stack)

For database exports, use Docker Compose which includes Elasticsearch, MongoDB, and ScyllaDB:

```bash
# Start all services
docker-compose up -d

# Run RDNSx with database export
docker-compose exec rdnsx rdnsx query -d example.com --elasticsearch

# View logs
docker-compose logs -f rdnsx

# Stop services
docker-compose down
```

### Database Configuration

When using Docker Compose, RDNSx will automatically connect to the databases using these default settings:

- **Elasticsearch**: `http://elasticsearch:9200`
- **MongoDB**: `mongodb://admin:password@mongodb:27017`
- **ScyllaDB**: `scylla:9042`

## DNS Resolvers

RDNSx works best with reliable DNS resolvers. In containerized environments, the default system resolvers may not work properly, so it's recommended to specify custom resolvers.

### Public DNS Resolvers

```bash
# Google DNS (most popular)
docker run --rm rdnsx:latest query --resolvers "8.8.8.8,8.8.4.4" -d example.com

# Cloudflare DNS (fast and private)
docker run --rm rdnsx:latest query --resolvers "1.1.1.1,1.0.0.1" -d example.com

# Quad9 DNS (secure and filtered)
docker run --rm rdnsx:latest query --resolvers "9.9.9.9,149.112.112.112" -d example.com

# OpenDNS
docker run --rm rdnsx:latest query --resolvers "208.67.222.222,208.67.220.220" -d example.com
```

### Resolver from File

```bash
# Create resolver list
echo -e "8.8.8.8\n8.8.4.4\n1.1.1.1" > config/resolvers.txt

# Use resolvers from file
docker run --rm -v $(pwd)/config/resolvers.txt:/resolvers.txt rdnsx:latest query --resolvers /resolvers.txt -d example.com
```

### Docker Network DNS

For better container networking, you can also configure DNS at the Docker level:

```bash
# Use host's DNS (Linux/macOS)
docker run --rm --dns $(ip route show default | awk '{print $3}') rdnsx:latest query --resolvers "8.8.8.8,8.8.4.4" -d example.com

# Use host networking (bypasses container network isolation)
docker run --rm --network host rdnsx:latest query --resolvers "8.8.8.8,8.8.4.4" -d example.com

# Or specify DNS in docker-compose.yml
version: '3.8'
services:
  rdnsx:
    build: .
    dns:
      - 8.8.8.8
      - 8.8.4.4
      - 1.1.1.1
    # Alternative: use host network
    # network_mode: host
```

## Advanced Usage

### Custom Build

```bash
# Build with specific Rust version
docker build --build-arg RUST_VERSION=1.92 -t rdnsx:custom .

# Build for different architecture
docker build --platform linux/arm64 -t rdnsx:arm64 .
```

### Mounting Volumes

```bash
# Mount wordlists directory
docker run --rm -v /path/to/wordlists:/app/wordlists rdnsx:latest bruteforce -d example.com -w /app/wordlists/big.txt

# Mount output directory
docker run --rm -v /path/to/output:/app/output rdnsx:latest query -d example.com -o /app/output/results.json

# Mount configuration files
docker run --rm -v $(pwd)/config:/app/config rdnsx:latest --config /app/config/rdnsx.toml query -d example.com
```

### Environment Variables

```bash
# Set DNS resolvers
docker run --rm -e RDNSX_RESOLVERS="8.8.8.8,1.1.1.1" rdnsx:latest query -d example.com

# Configure timeouts
docker run --rm -e RDNSX_TIMEOUT=10 rdnsx:latest query -d example.com
```

## Troubleshooting

### Build Issues

If the build fails, try:

```bash
# Clear Docker cache
docker system prune -f

# Rebuild without cache
docker build --no-cache -t rdnsx:latest .
```

### Runtime Issues

```bash
# Check container logs
docker logs <container_id>

# Run with verbose output (RDNSx doesn't have --verbose, but you can check timing)
docker run --rm rdnsx:latest query --timeout 15 -d example.com

# Debug shell access
docker run --rm -it rdnsx:latest /bin/bash
```

### DNS Resolution Issues

**Root Cause**: Docker containers have restricted network access by default. DNS queries to external servers are often blocked or filtered by container networking.

**✅ PROVEN SOLUTION: Use Host Networking**

```bash
# ✅ This works! (tested and confirmed)
echo "example.com" | docker run --rm --network host -i rdnsx:latest query --resolvers "8.8.8.8:53"

# Multiple domains
echo -e "google.com\ncloudflare.com" | docker run --rm --network host -i rdnsx:latest query --resolvers "8.8.8.8,1.1.1.1"

# With different resolvers
echo "example.com" | docker run --rm --network host -i rdnsx:latest query --resolvers "208.67.222.222:53"
```

**Alternative Solutions** (may not work in all environments):

```bash
# Specify DNS servers in Docker run
docker run --rm --dns 8.8.8.8 --dns 8.8.4.4 rdnsx:latest query --resolvers "8.8.8.8,8.8.4.4" -d example.com

# Use docker-compose (includes DNS config)
docker-compose up -d
docker-compose exec rdnsx rdnsx query -d example.com

# Test connectivity from container
docker run --rm --network host rdnsx:latest bash -c "nslookup google.com 8.8.8.8"
```

**Why Host Networking Works:**
- Bypasses Docker's network isolation
- Allows direct access to host's network stack
- No DNS server restrictions
- Most reliable solution for DNS queries in containers

### Network Issues

RDNSx needs network access for DNS queries. If running in restricted environments:

```bash
# Allow all network access
docker run --network host rdnsx:latest query -d example.com

# Use specific DNS servers
docker run --dns 8.8.8.8 --dns 1.1.1.1 rdnsx:latest query -d example.com
```

## Image Details

- **Base Image**: Debian Bookworm Slim
- **Rust Version**: 1.92
- **User**: Non-root (rdnsx:rdnsx)
- **Size**: ~50MB (compressed)
- **Architecture**: x86_64 (can be built for ARM64)

## Security

The Docker image runs as a non-root user and includes only essential runtime dependencies. For production use, consider:

- Scanning for vulnerabilities: `docker scan rdnsx:latest`
- Using specific image tags instead of `latest`
- Implementing resource limits in docker-compose.yml