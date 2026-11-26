---
layout: page
title: "RDNSx Installation Guide - Setup Instructions"
description: "Complete installation guide for RDNSx DNS toolkit. Install on Windows, Linux, macOS, or using Docker. Includes Rust setup and troubleshooting."
keywords: "RDNSx installation, setup guide, Rust installation, Docker setup, Windows install, Linux install, macOS install"
og_image: /assets/images/logo.svg
twitter_card: summary_large_image
author: "TelcoSec"
lang: en-US
permalink: /guide/installation/
priority: 0.9
changefreq: monthly
---

# Installation Guide

## Prerequisites

- Rust 1.94 or later
- Cargo package manager

## From Source (Recommended)

### 1. Clone the repository
```bash
git clone https://github.com/TelcoSec-Tools/RDNSx.git
cd RDNSx
```

### 2. Build the project
```bash
cargo build --release
```

### 3. Install globally (optional)
```bash
cargo install --path rdnsx
```

The binary will be available at `target/release/rdnsx`

## Pre-built Binaries

Download pre-built binaries for your platform from the [releases page](https://github.com/TelcoSec-Tools/RDNSx/releases).

### Linux/macOS
```bash
# Download and extract
wget https://github.com/TelcoSec-Tools/RDNSx/releases/download/v0.1.0/rdnsx-linux-x86_64.tar.gz
tar -xzf rdnsx-linux-x86_64.tar.gz
sudo mv rdnsx /usr/local/bin/
```

### Windows
Download `rdnsx-windows-x86_64.zip` and extract the `rdnsx.exe` file to a directory in your PATH.

## Docker

### Using Docker Hub
```bash
docker pull ghcr.io/telcosec-tools/rdnsx:latest
docker run --rm ghcr.io/telcosec-tools/rdnsx --help
```

### Building from source
```bash
docker build -t rdnsx .
docker run --rm rdnsx --help
```

## Docker Compose

For more complex setups with database exports:

```yaml
version: '3.8'
services:
  rdnsx:
    image: ghcr.io/telcosec-tools/rdnsx:latest
    volumes:
      - ./config:/app/config
      - ./output:/app/output
    command: query example.com
```

## Verification

Verify your installation:

```bash
rdnsx --version
rdnsx --help
```

You should see the RDNSx banner and available commands.

## System Requirements

- **Memory**: 128MB minimum, 512MB recommended
- **Disk**: 50MB for installation
- **Network**: Internet access for DNS queries

## Troubleshooting

### Build fails
Ensure you have Rust 1.94+ installed:
```bash
rustc --version
cargo --version
```

### Permission denied
On Unix systems, make the binary executable:
```bash
chmod +x target/release/rdnsx
```

### Docker issues
Ensure Docker daemon is running:
```bash
docker info
```