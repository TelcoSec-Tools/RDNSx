# Multi-stage build for RDNSx DNS toolkit
# Build stage
# Must be at least workspace.package.rust-version (Cargo.toml)
FROM rust:1-slim-bookworm AS builder

# Install required build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy workspace configuration and the lock file (reproducible builds)
COPY Cargo.toml Cargo.lock ./

# Copy package configurations
COPY rdnsx-core/Cargo.toml rdnsx-core/
COPY rdnsx/Cargo.toml rdnsx/

# Copy actual source files for dependency building
COPY rdnsx-core/src rdnsx-core/src/
COPY rdnsx-core/benches rdnsx-core/benches/
COPY rdnsx/src rdnsx/src/

# Build the application
RUN cargo build --release --locked --bin rdnsx

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r rdnsx && useradd -r -g rdnsx rdnsx

# Create app directory
WORKDIR /app

# Copy the compiled binary from builder stage
COPY --from=builder /app/target/release/rdnsx /app/rdnsx

# Change ownership to non-root user
RUN chown rdnsx:rdnsx /app/rdnsx

# Switch to non-root user
USER rdnsx

# Set the binary as executable
RUN chmod +x /app/rdnsx

# Expose any ports if needed (RDNSx is a CLI tool, so probably not needed)
# EXPOSE 53/udp

# Set the entrypoint
ENTRYPOINT ["/app/rdnsx"]

# Default command (show help)
CMD ["--help"]