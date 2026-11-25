# Contributing to RDNSx

Thank you for your interest in contributing to RDNSx! We welcome contributions from everyone.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/TelcoSec-Tools/RDNSx.git
   cd rdnsx
   ```

3. **Set up the development environment**:
   ```bash
   # Install Rust (if not already installed)
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env

   # Build the project
   cargo build

   # Run the offline tests (a mock DNS server, no network needed)
   cargo test --workspace

   # Also run the tests that need public DNS
   cargo test --workspace -- --include-ignored
   ```

## Development Workflow

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the coding standards

3. **Run tests and linting**:
   ```bash
   cargo test --workspace
   cargo clippy --workspace --all-targets -- -D warnings
   cargo fmt --all -- --check
   ```

4. **Commit your changes**:
   ```bash
   git commit -m "Add your descriptive commit message"
   ```

5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request** on GitHub

## Coding Standards

### Rust Code

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` for consistent formatting
- Use `cargo clippy` for linting
- Write comprehensive documentation for public APIs
- Include unit tests for new functionality
- Use meaningful variable and function names

### Commit Messages

- Use clear, descriptive commit messages
- Start with a verb (Add, Fix, Update, Remove, etc.)
- Keep the first line under 50 characters
- Add detailed description if needed

### Testing

- Write unit tests for all new functionality
- Integration tests for CLI features
- Test edge cases and error conditions
- Ensure all tests pass before submitting PR

## Project Structure

```
rdnsx/
├── rdnsx-core/          # Core library crate
│   ├── src/
│   │   ├── client.rs    # Main DNS client
│   │   ├── resolver.rs  # DNS resolver pool
│   │   ├── query.rs     # Query engine
│   │   ├── wildcard.rs  # Wildcard filtering
│   │   ├── bruteforce.rs # Subdomain enumeration
│   │   ├── export/      # Database exporters
│   │   └── ...
├── rdnsx/               # CLI binary crate
│   ├── src/
│   │   ├── main.rs      # CLI entry point
│   │   ├── cli.rs       # Command line parsing
│   │   ├── commands/    # CLI commands
│   │   └── ...
├── README.md
├── LICENSE
└── Cargo.toml
```

## Adding New Features

1. **Add tests** for new functionality
2. **Update documentation** including README and API docs
3. **Update CLI help** if adding new commands or options

## License

By contributing to RDNSx, you agree that your contributions will be licensed under the MIT License.