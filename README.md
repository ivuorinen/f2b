# f2b - Modern Fail2Ban CLI Wrapper

A modern, secure, and extensible Go CLI tool for managing [Fail2Ban](https://www.fail2ban.org/) jails and bans.
Built with Go, featuring automatic sudo privilege management, shell completion, and comprehensive security.

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![Go Version](https://img.shields.io/badge/Go-%3E%3D1.20-blue.svg)](https://golang.org/)
[![Build Status](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/ivuorinen/f2b/actions)

---

## 🚀 Quick Start

### Prerequisites

- **Go 1.20+** (for building from source)
- **Fail2Ban** installed and running
- **Appropriate privileges** (root, sudo group, or sudo access) for ban operations

### Installation

#### Download Pre-built Binary

Download the latest release for your platform from the [releases page](https://github.com/ivuorinen/f2b/releases).

```bash
# Linux (amd64)
wget https://github.com/ivuorinen/f2b/releases/latest/download/f2b_Linux_x86_64.tar.gz
tar -xzf f2b_Linux_x86_64.tar.gz
sudo mv f2b /usr/local/bin/

# macOS (Apple Silicon)
wget https://github.com/ivuorinen/f2b/releases/latest/download/f2b_Darwin_arm64.tar.gz
tar -xzf f2b_Darwin_arm64.tar.gz
sudo mv f2b /usr/local/bin/
```

#### Using Homebrew (macOS/Linux)

```bash
brew tap ivuorinen/tap
brew install f2b
```

#### Using Go

```bash
# Install latest version
go install github.com/ivuorinen/f2b@latest

# Install specific version
go install github.com/ivuorinen/f2b@v1.2.3
```

#### Using Docker (Multi-Architecture)

```bash
# Pull latest multi-architecture image
docker pull ghcr.io/ivuorinen/f2b:latest

# Run with mounted fail2ban directory
docker run --rm -v /etc/fail2ban:/etc/fail2ban:ro ghcr.io/ivuorinen/f2b:latest status all

# Architecture-specific images available:
# ghcr.io/ivuorinen/f2b:latest-amd64
# ghcr.io/ivuorinen/f2b:latest-arm64
# ghcr.io/ivuorinen/f2b:latest-armv7
```

#### Build from Source

```bash
# Clone and build
git clone https://github.com/ivuorinen/f2b.git
cd f2b
make build

# Or with custom version
go build -ldflags "-X github.com/ivuorinen/f2b/cmd.version=1.2.3" -o f2b .
```

---

## ✨ Key Features

### 🔐 **Smart Privilege Management**

- Automatic sudo detection and escalation
- Secure command execution with input validation
- Clear error messages for privilege issues

### 🛠️ **Modern CLI Experience**

- Shell completion (bash, zsh, fish, PowerShell)
- Command aliases (`ls-jails`, `st`, `b`, `ub`)
- JSON output for scripting (`--format=json`)
- Structured logging with configurable levels

### 🔒 **Security First**

- Comprehensive input validation
- No shell injection vulnerabilities
- Principle of least privilege
- Extensive test coverage with mocks

### 📊 **Comprehensive Functionality**

- List jails and view status with context-aware operations
- Ban/unban IPs with automatic sudo and timeout handling
- Monitor logs with filtering, tailing, and real-time watching
- Test filters and control services with enhanced validation
- Performance metrics collection and monitoring (`f2b metrics`)
- Advanced parallel processing for multi-jail operations
- Validation caching for improved performance

---

## 📋 Usage Examples

### Basic Operations

```bash
# List all jails (aliases: ls-jails, jails)
f2b list-jails

# Show status (aliases: st, stat)
f2b status all
f2b status sshd

# Ban/unban IPs (aliases: b/banip, ub/unbanip)
f2b ban 192.168.1.100
f2b ban 192.168.1.100 sshd
f2b unban 192.168.1.100

# Check if IP is banned
f2b test 192.168.1.100
```

### Advanced Features

```bash
# JSON output for scripting
f2b banned all --format=json

# Performance metrics and monitoring
f2b metrics
f2b metrics --format=json

# Log monitoring with filtering and limits
f2b logs sshd --limit 20
f2b logs-watch all 192.168.1.100

# Service management (automatic sudo with timeout handling)
f2b service status
f2b service restart

# Filter testing with enhanced validation
f2b test-filter sshd

# Parallel operations for multiple jails
f2b banned all  # Uses parallel processing automatically
```

### Shell Completion

```bash
# Bash
source <(f2b completion bash)
# Or install system-wide:
f2b completion bash > /etc/bash_completion.d/f2b

# Zsh
f2b completion zsh > "${fpath[1]}/_f2b"

# Fish
f2b completion fish > ~/.config/fish/completions/f2b.fish

# PowerShell
f2b completion powershell | Out-String | Invoke-Expression
```

---

## ⚙️ Configuration

### Environment Variables

```bash
F2B_LOG_DIR=/var/log                    # Fail2Ban log directory
F2B_FILTER_DIR=/etc/fail2ban/filter.d   # Filter directory
F2B_LOG_LEVEL=info                      # Log level (debug,info,warn,error)
F2B_LOG_FILE=/path/to/f2b.log          # f2b's own log file
F2B_TEST_SUDO=false                     # Enable sudo checking in tests
F2B_VERBOSE_TESTS=false                 # Force verbose logging in CI/tests
ALLOW_DEV_PATHS=false                   # Allow /tmp paths (development only)
```

### Global Flags

```bash
--log-dir string      # Override log directory
--filter-dir string   # Override filter directory
--format string       # Output format (plain|json)
--log-level string    # Logging level
--log-file string     # Log file path
--limit int           # Limit output lines (for log commands)
```

### Command-Line Examples

```bash
# Custom directories for non-standard installations
F2B_LOG_DIR=/custom/log F2B_FILTER_DIR=/custom/filters f2b status all

# JSON output for scripting and automation
f2b banned all --format=json | jq '.[] | select(.Remaining | test("^0[01]:"))'

# Efficient log monitoring with limits
f2b logs sshd --limit 50 --format=json

# Debug mode with file logging
f2b --log-level=debug --log-file=/tmp/f2b-debug.log ban 192.168.1.100
```

---

## 🔐 Security & Privileges

f2b is designed with security as a fundamental principle:

- **Smart Privilege Management**: Automatic sudo detection and escalation only when needed
- **Input Validation**: Comprehensive validation of all user input (IPs, jail names, etc.)
- **Safe Execution**: No shell injection vulnerabilities; uses argument arrays exclusively
- **Clear Error Guidance**: Helpful messages when privileges are insufficient

### Command Privilege Requirements

**Require sudo**: `ban`, `unban`, `service` operations
**No sudo needed**: `status`, `list-jails`, `test`, `logs`, `version`, `completion`

For detailed security practices, threat model, and contribution security guidelines, see
[docs/security.md](docs/security.md).

---

## 📖 Complete Command Reference

### Core Commands

```bash
# Jail Management
f2b list-jails                         # List all available jails
f2b status all                         # Show status of all jails
f2b status <jail>                      # Show status of specific jail

# IP Ban Management
f2b banned all                         # Show all banned IPs
f2b banned <jail>                      # Show banned IPs for specific jail
f2b ban <ip> [jail]                    # Ban IP globally or in specific jail
f2b unban <ip> [jail]                  # Unban IP globally or from specific jail
f2b test <ip>                          # Check if IP is banned

# Log Management
f2b logs <jail> [ip] --limit N         # Show jail logs with optional IP filter
f2b logs-watch <jail> [ip] --limit N   # Watch/tail jail logs in real-time

# Service Control
f2b service status                     # Show Fail2Ban service status
f2b service start|stop|restart         # Control Fail2Ban service

# Filter Testing
f2b test-filter <jail>                 # Test Fail2Ban filter configuration

# Performance & Monitoring
f2b metrics                            # Show performance metrics
f2b metrics --format=json              # Metrics in JSON format

# Utility Commands
f2b version                            # Show version information
f2b completion <shell>                 # Generate shell completion
f2b help [command]                     # Show help information
```

### Command Aliases

For convenience, most commands have short aliases:

- `list-jails` → `ls-jails`, `jails`
- `status` → `st`, `stat`, `show-status`
- `ban` → `banip`, `b`
- `unban` → `unbanip`, `ub`

---

## 🏗️ Architecture

f2b is built with modern Go architecture principles, focusing on security, testability, and extensibility:

- **Security-First Design**: Automatic privilege management with comprehensive input validation and path
  traversal protection
- **Context-Aware Operations**: Timeout handling and cancellation support throughout the application
- **Performance Monitoring**: Built-in metrics collection with validation caching for improved performance
- **Dependency Injection**: All components use interfaces for easy testing and extension
- **Comprehensive Testing**: 76.8% test coverage (cmd/), 59.3% (fail2ban/) with modern fluent testing framework
- **Modern CLI**: Built with Cobra framework, supporting JSON output and shell completion
- **Parallel Processing**: Advanced concurrent operations for multi-jail scenarios

**Technology Stack**: Go 1.20+, Cobra CLI framework, Logrus structured logging, Docker multi-architecture support

For detailed architecture information, see [docs/architecture.md](docs/architecture.md).

---

## 🧪 Development & Testing

### Quick Start

```bash
# Run all tests
go test ./...

# Run with coverage
go test -coverprofile=coverage.out ./...

# Security-focused testing with enhanced validation
F2B_TEST_SUDO=true go test ./fail2ban -run TestSudo

# Test modern fluent framework
go test ./cmd -run TestCommand

# Run parallel processing tests
go test ./fail2ban -run TestParallel
```

For comprehensive testing guidelines, mock patterns, and security testing practices, see
[docs/testing.md](docs/testing.md).

### Code Quality & Linting

This project uses [pre-commit](https://pre-commit.com/) for unified linting and formatting.
Install the development dependencies and hooks:

```bash
make dev-deps
make pre-commit-setup
```

Run all linters:

```bash
# Preferred method (unified tooling)
make lint

# Run specific hooks
pre-commit run yamlfmt --all-files
pre-commit run golangci-lint --all-files
```

For detailed information about linting tools and configuration, see [docs/linting.md](docs/linting.md).

### Integration Examples

```bash
# Bash script integration
#!/bin/bash
BANNED_IPS=$(f2b banned all --format=json | jq -r '.[].IP')
for ip in $BANNED_IPS; do
    echo "Processing banned IP: $ip"
done

# Monitoring script
f2b logs-watch all --limit 20 | while read line; do
    echo "$(date): $line" >> /var/log/f2b-monitor.log
done
```

---

## 🚀 Releases

### Creating a New Release

Releases are automated using [GoReleaser](https://goreleaser.com/). To create a new release:

1. **Tag the release:**

  ```bash
  git tag -a v1.2.3 -m "Release v1.2.3"
  git push origin v1.2.3
  ```

2. **GitHub Actions will automatically:**

  - Build binaries for multiple platforms (Linux, macOS, Windows, BSD)
  - Create a GitHub release with changelog
  - Upload release artifacts
  - Build and push Docker images
  - Update Homebrew tap (if configured)
  - Generate .deb, .rpm, and .apk packages

### Manual Release (Development)

```bash
# Check GoReleaser configuration
make release-check

# Create a snapshot release (no tag required)
make release-snapshot

# Create a full release (requires git tag)
make release
```

### Release Artifacts

Each release includes:

- Pre-built binaries for multiple platforms and architectures (Linux, macOS, Windows, BSD)
- Multi-architecture Docker images (amd64, arm64, armv7) with manifests
- SHA256 checksums file
- Source code archives
- Docker images at `ghcr.io/ivuorinen/f2b` with architecture-specific tags
- Linux packages (.deb, .rpm, .apk) for multiple architectures

---

## 🤝 Contributing

We welcome contributions! To get started:

- **Open an issue** for bugs, feature requests, or questions
- **Fork the repository** and create a feature branch for your changes
- **Write clear commit messages** and keep pull requests focused and well-documented
- **Add or update tests** for any code changes
- **Run `go test ./...` and ensure all tests pass** before submitting a PR
- **Be respectful and constructive** in all communications

For larger changes or proposals, please open an issue to discuss your ideas first.

Please see:

- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [AGENTS.md](AGENTS.md) - Guidelines for AI/LLM contributors
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Community standards
- [docs/architecture.md](docs/architecture.md) - System architecture and design
- [docs/security.md](docs/security.md) - Security practices and guidelines
- [docs/testing.md](docs/testing.md) - Testing strategies and patterns

---

## 📄 License

[MIT License](LICENSE.md).

---

## 👨‍💻 Author

**Ismo Vuorinen** ([@ivuorinen](https://github.com/ivuorinen))

---

## 🆘 Support

- 📝 [Open an issue](https://github.com/ivuorinen/f2b/issues)
- 📖 [Read the FAQ](docs/faq.md)

---

_Built with ❤️ and Go. Securing systems one ban at a time._
