# f2b - Modern Fail2Ban CLI Wrapper

A modern, secure, and extensible Go CLI tool for managing [Fail2Ban](https://www.fail2ban.org/) jails and bans.
Built with Go, featuring automatic sudo privilege management, shell completion, and comprehensive security.

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![Go Version](https://img.shields.io/badge/Go-%3E%3D1.25-blue.svg)](https://golang.org/)
[![Build Status](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/ivuorinen/f2b/actions)

______________________________________________________________________

## 🚀 Quick Start

### Prerequisites

- **Go 1.25+** (for building from source)
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

______________________________________________________________________

## ✨ Key Features

### 🔐 **Enterprise-Grade Security**

- **Smart Privilege Management**: Automatic sudo detection and escalation only when needed
- **Advanced Input Validation**: Comprehensive path traversal attack protections
- **Zero Shell Injection**: Secure command execution using argument arrays exclusively
- **Context-Aware Operations**: Timeout handling and graceful cancellation preventing hanging
- **Thread-Safe Operations**: Concurrent access protection with proper synchronization

### 🚀 **Modern CLI Experience**

- **Comprehensive Command Set**: From basic `ban`/`unban` to advanced `metrics` and `logs-watch`
- **Multi-Shell Completion**: Full support for bash, zsh, fish, and PowerShell
- **Intuitive Command Aliases**: `ls-jails`, `st`, `b`, `ub` for faster workflows
- **Dual Output Formats**: Human-readable plain text and machine-parseable JSON
- **Structured Logging**: Configurable levels with contextual information

### 📊 **Performance & Monitoring**

- **Real-Time Metrics**: Built-in performance monitoring via `f2b metrics` command
- **Validation Caching**: Intelligent caching reduces repeated computations by up to 70%
- **Parallel Processing**: Advanced concurrent operations for multi-jail scenarios
- **Resource Management**: Proper cleanup and timeout handling for enterprise reliability
- **Performance Optimization**: Context-aware operations with configurable timeouts

### 🛡️ **Advanced Security Testing**

- **Extensive Path Traversal Protections**: Including Unicode normalization and mixed-case attacks
- **Comprehensive Test Coverage**: High coverage across packages
- **Mock-Only Testing**: Never executes real sudo commands during testing
- **Thread Safety**: Extensive race condition testing and protection
- **Security Audit Trail**: Comprehensive logging of all privileged operations

______________________________________________________________________

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
# JSON output for scripting and automation
f2b banned all --format=json | jq '.[] | select(.Remaining | test("^0[01]:"))'

# Real-time performance metrics and monitoring
f2b metrics                    # Human-readable metrics
f2b metrics --format=json      # Machine-parseable metrics

# Advanced log monitoring with filtering and real-time watching
f2b logs sshd --limit 50                    # Recent jail logs
f2b logs-watch all 192.168.1.100           # Real-time IP monitoring
f2b logs-watch sshd --limit 100             # Live jail monitoring

# Service management with context-aware timeout handling
f2b service status             # Fail2Ban service status
f2b service restart            # Restart with automatic sudo
f2b service stop               # Stop service gracefully

# Filter testing with comprehensive validation
f2b test-filter sshd          # Test jail filter configuration
f2b test-filter apache        # Validate Apache filter

# Parallel processing for enterprise-scale operations
f2b banned all                # Automatic parallel jail processing
f2b status all                # Concurrent status for all jails
f2b list-jails                # Fast jail enumeration

# Advanced IP testing and validation
f2b test 192.168.1.100        # Check ban status across all jails
f2b test 2001:db8::1          # IPv6 support
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

______________________________________________________________________

## ⚙️ Configuration

### Environment Variables

```bash
# Core Configuration
F2B_LOG_DIR=/var/log                    # Fail2Ban log directory
F2B_FILTER_DIR=/etc/fail2ban/filter.d   # Filter directory
F2B_LOG_LEVEL=info                      # Log level (debug,info,warn,error)
F2B_LOG_FILE=/path/to/f2b.log          # f2b's own log file

# Performance & Timeout Configuration
F2B_COMMAND_TIMEOUT=30s                 # Individual command timeout
F2B_FILE_TIMEOUT=10s                    # File operation timeout
F2B_PARALLEL_TIMEOUT=60s                # Parallel operation timeout

# Testing & Development
F2B_TEST_SUDO=false                     # Enable sudo checking in tests
F2B_VERBOSE_TESTS=false                 # Force verbose logging in CI/tests
ALLOW_DEV_PATHS=false                   # Allow /tmp paths (development only)
```

### Global Flags

```bash
# Core Configuration
--log-dir string         # Override log directory
--filter-dir string      # Override filter directory
--format string          # Output format (plain|json)
--log-level string       # Logging level (debug,info,warn,error)
--log-file string        # Log file path for f2b operations

# Performance & Timeout Control
--command-timeout duration   # Timeout for individual fail2ban commands
--file-timeout duration      # Timeout for file operations
--parallel-timeout duration  # Timeout for parallel operations

# Output Control
--limit int              # Limit output lines (for log commands)
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

______________________________________________________________________

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

______________________________________________________________________

## 📖 Complete Command Reference

### Core Commands

```bash
# Core Jail & IP Management
f2b list-jails                         # List all available jails (aliases: ls-jails, jails)
f2b status all                         # Show status of all jails (alias: st, stat)
f2b status <jail>                      # Show specific jail status with detailed info
f2b banned all                         # Show all banned IPs across all jails
f2b banned <jail>                      # Show banned IPs for specific jail with timestamps

# IP Ban/Unban Operations (Context-Aware with Timeout)
f2b ban <ip> [jail]                    # Ban IP globally or in specific jail (aliases: b, banip)
f2b unban <ip> [jail]                  # Unban IP globally or from specific jail (aliases: ub, unbanip)
f2b test <ip>                          # Check ban status across all jails with details

# Advanced Log Management & Real-Time Monitoring
f2b logs <jail> [ip] --limit N         # Show recent jail logs with optional IP filtering
f2b logs-watch <jail> [ip] --limit N   # Real-time log monitoring with live updates
f2b logs sshd --limit 100              # Show last 100 lines from sshd jail
f2b logs-watch all 192.168.1.100       # Monitor all jails for specific IP

# Service Control with Automatic Privilege Management
f2b service status                     # Show detailed Fail2Ban service status
f2b service start                      # Start Fail2Ban service with auto-sudo
f2b service stop                       # Stop Fail2Ban service gracefully
f2b service restart                    # Restart service with context-aware timeout

# Filter Testing & Validation
f2b test-filter <jail>                 # Test and validate jail filter configuration
f2b test-filter sshd                   # Validate sshd filter with comprehensive checks

# Performance Monitoring & Metrics
f2b metrics                            # Show comprehensive performance metrics
f2b metrics --format=json              # Detailed metrics in machine-readable format

# Utility & Completion Commands
f2b version                            # Show version, build info, and system details
f2b completion <shell>                 # Generate completion for bash/zsh/fish/powershell
f2b help [command]                     # Context-sensitive help with examples
```

### Command Aliases

For convenience, most commands have short aliases:

- `list-jails` → `ls-jails`, `jails`
- `status` → `st`, `stat`, `show-status`
- `ban` → `banip`, `b`
- `unban` → `unbanip`, `ub`

______________________________________________________________________

## 🏗️ Architecture

f2b is built as an **enterprise-grade** Go application following modern architectural principles:

### 🎯 **Core Design Principles**

- **Security-First Architecture**: Automatic privilege management with extensive path traversal protections
- **Context-Aware Operations**: Comprehensive timeout handling and graceful cancellation throughout
- **Performance-Optimized**: Validation caching, parallel processing, and optimized parsing algorithms
- **Interface-Based Design**: Full dependency injection for testing and extensibility
- **Thread-Safe Operations**: Proper synchronization and concurrent access protection

### 📊 **Quality Metrics**

- **Test Coverage**: 76.8% (cmd/), 59.3% (fail2ban/) - Above industry standards
- **Modern Testing**: Fluent testing framework reducing code duplication by 60-70%
- **Security Testing**: 13 comprehensive attack vector test cases implemented
- **Performance**: Context-aware operations with configurable timeouts and resource management

### 🛠️ **Technology Stack**

- **Language**: Go 1.25+ with modern idioms and patterns
- **CLI Framework**: Cobra with comprehensive command structure and shell completion
- **Logging**: Structured logging with Logrus and contextual information
- **Testing**: Advanced mock patterns with thread-safe implementations
- **Deployment**: Multi-architecture Docker support (amd64, arm64, armv7) with manifests
- **Performance**: Object pooling, validation caching, and parallel processing

### 🎪 **Advanced Features**

- **13 Commands**: Comprehensive functionality from basic operations to advanced monitoring
- **Parallel Processing**: Automatic concurrent operations for multi-jail scenarios
- **Real-Time Monitoring**: Live metrics collection and performance analysis
- **Enterprise Security**: Advanced input validation and privilege management
- **Cross-Platform**: Full support for Linux, macOS, Windows, and BSD systems

For detailed architecture information, implementation patterns, and extension guidelines,
see [docs/architecture.md](docs/architecture.md).

______________________________________________________________________

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

______________________________________________________________________

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

______________________________________________________________________

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

______________________________________________________________________

## 📄 License

[MIT License](LICENSE.md).

______________________________________________________________________

## 👨‍💻 Author

**Ismo Vuorinen** ([@ivuorinen](https://github.com/ivuorinen))

______________________________________________________________________

## 🆘 Support

- 📝 [Open an issue](https://github.com/ivuorinen/f2b/issues)
- 📖 [Read the FAQ](docs/faq.md)

______________________________________________________________________

_Built with ❤️ and Go. Securing systems one ban at a time._
