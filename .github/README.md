# f2b - Modern Fail2Ban CLI Wrapper

A modern, secure, and extensible Go CLI tool for managing [Fail2Ban](https://www.fail2ban.org/) jails and bans. Built with Go, featuring automatic sudo privilege management, shell completion, and comprehensive security.

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![Go Version](https://img.shields.io/badge/Go-%3E%3D1.20-blue.svg)](https://golang.org/)
[![Build Status](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()

---

## 🚀 Quick Start

### Prerequisites

- **Go 1.20+** (for building from source)
- **Fail2Ban** installed and running
- **Appropriate privileges** (root, sudo group, or sudo access) for ban operations

### Installation

```bash
# Clone and build
git clone https://github.com/ivuorinen/f2b.git
cd f2b
# set version information via ldflags if desired
go build -ldflags "-X github.com/ivuorinen/f2b/cmd.version=1.2.3" -o f2b .

# Or install globally
go install github.com/ivuorinen/f2b@latest
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

- List jails and view status
- Ban/unban IPs with automatic sudo
- Monitor logs with filtering and tailing
- Test filters and control services
- Watch logs in real-time

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

# Log monitoring with filtering
f2b logs sshd --limit 20
f2b logs-watch all 192.168.1.100

# Service management (automatic sudo)
f2b service status
f2b service restart

# Filter testing
f2b test-filter sshd
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

### Automatic Privilege Handling

f2b intelligently manages sudo requirements:

- **Root users**: Commands run directly
- **Sudo users**: Automatic escalation for privileged operations
- **Regular users**: Clear error messages with guidance

### Commands by Privilege Level

**Require sudo:**

- `ban`, `unban` operations
- `service` control commands
- Some configuration changes

**No sudo needed:**

- `status`, `list-jails`, `test`
- `logs`, `version`, `completion`
- Most read-only operations

### Error Guidance

```
Error: fail2ban operations require sudo privileges. Current user: username (UID: 1000).
Please run with sudo or ensure user is in sudo group
Hint: Try running with 'sudo' or ensure your user is in the sudo group
Example: sudo f2b ban 192.168.1.100
```

### Input Validation & Security

- **Comprehensive validation:** All user-supplied IP addresses and jail names are validated
- **Secure execution:** No shell string concatenation; all system commands use argument arrays
- **Principle of least privilege:** Only escalates privileges when absolutely necessary
- **Safe testing:** Extensive test coverage with mock implementations prevents accidental privilege escalation

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

### Project Summary

- **Modern Go architecture:** All commands use dependency injection for testability and extensibility
- **Structured logging:** Uses [logrus](https://github.com/sirupsen/logrus) for consistent, structured logs
- **Consistent output:** All commands support `plain` and `json` output via the `--format` flag
- **Sudo privilege management:** Automatic privilege detection and escalation for secure operations
- **Shell completion:** Built-in completion support for bash, zsh, fish, and PowerShell
- **Command aliases:** Convenient short forms for frequently used commands
- **Pagination/tailing:** Log commands support the `--limit` flag for efficient log viewing
- **Enhanced security:** Comprehensive input validation and secure command execution
- **Easy to extend:** The codebase is modular and ready for new features or backends

### Built for Reliability

- **Dependency Injection**: Testable, modular design
- **Interface-based**: Easy to extend and mock
- **Comprehensive Testing**: 85%+ test coverage
- **Security-focused**: Input validation and safe execution

### Technology Stack

- **Language**: Go 1.20+
- **CLI Framework**: Cobra
- **Logging**: Logrus with structured output
- **Testing**: Comprehensive mocks and integration tests

---

## 🧪 Development & Testing

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -coverprofile=coverage.out ./...

# Security-focused testing
F2B_TEST_SUDO=true go test ./fail2ban -run TestSudo
```

### Pre-commit Hooks

This project uses [pre-commit](https://pre-commit.com/) to automate linting and formatting.
Install the hooks after cloning:

```bash
pip install pre-commit
pre-commit install
```

MegaLinter requires Docker and does not currently work with Podman. Run the hooks before committing:

```bash
pre-commit run --all-files
```

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

- [CONTRIBUTING.md](../CONTRIBUTING.md) - Contribution guidelines
- [AGENTS.md](AGENTS.md) - Guidelines for AI/LLM contributors
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Community standards

---

## 📄 License

[MIT License](../LICENSE.md).

---

## 👨‍💻 Author

**Ismo Vuorinen** ([@ivuorinen](https://github.com/ivuorinen))

---

## 🆘 Support

- 📝 [Open an issue](https://github.com/ivuorinen/f2b/issues)
- 📖 [Read the FAQ](../FAQ.md)

---

_Built with ❤️ and Go. Securing systems one ban at a time._
