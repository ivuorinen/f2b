# f2b FAQ (Frequently Asked Questions)

## General

### What is `f2b`?

`f2b` is a modern, Go-based CLI tool for managing Fail2Ban jails and bans. It provides a safer, more
extensible, and user-friendly alternative to Bash scripts for interacting with Fail2Ban, with automatic sudo
privilege management, shell completion, and comprehensive security features.

---

## Installation & Setup

### What are the prerequisites for running `f2b`?

- Go 1.20 or newer (for building from source)
- Fail2Ban installed and running on your system
- Appropriate privileges (root, sudo group membership, or sudo capability) for ban/unban operations

### How do I install `f2b`?

See the README for full instructions. In short:

```bash
git clone https://github.com/ivuorinen/f2b.git
cd f2b
go build -ldflags "-X github.com/ivuorinen/f2b/cmd.version=1.2.3" -o f2b .
```

Or install globally:

```bash
go install github.com/ivuorinen/f2b@latest
```

---

## Usage

### Why do some commands require root or sudo?

Fail2Ban operations (like banning/unbanning IPs or controlling the service) often require elevated privileges.
f2b automatically detects your privilege level and escalates to sudo only when necessary. Commands like `status`,
`list-jails`, and `logs` typically don't require sudo.

### Do I need to run everything with sudo?

No! f2b is smart about privileges:

- **Commands that need sudo:** `ban`, `unban`, `service` operations
- **Commands that don't need sudo:** `status`, `list-jails`, `test`, `logs`, `version`, `completion`
- **Automatic detection:** f2b checks if you're root, in sudo group, or can use sudo
- **Smart escalation:** Only adds sudo when the specific command requires it

### What if I don't have sudo privileges?

If you lack privileges for privileged operations, f2b will show a clear error message:

```text
Error: fail2ban operations require sudo privileges. Current user: username (UID: 1000).
Please run with sudo or ensure user is in sudo group
Hint: Try running with 'sudo' or ensure your user is in the sudo group
Example: sudo f2b ban 192.168.1.100
```

### How do I change the log or filter directory?

Use environment variables or CLI flags:

- `F2B_LOG_DIR` or `--log-dir`
- `F2B_FILTER_DIR` or `--filter-dir`

### How can I get JSON output for scripting?

Add `--format=json` to any supported command, e.g.:

```bash
f2b banned all --format=json
```

### How do I tail only the last N lines of logs?

Use the `--limit` flag:

```bash
f2b logs sshd --limit 20
```

### How do I set up shell completion?

f2b supports completion for bash, zsh, fish, and PowerShell:

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

### Are there command shortcuts/aliases?

Yes! Most commands have convenient aliases:

- `list-jails` → `ls-jails`, `jails`
- `status` → `st`, `stat`, `show-status`
- `ban` → `banip`, `b`
- `unban` → `unbanip`, `ub`

Example: `f2b st all` instead of `f2b status all`

### How do I configure logging?

You can control f2b's own logging (separate from fail2ban logs):

```bash
# Set log level
f2b --log-level=debug status all
# Or via environment
F2B_LOG_LEVEL=debug f2b status all

# Log to file
f2b --log-file=/tmp/f2b.log ban 192.168.1.100
# Or via environment
F2B_LOG_FILE=/tmp/f2b.log f2b ban 192.168.1.100
```

### How do I monitor f2b performance?

f2b includes comprehensive performance monitoring:

```bash
# View performance metrics
f2b metrics

# Get detailed metrics in JSON format
f2b metrics --format=json

# Monitor with real-time log watching
f2b logs-watch all 192.168.1.100
```

The metrics command shows:

- Operation counts and timing
- Cache hit/miss ratios
- Memory usage and optimization
- System performance statistics

### How do I configure timeouts?

f2b supports configurable timeouts for all operations:

```bash
# Environment variables
F2B_COMMAND_TIMEOUT=30s     # Individual command timeout
F2B_FILE_TIMEOUT=10s        # File operation timeout
F2B_PARALLEL_TIMEOUT=60s    # Parallel operation timeout

# Command-line flags
f2b --command-timeout=45s ban 192.168.1.100
f2b --parallel-timeout=120s banned all
```

---

## Troubleshooting

### I get "fail2ban-client not found in PATH" or "fail2ban service not running"

- Ensure Fail2Ban is installed and running on your system.
- You may need to run `sudo systemctl start fail2ban` or similar.
- Check installation: `which fail2ban-client`

### Why do I see "invalid IP address" or "invalid jail name"?

- The tool validates all input for security. Double-check your IP address and jail name for typos or unsupported
  characters.
- IP addresses must be valid IPv4 or IPv6 format
- Jail names can only contain alphanumeric characters, dashes, underscores, and dots

### I get "fail2ban operations require sudo privileges"

This means you need elevated privileges for the operation you're trying to perform:

1. **Check your privileges:** Run `f2b --log-level=debug version` to see your privilege status
2. **Add sudo:** Try `sudo f2b [command]`
3. **Join sudo group:** Ask your admin to add you to the sudo group
4. **Test sudo access:** Run `sudo -n true` to check if you can use sudo

### The CLI says "permission denied" or "operation not permitted"

- Try running the command with `sudo` if it requires elevated privileges
- Check that fail2ban service is running: `sudo systemctl status fail2ban`
- Verify you have permission to read log files if using log commands

### My logs or filters are not found

- Make sure you have set the correct log and filter directory using the appropriate flags or environment variables.

### How do I enable debug logging?

Use the `--log-level=debug` flag or set `F2B_LOG_LEVEL=debug` in your environment:

```bash
# Command line
f2b --log-level=debug ban 192.168.1.100

# Environment variable
F2B_LOG_LEVEL=debug f2b ban 192.168.1.100

# With log file
f2b --log-level=debug --log-file=/tmp/debug.log ban 192.168.1.100
```

### Can I use f2b in scripts?

Absolutely! Use JSON output for easy parsing:

```bash
# Get banned IPs as JSON
f2b banned all --format=json

# Script example
BANNED_COUNT=$(f2b banned all --format=json | jq length)
echo "Total banned IPs: $BANNED_COUNT"

# Check specific IP
f2b test 192.168.1.100 --format=json
```

### How do I troubleshoot privilege issues?

#### 1. Check current user info

```bash
f2b --log-level=debug version
```

#### 2. Test sudo access

```bash
sudo -n true && echo "Can use sudo" || echo "Cannot use sudo"
```

#### 3. Check group membership

```bash
groups $USER
```

#### 4. Verify fail2ban permissions

```bash
ls -la /etc/fail2ban/
sudo fail2ban-client ping
```

---

## Development

### How do I run tests?

```bash
go test ./...
```

### How do I contribute?

See the `CONTRIBUTING.md` and the Contributing section in the README.

---

## Still need help?

- Open an issue on GitHub: https://github.com/ivuorinen/f2b/issues
- Contact the maintainer: ismo@ivuorinen.net

---
