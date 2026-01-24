// Package shared provides constants used across all packages in the f2b project.
// This file consolidates all constants to ensure consistency and maintainability.
//
//nolint:revive // Package name 'shared' is intentional for project-wide constants
package shared

import "time"

// Cache configuration constants
const (
	// CacheMaxSize is the maximum number of entries in bounded caches
	CacheMaxSize = 10000

	// CacheEvictionThreshold is the percentage at which cache eviction triggers (0.9 = 90%)
	CacheEvictionThreshold = 0.9

	// CacheEvictionRate is the percentage of entries to evict (0.25 = remove 25%, keep 75%)
	CacheEvictionRate = 0.25
)

// Time format constants
const (
	// TimeFormat is the standard fail2ban timestamp format
	TimeFormat = "2006-01-02 15:04:05"
)

// Time duration constants
const (
	// SecondsPerMinute is the number of seconds in a minute
	SecondsPerMinute = 60

	// SecondsPerHour is the number of seconds in an hour
	SecondsPerHour = 3600

	// SecondsPerDay is the number of seconds in a day
	SecondsPerDay = 86400

	// DefaultBanDuration is the default fallback duration for bans when parsing fails
	DefaultBanDuration = 24 * time.Hour
)

// Timeout constants
const (
	// DefaultCommandTimeout is the default timeout for individual fail2ban commands
	DefaultCommandTimeout = 30 * time.Second

	// DefaultFileTimeout is the default timeout for file operations
	DefaultFileTimeout = 10 * time.Second

	// DefaultParallelTimeout is the default timeout for parallel operations
	DefaultParallelTimeout = 60 * time.Second

	// MaxCommandTimeout is the maximum allowed timeout for commands
	MaxCommandTimeout = 10 * time.Minute

	// MaxFileTimeout is the maximum allowed timeout for file operations
	MaxFileTimeout = 5 * time.Minute

	// MaxParallelTimeout is the maximum allowed timeout for parallel operations
	MaxParallelTimeout = 30 * time.Minute
)

// Default values
const (
	// UnknownValue represents an unknown or unset value
	UnknownValue = "unknown"

	// DefaultLogDir is the default directory for fail2ban logs
	DefaultLogDir = "/var/log"

	// DefaultFilterDir is the default directory for fail2ban filters
	DefaultFilterDir = "/etc/fail2ban/filter.d"

	// AllFilter represents all jails/IPs filter
	AllFilter = "all"

	// PathTypeLog is the path type identifier for log directories
	PathTypeLog = "log"

	// PathTypeFilter is the path type identifier for filter directories
	PathTypeFilter = "filter"

	// DefaultMaxFileSize is the default maximum file size for log reading (100MB)
	DefaultMaxFileSize = 100 * 1024 * 1024

	// DefaultLogLinesLimit is the default limit for log lines returned
	DefaultLogLinesLimit = 1000

	// DefaultPollingInterval is the default interval for polling operations
	DefaultPollingInterval = 5 * time.Second

	// MaxLogLinesLimit is the maximum number of log lines allowed per request
	MaxLogLinesLimit = 100000
)

// Validation length limits
const (
	// MaxIPAddressLength is the maximum length for an IP address string (IPv6 with brackets and port)
	MaxIPAddressLength = 45

	// MaxJailNameLength is the maximum length for a jail name
	MaxJailNameLength = 64

	// MaxFilterNameLength is the maximum length for a filter name
	MaxFilterNameLength = 255

	// MaxArgumentLength is the maximum length for a command argument
	MaxArgumentLength = 1024
)

// File permissions
const (
	// DefaultFilePermissions for log files and temporary files
	DefaultFilePermissions = 0600

	// DefaultDirectoryPermissions for created directories
	DefaultDirectoryPermissions = 0750
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

// Context key constants for structured logging
const (
	// ContextKeyRequestID is the context key for request IDs
	ContextKeyRequestID contextKey = "request_id"

	// ContextKeyOperation is the context key for operation names
	ContextKeyOperation contextKey = "operation"

	// ContextKeyJail is the context key for jail names
	ContextKeyJail contextKey = "jail"

	// ContextKeyIP is the context key for IP addresses
	ContextKeyIP contextKey = "ip"

	// ContextKeyCommand is the context key for command names
	ContextKeyCommand contextKey = "command"
)

// Fail2ban status codes
const (
	// Fail2BanStatusSuccess indicates successful operation (ban/unban succeeded)
	Fail2BanStatusSuccess = "0"

	// Fail2BanStatusAlreadyProcessed indicates IP was already banned/unbanned
	Fail2BanStatusAlreadyProcessed = "1"
)

// Fail2ban command names
const (
	// Fail2BanClientCommand is the standard fail2ban client command
	Fail2BanClientCommand = "fail2ban-client"

	// Fail2BanRegexCommand is the fail2ban regex testing command
	Fail2BanRegexCommand = "fail2ban-regex"

	// Fail2BanServerCommand is the fail2ban server command
	Fail2BanServerCommand = "fail2ban-server"
)

// f2b CLI command names
const (
	// CLICmdVersion is the f2b version command name
	CLICmdVersion = "version"

	// CLICmdListJails is the f2b list-jails command name
	CLICmdListJails = "list-jails"
)

// Fail2ban command argument constants
const (
	// CommandArgPing is the ping argument
	CommandArgPing = "ping"

	// CommandArgVersion is the version argument
	CommandArgVersion = "-V"

	// CommandArgStatus is the status argument
	CommandArgStatus = "status"
)

// Fail2ban command output constants for testing
const (
	// VersionOutput is the expected version response
	VersionOutput = "fail2ban-client v0.11.2"

	// PingOutput is the expected ping response
	PingOutput = "pong"

	// StatusOutput is sample status output for testing
	StatusOutput = "Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, apache"
)

// Fail2ban command actions
const (
	// ActionGet retrieves a value from fail2ban
	ActionGet = "get"

	// ActionSet sets a value in fail2ban
	ActionSet = "set"

	// ActionBanIP bans an IP address
	ActionBanIP = "banip"

	// ActionUnbanIP unbans an IP address
	ActionUnbanIP = "unbanip"

	// ActionReload reloads fail2ban configuration
	ActionReload = "reload"

	// ActionRestart restarts fail2ban
	ActionRestart = "restart"

	// ActionStart represents the start action (systemctl start, duration markers)
	ActionStart = "start"

	// ActionStop stops fail2ban
	ActionStop = "stop"

	// ActionBanned gets banned IPs
	ActionBanned = "banned"
)

// Mock command responses for testing
const (
	// MockCommandVersion is the full version command string
	MockCommandVersion = "fail2ban-client -V"

	// MockCommandPing is the full ping command string
	MockCommandPing = "fail2ban-client ping"

	// MockCommandStatus is the full status command string
	MockCommandStatus = "fail2ban-client status"

	// MockCommandStatusSSHD is a mock command for getting sshd jail status
	MockCommandStatusSSHD = "fail2ban-client status sshd"

	// MockCommandStatusApache is a mock command for getting apache jail status
	MockCommandStatusApache = "fail2ban-client status apache"

	// MockCommandBanIP is a mock command for banning an IP
	MockCommandBanIP = "fail2ban-client set sshd banip 192.168.1.100"

	// MockCommandUnbanIP is a mock command for unbanning an IP
	MockCommandUnbanIP = "fail2ban-client set sshd unbanip 192.168.1.100"

	// MockCommandBanned is a mock command for getting banned IPs
	MockCommandBanned = "fail2ban-client banned 192.168.1.100"

	// MockBannedOutput is mock output for banned command
	MockBannedOutput = "[\"sshd\"]"
)

// Version information
const (
	// MockVersion is the mock fail2ban version used in tests
	MockVersion = "Fail2Ban v0.11.2"
)

// File and directory constants
const (
	// LogFileName is the standard fail2ban log file name
	LogFileName = "fail2ban.log"

	// LogFilePrefix is the prefix for fail2ban log files
	LogFilePrefix = "fail2ban.log."

	// GzipExtension is the gzip file extension
	GzipExtension = ".gz"

	// ConfExtension is the configuration file extension
	ConfExtension = ".conf"

	// TestDataDir is the directory for test data files
	TestDataDir = "testdata"
)

// Error message templates
const (
	// ErrCommandValidationFailed is the error message for command validation failures
	ErrCommandValidationFailed = "command validation failed: %w"

	// ErrArgumentValidationFailed is the error message for argument validation failures
	ErrArgumentValidationFailed = "argument validation failed: %w"

	// ErrFailedToParseJails is the error message for jail parsing failures
	ErrFailedToParseJails = "failed to parse jails"

	// ErrInvalidJailFormat is the error message for invalid jail name format
	ErrInvalidJailFormat = "invalid jail name format"

	// ErrInvalidIPAddress is the error message for invalid IP address format
	ErrInvalidIPAddress = "invalid IP address: %s"

	// ErrInvalidCommandFormat is the error message for invalid command format
	ErrInvalidCommandFormat = "invalid command format"

	// ErrUnexpectedOutput is the error message for unexpected fail2ban output
	ErrUnexpectedOutput = "unexpected output from fail2ban-client: %s"

	// ErrFailedToBanIP is the error message for ban failures
	ErrFailedToBanIP = "failed to ban IP %s in jail %s: %w"

	// ErrFailedToUnbanIP is the error message for unban failures
	ErrFailedToUnbanIP = "failed to unban IP %s in jail %s: %w"

	// ErrInvalidFilterDirectory is the error message for invalid filter directory
	ErrInvalidFilterDirectory = "invalid filter directory: %w"

	// ErrOperationFailed is the error message template for operation failures
	ErrOperationFailed = "Operation failed after %v"

	// ErrSlowOperation is the error message template for slow operations
	ErrSlowOperation = "Slow operation completed in %v"

	// MsgOperationCompleted is the message template for completed operations
	MsgOperationCompleted = "Operation completed in %v"

	// ErrFailedToResolveSymlink is the error message for symlink resolution failures
	ErrFailedToResolveSymlink = "failed to resolve symlink: %w"

	// ErrScanLogFile is the error message for log scanning errors
	ErrScanLogFile = "error scanning log file: %w"

	// ErrTestDataNotFound is the error message for missing test data
	ErrTestDataNotFound = "Test data file not found: %s"

	// ErrFailedToGetAbsPath is the error message for absolute path failures
	ErrFailedToGetAbsPath = "Failed to get absolute path: %v"

	// ErrMaxLinesNegative is the error message for negative maxLines values
	ErrMaxLinesNegative = "maxLines must be non-negative, got %d"

	// ErrMaxLinesExceedsLimit is the error message for excessive maxLines values
	ErrMaxLinesExceedsLimit = "maxLines exceeds maximum allowed value %d"
)

// Log message templates
const (
	// LogFieldError is the log field name for errors
	LogFieldError = "error"

	// LogFieldFile is the log field name for files
	LogFieldFile = "file"

	// LogFieldPath is the log field name for file paths
	LogFieldPath = "path"

	// LogFieldValue is the log field name for values
	LogFieldValue = "value"

	// LogFieldEnvVar is the log field name for environment variables
	LogFieldEnvVar = "env_var"
)

// Output messages
const (
	// MsgCommandFailed is the message for failed commands
	MsgCommandFailed = "Command failed"

	// MsgBanResult is the message prefix for ban results
	MsgBanResult = "Ban result"

	// MsgUnbanResult is the message prefix for unban results
	MsgUnbanResult = "Unban result"

	// MsgFailedToEncodeJSON is the error message for JSON encoding failures
	MsgFailedToEncodeJSON = "Failed to encode JSON output"

	// MsgFailedToWriteOutput is the error message for output write failures
	MsgFailedToWriteOutput = "Failed to write fallback output"
)

// Command names for metrics and logging
const (
	// MetricsBan is the metrics key for ban operations
	MetricsBan = "ban"

	// MetricsUnban is the metrics key for unban operations
	MetricsUnban = "unban"
)

// Sudo constants
const (
	// SudoCommand is the sudo executable name
	SudoCommand = "sudo"

	// ServiceCommand is the system service command and f2b CLI command name
	ServiceCommand = "service"

	// ServiceFail2ban is the fail2ban service name
	ServiceFail2ban = "fail2ban"
)

// Test assertion templates
const (
	// ErrTestUnexpected is the template for unexpected test errors
	ErrTestUnexpected = "%s: unexpected error: %v"

	// ErrTestExpectedError is the template for missing expected errors
	ErrTestExpectedError = "%s: expected error but got none"

	// ErrTestExpectedOutput is the template for output mismatch
	ErrTestExpectedOutput = "%s: expected output to contain %q, got: %s"

	// ErrTestUnexpectedWithOutput is the template for unexpected errors with output
	ErrTestUnexpectedWithOutput = "%s: unexpected error: %v, output: %s"

	// ErrTestJSONFieldMismatch is the template for JSON field mismatches
	ErrTestJSONFieldMismatch = "%s: expected JSON field %q to be %q, got %v"
)

// CLI flag names
const (
	// FlagLogFile is the log file flag name
	FlagLogFile = "log-file"

	// FlagLogLevel is the log level flag name
	FlagLogLevel = "log-level"

	// FlagFormat is the format flag name
	FlagFormat = "format"

	// FlagLimit is the limit flag name
	FlagLimit = "limit"

	// FlagInterval is the interval flag name
	FlagInterval = "interval"
)

// CLI flag descriptions
const (
	// FlagDescFormat is the description for the format flag
	FlagDescFormat = "Output format: plain or json"
)

// Environment variable names
const (
	// EnvLogLevel is the environment variable for log level
	EnvLogLevel = "F2B_LOG_LEVEL"
)

// Default configuration values
const (
	// DefaultLogLevel is the default log level
	DefaultLogLevel = "info"
)

// Version output format
const (
	// VersionFormat is the format string for version output
	VersionFormat = "f2b version %s"
)

// Output message prefixes
const (
	// ErrorPrefix is the prefix for error messages
	ErrorPrefix = "Error:"

	// MsgInvalidTimeout is the message for invalid timeout values
	MsgInvalidTimeout = "Invalid timeout value, using default"
)

// Metrics output format strings
const (
	// MetricsFmtOperationHeader is the format for operation headers
	MetricsFmtOperationHeader = "  %s:\n"

	// MetricsFmtLatencyUnder1ms is the format for <1ms latency bucket
	MetricsFmtLatencyUnder1ms = "    < 1ms: %d\n"

	// MetricsFmtLatencyUnder10ms is the format for <10ms latency bucket
	MetricsFmtLatencyUnder10ms = "    < 10ms: %d\n"

	// MetricsFmtLatencyUnder100ms is the format for <100ms latency bucket
	MetricsFmtLatencyUnder100ms = "    < 100ms: %d\n"

	// MetricsFmtLatencyUnder1s is the format for <1s latency bucket
	MetricsFmtLatencyUnder1s = "    < 1s: %d\n"

	// MetricsFmtLatencyUnder10s is the format for <10s latency bucket
	MetricsFmtLatencyUnder10s = "    < 10s: %d\n"

	// MetricsFmtLatencyOver10s is the format for >10s latency bucket
	MetricsFmtLatencyOver10s = "    > 10s: %d\n"

	// MetricsFmtAverageLatency is the format for average latency in buckets
	MetricsFmtAverageLatency = "    Average: %.2f ms\n"

	// MetricsFmtTotalFailures is the format for total failures
	MetricsFmtTotalFailures = "  Total Failures: %d\n"

	// MetricsFmtTotalExecutions is the format for total executions
	MetricsFmtTotalExecutions = "  Total Executions: %d\n"

	// MetricsFmtTotalOperations is the format for total operations
	MetricsFmtTotalOperations = "  Total Operations: %d\n"

	// MetricsFmtAverageLatencyTop is the format for average latency (top-level)
	MetricsFmtAverageLatencyTop = "  Average Latency: %.2f ms\n"
)
