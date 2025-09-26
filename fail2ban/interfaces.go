package fail2ban

import (
	"context"
)

// Client defines the interface for interacting with Fail2Ban.
// Implementations must provide all core operations for jail and ban management.
type Client interface {
	// ListJails returns all available Fail2Ban jails.
	ListJails() ([]string, error)
	// StatusAll returns the status output for all jails.
	StatusAll() (string, error)
	// StatusJail returns the status output for a specific jail.
	StatusJail(string) (string, error)
	// BanIP bans the given IP in the specified jail. Returns 0 if banned, 1 if already banned.
	BanIP(ip, jail string) (int, error)
	// UnbanIP unbans the given IP in the specified jail. Returns 0 if unbanned, 1 if already unbanned.
	UnbanIP(ip, jail string) (int, error)
	// BannedIn returns the list of jails in which the IP is currently banned.
	BannedIn(ip string) ([]string, error)
	// GetBanRecords returns ban records for the specified jails.
	GetBanRecords(jails []string) ([]BanRecord, error)
	// GetLogLines returns log lines filtered by jail and/or IP.
	GetLogLines(jail, ip string) ([]string, error)
	// ListFilters returns the available Fail2Ban filters.
	ListFilters() ([]string, error)
	// TestFilter runs fail2ban-regex for the given filter.
	TestFilter(filter string) (string, error)

	// Context-aware versions for timeout and cancellation support
	ListJailsWithContext(ctx context.Context) ([]string, error)
	StatusAllWithContext(ctx context.Context) (string, error)
	StatusJailWithContext(ctx context.Context, jail string) (string, error)
	BanIPWithContext(ctx context.Context, ip, jail string) (int, error)
	UnbanIPWithContext(ctx context.Context, ip, jail string) (int, error)
	BannedInWithContext(ctx context.Context, ip string) ([]string, error)
	GetBanRecordsWithContext(ctx context.Context, jails []string) ([]BanRecord, error)
	GetLogLinesWithContext(ctx context.Context, jail, ip string) ([]string, error)
	ListFiltersWithContext(ctx context.Context) ([]string, error)
	TestFilterWithContext(ctx context.Context, filter string) (string, error)
}

// Runner defines the interface for executing system commands.
// Implementations provide different execution strategies (real, mock, etc.).
type Runner interface {
	CombinedOutput(name string, args ...string) ([]byte, error)
	CombinedOutputWithSudo(name string, args ...string) ([]byte, error)
	// Context-aware versions for timeout and cancellation support
	CombinedOutputWithContext(ctx context.Context, name string, args ...string) ([]byte, error)
	CombinedOutputWithSudoContext(ctx context.Context, name string, args ...string) ([]byte, error)
}

// SudoChecker provides methods to check sudo privileges
type SudoChecker interface {
	// IsRoot returns true if the current user is root (UID 0)
	IsRoot() bool
	// InSudoGroup returns true if the current user is in the sudo group
	InSudoGroup() bool
	// CanUseSudo returns true if the current user can use sudo
	CanUseSudo() bool
	// HasSudoPrivileges returns true if user has any form of sudo access
	HasSudoPrivileges() bool
}

// MetricsRecorder defines interface for recording metrics
type MetricsRecorder interface {
	// RecordValidationCacheHit records validation cache hits
	RecordValidationCacheHit()
	// RecordValidationCacheMiss records validation cache misses
	RecordValidationCacheMiss()
}
