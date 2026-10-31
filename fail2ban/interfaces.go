// Core interfaces (Client, Runner, SudoChecker) that define the contract for
// interacting with fail2ban services and system operations.

package fail2ban

import (
	"context"
)

// Client defines the interface for interacting with Fail2Ban.
//
// Every operation takes a context so commands run under their timeout and
// signal cancellation; there are deliberately no context-free variants.
type Client interface {
	// ListJailsWithContext returns all available Fail2Ban jails.
	ListJailsWithContext(ctx context.Context) ([]string, error)
	// StatusAllWithContext returns the status output for all jails.
	StatusAllWithContext(ctx context.Context) (string, error)
	// StatusJailWithContext returns the status output for a specific jail.
	StatusJailWithContext(ctx context.Context, jail string) (string, error)
	// BanIPWithContext bans ip in jail. Returns 0 if banned, 1 if already banned.
	BanIPWithContext(ctx context.Context, ip, jail string) (int, error)
	// UnbanIPWithContext unbans ip in jail. Returns 0 if unbanned, 1 if already unbanned.
	UnbanIPWithContext(ctx context.Context, ip, jail string) (int, error)
	// BannedInWithContext returns the jails in which ip is currently banned.
	BannedInWithContext(ctx context.Context, ip string) ([]string, error)
	// GetBanRecordsWithContext returns ban records for the specified jails.
	GetBanRecordsWithContext(ctx context.Context, jails []string) ([]BanRecord, error)
	// GetLogLinesWithContext returns the newest DefaultLogLinesLimit log lines
	// filtered by jail and/or IP.
	GetLogLinesWithContext(ctx context.Context, jail, ip string) ([]string, error)
	// GetLogLinesWithLimitContext returns the newest maxLines log lines
	// filtered by jail and/or IP. The limit is part of the contract so callers
	// never fall back to a default-capped read and trim afterwards, which
	// silently truncated any limit above the default.
	GetLogLinesWithLimitContext(ctx context.Context, jail, ip string, maxLines int) ([]string, error)
	// ListFiltersWithContext returns the available Fail2Ban filters.
	ListFiltersWithContext(ctx context.Context) ([]string, error)
	// TestFilterWithContext runs fail2ban-regex for the given filter.
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
