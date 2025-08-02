package fail2ban

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
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

// RealClient is the default implementation of Client, using the local fail2ban-client binary.
type RealClient struct {
	Path      string // Path to fail2ban-client
	Jails     []string
	LogDir    string
	FilterDir string
}

// BanRecord represents a single ban entry with jail, IP, ban time, and remaining duration.
type BanRecord struct {
	Jail      string
	IP        string
	BannedAt  time.Time
	Remaining string
}

// NewClient initializes a RealClient, verifying the environment and fail2ban-client availability.
// It checks for fail2ban-client in PATH, ensures the service is running, checks sudo privileges,
// and loads available jails. Returns an error if fail2ban is not available, not running, or
// user lacks sudo privileges.
func NewClient(logDir, filterDir string) (*RealClient, error) {
	return NewClientWithContext(context.Background(), logDir, filterDir)
}

// NewClientWithContext initializes a RealClient with context support for timeout and cancellation.
// It checks for fail2ban-client in PATH, ensures the service is running, checks sudo privileges,
// and loads available jails. Returns an error if fail2ban is not available, not running, or
// user lacks sudo privileges.
func NewClientWithContext(ctx context.Context, logDir, filterDir string) (*RealClient, error) {
	// Check sudo privileges first (skip in test environment unless forced)
	if !IsTestEnvironment() || os.Getenv("F2B_TEST_SUDO") == "true" {
		if err := CheckSudoRequirements(); err != nil {
			return nil, err
		}
	}

	path, err := exec.LookPath(Fail2BanClientCommand)
	if err != nil {
		// Check if we have a mock runner set up
		if _, ok := GetRunner().(*MockRunner); !ok {
			return nil, fmt.Errorf("%s not found in PATH", Fail2BanClientCommand)
		}
		path = Fail2BanClientCommand // Use mock path
	}
	if logDir == "" {
		logDir = DefaultLogDir
	}
	if filterDir == "" {
		filterDir = DefaultFilterDir
	}

	// Validate log directory
	logAllowedPaths := GetLogAllowedPaths()
	logConfig := PathSecurityConfig{
		AllowedBasePaths: logAllowedPaths,
		MaxPathLength:    4096,
		AllowSymlinks:    false,
		ResolveSymlinks:  true,
	}
	validatedLogDir, err := validatePathWithSecurity(logDir, logConfig)
	if err != nil {
		return nil, fmt.Errorf("invalid log directory: %w", err)
	}

	// Validate filter directory
	filterAllowedPaths := GetFilterAllowedPaths()
	filterConfig := PathSecurityConfig{
		AllowedBasePaths: filterAllowedPaths,
		MaxPathLength:    4096,
		AllowSymlinks:    false,
		ResolveSymlinks:  true,
	}
	validatedFilterDir, err := validatePathWithSecurity(filterDir, filterConfig)
	if err != nil {
		return nil, fmt.Errorf("invalid filter directory: %w", err)
	}

	rc := &RealClient{Path: path, LogDir: validatedLogDir, FilterDir: validatedFilterDir}

	// Version check - use sudo if needed with context
	out, err := RunnerCombinedOutputWithSudoContext(ctx, path, "-V")
	if err != nil {
		return nil, fmt.Errorf("version check failed: %w", err)
	}
	if CompareVersions(strings.TrimSpace(string(out)), "0.11.0") < 0 {
		return nil, fmt.Errorf("fail2ban >=0.11.0 required, got %s", out)
	}
	// Ping - use sudo if needed with context
	if err := runnerCombinedRunWithSudoContext(ctx, path, "ping"); err != nil {
		return nil, errors.New("fail2ban service not running")
	}
	jails, err := rc.fetchJailsWithContext(ctx)
	if err != nil {
		return nil, err
	}
	rc.Jails = jails
	return rc, nil
}

// ListJails returns the list of available jails for this client.
func (c *RealClient) ListJails() ([]string, error) {
	return c.Jails, nil
}
