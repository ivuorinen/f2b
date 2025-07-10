package fail2ban

import (
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
	// Check sudo privileges first (skip in test environment unless forced)
	if !isTest() || os.Getenv("F2B_TEST_SUDO") == "true" {
		if err := CheckSudoRequirements(); err != nil {
			return nil, err
		}
	}

	path, err := exec.LookPath("fail2ban-client")
	if err != nil {
		// Check if we have a mock runner set up
		if _, ok := runner.(*MockRunner); ok {
			path = "fail2ban-client" // Use mock path
		} else {
			return nil, errors.New("fail2ban-client not found in PATH")
		}
	}
	if logDir == "" {
		logDir = DefaultLogDir
	}
	if filterDir == "" {
		filterDir = DefaultFilterDir
	}

	rc := &RealClient{Path: path, LogDir: logDir, FilterDir: filterDir}

	// Version check - use sudo if needed
	out, err := RunnerCombinedOutputWithSudo(path, "-V")
	if err != nil {
		return nil, fmt.Errorf("version check failed: %v", err)
	}
	if compareVersions(strings.TrimSpace(string(out)), "0.11.0") < 0 {
		return nil, fmt.Errorf("fail2ban >=0.11.0 required, got %s", out)
	}
	// Ping - use sudo if needed
	if err := runnerCombinedRunWithSudo(path, "ping"); err != nil {
		return nil, errors.New("fail2ban service not running")
	}
	jails, err := rc.fetchJails()
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
