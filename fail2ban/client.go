package fail2ban

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// RealClient is the default implementation of Client, using the local fail2ban-client binary.
type RealClient struct {
	Path      string // Command used to invoke fail2ban-client
	Jails     []string
	LogDir    string
	FilterDir string
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
	// Check sudo privileges first (skip in test environment)
	if !IsTestEnvironment() {
		if err := CheckSudoRequirements(); err != nil {
			return nil, err
		}
	}

	// Resolve the absolute path to prevent PATH hijacking
	resolvedPath, err := exec.LookPath(Fail2BanClientCommand)
	if err != nil {
		if _, ok := GetRunner().(*MockRunner); !ok {
			return nil, fmt.Errorf("%s not found in PATH", Fail2BanClientCommand)
		}
		// For mock runner, use the plain command name
		resolvedPath = Fail2BanClientCommand
	}

	if logDir == "" {
		logDir = DefaultLogDir
	}
	if filterDir == "" {
		filterDir = DefaultFilterDir
	}

	// Validate log directory using centralized helper
	validatedLogDir, err := ValidateClientLogPath(logDir)
	if err != nil {
		return nil, fmt.Errorf("invalid log directory: %w", err)
	}

	// Validate filter directory using centralized helper
	validatedFilterDir, err := ValidateClientFilterPath(filterDir)
	if err != nil {
		return nil, fmt.Errorf("invalid filter directory: %w", err)
	}

	rc := &RealClient{
		Path:      resolvedPath, // Use resolved absolute path
		LogDir:    validatedLogDir,
		FilterDir: validatedFilterDir,
	}

	// Version check - use sudo if needed with context
	out, err := RunnerCombinedOutputWithSudoContext(ctx, rc.Path, "-V")
	if err != nil {
		return nil, fmt.Errorf("version check failed: %w", err)
	}
	rawVersion := strings.TrimSpace(string(out))
	parsedVersion, err := ExtractFail2BanVersion(rawVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to parse fail2ban version: %w", err)
	}
	if CompareVersions(parsedVersion, "0.11.0") < 0 {
		return nil, fmt.Errorf("fail2ban >=0.11.0 required, got %s", rawVersion)
	}
	// Ping - use sudo if needed with context
	if _, err := RunnerCombinedOutputWithSudoContext(ctx, rc.Path, "ping"); err != nil {
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
