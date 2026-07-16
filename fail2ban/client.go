package fail2ban

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ivuorinen/f2b/constants"
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
	resolvedPath, err := exec.LookPath(constants.Fail2BanClientCommand)
	if err != nil {
		if !IsTestEnvironment() {
			return nil, fmt.Errorf("%s not found in PATH", constants.Fail2BanClientCommand)
		}
		// In tests the real binary may be absent; fall back to the plain command
		// name so an injected mock runner still receives the expected argv.
		resolvedPath = constants.Fail2BanClientCommand
	}

	if logDir == "" {
		logDir = constants.DefaultLogDir
	}
	if filterDir == "" {
		filterDir = constants.DefaultFilterDir
	}

	// Validate log directory using centralized helper with context
	validatedLogDir, err := ValidateClientLogPath(ctx, logDir)
	if err != nil {
		return nil, fmt.Errorf("invalid log directory: %w", err)
	}

	// Validate filter directory using centralized helper with context
	validatedFilterDir, err := ValidateClientFilterPath(ctx, filterDir)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", constants.ErrInvalidFilterDirectory, err)
	}

	rc := &RealClient{
		Path:      resolvedPath, // Use resolved absolute path
		LogDir:    validatedLogDir,
		FilterDir: validatedFilterDir,
	}

	// Version check - use sudo if needed with context
	if err := verifyMinimumVersion(ctx, rc.Path); err != nil {
		return nil, err
	}
	// Ping - use sudo if needed with context. Wrap the underlying error so the
	// real cause (socket permission denied, validation failure, timeout) is not
	// masked as a stopped service.
	if _, err := RunnerCombinedOutputWithSudoContext(ctx, rc.Path, constants.CommandArgPing); err != nil {
		return nil, fmt.Errorf("fail2ban service not running: %w", err)
	}
	jails, err := rc.fetchJailsWithContext(ctx)
	if err != nil {
		return nil, err
	}
	rc.Jails = jails
	return rc, nil
}

// verifyMinimumVersion runs `fail2ban-client -V`, parses the reported version,
// and returns an error if it is below the minimum f2b supports.
func verifyMinimumVersion(ctx context.Context, path string) error {
	const minVersion = "0.11.0"
	out, err := RunnerCombinedOutputWithSudoContext(ctx, path, constants.CommandArgVersion)
	if err != nil {
		return fmt.Errorf("version check failed: %w", err)
	}
	rawVersion := strings.TrimSpace(string(out))
	parsedVersion, err := ExtractFail2BanVersion(rawVersion)
	if err != nil {
		return fmt.Errorf("failed to parse fail2ban version: %w", err)
	}
	if CompareVersions(parsedVersion, minVersion) < 0 {
		return fmt.Errorf("fail2ban >=%s required, got %s", minVersion, rawVersion)
	}
	return nil
}

// ListJails returns the list of available jails for this client.
func (c *RealClient) ListJails() ([]string, error) {
	return c.Jails, nil
}
