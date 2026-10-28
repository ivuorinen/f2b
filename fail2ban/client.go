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

	// runner executes this client's commands. It is injected at construction
	// so a client keeps the runner it was built with instead of whatever the
	// process-global SetRunner holds at call time; nil (a zero-value
	// RealClient) falls back to GetRunner().
	runner Runner
}

// cmdRunner returns the client's injected runner, or the global runner for a
// zero-value RealClient so struct literals in tests keep working.
func (c *RealClient) cmdRunner() Runner {
	if c.runner != nil {
		return c.runner
	}
	return GetRunner()
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

	// Go test binaries always use the plain command name, so an injected mock
	// runner receives the same argv on every host. Resolving here instead would
	// make the argv depend on whether the machine happens to have fail2ban
	// installed — the suite then passes on CI, where it is absent, and fails on
	// a maintainer's workstation, where LookPath yields /usr/bin/fail2ban-client
	// and no registered mock response matches.
	//
	// Gated on IsGoTestBinary, not IsTestEnvironment: the latter also trusts the
	// GO_TEST/F2B_TEST/F2B_TEST_SUDO variables, and a bare command name set from
	// an ordinary shell would hand PATH the choice of which binary sudo runs.
	resolvedPath := constants.Fail2BanClientCommand
	if !IsGoTestBinary() {
		// Resolve the absolute path to prevent PATH hijacking.
		lookedUpPath, err := exec.LookPath(constants.Fail2BanClientCommand)
		if err != nil {
			return nil, fmt.Errorf("%s not found in PATH", constants.Fail2BanClientCommand)
		}
		resolvedPath = lookedUpPath
	}

	if logDir == "" {
		logDir = constants.DefaultLogDir
	}
	if filterDir == "" {
		filterDir = constants.DefaultFilterDir
	}

	validatedLogDir, err := ValidateClientLogPath(logDir)
	if err != nil {
		return nil, fmt.Errorf("invalid log directory: %w", err)
	}

	validatedFilterDir, err := ValidateClientFilterPath(filterDir)
	if err != nil {
		// The constant already carries %w; nesting it under "%s: %w" printed a
		// literal "%w" in the message.
		return nil, fmt.Errorf(constants.ErrInvalidFilterDirectory, err)
	}

	rc := &RealClient{
		Path:      resolvedPath, // Use resolved absolute path
		LogDir:    validatedLogDir,
		FilterDir: validatedFilterDir,
		runner:    GetRunner(),
	}

	// Version check - use sudo if needed with context
	if err := rc.verifyMinimumVersion(ctx); err != nil {
		return nil, err
	}
	// Ping - use sudo if needed with context. Wrap the underlying error so the
	// real cause (socket permission denied, validation failure, timeout) is not
	// masked as a stopped service.
	if _, err := rc.cmdRunner().CombinedOutputWithSudoContext(ctx, rc.Path, constants.CommandArgPing); err != nil {
		return nil, fmt.Errorf("fail2ban service not running: %w", err)
	}
	jails, err := rc.fetchJailsWithContext(ctx)
	if err != nil {
		return nil, err
	}
	rc.Jails = jails
	return rc, nil
}

// verifyMinimumVersion runs `fail2ban-client -V` through the client's runner,
// parses the reported version, and returns an error if it is below the
// minimum f2b supports.
func (c *RealClient) verifyMinimumVersion(ctx context.Context) error {
	const minVersion = "0.11.0"
	out, err := c.cmdRunner().CombinedOutputWithSudoContext(ctx, c.Path, constants.CommandArgVersion)
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

// ListJailsWithContext returns the jails loaded when the client was built. It
// honors cancellation so a canceled command does not report a stale success.
func (c *RealClient) ListJailsWithContext(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.Jails, nil
}
