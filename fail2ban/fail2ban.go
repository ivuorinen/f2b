// Package fail2ban provides comprehensive functionality for managing fail2ban jails and filters
// with secure command execution, input validation, caching, and performance optimization.
package fail2ban

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	// DefaultLogDir is the default directory for fail2ban logs
	DefaultLogDir = "/var/log"
	// DefaultFilterDir is the default directory for fail2ban filters
	DefaultFilterDir = "/etc/fail2ban/filter.d"
	// AllFilter represents all jails/IPs filter
	AllFilter = "all"
	// DefaultMaxFileSize is the default maximum file size for log reading (100MB)
	DefaultMaxFileSize = 100 * 1024 * 1024
	// DefaultLogLinesLimit is the default limit for log lines returned
	DefaultLogLinesLimit = 1000
)

var logDir = DefaultLogDir // base directory for fail2ban logs
var logDirMu sync.RWMutex  // protects logDir from concurrent access
var filterDir = DefaultFilterDir
var filterDirMu sync.RWMutex // protects filterDir from concurrent access

// GetFilterDir returns the current filter directory path.
func GetFilterDir() string {
	filterDirMu.RLock()
	defer filterDirMu.RUnlock()
	return filterDir
}

// SetLogDir sets the directory path for log files.
func SetLogDir(dir string) {
	logDirMu.Lock()
	defer logDirMu.Unlock()
	logDir = dir
}

// GetLogDir returns the current log directory path.
func GetLogDir() string {
	logDirMu.RLock()
	defer logDirMu.RUnlock()
	return logDir
}

// SetFilterDir sets the directory path for filter configuration files.
func SetFilterDir(dir string) {
	filterDirMu.Lock()
	defer filterDirMu.Unlock()
	filterDir = dir
}

// OSRunner runs commands locally.
type OSRunner struct{}

// CombinedOutput executes a command without sudo.
func (r *OSRunner) CombinedOutput(name string, args ...string) ([]byte, error) {
	// Validate command for security
	if err := CachedValidateCommand(name); err != nil {
		return nil, fmt.Errorf("command validation failed: %w", err)
	}
	// Validate arguments for security
	if err := ValidateArguments(args); err != nil {
		return nil, fmt.Errorf("argument validation failed: %w", err)
	}
	return exec.Command(name, args...).CombinedOutput()
}

// CombinedOutputWithContext executes a command without sudo with context support.
func (r *OSRunner) CombinedOutputWithContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	// Validate command for security
	if err := CachedValidateCommand(name); err != nil {
		return nil, fmt.Errorf("command validation failed: %w", err)
	}
	// Validate arguments for security
	if err := ValidateArguments(args); err != nil {
		return nil, fmt.Errorf("argument validation failed: %w", err)
	}
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// CombinedOutputWithSudo executes a command with sudo if needed.
func (r *OSRunner) CombinedOutputWithSudo(name string, args ...string) ([]byte, error) {
	// Validate command for security
	if err := CachedValidateCommand(name); err != nil {
		return nil, fmt.Errorf("command validation failed: %w", err)
	}
	// Validate arguments for security
	if err := ValidateArguments(args); err != nil {
		return nil, fmt.Errorf("argument validation failed: %w", err)
	}

	checker := GetSudoChecker()

	// If already root, no need for sudo
	if checker.IsRoot() {
		return exec.Command(name, args...).CombinedOutput()
	}

	// If command requires sudo and user has privileges, use sudo
	if RequiresSudo(name, args...) && checker.HasSudoPrivileges() {
		sudoArgs := append([]string{name}, args...)
		// #nosec G204 - This is a legitimate use case for executing fail2ban-client with sudo
		// The command name and arguments are validated by ValidateCommand() and RequiresSudo()
		return exec.Command("sudo", sudoArgs...).CombinedOutput()
	}

	// Otherwise run without sudo
	return exec.Command(name, args...).CombinedOutput()
}

// CombinedOutputWithSudoContext executes a command with sudo if needed, with context support.
func (r *OSRunner) CombinedOutputWithSudoContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	// Validate command for security
	if err := CachedValidateCommand(name); err != nil {
		return nil, fmt.Errorf("command validation failed: %w", err)
	}
	// Validate arguments for security
	if err := ValidateArguments(args); err != nil {
		return nil, fmt.Errorf("argument validation failed: %w", err)
	}

	checker := GetSudoChecker()

	// If already root, no need for sudo
	if checker.IsRoot() {
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}

	// If command requires sudo and user has privileges, use sudo
	if RequiresSudo(name, args...) && checker.HasSudoPrivileges() {
		sudoArgs := append([]string{name}, args...)
		// #nosec G204 - This is a legitimate use case for executing fail2ban-client with sudo
		// The command name and arguments are validated by ValidateCommand() and RequiresSudo()
		return exec.CommandContext(ctx, "sudo", sudoArgs...).CombinedOutput()
	}

	// Otherwise run without sudo
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// runnerManager provides thread-safe access to the global Runner.
type runnerManager struct {
	mu     sync.RWMutex
	runner Runner
}

// globalRunnerManager is the singleton instance for managing the global runner.
var globalRunnerManager = &runnerManager{
	runner: &OSRunner{},
}

// SetRunner injects a custom runner (for tests or alternate backends).
// SetRunner sets the global command runner instance.
func SetRunner(r Runner) {
	globalRunnerManager.mu.Lock()
	defer globalRunnerManager.mu.Unlock()
	globalRunnerManager.runner = r
}

// GetRunner returns the current runner (for tests that need access).
// GetRunner returns the current global command runner instance.
func GetRunner() Runner {
	globalRunnerManager.mu.RLock()
	defer globalRunnerManager.mu.RUnlock()
	return globalRunnerManager.runner
}

// RunnerCombinedOutput invokes the runner for a command.
// RunnerCombinedOutput executes a command using the global runner and returns combined stdout/stderr output.
func RunnerCombinedOutput(name string, args ...string) ([]byte, error) {
	timer := NewTimedOperation("RunnerCombinedOutput", name, args...)

	runner := GetRunner()

	output, err := runner.CombinedOutput(name, args...)
	timer.Finish(err)

	return output, err
}

// RunnerCombinedOutputWithSudo invokes the runner for a command with sudo if needed.
// RunnerCombinedOutputWithSudo executes a command with sudo privileges using the global runner.
func RunnerCombinedOutputWithSudo(name string, args ...string) ([]byte, error) {
	timer := NewTimedOperation("RunnerCombinedOutputWithSudo", name, args...)

	runner := GetRunner()

	output, err := runner.CombinedOutputWithSudo(name, args...)
	timer.Finish(err)

	return output, err
}

// RunnerCombinedOutputWithContext invokes the runner for a command with context support.
// RunnerCombinedOutputWithContext executes a command with context using the global runner.
func RunnerCombinedOutputWithContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	timer := NewTimedOperation("RunnerCombinedOutputWithContext", name, args...)

	runner := GetRunner()

	output, err := runner.CombinedOutputWithContext(ctx, name, args...)
	timer.FinishWithContext(ctx, err)

	return output, err
}

// RunnerCombinedOutputWithSudoContext invokes the runner for a command with sudo and context support.
// RunnerCombinedOutputWithSudoContext executes a command with sudo privileges and context using the global runner.
func RunnerCombinedOutputWithSudoContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	timer := NewTimedOperation("RunnerCombinedOutputWithSudoContext", name, args...)

	runner := GetRunner()

	output, err := runner.CombinedOutputWithSudoContext(ctx, name, args...)
	timer.FinishWithContext(ctx, err)

	return output, err
}

// MockRunner is a simple mock for Runner, used in unit tests.
type MockRunner struct {
	mu        sync.Mutex // protects concurrent access to fields
	Responses map[string][]byte
	Errors    map[string]error
	CallLog   []string
}

// NewMockRunner creates a new MockRunner for testing
// NewMockRunner creates a new mock runner instance for testing.
func NewMockRunner() *MockRunner {
	return &MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
		CallLog:   []string{},
	}
}

// CombinedOutput returns a mocked response or error for a command.
func (m *MockRunner) CombinedOutput(name string, args ...string) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	if name == "sudo" {
		m.mu.Lock()
		defer m.mu.Unlock()

		m.CallLog = append(m.CallLog, key)

		if err, exists := m.Errors[key]; exists {
			return nil, err
		}

		if response, exists := m.Responses[key]; exists {
			return response, nil
		}

		return nil, fmt.Errorf("sudo should not be called directly in tests")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.CallLog = append(m.CallLog, key)

	if err, exists := m.Errors[key]; exists {
		return nil, err
	}

	if response, exists := m.Responses[key]; exists {
		return response, nil
	}

	return nil, fmt.Errorf("unexpected command: %s", key)
}

// CombinedOutputWithSudo returns a mocked response for sudo commands.
func (m *MockRunner) CombinedOutputWithSudo(name string, args ...string) ([]byte, error) {
	checker := GetSudoChecker()

	// If mock checker says we're root, don't use sudo
	if checker.IsRoot() {
		return m.CombinedOutput(name, args...)
	}

	// If command requires sudo and we have privileges, mock with sudo
	if RequiresSudo(name, args...) && checker.HasSudoPrivileges() {
		sudoKey := "sudo " + name + " " + strings.Join(args, " ")

		// Check for sudo-specific response first (with lock protection)
		m.mu.Lock()
		m.CallLog = append(m.CallLog, sudoKey)

		if err, exists := m.Errors[sudoKey]; exists {
			m.mu.Unlock()
			return nil, err
		}

		if response, exists := m.Responses[sudoKey]; exists {
			m.mu.Unlock()
			return response, nil
		}
		m.mu.Unlock()

		// Fall back to non-sudo version if sudo version not mocked
		return m.CombinedOutput(name, args...)
	}

	// Otherwise run without sudo
	return m.CombinedOutput(name, args...)
}

// SetResponse sets a response for a command.
func (m *MockRunner) SetResponse(cmd string, response []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Responses[cmd] = response
}

// SetError sets an error for a command.
func (m *MockRunner) SetError(cmd string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Errors[cmd] = err
}

// GetCalls returns the log of commands called.
func (m *MockRunner) GetCalls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Return a copy to prevent external modification
	calls := make([]string, len(m.CallLog))
	copy(calls, m.CallLog)
	return calls
}

// CombinedOutputWithContext returns a mocked response or error for a command with context support.
func (m *MockRunner) CombinedOutputWithContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	// Check if context is canceled
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Delegate to the non-context version for simplicity in tests
	return m.CombinedOutput(name, args...)
}

// CombinedOutputWithSudoContext returns a mocked response for sudo commands with context support.
func (m *MockRunner) CombinedOutputWithSudoContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	// Check if context is canceled
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Delegate to the non-context version for simplicity in tests
	return m.CombinedOutputWithSudo(name, args...)
}

func (c *RealClient) fetchJailsWithContext(ctx context.Context) ([]string, error) {
	currentRunner := GetRunner()
	out, err := currentRunner.CombinedOutputWithSudoContext(ctx, c.Path, "status")
	if err != nil {
		return nil, err
	}
	return ParseJailList(string(out))
}

// StatusAll returns the status of all fail2ban jails.
func (c *RealClient) StatusAll() (string, error) {
	currentRunner := GetRunner()
	out, err := currentRunner.CombinedOutputWithSudo(c.Path, "status")
	return string(out), err
}

// StatusJail returns the status of a specific fail2ban jail.
func (c *RealClient) StatusJail(j string) (string, error) {
	currentRunner := GetRunner()
	out, err := currentRunner.CombinedOutputWithSudo(c.Path, "status", j)
	return string(out), err
}

// BanIP bans an IP address in the specified jail and returns the ban status code.
func (c *RealClient) BanIP(ip, jail string) (int, error) {
	if err := CachedValidateIP(ip); err != nil {
		return 0, err
	}
	if err := CachedValidateJail(jail); err != nil {
		return 0, err
	}

	// Check if jail exists
	if err := ValidateJailExists(jail, c.Jails); err != nil {
		return 0, err
	}

	currentRunner := GetRunner()
	out, err := currentRunner.CombinedOutputWithSudo(c.Path, "set", jail, "banip", ip)
	if err != nil {
		return 0, fmt.Errorf("failed to ban IP %s in jail %s: %w", ip, jail, err)
	}
	code := strings.TrimSpace(string(out))
	if code == Fail2BanStatusSuccess {
		return 0, nil
	}
	if code == Fail2BanStatusAlreadyProcessed {
		return 1, nil
	}
	return 0, fmt.Errorf("unexpected output from fail2ban-client: %s", code)
}

// UnbanIP unbans an IP address from the specified jail and returns the unban status code.
func (c *RealClient) UnbanIP(ip, jail string) (int, error) {
	if err := CachedValidateIP(ip); err != nil {
		return 0, err
	}
	if err := CachedValidateJail(jail); err != nil {
		return 0, err
	}

	// Check if jail exists
	if err := ValidateJailExists(jail, c.Jails); err != nil {
		return 0, err
	}

	currentRunner := GetRunner()
	out, err := currentRunner.CombinedOutputWithSudo(c.Path, "set", jail, "unbanip", ip)
	if err != nil {
		return 0, fmt.Errorf("failed to unban IP %s in jail %s: %w", ip, jail, err)
	}
	code := strings.TrimSpace(string(out))
	if code == Fail2BanStatusSuccess {
		return 0, nil
	}
	if code == Fail2BanStatusAlreadyProcessed {
		return 1, nil
	}
	return 0, fmt.Errorf("unexpected output from fail2ban-client: %s", code)
}

// BannedIn returns a list of jails where the specified IP address is currently banned.
func (c *RealClient) BannedIn(ip string) ([]string, error) {
	if err := CachedValidateIP(ip); err != nil {
		return nil, err
	}

	currentRunner := GetRunner()
	out, err := currentRunner.CombinedOutputWithSudo(c.Path, "banned", ip)
	if err != nil {
		return nil, fmt.Errorf("failed to check if IP %s is banned: %w", ip, err)
	}
	return ParseBracketedList(string(out)), nil
}

// GetBanRecords retrieves ban records for the specified jails.
func (c *RealClient) GetBanRecords(jails []string) ([]BanRecord, error) {
	return c.GetBanRecordsWithContext(context.Background(), jails)
}

// getBanRecordsInternal is the internal implementation with context support
func (c *RealClient) getBanRecordsInternal(ctx context.Context, jails []string) ([]BanRecord, error) {
	var toQuery []string
	if len(jails) == 1 && (jails[0] == AllFilter || jails[0] == "") {
		toQuery = c.Jails
	} else {
		toQuery = jails
	}

	currentRunner := GetRunner()

	// Use parallel processing for multiple jails
	allRecords, err := ProcessJailsParallel(
		ctx,
		toQuery,
		func(operationCtx context.Context, jail string) ([]BanRecord, error) {
			out, err := currentRunner.CombinedOutputWithSudoContext(
				operationCtx,
				c.Path,
				"get",
				jail,
				"banip",
				"--with-time",
			)
			if err != nil {
				// Log error but continue processing (backward compatibility)
				getLogger().WithError(err).WithField("jail", jail).
					Warn("Failed to get ban records for jail")
				return []BanRecord{}, nil // Return empty slice instead of error (original behavior)
			}

			// Use ultra-optimized parser for this jail's records
			jailRecords, parseErr := ParseBanRecordsUltraOptimized(string(out), jail)
			if parseErr != nil {
				// Log parse errors to help with debugging
				getLogger().WithError(parseErr).WithField("jail", jail).
					Warn("Failed to parse ban records for jail")
				return []BanRecord{}, nil // Return empty slice on parse error
			}

			return jailRecords, nil
		},
	)

	if err != nil {
		return nil, err
	}

	sort.Slice(allRecords, func(i, j int) bool {
		return allRecords[i].BannedAt.Before(allRecords[j].BannedAt)
	})
	return allRecords, nil
}

// GetLogLines retrieves log lines related to an IP address from the specified jail.
func (c *RealClient) GetLogLines(jail, ip string) ([]string, error) {
	return c.GetLogLinesWithLimit(jail, ip, DefaultLogLinesLimit)
}

// GetLogLinesWithLimit returns log lines with configurable limits for memory management.
func (c *RealClient) GetLogLinesWithLimit(jail, ip string, maxLines int) ([]string, error) {
	return c.GetLogLinesWithLimitContext(context.Background(), jail, ip, maxLines)
}

// GetLogLinesWithLimitContext returns log lines with configurable limits and context support.
func (c *RealClient) GetLogLinesWithLimitContext(ctx context.Context, jail, ip string, maxLines int) ([]string, error) {
	if maxLines == 0 {
		return []string{}, nil
	}

	config := LogReadConfig{
		MaxLines:    maxLines,
		MaxFileSize: DefaultMaxFileSize,
		JailFilter:  jail,
		IPFilter:    ip,
		BaseDir:     c.LogDir,
	}

	return collectLogLines(ctx, c.LogDir, config)
}

// ListFilters returns a list of available fail2ban filter files.
func (c *RealClient) ListFilters() ([]string, error) {
	entries, err := os.ReadDir(c.FilterDir)
	if err != nil {
		return nil, fmt.Errorf("could not list filters: %w", err)
	}
	filters := []string{}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".conf") {
			filters = append(filters, strings.TrimSuffix(name, ".conf"))
		}
	}
	return filters, nil
}

// Context-aware implementations for RealClient

// ListJailsWithContext returns a list of all fail2ban jails with context support.
func (c *RealClient) ListJailsWithContext(ctx context.Context) ([]string, error) {
	return wrapWithContext0(c.ListJails)(ctx)
}

// StatusAllWithContext returns the status of all fail2ban jails with context support.
func (c *RealClient) StatusAllWithContext(ctx context.Context) (string, error) {
	currentRunner := GetRunner()

	out, err := currentRunner.CombinedOutputWithSudoContext(ctx, c.Path, "status")
	return string(out), err
}

// StatusJailWithContext returns the status of a specific fail2ban jail with context support.
func (c *RealClient) StatusJailWithContext(ctx context.Context, jail string) (string, error) {
	currentRunner := GetRunner()

	out, err := currentRunner.CombinedOutputWithSudoContext(ctx, c.Path, "status", jail)
	return string(out), err
}

// BanIPWithContext bans an IP address in the specified jail with context support.
func (c *RealClient) BanIPWithContext(ctx context.Context, ip, jail string) (int, error) {
	if err := CachedValidateIP(ip); err != nil {
		return 0, err
	}
	if err := CachedValidateJail(jail); err != nil {
		return 0, err
	}

	currentRunner := GetRunner()

	out, err := currentRunner.CombinedOutputWithSudoContext(ctx, c.Path, "set", jail, "banip", ip)
	if err != nil {
		return 0, fmt.Errorf("failed to ban IP %s in jail %s: %w", ip, jail, err)
	}
	code := strings.TrimSpace(string(out))
	if code == Fail2BanStatusSuccess {
		return 0, nil
	}
	if code == Fail2BanStatusAlreadyProcessed {
		return 1, nil
	}
	return 0, fmt.Errorf("unexpected output from fail2ban-client: %s", code)
}

// UnbanIPWithContext unbans an IP address from the specified jail with context support.
func (c *RealClient) UnbanIPWithContext(ctx context.Context, ip, jail string) (int, error) {
	if err := CachedValidateIP(ip); err != nil {
		return 0, err
	}
	if err := CachedValidateJail(jail); err != nil {
		return 0, err
	}

	currentRunner := GetRunner()

	out, err := currentRunner.CombinedOutputWithSudoContext(ctx, c.Path, "set", jail, "unbanip", ip)
	if err != nil {
		return 0, fmt.Errorf("failed to unban IP %s in jail %s: %w", ip, jail, err)
	}
	code := strings.TrimSpace(string(out))
	if code == Fail2BanStatusSuccess {
		return 0, nil
	}
	if code == Fail2BanStatusAlreadyProcessed {
		return 1, nil
	}
	return 0, fmt.Errorf("unexpected output from fail2ban-client: %s", code)
}

// BannedInWithContext returns a list of jails where the specified IP address is currently banned with context support.
func (c *RealClient) BannedInWithContext(ctx context.Context, ip string) ([]string, error) {
	if err := CachedValidateIP(ip); err != nil {
		return nil, err
	}

	currentRunner := GetRunner()

	out, err := currentRunner.CombinedOutputWithSudoContext(ctx, c.Path, "banned", ip)
	if err != nil {
		return nil, fmt.Errorf("failed to get banned status for IP %s: %w", ip, err)
	}
	return ParseBracketedList(string(out)), nil
}

// GetBanRecordsWithContext retrieves ban records for the specified jails with context support.
func (c *RealClient) GetBanRecordsWithContext(ctx context.Context, jails []string) ([]BanRecord, error) {
	return c.getBanRecordsInternal(ctx, jails)
}

// GetLogLinesWithContext retrieves log lines related to an IP address from the specified jail with context support.
func (c *RealClient) GetLogLinesWithContext(ctx context.Context, jail, ip string) ([]string, error) {
	return c.GetLogLinesWithLimitAndContext(ctx, jail, ip, DefaultLogLinesLimit)
}

// GetLogLinesWithLimitAndContext returns log lines with configurable limits
// and context support for memory management and timeouts.
func (c *RealClient) GetLogLinesWithLimitAndContext(
	ctx context.Context,
	jail, ip string,
	maxLines int,
) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if maxLines == 0 {
		return []string{}, nil
	}

	config := LogReadConfig{
		MaxLines:    maxLines,
		MaxFileSize: DefaultMaxFileSize,
		JailFilter:  jail,
		IPFilter:    ip,
		BaseDir:     c.LogDir,
	}

	return collectLogLines(ctx, c.LogDir, config)
}

// ListFiltersWithContext returns a list of available fail2ban filter files with context support.
func (c *RealClient) ListFiltersWithContext(ctx context.Context) ([]string, error) {
	return wrapWithContext0(c.ListFilters)(ctx)
}

// validateFilterPath validates filter name and returns secure path and log path
func (c *RealClient) validateFilterPath(filter string) (string, string, error) {
	if err := CachedValidateFilter(filter); err != nil {
		return "", "", err
	}
	path := filepath.Join(c.FilterDir, filter+".conf")

	// Additional security check: ensure path doesn't escape filter directory
	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", "", fmt.Errorf("invalid filter path: %w", err)
	}

	cleanFilterDir, err := filepath.Abs(filepath.Clean(c.FilterDir))
	if err != nil {
		return "", "", fmt.Errorf("invalid filter directory: %w", err)
	}

	// Ensure the resolved path is within the filter directory
	if !strings.HasPrefix(cleanPath, cleanFilterDir+string(filepath.Separator)) {
		return "", "", fmt.Errorf("filter path outside allowed directory")
	}

	// #nosec G304 - Path is validated, sanitized, and restricted to filter directory above
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return "", "", fmt.Errorf("filter not found: %w", err)
	}
	content := string(data)

	var logPath string
	var patterns []string
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.ToLower(line), "logpath") {
			parts := strings.SplitN(line, "=", 2)
			logPath = strings.TrimSpace(parts[1])
		}
		if strings.HasPrefix(strings.ToLower(line), "failregex") {
			parts := strings.SplitN(line, "=", 2)
			patterns = append(patterns, strings.TrimSpace(parts[1]))
		}
	}
	if logPath == "" || len(patterns) == 0 {
		return "", "", errors.New("invalid filter file")
	}

	return cleanPath, logPath, nil
}

// TestFilterWithContext tests a fail2ban filter against its configured log files with context support.
func (c *RealClient) TestFilterWithContext(ctx context.Context, filter string) (string, error) {
	cleanPath, logPath, err := c.validateFilterPath(filter)
	if err != nil {
		return "", err
	}

	currentRunner := GetRunner()

	output, err := currentRunner.CombinedOutputWithSudoContext(ctx, Fail2BanRegexCommand, logPath, cleanPath)
	return string(output), err
}

// TestFilter tests a fail2ban filter against its configured log files and returns the test output.
func (c *RealClient) TestFilter(filter string) (string, error) {
	cleanPath, logPath, err := c.validateFilterPath(filter)
	if err != nil {
		return "", err
	}

	currentRunner := GetRunner()

	output, err := currentRunner.CombinedOutputWithSudo(Fail2BanRegexCommand, logPath, cleanPath)
	return string(output), err
}
