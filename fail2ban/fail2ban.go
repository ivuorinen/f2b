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
	"strconv"
	"strings"
	"sync"

	"github.com/ivuorinen/f2b/constants"
)

var logDir = constants.DefaultLogDir // base directory for fail2ban logs
var logDirMu sync.RWMutex            // protects logDir from concurrent access

// SetLogDir sets the directory path for log files. Log-reading functions read
// this global via GetLogDir, so tests use it to point log reads at a temp dir.
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

// OSRunner runs commands locally.
type OSRunner struct{}

// validateCommandExecution validates command name and arguments before execution.
// This helper consolidates the duplicate validation pattern used in command execution methods.
func validateCommandExecution(ctx context.Context, name string, args []string) error {
	if err := ValidateCommand(name); err != nil {
		return fmt.Errorf(constants.ErrCommandValidationFailed, err)
	}
	if err := ValidateArgumentsWithContext(ctx, args); err != nil {
		return fmt.Errorf(constants.ErrArgumentValidationFailed, err)
	}
	return nil
}

// CombinedOutput executes a command without sudo.
func (r *OSRunner) CombinedOutput(name string, args ...string) ([]byte, error) {
	return r.CombinedOutputWithContext(context.Background(), name, args...)
}

// CombinedOutputWithContext executes a command without sudo with context support.
func (r *OSRunner) CombinedOutputWithContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := validateCommandExecution(ctx, name, args); err != nil {
		return nil, err
	}
	// #nosec G204 -- command validated by validateCommandExecution
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// CombinedOutputWithSudo executes a command with sudo if needed.
func (r *OSRunner) CombinedOutputWithSudo(name string, args ...string) ([]byte, error) {
	return r.CombinedOutputWithSudoContext(context.Background(), name, args...)
}

// CombinedOutputWithSudoContext executes a command with sudo if needed, with context support.
func (r *OSRunner) CombinedOutputWithSudoContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := validateCommandExecution(ctx, name, args); err != nil {
		return nil, err
	}

	checker := GetSudoChecker()

	// If already root, no need for sudo
	if checker.IsRoot() {
		return exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204 -- command validated above
	}

	// If command requires sudo and user has privileges, use sudo
	if RequiresSudo(name, args...) && checker.HasSudoPrivileges() {
		sudoArgs := append([]string{name}, args...)
		// #nosec G204 - This is a legitimate use case for executing fail2ban-client with sudo
		// The command name and arguments are validated by ValidateCommand() and RequiresSudo()
		return exec.CommandContext(ctx, constants.SudoCommand, sudoArgs...).CombinedOutput()
	}

	// Otherwise run without sudo
	return exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204 -- command validated above
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
func SetRunner(r Runner) {
	globalRunnerManager.mu.Lock()
	defer globalRunnerManager.mu.Unlock()
	globalRunnerManager.runner = r
}

// GetRunner returns the current global command runner instance.
func GetRunner() Runner {
	globalRunnerManager.mu.RLock()
	defer globalRunnerManager.mu.RUnlock()
	return globalRunnerManager.runner
}

// RunnerCombinedOutput executes a command using the global runner and returns combined stdout/stderr output.
func RunnerCombinedOutput(name string, args ...string) ([]byte, error) {
	timer := NewTimedOperation("RunnerCombinedOutput", name, args...)

	runner := GetRunner()

	output, err := runner.CombinedOutput(name, args...)
	timer.Finish(err)

	return output, err
}

// RunnerCombinedOutputWithSudo executes a command with sudo privileges using the global runner.
func RunnerCombinedOutputWithSudo(name string, args ...string) ([]byte, error) {
	timer := NewTimedOperation("RunnerCombinedOutputWithSudo", name, args...)

	runner := GetRunner()

	output, err := runner.CombinedOutputWithSudo(name, args...)
	timer.Finish(err)

	return output, err
}

// runWithTimerContext is a helper that consolidates the common pattern of
// creating a timer, getting the runner, executing a command, and finishing the timer.
// This reduces code duplication between RunnerCombinedOutputWithContext and RunnerCombinedOutputWithSudoContext.
func runWithTimerContext(
	ctx context.Context,
	opName, name string,
	args []string,
	runFn func(Runner, context.Context, string, ...string) ([]byte, error),
) ([]byte, error) {
	timer := NewTimedOperation(opName, name, args...)
	runner := GetRunner()
	output, err := runFn(runner, ctx, name, args...)
	timer.FinishWithContext(ctx, err)
	return output, err
}

// RunnerCombinedOutputWithContext executes a command with context using the global runner.
func RunnerCombinedOutputWithContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	return runWithTimerContext(ctx, "RunnerCombinedOutputWithContext", name, args,
		func(r Runner, c context.Context, n string, a ...string) ([]byte, error) {
			return r.CombinedOutputWithContext(c, n, a...)
		})
}

// RunnerCombinedOutputWithSudoContext executes a command with sudo privileges and context using the global runner.
func RunnerCombinedOutputWithSudoContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	return runWithTimerContext(ctx, "RunnerCombinedOutputWithSudoContext", name, args,
		func(r Runner, c context.Context, n string, a ...string) ([]byte, error) {
			return r.CombinedOutputWithSudoContext(c, n, a...)
		})
}

func (c *RealClient) fetchJailsWithContext(ctx context.Context) ([]string, error) {
	currentRunner := GetRunner()
	out, err := currentRunner.CombinedOutputWithSudoContext(ctx, c.Path, constants.CommandArgStatus)
	if err != nil {
		return nil, err
	}
	return ParseJailList(string(out))
}

// StatusAll returns the status of all fail2ban jails.
func (c *RealClient) StatusAll() (string, error) {
	currentRunner := GetRunner()
	out, err := currentRunner.CombinedOutputWithSudo(c.Path, constants.CommandArgStatus)
	return string(out), err
}

// StatusJail returns the status of a specific fail2ban jail.
func (c *RealClient) StatusJail(j string) (string, error) {
	currentRunner := GetRunner()
	out, err := currentRunner.CombinedOutputWithSudo(c.Path, constants.CommandArgStatus, j)
	return string(out), err
}

// BanIP bans an IP address in the specified jail and returns the ban status code.
func (c *RealClient) BanIP(ip, jail string) (int, error) {
	return c.BanIPWithContext(context.Background(), ip, jail)
}

// UnbanIP unbans an IP address from the specified jail and returns the unban status code.
func (c *RealClient) UnbanIP(ip, jail string) (int, error) {
	return c.UnbanIPWithContext(context.Background(), ip, jail)
}

// BannedIn returns a list of jails where the specified IP address is currently banned.
func (c *RealClient) BannedIn(ip string) ([]string, error) {
	return c.BannedInWithContext(context.Background(), ip)
}

// GetBanRecords retrieves ban records for the specified jails.
func (c *RealClient) GetBanRecords(jails []string) ([]BanRecord, error) {
	return c.GetBanRecordsWithContext(context.Background(), jails)
}

// requestsAllJails reports whether the requested jail list should expand to
// every configured jail: an empty list, or a list containing "all" or "".
func requestsAllJails(jails []string) bool {
	if len(jails) == 0 {
		return true
	}
	for _, j := range jails {
		if j == constants.AllFilter || j == "" {
			return true
		}
	}
	return false
}

// getBanRecordsInternal is the internal implementation with context support
func (c *RealClient) getBanRecordsInternal(ctx context.Context, jails []string) ([]BanRecord, error) {
	// Expand to all configured jails when no specific jail is requested: an
	// empty list, or any "all"/"" element in the list. Previously only a
	// single-element ["all"]/[""] expanded, so GetBanRecords(nil) silently
	// returned nothing and ["sshd","all"] queried a literal jail named "all".
	toQuery := jails
	if requestsAllJails(jails) {
		toQuery = c.Jails
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
				constants.ActionGet,
				jail,
				constants.ActionBanIP,
				"--with-time",
			)
			if err != nil {
				// Surface the error: ProcessJailsParallel returns partial
				// records when only some jails fail, and a joined error when
				// all do. Swallowing here made total failure (e.g. broken
				// socket perms) indistinguishable from "no bans anywhere".
				getLogger().WithError(err).WithField(string(constants.ContextKeyJail), jail).
					Warn("Failed to get ban records for jail")
				return nil, fmt.Errorf("jail %s: %w", jail, err)
			}

			// Use ultra-optimized parser for this jail's records
			jailRecords, parseErr := ParseBanRecordsUltraOptimized(string(out), jail)
			if parseErr != nil {
				getLogger().WithError(parseErr).WithField("jail", jail).
					Warn("Failed to parse ban records for jail")
				return nil, fmt.Errorf("jail %s: parse: %w", jail, parseErr)
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
	return c.GetLogLinesWithLimit(jail, ip, constants.DefaultLogLinesLimit)
}

// GetLogLinesWithLimit returns log lines with configurable limits for memory management.
func (c *RealClient) GetLogLinesWithLimit(jail, ip string, maxLines int) ([]string, error) {
	return c.GetLogLinesWithLimitContext(context.Background(), jail, ip, maxLines)
}

// GetLogLinesWithLimitContext returns log lines with configurable limits and context support.
func (c *RealClient) GetLogLinesWithLimitContext(ctx context.Context, jail, ip string, maxLines int) ([]string, error) {
	if err := validateMaxLines(maxLines); err != nil {
		return nil, err
	}
	if maxLines == 0 {
		return []string{}, nil
	}

	// Same filter validation as the package-level entry point: an invalid
	// jail/IP must error, not silently match nothing.
	jail, ip, err := validateLogFilters(jail, ip)
	if err != nil {
		return nil, err
	}

	config := LogReadConfig{
		MaxLines:    maxLines,
		MaxFileSize: constants.DefaultMaxFileSize,
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
		if before, ok := strings.CutSuffix(name, constants.ConfExtension); ok {
			filters = append(filters, before)
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

	out, err := currentRunner.CombinedOutputWithSudoContext(ctx, c.Path, constants.CommandArgStatus)
	return string(out), err
}

// StatusJailWithContext returns the status of a specific fail2ban jail with context support.
func (c *RealClient) StatusJailWithContext(ctx context.Context, jail string) (string, error) {
	currentRunner := GetRunner()

	out, err := currentRunner.CombinedOutputWithSudoContext(ctx, c.Path, constants.CommandArgStatus, jail)
	return string(out), err
}

// executeIPActionWithContext executes a ban/unban IP action with validation and response parsing.
// It returns (0, nil) for success, (1, nil) if already processed, or an error.
func (c *RealClient) executeIPActionWithContext(
	ctx context.Context,
	ip, jail, action, errorTemplate string,
) (int, error) {
	if err := ValidateIP(ip); err != nil {
		return 0, err
	}
	if err := ValidateJail(jail); err != nil {
		return 0, err
	}

	currentRunner := GetRunner()
	out, err := currentRunner.CombinedOutputWithSudoContext(ctx, c.Path, constants.ActionSet, jail, action, ip)
	if err != nil {
		return 0, fmt.Errorf(errorTemplate, ip, jail, err)
	}
	// fail2ban >= 0.11 (the enforced minimum) prints the NUMBER of addresses
	// affected by set <jail> banip/unbanip: >=1 means the IP was newly
	// banned/unbanned (success), 0 means it was already in the desired state.
	code := strings.TrimSpace(string(out))
	count, convErr := strconv.Atoi(code)
	if convErr != nil {
		return 0, fmt.Errorf(constants.ErrUnexpectedOutput, code)
	}
	if count >= 1 {
		return 0, nil // newly processed
	}
	return 1, nil // already processed
}

// BanIPWithContext bans an IP address in the specified jail with context support.
func (c *RealClient) BanIPWithContext(ctx context.Context, ip, jail string) (int, error) {
	return c.executeIPActionWithContext(ctx, ip, jail, constants.ActionBanIP, constants.ErrFailedToBanIP)
}

// UnbanIPWithContext unbans an IP address from the specified jail with context support.
func (c *RealClient) UnbanIPWithContext(ctx context.Context, ip, jail string) (int, error) {
	return c.executeIPActionWithContext(ctx, ip, jail, constants.ActionUnbanIP, constants.ErrFailedToUnbanIP)
}

// BannedInWithContext returns a list of jails where the specified IP address is currently banned with context support.
func (c *RealClient) BannedInWithContext(ctx context.Context, ip string) ([]string, error) {
	if err := ValidateIP(ip); err != nil {
		return nil, err
	}

	currentRunner := GetRunner()

	out, err := currentRunner.CombinedOutputWithSudoContext(ctx, c.Path, constants.ActionBanned, ip)
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
	return c.GetLogLinesWithLimitAndContext(ctx, jail, ip, constants.DefaultLogLinesLimit)
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

	if err := validateMaxLines(maxLines); err != nil {
		return nil, err
	}
	if maxLines == 0 {
		return []string{}, nil
	}

	config := LogReadConfig{
		MaxLines:    maxLines,
		MaxFileSize: constants.DefaultMaxFileSize,
		JailFilter:  jail,
		IPFilter:    ip,
		BaseDir:     c.LogDir,
	}

	return collectLogLines(ctx, c.LogDir, config)
}

// validateMaxLines rejects negative limits and limits above MaxLogLinesLimit,
// so the RealClient log methods cannot bypass the bounds enforced by the
// package-level GetLogLinesWithLimit.
func validateMaxLines(maxLines int) error {
	if maxLines < 0 {
		return fmt.Errorf(constants.ErrMaxLinesNegative, maxLines)
	}
	if maxLines > constants.MaxLogLinesLimit {
		return fmt.Errorf(constants.ErrMaxLinesExceedsLimit, constants.MaxLogLinesLimit)
	}
	return nil
}

// ListFiltersWithContext returns a list of available fail2ban filter files with context support.
func (c *RealClient) ListFiltersWithContext(ctx context.Context) ([]string, error) {
	return wrapWithContext0(c.ListFilters)(ctx)
}

// validateFilterPath validates filter name and returns secure path and log path
// resolveFilterPath validates the filter name and returns the absolute path to
// its .conf file, guaranteeing the result stays within the client's filter
// directory (defense against path traversal).
func (c *RealClient) resolveFilterPath(_ context.Context, filter string) (string, error) {
	if err := ValidateFilter(filter); err != nil {
		return "", err
	}
	path := filepath.Join(c.FilterDir, filter+".conf")

	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("invalid filter path: %w", err)
	}
	cleanFilterDir, err := filepath.Abs(filepath.Clean(c.FilterDir))
	if err != nil {
		return "", fmt.Errorf(constants.ErrInvalidFilterDirectory, err)
	}
	if !strings.HasPrefix(cleanPath, cleanFilterDir+string(filepath.Separator)) {
		return "", fmt.Errorf("filter path outside allowed directory")
	}
	return cleanPath, nil
}

func (c *RealClient) validateFilterPath(ctx context.Context, filter string) (string, string, error) {
	cleanPath, err := c.resolveFilterPath(ctx, filter)
	if err != nil {
		return "", "", err
	}

	// #nosec G304 - Path is validated, sanitized, and restricted to filter directory above
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return "", "", fmt.Errorf("filter not found: %w", err)
	}
	content := string(data)

	var logPath string
	var patterns []string
	for line := range strings.SplitSeq(content, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "logpath") {
			// Guard against lines with no '=' (e.g. a bare "logpath" key in a
			// hand-edited file), which would otherwise panic on parts[1].
			if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
				logPath = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(lower, "failregex") {
			if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
				patterns = append(patterns, strings.TrimSpace(parts[1]))
			}
		}
	}
	if len(patterns) == 0 {
		return "", "", errors.New("invalid filter file: no failregex patterns found")
	}

	// Stock fail2ban filters (filter.d/*.conf) define failregex only; logpath
	// lives in the jail config, not the filter. Without one there is nothing
	// meaningful to test against — scanning fail2ban's own log would report
	// "success, 0 matches" for any filter. Fail with guidance instead.
	if logPath == "" {
		return "", "", fmt.Errorf(
			"filter %q defines no logpath; test it against a specific log with: fail2ban-regex <logfile> %s",
			filter, cleanPath)
	}

	return cleanPath, logPath, nil
}

// TestFilterWithContext tests a fail2ban filter against its configured log files with context support.
func (c *RealClient) TestFilterWithContext(ctx context.Context, filter string) (string, error) {
	cleanPath, logPath, err := c.validateFilterPath(ctx, filter)
	if err != nil {
		return "", err
	}

	// fail2ban-regex runs under sudo (RequiresSudo), so the filter-supplied
	// logpath must pass the log allowlist before it reaches argv — otherwise a
	// user-writable filter file turns `sudo fail2ban-regex <logpath> <filter>`
	// into a read-as-root primitive (e.g. logpath = /etc/shadow).
	validatedLogPath, err := ValidatePathWithSecurity(logPath, CreateLogPathConfig())
	if err != nil {
		return "", fmt.Errorf("filter %q has an invalid logpath %q: %w", filter, logPath, err)
	}

	currentRunner := GetRunner()

	output, err := currentRunner.CombinedOutputWithSudoContext(
		ctx, constants.Fail2BanRegexCommand, validatedLogPath, cleanPath)
	return string(output), err
}

// TestFilter tests a fail2ban filter against its configured log files and returns the test output.
func (c *RealClient) TestFilter(filter string) (string, error) {
	return c.TestFilterWithContext(context.Background(), filter)
}
