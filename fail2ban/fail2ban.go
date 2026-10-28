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
	"syscall"
	"time"

	"github.com/ivuorinen/f2b/constants"
)

// commandWaitDelay bounds how long a canceled command may keep its output
// pipes open before Wait gives up and kills it. A variable only so tests can
// shorten it.
var commandWaitDelay = 5 * time.Second

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
func validateCommandExecution(name string, args []string) error {
	if err := ValidateCommand(name); err != nil {
		return fmt.Errorf(constants.ErrCommandValidationFailed, err)
	}
	if err := ValidateArguments(args); err != nil {
		return fmt.Errorf(constants.ErrArgumentValidationFailed, err)
	}
	return nil
}

// runCombined runs an already-validated command and returns its combined output.
//
// exec.CommandContext's default cancellation SIGKILLs only the direct child.
// When that child is sudo, the command sudo started survives (sudo cannot relay
// SIGKILL) and keeps the output pipe open, so CombinedOutput blocked until the
// orphan exited and no context deadline bounded the call. SIGTERM is relayed by
// sudo to its command, and WaitDelay stops waiting on pipes still held after
// the context ends.
//
// A non-zero exit carries the command's own diagnostic (e.g. fail2ban-client's
// "Sorry but the jail 'x' does not exist") only in the output bytes, which
// callers drop on the error path; the bare *exec.ExitError reads "exit status
// N". The trimmed output is therefore folded into the error, keeping the
// ExitError reachable through errors.As.
func runCombined(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- callers validate via validateCommandExecution
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = commandWaitDelay
	out, err := cmd.CombinedOutput()
	if _, ok := errors.AsType[*exec.ExitError](err); ok {
		if msg := strings.TrimSpace(string(out)); msg != "" {
			err = fmt.Errorf("%w: %s", err, msg)
		}
	}
	return out, err
}

// CombinedOutput executes a command without sudo.
func (r *OSRunner) CombinedOutput(name string, args ...string) ([]byte, error) {
	return r.CombinedOutputWithContext(context.Background(), name, args...)
}

// CombinedOutputWithContext executes a command without sudo with context support.
func (r *OSRunner) CombinedOutputWithContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := validateCommandExecution(name, args); err != nil {
		return nil, err
	}
	return runCombined(ctx, name, args...)
}

// CombinedOutputWithSudo executes a command with sudo if needed.
func (r *OSRunner) CombinedOutputWithSudo(name string, args ...string) ([]byte, error) {
	return r.CombinedOutputWithSudoContext(context.Background(), name, args...)
}

// CombinedOutputWithSudoContext executes a command with sudo if needed, with context support.
func (r *OSRunner) CombinedOutputWithSudoContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := validateCommandExecution(name, args); err != nil {
		return nil, err
	}

	checker := GetSudoChecker()

	// If already root, no need for sudo
	if checker.IsRoot() {
		return runCombined(ctx, name, args...)
	}

	// If command requires sudo and user has privileges, use sudo. The command
	// name and arguments were validated above by validateCommandExecution.
	if RequiresSudo(name, args...) && checker.HasSudoPrivileges() {
		sudoArgs := append([]string{name}, args...)
		return runCombined(ctx, constants.SudoCommand, sudoArgs...)
	}

	// Otherwise run without sudo
	return runCombined(ctx, name, args...)
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

// RunnerCombinedOutputWithSudoContext executes a command with sudo privileges
// and context using the global runner, logging its duration. It is the only
// global-runner entry point: its context-free and non-sudo twins had no
// production caller, and the context-free one let the service command ignore
// Ctrl-C.
func RunnerCombinedOutputWithSudoContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	timer := NewTimedOperation("RunnerCombinedOutputWithSudoContext", name, args...)
	output, err := GetRunner().CombinedOutputWithSudoContext(ctx, name, args...)
	timer.FinishWithContext(ctx, err)
	return output, err
}

func (c *RealClient) fetchJailsWithContext(ctx context.Context) ([]string, error) {
	out, err := c.cmdRunner().CombinedOutputWithSudoContext(ctx, c.Path, constants.CommandArgStatus)
	if err != nil {
		return nil, err
	}
	return ParseJailList(string(out))
}

// lastLine returns the last non-empty line of combined command output. The
// runner captures stdout and stderr together, so a stray stderr line (e.g.
// sudo's "unable to resolve host") precedes fail2ban-client's actual answer;
// parsing the whole buffer turned a successful command into an error.
func lastLine(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
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

	currentRunner := c.cmdRunner()

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

			jailRecords, parseErr := ParseBanRecords(string(out), jail)
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

// GetLogLinesWithLimitContext returns the newest maxLines log lines matching
// jail and ip. It is the single log-read entry point: every other read
// delegates here, so the limit bounds and the jail/IP validation (an invalid
// filter must error, not silently match nothing) cannot be skipped.
func (c *RealClient) GetLogLinesWithLimitContext(ctx context.Context, jail, ip string, maxLines int) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateMaxLines(maxLines); err != nil {
		return nil, err
	}
	if maxLines == 0 {
		return []string{}, nil
	}

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

// ListFiltersWithContext returns the names of the *.conf files in the filter
// directory. It honors cancellation like every other client operation.
func (c *RealClient) ListFiltersWithContext(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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

// StatusAllWithContext returns the status of all fail2ban jails with context support.
func (c *RealClient) StatusAllWithContext(ctx context.Context) (string, error) {
	out, err := c.cmdRunner().CombinedOutputWithSudoContext(ctx, c.Path, constants.CommandArgStatus)
	return string(out), err
}

// StatusJailWithContext returns the status of a specific fail2ban jail with context support.
func (c *RealClient) StatusJailWithContext(ctx context.Context, jail string) (string, error) {
	out, err := c.cmdRunner().CombinedOutputWithSudoContext(ctx, c.Path, constants.CommandArgStatus, jail)
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

	out, err := c.cmdRunner().CombinedOutputWithSudoContext(ctx, c.Path, constants.ActionSet, jail, action, ip)
	if err != nil {
		return 0, fmt.Errorf(errorTemplate, ip, jail, err)
	}
	// fail2ban >= 0.11 (the enforced minimum) prints the NUMBER of addresses
	// affected by set <jail> banip/unbanip: >=1 means the IP was newly
	// banned/unbanned (success), 0 means it was already in the desired state.
	// Only the last line is the answer; earlier lines are stderr noise.
	code := lastLine(out)
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

	out, err := c.cmdRunner().CombinedOutputWithSudoContext(ctx, c.Path, constants.ActionBanned, ip)
	if err != nil {
		return nil, fmt.Errorf("failed to get banned status for IP %s: %w", ip, err)
	}
	// The jail list is the last line; earlier lines are stderr noise that would
	// otherwise be parsed as jail names.
	return ParseBracketedList(lastLine(out)), nil
}

// GetBanRecordsWithContext retrieves ban records for the specified jails with context support.
func (c *RealClient) GetBanRecordsWithContext(ctx context.Context, jails []string) ([]BanRecord, error) {
	return c.getBanRecordsInternal(ctx, jails)
}

// GetLogLinesWithContext returns the newest DefaultLogLinesLimit matching log
// lines. It delegates to GetLogLinesWithLimitContext; its former standalone
// implementation skipped the jail/IP filter validation.
func (c *RealClient) GetLogLinesWithContext(ctx context.Context, jail, ip string) ([]string, error) {
	return c.GetLogLinesWithLimitContext(ctx, jail, ip, constants.DefaultLogLinesLimit)
}

// validateMaxLines rejects negative limits and limits above MaxLogLinesLimit.
func validateMaxLines(maxLines int) error {
	if maxLines < 0 {
		return fmt.Errorf(constants.ErrMaxLinesNegative, maxLines)
	}
	if maxLines > constants.MaxLogLinesLimit {
		return fmt.Errorf(constants.ErrMaxLinesExceedsLimit, constants.MaxLogLinesLimit)
	}
	return nil
}

// resolveFilterPath validates the filter name and returns the absolute path to
// its .conf file, guaranteeing the result stays within the client's filter
// directory (defense against path traversal).
func (c *RealClient) resolveFilterPath(filter string) (string, error) {
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

// validateFilterPath validates the filter name and returns the filter's path
// and the logpath it declares.
func (c *RealClient) validateFilterPath(filter string) (string, string, error) {
	cleanPath, err := c.resolveFilterPath(filter)
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
	if err := ctx.Err(); err != nil {
		return "", err
	}
	cleanPath, logPath, err := c.validateFilterPath(filter)
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

	output, err := c.cmdRunner().CombinedOutputWithSudoContext(
		ctx, constants.Fail2BanRegexCommand, validatedLogPath, cleanPath)
	return string(output), err
}
