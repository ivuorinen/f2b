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
	"github.com/ivuorinen/f2b/fail2ban/internal/query"
)

// commandWaitDelay bounds how long a canceled command may keep its output
// pipes open before Wait gives up and kills it. A variable only so tests can
// shorten it.
var commandWaitDelay = 5 * time.Second

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
	// name cannot be a literal: ValidateCommand admits an allowlisted bare name
	// or a trusted absolute path, which keeps sudo from resolving it via PATH.
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command, go_subproc_rule-subproc
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

// CombinedOutputWithSudoContext executes a command with sudo if needed, with context support.
func (r *OSRunner) CombinedOutputWithSudoContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := validateCommandExecution(name, args); err != nil {
		return nil, err
	}
	path, err := resolveTrustedCommand(name)
	if err != nil {
		return nil, err
	}

	checker := GetSudoChecker()

	// If already root, no need for sudo
	if checker.IsRoot() {
		return runCombined(ctx, path, args...)
	}

	// If command requires sudo and user has privileges, use sudo. The command
	// name and arguments were validated above by validateCommandExecution.
	if RequiresSudo(name, args...) && checker.HasSudoPrivileges() {
		sudoPath, err := resolveTrustedCommand(constants.SudoCommand)
		if err != nil {
			return nil, err
		}
		sudoArgs := append([]string{path}, args...)
		return runCombined(ctx, sudoPath, sudoArgs...)
	}

	// Otherwise run without sudo
	return runCombined(ctx, path, args...)
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

// getBanRecordsInternal is the internal implementation with context support
func (c *RealClient) getBanRecordsInternal(ctx context.Context, jails []string) ([]BanRecord, error) {
	// Expand to all configured jails when no specific jail is requested: an
	// empty list, or any "all"/"" element in the list. Previously only a
	// single-element ["all"]/[""] expanded, so GetBanRecords(nil) silently
	// returned nothing and ["sshd","all"] queried a literal jail named "all".
	toQuery := jails
	if query.RequestsAllJails(jails) {
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
				// It is not logged here: the caller prints the returned
				// error, and ProcessJailsParallel logs a partial failure.
				return nil, fmt.Errorf("jail %s: %w", jail, err)
			}

			jailRecords, parseErr := ParseBanRecords(string(out), jail)
			if parseErr != nil {
				return nil, fmt.Errorf("jail %s: %w", jail, parseErr)
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
	if err := ValidateMaxLines(maxLines); err != nil {
		return nil, err
	}
	if maxLines == 0 {
		return []string{}, nil
	}

	jail, ip, err := ValidateLogFilters(jail, ip)
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
	if err := ValidateBanTarget(ip); err != nil {
		return 0, err
	}
	if err := ValidateJail(jail); err != nil {
		return 0, err
	}

	args := []string{constants.ActionSet, jail, action, ip}
	if action == constants.ActionUnbanIP && strings.Contains(ip, "/") {
		// fail2ban 0.11 removes a range's own entry and stops there; it unbans
		// the addresses inside a range only when the range itself is not
		// banned. Naming the validated range twice runs both steps in one
		// call: the first removes the range entry (or, without one, the
		// addresses inside it), the second the addresses that remain. A step
		// with nothing left to remove counts 0.
		args = append(args, ip)
	}
	out, err := c.cmdRunner().CombinedOutputWithSudoContext(ctx, c.Path, args...)
	if err != nil {
		return 0, fmt.Errorf(errorTemplate, ip, jail, err)
	}
	// fail2ban >= 0.11 (the enforced minimum) prints the NUMBER of addresses
	// affected by set <jail> banip/unbanip, summed over every target named:
	// >=1 means the IP was newly banned/unbanned (success), 0 means it was
	// already in the desired state.
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

// UnbanIPWithContext unbans an IP address, or a CIDR range together with every
// banned address inside it, from the specified jail with context support.
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

// ValidateMaxLines rejects negative limits and limits above MaxLogLinesLimit.
// Exported so fail2bantest.MockClient applies the same rules.
func ValidateMaxLines(maxLines int) error {
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
// and the log to test it against: logFile when given, otherwise the logpath
// the filter declares.
func (c *RealClient) validateFilterPath(filter, logFile string) (string, string, error) {
	cleanPath, err := c.resolveFilterPath(filter)
	if err != nil {
		return "", "", err
	}

	// #nosec G304 - Path is validated, sanitized, and restricted to filter directory above
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return "", "", fmt.Errorf("filter not found: %w", err)
	}

	logPath, hasFailregex := parseFilterFile(string(data))
	if !hasFailregex {
		return "", "", errors.New("invalid filter file: no failregex patterns found")
	}

	if logFile != "" {
		logPath = logFile
	}

	// Stock fail2ban filters (filter.d/*.conf) define failregex only; logpath
	// lives in the jail config, not the filter. Without one there is nothing
	// meaningful to test against — scanning fail2ban's own log would report
	// "success, 0 matches" for any filter. Fail with guidance instead.
	if logPath == "" {
		return "", "", fmt.Errorf(
			"filter %q defines no logpath; name a log to test it against: f2b test-filter %s <logfile>",
			filter, filter)
	}

	return cleanPath, logPath, nil
}

// parseFilterFile returns the logpath a filter file declares and whether it
// defines any failregex. Lines with no '=' (a bare "logpath" key in a
// hand-edited file) carry no value and are skipped.
func parseFilterFile(content string) (logPath string, hasFailregex bool) {
	for line := range strings.SplitSeq(content, "\n") {
		_, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "logpath") {
			logPath = strings.TrimSpace(value)
		}
		if strings.HasPrefix(lower, "failregex") {
			hasFailregex = true
		}
	}
	return logPath, hasFailregex
}

// TestFilterWithContext runs fail2ban-regex for filter against logFile, or
// against the logpath the filter declares when logFile is empty.
func (c *RealClient) TestFilterWithContext(ctx context.Context, filter, logFile string) (output string, err error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	cleanPath, logPath, err := c.validateFilterPath(filter, logFile)
	if err != nil {
		return "", err
	}

	// fail2ban-regex runs under sudo (RequiresSudo) and prints the lines it
	// reads, so the log, whether the caller named it or the filter declared
	// it, must pass the log allowlist — otherwise `sudo fail2ban-regex <log>
	// <filter>` is a read-as-root primitive (e.g. /etc/shadow).
	logConfig := CreateLogPathConfig()
	validatedLogPath, err := ValidatePathWithSecurity(logPath, logConfig)
	if err != nil {
		return "", fmt.Errorf("filter %q has an invalid logpath %q: %w", filter, logPath, err)
	}

	// When f2b itself runs as root (`sudo f2b`, the privilege boundary), the
	// validated path is not handed on: a user who can write a directory on it
	// could swap the file for a symlink before fail2ban-regex opens it. f2b
	// opens the log through the allowlisted directory that holds it, where no
	// component can lead outside, refuses anything but a regular file of at
	// most DefaultMaxFileSize bytes, and gives fail2ban-regex a copy in a
	// private directory that is removed afterwards. An ordinary user whose
	// commands escalate one at a time can already run `sudo fail2ban-regex
	// <file>` directly, so there is no boundary to protect, and the path is
	// passed as is: f2b reading the log with that user's privileges would
	// refuse logs only root can read.
	regexLog := validatedLogPath
	if GetSudoChecker().IsRoot() {
		var removeCopy func() error
		regexLog, removeCopy, err = copyLogForRegex(
			validatedLogPath,
			logConfig.AllowedBasePaths,
			constants.DefaultMaxFileSize,
		)
		if err != nil {
			return "", fmt.Errorf("filter %q: cannot read log %q: %w", filter, validatedLogPath, err)
		}
		defer func() {
			if rmErr := removeCopy(); rmErr != nil {
				err = errors.Join(err, fmt.Errorf("could not remove the log copy %q: %w", regexLog, rmErr))
			}
		}()
	} else if fileErr := requireLogFile(validatedLogPath); fileErr != nil {
		return "", fmt.Errorf("filter %q: %w", filter, fileErr)
	}

	getLogger().WithFields(Fields{"filter": filter, "logpath": validatedLogPath}).Info("Running fail2ban-regex")
	out, err := c.cmdRunner().CombinedOutputWithSudoContext(ctx, constants.Fail2BanRegexCommand, regexLog, cleanPath)
	return string(out), err
}

// requireLogFile refuses a log that is missing or not a regular file on the
// ordinary-user path, where the log path reaches fail2ban-regex as is:
// fail2ban-regex reads any path that is not a file as one literal log line and
// reports success without testing a file. It reads metadata only, so a log
// only root may read still passes; a log in a directory the user cannot
// search passes unchecked, since only fail2ban-regex under sudo can see it.
func requireLogFile(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrPermission) {
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("log %s does not exist", path)
	}
	if err != nil {
		return fmt.Errorf("log %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("log %s is not a regular file", path)
	}
	return nil
}
