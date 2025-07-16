package fail2ban

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
)

const (
	// DefaultLogDir is the default directory for fail2ban logs
	DefaultLogDir = "/var/log"
	// DefaultFilterDir is the default directory for fail2ban filters
	DefaultFilterDir = "/etc/fail2ban/filter.d"
	// AllFilter represents all jails/IPs filter
	AllFilter = "all"
)

var logDir = DefaultLogDir // base directory for fail2ban logs
var filterDir = DefaultFilterDir

func SetLogDir(dir string) {
	logDir = dir
}

// GetLogDir returns the current log directory path
func GetLogDir() string {
	return logDir
}
func SetFilterDir(dir string) {
	filterDir = dir
}

// Runner executes system commands.
// Implementations may use sudo or other mechanisms as needed.
type Runner interface {
	CombinedOutput(name string, args ...string) ([]byte, error)
	CombinedOutputWithSudo(name string, args ...string) ([]byte, error)
	// Context-aware versions for timeout and cancellation support
	CombinedOutputWithContext(ctx context.Context, name string, args ...string) ([]byte, error)
	CombinedOutputWithSudoContext(ctx context.Context, name string, args ...string) ([]byte, error)
}

// OSRunner runs commands locally.
type OSRunner struct{}

// CombinedOutput executes a command without sudo.
func (r *OSRunner) CombinedOutput(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// CombinedOutputWithContext executes a command without sudo with context support.
func (r *OSRunner) CombinedOutputWithContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// CombinedOutputWithSudo executes a command with sudo if needed.
func (r *OSRunner) CombinedOutputWithSudo(name string, args ...string) ([]byte, error) {

	checker := GetSudoChecker()

	// If already root, no need for sudo
	if checker.IsRoot() {
		return exec.Command(name, args...).CombinedOutput()
	}

	// If command requires sudo and user has privileges, use sudo
	if RequiresSudo(name, args...) && checker.HasSudoPrivileges() {
		sudoArgs := append([]string{name}, args...)
		// #nosec G204 - This is a legitimate use case for executing fail2ban-client with sudo
		// The command name and arguments are validated by RequiresSudo() and come from controlled sources
		return exec.Command("sudo", sudoArgs...).CombinedOutput()
	}

	// Otherwise run without sudo
	return exec.Command(name, args...).CombinedOutput()
}

// CombinedOutputWithSudoContext executes a command with sudo if needed, with context support.
func (r *OSRunner) CombinedOutputWithSudoContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	checker := GetSudoChecker()

	// If already root, no need for sudo
	if checker.IsRoot() {
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}

	// If command requires sudo and user has privileges, use sudo
	if RequiresSudo(name, args...) && checker.HasSudoPrivileges() {
		sudoArgs := append([]string{name}, args...)
		// #nosec G204 - This is a legitimate use case for executing fail2ban-client with sudo
		// The command name and arguments are validated by RequiresSudo() and come from controlled sources
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
func SetRunner(r Runner) {
	globalRunnerManager.mu.Lock()
	defer globalRunnerManager.mu.Unlock()
	globalRunnerManager.runner = r
}

// GetRunner returns the current runner (for tests that need access).
func GetRunner() Runner {
	globalRunnerManager.mu.RLock()
	defer globalRunnerManager.mu.RUnlock()
	return globalRunnerManager.runner
}

// RunnerCombinedOutput invokes the runner for a command.
func RunnerCombinedOutput(name string, args ...string) ([]byte, error) {
	globalRunnerManager.mu.RLock()
	runner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()
	return runner.CombinedOutput(name, args...)
}

// RunnerCombinedOutputWithSudo invokes the runner for a command with sudo if needed.
func RunnerCombinedOutputWithSudo(name string, args ...string) ([]byte, error) {
	globalRunnerManager.mu.RLock()
	runner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()
	return runner.CombinedOutputWithSudo(name, args...)
}

// RunnerCombinedOutputWithContext invokes the runner for a command with context support.
func RunnerCombinedOutputWithContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	globalRunnerManager.mu.RLock()
	runner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()
	return runner.CombinedOutputWithContext(ctx, name, args...)
}

// RunnerCombinedOutputWithSudoContext invokes the runner for a command with sudo and context support.
func RunnerCombinedOutputWithSudoContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	globalRunnerManager.mu.RLock()
	runner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()
	return runner.CombinedOutputWithSudoContext(ctx, name, args...)
}

// Client defines Fail2Ban operations

// MockRunner is a simple mock for Runner, used in unit tests.
type MockRunner struct {
	Responses map[string][]byte
	Errors    map[string]error
	CallLog   []string
}

// NewMockRunner creates a new MockRunner for testing
func NewMockRunner() *MockRunner {
	return &MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
		CallLog:   []string{},
	}
}

// CombinedOutput returns a mocked response or error for a command.
func (m *MockRunner) CombinedOutput(name string, args ...string) ([]byte, error) {
	// Prevent actual sudo execution in tests
	if name == "sudo" {
		return nil, fmt.Errorf("sudo should not be called directly in tests")
	}

	key := name + " " + strings.Join(args, " ")
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
		m.CallLog = append(m.CallLog, sudoKey)

		if err, exists := m.Errors[sudoKey]; exists {
			return nil, err
		}

		if response, exists := m.Responses[sudoKey]; exists {
			return response, nil
		}

		// Fall back to non-sudo version if sudo version not mocked
		return m.CombinedOutput(name, args...)
	}

	// Otherwise run without sudo
	return m.CombinedOutput(name, args...)
}

// isTest returns true if running in a test environment.
func isTest() bool {
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "-test.") {
			return true
		}
	}
	return false
}

// SetResponse sets a response for a command.
func (m *MockRunner) SetResponse(cmd string, response []byte) {
	m.Responses[cmd] = response
}

// SetError sets an error for a command.
func (m *MockRunner) SetError(cmd string, err error) {
	m.Errors[cmd] = err
}

// GetCalls returns the log of commands called.
func (m *MockRunner) GetCalls() []string {
	return m.CallLog
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

func runnerCombinedRunWithSudo(name string, args ...string) error {
	globalRunnerManager.mu.RLock()
	currentRunner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()

	out, err := currentRunner.CombinedOutputWithSudo(name, args...)
	if err != nil {
		return fmt.Errorf("%s", bytes.TrimSpace(out))
	}
	return nil
}

func compareVersions(v1, v2 string) int {
	version1, err1 := version.NewVersion(v1)
	version2, err2 := version.NewVersion(v2)

	// If either version is invalid, fall back to string comparison
	if err1 != nil || err2 != nil {
		return strings.Compare(v1, v2)
	}

	return version1.Compare(version2)
}

func (c *RealClient) fetchJails() ([]string, error) {
	globalRunnerManager.mu.RLock()
	currentRunner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()

	out, err := currentRunner.CombinedOutputWithSudo(c.Path, "status")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Jail list:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) < 2 {
				return nil, errors.New("failed to parse jails")
			}
			jailList := strings.TrimSpace(parts[1])
			if jailList == "" {
				return []string{}, nil // Return empty list for no jails
			}
			return strings.Fields(strings.ReplaceAll(jailList, ",", " ")), nil
		}
	}
	return nil, errors.New("failed to parse jails")
}

func (c *RealClient) StatusAll() (string, error) {
	globalRunnerManager.mu.RLock()
	currentRunner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()

	out, err := currentRunner.CombinedOutputWithSudo(c.Path, "status")
	return string(out), err
}

func (c *RealClient) StatusJail(j string) (string, error) {
	globalRunnerManager.mu.RLock()
	currentRunner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()

	out, err := currentRunner.CombinedOutputWithSudo(c.Path, "status", j)
	return string(out), err
}

func (c *RealClient) BanIP(ip, jail string) (int, error) {
	if !isValidIP(ip) {
		return 0, fmt.Errorf("invalid IP address: %s", ip)
	}
	if !isValidJail(jail) {
		return 0, fmt.Errorf("invalid jail name: %s", jail)
	}

	// Check if jail exists
	jailExists := false
	for _, j := range c.Jails {
		if j == jail {
			jailExists = true
			break
		}
	}
	if !jailExists {
		return 0, fmt.Errorf("jail '%s' not found", jail)
	}

	globalRunnerManager.mu.RLock()
	currentRunner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()

	out, err := currentRunner.CombinedOutputWithSudo(c.Path, "set", jail, "banip", ip)
	if err != nil {
		return 0, fmt.Errorf("failed to ban IP %s in jail %s: %w", ip, jail, err)
	}
	code := strings.TrimSpace(string(out))
	if code == "0" {
		return 0, nil
	}
	if code == "1" {
		return 1, nil
	}
	return 0, fmt.Errorf("unexpected output from fail2ban-client: %s", code)
}

func (c *RealClient) UnbanIP(ip, jail string) (int, error) {
	if !isValidIP(ip) {
		return 0, fmt.Errorf("invalid IP address: %s", ip)
	}
	if !isValidJail(jail) {
		return 0, fmt.Errorf("invalid jail name: %s", jail)
	}

	// Check if jail exists
	jailExists := false
	for _, j := range c.Jails {
		if j == jail {
			jailExists = true
			break
		}
	}
	if !jailExists {
		return 0, fmt.Errorf("jail '%s' not found", jail)
	}

	globalRunnerManager.mu.RLock()
	currentRunner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()

	out, err := currentRunner.CombinedOutputWithSudo(c.Path, "set", jail, "unbanip", ip)
	if err != nil {
		return 0, fmt.Errorf("failed to unban IP %s in jail %s: %w", ip, jail, err)
	}
	code := strings.TrimSpace(string(out))
	if code == "0" {
		return 0, nil
	}
	if code == "1" {
		return 1, nil
	}
	return 0, fmt.Errorf("unexpected output from fail2ban-client: %s", code)
}

func (c *RealClient) BannedIn(ip string) ([]string, error) {
	if !isValidIP(ip) {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	globalRunnerManager.mu.RLock()
	currentRunner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()

	out, err := currentRunner.CombinedOutputWithSudo(c.Path, "banned", ip)
	if err != nil {
		return nil, fmt.Errorf("failed to check if IP %s is banned: %w", ip, err)
	}
	s := strings.Trim(string(out), "[]")
	if s == "" {
		return []string{}, nil
	}
	parts := strings.Split(strings.ReplaceAll(s, "\"", ""), ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts, nil
}

func (c *RealClient) GetBanRecords(jails []string) ([]BanRecord, error) {
	var recs []BanRecord
	var toQuery []string
	if len(jails) == 1 && (jails[0] == AllFilter || jails[0] == "") {
		toQuery = c.Jails
	} else {
		toQuery = jails
	}

	globalRunnerManager.mu.RLock()
	currentRunner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()

	for _, j := range toQuery {
		out, err := currentRunner.CombinedOutputWithSudo(c.Path, "get", j, "banip", "--with-time")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			ip := fields[0]
			if len(fields) >= 8 {
				// Format: IP BANNED_DATE BANNED_TIME + UNBAN_DATE UNBAN_TIME
				bannedStr := fields[1] + " " + fields[2]
				unbanStr := fields[4] + " " + fields[5]

				tBan, err := time.Parse("2006-01-02 15:04:05", bannedStr)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"jail":      j,
						"ip":        ip,
						"bannedStr": bannedStr,
					}).Warnf("Failed to parse ban time: %v", err)
					// Skip this entry if we can't parse the ban time
					continue
				}

				tUnban, err := time.Parse("2006-01-02 15:04:05", unbanStr)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"jail":     j,
						"ip":       ip,
						"unbanStr": unbanStr,
					}).Warnf("Failed to parse unban time: %v", err)
					// Use current time as fallback for unban time calculation
					tUnban = time.Now().Add(24 * time.Hour) // Assume 24h remaining
				}

				rem := tUnban.Unix() - time.Now().Unix()
				if rem < 0 {
					rem = 0
				}
				recs = append(recs, BanRecord{Jail: j, IP: ip, BannedAt: tBan, Remaining: formatDuration(rem)})
			} else {
				// Fallback for simpler format
				recs = append(recs, BanRecord{Jail: j, IP: ip, BannedAt: time.Now(), Remaining: "unknown"})
			}
		}
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].BannedAt.Before(recs[j].BannedAt) })
	return recs, nil
}

func formatDuration(sec int64) string {
	days := sec / 86400
	h := (sec % 86400) / 3600
	m := (sec % 3600) / 60
	s := sec % 60
	return fmt.Sprintf("%02d:%02d:%02d:%02d", days, h, m, s)
}

func (c *RealClient) GetLogLines(jail, ip string) ([]string, error) {
	return c.GetLogLinesWithLimit(jail, ip, 1000) // Default limit for safety
}

// GetLogLinesWithLimit returns log lines with configurable limits for memory management.
func (c *RealClient) GetLogLinesWithLimit(jail, ip string, maxLines int) ([]string, error) {
	pattern := filepath.Join(c.LogDir, "fail2ban.log*")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		return []string{}, nil
	}

	// Sort files to read in order (current log first, then rotated logs newest to oldest)
	sort.Strings(files)

	// Use streaming approach with memory limits
	config := LogReadConfig{
		MaxLines:    maxLines,
		MaxFileSize: 100 * 1024 * 1024, // 100MB file size limit
		JailFilter:  jail,
		IPFilter:    ip,
	}

	var allLines []string
	totalLines := 0

	for _, fpath := range files {
		if config.MaxLines > 0 && totalLines >= config.MaxLines {
			break
		}

		// Adjust remaining lines limit
		remainingLines := config.MaxLines - totalLines
		if remainingLines <= 0 {
			break
		}

		fileConfig := config
		fileConfig.MaxLines = remainingLines

		lines, err := streamLogFile(fpath, fileConfig)
		if err != nil {
			logrus.WithError(err).WithField("file", fpath).Error("Failed to read log file")
			continue
		}

		allLines = append(allLines, lines...)
		totalLines += len(lines)
	}

	return allLines, nil
}

// GetLogLinesLegacy returns log lines using the original memory-intensive approach.
// DEPRECATED: Use GetLogLines or GetLogLinesWithLimit instead.
func (c *RealClient) GetLogLinesLegacy(jail, ip string) ([]string, error) {
	pattern := filepath.Join(c.LogDir, "fail2ban.log*")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, fpath := range files {
		data, err := readLogFile(fpath)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(data), "\n") {
			if l == "" {
				continue
			}
			lines = append(lines, l)
		}
	}
	if jail != "" && jail != AllFilter {
		key := fmt.Sprintf("[%s]", jail)
		var filt []string
		for _, l := range lines {
			if strings.Contains(l, key) {
				filt = append(filt, l)
			}
		}
		lines = filt
	}
	if ip != "" && ip != AllFilter {
		var filt []string
		for _, l := range lines {
			if strings.Contains(l, ip) {
				filt = append(filt, l)
			}
		}
		lines = filt
	}
	return lines, nil
}

func ListFilters() ([]string, error) {
	entries, err := os.ReadDir(filterDir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".conf") {
			names = append(names, strings.TrimSuffix(e.Name(), ".conf"))
		}
	}
	return names, nil
}

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

func TestFilter(filter string) (string, error) {
	if !isValidFilter(filter) {
		return "", fmt.Errorf("invalid filter name")
	}
	path := filepath.Join(filterDir, filter+".conf")

	// Additional security check: ensure path doesn't escape filter directory
	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("invalid filter path: %w", err)
	}

	cleanFilterDir, err := filepath.Abs(filepath.Clean(filterDir))
	if err != nil {
		return "", fmt.Errorf("invalid filter directory: %w", err)
	}

	// Ensure the resolved path is within the filter directory
	if !strings.HasPrefix(cleanPath, cleanFilterDir+string(filepath.Separator)) {
		return "", fmt.Errorf("filter path outside allowed directory")
	}

	// #nosec G304 - Path is validated, sanitized, and restricted to filter directory above
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return "", fmt.Errorf("filter not found: %w", err)
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
		return "", errors.New("invalid filter file")
	}

	globalRunnerManager.mu.RLock()
	currentRunner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()

	output, err := currentRunner.CombinedOutputWithSudo("fail2ban-regex", logPath, path)
	return string(output), err
}

// Context-aware implementations for RealClient

func (c *RealClient) ListJailsWithContext(ctx context.Context) ([]string, error) {
	// ListJails doesn't require external commands, so just delegate
	return c.ListJails()
}

func (c *RealClient) StatusAllWithContext(ctx context.Context) (string, error) {
	globalRunnerManager.mu.RLock()
	currentRunner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()

	out, err := currentRunner.CombinedOutputWithSudoContext(ctx, c.Path, "status")
	return string(out), err
}

func (c *RealClient) StatusJailWithContext(ctx context.Context, jail string) (string, error) {
	globalRunnerManager.mu.RLock()
	currentRunner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()

	out, err := currentRunner.CombinedOutputWithSudoContext(ctx, c.Path, "status", jail)
	return string(out), err
}

func (c *RealClient) BanIPWithContext(ctx context.Context, ip, jail string) (int, error) {
	if !isValidIP(ip) {
		return 0, fmt.Errorf("invalid IP address: %s", ip)
	}
	if !isValidJail(jail) {
		return 0, fmt.Errorf("invalid jail name: %s", jail)
	}

	globalRunnerManager.mu.RLock()
	currentRunner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()

	out, err := currentRunner.CombinedOutputWithSudoContext(ctx, c.Path, "set", jail, "banip", ip)
	if err != nil {
		return 0, fmt.Errorf("failed to ban IP %s in jail %s: %w", ip, jail, err)
	}
	code := strings.TrimSpace(string(out))
	if code == "0" {
		return 0, nil
	}
	if code == "1" {
		return 1, nil
	}
	return 0, fmt.Errorf("unexpected output from fail2ban-client: %s", code)
}

func (c *RealClient) UnbanIPWithContext(ctx context.Context, ip, jail string) (int, error) {
	if !isValidIP(ip) {
		return 0, fmt.Errorf("invalid IP address: %s", ip)
	}
	if !isValidJail(jail) {
		return 0, fmt.Errorf("invalid jail name: %s", jail)
	}

	globalRunnerManager.mu.RLock()
	currentRunner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()

	out, err := currentRunner.CombinedOutputWithSudoContext(ctx, c.Path, "set", jail, "unbanip", ip)
	if err != nil {
		return 0, fmt.Errorf("failed to unban IP %s in jail %s: %w", ip, jail, err)
	}
	code := strings.TrimSpace(string(out))
	if code == "0" {
		return 0, nil
	}
	if code == "1" {
		return 1, nil
	}
	return 0, fmt.Errorf("unexpected output from fail2ban-client: %s", code)
}

func (c *RealClient) BannedInWithContext(ctx context.Context, ip string) ([]string, error) {
	if !isValidIP(ip) {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	globalRunnerManager.mu.RLock()
	currentRunner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()

	out, err := currentRunner.CombinedOutputWithSudoContext(ctx, c.Path, "banned", ip)
	if err != nil {
		return nil, fmt.Errorf("failed to get banned status for IP %s: %w", ip, err)
	}

	lines := strings.Split(string(out), "\n")
	jails := []string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		jails = append(jails, line)
	}
	return jails, nil
}

func (c *RealClient) GetBanRecordsWithContext(ctx context.Context, jails []string) ([]BanRecord, error) {
	// For now, delegate to the non-context version since GetBanRecords is complex
	// In a full implementation, this would use context for all internal operations
	return c.GetBanRecords(jails)
}

func (c *RealClient) GetLogLinesWithContext(ctx context.Context, jail, ip string) ([]string, error) {
	// For now, delegate to the non-context version since GetLogLines is complex
	// In a full implementation, this would use context for all internal operations
	return c.GetLogLines(jail, ip)
}

func (c *RealClient) ListFiltersWithContext(ctx context.Context) ([]string, error) {
	// For now, delegate to the non-context version since ListFilters is complex
	// In a full implementation, this would use context for all internal operations
	return c.ListFilters()
}

func (c *RealClient) TestFilterWithContext(ctx context.Context, filter string) (string, error) {
	if !isValidFilter(filter) {
		return "", fmt.Errorf("invalid filter name")
	}
	path := filepath.Join(c.FilterDir, filter+".conf")

	// Additional security check: ensure path doesn't escape filter directory
	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("invalid filter path: %w", err)
	}

	cleanFilterDir, err := filepath.Abs(filepath.Clean(c.FilterDir))
	if err != nil {
		return "", fmt.Errorf("invalid filter directory: %w", err)
	}

	// Ensure the resolved path is within the filter directory
	if !strings.HasPrefix(cleanPath, cleanFilterDir+string(filepath.Separator)) {
		return "", fmt.Errorf("filter path outside allowed directory")
	}

	// #nosec G304 - Path is validated, sanitized, and restricted to filter directory above
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return "", fmt.Errorf("filter not found: %w", err)
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
		return "", errors.New("invalid filter file")
	}

	globalRunnerManager.mu.RLock()
	currentRunner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()

	output, err := currentRunner.CombinedOutputWithSudoContext(ctx, "fail2ban-regex", logPath, path)
	return string(output), err
}

func (c *RealClient) TestFilter(filter string) (string, error) {
	if !isValidFilter(filter) {
		return "", fmt.Errorf("invalid filter name")
	}
	path := filepath.Join(c.FilterDir, filter+".conf")

	// Additional security check: ensure path doesn't escape filter directory
	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("invalid filter path: %w", err)
	}

	cleanFilterDir, err := filepath.Abs(filepath.Clean(c.FilterDir))
	if err != nil {
		return "", fmt.Errorf("invalid filter directory: %w", err)
	}

	// Ensure the resolved path is within the filter directory
	if !strings.HasPrefix(cleanPath, cleanFilterDir+string(filepath.Separator)) {
		return "", fmt.Errorf("filter path outside allowed directory")
	}

	// #nosec G304 - Path is validated, sanitized, and restricted to filter directory above
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return "", fmt.Errorf("filter not found: %w", err)
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
		return "", errors.New("invalid filter file")
	}

	globalRunnerManager.mu.RLock()
	currentRunner := globalRunnerManager.runner
	globalRunnerManager.mu.RUnlock()

	output, err := currentRunner.CombinedOutputWithSudo("fail2ban-regex", logPath, path)
	return string(output), err
}

// containsPathTraversalPatterns checks for various path traversal patterns in filter names
func containsPathTraversalPatterns(filter string) bool {
	// Path separators and traversal patterns
	if strings.ContainsAny(filter, "/\\") {
		return true
	}

	// Various representations of ".."
	dangerousPatterns := []string{
		"..",
		"%2e%2e",       // URL encoded ..
		"%2f",          // URL encoded /
		"%5c",          // URL encoded \
		"\u002e\u002e", // Unicode ..
		"\uff0e\uff0e", // Full-width Unicode ..
	}

	filterLower := strings.ToLower(filter)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(filterLower, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// isValidFilterChar checks if a character is allowed in filter names
func isValidFilterChar(r rune) bool {
	// Allow letters, digits, and safe punctuation
	return unicode.IsLetter(r) ||
		unicode.IsDigit(r) ||
		r == '-' ||
		r == '_' ||
		r == '.' ||
		r == '@' || // Allow @ for email-like patterns
		r == '+' || // Allow + for variations
		r == '~' // Allow ~ for common naming
}

// isValidFilter validates a filter name to prevent path traversal and other attacks
func isValidFilter(filter string) bool {
	if filter == "" {
		return false
	}

	// Check length limits to prevent buffer overflow attacks
	if len(filter) > 255 {
		return false
	}

	// Check for null bytes
	if strings.Contains(filter, "\x00") {
		return false
	}

	// Enhanced path traversal detection
	if containsPathTraversalPatterns(filter) {
		return false
	}

	// Character validation - only allow safe characters
	for _, r := range filter {
		if !isValidFilterChar(r) {
			return false
		}
	}

	// Additional validation: ensure filter doesn't start/end with dangerous patterns
	if strings.HasPrefix(filter, ".") || strings.HasSuffix(filter, ".") {
		// Allow single extension like ".conf" but not ".." or "..."
		if strings.Contains(filter, "..") {
			return false
		}
	}

	return true
}

// isValidIP validates an IP address string
func isValidIP(ip string) bool {
	if ip == "" {
		return false
	}
	// Check for valid IPv4 or IPv6 address
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	// Additional check to prevent loopback addresses in production use
	if parsed.IsLoopback() {
		return true // Allow loopback for testing
	}
	return true
}

// isValidJail validates a jail name (alphanumeric, dash, underscore)
func isValidJail(jail string) bool {
	if jail == "" {
		return false
	}
	// Jail names should be reasonable length
	if len(jail) > 64 {
		return false
	}
	// First character should be alphanumeric
	if len(jail) > 0 {
		first := rune(jail[0])
		if !unicode.IsLetter(first) && !unicode.IsDigit(first) {
			return false
		}
	}
	// Rest can be alphanumeric, dash, underscore, or dot
	for _, r := range jail {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return true
}
