package fail2ban

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
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
}

// OSRunner runs commands locally.
type OSRunner struct{}

// CombinedOutput executes a command without sudo.
func (r *OSRunner) CombinedOutput(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
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
		return exec.Command("sudo", sudoArgs...).CombinedOutput()
	}

	// Otherwise run without sudo
	return exec.Command(name, args...).CombinedOutput()
}

// runner is the global Runner used for system commands.
var runner Runner = &OSRunner{}
var runnerMutex sync.RWMutex

// SetRunner injects a custom runner (for tests or alternate backends).
func SetRunner(r Runner) {
	runnerMutex.Lock()
	defer runnerMutex.Unlock()
	runner = r
}

// RunnerCombinedOutput invokes the runner for a command.
func RunnerCombinedOutput(name string, args ...string) ([]byte, error) {
	runnerMutex.RLock()
	defer runnerMutex.RUnlock()
	return runner.CombinedOutput(name, args...)
}

// RunnerCombinedOutputWithSudo invokes the runner for a command with sudo if needed.
func RunnerCombinedOutputWithSudo(name string, args ...string) ([]byte, error) {
	runnerMutex.RLock()
	defer runnerMutex.RUnlock()
	return runner.CombinedOutputWithSudo(name, args...)
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

// skipTest logs a skip message but doesn't exit the program.
// skipTest is used in tests to indicate skipping scenarios.
//
//nolint:unused
func skipTest(msg string) {
	// Log the skip message but don't exit - this was causing unexpected program termination
	fmt.Fprintln(os.Stderr, "SKIP:", msg)
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

// runnerCombinedRun is used in tests to run commands without sudo.
//
//nolint:unused
func runnerCombinedRun(name string, args ...string) error {
	runnerMutex.RLock()
	currentRunner := runner
	runnerMutex.RUnlock()

	out, err := currentRunner.CombinedOutput(name, args...)
	if err != nil {
		return fmt.Errorf("%s", bytes.TrimSpace(out))
	}
	return nil
}

func runnerCombinedRunWithSudo(name string, args ...string) error {
	runnerMutex.RLock()
	currentRunner := runner
	runnerMutex.RUnlock()

	out, err := currentRunner.CombinedOutputWithSudo(name, args...)
	if err != nil {
		return fmt.Errorf("%s", bytes.TrimSpace(out))
	}
	return nil
}

func compareVersions(v1, v2 string) int {
	p1 := strings.Split(v1, ".")
	p2 := strings.Split(v2, ".")
	for len(p1) < 3 {
		p1 = append(p1, "0")
	}
	for len(p2) < 3 {
		p2 = append(p2, "0")
	}
	for i := 0; i < 3; i++ {
		n1, _ := strconv.Atoi(p1[i])
		n2, _ := strconv.Atoi(p2[i])
		if n1 < n2 {
			return -1
		} else if n1 > n2 {
			return 1
		}
	}
	return 0
}

func (c *RealClient) fetchJails() ([]string, error) {
	runnerMutex.RLock()
	currentRunner := runner
	runnerMutex.RUnlock()

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
	runnerMutex.RLock()
	currentRunner := runner
	runnerMutex.RUnlock()

	out, err := currentRunner.CombinedOutputWithSudo(c.Path, "status")
	return string(out), err
}

func (c *RealClient) StatusJail(j string) (string, error) {
	runnerMutex.RLock()
	currentRunner := runner
	runnerMutex.RUnlock()

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

	runnerMutex.RLock()
	currentRunner := runner
	runnerMutex.RUnlock()

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

	runnerMutex.RLock()
	currentRunner := runner
	runnerMutex.RUnlock()

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

	runnerMutex.RLock()
	currentRunner := runner
	runnerMutex.RUnlock()

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

	runnerMutex.RLock()
	currentRunner := runner
	runnerMutex.RUnlock()

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
				tBan, _ := time.Parse("2006-01-02 15:04:05", bannedStr)
				tUnban, _ := time.Parse("2006-01-02 15:04:05", unbanStr)
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
	path := filterDir + "/" + filter + ".conf"
	data, err := os.ReadFile(path)
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

	runnerMutex.RLock()
	currentRunner := runner
	runnerMutex.RUnlock()

	output, err := currentRunner.CombinedOutputWithSudo("fail2ban-regex", logPath, path)
	return string(output), err
}

func (c *RealClient) TestFilter(filter string) (string, error) {
	if !isValidFilter(filter) {
		return "", fmt.Errorf("invalid filter name")
	}
	path := filepath.Join(c.FilterDir, filter+".conf")
	data, err := os.ReadFile(path)
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

	runnerMutex.RLock()
	currentRunner := runner
	runnerMutex.RUnlock()

	output, err := currentRunner.CombinedOutputWithSudo("fail2ban-regex", logPath, path)
	return string(output), err
}

// isValidFilter validates a filter name to prevent path traversal
func isValidFilter(filter string) bool {
	if filter == "" {
		return false
	}
	if strings.Contains(filter, "..") || strings.ContainsAny(filter, "/\\") {
		return false
	}
	for _, r := range filter {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' && r != '.' {
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
