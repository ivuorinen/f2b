package fail2ban

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ivuorinen/f2b/constants"
)

// parseTimestamp extracts and parses timestamp from log line
func parseTimestamp(line string) (time.Time, error) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return time.Time{}, errors.New("insufficient fields for timestamp")
	}

	dateStr := parts[0]
	timeStr := strings.TrimSuffix(parts[1], ",")
	timeStr = strings.Replace(timeStr, ",", ".", 1)
	fullTime := dateStr + " " + timeStr
	return time.Parse("2006-01-02 15:04:05.000", fullTime)
}

// extractJailFromLine finds the jail name in a log line, skipping process IDs
func extractJailFromLine(line string) string {
	var jail string
	lastStart := -1
	for i := 0; i < len(line); i++ {
		if line[i] == '[' {
			lastStart = i
		} else if line[i] == ']' && lastStart >= 0 {
			possibleJail := line[lastStart+1 : i]
			// Skip numeric process IDs - jail names are alphabetic
			if len(possibleJail) > 0 && !isNumeric(possibleJail) {
				jail = possibleJail
			}
		}
	}
	return jail
}

// extractIPFromAction extracts IP from ban/unban/found action lines
func extractIPFromAction(line, action string) string {
	ipParts := strings.Split(line, action+" ")
	if len(ipParts) > 1 {
		if action == "Found" {
			fields := strings.Fields(ipParts[1])
			if len(fields) > 0 {
				return fields[0]
			}
			return ""
		}
		return strings.TrimSpace(ipParts[1])
	}
	return ""
}

func TestParseLogLineWithRealData(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		wantJail  string
		wantIP    string
		wantEvent string
		wantTime  time.Time
		wantErr   bool
	}{
		{
			name: "filter found event",
			line: "2025-07-20 00:02:41,241 fail2ban.filter         [212791]: INFO    " +
				"[sshd] Found 192.168.1.100 - 2025-07-20 00:02:40",
			wantJail:  "sshd",
			wantIP:    "192.168.1.100",
			wantEvent: "found",
			wantTime:  time.Date(2025, 7, 20, 0, 2, 41, 241000000, time.UTC),
			wantErr:   false,
		},
		{
			name:      "ban action",
			line:      "2025-07-20 02:37:27,231 fail2ban.actions        [212791]: NOTICE  [sshd] Ban 10.0.0.50",
			wantJail:  "sshd",
			wantIP:    "10.0.0.50",
			wantEvent: "ban",
			wantTime:  time.Date(2025, 7, 20, 2, 37, 27, 231000000, time.UTC),
			wantErr:   false,
		},
		{
			name:      "unban action",
			line:      "2025-07-20 02:47:26,575 fail2ban.actions        [212791]: NOTICE  [sshd] Unban 10.0.0.50",
			wantJail:  "sshd",
			wantIP:    "10.0.0.50",
			wantEvent: "unban",
			wantTime:  time.Date(2025, 7, 20, 2, 47, 26, 575000000, time.UTC),
			wantErr:   false,
		},
		{
			name: "rollover event",
			line: "2025-07-20 00:00:15,998 fail2ban.server         [212791]: INFO    " +
				"rollover performed on /var/log/fail2ban.log",
			wantJail:  "",
			wantIP:    "",
			wantEvent: "rollover",
			wantTime:  time.Date(2025, 7, 20, 0, 0, 15, 998000000, time.UTC),
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLogLineParsing(t, tt.line, tt.wantJail, tt.wantIP, tt.wantEvent, tt.wantTime, tt.wantErr)

			// Exercise the PRODUCTION filter path (passesFilters / containsIPToken),
			// not just the test-local extractors above — this is what GetLogLines
			// actually uses to decide whether a line matches a jail/IP query.
			if tt.wantJail != "" {
				if !passesFilters(tt.line, LogReadConfig{JailFilter: tt.wantJail}) {
					t.Errorf("passesFilters(jail=%q) = false, want true for line %q", tt.wantJail, tt.line)
				}
				if passesFilters(tt.line, LogReadConfig{JailFilter: "no-such-jail"}) {
					t.Errorf("passesFilters(jail=no-such-jail) = true, want false for line %q", tt.line)
				}
			}
			if tt.wantIP != "" {
				if !containsIPToken(tt.line, tt.wantIP) {
					t.Errorf("containsIPToken(%q) = false, want true for line %q", tt.wantIP, tt.line)
				}
				if containsIPToken(tt.line, "203.0.113.255") {
					t.Errorf("containsIPToken(absent IP) = true, want false for line %q", tt.line)
				}
			}
		})
	}
}

// testLogLineParsing is a helper function to test log line parsing logic
func testLogLineParsing(t *testing.T, line, wantJail, wantIP, wantEvent string, wantTime time.Time, wantErr bool) {
	t.Helper()

	// Parse the log line
	parts := strings.Fields(line)
	if len(parts) < 5 {
		if !wantErr {
			t.Errorf("Expected successful parse, but line has insufficient fields")
		}
		return
	}

	// Extract and verify timestamp
	if err := verifyLogTimestamp(t, line, wantTime, wantErr); err != nil {
		return
	}

	// Extract event type and details
	verifyLogEvent(t, line, wantJail, wantIP, wantEvent)
}

// verifyLogTimestamp extracts and verifies the timestamp from a log line
func verifyLogTimestamp(t *testing.T, line string, wantTime time.Time, wantErr bool) error {
	t.Helper()
	parsedTime, err := parseTimestamp(line)
	if err != nil && !wantErr {
		t.Errorf("Failed to parse time: %v", err)
		return err
	}

	if !wantErr && !parsedTime.Equal(wantTime) {
		t.Errorf("Time mismatch: got %v, want %v", parsedTime, wantTime)
	}
	return nil
}

// verifyLogEvent extracts and verifies the event details from a log line
func verifyLogEvent(t *testing.T, line, wantJail, wantIP, wantEvent string) {
	t.Helper()
	if strings.Contains(line, "rollover") {
		if wantEvent != "rollover" {
			t.Errorf("Expected rollover event")
		}
		return
	}

	if !strings.Contains(line, "[") || !strings.Contains(line, "]") {
		return
	}

	// Extract and verify jail
	jail := extractJailFromLine(line)
	if jail != wantJail {
		t.Errorf("Jail mismatch: got %s, want %s", jail, wantJail)
	}

	// Extract and verify IP based on action type
	ip := extractIPFromLogLine(line)
	if ip != wantIP {
		t.Errorf("IP mismatch: got %s, want %s", ip, wantIP)
	}
}

// extractIPFromLogLine extracts IP address from log line based on action type
func extractIPFromLogLine(line string) string {
	if strings.Contains(line, "Found") {
		return extractIPFromAction(line, "Found")
	}
	if strings.Contains(line, "Ban ") {
		return extractIPFromAction(line, "Ban")
	}
	if strings.Contains(line, "Unban ") {
		return extractIPFromAction(line, "Unban")
	}
	return ""
}

func TestGetLogLinesWithRealTestData(t *testing.T) {
	// Use the sample test data file
	testLogFile := filepath.Join("testdata", "fail2ban_sample.log")

	// Validate test data file exists
	testLogFile = validateTestDataFile(t, testLogFile)

	tests := []struct {
		name        string
		jail        string
		ip          string
		wantMinimum int // Minimum expected lines
		checkLine   string
	}{
		{
			name:        "filter by jail sshd",
			jail:        "sshd",
			ip:          "",
			wantMinimum: 50, // Most lines are sshd
			checkLine:   "[sshd]",
		},
		{
			name:        "filter by IP 192.168.1.100",
			jail:        "",
			ip:          "192.168.1.100",
			wantMinimum: 5,
			checkLine:   "192.168.1.100",
		},
		{
			name:        "filter by both jail and IP",
			jail:        "sshd",
			ip:          "10.0.0.50",
			wantMinimum: 1,
			checkLine:   "10.0.0.50",
		},
		{
			name:        "all logs",
			jail:        "",
			ip:          "",
			wantMinimum: 90, // Sample has 100 lines
			checkLine:   "",
		},
	}

	// Set up test environment with test data
	cleanup := setupTestLogEnvironment(t, testLogFile)
	defer cleanup()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines, err := GetLogLines(context.Background(), tt.jail, tt.ip)
			if err != nil {
				t.Fatalf("GetLogLines failed: %v", err)
			}

			assertMinimumLines(t, lines, tt.wantMinimum, "lines")

			// Check that lines contain expected content
			if tt.checkLine != "" {
				assertContainsText(t, lines, tt.checkLine)
			}

			// Verify filtering works correctly
			for _, line := range lines {
				if tt.jail != "" && !strings.Contains(line, "["+tt.jail+"]") && !strings.Contains(line, "rollover") {
					t.Errorf("Line doesn't match jail filter: %s", line)
				}
				if tt.ip != "" && !strings.Contains(line, tt.ip) {
					t.Errorf("Line doesn't match IP filter: %s", line)
				}
			}
		})
	}
}

func TestParseBanRecordsFromRealLogs(t *testing.T) {
	// Test with real ban/unban patterns from production
	parser, err := NewBanRecordParser()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		output    string
		jail      string
		wantCount int
		checkIP   string
	}{
		{
			name: "multiple ban records",
			output: `192.168.1.100 2025-07-20 02:37:27 + 2025-07-20 02:47:27 remaining
10.0.0.50 2025-07-20 02:54:28 + 2025-07-20 03:04:28 remaining
172.16.0.100 2025-07-20 03:21:21 + 2025-07-20 03:31:21 remaining`,
			jail:      "sshd",
			wantCount: 3,
			checkIP:   "10.0.0.50",
		},
		{
			name: "ban record with expired time",
			output: `192.168.1.100 2025-07-19 02:37:27 + 2025-07-19 02:47:27 remaining
10.0.0.50 2025-07-20 02:54:28 + 2025-07-20 03:04:28 remaining`,
			jail:      "sshd",
			wantCount: 2,
			checkIP:   "192.168.1.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records, err := parser.ParseBanRecords(tt.output, tt.jail)
			if err != nil {
				t.Fatalf("ParseBanRecords failed: %v", err)
			}

			if len(records) != tt.wantCount {
				t.Errorf("Expected %d records, got %d", tt.wantCount, len(records))
			}

			// Check for specific IP
			found := false
			for _, record := range records {
				if record.IP == tt.checkIP {
					found = true
					if record.Jail != tt.jail {
						t.Errorf("Record jail mismatch: got %s, want %s", record.Jail, tt.jail)
					}
				}
			}
			if !found {
				t.Errorf("Expected to find IP %s in records", tt.checkIP)
			}
		})
	}
}

func TestLogFileRotationPatterns(t *testing.T) {
	// Test detection of rotated log files
	tempDir := t.TempDir()

	// Create test log files with rotation patterns
	testFiles := []string{
		"fail2ban.log",
		"fail2ban.log.1",
		"fail2ban.log.2.gz",
		"fail2ban.log.3.gz",
		"fail2ban.log.20250720",
		"fail2ban.log.old",
	}

	for _, file := range testFiles {
		path := filepath.Join(tempDir, file)
		if strings.HasSuffix(file, constants.GzipExtension) {
			// Create compressed file
			content := []byte("test log content")
			createTestGzipFile(t, path, content)
		} else {
			// Create regular file
			if err := os.WriteFile(path, []byte("test log content"), 0600); err != nil {
				t.Fatalf("Failed to create file: %v", err)
			}
		}
	}

	files, err := filepath.Glob(filepath.Join(tempDir, "fail2ban*"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}

	// Drive the PRODUCTION rotation parser, not a filepath.Glob stand-in.
	currentLog, rotated := parseLogFiles(files)

	// The active log must be identified as the current log.
	if filepath.Base(currentLog) != constants.LogFileName {
		t.Errorf("currentLog = %q, want base %q", currentLog, constants.LogFileName)
	}

	// Rotated logs are ordered oldest-first (num descending). Numbered rotations
	// .1/.2.gz/.3.gz carry nums 1/2/3; the dateext .20250720 negates to a large
	// negative key (newest); "fail2ban.log.old" matches no scheme and is dropped.
	wantRotatedOrder := []string{
		"fail2ban.log.3.gz",
		"fail2ban.log.2.gz",
		"fail2ban.log.1",
		"fail2ban.log.20250720",
	}
	if len(rotated) != len(wantRotatedOrder) {
		t.Fatalf("rotated count = %d (%v), want %d", len(rotated), rotated, len(wantRotatedOrder))
	}
	for i, want := range wantRotatedOrder {
		if got := filepath.Base(rotated[i].path); got != want {
			t.Errorf("rotated[%d] = %q, want %q", i, got, want)
		}
	}
}

func TestMalformedLogHandling(t *testing.T) {
	// Test with malformed log file
	testLogFile := filepath.Join("testdata", "fail2ban_malformed.log")

	// Set up test environment with test data
	cleanup := setupTestLogEnvironment(t, testLogFile)
	defer cleanup()

	// Should handle malformed entries gracefully
	lines, err := GetLogLines(context.Background(), "", "")
	if err != nil {
		t.Fatalf("GetLogLines should handle malformed entries: %v", err)
	}

	// Should still return some valid lines
	if len(lines) == 0 {
		t.Error("Expected some valid lines from malformed log")
	}

	// Check that we can parse at least some lines
	validCount := 0
	for _, line := range lines {
		if strings.Contains(line, "fail2ban.") && strings.Contains(line, "[") {
			validCount++
		}
	}

	if validCount == 0 {
		t.Error("No valid lines parsed from malformed log")
	}
}

func TestMultiJailLogParsing(t *testing.T) {
	// Test with multi-jail log file
	testLogFile := filepath.Join("testdata", "fail2ban_multi_jail.log")

	// Set up test environment with test data
	cleanup := setupTestLogEnvironment(t, testLogFile)
	defer cleanup()

	// Test filtering by different jails
	jails := []string{"sshd", "nginx", "postfix", "dovecot"}

	for _, jail := range jails {
		t.Run("jail_"+jail, func(t *testing.T) {
			lines, err := GetLogLines(context.Background(), jail, "")
			if err != nil {
				t.Fatalf("GetLogLines failed for jail %s: %v", jail, err)
			}

			// Should find at least some lines for each jail
			if len(lines) == 0 {
				t.Errorf("No lines found for jail %s", jail)
			}

			// Verify all lines match the jail
			for _, line := range lines {
				if !strings.Contains(line, "["+jail+"]") && !strings.Contains(line, "rollover") {
					t.Errorf("Line doesn't match jail %s: %s", jail, line)
				}
			}
		})
	}
}

// isNumeric checks if a string contains only digits
func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// TestParseLogFilesOrdering verifies rotated logs are ordered oldest-first for
// both logrotate schemes: numbered (higher N = older) and dateext (higher
// date = newer). A newest-first order would make appendAndTrim keep the
// oldest rotated lines and drop the newest when MaxLines trims.
func TestParseLogFilesOrdering(t *testing.T) {
	t.Run("numbered scheme", func(t *testing.T) {
		current, rotated := parseLogFiles([]string{
			"/var/log/fail2ban.log.1",
			"/var/log/fail2ban.log",
			"/var/log/fail2ban.log.3.gz",
			"/var/log/fail2ban.log.2.gz",
		})
		if current != "/var/log/fail2ban.log" {
			t.Fatalf("current = %q", current)
		}
		want := []string{
			"/var/log/fail2ban.log.3.gz",
			"/var/log/fail2ban.log.2.gz",
			"/var/log/fail2ban.log.1",
		}
		if len(rotated) != len(want) {
			t.Fatalf("rotated = %d files, want %d", len(rotated), len(want))
		}
		for i, r := range rotated {
			if r.path != want[i] {
				t.Errorf("rotated[%d] = %q, want %q", i, r.path, want[i])
			}
		}
	})

	t.Run("dateext scheme oldest first", func(t *testing.T) {
		current, rotated := parseLogFiles([]string{
			"/var/log/fail2ban.log-20240301",
			"/var/log/fail2ban.log",
			"/var/log/fail2ban.log-20240101.gz",
			"/var/log/fail2ban.log-20240201",
		})
		if current != "/var/log/fail2ban.log" {
			t.Fatalf("current = %q", current)
		}
		want := []string{
			"/var/log/fail2ban.log-20240101.gz",
			"/var/log/fail2ban.log-20240201",
			"/var/log/fail2ban.log-20240301",
		}
		if len(rotated) != len(want) {
			t.Fatalf("rotated = %d files, want %d", len(rotated), len(want))
		}
		for i, r := range rotated {
			if r.path != want[i] {
				t.Errorf("rotated[%d] = %q, want %q", i, r.path, want[i])
			}
		}
	})
}

// TestContainsIPToken covers whole-token matching including IPv4-mapped IPv6
// and IP:port forms, which a strict "no adjacent ':'" boundary would miss.
func TestContainsIPToken(t *testing.T) {
	tests := []struct {
		name string
		line string
		ip   string
		want bool
	}{
		{"exact token", "Ban 192.168.1.100", "192.168.1.100", true},
		{"longer address suffix", "Ban 192.168.1.100", "192.168.1.10", false},
		{"longer address prefix", "Ban 1192.168.1.100", "192.168.1.100", false},
		{"ipv4-mapped ipv6", "Ban ::ffff:192.168.1.100", "192.168.1.100", true},
		{"ipv4 with port", "connection from 192.168.1.100:2222", "192.168.1.100", true},
		{"ipv4-mapped longer address", "Ban ::ffff:192.168.1.100", "92.168.1.100", false},
		{"ipv6 token", "Ban 2001:db8::1", "2001:db8::1", true},
		{"ipv6 inside longer address", "Ban 2001:db8::12", "2001:db8::1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsIPToken(tt.line, tt.ip); got != tt.want {
				t.Errorf("containsIPToken(%q, %q) = %v, want %v", tt.line, tt.ip, got, tt.want)
			}
		})
	}
}
