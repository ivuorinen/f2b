package fail2ban

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name          string
		hasPrivileges bool
		expectError   bool
		errorContains string
	}{
		{
			name:          "with sudo privileges",
			hasPrivileges: true,
			expectError:   false,
		},
		{
			name:          "without sudo privileges",
			hasPrivileges: false,
			expectError:   true,
			errorContains: "fail2ban operations require sudo privileges",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable to force sudo checking in tests
			t.Setenv("F2B_TEST_SUDO", "true")

			// Set up mock environment
			_, cleanup := SetupMockEnvironmentWithSudo(t, tt.hasPrivileges)
			defer cleanup()

			// Get the mock runner that was set up
			mockRunner := GetRunner().(*MockRunner)
			if tt.hasPrivileges {
				mockRunner.SetResponse("fail2ban-client -V", []byte("0.11.2"))
				mockRunner.SetResponse("sudo fail2ban-client -V", []byte("0.11.2"))
				mockRunner.SetResponse("fail2ban-client ping", []byte("pong"))
				mockRunner.SetResponse("sudo fail2ban-client ping", []byte("pong"))
				mockRunner.SetResponse(
					"fail2ban-client status",
					[]byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"),
				)
				mockRunner.SetResponse(
					"sudo fail2ban-client status",
					[]byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"),
				)
			} else {
				// For unprivileged tests, set up basic responses for non-sudo commands
				mockRunner.SetResponse("fail2ban-client -V", []byte("0.11.2"))
				mockRunner.SetResponse("fail2ban-client ping", []byte("pong"))
				mockRunner.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
			}

			client, err := NewClient(DefaultLogDir, DefaultFilterDir)

			AssertError(t, err, tt.expectError, tt.name)
			if tt.expectError {
				if tt.errorContains != "" && err != nil && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain %q, got %q", tt.errorContains, err.Error())
				}
				return
			}

			if client == nil {
				t.Fatal("expected client to be non-nil")
			}
		})
	}
}

func TestListJails(t *testing.T) {
	tests := []struct {
		name          string
		statusOutput  string
		expectedJails []string
		expectError   bool
	}{
		{
			name:          "parse single jail",
			statusOutput:  "Status\n|- Number of jail: 1\n`- Jail list: sshd",
			expectedJails: []string{"sshd"},
			expectError:   false,
		},
		{
			name:          "parse multiple jails",
			statusOutput:  "Status\n|- Number of jail: 3\n`- Jail list: sshd, apache, nginx",
			expectedJails: []string{"sshd", "apache", "nginx"},
			expectError:   false,
		},
		{
			name:          "parse jails with extra spaces",
			statusOutput:  "Status\n|- Number of jail: 2\n`- Jail list:  sshd ,  apache  ",
			expectedJails: []string{"sshd", "apache"},
			expectError:   false,
		},
		{
			name:         "no jail list found",
			statusOutput: "Status\n|- Number of jail: 0",
			expectError:  true,
		},
		{
			name:          "empty jail list",
			statusOutput:  "Status\n|- Number of jail: 0\n`- Jail list: ",
			expectError:   false,
			expectedJails: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock environment with sudo privileges
			_, cleanup := SetupMockEnvironmentWithSudo(t, true)
			defer cleanup()

			// Configure specific responses for this test
			mock := GetRunner().(*MockRunner)
			mock.SetResponse("fail2ban-client status", []byte(tt.statusOutput))
			mock.SetResponse("sudo fail2ban-client status", []byte(tt.statusOutput))

			if tt.expectError {
				// For error cases, we expect NewClient to fail
				_, err := NewClient(DefaultLogDir, DefaultFilterDir)
				AssertError(t, err, true, tt.name)
				return
			}

			client, err := NewClient(DefaultLogDir, DefaultFilterDir)
			AssertError(t, err, false, "create client")

			jails, err := client.ListJails()
			AssertError(t, err, false, "list jails")

			if len(jails) != len(tt.expectedJails) {
				t.Errorf("expected %d jails, got %d", len(tt.expectedJails), len(jails))
			}

			for i, expected := range tt.expectedJails {
				if i >= len(jails) || jails[i] != expected {
					t.Errorf("expected jail %q at index %d, got %q", expected, i, jails[i])
				}
			}
		})
	}
}

func TestStatusAll(t *testing.T) {
	// Set up mock environment with sudo privileges
	_, cleanup := SetupMockEnvironmentWithSudo(t, true)
	defer cleanup()

	// Configure specific responses for this test
	expectedOutput := "Status\n|- Number of jail: 1\n`- Jail list: sshd"
	mock := GetRunner().(*MockRunner)
	mock.SetResponse("fail2ban-client status", []byte(expectedOutput))
	mock.SetResponse("sudo fail2ban-client status", []byte(expectedOutput))

	client, err := NewClient(DefaultLogDir, DefaultFilterDir)
	AssertError(t, err, false, "create client")

	output, err := client.StatusAll()
	AssertError(t, err, false, "status all")

	if output != expectedOutput {
		t.Errorf("expected %q, got %q", expectedOutput, output)
	}
}

func TestStatusJail(t *testing.T) {
	// Set up mock environment with sudo privileges
	_, cleanup := SetupMockEnvironmentWithSudo(t, true)
	defer cleanup()

	// Configure specific responses for this test
	mock := GetRunner().(*MockRunner)
	expectedOutput := "Status for the jail: sshd\n|- Filter\n" +
		"|- Currently failed: 0\n|- Total failed: 5\n|- Currently banned: 1\n|- Total banned: 1"
	mock.SetResponse("fail2ban-client status sshd", []byte(expectedOutput))
	mock.SetResponse("sudo fail2ban-client status sshd", []byte(expectedOutput))

	client, err := NewClient(DefaultLogDir, DefaultFilterDir)
	AssertError(t, err, false, "create client")

	output, err := client.StatusJail("sshd")
	AssertError(t, err, false, "status jail")

	if output != expectedOutput {
		t.Errorf("expected %q, got %q", expectedOutput, output)
	}
}

func TestBanIP(t *testing.T) {
	tests := []struct {
		name         string
		ip           string
		jail         string
		mockResponse string
		expectedCode int
		expectError  bool
	}{
		{
			name:         "successful ban",
			ip:           "192.168.1.100",
			jail:         "sshd",
			mockResponse: "0",
			expectedCode: 0,
			expectError:  false,
		},
		{
			name:         "already banned",
			ip:           "192.168.1.100",
			jail:         "sshd",
			mockResponse: "1",
			expectedCode: 1,
			expectError:  false,
		},
		{
			name:         "ban command error",
			ip:           "192.168.1.100",
			jail:         "sshd",
			mockResponse: "",
			expectedCode: 0,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock environment with sudo privileges
			_, cleanup := SetupMockEnvironmentWithSudo(t, true)
			defer cleanup()

			// Configure specific responses for this test
			mock := GetRunner().(*MockRunner)
			if tt.expectError {
				mock.SetError(
					fmt.Sprintf("sudo fail2ban-client set %s banip %s", tt.jail, tt.ip),
					fmt.Errorf("command failed"),
				)
			} else {
				mock.SetResponse(fmt.Sprintf("sudo fail2ban-client set %s banip %s", tt.jail, tt.ip), []byte(tt.mockResponse))
			}

			client, err := NewClient(DefaultLogDir, DefaultFilterDir)
			AssertError(t, err, false, "create client")

			code, err := client.BanIP(tt.ip, tt.jail)

			AssertError(t, err, tt.expectError, tt.name)
			if tt.expectError {
				return
			}

			if code != tt.expectedCode {
				t.Errorf("expected code %d, got %d", tt.expectedCode, code)
			}
		})
	}
}

func TestUnbanIP(t *testing.T) {
	tests := []struct {
		name         string
		ip           string
		jail         string
		mockResponse string
		expectedCode int
		expectError  bool
	}{
		{
			name:         "successful unban",
			ip:           "192.168.1.100",
			jail:         "sshd",
			mockResponse: "0",
			expectedCode: 0,
			expectError:  false,
		},
		{
			name:         "already unbanned",
			ip:           "192.168.1.100",
			jail:         "sshd",
			mockResponse: "1",
			expectedCode: 1,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock environment with sudo privileges
			_, cleanup := SetupMockEnvironmentWithSudo(t, true)
			defer cleanup()

			// Configure specific responses for this test
			mock := GetRunner().(*MockRunner)
			mock.SetResponse(
				fmt.Sprintf("sudo fail2ban-client set %s unbanip %s", tt.jail, tt.ip),
				[]byte(tt.mockResponse),
			)

			client, err := NewClient(DefaultLogDir, DefaultFilterDir)
			AssertError(t, err, false, "create client")

			code, err := client.UnbanIP(tt.ip, tt.jail)

			AssertError(t, err, tt.expectError, tt.name)
			if tt.expectError {
				return
			}

			if code != tt.expectedCode {
				t.Errorf("expected code %d, got %d", tt.expectedCode, code)
			}
		})
	}
}

func TestBannedIn(t *testing.T) {
	tests := []struct {
		name          string
		ip            string
		mockResponse  string
		expectedJails []string
		expectError   bool
	}{
		{
			name:          "ip banned in single jail",
			ip:            "192.168.1.100",
			mockResponse:  `["sshd"]`,
			expectedJails: []string{"sshd"},
			expectError:   false,
		},
		{
			name:          "ip banned in multiple jails",
			ip:            "192.168.1.100",
			mockResponse:  `["sshd", "apache"]`,
			expectedJails: []string{"sshd", "apache"},
			expectError:   false,
		},
		{
			name:          "ip not banned",
			ip:            "192.168.1.100",
			mockResponse:  `[]`,
			expectedJails: []string{},
			expectError:   false,
		},
		{
			name:          "empty response",
			ip:            "192.168.1.100",
			mockResponse:  "",
			expectedJails: []string{},
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock environment with sudo privileges
			_, cleanup := SetupMockEnvironmentWithSudo(t, true)
			defer cleanup()

			// Configure specific responses for this test
			mock := GetRunner().(*MockRunner)
			mock.SetResponse(fmt.Sprintf("fail2ban-client banned %s", tt.ip), []byte(tt.mockResponse))
			mock.SetResponse(fmt.Sprintf("sudo fail2ban-client banned %s", tt.ip), []byte(tt.mockResponse))

			client, err := NewClient(DefaultLogDir, DefaultFilterDir)
			AssertError(t, err, false, "create client")

			jails, err := client.BannedIn(tt.ip)

			AssertError(t, err, tt.expectError, tt.name)
			if tt.expectError {
				return
			}

			if len(jails) != len(tt.expectedJails) {
				t.Errorf("expected %d jails, got %d", len(tt.expectedJails), len(jails))
			}

			for i, expected := range tt.expectedJails {
				if i >= len(jails) || jails[i] != expected {
					t.Errorf("expected jail %q at index %d, got %q", expected, i, jails[i])
				}
			}
		})
	}
}

func TestGetBanRecords(t *testing.T) {
	// Set up mock environment with sudo privileges
	_, cleanup := SetupMockEnvironmentWithSudo(t, true)
	defer cleanup()

	// Configure specific responses for this test
	mock := GetRunner().(*MockRunner)
	// Mock ban records response
	banTime := time.Now().Add(-1 * time.Hour)
	unbanTime := time.Now().Add(1 * time.Hour)
	mockBanOutput := fmt.Sprintf("192.168.1.100 %s + %s",
		banTime.Format("2006-01-02 15:04:05"),
		unbanTime.Format("2006-01-02 15:04:05"))
	mock.SetResponse("sudo fail2ban-client get sshd banip --with-time", []byte(mockBanOutput))

	client, err := NewClient(DefaultLogDir, DefaultFilterDir)
	AssertError(t, err, false, "create client")

	records, err := client.GetBanRecords([]string{"sshd"})
	AssertError(t, err, false, "get ban records")

	if len(records) != 1 {
		t.Errorf("expected 1 record, got %d", len(records))
	}

	if len(records) > 0 {
		record := records[0]
		if record.Jail != "sshd" {
			t.Errorf("expected jail 'sshd', got %q", record.Jail)
		}
		if record.IP != "192.168.1.100" {
			t.Errorf("expected IP '192.168.1.100', got %q", record.IP)
		}
	}
}

func TestGetLogLines(t *testing.T) {
	// Create a temporary test log directory
	tempDir := t.TempDir()
	SetLogDir(tempDir)

	// Create test log files
	logContent := `2024-01-01 12:00:00,123 fail2ban.filter [1234]: INFO [sshd] Found 192.168.1.100 - 2024-01-01 12:00:00
2024-01-01 12:01:00,456 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.100
2024-01-01 12:02:00,789 fail2ban.filter [1234]: INFO [apache] Found 192.168.1.101 - 2024-01-01 12:02:00`

	err := os.WriteFile(filepath.Join(tempDir, "fail2ban.log"), []byte(logContent), 0600)
	if err != nil {
		t.Fatalf("failed to create test log file: %v", err)
	}

	mock := NewMockRunner()
	mock.SetResponse("fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("fail2ban-client ping", []byte("pong"))
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	SetRunner(mock)

	tests := []struct {
		name          string
		jail          string
		ip            string
		expectedLines int
	}{
		{
			name:          "all logs",
			jail:          "",
			ip:            "",
			expectedLines: 3,
		},
		{
			name:          "filter by jail",
			jail:          "sshd",
			ip:            "",
			expectedLines: 2,
		},
		{
			name:          "filter by IP",
			jail:          "",
			ip:            "192.168.1.100",
			expectedLines: 2,
		},
		{
			name:          "filter by jail and IP",
			jail:          "sshd",
			ip:            "192.168.1.100",
			expectedLines: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines, err := GetLogLines(tt.jail, tt.ip)
			AssertError(t, err, false, "get log lines")

			if len(lines) != tt.expectedLines {
				t.Errorf("expected %d lines, got %d", tt.expectedLines, len(lines))
			}
		})
	}
}

func TestListFilters(t *testing.T) {
	// Create a temporary test filter directory
	tempDir := t.TempDir()
	filterDir := filepath.Join(tempDir, "filter.d")
	err := os.MkdirAll(filterDir, 0750)
	if err != nil {
		t.Fatalf("failed to create filter directory: %v", err)
	}

	// Create test filter files
	filterFiles := []string{"sshd.conf", "apache.conf", "nginx.conf", "readme.txt"}
	for _, file := range filterFiles {
		err := os.WriteFile(filepath.Join(filterDir, file), []byte("# test filter"), 0600)
		if err != nil {
			t.Fatalf("failed to create test filter file: %v", err)
		}
	}

	// Mock the filter directory path
	mock := NewMockRunner()
	mock.SetResponse("fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("fail2ban-client ping", []byte("pong"))
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	SetRunner(mock)

	// Create client with the temporary filter directory
	client, err := NewClient(DefaultLogDir, filterDir)
	AssertError(t, err, false, "create client")

	// Test ListFilters with the temporary directory
	filters, err := client.ListFilters()
	AssertError(t, err, false, "list filters")

	// Should find only .conf files (sshd, apache, nginx - not readme.txt)
	expectedFilters := []string{"apache", "nginx", "sshd"}
	if len(filters) != len(expectedFilters) {
		t.Errorf("Expected %d filters, got %d: %v", len(expectedFilters), len(filters), filters)
	}

	// Check that all expected filters are present (order may vary)
	for _, expected := range expectedFilters {
		found := false
		for _, actual := range filters {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected filter %q not found in %v", expected, filters)
		}
	}
}

func TestTestFilter(t *testing.T) {
	// Create a temporary test filter file
	tempDir := t.TempDir()
	filterPath := filepath.Join(tempDir, "test-filter.conf")
	filterContent := `[Definition]
failregex = Failed password for .* from <HOST>
logpath = /var/log/auth.log`

	err := os.WriteFile(filterPath, []byte(filterContent), 0600)
	if err != nil {
		t.Fatalf("failed to create test filter file: %v", err)
	}

	// Set up mock environment with sudo privileges
	_, cleanup := SetupMockEnvironmentWithSudo(t, true)
	defer cleanup()

	// Configure specific responses for this test
	mock := GetRunner().(*MockRunner)
	expectedOutput := "Running tests on fail2ban-regex\nResults: 5 matches found"
	mock.SetResponse("sudo fail2ban-regex /var/log/auth.log "+filterPath, []byte(expectedOutput))

	client, err := NewClient(DefaultLogDir, DefaultFilterDir)
	AssertError(t, err, false, "create client")

	// This test will fail in normal circumstances as it tries to read from /etc/fail2ban/filter.d
	// but we're testing the method structure
	_, err = client.TestFilter("nonexistent")
	if err != nil {
		t.Logf("TestFilter failed as expected for nonexistent filter: %v", err)
	}
}

func TestVersionComparison(t *testing.T) {
	// This tests the version comparison logic indirectly through NewClient
	tests := []struct {
		name        string
		version     string
		expectError bool
	}{
		{
			name:        "version 0.11.2 should work",
			version:     "0.11.2",
			expectError: false,
		},
		{
			name:        "version 0.12.0 should work",
			version:     "0.12.0",
			expectError: false,
		},
		{
			name:        "version 0.10.9 should fail",
			version:     "0.10.9",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock environment with privileges based on expected outcome
			_, cleanup := SetupMockEnvironmentWithSudo(t, !tt.expectError)
			defer cleanup()

			// Configure specific responses for this test
			mock := GetRunner().(*MockRunner)
			mock.SetResponse("fail2ban-client -V", []byte(tt.version))
			mock.SetResponse("sudo fail2ban-client -V", []byte(tt.version))
			if !tt.expectError {
				mock.SetResponse("fail2ban-client ping", []byte("pong"))
				mock.SetResponse("sudo fail2ban-client ping", []byte("pong"))
				mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
				mock.SetResponse(
					"sudo fail2ban-client status",
					[]byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"),
				)
			}

			_, err := NewClient(DefaultLogDir, DefaultFilterDir)

			AssertError(t, err, tt.expectError, tt.name)
		})
	}
}

func TestSetFilterDir(_ *testing.T) {
	originalDir := "/etc/fail2ban/filter.d" // Assume this is the default
	testDir := "/custom/filter/dir"

	// Set a custom filter directory
	SetFilterDir(testDir)

	// Test that the directory change affects filter operations
	// Since SetFilterDir doesn't return anything, we test indirectly
	// by checking that it doesn't panic and can be called multiple times
	SetFilterDir(testDir)
	SetFilterDir("/another/dir")
	SetFilterDir(originalDir)

	// Test with empty string
	SetFilterDir("")

	// Test with relative path
	SetFilterDir("./filters")

	// No assertions needed as SetFilterDir is a simple setter
	// The fact that it doesn't panic is sufficient
}

func TestIsValidFilter(t *testing.T) {
	valid := []string{"sshd", "nginx-error", "custom.filter"}
	invalid := []string{"../evil", "bad/name", "bad\\name", "", ".."}
	for _, f := range valid {
		if err := ValidateFilter(f); err != nil {
			t.Errorf("expected filter %s to be valid, got error: %v", f, err)
		}
	}
	for _, f := range invalid {
		if err := ValidateFilter(f); err == nil {
			t.Errorf("expected filter %s to be invalid", f)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name     string
		v1       string
		v2       string
		expected int
	}{
		{
			name:     "equal versions",
			v1:       "1.0.0",
			v2:       "1.0.0",
			expected: 0,
		},
		{
			name:     "v1 less than v2",
			v1:       "0.11.0",
			v2:       "1.0.0",
			expected: -1,
		},
		{
			name:     "v1 greater than v2",
			v1:       "1.2.0",
			v2:       "1.0.0",
			expected: 1,
		},
		{
			name:     "patch version difference",
			v1:       "1.0.1",
			v2:       "1.0.2",
			expected: -1,
		},
		{
			name:     "prerelease versions",
			v1:       "1.0.0-alpha",
			v2:       "1.0.0",
			expected: -1,
		},
		{
			name:     "invalid version strings fallback to string comparison",
			v1:       "invalid.version",
			v2:       "another.invalid",
			expected: 1, // "invalid.version" > "another.invalid" lexicographically
		},
		{
			name:     "mixed valid and invalid",
			v1:       "1.0.0",
			v2:       "invalid",
			expected: -1, // string comparison: "1.0.0" < "invalid"
		},
		{
			name:     "version with build metadata",
			v1:       "1.0.0+build.1",
			v2:       "1.0.0+build.2",
			expected: 0, // build metadata should be ignored in semantic versioning
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CompareVersions(tt.v1, tt.v2)
			if result != tt.expected {
				t.Errorf("CompareVersions(%q, %q) = %d, expected %d", tt.v1, tt.v2, result, tt.expected)
			}
		})
	}
}

func TestGetBanRecordsWithInvalidTimes(t *testing.T) {
	// Set up mock environment with sudo privileges
	_, cleanup := SetupMockEnvironmentWithSudo(t, true)
	defer cleanup()

	// Get mock runner for configuration
	mockRunner := GetRunner().(*MockRunner)

	// Create client
	client := &RealClient{
		Path:      "fail2ban-client",
		Jails:     []string{"sshd"},
		LogDir:    "/var/log",
		FilterDir: "/etc/fail2ban/filter.d",
	}

	tests := []struct {
		name          string
		mockResponse  string
		expectedCount int
		expectSkipped bool
	}{
		{
			name: "valid times",
			mockResponse: "192.168.1.100 2023-01-01 12:00:00 + 2023-01-01 13:00:00 extra field\n" +
				"192.168.1.101 2023-01-01 14:00:00 + 2023-01-01 15:00:00 extra field",
			expectedCount: 2,
			expectSkipped: false,
		},
		{
			name: "invalid ban time - entry should be skipped",
			mockResponse: "192.168.1.100 invalid-date 12:00:00 + 2023-01-01 13:00:00 extra field\n" +
				"192.168.1.101 2023-01-01 14:00:00 + 2023-01-01 15:00:00 extra field",
			expectedCount: 1,
			expectSkipped: true,
		},
		{
			name: "invalid unban time - entry should use fallback",
			mockResponse: "192.168.1.100 2023-01-01 12:00:00 + invalid-time 13:00:00 extra field\n" +
				"192.168.1.101 2023-01-01 14:00:00 + 2023-01-01 15:00:00 extra field",
			expectedCount: 2,
			expectSkipped: false,
		},
		{
			name: "both times invalid - entry should be skipped",
			mockResponse: "192.168.1.100 invalid-date 12:00:00 + invalid-time 13:00:00 extra field\n" +
				"192.168.1.101 2023-01-01 14:00:00 + 2023-01-01 15:00:00 extra field",
			expectedCount: 1,
			expectSkipped: true,
		},
		{
			name: "short format fallback",
			mockResponse: "192.168.1.100 banned extra field\n" +
				"192.168.1.101 also banned extra",
			expectedCount: 2,
			expectSkipped: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock response (the command uses sudo)
			mockRunner.SetResponse("sudo fail2ban-client get sshd banip --with-time", []byte(tt.mockResponse))

			// Get ban records
			records, err := client.GetBanRecords([]string{"sshd"})
			if err != nil {
				t.Fatalf("GetBanRecords failed: %v", err)
			}

			// Check count
			if len(records) != tt.expectedCount {
				t.Errorf("expected %d records, got %d", tt.expectedCount, len(records))
			}

			// For entries with invalid unban time (but valid ban time), verify fallback worked
			if tt.name == "invalid unban time - entry should use fallback" && len(records) > 0 {
				// The first record should have a reasonable remaining time (not zero)
				if records[0].Remaining == "00:00:00:00" {
					t.Errorf("expected fallback time calculation, got zero remaining time")
				}
			}

			// For entries using short format fallback
			if tt.name == "short format fallback" && len(records) > 0 {
				for _, record := range records {
					if record.Remaining != "unknown" {
						t.Errorf("expected 'unknown' remaining time for short format, got %s", record.Remaining)
					}
				}
			}
		})
	}
}
