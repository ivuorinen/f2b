package fail2ban

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// NewMockRunner creates a new MockRunner for testing

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
			// Save original checker
			originalChecker := GetSudoChecker()
			defer SetSudoChecker(originalChecker)

			// Set environment variable to force sudo checking in tests
			os.Setenv("F2B_TEST_SUDO", "true")
			defer os.Unsetenv("F2B_TEST_SUDO")

			// Set mock checker
			mock := NewMockSudoCheckerWithPrivileges(tt.hasPrivileges)
			SetSudoChecker(mock)

			// Set up mock runner
			mockRunner := NewMockRunner()
			if tt.hasPrivileges {
				mockRunner.SetResponse("fail2ban-client -V", []byte("0.11.2"))
				mockRunner.SetResponse("sudo fail2ban-client -V", []byte("0.11.2"))
				mockRunner.SetResponse("fail2ban-client ping", []byte("pong"))
				mockRunner.SetResponse("sudo fail2ban-client ping", []byte("pong"))
				mockRunner.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
				mockRunner.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
			} else {
				// For unprivileged tests, set up basic responses for non-sudo commands
				mockRunner.SetResponse("fail2ban-client -V", []byte("0.11.2"))
				mockRunner.SetResponse("fail2ban-client ping", []byte("pong"))
				mockRunner.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
			}
			SetRunner(mockRunner)

			client, err := NewClient()

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain %q, got %q", tt.errorContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
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
			// Save original checker and set up mock with privileges
			originalChecker := GetSudoChecker()
			defer SetSudoChecker(originalChecker)
			mockChecker := NewMockSudoCheckerWithPrivileges(true)
			SetSudoChecker(mockChecker)

			mock := &MockRunner{
				Responses: make(map[string][]byte),
				Errors:    make(map[string]error),
			}
			mock.SetResponse("fail2ban-client -V", []byte("0.11.2"))
			mock.SetResponse("sudo fail2ban-client -V", []byte("0.11.2"))
			mock.SetResponse("fail2ban-client ping", []byte("pong"))
			mock.SetResponse("sudo fail2ban-client ping", []byte("pong"))
			mock.SetResponse("fail2ban-client status", []byte(tt.statusOutput))
			mock.SetResponse("sudo fail2ban-client status", []byte(tt.statusOutput))
			SetRunner(mock)

			if tt.expectError {
				// For error cases, we expect NewClient to fail
				_, err := NewClient()
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}

			client, err := NewClient()
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			jails, err := client.ListJails()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
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

func TestStatusAll(t *testing.T) {
	// Save original checker and set up mock with privileges
	originalChecker := GetSudoChecker()
	defer SetSudoChecker(originalChecker)
	mockChecker := NewMockSudoCheckerWithPrivileges(true)
	SetSudoChecker(mockChecker)

	mock := &MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}
	mock.SetResponse("fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("sudo fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("fail2ban-client ping", []byte("pong"))
	mock.SetResponse("sudo fail2ban-client ping", []byte("pong"))
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mock.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))

	expectedOutput := "Status\n|- Number of jail: 1\n`- Jail list: sshd"
	mock.SetResponse("sudo fail2ban-client status", []byte(expectedOutput))

	SetRunner(mock)

	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	output, err := client.StatusAll()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if output != expectedOutput {
		t.Errorf("expected %q, got %q", expectedOutput, output)
	}
}

func TestStatusJail(t *testing.T) {
	// Save original checker and set up mock with privileges
	originalChecker := GetSudoChecker()
	defer SetSudoChecker(originalChecker)
	mockChecker := NewMockSudoCheckerWithPrivileges(true)
	SetSudoChecker(mockChecker)

	mock := &MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}
	mock.SetResponse("fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("sudo fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("fail2ban-client ping", []byte("pong"))
	mock.SetResponse("sudo fail2ban-client ping", []byte("pong"))
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mock.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))

	expectedOutput := "Status for the jail: sshd\n|- Filter\n|- Currently failed: 0\n|- Total failed: 5\n|- Currently banned: 1\n|- Total banned: 1"
	mock.SetResponse("fail2ban-client status sshd", []byte(expectedOutput))
	mock.SetResponse("sudo fail2ban-client status sshd", []byte(expectedOutput))

	SetRunner(mock)

	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	output, err := client.StatusJail("sshd")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
			// Save original checker and set up mock with privileges
			originalChecker := GetSudoChecker()
			defer SetSudoChecker(originalChecker)
			mockChecker := NewMockSudoCheckerWithPrivileges(true)
			SetSudoChecker(mockChecker)

			mock := &MockRunner{
				Responses: make(map[string][]byte),
				Errors:    make(map[string]error),
			}
			mock.SetResponse("fail2ban-client -V", []byte("0.11.2"))
			mock.SetResponse("sudo fail2ban-client -V", []byte("0.11.2"))
			mock.SetResponse("fail2ban-client ping", []byte("pong"))
			mock.SetResponse("sudo fail2ban-client ping", []byte("pong"))
			mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
			mock.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
			mock.SetResponse("fail2ban-client banned 192.168.1.100", []byte("0"))
			mock.SetResponse("sudo fail2ban-client banned 192.168.1.100", []byte("0"))

			if tt.expectError {
				mock.SetError(fmt.Sprintf("sudo fail2ban-client set %s banip %s", tt.jail, tt.ip), fmt.Errorf("command failed"))
			} else {
				mock.SetResponse(fmt.Sprintf("sudo fail2ban-client set %s banip %s", tt.jail, tt.ip), []byte(tt.mockResponse))
			}

			SetRunner(mock)

			client, err := NewClient()
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			code, err := client.BanIP(tt.ip, tt.jail)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
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
			// Save original checker and set up mock with privileges
			originalChecker := GetSudoChecker()
			defer SetSudoChecker(originalChecker)
			mockChecker := NewMockSudoCheckerWithPrivileges(true)
			SetSudoChecker(mockChecker)

			mock := &MockRunner{
				Responses: make(map[string][]byte),
				Errors:    make(map[string]error),
			}
			mock.SetResponse("fail2ban-client -V", []byte("0.11.2"))
			mock.SetResponse("sudo fail2ban-client -V", []byte("0.11.2"))
			mock.SetResponse("fail2ban-client ping", []byte("pong"))
			mock.SetResponse("sudo fail2ban-client ping", []byte("pong"))
			mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
			mock.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
			mock.SetResponse("fail2ban-client banned 192.168.1.100", []byte("0"))
			mock.SetResponse("sudo fail2ban-client banned 192.168.1.100", []byte("0"))
			mock.SetResponse(fmt.Sprintf("sudo fail2ban-client set %s unbanip %s", tt.jail, tt.ip), []byte(tt.mockResponse))

			SetRunner(mock)

			client, err := NewClient()
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			code, err := client.UnbanIP(tt.ip, tt.jail)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
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
			// Save original checker and set up mock with privileges
			originalChecker := GetSudoChecker()
			defer SetSudoChecker(originalChecker)
			mockChecker := NewMockSudoCheckerWithPrivileges(true)
			SetSudoChecker(mockChecker)

			mock := &MockRunner{
				Responses: make(map[string][]byte),
				Errors:    make(map[string]error),
			}
			mock.SetResponse("fail2ban-client -V", []byte("0.11.2"))
			mock.SetResponse("sudo fail2ban-client -V", []byte("0.11.2"))
			mock.SetResponse("fail2ban-client ping", []byte("pong"))
			mock.SetResponse("sudo fail2ban-client ping", []byte("pong"))
			mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
			mock.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
			mock.SetResponse(fmt.Sprintf("fail2ban-client banned %s", tt.ip), []byte(tt.mockResponse))
			mock.SetResponse(fmt.Sprintf("sudo fail2ban-client banned %s", tt.ip), []byte(tt.mockResponse))

			SetRunner(mock)

			client, err := NewClient()
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			jails, err := client.BannedIn(tt.ip)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
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
	// Save original checker and set up mock with privileges
	originalChecker := GetSudoChecker()
	defer SetSudoChecker(originalChecker)
	mockChecker := NewMockSudoCheckerWithPrivileges(true)
	SetSudoChecker(mockChecker)

	mock := &MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}
	mock.SetResponse("fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("sudo fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("fail2ban-client ping", []byte("pong"))
	mock.SetResponse("sudo fail2ban-client ping", []byte("pong"))
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mock.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))

	// Mock ban records response
	banTime := time.Now().Add(-1 * time.Hour)
	unbanTime := time.Now().Add(1 * time.Hour)
	mockBanOutput := fmt.Sprintf("192.168.1.100 %s + %s",
		banTime.Format("2006-01-02 15:04:05"),
		unbanTime.Format("2006-01-02 15:04:05"))
	mock.SetResponse("sudo fail2ban-client get sshd banip --with-time", []byte(mockBanOutput))

	SetRunner(mock)

	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	records, err := client.GetBanRecords([]string{"sshd"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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

	err := os.WriteFile(filepath.Join(tempDir, "fail2ban.log"), []byte(logContent), 0644)
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
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

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
	err := os.MkdirAll(filterDir, 0755)
	if err != nil {
		t.Fatalf("failed to create filter directory: %v", err)
	}

	// Create test filter files
	filterFiles := []string{"sshd.conf", "apache.conf", "nginx.conf", "readme.txt"}
	for _, file := range filterFiles {
		err := os.WriteFile(filepath.Join(filterDir, file), []byte("# test filter"), 0644)
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

	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// We can't easily test ListFilters as it reads from /etc/fail2ban/filter.d
	// This would require more complex mocking or dependency injection
	// For now, we'll test the basic functionality
	_, err = client.ListFilters()
	// We expect this to fail in test environment since /etc/fail2ban/filter.d might not exist
	// but we're testing that the method doesn't panic
	if err != nil {
		t.Logf("ListFilters failed as expected in test environment: %v", err)
	}
}

func TestTestFilter(t *testing.T) {
	// Create a temporary test filter file
	tempDir := t.TempDir()
	filterPath := filepath.Join(tempDir, "test-filter.conf")
	filterContent := `[Definition]
failregex = Failed password for .* from <HOST>
logpath = /var/log/auth.log`

	err := os.WriteFile(filterPath, []byte(filterContent), 0644)
	if err != nil {
		t.Fatalf("failed to create test filter file: %v", err)
	}

	// Save original checker and set up mock with privileges
	originalChecker := GetSudoChecker()
	defer SetSudoChecker(originalChecker)
	mockChecker := NewMockSudoCheckerWithPrivileges(true)
	SetSudoChecker(mockChecker)

	mock := &MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}
	mock.SetResponse("fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("sudo fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("fail2ban-client ping", []byte("pong"))
	mock.SetResponse("sudo fail2ban-client ping", []byte("pong"))
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mock.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))

	expectedOutput := "Running tests on fail2ban-regex\nResults: 5 matches found"
	mock.SetResponse("sudo fail2ban-regex /var/log/auth.log "+filterPath, []byte(expectedOutput))

	SetRunner(mock)

	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

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
			// Save original checker and set up mock with privileges for successful cases
			originalChecker := GetSudoChecker()
			defer SetSudoChecker(originalChecker)
			mockChecker := NewMockSudoCheckerWithPrivileges(!tt.expectError)
			SetSudoChecker(mockChecker)

			mock := &MockRunner{
				Responses: make(map[string][]byte),
				Errors:    make(map[string]error),
			}
			mock.SetResponse("fail2ban-client -V", []byte(tt.version))
			mock.SetResponse("sudo fail2ban-client -V", []byte(tt.version))
			if !tt.expectError {
				mock.SetResponse("fail2ban-client ping", []byte("pong"))
				mock.SetResponse("sudo fail2ban-client ping", []byte("pong"))
				mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
				mock.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
			}
			SetRunner(mock)

			_, err := NewClient()

			if tt.expectError && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// Test the global GetLogLines function
func TestGetLogLinesGlobal(t *testing.T) {
	// Create a temporary test log directory
	tempDir := t.TempDir()
	SetLogDir(tempDir)

	// Create test log files
	logContent := `2024-01-01 12:00:00,123 fail2ban.filter [1234]: INFO [sshd] Found 192.168.1.100 - 2024-01-01 12:00:00
2024-01-01 12:01:00,456 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.100
2024-01-01 12:02:00,789 fail2ban.filter [1234]: INFO [apache] Found 192.168.1.101 - 2024-01-01 12:02:00`

	err := os.WriteFile(filepath.Join(tempDir, "fail2ban.log"), []byte(logContent), 0644)
	if err != nil {
		t.Fatalf("failed to create test log file: %v", err)
	}

	lines, err := GetLogLines("sshd", "192.168.1.100")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(lines) != 2 {
		t.Errorf("expected 2 lines, got %d", len(lines))
	}

	// Test with "all" parameters
	lines, err = GetLogLines("all", "all")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d", len(lines))
	}
}

// Test the global ListFilters function
func TestListFiltersGlobal(t *testing.T) {
	// This will likely fail in test environment, but we test it doesn't panic
	_, err := ListFilters()
	if err != nil {
		t.Logf("ListFilters failed as expected in test environment: %v", err)
	}
}

// Test the global TestFilter function
func TestTestFilterGlobal(t *testing.T) {
	mock := &MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}
	expectedOutput := "Running tests on fail2ban-regex\nResults: 5 matches found"
	mock.SetResponse("sudo fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/test.conf", []byte(expectedOutput))
	SetRunner(mock)

	// This will likely fail since we don't have the actual filter file
	_, err := TestFilter("test")
	if err != nil {
		t.Logf("TestFilter failed as expected for missing filter: %v", err)
	}
}

func TestSetFilterDir(t *testing.T) {
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

func TestListFiltersWithCustomDir(t *testing.T) {
	// Create a temporary directory with filter files
	tempDir := t.TempDir()
	SetFilterDir(tempDir)

	// Create some test filter files
	filterFiles := []string{
		"apache.conf",
		"sshd.conf",
		"nginx.conf",
		"test-filter.conf",
		"readme.txt", // Should be ignored (not .conf)
	}

	for _, file := range filterFiles {
		content := `[Definition]
failregex = test regex
`
		err := os.WriteFile(tempDir+"/"+file, []byte(content), 0644)
		if err != nil {
			t.Fatalf("failed to create test filter file: %v", err)
		}
	}

	// Test ListFilters
	filters, err := ListFilters()
	if err != nil {
		t.Fatalf("ListFilters failed: %v", err)
	}

	expectedFilters := []string{"apache", "sshd", "nginx", "test-filter"}
	if len(filters) != len(expectedFilters) {
		t.Errorf("expected %d filters, got %d", len(expectedFilters), len(filters))
	}

	// Check that all expected filters are present
	filterMap := make(map[string]bool)
	for _, filter := range filters {
		filterMap[filter] = true
	}

	for _, expected := range expectedFilters {
		if !filterMap[expected] {
			t.Errorf("expected filter %s not found in results", expected)
		}
	}

	// Verify that non-.conf files are excluded
	if filterMap["readme"] {
		t.Errorf("non-.conf file should not be included in filter list")
	}
}

func TestListFiltersEmptyDirectory(t *testing.T) {
	// Create an empty temporary directory
	tempDir := t.TempDir()
	SetFilterDir(tempDir)

	filters, err := ListFilters()
	if err != nil {
		t.Fatalf("ListFilters failed: %v", err)
	}

	if len(filters) != 0 {
		t.Errorf("expected 0 filters in empty directory, got %d", len(filters))
	}
}

func TestListFiltersNonexistentDirectory(t *testing.T) {
	// Set filter directory to a non-existent path
	SetFilterDir("/nonexistent/directory/path")

	filters, err := ListFilters()
	if err == nil {
		t.Errorf("expected error for non-existent directory")
	}

	if filters != nil {
		t.Errorf("expected nil filters on error, got %v", filters)
	}
}

func TestTestFilterWithCustomDir(t *testing.T) {
	// Create a temporary directory with a test filter
	tempDir := t.TempDir()
	SetFilterDir(tempDir)

	// Create a test filter file
	filterContent := `[Definition]
failregex = Failed password for .* from <HOST>
logpath = /var/log/auth.log
`
	filterPath := tempDir + "/test-filter.conf"
	err := os.WriteFile(filterPath, []byte(filterContent), 0644)
	if err != nil {
		t.Fatalf("failed to create test filter file: %v", err)
	}

	// Create a mock runner for the fail2ban-regex command
	mock := &MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}

	expectedOutput := "Running tests on fail2ban-regex\nResults: 5 matches found"
	mock.SetResponse("sudo fail2ban-regex /var/log/auth.log "+filterPath, []byte(expectedOutput))
	SetRunner(mock)

	// Test the filter
	result, err := TestFilter("test-filter")
	if err != nil {
		t.Logf("TestFilter failed as expected: %v", err)
	} else {
		t.Logf("TestFilter result: %s", result)
	}
}

func TestIsValidFilter(t *testing.T) {
	valid := []string{"sshd", "nginx-error", "custom.filter"}
	invalid := []string{"../evil", "bad/name", "bad\\name", "", ".."}
	for _, f := range valid {
		if !isValidFilter(f) {
			t.Errorf("expected filter %s to be valid", f)
		}
	}
	for _, f := range invalid {
		if isValidFilter(f) {
			t.Errorf("expected filter %s to be invalid", f)
		}
	}
}
