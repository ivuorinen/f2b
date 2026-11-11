package fail2ban_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

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
			_, cleanup := fail2bantest.SetupMockEnvironmentWithSudo(t, true)
			defer cleanup()

			// Configure specific responses for this test
			mock := fail2bantest.MustMockRunner(t)
			mock.SetResponse("fail2ban-client status", []byte(tt.statusOutput))
			mock.SetResponse("sudo fail2ban-client status", []byte(tt.statusOutput))

			if tt.expectError {
				// For error cases, we expect NewClient to fail
				_, err := fail2ban.NewClient(constants.DefaultLogDir, constants.DefaultFilterDir)
				fail2bantest.AssertError(t, err, true, tt.name)
				return
			}

			client, err := fail2ban.NewClient(constants.DefaultLogDir, constants.DefaultFilterDir)
			fail2bantest.AssertError(t, err, false, "create client")

			jails, err := client.ListJailsWithContext(context.Background())
			fail2bantest.AssertError(t, err, false, "list jails")

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
	_, cleanup := fail2bantest.SetupMockEnvironmentWithSudo(t, true)
	defer cleanup()

	// Configure specific responses for this test
	expectedOutput := "Status\n|- Number of jail: 1\n`- Jail list: sshd"
	mock := fail2bantest.MustMockRunner(t)
	mock.SetResponse("fail2ban-client status", []byte(expectedOutput))
	mock.SetResponse("sudo fail2ban-client status", []byte(expectedOutput))

	client, err := fail2ban.NewClient(constants.DefaultLogDir, constants.DefaultFilterDir)
	fail2bantest.AssertError(t, err, false, "create client")

	output, err := client.StatusAllWithContext(context.Background())
	fail2bantest.AssertError(t, err, false, "status all")

	if output != expectedOutput {
		t.Errorf("expected %q, got %q", expectedOutput, output)
	}
}

func TestStatusJail(t *testing.T) {
	// Set up mock environment with sudo privileges
	_, cleanup := fail2bantest.SetupMockEnvironmentWithSudo(t, true)
	defer cleanup()

	// Configure specific responses for this test
	mock := fail2bantest.MustMockRunner(t)
	expectedOutput := "Status for the jail: sshd\n|- Filter\n" +
		"|- Currently failed: 0\n|- Total failed: 5\n|- Currently banned: 1\n|- Total banned: 1"
	mock.SetResponse("fail2ban-client status sshd", []byte(expectedOutput))
	mock.SetResponse("sudo fail2ban-client status sshd", []byte(expectedOutput))

	client, err := fail2ban.NewClient(constants.DefaultLogDir, constants.DefaultFilterDir)
	fail2bantest.AssertError(t, err, false, "create client")

	output, err := client.StatusJailWithContext(context.Background(), "sshd")
	fail2bantest.AssertError(t, err, false, "status jail")

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
			mockResponse: "1", // fail2ban prints the count banned: 1 = newly banned
			expectedCode: 0,
			expectError:  false,
		},
		{
			name:         "already banned",
			ip:           "192.168.1.100",
			jail:         "sshd",
			mockResponse: "0", // 0 = the IP was already banned
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
			_, cleanup := fail2bantest.SetupMockEnvironmentWithSudo(t, true)
			defer cleanup()

			// Configure specific responses for this test
			mock := fail2bantest.MustMockRunner(t)
			if tt.expectError {
				mock.SetError(
					fmt.Sprintf("sudo fail2ban-client set %s banip %s", tt.jail, tt.ip),
					fmt.Errorf("command failed"),
				)
			} else {
				mock.SetResponse(
					fmt.Sprintf("sudo fail2ban-client set %s banip %s", tt.jail, tt.ip),
					[]byte(tt.mockResponse),
				)
			}

			client, err := fail2ban.NewClient(constants.DefaultLogDir, constants.DefaultFilterDir)
			fail2bantest.AssertError(t, err, false, "create client")

			code, err := client.BanIPWithContext(context.Background(), tt.ip, tt.jail)

			fail2bantest.AssertError(t, err, tt.expectError, tt.name)
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
			mockResponse: "1", // fail2ban prints the count unbanned: 1 = newly unbanned
			expectedCode: 0,
			expectError:  false,
		},
		{
			name:         "already unbanned",
			ip:           "192.168.1.100",
			jail:         "sshd",
			mockResponse: "0", // 0 = the IP was already unbanned
			expectedCode: 1,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock environment with sudo privileges
			_, cleanup := fail2bantest.SetupMockEnvironmentWithSudo(t, true)
			defer cleanup()

			// Configure specific responses for this test
			mock := fail2bantest.MustMockRunner(t)
			mock.SetResponse(
				fmt.Sprintf("sudo fail2ban-client set %s unbanip %s", tt.jail, tt.ip),
				[]byte(tt.mockResponse),
			)

			client, err := fail2ban.NewClient(constants.DefaultLogDir, constants.DefaultFilterDir)
			fail2bantest.AssertError(t, err, false, "create client")

			code, err := client.UnbanIPWithContext(context.Background(), tt.ip, tt.jail)

			fail2bantest.AssertError(t, err, tt.expectError, tt.name)
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
			_, cleanup := fail2bantest.SetupMockEnvironmentWithSudo(t, true)
			defer cleanup()

			// Configure specific responses for this test
			mock := fail2bantest.MustMockRunner(t)
			mock.SetResponse(fmt.Sprintf("fail2ban-client banned %s", tt.ip), []byte(tt.mockResponse))
			mock.SetResponse(fmt.Sprintf("sudo fail2ban-client banned %s", tt.ip), []byte(tt.mockResponse))

			client, err := fail2ban.NewClient(constants.DefaultLogDir, constants.DefaultFilterDir)
			fail2bantest.AssertError(t, err, false, "create client")

			jails, err := client.BannedInWithContext(context.Background(), tt.ip)

			fail2bantest.AssertError(t, err, tt.expectError, tt.name)
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
	_, cleanup := fail2bantest.SetupMockEnvironmentWithSudo(t, true)
	defer cleanup()

	// Configure specific responses for this test
	mock := fail2bantest.MustMockRunner(t)
	// Mock ban records response
	banTime := time.Now().Add(-1 * time.Hour)
	unbanTime := time.Now().Add(1 * time.Hour)
	mockBanOutput := fmt.Sprintf("192.168.1.100 %s + %s",
		banTime.Format("2006-01-02 15:04:05"),
		unbanTime.Format("2006-01-02 15:04:05"))
	mock.SetResponse("sudo fail2ban-client get sshd banip --with-time", []byte(mockBanOutput))

	client, err := fail2ban.NewClient(constants.DefaultLogDir, constants.DefaultFilterDir)
	fail2bantest.AssertError(t, err, false, "create client")

	records, err := client.GetBanRecordsWithContext(context.Background(), []string{"sshd"})
	fail2bantest.AssertError(t, err, false, "get ban records")

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

func TestGetBanRecordsWithInvalidTimes(t *testing.T) {
	// Set up mock environment with sudo privileges
	_, cleanup := fail2bantest.SetupMockEnvironmentWithSudo(t, true)
	defer cleanup()

	// Get mock runner for configuration
	mockRunner := fail2bantest.MustMockRunner(t)

	// Create client
	client := &fail2ban.RealClient{
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
			assertInvalidTimeRecords(t, client, mockRunner, tt.name, tt.mockResponse, tt.expectedCount)
		})
	}
}

// assertInvalidTimeRecords runs a single GetBanRecords case for
// TestGetBanRecordsWithInvalidTimes and verifies count and fallback handling.
func assertInvalidTimeRecords(
	t *testing.T,
	client *fail2ban.RealClient,
	mockRunner *fail2bantest.MockRunner,
	name, mockResponse string,
	expectedCount int,
) {
	t.Helper()

	// Set up mock response (the command uses sudo)
	mockRunner.SetResponse("sudo fail2ban-client get sshd banip --with-time", []byte(mockResponse))

	// Get ban records
	records, err := client.GetBanRecordsWithContext(context.Background(), []string{"sshd"})
	if err != nil {
		t.Fatalf("GetBanRecords failed: %v", err)
	}

	// Check count
	if len(records) != expectedCount {
		t.Errorf("expected %d records, got %d", expectedCount, len(records))
	}

	// For entries with invalid unban time (but valid ban time), verify fallback worked
	if name == "invalid unban time - entry should use fallback" && len(records) > 0 {
		// The first record should have a reasonable remaining time (not zero)
		if records[0].Remaining == "00:00:00:00" {
			t.Errorf("expected fallback time calculation, got zero remaining time")
		}
	}

	// For entries using short format fallback
	if name == "short format fallback" && len(records) > 0 {
		for _, record := range records {
			if record.Remaining != "unknown" {
				t.Errorf("expected 'unknown' remaining time for short format, got %s", record.Remaining)
			}
		}
	}
}
