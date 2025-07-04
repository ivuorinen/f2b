package fail2ban_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/fail2ban"
)

func TestNewMockClient(t *testing.T) {
	client := fail2ban.NewMockClient()

	if client == nil {
		t.Fatal("NewMockClient should return a non-nil client")
	}

	// Test default jails
	jails, err := client.ListJails()
	if err != nil {
		t.Fatalf("ListJails failed: %v", err)
	}

	expectedJails := []string{"sshd", "apache"}
	if len(jails) != len(expectedJails) {
		t.Errorf("expected %d default jails, got %d", len(expectedJails), len(jails))
	}

	// Test default filters
	filters, err := client.ListFilters()
	if err != nil {
		t.Fatalf("ListFilters failed: %v", err)
	}

	expectedFilters := []string{"sshd", "apache"}
	if len(filters) != len(expectedFilters) {
		t.Errorf("expected %d default filters, got %d", len(expectedFilters), len(filters))
	}
}

func TestMockClientListJails(t *testing.T) {
	client := fail2ban.NewMockClient()

	jails, err := client.ListJails()
	if err != nil {
		t.Fatalf("ListJails failed: %v", err)
	}

	// Should contain default jails
	jailMap := make(map[string]bool)
	for _, jail := range jails {
		jailMap[jail] = true
	}

	if !jailMap["sshd"] {
		t.Errorf("expected 'sshd' jail in default jails")
	}
	if !jailMap["apache"] {
		t.Errorf("expected 'apache' jail in default jails")
	}
}

func TestMockClientStatusAll(t *testing.T) {
	client := fail2ban.NewMockClient()

	status, err := client.StatusAll()
	if err != nil {
		t.Fatalf("StatusAll failed: %v", err)
	}

	expected := "Mock status for all jails"
	if status != expected {
		t.Errorf("expected status %q, got %q", expected, status)
	}
}

func TestMockClientStatusJail(t *testing.T) {
	client := fail2ban.NewMockClient()

	tests := []struct {
		name        string
		jail        string
		expectError bool
	}{
		{
			name:        "existing jail",
			jail:        "sshd",
			expectError: false,
		},
		{
			name:        "another existing jail",
			jail:        "apache",
			expectError: false,
		},
		{
			name:        "non-existent jail",
			jail:        "nonexistent",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, err := client.StatusJail(tt.jail)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for jail %q", tt.jail)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for jail %q: %v", tt.jail, err)
				}
				expected := "Mock status for jail " + tt.jail
				if status != expected {
					t.Errorf("expected status %q, got %q", expected, status)
				}
			}
		})
	}
}

func TestMockClientBanIP(t *testing.T) {
	client := fail2ban.NewMockClient()

	tests := []struct {
		name         string
		ip           string
		jail         string
		expectedCode int
		expectError  bool
	}{
		{
			name:         "ban new IP",
			ip:           "192.168.1.100",
			jail:         "sshd",
			expectedCode: 0,
			expectError:  false,
		},
		{
			name:         "ban same IP again",
			ip:           "192.168.1.100",
			jail:         "sshd",
			expectedCode: 1,
			expectError:  false,
		},
		{
			name:         "ban IP in different jail",
			ip:           "192.168.1.100",
			jail:         "apache",
			expectedCode: 0,
			expectError:  false,
		},
		{
			name:        "ban IP in non-existent jail",
			ip:          "192.168.1.100",
			jail:        "nonexistent",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := client.BanIP(tt.ip, tt.jail)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for jail %q", tt.jail)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if code != tt.expectedCode {
					t.Errorf("expected code %d, got %d", tt.expectedCode, code)
				}
			}
		})
	}
}

func TestMockClientUnbanIP(t *testing.T) {
	client := fail2ban.NewMockClient()

	// First ban an IP
	_, err := client.BanIP("192.168.1.100", "sshd")
	if err != nil {
		t.Fatalf("failed to ban IP: %v", err)
	}

	tests := []struct {
		name         string
		ip           string
		jail         string
		expectedCode int
		expectError  bool
	}{
		{
			name:         "unban existing banned IP",
			ip:           "192.168.1.100",
			jail:         "sshd",
			expectedCode: 0,
			expectError:  false,
		},
		{
			name:         "unban already unbanned IP",
			ip:           "192.168.1.100",
			jail:         "sshd",
			expectedCode: 1,
			expectError:  false,
		},
		{
			name:         "unban never-banned IP",
			ip:           "192.168.1.101",
			jail:         "sshd",
			expectedCode: 1,
			expectError:  false,
		},
		{
			name:        "unban IP in non-existent jail",
			ip:          "192.168.1.100",
			jail:        "nonexistent",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := client.UnbanIP(tt.ip, tt.jail)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for jail %q", tt.jail)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if code != tt.expectedCode {
					t.Errorf("expected code %d, got %d", tt.expectedCode, code)
				}
			}
		})
	}
}

func TestMockClientBannedIn(t *testing.T) {
	client := fail2ban.NewMockClient()

	// Ban IP in multiple jails
	_, err := client.BanIP("192.168.1.100", "sshd")
	if err != nil {
		t.Fatalf("failed to ban IP in sshd: %v", err)
	}

	_, err = client.BanIP("192.168.1.100", "apache")
	if err != nil {
		t.Fatalf("failed to ban IP in apache: %v", err)
	}

	tests := []struct {
		name          string
		ip            string
		expectedJails []string
	}{
		{
			name:          "IP banned in multiple jails",
			ip:            "192.168.1.100",
			expectedJails: []string{"sshd", "apache"},
		},
		{
			name:          "IP not banned anywhere",
			ip:            "192.168.1.101",
			expectedJails: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jails, err := client.BannedIn(tt.ip)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if len(jails) != len(tt.expectedJails) {
				t.Errorf("expected %d jails, got %d", len(tt.expectedJails), len(jails))
			}

			// Convert to map for easier checking
			jailMap := make(map[string]bool)
			for _, jail := range jails {
				jailMap[jail] = true
			}

			for _, expectedJail := range tt.expectedJails {
				if !jailMap[expectedJail] {
					t.Errorf("expected jail %q not found in result", expectedJail)
				}
			}
		})
	}
}

func TestMockClientGetBanRecords(t *testing.T) {
	client := fail2ban.NewMockClient()

	// Ban some IPs
	_, err := client.BanIP("192.168.1.100", "sshd")
	if err != nil {
		t.Fatalf("failed to ban IP: %v", err)
	}

	_, err = client.BanIP("192.168.1.101", "apache")
	if err != nil {
		t.Fatalf("failed to ban IP: %v", err)
	}

	records, err := client.GetBanRecords([]string{"sshd", "apache"})
	if err != nil {
		t.Fatalf("GetBanRecords failed: %v", err)
	}

	if len(records) != 2 {
		t.Errorf("expected 2 ban records, got %d", len(records))
	}

	// Check that records contain expected data
	recordMap := make(map[string]fail2ban.BanRecord)
	for _, record := range records {
		key := record.Jail + ":" + record.IP
		recordMap[key] = record
	}

	if _, exists := recordMap["sshd:192.168.1.100"]; !exists {
		t.Errorf("expected ban record for sshd:192.168.1.100")
	}

	if _, exists := recordMap["apache:192.168.1.101"]; !exists {
		t.Errorf("expected ban record for apache:192.168.1.101")
	}

	// Check remaining time format
	for _, record := range records {
		if record.Remaining != "01:00:00:00" {
			t.Errorf("expected remaining time '01:00:00:00', got %q", record.Remaining)
		}
	}
}

func TestMockClientGetLogLines(t *testing.T) {
	client := fail2ban.NewMockClient()

	// Ban and unban some IPs to generate log entries
	_, err := client.BanIP("192.168.1.100", "sshd")
	if err != nil {
		t.Fatalf("failed to ban IP: %v", err)
	}

	_, err = client.UnbanIP("192.168.1.100", "sshd")
	if err != nil {
		t.Fatalf("failed to unban IP: %v", err)
	}

	_, err = client.BanIP("192.168.1.101", "apache")
	if err != nil {
		t.Fatalf("failed to ban IP: %v", err)
	}

	tests := []struct {
		name          string
		jail          string
		ip            string
		expectedLines int
		shouldContain []string
	}{
		{
			name:          "all logs",
			jail:          "",
			ip:            "",
			expectedLines: 3,
			shouldContain: []string{"Ban 192.168.1.100", "Unban 192.168.1.100", "Ban 192.168.1.101"},
		},
		{
			name:          "filter by jail",
			jail:          "sshd",
			ip:            "",
			expectedLines: 2,
			shouldContain: []string{"Ban 192.168.1.100", "Unban 192.168.1.100"},
		},
		{
			name:          "filter by IP",
			jail:          "",
			ip:            "192.168.1.100",
			expectedLines: 2,
			shouldContain: []string{"Ban 192.168.1.100", "Unban 192.168.1.100"},
		},
		{
			name:          "filter by jail and IP",
			jail:          "sshd",
			ip:            "192.168.1.100",
			expectedLines: 2,
			shouldContain: []string{"Ban 192.168.1.100", "Unban 192.168.1.100"},
		},
		{
			name:          "no matching logs",
			jail:          "nonexistent",
			ip:            "",
			expectedLines: 0,
			shouldContain: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines, err := client.GetLogLines(tt.jail, tt.ip)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if len(lines) != tt.expectedLines {
				t.Errorf("expected %d lines, got %d", tt.expectedLines, len(lines))
			}

			// Check that expected content is present
			logContent := strings.Join(lines, " ")
			for _, expected := range tt.shouldContain {
				if !strings.Contains(logContent, expected) {
					t.Errorf("expected log content to contain %q", expected)
				}
			}
		})
	}
}

func TestMockClientListFilters(t *testing.T) {
	client := fail2ban.NewMockClient()

	filters, err := client.ListFilters()
	if err != nil {
		t.Fatalf("ListFilters failed: %v", err)
	}

	expectedFilters := []string{"sshd", "apache"}
	if len(filters) != len(expectedFilters) {
		t.Errorf("expected %d filters, got %d", len(expectedFilters), len(filters))
	}

	filterMap := make(map[string]bool)
	for _, filter := range filters {
		filterMap[filter] = true
	}

	for _, expected := range expectedFilters {
		if !filterMap[expected] {
			t.Errorf("expected filter %q not found", expected)
		}
	}
}

func TestMockClientTestFilter(t *testing.T) {
	client := fail2ban.NewMockClient()

	tests := []struct {
		name        string
		filter      string
		expectError bool
	}{
		{
			name:        "non-existent filter",
			filter:      "nonexistent",
			expectError: true,
		},
		{
			name:        "empty filter name",
			filter:      "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := client.TestFilter(tt.filter)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for filter %q", tt.filter)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result == "" {
					t.Errorf("expected non-empty result")
				}
			}
		})
	}
}

func TestMockClientReset(t *testing.T) {
	client := fail2ban.NewMockClient()

	// Ban some IPs and generate logs
	_, err := client.BanIP("192.168.1.100", "sshd")
	if err != nil {
		t.Fatalf("failed to ban IP: %v", err)
	}

	_, err = client.BanIP("192.168.1.101", "apache")
	if err != nil {
		t.Fatalf("failed to ban IP: %v", err)
	}

	// Verify that IPs are banned
	jails, err := client.BannedIn("192.168.1.100")
	if err != nil {
		t.Fatalf("BannedIn failed: %v", err)
	}
	if len(jails) == 0 {
		t.Fatalf("expected IP to be banned before reset")
	}

	// Verify that logs exist
	logs, err := client.GetLogLines("", "")
	if err != nil {
		t.Fatalf("GetLogLines failed: %v", err)
	}
	if len(logs) == 0 {
		t.Fatalf("expected logs to exist before reset")
	}

	// Reset the client
	client.Reset()

	// Verify that bans are cleared
	jails, err = client.BannedIn("192.168.1.100")
	if err != nil {
		t.Fatalf("BannedIn failed after reset: %v", err)
	}
	if len(jails) != 0 {
		t.Errorf("expected no banned IPs after reset, got %d", len(jails))
	}

	// Verify that logs are cleared
	logs, err = client.GetLogLines("", "")
	if err != nil {
		t.Fatalf("GetLogLines failed after reset: %v", err)
	}
	if len(logs) != 0 {
		t.Errorf("expected no logs after reset, got %d", len(logs))
	}

	// Verify that ban records are cleared
	records, err := client.GetBanRecords([]string{"sshd", "apache"})
	if err != nil {
		t.Fatalf("GetBanRecords failed after reset: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected no ban records after reset, got %d", len(records))
	}
}

func TestMockClientConcurrency(t *testing.T) {
	client := fail2ban.NewMockClient()

	// Test concurrent operations
	done := make(chan bool, 10)
	errors := make(chan error, 10)

	// Start multiple goroutines performing operations
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()

			ip := fmt.Sprintf("192.168.1.%d", 100+id)
			jail := "sshd"

			// Ban IP
			_, err := client.BanIP(ip, jail)
			if err != nil {
				errors <- err
				return
			}

			// Check if banned
			jails, err := client.BannedIn(ip)
			if err != nil {
				errors <- err
				return
			}

			if len(jails) == 0 {
				errors <- fmt.Errorf("IP %s should be banned", ip)
				return
			}

			// Unban IP
			_, err = client.UnbanIP(ip, jail)
			if err != nil {
				errors <- err
				return
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Check for errors
	close(errors)
	for err := range errors {
		t.Errorf("concurrent operation error: %v", err)
	}
}

func BenchmarkMockClientBanUnban(b *testing.B) {
	client := fail2ban.NewMockClient()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i%255)
		_, _ = client.BanIP(ip, "sshd")
		_, _ = client.UnbanIP(ip, "sshd")
	}
}

func BenchmarkMockClientBannedIn(b *testing.B) {
	client := fail2ban.NewMockClient()

	// Pre-ban some IPs
	for i := 0; i < 100; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i)
		_, _ = client.BanIP(ip, "sshd")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i%100)
		_, _ = client.BannedIn(ip)
	}
}
