package fail2bantest

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// bg is the context for mock calls that do not exercise cancellation.
var bg = context.Background()

func TestNewMockClient(t *testing.T) {
	client := NewMockClient()

	if client == nil {
		t.Fatal("NewMockClient should return a non-nil client")
	}

	// Test default jails
	jails, err := client.ListJailsWithContext(bg)
	AssertError(t, err, false, "ListJails")

	expectedJails := []string{"sshd", "apache"}
	if len(jails) != len(expectedJails) {
		t.Errorf("expected %d default jails, got %d", len(expectedJails), len(jails))
	}

	// Test default filters
	filters, err := client.ListFiltersWithContext(bg)
	AssertError(t, err, false, "ListFilters")

	expectedFilters := []string{"sshd", "apache"}
	if len(filters) != len(expectedFilters) {
		t.Errorf("expected %d default filters, got %d", len(expectedFilters), len(filters))
	}
}

func TestMockClientListJails(t *testing.T) {
	client := NewMockClient()

	jails, err := client.ListJailsWithContext(bg)
	AssertError(t, err, false, "ListJails")

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
	client := NewMockClient()

	status, err := client.StatusAllWithContext(bg)
	AssertError(t, err, false, "StatusAll")

	expected := "Mock status for all jails"
	if status != expected {
		t.Errorf("expected status %q, got %q", expected, status)
	}
}

func TestMockClientStatusJail(t *testing.T) {
	client := NewMockClient()

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
			status, err := client.StatusJailWithContext(bg, tt.jail)

			AssertError(t, err, tt.expectError, tt.name)
			if !tt.expectError {
				expected := "Mock status for jail " + tt.jail
				if status != expected {
					t.Errorf("expected status %q, got %q", expected, status)
				}
			}
		})
	}
}

func TestMockClientGetLogLines(t *testing.T) {
	client := NewMockClient()

	// Ban and unban some IPs to generate log entries
	_, err := client.BanIPWithContext(bg, "192.168.1.100", "sshd")
	AssertError(t, err, false, "ban IP for logs")

	_, err = client.UnbanIPWithContext(bg, "192.168.1.100", "sshd")
	AssertError(t, err, false, "unban IP for logs")

	_, err = client.BanIPWithContext(bg, "192.168.1.101", "apache")
	AssertError(t, err, false, "ban IP 2 for logs")

	ip100 := []string{"Ban 192.168.1.100", "Unban 192.168.1.100"}
	// want lists every line the query returns, so its length is the line count.
	tests := []struct {
		name, jail, ip string
		want           []string
	}{
		{"all logs", "", "", append(slices.Clone(ip100), "Ban 192.168.1.101")},
		{"filter by jail", "sshd", "", ip100},
		{"filter by IP", "", "192.168.1.100", ip100},
		{"filter by jail and IP", "sshd", "192.168.1.100", ip100},
		{"no matching logs", "nonexistent", "", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines, err := client.GetLogLinesWithContext(bg, tt.jail, tt.ip)
			AssertError(t, err, false, tt.name)

			if len(lines) != len(tt.want) {
				t.Errorf("expected %d lines, got %d", len(tt.want), len(lines))
			}

			logContent := strings.Join(lines, " ")
			for _, expected := range tt.want {
				if !strings.Contains(logContent, expected) {
					t.Errorf("expected log content to contain %q", expected)
				}
			}
		})
	}
}

func TestMockClientListFilters(t *testing.T) {
	client := NewMockClient()

	filters, err := client.ListFiltersWithContext(bg)
	AssertError(t, err, false, "ListFilters")

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
	client := NewMockClient()

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
			result, err := client.TestFilterWithContext(bg, tt.filter, "")

			AssertError(t, err, tt.expectError, tt.name)
			if !tt.expectError {
				if result == "" {
					t.Errorf("expected non-empty result")
				}
			}
		})
	}
}

func TestMockClientReset(t *testing.T) {
	client := NewMockClient()

	// Ban some IPs and generate logs
	_, err := client.BanIPWithContext(bg, "192.168.1.100", "sshd")
	AssertError(t, err, false, "ban IP for reset test")

	_, err = client.BanIPWithContext(bg, "192.168.1.101", "apache")
	AssertError(t, err, false, "ban IP 2 for reset test")

	// Verify that IPs are banned
	jails, err := client.BannedInWithContext(bg, "192.168.1.100")
	AssertError(t, err, false, "BannedIn before reset")
	if len(jails) == 0 {
		t.Fatalf("expected IP to be banned before reset")
	}

	// Verify that logs exist
	logs, err := client.GetLogLinesWithContext(bg, "", "")
	AssertError(t, err, false, "GetLogLines before reset")
	if len(logs) == 0 {
		t.Fatalf("expected logs to exist before reset")
	}

	// Reset the client
	client.Reset()

	// Verify that bans are cleared
	jails, err = client.BannedInWithContext(bg, "192.168.1.100")
	AssertError(t, err, false, "BannedIn after reset")
	if len(jails) != 0 {
		t.Errorf("expected no banned IPs after reset, got %d", len(jails))
	}

	// Verify that logs are cleared
	logs, err = client.GetLogLinesWithContext(bg, "", "")
	AssertError(t, err, false, "GetLogLines after reset")
	if len(logs) != 0 {
		t.Errorf("expected no logs after reset, got %d", len(logs))
	}

	// Verify that ban records are cleared
	records, err := client.GetBanRecordsWithContext(bg, []string{"sshd", "apache"})
	if err != nil {
		t.Fatalf("GetBanRecords failed after reset: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected no ban records after reset, got %d", len(records))
	}
}

func TestMockClientConcurrency(t *testing.T) {
	client := NewMockClient()

	// Test concurrent operations
	done := make(chan bool, 10)
	errors := make(chan error, 10)

	// Start multiple goroutines performing operations
	for i := range 10 {
		go func(id int) {
			defer func() { done <- true }()

			ip := fmt.Sprintf("192.168.1.%d", 100+id)
			jail := "sshd"

			// Ban IP
			_, err := client.BanIPWithContext(bg, ip, jail)
			if err != nil {
				errors <- err
				return
			}

			// Check if banned
			jails, err := client.BannedInWithContext(bg, ip)
			if err != nil {
				errors <- err
				return
			}

			if len(jails) == 0 {
				errors <- fmt.Errorf("IP %s should be banned", ip)
				return
			}

			// Unban IP
			_, err = client.UnbanIPWithContext(bg, ip, jail)
			if err != nil {
				errors <- err
				return
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for range 10 {
		<-done
	}

	// Check for errors
	close(errors)
	for err := range errors {
		t.Errorf("concurrent operation error: %v", err)
	}
}
