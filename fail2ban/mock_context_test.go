package fail2ban

import (
	"context"
	"errors"
	"testing"
)

//nolint:gocyclo // exhaustive table-driven coverage of every mock context method
func TestMockClientContextMethods(t *testing.T) {
	mockClient := NewMockClient()
	ctx := context.Background()

	// Test ListJailsWithContext
	jails, err := mockClient.ListJailsWithContext(ctx)
	if err != nil {
		t.Errorf("ListJailsWithContext failed: %v", err)
	}
	if len(jails) == 0 {
		t.Error("Expected some jails, got empty list")
	}

	// Test StatusAllWithContext
	status, err := mockClient.StatusAllWithContext(ctx)
	if err != nil {
		t.Errorf("StatusAllWithContext failed: %v", err)
	}
	if status == "" {
		t.Error("Expected status output, got empty string")
	}

	// Test StatusJailWithContext
	status, err = mockClient.StatusJailWithContext(ctx, "sshd")
	if err != nil {
		t.Errorf("StatusJailWithContext failed: %v", err)
	}
	if status == "" {
		t.Error("Expected jail status output, got empty string")
	}

	// Test BanIPWithContext
	code, err := mockClient.BanIPWithContext(ctx, "192.168.1.100", "sshd")
	if err != nil {
		t.Errorf("BanIPWithContext failed: %v", err)
	}
	if code != 0 {
		t.Errorf("Expected ban code 0, got %d", code)
	}

	// Test UnbanIPWithContext
	code, err = mockClient.UnbanIPWithContext(ctx, "192.168.1.100", "sshd")
	if err != nil {
		t.Errorf("UnbanIPWithContext failed: %v", err)
	}
	if code != 0 {
		t.Errorf("Expected unban code 0, got %d", code)
	}

	// Test BannedInWithContext
	bannedJails, err := mockClient.BannedInWithContext(ctx, "192.168.1.100")
	if err != nil {
		t.Errorf("BannedInWithContext failed: %v", err)
	}
	// Should be empty for a fresh mock
	if len(bannedJails) != 0 {
		t.Errorf("Expected empty banned jails list, got %v", bannedJails)
	}

	// Test GetBanRecordsWithContext
	records, err := mockClient.GetBanRecordsWithContext(ctx, []string{"sshd"})
	if err != nil {
		t.Errorf("GetBanRecordsWithContext failed: %v", err)
	}
	// Should be empty for a fresh mock
	if len(records) != 0 {
		t.Errorf("Expected empty ban records, got %v", records)
	}

	// Test GetLogLinesWithContext
	lines, err := mockClient.GetLogLinesWithContext(ctx, "sshd", "192.168.1.100")
	if err != nil {
		t.Errorf("GetLogLinesWithContext failed: %v", err)
	}
	// Mock client may return some mock data, that's fine
	_ = lines

	// Test ListFiltersWithContext
	filters, err := mockClient.ListFiltersWithContext(ctx)
	if err != nil {
		t.Errorf("ListFiltersWithContext failed: %v", err)
	}
	if len(filters) == 0 {
		t.Error("Expected some filters, got empty list")
	}

	// Test TestFilterWithContext - may fail if filter doesn't exist, that's ok
	result, err := mockClient.TestFilterWithContext(ctx, "sshd")
	if err == nil && result == "" {
		t.Error("Expected test result or error, got neither")
	}

	// The WithContext wrappers must honor cancellation: a canceled context
	// returns its error before the underlying method runs. This exercises the
	// shared wrapWithContext* production logic, not the mock's canned data.
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := mockClient.ListJailsWithContext(canceledCtx); !errors.Is(err, context.Canceled) {
		t.Errorf("ListJailsWithContext(canceled) err = %v, want context.Canceled", err)
	}
	if _, err := mockClient.StatusJailWithContext(canceledCtx, "sshd"); !errors.Is(err, context.Canceled) {
		t.Errorf("StatusJailWithContext(canceled) err = %v, want context.Canceled", err)
	}
	if _, err := mockClient.BanIPWithContext(canceledCtx, "192.168.1.100", "sshd"); !errors.Is(err, context.Canceled) {
		t.Errorf("BanIPWithContext(canceled) err = %v, want context.Canceled", err)
	}
}

func TestMockClientConfigurationMethods(t *testing.T) {
	mockClient := NewMockClient()

	testErr := NewInvalidIPError("test ip")
	// Set*(jail, ip, ...) — jail first. (The original test passed these
	// swapped, which went unnoticed because it asserted nothing.)
	mockClient.SetBanError("sshd", "192.168.1.1", testErr)
	mockClient.SetBanResult("sshd", "192.168.1.2", 1)
	mockClient.SetUnbanError("sshd", "192.168.1.3", testErr)
	mockClient.SetUnbanResult("sshd", "192.168.1.4", 1)
	mockClient.SetStatusJailData("apache", "status: active")
	mockClient.SetFilterTest("apache", "filter test result")

	ctx := context.Background()

	// A configured ban error must be surfaced.
	if _, err := mockClient.BanIPWithContext(ctx, "192.168.1.1", "sshd"); !errors.Is(err, testErr) {
		t.Errorf("BanIPWithContext error = %v, want %v", err, testErr)
	}
	// A configured ban result code must be returned.
	if code, err := mockClient.BanIPWithContext(ctx, "192.168.1.2", "sshd"); err != nil || code != 1 {
		t.Errorf("BanIPWithContext = (%d, %v), want (1, nil)", code, err)
	}
	// A configured unban error must be surfaced.
	if _, err := mockClient.UnbanIPWithContext(ctx, "192.168.1.3", "sshd"); !errors.Is(err, testErr) {
		t.Errorf("UnbanIPWithContext error = %v, want %v", err, testErr)
	}
	// Configured status and filter data must round-trip through the context wrappers.
	if status, err := mockClient.StatusJailWithContext(ctx, "apache"); err != nil || status != "status: active" {
		t.Errorf("StatusJailWithContext = (%q, %v), want (\"status: active\", nil)", status, err)
	}
	if filter, err := mockClient.TestFilterWithContext(ctx, "apache"); err != nil || filter != "filter test result" {
		t.Errorf("TestFilterWithContext = (%q, %v), want (\"filter test result\", nil)", filter, err)
	}
}
