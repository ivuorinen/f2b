package fail2ban

import (
	"context"
	"testing"
)

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
}

func TestMockClientConfigurationMethods(_ *testing.T) {
	mockClient := NewMockClient()

	// Test that configuration methods exist and can be called
	testErr := NewInvalidIPError("test ip")
	mockClient.SetBanError("192.168.1.1", "sshd", testErr)
	mockClient.SetBanResult("192.168.1.2", "sshd", 1)
	mockClient.SetUnbanError("192.168.1.3", "sshd", testErr)
	mockClient.SetUnbanResult("192.168.1.4", "sshd", 1)
	mockClient.SetStatusJailData("apache", "status: active")
	mockClient.SetFilterTest("apache", "filter test result")

	// Just verify the methods don't panic
	ctx := context.Background()
	_, _ = mockClient.BanIPWithContext(ctx, "192.168.1.1", "sshd")
	_, _ = mockClient.UnbanIPWithContext(ctx, "192.168.1.3", "sshd")
	_, _ = mockClient.StatusJailWithContext(ctx, "apache")
	_, _ = mockClient.TestFilterWithContext(ctx, "apache")
}

func TestNoOpClientContextMethods(_ *testing.T) {
	noopClient := NewNoOpClient()
	ctx := context.Background()

	// Test that all context methods can be called without panicking
	// NoOpClient may return errors due to fail2ban not being available
	_, _ = noopClient.ListJailsWithContext(ctx)
	_, _ = noopClient.StatusAllWithContext(ctx)
	_, _ = noopClient.StatusJailWithContext(ctx, "sshd")
	_, _ = noopClient.BanIPWithContext(ctx, "192.168.1.1", "sshd")
	_, _ = noopClient.UnbanIPWithContext(ctx, "192.168.1.1", "sshd")
	_, _ = noopClient.BannedInWithContext(ctx, "192.168.1.1")
	_, _ = noopClient.GetBanRecordsWithContext(ctx, []string{"sshd"})
	_, _ = noopClient.GetLogLinesWithContext(ctx, "sshd", "192.168.1.1")
	_, _ = noopClient.ListFiltersWithContext(ctx)
	_, _ = noopClient.TestFilterWithContext(ctx, "sshd")
}

func TestNoOpClientRegularMethods(_ *testing.T) {
	noopClient := NewNoOpClient()

	// Test that all regular methods can be called without panicking
	// NoOpClient may return errors due to fail2ban not being available
	_, _ = noopClient.ListJails()
	_, _ = noopClient.StatusAll()
	_, _ = noopClient.StatusJail("sshd")
	_, _ = noopClient.BanIP("192.168.1.1", "sshd")
	_, _ = noopClient.UnbanIP("192.168.1.1", "sshd")
	_, _ = noopClient.BannedIn("192.168.1.1")
	_, _ = noopClient.GetBanRecords([]string{"sshd"})
	_, _ = noopClient.GetLogLines("sshd", "192.168.1.1")
	_, _ = noopClient.ListFilters()
	_, _ = noopClient.TestFilter("sshd")
}
