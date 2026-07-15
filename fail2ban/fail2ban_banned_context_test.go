package fail2ban

import (
	"context"
	"testing"
)

// setupMockForBannedInTest sets up mock responses for BannedIn tests
func setupMockForBannedInTest(ip, mockResponse string) *MockRunner {
	mock := NewMockRunner()
	mock.SetResponse("fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("sudo fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("fail2ban-client ping", []byte("pong"))
	mock.SetResponse("sudo fail2ban-client ping", []byte("pong"))
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mock.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mock.SetResponse("fail2ban-client banned "+ip, []byte(mockResponse))
	mock.SetResponse("sudo fail2ban-client banned "+ip, []byte(mockResponse))
	return mock
}

func TestBannedInWithContext_SingleJail(t *testing.T) {
	mock := setupMockForBannedInTest("192.168.1.100", `["sshd"]`)
	t.Cleanup(WithTestRunner(t, mock))

	client, err := NewClient("/var/log", "/etc/fail2ban/filter.d")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Test both versions return the same result
	nonContextResult, err1 := client.BannedIn("192.168.1.100")
	if err1 != nil {
		t.Fatalf("non-context version failed: %v", err1)
	}

	contextResult, err2 := client.BannedInWithContext(context.Background(), "192.168.1.100")
	if err2 != nil {
		t.Fatalf("context version failed: %v", err2)
	}

	// Both should return ["sshd"]
	if len(nonContextResult) != 1 || nonContextResult[0] != "sshd" {
		t.Errorf("non-context result: expected [sshd], got %v", nonContextResult)
	}
	if len(contextResult) != 1 || contextResult[0] != "sshd" {
		t.Errorf("context result: expected [sshd], got %v", contextResult)
	}
}

func TestBannedInWithContext_MultipleJails(t *testing.T) {
	mock := setupMockForBannedInTest("192.168.1.100", `["sshd", "apache"]`)
	t.Cleanup(WithTestRunner(t, mock))

	client, err := NewClient("/var/log", "/etc/fail2ban/filter.d")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Test both versions return the same result
	nonContextResult, err1 := client.BannedIn("192.168.1.100")
	if err1 != nil {
		t.Fatalf("non-context version failed: %v", err1)
	}

	contextResult, err2 := client.BannedInWithContext(context.Background(), "192.168.1.100")
	if err2 != nil {
		t.Fatalf("context version failed: %v", err2)
	}

	// Both should return ["sshd", "apache"]
	expected := []string{"sshd", "apache"}
	if len(nonContextResult) != len(expected) {
		t.Errorf("non-context result: expected %v, got %v", expected, nonContextResult)
	}
	if len(contextResult) != len(expected) {
		t.Errorf("context result: expected %v, got %v", expected, contextResult)
	}
}

func TestBannedInWithContext_NotBanned(t *testing.T) {
	mock := setupMockForBannedInTest("192.168.1.100", `[]`)
	t.Cleanup(WithTestRunner(t, mock))

	client, err := NewClient("/var/log", "/etc/fail2ban/filter.d")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Test both versions return empty result
	nonContextResult, err1 := client.BannedIn("192.168.1.100")
	if err1 != nil {
		t.Fatalf("non-context version failed: %v", err1)
	}

	contextResult, err2 := client.BannedInWithContext(context.Background(), "192.168.1.100")
	if err2 != nil {
		t.Fatalf("context version failed: %v", err2)
	}

	// Both should return empty slice
	if len(nonContextResult) != 0 {
		t.Errorf("non-context result: expected [], got %v", nonContextResult)
	}
	if len(contextResult) != 0 {
		t.Errorf("context result: expected [], got %v", contextResult)
	}
}

func TestBannedInWithContext_InvalidIP(t *testing.T) {
	mock := setupMockForBannedInTest("invalid-ip", "")
	t.Cleanup(WithTestRunner(t, mock))

	client, err := NewClient("/var/log", "/etc/fail2ban/filter.d")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Test invalid IP validation works the same in both versions
	_, err1 := client.BannedIn("invalid-ip")
	_, err2 := client.BannedInWithContext(context.Background(), "invalid-ip")

	if err1 == nil {
		t.Error("Expected error from non-context version for invalid IP")
	}
	if err2 == nil {
		t.Error("Expected error from context version for invalid IP")
	}
}
