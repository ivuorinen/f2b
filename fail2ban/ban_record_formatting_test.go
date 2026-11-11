// Package fail2ban_test provides external tests for the fail2ban package,
// ensuring proper isolation and testing of exported interfaces.
package fail2ban_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// TestBanRecordFormatting tests the ban record formatting
func TestBanRecordFormatting(t *testing.T) {
	// Test duration formatting indirectly through GetBanRecords
	mock := &fail2bantest.MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}
	mock.SetResponse("fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("fail2ban-client ping", []byte("pong"))
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))

	// Create a mock ban record with specific times. fail2ban-client emits
	// zone-less local timestamps and the parser interprets them in the local
	// zone, so build the expected times in time.Local to match.
	banTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.Local)
	unbanTime := time.Date(2024, 1, 1, 14, 30, 45, 0, time.Local) // 2 hours, 30 minutes, 45 seconds later

	mockBanOutput := fmt.Sprintf("192.168.1.100 %s + %s extra field",
		banTime.Format("2006-01-02 15:04:05"),
		unbanTime.Format("2006-01-02 15:04:05"))
	mock.SetResponse("fail2ban-client get sshd banip --with-time", []byte(mockBanOutput))

	t.Cleanup(fail2bantest.WithTestRunner(t, mock))

	client, err := fail2ban.NewClient(constants.DefaultLogDir, constants.DefaultFilterDir)
	fail2bantest.AssertError(t, err, false, "create client")

	records, err := client.GetBanRecordsWithContext(context.Background(), []string{"sshd"})
	fail2bantest.AssertError(t, err, false, "GetBanRecords")

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
		if !record.BannedAt.Equal(banTime) {
			t.Errorf("expected ban time %v, got %v", banTime, record.BannedAt)
		}
		// The remaining time should be formatted as DD:HH:MM:SS
		// We can't test the exact value as it depends on the current time
		// but we can test that it's formatted correctly
		if !strings.Contains(record.Remaining, ":") {
			t.Errorf("expected remaining time to contain colons, got %q", record.Remaining)
		}
	}
}
