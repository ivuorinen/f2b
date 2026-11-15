package fail2bantest

import (
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/ivuorinen/f2b/fail2ban"
)

func TestMockClientBanIP(t *testing.T) {
	client := NewMockClient()

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
			code, err := client.BanIPWithContext(bg, tt.ip, tt.jail)

			AssertError(t, err, tt.expectError, tt.name)
			if !tt.expectError {
				if code != tt.expectedCode {
					t.Errorf("expected code %d, got %d", tt.expectedCode, code)
				}
			}
		})
	}
}

func TestMockClientUnbanIP(t *testing.T) {
	client := NewMockClient()

	// First ban an IP
	_, err := client.BanIPWithContext(bg, "192.168.1.100", "sshd")
	AssertError(t, err, false, "ban IP for setup")

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
			code, err := client.UnbanIPWithContext(bg, tt.ip, tt.jail)

			AssertError(t, err, tt.expectError, tt.name)
			if !tt.expectError {
				if code != tt.expectedCode {
					t.Errorf("expected code %d, got %d", tt.expectedCode, code)
				}
			}
		})
	}
}

// TestMockClientRangeUnbanRemovesAddressesInside pins that the mock models the
// real client's range unban: it removes the range's own entry and every banned
// address inside the range, and leaves addresses outside it banned. Without
// this, a command test passes against a mock that keeps those bans.
func TestMockClientRangeUnbanRemovesAddressesInside(t *testing.T) {
	tests := map[string]struct {
		banned   []string
		target   string
		wantCode int
		wantLeft []string
	}{
		"range entry and an address inside": {
			[]string{"192.168.1.0/24", "192.168.1.100", "192.168.2.1"}, "192.168.1.0/24", 0, []string{"192.168.2.1"},
		},
		"address inside without a range entry": {
			[]string{"192.168.1.100", "192.168.2.1"}, "192.168.1.0/24", 0, []string{"192.168.2.1"},
		},
		"IPv6 address inside": {
			[]string{"2001:db8::1", "2001:db9::1"}, "2001:db8::/32", 0, []string{"2001:db9::1"},
		},
		"nothing inside": {
			[]string{"192.168.2.1"}, "192.168.1.0/24", 1, []string{"192.168.2.1"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client := NewMockClient()
			for _, ip := range tt.banned {
				_, err := client.BanIPWithContext(bg, ip, "sshd")
				AssertError(t, err, false, "ban "+ip+" for setup")
			}

			code, err := client.UnbanIPWithContext(bg, tt.target, "sshd")

			AssertError(t, err, false, "range unban")
			if code != tt.wantCode {
				t.Errorf("expected code %d, got %d", tt.wantCode, code)
			}
			if left := slices.Sorted(maps.Keys(client.Banned["sshd"])); !slices.Equal(left, tt.wantLeft) {
				t.Errorf("expected %v to stay banned, got %v", tt.wantLeft, left)
			}
		})
	}
}

// TestMockClientTreatsAZeroBanTimeAsBanned pins one ban-state rule across the
// mock: a Banned entry is banned whatever its ban time. Unban used to skip an
// entry with a zero time and answer "already unbanned" while ban and banned-in
// still reported the same entry as banned.
func TestMockClientTreatsAZeroBanTimeAsBanned(t *testing.T) {
	for _, target := range []string{"192.168.1.100", "192.168.1.0/24"} {
		t.Run("unban "+target, func(t *testing.T) {
			client := NewMockClient()
			client.Banned["sshd"] = map[string]time.Time{"192.168.1.100": {}}

			jails, err := client.BannedInWithContext(bg, "192.168.1.100")
			AssertError(t, err, false, "banned-in")
			if !slices.Equal(jails, []string{"sshd"}) {
				t.Errorf("expected banned in [sshd], got %v", jails)
			}
			code, err := client.BanIPWithContext(bg, "192.168.1.100", "sshd")
			AssertError(t, err, false, "ban")
			if code != 1 {
				t.Errorf("expected ban code 1 (already banned), got %d", code)
			}

			code, err = client.UnbanIPWithContext(bg, target, "sshd")

			AssertError(t, err, false, "unban")
			if code != 0 {
				t.Errorf("expected unban code 0, got %d", code)
			}
			if left := slices.Sorted(maps.Keys(client.Banned["sshd"])); len(left) != 0 {
				t.Errorf("expected nothing to stay banned, got %v", left)
			}
		})
	}
}

func TestMockClientBannedIn(t *testing.T) {
	client := NewMockClient()

	// Ban IP in multiple jails
	_, err := client.BanIPWithContext(bg, "192.168.1.100", "sshd")
	AssertError(t, err, false, "ban IP in sshd")

	_, err = client.BanIPWithContext(bg, "192.168.1.100", "apache")
	AssertError(t, err, false, "ban IP in apache")

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
			jails, err := client.BannedInWithContext(bg, tt.ip)
			AssertError(t, err, false, tt.name)

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
	client := NewMockClient()

	// Ban some IPs
	_, err := client.BanIPWithContext(bg, "192.168.1.100", "sshd")
	AssertError(t, err, false, "ban IP 1")

	_, err = client.BanIPWithContext(bg, "192.168.1.101", "apache")
	AssertError(t, err, false, "ban IP 2")

	records, err := client.GetBanRecordsWithContext(bg, []string{"sshd", "apache"})
	AssertError(t, err, false, "GetBanRecords")

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

func BenchmarkMockClientBanUnban(b *testing.B) {
	client := NewMockClient()

	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		ip := fmt.Sprintf("192.168.1.%d", i%255)
		if _, err := client.BanIPWithContext(bg, ip, "sshd"); err != nil {
			b.Fatal(err)
		}
		if _, err := client.UnbanIPWithContext(bg, ip, "sshd"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMockClientBannedIn(b *testing.B) {
	client := NewMockClient()

	// Pre-ban some IPs
	for i := range 100 {
		ip := fmt.Sprintf("192.168.1.%d", i)
		if _, err := client.BanIPWithContext(bg, ip, "sshd"); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		ip := fmt.Sprintf("192.168.1.%d", i%100)
		if _, err := client.BannedInWithContext(bg, ip); err != nil {
			b.Fatal(err)
		}
	}
}
