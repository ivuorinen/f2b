package query

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLogFilterMatches pins the jail/IP log filter: the jail must appear in
// brackets, the IP as a whole token in its canonical form, and an empty value
// or "all" disables that half of the filter.
func TestLogFilterMatches(t *testing.T) {
	const line = "2030-01-01 10:00:00,000 fail2ban.actions [1]: NOTICE [sshd] Ban 2001:db8::1"
	tests := map[string]struct {
		jail, ip string
		want     bool
	}{
		"no filter":                 {"", "", true},
		"all jails and all IPs":     {"all", "all", true},
		"matching jail":             {"sshd", "", true},
		"other jail":                {"nginx", "", false},
		"jail name without bracket": {"ssh", "", false},
		"matching IP":               {"", "2001:db8::1", true},
		"non-canonical IP":          {"", "2001:DB8::0001", true},
		"IP prefix of a longer one": {"", "2001:db8::", false},
		"other IP":                  {"", "192.0.2.1", false},
		"matching jail and IP":      {"sshd", "2001:db8::1", true},
		"matching jail, other IP":   {"sshd", "192.0.2.1", false},
		"other jail, matching IP":   {"nginx", "2001:db8::1", false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, NewLogFilter(tt.jail, tt.ip).Matches(line))
		})
	}
}

// TestLogFilterZeroValueMatchesEverything pins that an unprepared filter
// filters nothing, so a config that skipped preparation drops no lines.
func TestLogFilterZeroValueMatchesEverything(t *testing.T) {
	assert.True(t, LogFilter{}.Matches("any line at all"))
}
