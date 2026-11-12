package fail2bantest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// TestMockClientRefusesWhatRealClientRefusesToBan pins that ban and unban
// validate the target and jail before any configured result, as RealClient
// validates before running fail2ban-client.
func TestMockClientRefusesWhatRealClientRefusesToBan(t *testing.T) {
	actions := map[string]func(*MockClient, string, string) (int, error){
		"ban": func(m *MockClient, ip, jail string) (int, error) {
			return m.BanIPWithContext(context.Background(), ip, jail)
		},
		"unban": func(m *MockClient, ip, jail string) (int, error) {
			return m.UnbanIPWithContext(context.Background(), ip, jail)
		},
	}
	inputs := map[string][2]string{
		"range beyond /32": {"10.0.0.0/33", "sshd"},
		"host-bit range":   {"192.168.1.23/24", "sshd"},
		"not an address":   {"999.1.1.1", "sshd"},
		"invalid jail":     {"192.0.2.1", "bad jail"},
	}
	for action, run := range actions {
		for label, in := range inputs {
			t.Run(action+" "+label, func(t *testing.T) {
				m := NewMockClient()
				m.SetBanResult(in[1], in[0], 0)
				m.SetUnbanResult(in[1], in[0], 0)

				_, err := run(m, in[0], in[1])

				require.Error(t, err)
				assert.Empty(t, m.Banned[in[1]], "a refused ban changes no state")
			})
		}
	}
}

// TestMockClientFiltersConfiguredBanRecordsByJail pins that configured ban
// records are returned only for the requested jails, as RealClient queries
// only the jails it is given.
func TestMockClientFiltersConfiguredBanRecordsByJail(t *testing.T) {
	tests := map[string]struct {
		jails []string
		want  []string
	}{
		"one jail":   {[]string{"sshd"}, []string{"sshd"}},
		"other jail": {[]string{"apache"}, []string{"apache"}},
		"no match":   {[]string{"nginx"}, []string{}},
		"all":        {[]string{constants.AllFilter}, []string{"sshd", "apache"}},
		"none named": {nil, []string{"sshd", "apache"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := NewMockClient()
			m.BanRecords = []fail2ban.BanRecord{{Jail: "sshd", IP: "192.0.2.1"}, {Jail: "apache", IP: "192.0.2.2"}}

			recs, err := m.GetBanRecordsWithContext(context.Background(), tt.jails)

			require.NoError(t, err)
			got := make([]string, 0, len(recs))
			for _, rec := range recs {
				got = append(got, rec.Jail)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestMockClientValidatesLogQueries pins that log reads refuse the filters and
// limits RealClient refuses, and that a zero limit reads nothing.
func TestMockClientValidatesLogQueries(t *testing.T) {
	tests := map[string]struct {
		jail, ip string
		maxLines int
	}{
		"ip filter not an address": {"", "not-an-ip", 10},
		"invalid jail filter":      {"bad jail", "", 10},
		"negative limit":           {"", "", -5},
		"limit above maximum":      {"", "", constants.MaxLogLinesLimit + 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := NewMockClient()
			m.LogLines = []string{"[sshd] Ban 192.0.2.1"}

			lines, err := m.GetLogLinesWithLimitContext(context.Background(), tt.jail, tt.ip, tt.maxLines)

			require.Error(t, err)
			assert.Nil(t, lines)
		})
	}
	t.Run("zero limit", func(t *testing.T) {
		m := NewMockClient()
		m.LogLines = []string{"[sshd] Ban 192.0.2.1"}

		lines, err := m.GetLogLinesWithLimitContext(context.Background(), "", "", 0)

		require.NoError(t, err)
		assert.Empty(t, lines)
	})
}

// TestMockClientRecordsTheFilterTestLogFile pins that the log file passed to
// TestFilterWithContext is recorded, so a test can assert that test-filter
// forwarded it.
func TestMockClientRecordsTheFilterTestLogFile(t *testing.T) {
	m := NewMockClient()
	m.SetFilterTest("sshd", "Lines: 1 lines, 0 ignored, 1 matched")

	out, err := m.TestFilterWithContext(context.Background(), "sshd", "/var/log/auth.log")

	require.NoError(t, err)
	assert.NotEmpty(t, out)
	assert.Equal(t, "/var/log/auth.log", m.LastFilterLogFile)
}
