package fail2ban_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// banListTail is what fail2ban 1.0.2 prints after the ban ID in
// `get <jail> banip --with-time`.
const banListTail = " \t2030-01-01 10:00:00 + 600 = 2030-01-01 10:10:00"

// TestParseBanRecordsReadsEveryAddressForm covers the forms fail2ban prints for
// an address ban. `set <jail> banip` accepts a range, and it is listed as one.
func TestParseBanRecordsReadsEveryAddressForm(t *testing.T) {
	for _, id := range []string{"192.0.2.1", "198.51.100.0/24", "2001:db8::1", "2001:db8::/32"} {
		t.Run(id, func(t *testing.T) {
			records, err := fail2ban.ParseBanRecords(id+banListTail, "sshd")

			require.NoError(t, err)
			require.Len(t, records, 1)
			assert.Equal(t, id, records[0].IP)
			assert.NotEqual(t, constants.UnknownValue, records[0].Remaining, "the ban times were not parsed")
		})
	}
}

// TestParseBanRecordsReportsBansItCannotRead pins the difference from an empty
// jail: an empty result would tell the operator that a jail with active bans
// has none.
func TestParseBanRecordsReportsBansItCannotRead(t *testing.T) {
	tests := map[string]struct {
		output string
		want   string
	}{
		"id taken from a log line": {"alice" + banListTail, "none of the 1 ban records"},
		"id holding a space":       {"some user" + banListTail, "none of the 1 ban records"},
		"malformed range":          {"198.51.100.0/33" + banListTail, "none of the 1 ban records"},
		"unparseable ban time": {
			"192.0.2.1 \tnot-a time + 600 = 2030-01-01 10:10:00", "none of the 1 ban records",
		},
		"several bans":        {"alice" + banListTail + "\nbob" + banListTail, "none of the 2 ban records"},
		"beside a warning":    {clientWarningLine + "\nalice" + banListTail, "none of the 1 ban records"},
		"unsafe jail on bans": {"192.0.2.1" + banListTail, "none of the 1 ban records"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			jail := "sshd"
			if name == "unsafe jail on bans" {
				jail = "../sshd"
			}

			records, err := fail2ban.ParseBanRecords(tt.output, jail)

			require.ErrorContains(t, err, tt.want)
			assert.Nil(t, records)
		})
	}
}

// clientWarningLine is stderr output from fail2ban-client. CombinedOutput mixes
// it into the ban list.
const clientWarningLine = "2030-01-01 10:00:00,000 fail2ban.configreader [123]: " +
	"WARNING 'allowipv6' not defined in 'Definition'. Using default one: 'auto'"

// TestParseBanRecordsTreatsOtherOutputAsNoBans pins that stderr noise on a jail
// with no bans stays an empty result rather than a failure. Each row misses one
// part of the ban list layout.
func TestParseBanRecordsTreatsOtherOutputAsNoBans(t *testing.T) {
	tests := map[string]string{
		"client warning":     clientWarningLine,
		"no plus separator":  "WARNING a b c d e f = g h",
		"no equals sign":     "WARNING a b c + e f g h",
		"too few fields":     "alice date + 600 = date time",
		"single unknown id":  "alice",
		"blank between junk": "WARNING one\n\nWARNING two",
	}
	for name, output := range tests {
		t.Run(name, func(t *testing.T) {
			records, err := fail2ban.ParseBanRecords(output, "sshd")

			require.NoError(t, err)
			assert.Empty(t, records)
		})
	}
}

// TestParseBanRecordsKeepsReadableBansBesideUnreadableOnes pins the partial
// result: the bans that could be read are listed and the rest are logged.
func TestParseBanRecordsKeepsReadableBansBesideUnreadableOnes(t *testing.T) {
	buf := captureLog(t, slog.LevelDebug)

	records, err := fail2ban.ParseBanRecords("alice"+banListTail+"\n192.0.2.1"+banListTail, "sshd")

	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "192.0.2.1", records[0].IP)
	assert.Contains(t, buf.String(), "skipped=1")
}

// TestGetBanRecordsReportsAnUnreadableJailOnce pins that the failure reaches
// the caller with the jail named, and is not also logged: with logs on stderr
// that would print the same failure twice.
func TestGetBanRecordsReportsAnUnreadableJailOnce(t *testing.T) {
	buf := captureLog(t, slog.LevelDebug)
	client, mock := clientOverMockRunner(t, "sshd")
	mock.SetResponse("fail2ban-client get sshd banip --with-time", []byte("alice"+banListTail))

	records, err := client.GetBanRecordsWithContext(context.Background(), []string{"sshd"})

	require.ErrorContains(t, err, "jail sshd: none of the 1 ban records")
	assert.Nil(t, records)
	assert.NotContains(t, buf.String(), "ban record")
}

// TestGetBanRecordsListsOtherJailsWhenOneIsUnreadable pins that one unreadable
// jail does not hide the bans of the others in `banned all`.
func TestGetBanRecordsListsOtherJailsWhenOneIsUnreadable(t *testing.T) {
	client, mock := clientOverMockRunner(t, "sshd", "nginx")
	mock.SetResponse("fail2ban-client get sshd banip --with-time", []byte("alice"+banListTail))
	mock.SetResponse("fail2ban-client get nginx banip --with-time", []byte("192.0.2.1"+banListTail))

	records, err := client.GetBanRecordsWithContext(context.Background(), []string{"all"})

	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "nginx", records[0].Jail)
}
