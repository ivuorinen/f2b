package fail2ban_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// TestRemainingBanTimeComesFromTheBanDuration pins that the remaining time of
// an "IP date time + SECS = date time" record is the ban time plus SECS. The
// end timestamp carries no zone, so during a DST fall-back hour it reads an
// hour early; this record's end is an hour short of ban time + SECS, as that
// misreading produces, and an active ban must not show as expired.
func TestRemainingBanTimeComesFromTheBanDuration(t *testing.T) {
	bannedAt := time.Now().Add(-10 * time.Minute)
	misreadEnd := bannedAt.Add(10 * time.Minute)
	line := fmt.Sprintf("192.0.2.1 \t%s + 3600 = %s",
		bannedAt.Format(constants.TimeFormat), misreadEnd.Format(constants.TimeFormat))

	records, err := fail2ban.ParseBanRecords(line, "sshd")

	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Contains(t, []string{"00:00:50:00", "00:00:49:59"}, records[0].Remaining,
		"50 minutes of the hour-long ban are left")
}

// TestBanDurationThatIsNotANumberMakesTheRecordUnreadable pins that the
// 8-field layout's SECS must be a whole number of seconds: it is what the
// remaining time is computed from.
func TestBanDurationThatIsNotANumberMakesTheRecordUnreadable(t *testing.T) {
	for _, secs := range []string{"abc", "-5", "1.5"} {
		t.Run(secs, func(t *testing.T) {
			line := "192.0.2.1 \t2026-11-01 00:50:00 + " + secs + " = 2026-11-01 01:20:00"

			records, err := fail2ban.ParseBanRecords(line, "sshd")

			require.Error(t, err)
			assert.Empty(t, records)
		})
	}
}
