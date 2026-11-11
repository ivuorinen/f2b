package fail2ban

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseBanRecordsMarksPermanentBans pins the line fail2ban prints for
// bantime = -1: banmanager.getBanList formats "+ -1", and time2str clamps the
// end of the ban to the year 9999, which used to surface as a remaining time
// of millions of days.
func TestParseBanRecordsMarksPermanentBans(t *testing.T) {
	records, err := ParseBanRecords("192.0.2.1 \t2026-11-08 12:00:00 + -1 = 9999-12-31 23:59:59", "sshd")

	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "permanent", records[0].Remaining)
	assert.Equal(t, 2026, records[0].BannedAt.Year())
}
