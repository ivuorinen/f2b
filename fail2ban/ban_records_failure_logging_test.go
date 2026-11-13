package fail2ban_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBanRecordRunnerFailureIsReportedOnce pins that a jail whose ban list
// cannot be read is reported through the returned error only: the command
// prints that error, and a warning logged beside it repeated the failure.
func TestBanRecordRunnerFailureIsReportedOnce(t *testing.T) {
	client, mock := clientOverMockRunner(t, "sshd")
	mock.SetError("fail2ban-client get sshd banip --with-time", errSocketRefused)
	buf := captureLog(t, slog.LevelDebug)

	records, err := client.GetBanRecordsWithContext(context.Background(), []string{"sshd"})

	require.ErrorIs(t, err, errSocketRefused)
	assert.ErrorContains(t, err, "jail sshd")
	assert.Empty(t, records)
	assert.NotContains(t, buf.String(), "socket refused", "the failure is not logged beside the returned error")
}

// TestBanRecordPartialFailureIsStillLogged pins that when only some jails
// fail, the failure is still logged: the records of the others are returned
// with no error to carry it.
func TestBanRecordPartialFailureIsStillLogged(t *testing.T) {
	client, mock := clientOverMockRunner(t, "sshd", "nginx")
	mock.SetError("fail2ban-client get sshd banip --with-time", errSocketRefused)
	mock.SetResponse("fail2ban-client get nginx banip --with-time",
		[]byte("192.0.2.1 2030-01-01 10:00:00 + 600 = 2030-01-01 10:10:00"))
	buf := captureLog(t, slog.LevelDebug)

	records, err := client.GetBanRecordsWithContext(context.Background(), nil)

	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "nginx", records[0].Jail)
	assert.Contains(t, buf.String(), "some jails failed during parallel ban record retrieval")
	assert.Contains(t, buf.String(), "socket refused")
}
