package cmd

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/ivuorinen/f2b/fail2ban"
)

// deadlineRecordingClient is a bannedClient that records the deadline of the
// context its ban-record query runs under.
type deadlineRecordingClient struct {
	records  []fail2ban.BanRecord
	deadline time.Time
}

func (c *deadlineRecordingClient) GetBanRecordsWithContext(
	ctx context.Context,
	_ []string,
) ([]fail2ban.BanRecord, error) {
	c.deadline, _ = ctx.Deadline()
	return c.records, nil
}

func (c *deadlineRecordingClient) ListJailsWithContext(context.Context) ([]string, error) {
	return []string{"sshd"}, nil
}

// TestBannedAllUsesParallelTimeout pins the multi-jail budget: `banned all`
// fans out over every jail, and under CommandTimeout alone a host with many
// jails always ended in "context deadline exceeded".
func TestBannedAllUsesParallelTimeout(t *testing.T) {
	config := &Config{Format: PlainFormat, CommandTimeout: time.Second, ParallelTimeout: time.Hour}
	tests := []struct {
		args     []string
		minLeft  time.Duration
		maxLeft  time.Duration
		scenario string
	}{
		{args: nil, minLeft: 30 * time.Minute, maxLeft: time.Hour + time.Second, scenario: "all gets ParallelTimeout"},
		{args: []string{"sshd"}, minLeft: 0, maxLeft: 2 * time.Second, scenario: "one jail keeps CommandTimeout"},
	}
	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			client := &deadlineRecordingClient{}
			cmd := BannedCmd(client, config)
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetArgs(tt.args)
			start := time.Now()
			if err := cmd.Execute(); err != nil {
				t.Fatalf("banned failed: %v", err)
			}
			left := client.deadline.Sub(start)
			if client.deadline.IsZero() || left < tt.minLeft || left > tt.maxLeft {
				t.Errorf("records query budget = %v, want between %v and %v", left, tt.minLeft, tt.maxLeft)
			}
		})
	}
}

// countingWriter counts Write calls.
type countingWriter struct {
	bytes.Buffer
	writes int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.writes++
	return w.Buffer.Write(p)
}

// TestBannedPlainOutputIsOneWrite pins that plain ban records are written in a
// single write: one unbuffered write per record cost one write(2) per banned IP.
func TestBannedPlainOutputIsOneWrite(t *testing.T) {
	client := &deadlineRecordingClient{records: []fail2ban.BanRecord{
		{Jail: "sshd", IP: "192.168.1.1", Remaining: "00:01:00:00"},
		{Jail: "sshd", IP: "192.168.1.2", Remaining: "00:02:00:00"},
		{Jail: "apache", IP: "10.0.0.1", Remaining: "00:03:00:00"},
	}}
	out := &countingWriter{}
	cmd := BannedCmd(client, &Config{Format: PlainFormat, CommandTimeout: time.Second, ParallelTimeout: time.Second})
	cmd.SetOut(out)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("banned failed: %v", err)
	}

	want := "sshd | 192.168.1.1 | 00:01:00:00 remaining\n" +
		"sshd | 192.168.1.2 | 00:02:00:00 remaining\n" +
		"apache | 10.0.0.1 | 00:03:00:00 remaining\n"
	if out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
	if out.writes != 1 {
		t.Errorf("writes = %d, want 1", out.writes)
	}
}
