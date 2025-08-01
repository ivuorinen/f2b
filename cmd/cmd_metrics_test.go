package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/ivuorinen/f2b/fail2ban"
)

func TestMetricsCommand(t *testing.T) {
	// Setup
	_, cleanup := fail2ban.SetupMockEnvironmentWithSudo(t, true)
	defer cleanup()

	// Set global metrics for testing
	metrics := NewMetrics()
	// Simulate some metrics
	metrics.RecordCommandExecution("ban", 50*time.Millisecond, true)
	metrics.RecordCommandExecution("ban", 100*time.Millisecond, false)
	metrics.RecordBanOperation("ban", 50*time.Millisecond, true)
	metrics.RecordBanOperation("unban", 30*time.Millisecond, true)
	metrics.RecordClientOperation("list-jails", 20*time.Millisecond, true)
	metrics.RecordValidationCacheHit()
	metrics.RecordValidationCacheMiss()
	metrics.UpdateMemoryUsage(10 * 1024 * 1024) // 10MB
	metrics.UpdateGoroutineCount(5)
	SetGlobalMetrics(metrics)

	tests := []struct {
		name       string
		args       []string
		format     string
		wantError  bool
		wantOutput []string
	}{
		{
			name:      "show metrics in plain format",
			args:      []string{"metrics"},
			format:    "plain",
			wantError: false,
			wantOutput: []string{
				"F2B Performance Metrics",
				"System:",
				"Commands:",
				"Total Executions: 2",
				"Total Failures: 1",
				"Ban Operations:",
				"Ban Operations: 1 (failures: 0)",
				"Unban Operations: 1 (failures: 0)",
				"Client Operations:",
				"Total Operations: 1",
				"Validation:",
				"Cache Hits: 1",
				"Cache Misses: 1",
			},
		},
		{
			name:      "show metrics in JSON format",
			args:      []string{"metrics", "--format=json"},
			format:    "json",
			wantError: false,
			wantOutput: []string{
				`"command_executions": 2`,
				`"command_failures": 1`,
				`"ban_operations": 1`,
				`"unban_operations": 1`,
				`"client_operations": 1`,
				`"validation_cache_hits": 1`,
				`"validation_cache_miss": 1`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockClient()
			setMockJails(mock, []string{"sshd", "apache"})

			// Execute command
			output, err := executeCommand(mock, tt.args...)

			// Check error
			if (err != nil) != tt.wantError {
				t.Errorf("MetricsCmd() error = %v, wantError %v", err, tt.wantError)
				return
			}

			// Check output
			for _, want := range tt.wantOutput {
				if !strings.Contains(output, want) {
					t.Errorf("MetricsCmd() output missing %q\nGot: %s", want, output)
				}
			}
		})
	}
}
