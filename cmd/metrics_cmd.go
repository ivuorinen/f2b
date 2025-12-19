package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/shared"
)

// MetricsCmd returns the metrics command with injected client and config
func MetricsCmd(_ fail2ban.Client, config *Config) *cobra.Command {
	return NewCommand(
		"metrics",
		"Show performance metrics",
		[]string{"stats"},
		func(cmd *cobra.Command, _ []string) error {
			// Get the global metrics instance
			metrics := GetGlobalMetrics()
			snapshot := metrics.GetSnapshot()

			// Output metrics based on format
			if config != nil && config.Format == JSONFormat {
				encoder := json.NewEncoder(GetCmdOutput(cmd))
				encoder.SetIndent("", "  ")
				if err := encoder.Encode(snapshot); err != nil {
					return fmt.Errorf("failed to encode metrics: %w", err)
				}
			} else {
				// Plain text output - use a helper to simplify error handling
				if err := printMetricsPlain(GetCmdOutput(cmd), snapshot); err != nil {
					return fmt.Errorf("failed to print metrics: %w", err)
				}
			}

			return nil
		})
}

// printMetricsPlain prints metrics in plain text format
func printMetricsPlain(output io.Writer, snapshot MetricsSnapshot) error {
	// Use a string builder to build the output
	var sb strings.Builder

	sb.WriteString("F2B Performance Metrics\n")
	sb.WriteString("======================\n\n")

	// System metrics
	sb.WriteString("System:\n")
	sb.WriteString(fmt.Sprintf("  Uptime: %ds\n", snapshot.UptimeSeconds))
	sb.WriteString(fmt.Sprintf("  Max Memory: %.2f MB\n", float64(snapshot.MaxMemoryUsage)/(1024*1024)))
	sb.WriteString(fmt.Sprintf("  Goroutines: %d\n\n", snapshot.GoroutineCount))

	// Command metrics
	sb.WriteString("Commands:\n")
	sb.WriteString(fmt.Sprintf(shared.MetricsFmtTotalExecutions, snapshot.CommandExecutions))
	sb.WriteString(fmt.Sprintf(shared.MetricsFmtTotalFailures, snapshot.CommandFailures))
	if snapshot.CommandExecutions > 0 {
		avgLatency := float64(snapshot.CommandTotalDuration) / float64(snapshot.CommandExecutions)
		sb.WriteString(fmt.Sprintf(shared.MetricsFmtAverageLatencyTop, avgLatency))
	}
	sb.WriteString("\n")

	// Ban/Unban metrics
	sb.WriteString("Ban Operations:\n")
	sb.WriteString(fmt.Sprintf("  Ban Operations: %d (failures: %d)\n", snapshot.BanOperations, snapshot.BanFailures))
	sb.WriteString(
		fmt.Sprintf("  Unban Operations: %d (failures: %d)\n", snapshot.UnbanOperations, snapshot.UnbanFailures),
	)
	sb.WriteString("\n")

	// Client metrics
	sb.WriteString("Client Operations:\n")
	sb.WriteString(fmt.Sprintf(shared.MetricsFmtTotalOperations, snapshot.ClientOperations))
	sb.WriteString(fmt.Sprintf(shared.MetricsFmtTotalFailures, snapshot.ClientFailures))
	if snapshot.ClientOperations > 0 {
		avgLatency := float64(snapshot.ClientTotalDuration) / float64(snapshot.ClientOperations)
		sb.WriteString(fmt.Sprintf(shared.MetricsFmtAverageLatencyTop, avgLatency))
	}
	sb.WriteString("\n")

	// Validation metrics
	sb.WriteString("Validation:\n")
	sb.WriteString(fmt.Sprintf("  Cache Hits: %d\n", snapshot.ValidationCacheHits))
	sb.WriteString(fmt.Sprintf("  Cache Misses: %d\n", snapshot.ValidationCacheMiss))
	sb.WriteString(fmt.Sprintf("  Failures: %d\n", snapshot.ValidationFailures))
	if total := snapshot.ValidationCacheHits + snapshot.ValidationCacheMiss; total > 0 {
		hitRate := float64(snapshot.ValidationCacheHits) / float64(total) * 100
		sb.WriteString(fmt.Sprintf("  Cache Hit Rate: %.2f%%\n", hitRate))
	}
	sb.WriteString("\n")

	// Command latency distribution
	if len(snapshot.CommandLatencyBuckets) > 0 {
		sb.WriteString("Command Latency Distribution:\n")
		for cmd, bucket := range snapshot.CommandLatencyBuckets {
			sb.WriteString(fmt.Sprintf(shared.MetricsFmtOperationHeader, cmd))
			sb.WriteString(fmt.Sprintf(shared.MetricsFmtLatencyUnder1ms, bucket.Under1ms))
			sb.WriteString(fmt.Sprintf(shared.MetricsFmtLatencyUnder10ms, bucket.Under10ms))
			sb.WriteString(fmt.Sprintf(shared.MetricsFmtLatencyUnder100ms, bucket.Under100ms))
			sb.WriteString(fmt.Sprintf(shared.MetricsFmtLatencyUnder1s, bucket.Under1s))
			sb.WriteString(fmt.Sprintf(shared.MetricsFmtLatencyUnder10s, bucket.Under10s))
			sb.WriteString(fmt.Sprintf(shared.MetricsFmtLatencyOver10s, bucket.Over10s))
			sb.WriteString(fmt.Sprintf(shared.MetricsFmtAverageLatency, bucket.GetAverageLatency()))
		}
		sb.WriteString("\n")
	}

	// Client latency distribution
	if len(snapshot.ClientLatencyBuckets) > 0 {
		sb.WriteString("Client Operation Latency Distribution:\n")
		for op, bucket := range snapshot.ClientLatencyBuckets {
			sb.WriteString(fmt.Sprintf(shared.MetricsFmtOperationHeader, op))
			sb.WriteString(fmt.Sprintf(shared.MetricsFmtLatencyUnder1ms, bucket.Under1ms))
			sb.WriteString(fmt.Sprintf(shared.MetricsFmtLatencyUnder10ms, bucket.Under10ms))
			sb.WriteString(fmt.Sprintf(shared.MetricsFmtLatencyUnder100ms, bucket.Under100ms))
			sb.WriteString(fmt.Sprintf(shared.MetricsFmtLatencyUnder1s, bucket.Under1s))
			sb.WriteString(fmt.Sprintf(shared.MetricsFmtLatencyUnder10s, bucket.Under10s))
			sb.WriteString(fmt.Sprintf(shared.MetricsFmtLatencyOver10s, bucket.Over10s))
			sb.WriteString(fmt.Sprintf(shared.MetricsFmtAverageLatency, bucket.GetAverageLatency()))
		}
	}

	// Write the entire string at once
	_, err := output.Write([]byte(sb.String()))
	return err
}
