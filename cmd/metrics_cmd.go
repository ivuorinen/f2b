package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
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
	fmt.Fprintf(&sb, "  Uptime: %ds\n", snapshot.UptimeSeconds)
	fmt.Fprintf(&sb, "  Max Memory: %.2f MB\n", float64(snapshot.MaxMemoryUsage)/(1024*1024))
	fmt.Fprintf(&sb, "  Goroutines: %d\n\n", snapshot.GoroutineCount)

	// Command metrics
	sb.WriteString("Commands:\n")
	fmt.Fprintf(&sb, shared.MetricsFmtTotalExecutions, snapshot.CommandExecutions)
	fmt.Fprintf(&sb, shared.MetricsFmtTotalFailures, snapshot.CommandFailures)
	if snapshot.CommandExecutions > 0 {
		avgLatency := float64(snapshot.CommandTotalDuration) / float64(snapshot.CommandExecutions)
		fmt.Fprintf(&sb, shared.MetricsFmtAverageLatencyTop, avgLatency)
	}
	sb.WriteString("\n")

	// Ban/Unban metrics
	sb.WriteString("Ban Operations:\n")
	fmt.Fprintf(&sb, "  Ban Operations: %d (failures: %d)\n", snapshot.BanOperations, snapshot.BanFailures)
	fmt.Fprintf(&sb, "  Unban Operations: %d (failures: %d)\n", snapshot.UnbanOperations, snapshot.UnbanFailures)
	sb.WriteString("\n")

	// Client metrics
	sb.WriteString("Client Operations:\n")
	fmt.Fprintf(&sb, shared.MetricsFmtTotalOperations, snapshot.ClientOperations)
	fmt.Fprintf(&sb, shared.MetricsFmtTotalFailures, snapshot.ClientFailures)
	if snapshot.ClientOperations > 0 {
		avgLatency := float64(snapshot.ClientTotalDuration) / float64(snapshot.ClientOperations)
		fmt.Fprintf(&sb, shared.MetricsFmtAverageLatencyTop, avgLatency)
	}
	sb.WriteString("\n")

	// Validation metrics
	sb.WriteString("Validation:\n")
	fmt.Fprintf(&sb, "  Cache Hits: %d\n", snapshot.ValidationCacheHits)
	fmt.Fprintf(&sb, "  Cache Misses: %d\n", snapshot.ValidationCacheMiss)
	fmt.Fprintf(&sb, "  Failures: %d\n", snapshot.ValidationFailures)
	if total := snapshot.ValidationCacheHits + snapshot.ValidationCacheMiss; total > 0 {
		hitRate := float64(snapshot.ValidationCacheHits) / float64(total) * 100
		fmt.Fprintf(&sb, "  Cache Hit Rate: %.2f%%\n", hitRate)
	}
	sb.WriteString("\n")

	// Command latency distribution
	if len(snapshot.CommandLatencyBuckets) > 0 {
		sb.WriteString("Command Latency Distribution:\n")
		formatLatencyBuckets(&sb, snapshot.CommandLatencyBuckets)
		sb.WriteString("\n")
	}

	// Client latency distribution
	if len(snapshot.ClientLatencyBuckets) > 0 {
		sb.WriteString("Client Operation Latency Distribution:\n")
		formatLatencyBuckets(&sb, snapshot.ClientLatencyBuckets)
	}

	// Write the entire string at once
	_, err := output.Write([]byte(sb.String()))
	return err
}

// formatLatencyBuckets writes latency bucket distribution to the builder.
// Keys are sorted for deterministic output.
func formatLatencyBuckets(sb *strings.Builder, buckets map[string]LatencyBucketSnapshot) {
	// Sort keys for deterministic output
	keys := make([]string, 0, len(buckets))
	for name := range buckets {
		keys = append(keys, name)
	}
	sort.Strings(keys)

	for _, name := range keys {
		bucket := buckets[name]
		fmt.Fprintf(sb, shared.MetricsFmtOperationHeader, name)
		fmt.Fprintf(sb, shared.MetricsFmtLatencyUnder1ms, bucket.Under1ms)
		fmt.Fprintf(sb, shared.MetricsFmtLatencyUnder10ms, bucket.Under10ms)
		fmt.Fprintf(sb, shared.MetricsFmtLatencyUnder100ms, bucket.Under100ms)
		fmt.Fprintf(sb, shared.MetricsFmtLatencyUnder1s, bucket.Under1s)
		fmt.Fprintf(sb, shared.MetricsFmtLatencyUnder10s, bucket.Under10s)
		fmt.Fprintf(sb, shared.MetricsFmtLatencyOver10s, bucket.Over10s)
		fmt.Fprintf(sb, shared.MetricsFmtAverageLatency, bucket.GetAverageLatency())
	}
}
