package cmd

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

const (
	// DefaultLogWatchLimit is the default limit for log lines in watch mode
	DefaultLogWatchLimit = 10
)

// LogsWatchCmd returns the logs-watch command with injected client and config
func LogsWatchCmd(ctx context.Context, client fail2ban.Client, config *Config) *cobra.Command {
	var limit int
	var interval time.Duration

	cmd := NewCommand(
		"logs-watch [jail] [ip]",
		"Continuously watch Fail2Ban logs (filtered by jail and/or IP)",
		nil,
		func(_ *cobra.Command, args []string) error {
			// Parse optional arguments
			parsedArgs := ParseOptionalArgs(args, 2)
			jail := parsedArgs[0]
			ip := parsedArgs[1]

			// Use memory-efficient approach with configurable limits
			maxLines := limit
			if maxLines <= 0 {
				maxLines = 1000 // Default safe limit
			}

			// Get initial log lines with memory limits (with file timeout)
			prev, err := getLogLinesWithLimitAndContext(ctx, client, jail, ip, maxLines, config.FileTimeout)
			if err != nil {
				return HandleClientError(err)
			}

			prevHash := computeHash(prev)
			PrintOutput(strings.Join(prev, "\n"), config.Format)

			if interval <= 0 {
				interval = 5 * time.Second
			}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return nil
				case <-ticker.C:
					curr, err := getLogLinesWithLimitAndContext(ctx, client, jail, ip, maxLines, config.FileTimeout)
					if err != nil {
						return HandleClientError(err)
					}

					currHash := computeHash(curr)
					if prevHash != currHash {
						PrintOutput(strings.Join(curr, "\n"), config.Format)
						prevHash = currHash
					}
				}
			}
		})

	cmd.Flags().IntVarP(&limit, "limit", "n", DefaultLogWatchLimit, "Number of log lines to show/tail")
	cmd.Flags().
		DurationVarP(&interval, "interval", "i", DefaultPollingInterval, "Polling interval for checking new logs")
	return cmd
}

// getLogLinesWithLimitAndContext tries to use the new memory-efficient method with timeout context,
// otherwise falls back to the standard method with post-processing limits
func getLogLinesWithLimitAndContext(
	ctx context.Context,
	client fail2ban.Client,
	jail, ip string,
	maxLines int,
	timeout time.Duration,
) ([]string, error) {
	// Create timeout context for this specific operation
	logCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Try to use the new method if it's available (RealClient has GetLogLinesWithLimit)
	if realClient, ok := client.(*fail2ban.RealClient); ok {
		return realClient.GetLogLinesWithLimit(jail, ip, maxLines)
	}

	// Fallback to standard method with timeout context and post-processing limit
	lines, err := client.GetLogLinesWithContext(logCtx, jail, ip)
	if err != nil {
		return nil, err
	}

	// Apply limit after the fact for other client implementations
	if maxLines > 0 && len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}

	return lines, nil
}

// computeHash computes a SHA256 hash of the log lines for efficient comparison
func computeHash(lines []string) string {
	if len(lines) == 0 {
		return ""
	}

	h := sha256.New()
	for _, line := range lines {
		h.Write([]byte(line))
		h.Write([]byte("\n"))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
