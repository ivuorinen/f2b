package cmd

import (
	"context"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/ivuorinen/f2b/constants"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// LogsWatchCmd returns the logs-watch command with injected client and config
func LogsWatchCmd(ctx context.Context, client fail2ban.Client, config *Config) *cobra.Command {
	var limit int
	var interval time.Duration

	cmd := NewCommand(
		"logs-watch [jail] [ip]",
		"Continuously watch Fail2Ban logs (filtered by jail and/or IP)",
		nil,
		func(cobraCmd *cobra.Command, args []string) error {
			// Prefer the command's context (canceled on SIGINT/SIGTERM via
			// ExecuteContext) so Ctrl-C exits the watch loop gracefully. Fall
			// back to the construction-time context if none is set.
			watchCtx := cobraCmd.Context()
			if watchCtx == nil {
				watchCtx = ctx
			}

			// Parse optional arguments
			parsedArgs := ParseOptionalArgs(args, 2)
			jail := parsedArgs[0]
			ip := parsedArgs[1]

			// Use memory-efficient approach with configurable limits
			maxLines := limit
			if maxLines <= 0 {
				maxLines = constants.DefaultLogLinesLimit // Default safe limit
			}
			// The fail2ban layer rejects limits above MaxLogLinesLimit; clamp
			// here so an oversized -n degrades gracefully instead of erroring.
			if maxLines > constants.MaxLogLinesLimit {
				Logger.WithField("limit", maxLines).
					Warnf("limit exceeds maximum, clamping to %d", constants.MaxLogLinesLimit)
				maxLines = constants.MaxLogLinesLimit
			}

			// Get initial log lines with memory limits (with file timeout)
			prev, err := getLogLinesWithLimitAndContext(watchCtx, client, jail, ip, maxLines, config.FileTimeout)
			if err != nil {
				return HandleClientError(err)
			}

			out := GetCmdOutput(cobraCmd)
			if len(prev) > 0 {
				PrintOutputTo(out, strings.Join(prev, "\n"), config.Format)
			}

			if interval <= 0 {
				interval = constants.DefaultPollingInterval
			}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			for {
				select {
				case <-watchCtx.Done():
					return nil
				case <-ticker.C:
					prev = pollLogsOnce(watchCtx, out, client, jail, ip, maxLines, config, prev)
				}
			}
		})

	cmd.Flags().IntVarP(
		&limit, constants.FlagLimit, "n", constants.DefaultLogLinesLimit, "Number of log lines to show/tail",
	)
	cmd.Flags().DurationVarP(
		&interval, constants.FlagInterval, "i", constants.DefaultPollingInterval, "Polling interval for checking new logs",
	)
	return cmd
}

// pollLogsOnce fetches the current log window and prints only the lines
// appended since prev, returning the new window to carry forward. A transient
// fetch error is logged and prev is returned unchanged so the watcher keeps
// polling instead of exiting.
func pollLogsOnce(
	ctx context.Context,
	out io.Writer,
	client fail2ban.Client,
	jail, ip string,
	maxLines int,
	config *Config,
	prev []string,
) []string {
	curr, err := getLogLinesWithLimitAndContext(ctx, client, jail, ip, maxLines, config.FileTimeout)
	if err != nil {
		Logger.WithError(err).Warn("logs-watch poll failed; continuing")
		return prev
	}
	if newLines := newTailLines(prev, curr); len(newLines) > 0 {
		PrintOutputTo(out, strings.Join(newLines, "\n"), config.Format)
	}
	return curr
}

// logLinesLimiter is the optional capability of clients that can apply the
// line limit at read time instead of post-processing (RealClient and the
// lazyClient wrapper implement it).
type logLinesLimiter interface {
	GetLogLinesWithLimitContext(ctx context.Context, jail, ip string, maxLines int) ([]string, error)
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

	// Use the read-time limit capability when the client offers it. This is a
	// capability interface, not a *RealClient assertion: production wraps the
	// real client in lazyClient, so a concrete-type assertion never matched
	// and every read fell through to the default-capped fallback below.
	if lc, ok := client.(logLinesLimiter); ok {
		return lc.GetLogLinesWithLimitContext(logCtx, jail, ip, maxLines)
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

// newTailLines returns the lines in curr that were appended since prev. Both
// are tail windows of the same file, so the new lines are those following the
// last line of prev within curr. Matching only prev's final line is not
// enough: fail2ban logs repeat identical lines, and if a freshly appended
// line equals prev's last line, the single-line match would anchor on the new
// copy and silently drop everything before it. So a candidate position must
// also match as much of prev's tail as is available before it. If no position
// matches (e.g. after log rotation), all of curr is returned.
func newTailLines(prev, curr []string) []string {
	if len(prev) == 0 {
		return curr
	}
	// Unclamped fast path: while the window hasn't hit maxLines, curr still
	// contains prev as its prefix, and the appended lines are exactly the
	// remainder. Content-based anchoring below is inherently ambiguous for
	// fully periodic logs (prev=[L,L], curr=[L,L,L] has three defensible
	// answers), so prefer the exact prefix check whenever it applies.
	if len(curr) >= len(prev) && slices.Equal(curr[:len(prev)], prev) {
		return curr[len(prev):]
	}
	// ponytail: once the window is clamped, periodic content can still be
	// over/under-reported by one period; tracking file offsets is the upgrade
	// path if that ever matters.
	last := prev[len(prev)-1]
	for i, c := range slices.Backward(curr) {
		if c != last {
			continue
		}
		overlap := min(i, len(prev)-1)
		matched := true
		for k := 1; k <= overlap; k++ {
			if curr[i-k] != prev[len(prev)-1-k] {
				matched = false
				break
			}
		}
		if matched {
			return curr[i+1:]
		}
	}
	return curr
}
