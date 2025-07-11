package cmd

import (
	"context"
	"strings"
	"time"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/spf13/cobra"
)

// LogsWatchCmd returns the logs-watch command with injected client and config
func LogsWatchCmd(ctx context.Context, client fail2ban.Client, config *Config) *cobra.Command {
	var limit int
	var interval time.Duration
	cmd := &cobra.Command{
		Use:   "logs-watch [jail] [ip]",
		Short: "Continuously watch Fail2Ban logs (filtered by jail and/or IP)",
		RunE: func(cmd *cobra.Command, args []string) error {
			jail := ""
			ip := ""
			if len(args) > 0 {
				jail = args[0]
			}
			if len(args) > 1 {
				ip = args[1]
			}
			prev, err := client.GetLogLines(jail, ip)
			if err != nil {
				PrintError(err)
				return err
			}
			if limit > 0 && len(prev) > limit {
				prev = prev[len(prev)-limit:]
			}
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
					curr, err := client.GetLogLines(jail, ip)
					if err != nil {
						PrintError(err)
						return err
					}
					if limit > 0 && len(curr) > limit {
						curr = curr[len(curr)-limit:]
					}
					if !equal(prev, curr) {
						PrintOutput(strings.Join(curr, "\n"), config.Format)
						prev = curr
					}
				}
			}
		},
	}
	cmd.Flags().IntVarP(&limit, "limit", "n", 10, "Number of log lines to show/tail")
	cmd.Flags().DurationVarP(&interval, "interval", "i", 5*time.Second, "Polling interval for checking new logs")
	return cmd
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
