package cmd

import (
	"fmt"
	"strings"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/spf13/cobra"
)

// List of ban results for JSON output
// BanResult represents the result of a ban operation for output.
type BanResult struct {
	IP     string `json:"ip"`
	Jail   string `json:"jail"`
	Status string `json:"status"`
}

// BanCmd returns the ban command with injected client and config
func BanCmd(client fail2ban.Client, config *Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ban <ip> [jail]",
		Short:   "Ban an IP address",
		Aliases: []string{"banip", "b"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				PrintError(fmt.Errorf("IP address required"))
				return fmt.Errorf("IP address required")
			}
			ip := args[0]
			var jails []string
			if len(args) > 1 {
				jails = []string{strings.ToLower(args[1])}
			} else {
				var err error
				jails, err = client.ListJails()
				if err != nil {
					PrintError(err)
					return err
				}
			}
			var results []BanResult
			for _, jail := range jails {
				code, err := client.BanIP(ip, jail)
				if err != nil {
					PrintError(err)
					return err
				}
				status := "Banned"
				if code == 1 {
					status = "Already banned"
				}
				Logger.WithFields(map[string]interface{}{
					"ip":     ip,
					"jail":   jail,
					"status": status,
				}).Info("Ban result")
				results = append(results, BanResult{IP: ip, Jail: jail, Status: status})
			}
			// Output results
			if config != nil && config.Format == JSONFormat {
				PrintOutputTo(GetCmdOutput(cmd), results, JSONFormat)
			} else {
				for _, r := range results {
					if _, err := fmt.Fprintf(GetCmdOutput(cmd), "%s %s in %s\n", r.Status, r.IP, r.Jail); err != nil {
						return err
					}
				}
			}
			return nil
		},
	}
	// Read the format flag and override config.Format if set
	format, _ := cmd.Flags().GetString("format")
	if format != "" {
		config.Format = format
	}
	// Output results
	if (config != nil && config.Format == JSONFormat) || format == JSONFormat {
		// existing JSON output logic...
	} else {
		// existing plain output logic...
	}
	return cmd
}
