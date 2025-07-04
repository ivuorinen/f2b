package cmd

import (
	"fmt"
	"strings"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/spf13/cobra"
)

// TestFilterCmd returns the test-filter command with injected client and config
func TestFilterCmd(client fail2ban.Client, config *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "test-filter <filter>",
		Short: "Test a Fail2Ban filter",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				filters, err := client.ListFilters()
				if err != nil {
					PrintError(err)
					return err
				}
				PrintOutputTo(GetCmdOutput(cmd), "Available filters: "+strings.Join(filters, ", "), config.Format)
				PrintError(fmt.Errorf("filter name required"))
				return fmt.Errorf("filter name required")
			}
			out, err := client.TestFilter(strings.ToLower(args[0]))
			if err != nil {
				PrintError(err)
				return err
			}
			PrintOutputTo(GetCmdOutput(cmd), out, config.Format)
			return nil
		},
	}
}
