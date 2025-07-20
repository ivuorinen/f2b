package cmd

import (
	"fmt"
	"strings"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/spf13/cobra"
)

// TestFilterCmd returns the test-filter command with injected client and config
func TestFilterCmd(client fail2ban.Client, config *Config) *cobra.Command {
	return NewCommand("test-filter <filter>", "Test a Fail2Ban filter", nil, func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			filters, err := client.ListFilters()
			if err != nil {
				return HandleClientError(err)
			}
			PrintOutputTo(GetCmdOutput(cmd), "Available filters: "+strings.Join(filters, ", "), config.Format)
			return PrintErrorAndReturn(fmt.Errorf("filter name required"))
		}

		filterName := strings.ToLower(args[0])
		if err := RequireNonEmptyArgument(filterName, "filter name"); err != nil {
			return PrintErrorAndReturn(err)
		}

		out, err := client.TestFilter(filterName)
		if err != nil {
			return HandleClientError(err)
		}

		PrintOutputTo(GetCmdOutput(cmd), out, config.Format)
		return nil
	})
}
