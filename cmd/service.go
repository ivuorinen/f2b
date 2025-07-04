package cmd

import (
	"fmt"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/spf13/cobra"
)

// ServiceCmd returns the service command with injected config
func ServiceCmd(config *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "service [start|stop|restart|status]",
		Short: "Manage the Fail2Ban service",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				PrintError(fmt.Errorf("action required: start|stop|restart|status"))
				return nil
			}
			action := args[0]
			out, err := fail2ban.RunnerCombinedOutputWithSudo("service", "fail2ban", action)
			if err != nil {
				PrintError(err)
				return err
			}
			PrintOutput(string(out), config.Format)
			return nil
		},
	}
}
