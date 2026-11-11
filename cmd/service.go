package cmd

import (
	"context"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// ServiceCmd returns the service command with injected runner and config
func ServiceCmd(runner fail2ban.Runner, config *Config) *cobra.Command {
	actions := strings.Join(serviceActions, "|")
	return withArgs(cobra.MaximumNArgs(1), NewCommand(
		"service ["+actions+"]",
		"Manage the Fail2Ban service",
		nil,
		func(cmd *cobra.Command, args []string) error {
			// Validate service action argument
			if err := RequireArguments(args, 1, "action required: "+actions); err != nil {
				return HandleValidationError(err)
			}

			action := args[0]
			if err := ValidateServiceAction(action); err != nil {
				return HandleValidationError(err)
			}

			// A restart can legitimately outlast the per-command default, so
			// CommandTimeout is not applied; the ceiling keeps a hung service
			// manager from blocking an unattended run forever.
			ctx, cancel := context.WithTimeout(cmd.Context(), constants.MaxCommandTimeout)
			defer cancel()

			// enable/disable are systemd concepts that service(8) does not
			// forward to systemctl, so invoke systemctl directly for them.
			// The runner folds the command's own diagnostic output into a
			// failure's error, so it is not appended again here.
			name, serviceArgs := constants.ServiceCommand, []string{constants.ServiceFail2ban, action}
			if action == "enable" || action == "disable" {
				name, serviceArgs = "systemctl", []string{action, constants.ServiceFail2ban}
			}
			timer := fail2ban.NewTimedOperation("service", name, serviceArgs...)
			out, err := runner.CombinedOutputWithSudoContext(ctx, name, serviceArgs...)
			timer.FinishWithContext(ctx, err)
			if err != nil {
				Logger.WithField("action", action).WithError(err).Error("Service action failed")
				return HandleSystemError(err)
			}

			// A privileged state change (stop/disable/restart) must leave an
			// audit record like ban/unban do, not only stdout output.
			Logger.WithField("action", action).Info("Service action completed")
			return PrintOutput(string(out), config.Format)
		}))
}
