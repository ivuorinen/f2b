package cmd

import (
	"context"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// bannedClient is the subset of the client used by the banned command.
type bannedClient interface {
	GetBanRecordsWithContext(context.Context, []string) ([]fail2ban.BanRecord, error)
	ListJailsWithContext(context.Context) ([]string, error)
}

// BannedCmd returns the banned command with injected client and config
func BannedCmd(client bannedClient, config *Config) *cobra.Command {
	if client == nil {
		panic("client cannot be nil")
	}
	return NewCommand(
		"banned [all|<jail>]",
		"List banned IPs with remaining time",
		nil,
		func(cmd *cobra.Command, args []string) error {
			ctx, cancel := createTimeoutContext(cmd.Context(), config)
			defer cancel()

			target, err := resolveBannedJail(ctx, client, args)
			if err != nil {
				return err
			}

			// "all" fans out over every jail, so it gets the multi-jail budget
			// (derived from cmd.Context(), not from the CommandTimeout context,
			// which it cannot outlive): under CommandTimeout alone a host with
			// many jails always failed with "context deadline exceeded".
			recordsCtx := ctx
			if target == constants.AllFilter {
				parallelCtx, parallelCancel := context.WithTimeout(cmd.Context(), config.ParallelTimeout)
				defer parallelCancel()
				recordsCtx = parallelCtx
			}

			records, err := client.GetBanRecordsWithContext(recordsCtx, []string{target})
			if err != nil {
				return HandleClientError(err)
			}

			return printBanRecords(cmd, records, config.Format)
		})
}

// resolveBannedJail resolves the jail to query. Jail names are case-sensitive,
// so the argument is kept verbatim; only the special "all" selector is matched
// case-insensitively. A specific jail is validated and confirmed to exist (a
// typo'd jail would otherwise be indistinguishable from "no bans" because
// GetBanRecords swallows per-jail failures). Returned errors are already
// wrapped for the user.
func resolveBannedJail(ctx context.Context, client bannedClient, args []string) (string, error) {
	target := constants.AllFilter
	if len(args) > 0 && !strings.EqualFold(args[0], constants.AllFilter) {
		target = args[0]
	}
	if target == constants.AllFilter {
		return target, nil
	}

	if err := fail2ban.ValidateJail(target); err != nil {
		return "", HandleValidationError(err)
	}
	jails, err := client.ListJailsWithContext(ctx)
	if err != nil {
		return "", HandleClientError(err)
	}
	if !slices.Contains(jails, target) {
		return "", HandleClientError(fail2ban.NewJailNotFoundError(target))
	}
	return target, nil
}

// printBanRecords writes ban records in the requested format. Plain output is
// built in memory and written once: one unbuffered write per record made a
// large ban list cost one write(2) per banned IP.
func printBanRecords(cmd *cobra.Command, records []fail2ban.BanRecord, format string) error {
	if format == JSONFormat {
		return PrintOutputTo(GetCmdOutput(cmd), records, format)
	}
	if len(records) == 0 {
		return nil
	}
	var b strings.Builder
	for i, r := range records {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(r.Jail + " | " + r.IP + " | " + r.Remaining + " remaining")
	}
	return PrintOutputTo(GetCmdOutput(cmd), b.String(), format)
}
