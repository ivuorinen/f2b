// Package cmd provides the shared validate-then-execute helper for IP
// operations (ban/unban). The per-command operation functions are wired
// directly into IPCommandConfig; no processor abstraction is needed.
package cmd

import (
	"context"

	"github.com/ivuorinen/f2b/fail2ban"
)

// multiJailOperationFunc defines the signature for IP operation functions that process multiple jails
type multiJailOperationFunc func(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
) ([]OperationResult, error)

// validateIPAndJails validates an IP address and a list of jail names,
// returning an error if any validation fails.
func validateIPAndJails(ip string, jails []string) error {
	if err := fail2ban.ValidateIP(ip); err != nil {
		return err
	}
	for _, jail := range jails {
		if err := fail2ban.ValidateJail(jail); err != nil {
			return err
		}
	}
	return nil
}

// processWithValidation validates inputs and executes the provided operation function.
// This consolidates the common validation-then-execute pattern.
func processWithValidation(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
	opFunc multiJailOperationFunc,
) ([]OperationResult, error) {
	if err := validateIPAndJails(ip, jails); err != nil {
		return nil, err
	}
	return opFunc(ctx, client, ip, jails)
}
