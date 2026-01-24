// Package cmd provides concrete implementations of IP operation processors.
// This module contains the specific processors for ban and unban operations
// that implement the IPOperationProcessor interface.
package cmd

import (
	"context"

	"github.com/ivuorinen/f2b/fail2ban"
)

// validateIPAndJails validates an IP address and a list of jail names.
// Returns an error if any validation fails.
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

// BanProcessor handles ban operations
type BanProcessor struct{}

// ProcessSingle processes a ban operation for a single jail
func (p *BanProcessor) ProcessSingle(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
) ([]OperationResult, error) {
	if err := validateIPAndJails(ip, jails); err != nil {
		return nil, err
	}
	return ProcessBanOperationWithContext(ctx, client, ip, jails)
}

// ProcessParallel processes ban operations for multiple jails in parallel
func (p *BanProcessor) ProcessParallel(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
) ([]OperationResult, error) {
	if err := validateIPAndJails(ip, jails); err != nil {
		return nil, err
	}
	return ProcessBanOperationParallelWithContext(ctx, client, ip, jails)
}

// UnbanProcessor handles unban operations
type UnbanProcessor struct{}

// ProcessSingle processes an unban operation for a single jail
func (p *UnbanProcessor) ProcessSingle(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
) ([]OperationResult, error) {
	if err := validateIPAndJails(ip, jails); err != nil {
		return nil, err
	}
	return ProcessUnbanOperationWithContext(ctx, client, ip, jails)
}

// ProcessParallel processes unban operations for multiple jails in parallel
func (p *UnbanProcessor) ProcessParallel(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
) ([]OperationResult, error) {
	if err := validateIPAndJails(ip, jails); err != nil {
		return nil, err
	}
	return ProcessUnbanOperationParallelWithContext(ctx, client, ip, jails)
}
