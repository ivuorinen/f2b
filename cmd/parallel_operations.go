package cmd

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"time"

	"github.com/ivuorinen/f2b/fail2ban"
)

// ProcessBanOperationParallelWithContext bans ip across multiple jails concurrently.
func ProcessBanOperationParallelWithContext(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
) ([]OperationResult, error) {
	return processJailsParallel(ctx, client, ip, jails, BanOperationType)
}

// ProcessUnbanOperationParallelWithContext unbans ip across multiple jails concurrently.
func ProcessUnbanOperationParallelWithContext(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
) ([]OperationResult, error) {
	return processJailsParallel(ctx, client, ip, jails, UnbanOperationType)
}

// processJailsParallel runs opType's per-jail operation against every jail
// concurrently, bounded to runtime.NumCPU() goroutines, returning the per-jail
// results in jail order. Zero or one jail takes the sequential path to skip the
// goroutine setup and keep the fail-fast single-jail semantics.
//
// Inputs are not re-validated here: the command path validates the IP and
// every jail in processWithValidation, and the client validates them again
// before running fail2ban-client.
func processJailsParallel(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
	opType OperationType,
) ([]OperationResult, error) {
	if len(jails) <= 1 {
		return ProcessOperationWithContext(ctx, client, ip, jails, opType)
	}

	results := make([]OperationResult, len(jails))
	errs := make([]error, len(jails))
	logger := GetContextualLogger()
	sem := make(chan struct{}, min(len(jails), runtime.NumCPU()))
	var wg sync.WaitGroup

	for i, jail := range jails {
		sem <- struct{}{} // bound in-flight goroutines to the worker limit
		wg.Go(func() {
			defer func() { <-sem }()
			results[i], errs[i] = runJailOperation(ctx, client, ip, jail, opType, logger)
		})
	}
	wg.Wait()

	return results, joinOperationErrors(errs)
}

// runJailOperation executes a single per-jail operation under its own
// CommandTimeout and records the structured ban audit log with its duration,
// so a multi-jail run is as observable as a single-jail one.
func runJailOperation(
	ctx context.Context,
	client fail2ban.Client,
	ip, jail string,
	opType OperationType,
	logger *ContextualLogger,
) (OperationResult, error) {
	// Stop before spawning a doomed fail2ban-client invocation once the run is
	// canceled; surface the context error as this jail's status.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return OperationResult{IP: ip, Jail: jail, Status: ctxErr.Error()}, ctxErr
	}

	jailCtx := fail2ban.WithJail(ctx, jail)
	// Per-jail CommandTimeout: without it one hung invocation stalls for the
	// whole ParallelTimeout, while single-jail runs are capped at CommandTimeout.
	opCtx, opCancel := createTimeoutContext(jailCtx, &cfg)
	start := time.Now()
	code, err := opType.OperationCtx(opCtx, client, ip, jail)
	opCancel()
	logger.LogBanOperation(jailCtx, opType.Operation, ip, jail, err == nil, time.Since(start))

	status := InterpretBanStatus(code, opType.Operation)
	if err != nil {
		status = err.Error()
	}
	return OperationResult{IP: ip, Jail: jail, Status: status}, err
}

// joinOperationErrors collapses the per-jail errors into one, deduping the
// repeated context error a canceled run produces for every unprocessed jail so
// the user doesn't see "context canceled" N times.
func joinOperationErrors(errs []error) error {
	var out []error
	var ctxErr error
	for _, err := range errs {
		switch {
		case err == nil:
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			ctxErr = err
		default:
			out = append(out, err)
		}
	}
	if ctxErr != nil {
		out = append(out, ctxErr)
	}
	return errors.Join(out...)
}
