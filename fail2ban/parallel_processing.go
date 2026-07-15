package fail2ban

import (
	"context"
	"errors"
	"runtime"
	"sync"
)

// ProcessJailsParallel retrieves ban records for multiple jails concurrently,
// bounded to runtime.NumCPU() goroutines, and concatenates them. A single jail
// runs inline to skip the goroutine setup.
//
// Error handling: a canceled run surfaces the context error rather than a
// silently truncated result set. If every jail fails, the joined per-jail error
// is returned instead of an empty slice with nil error (which is
// indistinguishable from "no bans"). A mix of successes and failures is a valid
// partial result: the records are returned and the failures are logged so they
// are not silently dropped.
func ProcessJailsParallel(
	ctx context.Context,
	jails []string,
	workFunc func(ctx context.Context, jail string) ([]BanRecord, error),
) ([]BanRecord, error) {
	if len(jails) <= 1 {
		if len(jails) == 1 {
			return workFunc(ctx, jails[0])
		}
		return []BanRecord{}, nil
	}

	perJail := make([][]BanRecord, len(jails))
	errs := make([]error, len(jails))
	sem := make(chan struct{}, min(len(jails), runtime.NumCPU()))
	var wg sync.WaitGroup

	for i, jail := range jails {
		sem <- struct{}{} // bound in-flight goroutines to the worker limit
		wg.Go(func() {
			defer func() { <-sem }()
			perJail[i], errs[i] = workFunc(ctx, jail)
		})
	}
	wg.Wait()

	// A canceled run leaves holes; surface the context error so callers don't
	// mistake a truncated result set for a complete, successful one.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}

	var allRecords []BanRecord
	var failed []error
	for i := range jails {
		if errs[i] != nil {
			failed = append(failed, errs[i])
			continue
		}
		allRecords = append(allRecords, perJail[i]...)
	}

	if len(failed) == len(jails) {
		return nil, errors.Join(failed...)
	}
	if len(failed) > 0 {
		getLogger().WithError(errors.Join(failed...)).Warn("some jails failed during parallel ban record retrieval")
	}

	return allRecords, nil
}
