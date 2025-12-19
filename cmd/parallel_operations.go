package cmd

import (
	"context"
	"runtime"
	"sync"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/shared"
)

// ParallelOperationProcessor handles parallel ban/unban operations across multiple jails
type ParallelOperationProcessor struct {
	workerCount int
}

// NewParallelOperationProcessor creates a new parallel operation processor
func NewParallelOperationProcessor(workerCount int) *ParallelOperationProcessor {
	if workerCount <= 0 {
		workerCount = runtime.NumCPU()
	}
	return &ParallelOperationProcessor{
		workerCount: workerCount,
	}
}

// ProcessBanOperationParallel processes ban operations across multiple jails in parallel
func (pop *ParallelOperationProcessor) ProcessBanOperationParallel(
	client fail2ban.Client,
	ip string,
	jails []string,
) ([]OperationResult, error) {
	if len(jails) <= 1 {
		// For single jail, use sequential processing to avoid overhead
		return ProcessBanOperation(client, ip, jails)
	}

	return pop.processOperations(
		context.Background(),
		client,
		ip,
		jails,
		func(ctx context.Context, client fail2ban.Client, ip, jail string) (int, error) {
			return client.BanIPWithContext(ctx, ip, jail)
		},
		shared.MetricsBan,
	)
}

// ProcessBanOperationParallelWithContext processes ban operations across
// multiple jails in parallel with timeout context
func (pop *ParallelOperationProcessor) ProcessBanOperationParallelWithContext(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
) ([]OperationResult, error) {
	if len(jails) <= 1 {
		// For single jail, use sequential processing to avoid overhead
		return ProcessBanOperationWithContext(ctx, client, ip, jails)
	}

	return pop.processOperations(
		ctx,
		client,
		ip,
		jails,
		func(opCtx context.Context, client fail2ban.Client, ip, jail string) (int, error) {
			return client.BanIPWithContext(opCtx, ip, jail)
		},
		shared.MetricsBan,
	)
}

// ProcessUnbanOperationParallel processes unban operations across multiple jails in parallel
func (pop *ParallelOperationProcessor) ProcessUnbanOperationParallel(
	client fail2ban.Client,
	ip string,
	jails []string,
) ([]OperationResult, error) {
	if len(jails) <= 1 {
		// For single jail, use sequential processing to avoid overhead
		return ProcessUnbanOperation(client, ip, jails)
	}

	return pop.processOperations(
		context.Background(),
		client,
		ip,
		jails,
		func(ctx context.Context, client fail2ban.Client, ip, jail string) (int, error) {
			return client.UnbanIPWithContext(ctx, ip, jail)
		},
		shared.MetricsUnban,
	)
}

// ProcessUnbanOperationParallelWithContext processes unban operations across
// multiple jails in parallel with timeout context
func (pop *ParallelOperationProcessor) ProcessUnbanOperationParallelWithContext(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
) ([]OperationResult, error) {
	if len(jails) <= 1 {
		// For single jail, use sequential processing to avoid overhead
		return ProcessUnbanOperationWithContext(ctx, client, ip, jails)
	}

	return pop.processOperations(
		ctx,
		client,
		ip,
		jails,
		func(opCtx context.Context, client fail2ban.Client, ip, jail string) (int, error) {
			return client.UnbanIPWithContext(opCtx, ip, jail)
		},
		shared.MetricsUnban,
	)
}

// operationFunc represents a ban or unban operation with context
type operationFunc func(ctx context.Context, client fail2ban.Client, ip, jail string) (int, error)

// processOperations handles the parallel processing of operations
func (pop *ParallelOperationProcessor) processOperations(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
	operation operationFunc,
	operationType string,
) ([]OperationResult, error) {
	results := make([]OperationResult, len(jails))
	resultCh := make(chan operationResult, len(jails))

	// Create worker pool
	var wg sync.WaitGroup
	jailCh := make(chan jailWork, len(jails))

	workerCount := pop.workerCount
	if len(jails) < workerCount {
		workerCount = len(jails)
	}

	// Start workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pop.worker(ctx, client, ip, operation, operationType, jailCh, resultCh)
		}()
	}

	// Send work items
	go func() {
		defer close(jailCh)
		for i, jail := range jails {
			jailCh <- jailWork{jail: jail, index: i}
		}
	}()

	// Wait for workers to complete
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results
	for result := range resultCh {
		if result.index >= 0 && result.index < len(results) {
			results[result.index] = result.result
		}
	}

	return results, nil
}

// jailWork represents work for a specific jail
type jailWork struct {
	jail  string
	index int
}

// operationResult represents the result of an operation
type operationResult struct {
	result OperationResult
	index  int
}

// worker processes jail operations
func (pop *ParallelOperationProcessor) worker(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	operation operationFunc,
	operationType string,
	jailCh <-chan jailWork,
	resultCh chan<- operationResult,
) {
	for work := range jailCh {
		code, err := operation(ctx, client, ip, work.jail)

		var status string
		if err != nil {
			status = err.Error()
		} else {
			status = InterpretBanStatus(code, operationType)
		}

		Logger.WithFields(map[string]interface{}{
			"ip":     ip,
			"jail":   work.jail,
			"status": status,
		}).Info("Operation result")

		result := operationResult{
			result: OperationResult{
				IP:     ip,
				Jail:   work.jail,
				Status: status,
			},
			index: work.index,
		}

		resultCh <- result
	}
}

// Global processor instance
var defaultParallelProcessor = NewParallelOperationProcessor(runtime.NumCPU())

// ProcessBanOperationParallel processes ban operations in parallel using the default processor
func ProcessBanOperationParallel(client fail2ban.Client, ip string, jails []string) ([]OperationResult, error) {
	return defaultParallelProcessor.ProcessBanOperationParallel(client, ip, jails)
}

// ProcessBanOperationParallelWithContext processes ban operations in parallel using the default processor with context
func ProcessBanOperationParallelWithContext(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
) ([]OperationResult, error) {
	return defaultParallelProcessor.ProcessBanOperationParallelWithContext(
		ctx, client, ip, jails)
}

// ProcessUnbanOperationParallel processes unban operations in parallel using the default processor
func ProcessUnbanOperationParallel(client fail2ban.Client, ip string, jails []string) ([]OperationResult, error) {
	return defaultParallelProcessor.ProcessUnbanOperationParallel(client, ip, jails)
}

// ProcessUnbanOperationParallelWithContext processes unban operations in
// parallel using the default processor with context
func ProcessUnbanOperationParallelWithContext(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
) ([]OperationResult, error) {
	return defaultParallelProcessor.ProcessUnbanOperationParallelWithContext(ctx, client, ip, jails)
}
