package fail2ban

import (
	"context"
	"runtime"
	"sync"
)

// WorkerPool provides parallel processing capabilities with error aggregation
type WorkerPool[T any, R any] struct {
	workerCount int
}

// NewWorkerPool creates a new worker pool with the specified number of workers
func NewWorkerPool[T any, R any](workerCount int) *WorkerPool[T, R] {
	if workerCount <= 0 {
		workerCount = runtime.NumCPU()
	}
	return &WorkerPool[T, R]{
		workerCount: workerCount,
	}
}

// WorkFunc represents a function that processes a single work item
type WorkFunc[T any, R any] func(ctx context.Context, item T) (R, error)

// Result holds the result of processing a work item
type Result[R any] struct {
	Value R
	Error error
	Index int // Original index in the input slice
}

// Process processes work items in parallel and returns results in original order
func (wp *WorkerPool[T, R]) Process(ctx context.Context, items []T, workFunc WorkFunc[T, R]) ([]Result[R], error) {
	if len(items) == 0 {
		return []Result[R]{}, nil
	}

	// Create channels
	workCh := make(chan workItem[T], len(items))
	resultCh := make(chan Result[R], len(items))

	// Start workers
	var wg sync.WaitGroup
	workerCount := wp.workerCount
	if len(items) < workerCount {
		workerCount = len(items)
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wp.worker(ctx, workCh, resultCh, workFunc)
		}()
	}

	// Send work items
	go func() {
		defer close(workCh)
		for i, item := range items {
			select {
			case workCh <- workItem[T]{item: item, index: i}:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Gather results
	results := make([]Result[R], len(items))
	for result := range resultCh {
		if result.Index < len(results) {
			results[result.Index] = result
		}
	}

	return results, nil
}

// workItem represents a work item with its original index
type workItem[T any] struct {
	item  T
	index int
}

// worker processes work items from the work channel
func (wp *WorkerPool[T, R]) worker(
	ctx context.Context,
	workCh <-chan workItem[T],
	resultCh chan<- Result[R],
	workFunc WorkFunc[T, R],
) {
	for {
		select {
		case work, ok := <-workCh:
			if !ok {
				return
			}

			value, err := workFunc(ctx, work.item)
			result := Result[R]{
				Value: value,
				Error: err,
				Index: work.index,
			}

			select {
			case resultCh <- result:
			case <-ctx.Done():
				return
			}

		case <-ctx.Done():
			return
		}
	}
}

// ProcessWithErrorAggregation processes items and aggregates errors
func (wp *WorkerPool[T, R]) ProcessWithErrorAggregation(
	ctx context.Context,
	items []T,
	workFunc WorkFunc[T, R],
) ([]R, []error) {
	results, err := wp.Process(ctx, items, workFunc)
	if err != nil {
		return nil, []error{err}
	}

	values := make([]R, 0, len(results))
	errors := make([]error, 0)

	for _, result := range results {
		if result.Error != nil {
			errors = append(errors, result.Error)
		} else {
			values = append(values, result.Value)
		}
	}

	return values, errors
}

// Global worker pool instances for common use cases
var (
	defaultWorkerPool = NewWorkerPool[string, []BanRecord](runtime.NumCPU())
)

// ProcessJailsParallel processes multiple jails in parallel for ban record retrieval
func ProcessJailsParallel(
	ctx context.Context,
	jails []string,
	workFunc func(ctx context.Context, jail string) ([]BanRecord, error),
) ([]BanRecord, error) {
	if len(jails) <= 1 {
		// For single jail, don't use parallelization overhead
		if len(jails) == 1 {
			return workFunc(ctx, jails[0])
		}
		return []BanRecord{}, nil
	}

	results, err := defaultWorkerPool.Process(ctx, jails, workFunc)
	if err != nil {
		return nil, err
	}

	// Aggregate all ban records
	var allRecords []BanRecord
	for _, result := range results {
		if result.Error == nil {
			allRecords = append(allRecords, result.Value...)
		}
		// Silently ignore errors for individual jails (original behavior)
	}

	return allRecords, nil
}
