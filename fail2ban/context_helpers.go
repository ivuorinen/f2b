package fail2ban

import "context"

// Context Wrapper Pattern
//
// This package provides generic helper functions for creating WithContext method wrappers.
// These helpers eliminate boilerplate for methods that simply need context propagation
// without additional logic.
//
// For simple methods (no validation, direct delegation to non-context version):
//
//	func (c *Client) ListJailsWithContext(ctx context.Context) ([]string, error) {
//	    return wrapWithContext0(c.ListJails)(ctx)
//	}
//
// For complex methods (validation, custom logic, different execution paths):
// Implement the WithContext version directly with the required logic.
//
// Note: Code generation was evaluated but determined unnecessary because:
// - Only 2 methods use the simple wrapper pattern
// - Most WithContext methods require custom validation/logic
// - The generic helpers below already solve the simple cases cleanly

// Helper functions to reduce boilerplate in WithContext implementations

// wrapWithContext0 wraps a function with no parameters to accept a context parameter.
func wrapWithContext0[T any](fn func() (T, error)) func(context.Context) (T, error) {
	return func(_ context.Context) (T, error) {
		return fn()
	}
}

// wrapWithContext1 wraps a function with one parameter to accept a context parameter.
func wrapWithContext1[T any, A any](fn func(A) (T, error)) func(context.Context, A) (T, error) {
	return func(_ context.Context, a A) (T, error) {
		return fn(a)
	}
}

// wrapWithContext2 wraps a function with two parameters to accept a context parameter.
func wrapWithContext2[T any, A any, B any](fn func(A, B) (T, error)) func(context.Context, A, B) (T, error) {
	return func(_ context.Context, a A, b B) (T, error) {
		return fn(a, b)
	}
}
