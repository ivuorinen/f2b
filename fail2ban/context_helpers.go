package fail2ban

import "context"

// ContextWrappers provides a helper to automatically generate WithContext method wrappers.
// This eliminates the need for duplicate WithContext implementations across different Client types.
// Usage: embed this in your Client struct and call DefineContextWrappers to get automatic context support.
type ContextWrappers struct{}

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
