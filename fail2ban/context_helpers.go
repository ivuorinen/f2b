package fail2ban

import "context"

// ContextWrapper provides a helper to automatically generate WithContext method wrappers
// This eliminates the need for duplicate WithContext implementations across different Client types

// DefineContextWrappers generates all WithContext methods for a Client implementation
// Usage: embed this in your Client struct and call DefineContextWrappers to get automatic context support
type ContextWrappers struct{}

// Helper functions to reduce boilerplate in WithContext implementations

func wrapWithContext0[T any](fn func() (T, error)) func(context.Context) (T, error) {
	return func(_ context.Context) (T, error) {
		return fn()
	}
}

func wrapWithContext1[T any, A any](fn func(A) (T, error)) func(context.Context, A) (T, error) {
	return func(_ context.Context, a A) (T, error) {
		return fn(a)
	}
}

func wrapWithContext2[T any, A any, B any](fn func(A, B) (T, error)) func(context.Context, A, B) (T, error) {
	return func(_ context.Context, a A, b B) (T, error) {
		return fn(a, b)
	}
}
