// Package cmd provides structured logging and contextual logging capabilities.
// This package implements context-aware logging with request tracing and
// structured field support for better observability in f2b operations.
package cmd

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// ContextualLogger provides structured logging with context propagation
type ContextualLogger struct {
	*fail2ban.SlogLogger
	defaultFields fail2ban.Fields
}

// NewContextualLogger creates a new contextual logger using the centralized cmd.Logger
func NewContextualLogger() *ContextualLogger {
	// Structured JSON logger mirroring the main Logger's output and level. The
	// JSON handler keeps logrus's timestamp/message key names (see SlogJSON).
	contextLogger := fail2ban.NewSlogLogger(fail2ban.SlogJSON)
	contextLogger.SetOutput(Logger.Output())
	contextLogger.SetLevel(Logger.GetLevel())

	return &ContextualLogger{
		SlogLogger: contextLogger,
		defaultFields: fail2ban.Fields{
			"service": "f2b",
			"version": getVersion(),
		},
	}
}

// getVersion returns the build version. It reads the single exported Version
// var (set via ldflags, e.g. by goreleaser), so structured logs report the
// real release version instead of always logging "dev".
func getVersion() string {
	return Version
}

// contextKeyEntry defines a context key and its log field name
type contextKeyEntry struct {
	key       any    // The context key to look up
	fieldName string // The log field name to use
}

// contextKeys lists all context keys to extract for logging
var contextKeys = []contextKeyEntry{
	{constants.ContextKeyRequestID, string(constants.ContextKeyRequestID)},
	{constants.ContextKeyOperation, string(constants.ContextKeyOperation)},
	{constants.ContextKeyIP, string(constants.ContextKeyIP)},
	{constants.ContextKeyJail, string(constants.ContextKeyJail)},
	{constants.ContextKeyCommand, string(constants.ContextKeyCommand)},
}

// WithContext creates a logger entry with context values
func (cl *ContextualLogger) WithContext(ctx context.Context) fail2ban.LoggerEntry {
	entry := cl.WithFields(cl.defaultFields)

	// Extract context values and add as fields using table-driven approach
	for _, ck := range contextKeys {
		if val := ctx.Value(ck.key); val != nil {
			entry = entry.WithField(ck.fieldName, val)
		}
	}

	return entry
}

// WithOperation adds operation context and returns a new context.
// Delegates to fail2ban.WithOperation for consistent validation.
func WithOperation(ctx context.Context, operation string) context.Context {
	return fail2ban.WithOperation(ctx, operation)
}

// WithIP adds IP context and returns a new context.
// Delegates to fail2ban.WithIP for consistent IP validation.
func WithIP(ctx context.Context, ip string) context.Context {
	return fail2ban.WithIP(ctx, ip)
}

// WithJail adds jail context and returns a new context.
// Delegates to fail2ban.WithJail for consistent jail name validation.
func WithJail(ctx context.Context, jail string) context.Context {
	return fail2ban.WithJail(ctx, jail)
}

// WithCommand adds command context and returns a new context.
// This is cmd-specific as fail2ban doesn't need command tracking.
// Empty commands are not stored in context.
func WithCommand(ctx context.Context, command string) context.Context {
	command = strings.TrimSpace(command)
	if command == "" {
		return ctx
	}
	return context.WithValue(ctx, constants.ContextKeyCommand, command)
}

// WithRequestID adds request ID context and returns a new context.
// Delegates to fail2ban.WithRequestID for consistent validation.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return fail2ban.WithRequestID(ctx, requestID)
}

// LogOperation logs the start and end of an operation with timing and metrics
func (cl *ContextualLogger) LogOperation(ctx context.Context, operation string, fn func() error) error {
	start := time.Now()
	ctx = WithOperation(ctx, operation)

	// Ensure the operation carries a request ID so every log line it emits
	// (start, completion, and any nested operation logs) shares one correlatable
	// request_id in the structured output.
	if ctx.Value(constants.ContextKeyRequestID) == nil {
		ctx = WithRequestID(ctx, fail2ban.GenerateRequestID())
	}

	cl.WithContext(ctx).WithField("action", constants.ActionStart).Info("Operation started")

	err := fn()
	duration := time.Since(start)

	entry := cl.WithContext(ctx).WithField("duration_ms", duration.Milliseconds())

	if err != nil {
		entry.WithError(err).Error("Operation failed")
	} else {
		entry.Info("Operation completed")
	}

	return err
}

// LogBanOperation logs ban/unban operations with structured context and metrics
func (cl *ContextualLogger) LogBanOperation(
	ctx context.Context,
	operation, ip, jail string,
	success bool,
	duration time.Duration,
) {
	ctx = WithOperation(ctx, operation)
	ctx = WithIP(ctx, ip)
	ctx = WithJail(ctx, jail)

	entry := cl.WithContext(ctx).WithFields(fail2ban.Fields{
		"success":     success,
		"duration_ms": duration.Milliseconds(),
	})

	if success {
		entry.Info("Ban operation completed")
	} else {
		entry.Error("Ban operation failed")
	}
}

// Global contextual logger instance, built lazily on first use so it picks
// up the log level configured during package init (CI/test quieting in
// output.go) instead of the pre-init default.
var (
	contextualLogger     *ContextualLogger
	contextualLoggerOnce sync.Once
)

// GetContextualLogger returns the global contextual logger
func GetContextualLogger() *ContextualLogger {
	contextualLoggerOnce.Do(func() {
		if contextualLogger == nil {
			contextualLogger = NewContextualLogger()
		}
	})
	return contextualLogger
}

// SetContextualLogger sets a new global contextual logger.
//
// Not synchronized: call only during startup or from tests before concurrent
// readers exist — a call while workers run is a data race by contract.
func SetContextualLogger(logger *ContextualLogger) {
	contextualLoggerOnce.Do(func() {})
	contextualLogger = logger
}
