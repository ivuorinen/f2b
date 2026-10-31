// Structured, context-aware logging with request tracing for f2b operations.

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

// NewContextualLogger creates a contextual logger over the centralized
// cmd.Logger itself. Sharing Logger keeps one format, level and output, chosen
// in PersistentPreRunE; a second logger on the same sink would interleave two
// formats in one stream.
func NewContextualLogger() *ContextualLogger {
	return &ContextualLogger{
		SlogLogger: Logger,
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

// LogOperation logs the start and end of an operation with its duration. fn
// receives the derived context carrying request_id and operation, so the log
// lines fn emits correlate with the start/finish lines; a closure over the
// caller's context produced nested lines without the id.
func (cl *ContextualLogger) LogOperation(ctx context.Context, operation string, fn func(context.Context) error) error {
	start := time.Now()
	ctx = fail2ban.WithOperation(ctx, operation)

	// Ensure the operation carries a request ID so every log line it emits
	// (start, completion, and any nested operation logs) shares one correlatable
	// request_id in the structured output.
	if ctx.Value(constants.ContextKeyRequestID) == nil {
		ctx = fail2ban.WithRequestID(ctx, fail2ban.GenerateRequestID())
	}

	cl.WithContext(ctx).WithField("action", constants.ActionStart).Info("Operation started")

	err := fn(ctx)
	duration := time.Since(start)

	entry := cl.WithContext(ctx).WithField("duration_ms", duration.Milliseconds())

	if err != nil {
		entry.WithError(err).Error("Operation failed")
	} else {
		entry.Info("Operation completed")
	}

	return err
}

// LogBanOperation logs ban/unban operations with structured context and duration
func (cl *ContextualLogger) LogBanOperation(
	ctx context.Context,
	operation, ip, jail string,
	success bool,
	duration time.Duration,
) {
	ctx = fail2ban.WithOperation(ctx, operation)
	ctx = fail2ban.WithIP(ctx, ip)
	ctx = fail2ban.WithJail(ctx, jail)

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
