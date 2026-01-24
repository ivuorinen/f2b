// Package cmd provides structured logging and contextual logging capabilities.
// This package implements context-aware logging with request tracing and
// structured field support for better observability in f2b operations.
package cmd

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/shared"
)

// ContextualLogger provides structured logging with context propagation
type ContextualLogger struct {
	*logrus.Logger
	defaultFields logrus.Fields
}

// NewContextualLogger creates a new contextual logger using the centralized cmd.Logger
func NewContextualLogger() *ContextualLogger {
	// Use cmd.Logger as the backend, but with JSON formatter for structured logging
	contextLogger := logrus.New()
	contextLogger.SetOutput(Logger.Out)
	contextLogger.SetLevel(Logger.GetLevel())
	contextLogger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
		},
	})

	return &ContextualLogger{
		Logger: contextLogger,
		defaultFields: logrus.Fields{
			"service": "f2b",
			"version": getVersion(),
		},
	}
}

// Build-time variables set via ldflags
var (
	version = "dev"
	// Additional build variables that may be used in the future
	_ = "unknown" // commit placeholder
	_ = "unknown" // date placeholder
	_ = "unknown" // builtBy placeholder
)

// getVersion returns the version from build variables or default
func getVersion() string {
	return version
}

// WithContext creates a logger entry with context values
func (cl *ContextualLogger) WithContext(ctx context.Context) *logrus.Entry {
	entry := cl.WithFields(cl.defaultFields)

	// Extract context values and add as fields (using consistent constants)
	if requestID := ctx.Value(shared.ContextKeyRequestID); requestID != nil {
		entry = entry.WithField(string(shared.ContextKeyRequestID), requestID)
	}

	if operation := ctx.Value(shared.ContextKeyOperation); operation != nil {
		entry = entry.WithField(string(shared.ContextKeyOperation), operation)
	}

	if ip := ctx.Value(shared.ContextKeyIP); ip != nil {
		entry = entry.WithField(string(shared.ContextKeyIP), ip)
	}

	if jail := ctx.Value(shared.ContextKeyJail); jail != nil {
		entry = entry.WithField(string(shared.ContextKeyJail), jail)
	}

	if command := ctx.Value(shared.ContextKeyCommand); command != nil {
		entry = entry.WithField(string(shared.ContextKeyCommand), command)
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
func WithCommand(ctx context.Context, command string) context.Context {
	return context.WithValue(ctx, shared.ContextKeyCommand, command)
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

	// Get metrics instance
	metrics := GetGlobalMetrics()

	cl.WithContext(ctx).WithField("action", shared.ActionStart).Info("Operation started")

	err := fn()
	duration := time.Since(start)

	entry := cl.WithContext(ctx).WithField("duration_ms", duration.Milliseconds())

	// Record metrics based on operation type
	success := err == nil
	if command := ctx.Value(shared.ContextKeyCommand); command != nil {
		if cmdStr, ok := command.(string); ok {
			metrics.RecordCommandExecution(cmdStr, duration, success)
		}
	}

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

	// Record metrics
	metrics := GetGlobalMetrics()
	metrics.RecordBanOperation(operation, duration, success)

	entry := cl.WithContext(ctx).WithFields(logrus.Fields{
		"success":     success,
		"duration_ms": duration.Milliseconds(),
	})

	if success {
		entry.Info("Ban operation completed")
	} else {
		entry.Error("Ban operation failed")
	}
}

// LogCommandExecution logs command execution with context
func (cl *ContextualLogger) LogCommandExecution(
	ctx context.Context,
	command string,
	args []string,
	duration time.Duration,
	err error,
) {
	ctx = WithCommand(ctx, command)

	entry := cl.WithContext(ctx).WithFields(logrus.Fields{
		"args":        args,
		"duration_ms": duration.Milliseconds(),
	})

	if err != nil {
		entry.WithError(err).Error("Command execution failed")
	} else {
		entry.Info("Command executed successfully")
	}
}

// Global contextual logger instance
var contextualLogger = NewContextualLogger()

// GetContextualLogger returns the global contextual logger
func GetContextualLogger() *ContextualLogger {
	return contextualLogger
}

// SetContextualLogger sets a new global contextual logger
func SetContextualLogger(logger *ContextualLogger) {
	contextualLogger = logger
}
