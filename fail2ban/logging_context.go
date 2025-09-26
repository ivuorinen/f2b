// Package fail2ban provides context utility functions for structured logging and tracing.
// This module handles context value management, logger creation with context fields,
// and request ID generation for better traceability in fail2ban operations.
package fail2ban

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// WithRequestID adds a request ID to the context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, ContextKeyRequestID, requestID)
}

// WithOperation adds an operation name to the context
func WithOperation(ctx context.Context, operation string) context.Context {
	return context.WithValue(ctx, ContextKeyOperation, operation)
}

// WithJail adds a jail name to the context
func WithJail(ctx context.Context, jail string) context.Context {
	return context.WithValue(ctx, ContextKeyJail, jail)
}

// WithIP adds an IP address to the context
func WithIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, ContextKeyIP, ip)
}

// LoggerFromContext creates a logrus Entry with fields from context
func LoggerFromContext(ctx context.Context) *logrus.Entry {
	fields := logrus.Fields{}

	if requestID, ok := ctx.Value(ContextKeyRequestID).(string); ok && requestID != "" {
		fields["request_id"] = requestID
	}

	if operation, ok := ctx.Value(ContextKeyOperation).(string); ok && operation != "" {
		fields["operation"] = operation
	}

	if jail, ok := ctx.Value(ContextKeyJail).(string); ok && jail != "" {
		fields["jail"] = jail
	}

	if ip, ok := ctx.Value(ContextKeyIP).(string); ok && ip != "" {
		fields["ip"] = ip
	}

	return getLogger().WithFields(fields)
}

// GenerateRequestID generates a simple request ID for tracing
func GenerateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}
