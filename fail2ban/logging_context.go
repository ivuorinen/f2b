// Package fail2ban provides context utility functions for structured logging and tracing.
// This module handles context value management, logger creation with context fields,
// and request ID generation for better traceability in fail2ban operations.
package fail2ban

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ivuorinen/f2b/shared"
)

// WithRequestID adds a request ID to the context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, shared.ContextKeyRequestID, requestID)
}

// WithOperation adds an operation name to the context
func WithOperation(ctx context.Context, operation string) context.Context {
	return context.WithValue(ctx, shared.ContextKeyOperation, operation)
}

// WithJail adds a validated jail name to the context
func WithJail(ctx context.Context, jail string) context.Context {
	jail = strings.TrimSpace(jail)

	// Validate jail name before storing
	if err := ValidateJail(jail); err != nil {
		// Don't store invalid jail names in context
		getLogger().WithError(err).Warn("Invalid jail name not stored in context")
		return ctx
	}

	return context.WithValue(ctx, shared.ContextKeyJail, jail)
}

// WithIP adds a validated IP address to the context
func WithIP(ctx context.Context, ip string) context.Context {
	ip = strings.TrimSpace(ip)

	// Validate IP before storing
	if net.ParseIP(ip) == nil {
		getLogger().WithField("ip", ip).Warn("Invalid IP not stored in context")
		return ctx
	}

	return context.WithValue(ctx, shared.ContextKeyIP, ip)
}

// LoggerFromContext creates a logger entry with fields from context
func LoggerFromContext(ctx context.Context) LoggerEntry {
	fields := Fields{}

	if requestID, ok := ctx.Value(shared.ContextKeyRequestID).(string); ok && requestID != "" {
		fields["request_id"] = requestID
	}

	if operation, ok := ctx.Value(shared.ContextKeyOperation).(string); ok && operation != "" {
		fields["operation"] = operation
	}

	if jail, ok := ctx.Value(shared.ContextKeyJail).(string); ok && jail != "" {
		fields["jail"] = jail
	}

	if ip, ok := ctx.Value(shared.ContextKeyIP).(string); ok && ip != "" {
		fields["ip"] = ip
	}

	return getLogger().WithFields(fields)
}

// GenerateRequestID generates a simple request ID for tracing
func GenerateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}
