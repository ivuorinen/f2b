// Package fail2ban provides context utility functions for structured logging and tracing.
// This module handles context value management, logger creation with context fields,
// and request ID generation for better traceability in fail2ban operations.
package fail2ban

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"strings"

	"github.com/ivuorinen/f2b/constants"
)

// WithRequestID adds a request ID to the context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	// Trim whitespace and validate
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return ctx // Don't store empty request IDs
	}
	return context.WithValue(ctx, constants.ContextKeyRequestID, requestID)
}

// WithOperation adds an operation name to the context
func WithOperation(ctx context.Context, operation string) context.Context {
	// Trim whitespace and validate
	operation = strings.TrimSpace(operation)
	if operation == "" {
		return ctx // Don't store empty operations
	}
	return context.WithValue(ctx, constants.ContextKeyOperation, operation)
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

	return context.WithValue(ctx, constants.ContextKeyJail, jail)
}

// WithIP adds a validated IP address to the context
func WithIP(ctx context.Context, ip string) context.Context {
	ip = strings.TrimSpace(ip)

	// Validate IP before storing
	if net.ParseIP(ip) == nil {
		getLogger().WithField("ip", ip).Warn("Invalid IP not stored in context")
		return ctx
	}

	return context.WithValue(ctx, constants.ContextKeyIP, ip)
}

// LoggerFromContext creates a logger entry with fields from context
func LoggerFromContext(ctx context.Context) LoggerEntry {
	fields := Fields{}

	if requestID, ok := ctx.Value(constants.ContextKeyRequestID).(string); ok && requestID != "" {
		fields["request_id"] = requestID
	}

	if operation, ok := ctx.Value(constants.ContextKeyOperation).(string); ok && operation != "" {
		fields["operation"] = operation
	}

	if jail, ok := ctx.Value(constants.ContextKeyJail).(string); ok && jail != "" {
		fields["jail"] = jail
	}

	if ip, ok := ctx.Value(constants.ContextKeyIP).(string); ok && ip != "" {
		fields["ip"] = ip
	}

	return getLogger().WithFields(fields)
}

// GenerateRequestID generates a random request ID for tracing. 16 random bytes
// (128 bits) of hex is ample uniqueness for a correlation ID without pulling in
// a UUID dependency.
func GenerateRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req-unknown"
	}
	return hex.EncodeToString(b[:])
}
