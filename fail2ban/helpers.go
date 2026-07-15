package fail2ban

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ivuorinen/f2b/constants"
)

func init() {
	// Configure logging for CI/test environments to reduce noise
	// This now comes from the logging_env module
}

// Parsing helpers

// ParseJailList parses the jail list output from fail2ban-client status
func ParseJailList(output string) ([]string, error) {
	// Optimized: Find "Jail list:" position directly instead of splitting all lines
	jailListPos := strings.Index(output, "Jail list:")
	if jailListPos == -1 {
		return nil, fmt.Errorf(constants.ErrFailedToParseJails)
	}

	// Find the start of the jail list content (after "Jail list:")
	colonPos := strings.Index(output[jailListPos:], ":")
	if colonPos == -1 {
		return nil, fmt.Errorf(constants.ErrFailedToParseJails)
	}

	// Find the end of the line
	start := jailListPos + colonPos + 1
	end := strings.Index(output[start:], "\n")
	if end == -1 {
		end = len(output) - start
	}

	jailList := strings.TrimSpace(output[start : start+end])
	if jailList == "" {
		return []string{}, nil // Return empty list for no jails
	}

	// Optimized: Use byte replacement instead of string replacement for single character
	if strings.Contains(jailList, ",") {
		jailList = strings.ReplaceAll(jailList, ",", " ")
	}

	return strings.Fields(jailList), nil
}

// ParseBracketedList parses bracketed output like "[jail1, jail2]"
func ParseBracketedList(output string) []string {
	// Optimized: Manual bracket removal instead of Trim to avoid checking both ends
	s := output
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		s = s[1 : len(s)-1]
	}
	if s == "" {
		return []string{}
	}

	// fail2ban prints a Python list repr which uses single quotes
	// (e.g. ['sshd', 'nginx']), not just double quotes. Strip both, plus any
	// residual brackets from nested reprs, and drop empty elements.
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, "[]'\"")
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}

	return result
}

// Timing infrastructure for performance monitoring

// TimedOperation represents a timed operation with metadata
type TimedOperation struct {
	Name      string
	Command   string
	Args      []string
	StartTime time.Time
}

// NewTimedOperation creates a new timed operation and starts timing
func NewTimedOperation(name, command string, args ...string) *TimedOperation {
	return &TimedOperation{
		Name:      name,
		Command:   command,
		Args:      args,
		StartTime: time.Now(),
	}
}

// Finish completes the timed operation and logs the duration with context
func (t *TimedOperation) Finish(err error) {
	duration := time.Since(t.StartTime)

	fields := Fields{
		"operation": t.Name,
		"command":   t.Command,
		"duration":  duration,
		"args":      strings.Join(t.Args, " "),
	}

	if err != nil {
		getLogger().WithFields(fields).
			WithField(constants.LogFieldError, err.Error()).
			Warnf(constants.ErrOperationFailed, duration)
	} else {
		if duration > time.Second {
			// Log slow operations as warnings for visibility
			getLogger().WithFields(fields).Warnf(constants.ErrSlowOperation, duration)
		} else {
			// Log fast operations at debug level to reduce noise
			getLogger().WithFields(fields).Debugf(constants.MsgOperationCompleted, duration)
		}
	}
}

// FinishWithContext completes the timed operation and logs the duration with context
func (t *TimedOperation) FinishWithContext(ctx context.Context, err error) {
	duration := time.Since(t.StartTime)

	// Get logger with context fields
	logger := LoggerFromContext(ctx)

	// Add timing-specific fields
	fields := Fields{
		"operation": t.Name,
		"command":   t.Command,
		"duration":  duration,
		"args":      strings.Join(t.Args, " "),
	}
	logger = logger.WithFields(fields)

	if err != nil {
		logger.WithField(constants.LogFieldError, err.Error()).Warnf(constants.ErrOperationFailed, duration)
	} else {
		if duration > time.Second {
			// Log slow operations as warnings for visibility
			logger.Warnf(constants.ErrSlowOperation, duration)
		} else {
			// Log fast operations at debug level to reduce noise
			logger.Debugf(constants.MsgOperationCompleted, duration)
		}
	}
}
