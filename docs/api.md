# f2b Internal API Documentation

This document provides comprehensive documentation for the internal APIs
and interfaces used in the f2b project. This is intended for developers
who want to contribute to the project or integrate with its components.

## Table of Contents

- [Core Interfaces](#core-interfaces)
- [Client Package](#client-package)
- [Command Package](#command-package)
- [Error Handling](#error-handling)
- [Configuration](#configuration)
- [Logging and Metrics](#logging-and-metrics)
- [Testing Framework](#testing-framework)
- [Examples](#examples)

## Core Interfaces

### fail2ban.Client Interface

The core interface for interacting with fail2ban operations.

```go
type Client interface {
    // Basic operations
    BanIP(ip, jail string) (int, error)
    UnbanIP(ip, jail string) (int, error)
    BanIPWithContext(ctx context.Context, ip, jail string) (int, error)
    UnbanIPWithContext(ctx context.Context, ip, jail string) (int, error)

    // Information retrieval
    ListJails() ([]string, error)
    ListJailsWithContext(ctx context.Context) ([]string, error)
    StatusAll() (string, error)
    StatusJail(jail string) (string, error)
    GetBanRecords(jails []string) ([]BanRecord, error)
    BannedIn(ip string) ([]string, error)

    // Filter operations
    ListFilters() ([]string, error)
    TestFilter(filter, logfile string, verbose bool) ([]string, error)
}
```

### Implementation Examples

#### Using the Client Interface

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/ivuorinen/f2b/fail2ban"
)

func banIPExample() error {
    // Create a client
    client, err := fail2ban.NewClient()
    if err != nil {
        return fmt.Errorf("failed to create client: %w", err)
    }

    // Ban an IP with timeout context
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    code, err := client.BanIPWithContext(ctx, "192.168.1.100", "sshd")
    if err != nil {
        return fmt.Errorf("ban operation failed: %w", err)
    }

    fmt.Printf("Ban operation completed with code: %d\n", code)
    return nil
}
```

## Client Package

### Real Client

The `RealClient` struct implements the `Client` interface for actual fail2ban operations.

```go
type RealClient struct {
    path          string        // Path to fail2ban-client binary
    timeout       time.Duration // Default timeout for operations
    sudoChecker   SudoChecker   // Interface for sudo privilege checking
    runner        Runner        // Interface for command execution
}
```

#### Configuration

```go
// Create a new client with custom timeout
client, err := fail2ban.NewClientWithTimeout(45 * time.Second)
if err != nil {
    return err
}

// Create a client with custom sudo checker
customSudoChecker := &MyCustomSudoChecker{}
client, err := fail2ban.NewClientWithSudo(customSudoChecker)
```

### Mock Client

For testing purposes, use the `MockClient`:

```go
func TestMyFunction(t *testing.T) {
    mock := fail2ban.NewMockClient()

    // Configure mock responses
    mock.Jails = map[string]struct{}{
        "sshd": {},
        "apache": {},
    }

    mock.Banned = map[string]map[string]time.Time{
        "sshd": {"192.168.1.100": time.Now()},
    }

    // Use mock in your test
    result, err := myFunction(mock)
    // ... assertions
}
```

## Command Package

### Config Structure

The central configuration structure for the CLI:

```go
type Config struct {
    LogDir          string        // Path to Fail2Ban log directory
    FilterDir       string        // Path to Fail2Ban filter directory
    Format          string        // Output format: "plain" or "json"
    CommandTimeout  time.Duration // Timeout for individual fail2ban commands
    FileTimeout     time.Duration // Timeout for file operations
    ParallelTimeout time.Duration // Timeout for parallel operations
}
```

#### Configuration Validation

```go
func validateConfig() error {
    config := cmd.NewConfigFromEnv()

    // Validate the configuration
    if err := config.ValidateConfig(); err != nil {
        return fmt.Errorf("invalid configuration: %w", err)
    }

    return nil
}
```

### Command Helpers

The `cmd` package provides several helper functions for command creation and validation:

```go
// Command creation
func NewCommand(
  use,
  short string,
  aliases []string,
  runE func(*cobra.Command, []string) error
) *cobra.Command

// Validation helpers
func ValidateIPArgument(args []string) (string, error)
func ValidateServiceAction(action string) error

// Jail operations
func GetJailsFromArgsWithContext(
  ctx context.Context,
  client fail2ban.Client,
  args []string,
  startIndex int
) ([]string, error)

// Error handling
func HandleClientError(err error) error
func PrintErrorAndReturn(err error) error
```

## Error Handling

### Contextual Errors

The f2b project uses enhanced error handling with context and remediation hints:

```go
type ContextualError struct {
    Message     string
    Category    ErrorCategory
    Remediation string
    Cause       error
}

// Create contextual errors
validationErr := fail2ban.NewValidationError(
    "invalid IP address: 192.168.1.999",
    "Provide a valid IPv4 or IPv6 address",
)

systemErr := fail2ban.NewSystemError(
    "fail2ban service not running",
    "Start the service with: sudo systemctl start fail2ban",
    originalError,
)
```

### Error Categories

```go
const (
    ErrorCategoryValidation  ErrorCategory = "validation"
    ErrorCategoryNetwork     ErrorCategory = "network"
    ErrorCategoryPermission  ErrorCategory = "permission"
    ErrorCategorySystem      ErrorCategory = "system"
    ErrorCategoryConfig      ErrorCategory = "config"
)
```

## Configuration

### Environment Variables

The configuration system supports the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `F2B_LOG_DIR` | Log directory path | `/var/log` |
| `F2B_FILTER_DIR` | Filter directory path | `/etc/fail2ban/filter.d` |
| `F2B_LOG_LEVEL` | Log level | `info` |
| `F2B_COMMAND_TIMEOUT` | Command timeout | `30s` |
| `F2B_FILE_TIMEOUT` | File operation timeout | `10s` |
| `F2B_PARALLEL_TIMEOUT` | Parallel operation timeout | `60s` |

### Path Security

All configuration paths undergo comprehensive validation:

```go
func validateConfigPath(path, pathType string) (string, error)
```

This function:

- Checks for path traversal attempts
- Validates against null byte injection
- Ensures paths are within reasonable system locations
- Resolves to absolute paths
- Enforces length limits

## Logging and Metrics

### Contextual Logging

The logging system supports structured logging with context propagation:

```go
// Create a contextual logger
logger := cmd.NewContextualLogger()

// Add context to logging
ctx := cmd.WithOperation(context.Background(), "ban_ip")
ctx = cmd.WithIP(ctx, "192.168.1.100")
ctx = cmd.WithJail(ctx, "sshd")

// Log with context
logger.WithContext(ctx).Info("Starting ban operation")

// Log operations with timing
err := logger.LogOperation(ctx, "ban_operation", func() error {
    return client.BanIP("192.168.1.100", "sshd")
})
```

### Performance Metrics

The metrics system provides comprehensive performance monitoring:

```go
// Get global metrics
metrics := cmd.GetGlobalMetrics()

// Record operations
metrics.RecordCommandExecution("ban", duration, success)
metrics.RecordBanOperation("ban", duration, success)
metrics.RecordValidationCacheHit()

// Get metrics snapshot
snapshot := metrics.GetSnapshot()
fmt.Printf("Command executions: %d\n", snapshot.CommandExecutions)
fmt.Printf("Average latency: %.2fms\n", snapshot.CommandLatencyBuckets["ban"].GetAverageLatency())
```

### Timed Operations

Use timed operations for automatic instrumentation:

```go
func performBanOperation(ctx context.Context, ip, jail string) error {
    metrics := cmd.GetGlobalMetrics()
    timer := cmd.NewTimedOperation(ctx, metrics, "ban", "ban_ip")

    // Perform the operation
    err := client.BanIP(ip, jail)

    // Record timing and success/failure
    timer.Finish(err == nil)

    return err
}
```

## Testing Framework

### Modern Test Framework

The f2b project includes a fluent testing framework for command testing:

```go
func TestBanCommand(t *testing.T) {
    cmd.NewCommandTest(t, "ban").
        WithArgs("192.168.1.100", "sshd").
        WithSetup(func(mock *fail2ban.MockClient) {
            setMockJails(mock, []string{"sshd"})
        }).
        ExpectSuccess().
        ExpectOutput("Banned 192.168.1.100 in sshd").
        Run()
}
```

### Mock Client Builder

For complex mock scenarios:

```go
func TestComplexScenario(t *testing.T) {
    mockBuilder := cmd.NewMockClientBuilder().
        WithJails("sshd", "apache").
        WithBannedIP("192.168.1.100", "sshd").
        WithBanRecord("sshd", "192.168.1.100", "01:30:00").
        WithStatusResponse("sshd", "Status: active")

    cmd.NewCommandTest(t, "status").
        WithArgs("sshd").
        WithMockBuilder(mockBuilder).
        ExpectSuccess().
        Run()
}
```

### Environment Setup

Use standardized environment setup:

```go
func TestWithMockEnvironment(t *testing.T) {
    _, cleanup := fail2ban.SetupMockEnvironmentWithSudo(t, true)
    defer cleanup()

    // Test implementation with mocked environment
}
```

## Examples

### Complete Command Implementation

Here's how to implement a new command following f2b patterns:

```go
package cmd

import (
    "context"
    "fmt"

    "github.com/spf13/cobra"
    "github.com/ivuorinen/f2b/fail2ban"
)

// MyCmd implements a new command with full context and error handling
func MyCmd(client fail2ban.Client, config *Config) *cobra.Command {
    return NewCommand("mycmd <arg>", "My command description", []string{"mc"},
        func(cmd *cobra.Command, args []string) error {
            // Create timeout context
            ctx, cancel := context.WithTimeout(context.Background(), config.CommandTimeout)
            defer cancel()

            // Validate arguments
            if len(args) < 1 {
                return PrintErrorAndReturn(fail2ban.ErrActionRequiredError)
            }

            // Add context for logging
            ctx = WithOperation(ctx, "my_operation")
            ctx = WithCommand(ctx, "mycmd")

            // Log operation with timing
            logger := GetContextualLogger()
            return logger.LogOperation(ctx, "my_command", func() error {
                // Perform operation with client
                result, err := client.SomeOperation(args[0])
                if err != nil {
                    return HandleClientError(err)
                }

                // Output results
                OutputResults(cmd, result, config)
                return nil
            })
        })
}
```

### Custom Client Implementation

```go
package main

import (
    "context"
    "time"

    "github.com/ivuorinen/f2b/fail2ban"
)

// CustomClient implements the Client interface with custom logic
type CustomClient struct {
    baseClient fail2ban.Client
    customLogic string
}

func (c *CustomClient) BanIP(ip, jail string) (int, error) {
    // Custom pre-processing
    if err := c.preprocessBan(ip, jail); err != nil {
        return 0, err
    }

    // Delegate to base client
    return c.baseClient.BanIP(ip, jail)
}

func (c *CustomClient) BanIPWithContext(ctx context.Context, ip, jail string) (int, error) {
    // Context-aware implementation
    select {
    case <-ctx.Done():
        return 0, ctx.Err()
    default:
        return c.BanIP(ip, jail)
    }
}

// Implement other Client interface methods...

func (c *CustomClient) preprocessBan(ip, jail string) error {
    // Custom validation or processing logic
    return nil
}
```

### Integration with External Systems

```go
package integration

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"

    "github.com/ivuorinen/f2b/fail2ban"
    "github.com/ivuorinen/f2b/cmd"
)

// HTTPHandler provides HTTP API integration
type HTTPHandler struct {
    client fail2ban.Client
    logger *cmd.ContextualLogger
}

func (h *HTTPHandler) BanHandler(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // Extract parameters
    ip := r.URL.Query().Get("ip")
    jail := r.URL.Query().Get("jail")

    // Validate
    if err := fail2ban.ValidateIP(ip); err != nil {
        h.writeError(w, http.StatusBadRequest, err)
        return
    }

    // Perform operation with logging
    err := h.logger.LogOperation(ctx, "http_ban", func() error {
        _, err := h.client.BanIPWithContext(ctx, ip, jail)
        return err
    })

    if err != nil {
        h.writeError(w, http.StatusInternalServerError, err)
        return
    }

    // Success response
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "status": "success",
        "ip": ip,
        "jail": jail,
    })
}

func (h *HTTPHandler) writeError(w http.ResponseWriter, code int, err error) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(code)

    response := map[string]string{"error": err.Error()}

    // Add remediation hint if available
    if contextErr, ok := err.(*fail2ban.ContextualError); ok {
        response["hint"] = contextErr.GetRemediation()
        response["category"] = string(contextErr.GetCategory())
    }

    json.NewEncoder(w).Encode(response)
}
```

## Best Practices

### Error Handling

1. Always use contextual errors for user-facing messages
2. Provide remediation hints where possible
3. Log errors with appropriate context
4. Use error categories for systematic handling

### Context Usage

1. Always use context for operations that can timeout
2. Propagate context through the call chain
3. Add relevant context values for logging
4. Use context cancellation for cleanup

### Testing

1. Use the fluent testing framework for command tests
2. Always use mock environments for integration tests
3. Test both success and failure scenarios
4. Include timeout testing for long-running operations

### Performance

1. Use the metrics system to monitor performance
2. Implement proper caching where appropriate
3. Use object pooling for frequently allocated objects
4. Profile and optimize hot paths

This documentation provides a comprehensive overview of the f2b internal APIs and patterns.
For specific implementation details, refer to the source code and inline documentation.
