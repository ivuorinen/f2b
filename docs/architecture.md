# f2b Architecture

## Overview

f2b is designed as a modern, secure Go CLI tool for managing Fail2Ban with a focus on testability, security, and
extensibility. The architecture follows clean code principles with dependency injection, interface-based design,
comprehensive testing, and performance-conscious design. Built with context-aware operations, timeout handling,
object pooling, and parallel processing capabilities for enterprise-grade reliability.

## Core Components

### main.go

- **Purpose**: Entry point and application bootstrap
- **Responsibilities**:
  - Initial sudo privilege checking
  - Root command setup and execution
  - Global configuration initialization
  - Error handling and exit codes

### cmd/ Package

- **Purpose**: CLI command implementations using Cobra framework
- **Structure**: Each command has its own file (ban.go, unban.go, status.go, logs.go, etc.)
- **Responsibilities**:
  - Command-line argument parsing and validation
  - Input sanitization and security checks
  - Business logic orchestration with context-aware operations
  - Output formatting (plain/JSON)
  - Error handling and user feedback
  - Parallel processing coordination for multi-jail operations
  - Structured logging with contextual information

### fail2ban/ Package

- **Purpose**: Core business logic and system interaction

- **Key Interfaces**:

  - `Client`: Main interface for fail2ban operations with context support
  - `Runner`: Command execution interface
  - `SudoChecker`: Privilege validation interface

- **Implementations**:

  - `RealClient`: Production fail2ban client with timeout handling
  - `MockClient`: Comprehensive test double with thread-safe operations
  - `lazyClient` (cmd): defers RealClient construction until first use, so
    commands that need no client (help, version, completion) skip it

- **Advanced Features**:

  - Context-aware operations with timeout and cancellation support
  - Optimized ban record parsing with object pooling
  - Bounded caching of parsed ban-record timestamps
  - Parallel processing support for multi-jail operations

### constants/ Package

- **Purpose**: Shared constants used across all packages
  (`github.com/ivuorinen/f2b/constants`)
- **Contents**: Default and maximum timeouts, validation limits, environment
  variable names, error message formats, and output labels

## Design Patterns

### Dependency Injection

- All commands receive their dependencies via constructor injection
- Enables easy testing with mock implementations
- Supports multiple backends (real, mock)
- Clear separation of concerns

### Interface-Based Design

- Core functionality defined by interfaces
- Multiple implementations for different contexts
- Easy to extend with new backends
- Testable without external dependencies

### Security-First Approach

- Input validation before privilege escalation with caching
- Secure command execution using argument arrays
- No shell string concatenation
- Comprehensive privilege checking
- extensive sophisticated path traversal attack test cases
- Enhanced security with timeout handling preventing hanging operations

### Context-Aware Architecture

- All operations support context-based timeout and cancellation
- Graceful shutdown and resource cleanup
- Prevents hanging operations with configurable timeouts
- Enhanced error handling with context propagation

### Performance-Optimized Design

- Object pooling for memory-intensive operations
- Bounded caching of parsed ban-record timestamps
- Optimized parsing algorithms with minimal allocations
- Parallel processing capabilities for multi-jail scenarios

### Mock-Based Testing

- Extensive use of test doubles with fluent testing framework
- No real system calls in tests
- Thread-safe mock implementations
- Configurable behavior for different test scenarios
- Modern fluent testing patterns with substantial code reduction

## Data Flow

### Command Execution Flow

1. **CLI Parsing**: Cobra processes command-line arguments
1. **Context Creation**: Create context with timeout for operation
1. **Validation**: Input validation and sanitization
1. **Privilege Check**: Determine if sudo is required
1. **Business Logic**: Execute fail2ban operations via Client interface with context
1. **Parallel Processing**: Use parallel workers for multi-jail operations
1. **Output**: Format and display results (plain or JSON)

### Dependency Flow

```text
main.go
  ├── Creates root command with global config
  ├── Initializes Client implementation
  └── Executes command tree

cmd/[command].go
  ├── Receives Client interface and Config
  ├── Creates context with timeout
  ├── Validates user input
  ├── Calls Client methods with context
  └── Formats output (plain/JSON)

fail2ban/client.go
  ├── Implements business logic with context support
  ├── Uses Runner for system calls with timeout
  ├── Uses SudoChecker for privileges
  ├── Supports parallel operations
  └── Returns structured data
```

## Technology Stack

### Core Technologies

- **Language**: Go 1.26+
- **CLI Framework**: [Cobra](https://github.com/spf13/cobra)
- **Logging**: [Logrus](https://github.com/sirupsen/logrus) with structured output and contextual logging
- **Testing**: Go's built-in testing with comprehensive mocks and fluent testing framework
- **Containerization**: Multi-architecture Docker support (amd64, arm64, armv7)

### Key Libraries

- **cobra**: Command-line interface framework
- **logrus**: Structured logging with context propagation
- **Standard library**: Extensive use of Go stdlib for reliability
- **sync/atomic**: Thread-safe counters (parse statistics) and interrupt handling
- **context**: Timeout and cancellation support throughout

### Performance Technologies

- **Object Pooling**: Memory-efficient parsing with sync.Pool
- **Bounded Time Cache**: Thread-safe caching of parsed ban-record timestamps
- **Parallel Processing**: Worker pools for multi-jail operations
- **Atomic Operations**: Lock-free counters (parse statistics, interrupt handling)
- **Context-Aware Operations**: Timeout handling and graceful cancellation

## Extension Points

### Adding New Commands

1. Create new file in `cmd/` package
1. Implement command using established patterns with context support
1. Use dependency injection for testability
1. Implement fluent testing framework patterns
1. Add comprehensive tests with mocks and context-aware operations

### Adding New Backends

1. Implement the `Client` interface
1. Add any new required interfaces (Runner, etc.)
1. Update main.go to support new backend
1. Add configuration options

### Adding New Output Formats

1. Extend output formatting helpers
1. Update command implementations
1. Add format validation
1. Test with existing commands

## Testing Architecture

### Test Categories

- **Unit Tests**: Individual component testing with mocks and fluent framework
- **Integration Tests**: End-to-end command testing with context support
- **Security Tests**: Privilege escalation and validation testing (extensive path traversal cases)
- **Performance Tests**: Benchmarking critical paths with metrics collection
- **Context Tests**: Timeout and cancellation behavior testing
- **Parallel Tests**: Multi-worker concurrent operation testing

### Mock Strategy

- `MockClient`: Comprehensive fail2ban operations mock with context support
- `MockRunner`: System command execution mock with timeout handling
- `MockSudoChecker`: Privilege checking mock with thread-safe operations
- Thread-safe implementations with configurable behavior
- Fluent testing framework with substantial test code reduction
- Modern mock patterns with SetupMockEnvironmentWithSudo helper

## Security Architecture

### Privilege Management

- Automatic detection of user capabilities
- Smart escalation only when required
- Clear error messages for privilege issues
- No privilege leakage in tests

### Input Validation

- Comprehensive IP address validation (IPv4/IPv6)
- Jail name sanitization
- Filter name validation with performance optimization
- Advanced path traversal prevention (extensive sophisticated test cases)
- Unicode normalization attack protection
- Mixed case and Windows-style path protection

### Safe Execution

- Argument arrays instead of shell strings
- No command injection vulnerabilities
- Context-aware operations with timeout protection
- Proper error handling and logging with context propagation
- Audit trail for privileged operations
- Enhanced security with timeout handling preventing hanging operations

## Configuration

### Environment Variables

- `F2B_LOG_DIR`: Fail2Ban log directory
- `F2B_FILTER_DIR`: Filter configuration directory
- `F2B_LOG_LEVEL`: Application logging level
- `F2B_LOG_FILE`: Log file destination
- `F2B_COMMAND_TIMEOUT`: Timeout for individual fail2ban commands (default `30s`)
- `F2B_FILE_TIMEOUT`: Timeout for file operations (default `10s`)
- `F2B_PARALLEL_TIMEOUT`: Timeout for parallel operations (default `60s`)
- `F2B_TEST_SUDO`: Marks a test environment, so `CanUseSudo()` returns false and
  no real sudo runs (presence-checked: any non-empty value enables, unset disables)
- `F2B_VERBOSE_TESTS`: Force verbose logging in CI/tests (presence-checked)
- `ALLOW_DEV_PATHS`: Allow /tmp paths, development only (presence-checked)

### Runtime Configuration

- Global flags available to all commands
- Per-command configuration options
- Output format selection
- Logging configuration

## Performance and Monitoring Architecture

### Performance Features

- **Object Pooling**: Memory-efficient parsing with sync.Pool for ban record processing
- **Bounded Time Cache**: Thread-safe caching of parsed ban-record timestamps
- **Parallel Processing**: Worker pools for multi-jail operations with optimal CPU utilization
- **Optimized Parsing**: Ultra-fast ban record parsing with minimal allocations
- **Atomic Counters**: Lock-free parse statistics using atomic operations

### Monitoring and Observability

- **Structured Logging**: Contextual logging with request IDs and operation tracking
- **Operation Timing**: `TimedOperation` logs the duration and outcome of each operation

### Scalability Design

- **Context-Aware Operations**: All operations support timeout and cancellation
- **Parallel Processing**: Automatic scaling for multi-jail operations
- **Memory Optimization**: Object pooling and efficient memory management
- **Time-Parse Caching**: Bounded cache reduces repeated ban-record timestamp parsing
- **Resource Management**: Proper cleanup and resource lifecycle management

### Advanced Performance Features

- **Ultra-Optimized Parsing**: Custom parsing algorithms with zero-allocation techniques
- **Time Cache**: Bounded time-parsing cache reducing string-to-time conversions
- **Fast String Operations**: Custom string operations avoiding standard library overhead
- **Worker Pool Management**: Dynamic worker scaling based on operation load

This architecture provides enterprise-grade performance, comprehensive monitoring, and scalable design while maintaining
security, testability, and maintainability. The system is optimized for both single-operation efficiency and
high-throughput parallel processing scenarios.
