# f2b Architecture

## Overview

f2b is designed as a modern, secure Go CLI tool for managing Fail2Ban with a focus on testability, security, and
extensibility. The architecture follows clean code principles with dependency injection, interface-based design, and
comprehensive testing.

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
- **Structure**: Each command has its own file (ban.go, unban.go, status.go, etc.)
- **Responsibilities**:
  - Command-line argument parsing and validation
  - Input sanitization and security checks
  - Business logic orchestration
  - Output formatting (plain/JSON)
  - Error handling and user feedback

### fail2ban/ Package

- **Purpose**: Core business logic and system interaction
- **Key Interfaces**:
  - `Client`: Main interface for fail2ban operations
  - `Runner`: Command execution interface
  - `SudoChecker`: Privilege validation interface

- **Implementations**:
  - `RealClient`: Production fail2ban client
  - `MockClient`: Comprehensive test double
  - `NoOpClient`: Safe fallback implementation

## Design Patterns

### Dependency Injection

- All commands receive their dependencies via constructor injection
- Enables easy testing with mock implementations
- Supports multiple backends (real, mock, noop)
- Clear separation of concerns

### Interface-Based Design

- Core functionality defined by interfaces
- Multiple implementations for different contexts
- Easy to extend with new backends
- Testable without external dependencies

### Security-First Approach

- Input validation before privilege escalation
- Secure command execution using argument arrays
- No shell string concatenation
- Comprehensive privilege checking

### Mock-Based Testing

- Extensive use of test doubles
- No real system calls in tests
- Thread-safe mock implementations
- Configurable behavior for different test scenarios

## Data Flow

### Command Execution Flow

1. **CLI Parsing**: Cobra processes command-line arguments
2. **Validation**: Input validation and sanitization
3. **Privilege Check**: Determine if sudo is required
4. **Business Logic**: Execute fail2ban operations via Client interface
5. **Output**: Format and display results (plain or JSON)

### Dependency Flow

```text
main.go
  ├── Creates root command with global config
  ├── Initializes Client implementation
  └── Executes command tree

cmd/[command].go
  ├── Receives Client interface
  ├── Validates user input
  ├── Calls Client methods
  └── Formats output

fail2ban/client.go
  ├── Implements business logic
  ├── Uses Runner for system calls
  ├── Uses SudoChecker for privileges
  └── Returns structured data
```

## Technology Stack

### Core Technologies

- **Language**: Go 1.20+
- **CLI Framework**: [Cobra](https://github.com/spf13/cobra)
- **Logging**: [Logrus](https://github.com/sirupsen/logrus) with structured output
- **Testing**: Go's built-in testing with comprehensive mocks

### Key Libraries

- **cobra**: Command-line interface framework
- **logrus**: Structured logging
- **Standard library**: Extensive use of Go stdlib for reliability

## Extension Points

### Adding New Commands

1. Create new file in `cmd/` package
2. Implement command using established patterns
3. Use dependency injection for testability
4. Add comprehensive tests with mocks

### Adding New Backends

1. Implement the `Client` interface
2. Add any new required interfaces (Runner, etc.)
3. Update main.go to support new backend
4. Add configuration options

### Adding New Output Formats

1. Extend output formatting helpers
2. Update command implementations
3. Add format validation
4. Test with existing commands

## Testing Architecture

### Test Categories

- **Unit Tests**: Individual component testing with mocks
- **Integration Tests**: End-to-end command testing
- **Security Tests**: Privilege escalation and validation testing
- **Performance Tests**: Benchmarking critical paths

### Mock Strategy

- `MockClient`: Comprehensive fail2ban operations mock
- `MockRunner`: System command execution mock
- `MockSudoChecker`: Privilege checking mock
- Thread-safe implementations with configurable behavior

## Security Architecture

### Privilege Management

- Automatic detection of user capabilities
- Smart escalation only when required
- Clear error messages for privilege issues
- No privilege leakage in tests

### Input Validation

- Comprehensive IP address validation (IPv4/IPv6)
- Jail name sanitization
- Filter name validation
- Path traversal prevention

### Safe Execution

- Argument arrays instead of shell strings
- No command injection vulnerabilities
- Proper error handling and logging
- Audit trail for privileged operations

## Configuration

### Environment Variables

- `F2B_LOG_DIR`: Fail2Ban log directory
- `F2B_FILTER_DIR`: Filter configuration directory
- `F2B_LOG_LEVEL`: Application logging level
- `F2B_LOG_FILE`: Log file destination
- `F2B_TEST_SUDO`: Enable sudo checking in tests

### Runtime Configuration

- Global flags available to all commands
- Per-command configuration options
- Output format selection
- Logging configuration

## Scalability and Performance

### Design Decisions

- Minimal external dependencies
- Efficient command execution
- Memory-conscious log processing
- Fast startup time

### Optimization Points

- Connection pooling for repeated operations
- Caching of validation results
- Efficient file processing
- Minimal memory allocations

This architecture provides a solid foundation for a secure, testable, and maintainable CLI tool while remaining simple
enough for easy contribution and extension.
