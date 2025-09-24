# f2b Architecture

## Overview

f2b is designed as a modern, secure Go CLI tool for managing Fail2Ban with a focus on testability, security, and
extensibility. The architecture follows clean code principles with dependency injection, interface-based design,
comprehensive testing, and advanced performance monitoring. Built with context-aware operations, timeout handling,
validation caching, and parallel processing capabilities for enterprise-grade reliability.

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
- **Structure**: Each command has its own file (ban.go, unban.go, status.go, metrics.go, etc.)
- **Responsibilities**:
  - Command-line argument parsing and validation
  - Input sanitization and security checks
  - Business logic orchestration with context-aware operations
  - Output formatting (plain/JSON)
  - Error handling and user feedback
  - Performance metrics collection and monitoring
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
  - `NoOpClient`: Safe fallback implementation

- **Advanced Features**:
  - Context-aware operations with timeout and cancellation support
  - Validation caching system with thread-safe operations
  - Optimized ban record parsing with object pooling
  - Performance metrics collection and monitoring
  - Parallel processing support for multi-jail operations

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

- Input validation before privilege escalation with caching
- Secure command execution using argument arrays
- No shell string concatenation
- Comprehensive privilege checking
- 17 sophisticated path traversal attack test cases
- Enhanced security with timeout handling preventing hanging operations

### Context-Aware Architecture

- All operations support context-based timeout and cancellation
- Graceful shutdown and resource cleanup
- Prevents hanging operations with configurable timeouts
- Enhanced error handling with context propagation

### Performance-Optimized Design

- Validation result caching with thread-safe operations
- Object pooling for memory-intensive operations
- Optimized parsing algorithms with minimal allocations
- Parallel processing capabilities for multi-jail scenarios
- Real-time performance metrics collection and monitoring

### Mock-Based Testing

- Extensive use of test doubles with fluent testing framework
- No real system calls in tests
- Thread-safe mock implementations
- Configurable behavior for different test scenarios
- Modern fluent testing patterns reducing code by 60-70%

## Data Flow

### Command Execution Flow

1. **CLI Parsing**: Cobra processes command-line arguments
2. **Context Creation**: Create context with timeout for operation
3. **Validation**: Input validation with caching and sanitization
4. **Privilege Check**: Determine if sudo is required
5. **Metrics Start**: Begin performance metrics collection
6. **Business Logic**: Execute fail2ban operations via Client interface with context
7. **Parallel Processing**: Use parallel workers for multi-jail operations
8. **Metrics End**: Record operation timing and success/failure
9. **Output**: Format and display results (plain or JSON)

### Dependency Flow

```text
main.go
  ├── Creates root command with global config
  ├── Initializes Client implementation
  └── Executes command tree

cmd/[command].go
  ├── Receives Client interface and Config
  ├── Creates context with timeout
  ├── Validates user input with caching
  ├── Records metrics
  ├── Calls Client methods with context
  └── Formats output (plain/JSON)

fail2ban/client.go
  ├── Implements business logic with context support
  ├── Uses Runner for system calls with timeout
  ├── Uses SudoChecker for privileges
  ├── Uses ValidationCache for performance
  ├── Supports parallel operations
  └── Returns structured data
```

## Technology Stack

### Core Technologies

- **Language**: Go 1.25+
- **CLI Framework**: [Cobra](https://github.com/spf13/cobra)
- **Logging**: [Logrus](https://github.com/sirupsen/logrus) with structured output and contextual logging
- **Testing**: Go's built-in testing with comprehensive mocks and fluent testing framework
- **Containerization**: Multi-architecture Docker support (amd64, arm64, armv7)

### Key Libraries

- **cobra**: Command-line interface framework
- **logrus**: Structured logging with context propagation
- **Standard library**: Extensive use of Go stdlib for reliability
- **sync/atomic**: Thread-safe operations for metrics and caching
- **context**: Timeout and cancellation support throughout

### Performance Technologies

- **Object Pooling**: Memory-efficient parsing with sync.Pool
- **Validation Caching**: Thread-safe caching with sync.RWMutex
- **Parallel Processing**: Worker pools for multi-jail operations
- **Atomic Operations**: Lock-free metrics collection
- **Context-Aware Operations**: Timeout handling and graceful cancellation

## Extension Points

### Adding New Commands

1. Create new file in `cmd/` package
2. Implement command using established patterns with context support
3. Use dependency injection for testability
4. Add performance metrics collection
5. Implement fluent testing framework patterns
6. Add comprehensive tests with mocks and context-aware operations

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

- **Unit Tests**: Individual component testing with mocks and fluent framework
- **Integration Tests**: End-to-end command testing with context support
- **Security Tests**: Privilege escalation and validation testing (17 path traversal cases)
- **Performance Tests**: Benchmarking critical paths with metrics collection
- **Context Tests**: Timeout and cancellation behavior testing
- **Parallel Tests**: Multi-worker concurrent operation testing

### Mock Strategy

- `MockClient`: Comprehensive fail2ban operations mock with context support
- `MockRunner`: System command execution mock with timeout handling
- `MockSudoChecker`: Privilege checking mock with thread-safe operations
- Thread-safe implementations with configurable behavior
- Fluent testing framework reducing test code by 60-70%
- Modern mock patterns with SetupMockEnvironmentWithSudo helper

## Security Architecture

### Privilege Management

- Automatic detection of user capabilities
- Smart escalation only when required
- Clear error messages for privilege issues
- No privilege leakage in tests

### Input Validation

- Comprehensive IP address validation (IPv4/IPv6) with caching
- Jail name sanitization with validation caching
- Filter name validation with performance optimization
- Advanced path traversal prevention (17 sophisticated test cases)
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
- `F2B_TEST_SUDO`: Enable sudo checking in tests
- `F2B_VERBOSE_TESTS`: Force verbose logging in CI/tests
- `ALLOW_DEV_PATHS`: Allow /tmp paths (development only)

### Runtime Configuration

- Global flags available to all commands
- Per-command configuration options
- Output format selection
- Logging configuration

## Performance and Monitoring Architecture

### Performance Features

- **Validation Caching**: Thread-safe caching system with sync.RWMutex reducing repeated validations
- **Object Pooling**: Memory-efficient parsing with sync.Pool for ban record processing
- **Parallel Processing**: Worker pools for multi-jail operations with optimal CPU utilization
- **Optimized Parsing**: Ultra-fast ban record parsing with minimal allocations
- **Atomic Metrics**: Lock-free performance metrics collection using atomic operations

### Monitoring and Observability

- **Real-time Metrics**: Comprehensive performance metrics via `f2b metrics` command
- **Structured Logging**: Contextual logging with request IDs and operation tracking
- **Cache Analytics**: Cache hit/miss ratios and performance statistics
- **Operation Timing**: Detailed latency tracking for all operations
- **System Monitoring**: Memory usage, goroutine counts, and uptime tracking

### Scalability Design

- **Context-Aware Operations**: All operations support timeout and cancellation
- **Parallel Processing**: Automatic scaling for multi-jail operations
- **Memory Optimization**: Object pooling and efficient memory management
- **Performance Caching**: Intelligent caching reduces repeated computations
- **Resource Management**: Proper cleanup and resource lifecycle management

### Advanced Performance Features

- **Ultra-Optimized Parsing**: Custom parsing algorithms with zero-allocation techniques
- **Time Cache**: Intelligent time parsing cache reducing string-to-time conversions
- **Fast String Operations**: Custom string operations avoiding standard library overhead
- **Worker Pool Management**: Dynamic worker scaling based on operation load
- **Latency Buckets**: Detailed latency distribution tracking for performance analysis

This architecture provides enterprise-grade performance, comprehensive monitoring, and scalable design while maintaining
security, testability, and maintainability. The system is optimized for both single-operation efficiency and
high-throughput parallel processing scenarios.
