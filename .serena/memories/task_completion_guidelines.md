# f2b Task Completion Guidelines (Updated 2025-09-13)

## When a Task is Completed - MANDATORY CHECKLIST

**IMPORTANT**: ALL linting errors are considered BLOCKING. Never compromise on code quality.

### 1. Code Quality Pipeline (REQUIRED)

```bash
# Format code first (automatic fixes)
make fmt                    # Go formatting

# Run comprehensive linting (ALL must pass)
make lint                   # Pre-commit unified linting
# OR individually if debugging:
make lint-go               # Go linting via golangci-lint
make lint-md               # Markdown linting
make lint-yaml             # YAML linting
make lint-actions          # GitHub Actions linting
```

### 2. Testing Requirements (REQUIRED)

```bash
# Run all tests
make test                  # Basic test suite
make test-coverage         # With coverage analysis

# Security-focused testing
F2B_TEST_SUDO=true go test ./fail2ban -run TestSudo
go test ./fail2ban -run TestPath  # Path traversal tests
```

### 3. Build Verification (REQUIRED)

```bash
# Verify build succeeds
make build                 # Development build
make release-dry-run       # Release preparation test
```

### 4. Dependency Management (NEW 2025-09-13)

```bash
# Check for dependency updates when relevant
make update-deps           # Update all Go dependencies
go list -u -m all          # Check for available updates
```

### 5. Full CI Pipeline (RECOMMENDED)

```bash
make ci                    # Complete CI pipeline (format + lint + test)
make ci-coverage           # CI with coverage reporting
```

## EditorConfig Compliance (BLOCKING)

**CRITICAL**: All code MUST follow .editorconfig rules:

- **General files**: 2 spaces, max 120 chars, final newline
- **Go files**: Tab indentation, width 2
- **Makefiles**: Tab indentation

EditorConfig violations are **BLOCKING ERRORS** and must be fixed immediately.

## Linting Standards (BLOCKING)

### ALL linting issues are BLOCKING

- **Never simplify linting config** to make tests pass
- **Read error messages carefully** and compare against schema
- **Fix the code**, not the configuration
- **Schema is truth** - blindly follow it

### golangci-lint Requirements (20+ linters enabled)

Must pass ALL enabled linters:

- Core: errcheck, govet, ineffassign, staticcheck, unused
- Security: gosec
- Quality: revive, gocyclo, misspell, prealloc
- Context: contextcheck, containedctx, durationcheck
- Error handling: errorlint, errname, nilnil

### Pre-commit Requirements (10+ hooks)

ALL hooks must pass:

- trailing-whitespace, end-of-file-fixer
- golangci-lint, yamlfmt, markdownlint
- markdown-link-check, actionlint
- editorconfig-checker, checkov

## Testing Standards

### Modern Fluent Framework (PREFERRED)

```go
NewCommandTest(t, "command").
    WithArgs("arg1", "arg2").
    WithMockBuilder(builder).
    ExpectSuccess().
    Run()
```

### Coverage Requirements

- **Current Status**: Comprehensive coverage across all packages (cmd/, fail2ban/)
- All new code should maintain or improve coverage
- Above industry standards (typically 60-70%)

### Security Testing (MANDATORY)

- **Never execute real sudo** in tests
- **Test extensive path traversal protections**
- **Context-aware testing** with timeout simulation
- **Thread safety testing** for concurrent operations

## Security Checklist (MANDATORY)

### Before ANY Privilege Operations

1. **Input validation** - all user input validated
2. **Path validation** - extensive attack vector checks
3. **Context validation** - timeout handling
4. **Command arrays** - never shell strings

### Code Review Security

- **No shell injection** vulnerabilities
- **Proper error handling** without information leakage
- **Context propagation** throughout call chain
- **Resource cleanup** in defer statements

## Documentation Requirements

### Code Documentation

- **Exported functions** must have comments
- **Security-sensitive code** requires detailed comments
- **Complex algorithms** need explanation comments

### Link Validation (AUTOMATIC)

- All markdown links checked via markdown-link-check
- External links must be valid and accessible
- GitHub URLs may be rate-limited (handled by config)

## Release Readiness Checklist

### Before Any Release

```bash
make release-check         # Validate GoReleaser config
make release-dry-run       # Test without artifacts
go build -ldflags "-X github.com/ivuorinen/f2b/cmd.version=test" .
```

### Multi-Architecture Verification

```bash
# Test builds for all supported platforms
GOOS=linux GOARCH=amd64 go build .
GOOS=linux GOARCH=arm64 go build .
GOOS=darwin GOARCH=amd64 go build .
GOOS=darwin GOARCH=arm64 go build .
GOOS=windows GOARCH=amd64 go build .
```

## Error Resolution Principles

### Linting Errors (BLOCKING)

1. **Read the error message** carefully
2. **Understand the rule** being violated
3. **Fix the code** to comply with the rule
4. **Never modify linting configuration** unless explicitly told
5. **Verify fix** by re-running the specific linter

### Test Failures (BLOCKING)

1. **Understand the failure** before fixing
2. **Maintain test coverage** when making changes
3. **Use fluent testing framework** for new tests
4. **Mock external dependencies** properly

### Build Failures (BLOCKING)

1. **Check Go version compatibility** (Go 1.25+ current requirement)
2. **Verify all dependencies** are available and updated
3. **Ensure proper import paths** with local prefix
4. **Test across platforms** if applicable

## Version Compatibility

### Current Requirements

- **Go Version**: Latest stable (1.25+)
- **Core Dependencies**:
  - spf13/cobra (latest stable - CLI framework)
  - spf13/pflag (latest stable - flag parsing)
  - sirupsen/logrus (latest stable - structured logging)
  - stretchr/testify (latest stable - testing framework)
  - golang.org/x/sys (latest stable - system interfaces)
- **Development Tools**: All development dependencies should be at latest stable versions

Use `make update-deps` to ensure all dependencies are current.

## NEVER COMMIT WITHOUT

- [ ] All linting checks passing (`make lint`)
- [ ] All tests passing (`make test`)
- [ ] Build successful (`make build`)
- [ ] EditorConfig compliance verified
- [ ] Security guidelines followed
- [ ] Code coverage maintained or improved
- [ ] Dependencies up-to-date (check with `make update-deps` if relevant)
