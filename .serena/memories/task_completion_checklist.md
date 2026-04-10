# Task Completion Checklist

When a task is completed, ensure the following steps are done:

## Code Quality
1. Run `make fmt` to format code
2. Run `make vet` to check for issues
3. Run `make lint` to run linters (if golangci-lint is available)

## Testing
1. Run relevant unit tests: `make test-<package>` for the modified package(s)
2. Ensure 90+% code coverage: `make coverage-<package>`
3. Run integration tests if applicable: `make integration-test-<package>`
4. Every new function must have at least 2 tests (happy path + error case)
5. No skip guards or `-short` flags in tests

## Documentation
1. Update docs in `docs/` folder if feature/API changed
2. Update examples if usage changed
3. Keep documentation concise and organized

## Security
1. No command injection, XSS, SQL injection, or OWASP top 10 vulnerabilities
2. Run `make gosec` if security-sensitive code was modified
3. Typed errors throughout; no `fmt.Errorf`

## Architecture
1. Clean abstraction layers maintained
2. No stub implementations (production-grade only)
3. Map-based dispatch for routing logic
4. Lock-free algorithms preferred over mutexes
5. Build tags properly set for conditional compilation

## Integration Tests
- Always run in Docker (devcontainer or docker-compose)
- Never run on host OS
- Each test/integration/<pkg>/ has its own docker-compose.yml
- Use `run_in_devcontainer` Makefile helper for devcontainer-based tests
