# Code Style and Conventions

## Go Style
Follows the [Google Go Style Guide](https://google.github.io/styleguide/go/guide). Priority order: Clarity > Simplicity > Concision > Maintainability > Consistency.

## Error Handling
- **ALWAYS** declare errors as typed errors (custom error types), never `fmt.Errorf`
- **NEVER** ignore errors with `_`
- Each package has an `errors.go` with typed errors

## Architecture Patterns
- Clean abstraction layers: never call business logic directly from public interfaces
- Service layer for encapsulation between public API and business logic
- Map-based dispatch instead of large switch statements (O(1) lookup)
- Prefer lock-free algorithms (sync/atomic) over mutexes
- Use native Go atomic package, not pointer magic or unsafe operations
- Build tags for conditional compilation of backends

## Code Principles
- DRY (Don't Repeat Yourself)
- YAGNI (You Ain't Gonna Need It)
- KISS (Keep It Simple)
- No over-engineering; only make changes that are directly needed
- Write performance-conscious code (low latency, high throughput)
- Never use stub/mock implementations without explicit approval — always production-grade

## Naming
- Test files: `$SOURCE_FILE_NAME_test.go` (consolidate tests for a source file)
- Never use generic names like `_coverage_boost_test.go` or `_additional_coverage_test.go`
- Package names follow Go conventions (lowercase, no underscores)

## Documentation
- Keep docs in `docs/` folder, organized in subfolders
- Keep documentation concise
- Don't create superfluous .md files; only when asked
- Fully document packages/features upon completion

## Testing Conventions
- TDD with 90+% code coverage goal
- Every function needs at least 2 tests: happy path + error handling
- **NEVER** use skip guards or `-short` flags
- Unit tests: fast, in-memory, no host modifications, no blocking operations
- Integration tests: Docker-based, E2E with real services, in devcontainer
- Prefer running single tests for velocity, not whole suite
- Don't write tests just for coverage; they must be meaningful

## Build Tags
Common tags: `pkcs8`, `pkcs11`, `awskms`, `gcpkms`, `azurekv`, `vault`, `frost`, `tpm_simulator`, `fido2`, `webauthn`, `integration`, `codec_cbor`, `codec_json`, `codec_msgpack`

## Formatting & Linting
- `gofmt -s -w .` for formatting
- `golangci-lint` for linting
- `gosec` for security scanning (with documented exclusions: G103, G104, G115, G304, G401, G407, G505)
- `govulncheck` for vulnerability scanning

## Git
- **NEVER** run git commands in this repository (per CLAUDE.md)
