# Development Documentation

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: index of the contributor-facing development documents in this folder.

This directory contains development-focused documentation for contributors and maintainers.

## Available Documents

- [encoding-interop-status.md](encoding-interop-status.md) - Archived record of the completed JWK/JWT/JWE integration test plan
- [errors.md](errors.md) - Typed-error conventions (`pkg/errs` types, sentinels, sentinel-preservation rule)
- [lint-gates.md](lint-gates.md) - What CI's Lint job enforces (gofmt, go vet, golangci-lint, secure-analyzer) and the local Make target for each

## For Other Documentation

- **Architecture**: See [docs/architecture/](../architecture/)
- **Usage Guides**: See [xkey/docs/usage/](../../xkey/docs/usage/)
- **Backend Guides**: See [docs/crypto-backends/](../crypto-backends/)
- **Testing**: See [docs/testing/](../testing/)
- **Configuration**: See [docs/configuration/](../configuration/)
- **Deployment**: See [docs/deployment/](../deployment/)

## Contributing

When adding development documentation:
1. Use clear, descriptive file names (lowercase with hyphens)
2. Include status and priority information
3. Link to related code or issues
4. Keep documentation concise and actionable
