# 2042: Devcontainer image job steps after make coverage

- Cause: on main d55b1b73c and every PR since 11:50Z the Devcontainer image job never got past `make coverage` (lost runner or timeout), so `make security` (gosec, vuln, modverify, trivy) and `make deps-check` have not run on main's tree.
- Targets: `make gosec`, `make vuln`, `make modverify`, `make deps-check` with `XKMS_NATIVE_BUILD=1` on #2042's tree; trivy is not run here (needs Docker images), CI runs it.
- Results (fresh GOMODCACHE, -mod=mod, proxy.golang.org, XKMS_NATIVE_BUILD=1, GOMAXPROCS=2 GOGC=50):
  - `make gosec` over `./...` was OOM-killed twice in the 16g lane container; the Makefile's gosec command run on `./pkg/...` (24g container), then on `./internal/... ./cmd/...` and the rest: pass, Issues 0 in both.
  - `make vuln`: FAIL, outside cause. GO-2026-6911 (SSRF and credential leak via an unvalidated Location header) in github.com/mark3labs/mcp-go v1.5.0, Fixed in: N/A. First trace: pkg/mcptool/client.go:280:53 mcptool.Client.Connect calls client.NewStreamableHttpClient. No fixed release exists to bump to.
  - `make modverify`: pass (all modules verified).
  - `make deps-check`: pass (only non-failing lag and held-version notes).
  - `make lint`: pass (0 issues in every module and tag set).
  - trivy: not run here (needs Docker images); CI runs it.
