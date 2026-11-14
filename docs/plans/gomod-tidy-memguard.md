# Plan: tidy the root module (memguard direct)

Epic #1794 (E4 Test standard and suite audit), lane mf8654t.

## Cause

On main d55b1b73c, `make lint` (lanes cr2020, cr1962c) rewrites go.mod:
github.com/awnumar/memguard v0.23.0 moves from the indirect block to the
direct block, and about 177 lines are added to go.sum. The root module is
not tidy, so every deps-check or readonly build on main drifts.

## Method

1. Module setup as CI (DS-7500): fresh GOMODCACHE, GOWORK=off,
   GOFLAGS=-mod=mod, GOPROXY=https://proxy.golang.org, empty
   GOPRIVATE/GONOPROXY.
2. `go mod tidy` in the root module. Accept only: memguard to the direct
   block and go.sum lines added. Any version change or quicraft/luks2
   checksum mismatch stops the lane.
3. Commit go.mod + go.sum as build(deps).
4. Checks: `GOFLAGS=-mod=readonly go build ./...`; a second `go mod tidy`
   with `git diff --exit-code go.mod go.sum`; `make lint`.

Out of scope: any .go file, nested modules (sdk/go, xkey, web/desktop),
Makefile, workflows.

## Results

Departs from the expected edit: under the CI setup, `go mod tidy` leaves
go.mod unchanged and removes 179 stale go.sum lines (none added). memguard
v0.23.0 stays indirect: its only importer is
test/lint/secure/_fixtures/bad/bad.go, an underscore directory go ignores.
No module version changed; no quicraft/luks2 checksum mismatch.

- `GOFLAGS=-mod=readonly go build ./...`: pass.
- Second `go mod tidy`: go.mod and go.sum unchanged (idempotent).
- `make lint` on the tidied tree: pass ("Linting complete"), and it left
  go.mod/go.sum unchanged. So the memguard move and the +177 go.sum lines
  that lanes cr2020/cr1962c saw do not reproduce under the CI env. They
  probably come from those lanes' module env (a shared/warm GOMODCACHE or
  GOPRIVATE/GONOPROXY not cleared).
- The secure-analyzer builds go-qrdb's analyzer from the root module
  (scripts/secure-analyzer.sh:104). With the tidied go.sum it still builds
  under `-mod=readonly`.
