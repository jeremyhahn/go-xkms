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

Results to follow.
