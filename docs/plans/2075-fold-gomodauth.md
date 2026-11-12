# F1 (#2075): keep main's GOMODAUTH_GOPRIVATE default

## Cause

F1 tip 7f426f61e0 failed lane-verify gate 10 (make coverage -> test-scripts,
Makefile:1119). test/scripts/gomodauth.test.sh reported
`FAIL count2: <compose file> GOPRIVATE want: github.com/jeremyhahn/*` for
build/docker/devcontainer/compose.yaml and nine test/integration/*/docker-compose.yml.

The #2043 merge (6afcec4100) set `GOMODAUTH_GOPRIVATE := $(GOPRIVATE)` in both
Gitea-rewrite branches; GOPRIVATE is empty by default. Main d55b1b73c7
(#2057, CA m2514) sets github.com/jeremyhahn/* there, and main's test pins it.

## Fix

Makefile GOMODAUTH block back to main's two lines:

- GIT_CONFIG_KEY_0 branch: `$(if $(GOPRIVATE),$(GOPRIVATE),github.com/jeremyhahn/*)`
- FORGE_MODULE_TOKEN/GITEA_HOST branch: `github.com/jeremyhahn/*`
- final else branch unchanged (no GOPRIVATE on the public path).

## Checks

1. `bash test/scripts/gomodauth.test.sh` -> FAIL=0
2. `make test-scripts`
3. `make lint`

## Results

1. gomodauth.test.sh: 240 passed, 3 failed. The count2 compose GOPRIVATE
   checks now pass. Still failing: `runner: gomodauth secret`,
   `count2: gomodauth secret` and `token: gomodauth secret`. They want
   `export GOPRIVATE=` (empty), but this fix stages `github.com/jeremyhahn/*`.
   The #2043 merge (6afcec4100, from c7453558d) changed those three
   expectations from main's `github.com/jeremyhahn/*` to empty, so the
   folded test disagrees with itself: the same sections want `$GLOB` in the
   compose files. Fix, outside this lane's file list: restore main's three
   secret lines in test/scripts/gomodauth.test.sh and keep #2043's new
   "caller-supplied GOPRIVATE" section, which passes with main's Makefile.
2. make test-scripts: fails at Makefile:1115 on the same 3 gomodauth checks.
3. make lint: pass (0 issues in every module and tag set).

## Results after the test fix (fci2075c)

The three secret checks in test/scripts/gomodauth.test.sh are back to
main's `export GOPRIVATE=github.com/jeremyhahn/*`; #2043's
"caller-supplied GOPRIVATE" section is kept.

1. gomodauth.test.sh: 243 passed, 0 failed.
2. make test-scripts: pass (rc=0, "Shell script tests passed").
