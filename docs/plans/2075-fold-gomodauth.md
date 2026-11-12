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

Results to follow.
