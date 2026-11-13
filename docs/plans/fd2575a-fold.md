# Lane fd2575a: F1 CI fold (CA m2575)

- Merges: #2062 (bb081220b388, row/2536-devcontainer-step-timeout), then #2043 (0235eda35bdf, row/2458-devcontainer-public-proxy) into row/2575-fold-ci.
- Checks: actionlint .github/workflows/*.yml, go test ./internal/buildgates/... (codec tags), test/scripts/in-toolchain-image.test.sh, make lint.
- Results to follow.
- Merge #2062: ci.yml kept the fold's preflight `if:` lines and added #2062's step `timeout-minutes:`; CHANGELOG kept both entries (#2062's under a new `### Fixed`).
- Merge #2043: compose.yaml kept main's #2057 GOPRIVATE (Gitea rewrite only) and took #2043's proxy/sum.golang.org comment, reworded for that rule; #2043's Makefile and gomodauth test merged clean.
- Fold fixes: #2043's module-resolution test now accepts the Gitea-only GOPRIVATE; the CI Gate line pattern accepts v1.35.1's trailing `# v1.35`; the `make gosec (PR tier)` step got timeout-minutes 20 (#2062's step-bound test).
- actionlint: pass.
- go test ./internal/buildgates/... (codec tags): pass.
- test/scripts/in-toolchain-image.test.sh: pass (56/56).
- make lint: pass.
