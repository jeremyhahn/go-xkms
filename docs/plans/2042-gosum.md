# 2042: go.sum lines the gates add

## Cause

Lane-verify of row/8210-bigdisk-coverage-integration (tip 37707a080b17)
passed all 10 gates at 06:49Z 11-12 but refused the push: the clone was
not clean, ` M go.sum`. The gates run with GOFLAGS=-mod=mod and
GOSUMDB=sum.golang.org, so a gate resolved modules whose go.sum lines the
branch lacks and wrote them.

## Steps

Module setup as the gates (DS-7500): fresh GOMODCACHE, GOWORK=off,
GOFLAGS=-mod=mod, GOPROXY=https://proxy.golang.org, GOSUMDB=sum.golang.org.

1. `go list -deps -test -tags "<all tags>" ./...`, `go build ./...`,
   `make lint`; git status after each.
2. Commit only added go.sum lines; a changed hash for quicraft or go-luks2
   is a checksum finding, recorded here and not committed.

## Results

- `go list -deps -test -tags "codec_cbor codec_json codec_msgpack
  integration tpm2 tpm_simulator" ./...`: no go.sum change.
- `go build ./...`: root go.sum +177 lines, 0 removed or changed. All are
  `/go.mod` hash lines for modules in the build graph (cloud.google.com/go/*,
  go-openapi/swag/*, go-git, charmbracelet, swaggo, gorm, ...). Committed
  as build(deps).
- `make lint`: passes (0 issues on all modules and tag sets), no further
  go.sum change.
- No checksum finding: no quicraft or go-luks2 line changed. sdk/go,
  xkey and web/desktop go.sum unchanged.
