- **`make build` works on a host whose Go is older than the module declares.**
  The module has required Go 1.26.7 since 2026-08-27 and the fleet pins
  `GOTOOLCHAIN=local` on hosts, so a host on 1.26.4 refused every Make target
  (`go: go.mod requires go >= 1.26.7`) while the Docker builder, running
  under `GOTOOLCHAIN=auto`, downloaded the right one. The Makefile now
  selects the toolchain go.mod declares for every recipe, so the host go only
  bootstraps that exact version and the build is the same on every host and
  in CI. `make GOTOOLCHAIN=local ...` restores the host's own go.
