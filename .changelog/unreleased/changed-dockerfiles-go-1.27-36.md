- **Every Dockerfile now builds from `golang:1.27.0`, not `golang:1.26.x` (#36).**
  #560 moved every `go.mod` and the CI `GO_VERSION` pin to Go 1.27.0 but left
  the container base images behind, so a Docker build still resolved a
  toolchain a full minor version older than the one `go.mod` requires and CI
  runs against. Every `Dockerfile*` under the repository root, `.devcontainer/`,
  `test/integration/`, and `xkey/test/integration/` now pulls
  `golang:1.27.0-bookworm` or `golang:1.27.0-alpine` (same variant each file
  already used), the `create-dockerfile` fallback target in the Makefile emits
  the same pin, and the `.github/workflows/ci.yml` `GO_VERSION` comment — which
  still said the 1.27 move was pending "the Go 1.27.0 wave" — was rewritten to
  record that #560 already made it. `go.mod` files are unchanged; this is a
  base-image-only cleanup closing out the residue of #36.
