# OIDC — API

> **Status: NORMATIVE** · Last verified: 2026-10-13
> Conflicts with this document are defects. Fix them here first.

No API surface: the CLI's OIDC token store (this feature folder) is
reachable only through `xkey oidc ...` (see [cli.md](cli.md)) and, for the
xkey GUI, through `pkg/gui/services/oidc_service.go`'s Go method calls —
there is no REST, gRPC, or other network-transport surface for it. The
`pkg/oidc` package itself is a Go library (an OIDC relying-party client),
not a served API; a consumer imports it directly.
