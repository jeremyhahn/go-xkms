# Release engineering — API

**Status:** implemented.
**Last verified:** 2026-09-06.

No programmatic API surface: releases are cut by an operator or a project agent
through `make release-alpha`, and nothing in the library, the SDK or any
transport exposes them. Publishing is deliberately not reachable from a running
service.

The one contract worth naming is what a release **produces**, which consumers do
depend on:

- three annotated, signed tags at one commit — `v<V>`, `sdk/go/v<V>`,
  `xkey/v<V>` — published atomically;
- a commit whose `VERSION` file holds `<V>` and whose four `go.mod` files pin
  every intra-repo module at `v<V>`;
- a `CHANGELOG.md` carrying `## [<V>]` at the start of a line, which
  `.github/workflows/release.yml` validates after the tag lands.

A consumer resolving `github.com/jeremyhahn/go-xkms/sdk/go@v<V>` with
`GOWORK=off` therefore gets a module whose own requires resolve to the same
release, which is the property the pin bump exists to guarantee and which no
in-repo build can observe.
