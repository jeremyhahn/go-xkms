# Release engineering — API

**Status:** implemented.
**Last verified:** 2026-10-08.

No programmatic API surface: releases are cut by an operator or a project agent
through `make release-alpha` (prepare) and `make release-tag` (publish, once
that pull request has merged — go-xkms#419, go-xkms#211), and nothing in the
library, the SDK or any transport exposes them. Publishing is deliberately not
reachable from a running service.

The scripts are themselves clients of the forge's API. `release-alpha.sh`
calls two endpoints, as the project agent (`FORGE_TOKEN`):

- `GET /api/v1/repos/{owner}/{repo}`, which must answer `200` before anything
  is fetched or written;
- `POST /api/v1/repos/{owner}/{repo}/pulls`, with `title`
  `chore(release): v<V>`, `head` `release/v<V>` and `base` the release branch,
  which must answer `201`.

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
