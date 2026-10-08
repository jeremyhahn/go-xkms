# Datastore — API

> **Status: NORMATIVE** · Feature: `datastore` · Repo: `go-xkms` · Last verified: 2026-10-07

No API surface: verified — none of REST (`pkg/api/rest/routes.go`), gRPC
(`pkg/api/grpc`), or MCP (`pkg/api/mcp`) declares a route, RPC, or tool for
datastore selection or inspection. There is no `GET /api/v1/datastore/status`
and no equivalent RPC.

The datastore is a server-side configuration choice (see engineering.md),
not a runtime or per-request one, so there is nothing for a client to select
or query. Every capability that persists data through this layer exposes its
own API surface instead — see, for example,
[`../key-management/api.md`](../key-management/api.md) and
[`../certificate-authority/api.md`](../certificate-authority/api.md).

The one exception is clustering, which does have request-routing effects
visible at the API layer (leader redirects on a write sent to a follower).
That is documented in [`../clustering/api.md`](../clustering/api.md), not
here — it is a property of clustering, not of datastore selection.
