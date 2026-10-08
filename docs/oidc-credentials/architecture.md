# OIDC Credentials — Architecture

> **Status: NORMATIVE** · Feature: `oidc-credentials` · Repo: `go-xkms` · Last verified: 2026-10-08

## What it is

xkmsd holds named OAuth 2.0 / OIDC logins and keeps them fresh. A consumer —
a person, a CLI, or a workload such as an AI agent account in an embedding
host — asks for a **current access token by reference**
(`GetAccessToken`); it never holds the refresh token. The server refreshes
each credential before its access token expires and records when a provider
rejects a refresh, so the consumer sees "re-login needed" instead of a token
that silently stopped working.

The feature is **added alongside** xkey's local OIDC. This feature's own
records, locking, and scheduler below are unchanged. What did change is
`pkg/oidc`'s own token *cache* (xkey's local login, and xkmsctl/xkey's own
process, not this feature's tenant-shared credentials): its persistence
moved off a raw `storage.Backend` `Put`/`Get` pair onto go-qrdb's DAO/entity
pattern (`pkg/oidc.DAOStore`, on the injected `qrdbsdk.DAOFactory`) — see
[xkey/docs/oidc](../../xkey/docs/oidc/) and
[`../datastore/architecture.md`](../datastore/architecture.md)'s
"Feature-owned databases". `pkg/oidc/credential` (this feature) was not
touched: it stays on the tenant-barrier `Backend` it already uses for
compare-and-swap refresh locking (see "Ownership and storage" below), a
different and still-correct pattern for a different problem (per-tenant
sealing, not a DAO's typed entity shape).

## Components

```
            xkmsctl oidc · xkey oidc (server mode) · web console · SDKs
                                   │
            REST · gRPC · Unix · QUIC · MCP · embedded  (oidc_credentials:*)
                                   │
              pkg/xkms  XKMSService.OIDCCredential*   (principal from identity)
                                   │
              pkg/oidc/credential  Service ── Scheduler (leader-elected)
                 │            │            │
      tenant barriers    qrdb leases    pkg/oidc  (client, discovery, device
      (pkg/scope layout) (lock/leader)            flow, refresh, templates)
```

- **`pkg/oidc`** — the shared OIDC core, used by xkey's local OIDC and by
  this service: authorization code + PKCE, discovery, DPoP, refresh, the
  RFC 8628 device flow and OpenAI's own device login, providers configured
  without discovery (`NewEndpointProvider`), rotating-refresh handling
  (`TokenResponse.InheritFrom`), re-login classification (`ReloginReason`),
  the provider templates, and the codex `auth.json` codec.
- **`pkg/oidc/credential`** — the service: records, locking, refresh,
  device logins, imports, events, and the scheduler.
- **`pkg/xkms`** — `XKMSService` converts the transport types and passes the
  caller's `scope.Principal`; every transport calls it.
- **`pkg/compose`** — `BuildOIDCCredentialService`, the one construction
  path for xkmsd and an embedding host's module.

## Ownership and storage

A credential is **tenant-shared** (`scope.Tenant`, visible to every user of
the tenant) or **personal** (`scope.User`, visible only to its owner — never
to a system-tenant caller). Records use the `pkg/scope` layout on the
tenant's barrier:

```
{tenant}/oidc/shared/{name}.json
{tenant}/oidc/users/{subject}/{name}.json
```

A personal credential is sealed by the tenant barrier, not by a per-user
key: the server must read it unattended to refresh it. Its privacy is the
authorization rule, which only the owner passes. (The password vault's
personal entries, which are never used unattended, are sealed with the
user's own key; OIDC credentials cannot be.)

## Refresh, rotation and locking

`GetAccessToken` refreshes first when the access token is inside the
credential's refresh margin (default five minutes, codex's own window).
OpenAI rotates refresh tokens on use: two parties redeeming the same refresh
token lose the login. So a refresh runs under a **per-credential lock** —
an in-process mutex plus, on a raft cluster, a qrdb lease on
`xkms/oidc/lock/<hash of the record key>` — re-reads the record once the
lock is held, refreshes only if still due, and writes the result with the
barrier's **compare-and-swap** against the exact record it read. Of any
number of concurrent callers exactly one refreshes; the rest read its result.

The refresh request and the write of its result are detached from the
caller's context and bounded by their own timeout: a caller that gives up
between the provider's answer and the write must not cost the credential
its rotated token.

A refresh the provider **rejects** — `invalid_grant`, `refresh_token_expired`,
`refresh_token_reused`, `refresh_token_invalidated`, or HTTP 401 — moves the
credential to `relogin_required` and emits `oidc_credential.relogin_required`.
Any other failure (network, 5xx, 429) is kept as `last_error`; a token that
is still valid keeps being served.

A provider without refresh (the `anthropic` template: the one-year
`claude setup-token` token) is imported and tracked to its expiry; past it
the credential moves to `expired` and emits `oidc_credential.expired`.

## The scheduler

`Service.Start` runs a scheduler on every node. The node holding the qrdb
lease `xkms/oidc/scheduler` is the leader: every interval (30s) it refreshes
each credential that is due in every unsealed tenant, and renews its lease.
The others campaign each interval and take over when the leader's lease
lapses.

Since go-qrdb v0.27 a standalone node serves leases with raft mode's
semantics, so the service takes the same leases on either run mode. A node
whose storage backend cannot serve leases (go-qrdb's file and objstore
backends) refuses the lease family with a typed error
(`transport.CapabilityUnsupportedError` over a network transport;
`embedded.NilServiceError{Service: "LeaseServicer"}` from an in-process
`node.Client()`). The service recognises that refusal and, on that
single-process node, relies on its in-process mutex and is its own leader —
qrdb decides, not configuration that could be wrong.

## Logins

- **Device flow** — the server runs it: `DeviceStart` returns the user code
  and verification URI, `DevicePoll` polls the provider once. RFC 8628, or
  OpenAI's own protocol (`/api/accounts/deviceauth/usercode`, `/token`,
  then an authorization-code exchange), taken from the codex CLI.
- **Import** — tokens obtained elsewhere: a codex `auth.json`, a token
  printed by a CLI, or a browser login a client ran locally.

The browser authorization-code flow needs a redirect to a loopback port on
the user's machine, which a server cannot own; a client runs it (xkey's
local OIDC) and imports the result.

## Consumers that run the codex CLI

A host that gives a workload a codex login asks `GetAccessToken` for the
current token and writes `$CODEX_HOME/auth.json` with
`CodexAuthTokensFile` (SDK: `CodexAuthFile`) in the **`chatgptAuthTokens`**
mode. In that mode codex uses the tokens and never refreshes them (its
`refresh_token_from_authority_impl` returns early for the mode and
`should_refresh_proactively` answers false — openai/codex
`codex-rs/login/src/auth/manager.rs`), and the file holds no refresh token.
The server stays the only party that redeems it, so rotation cannot be
broken by a workload.

The projection lives in xkms beside the importer because both are the same
format knowledge; the host only writes the bytes.

## Rejected alternatives

- **Container write-back** (workloads refreshing and writing tokens back):
  removed by owner ruling. Every refresh happens in the server.
- **A per-user key for personal credentials**: the scheduler could not
  refresh them unattended.
- **CAS-emulated leases on a standalone node**: inventing a lock primitive;
  qrdb's typed refusal already says the node is one process.
- **Discovery on every refresh**: endpoints are discovered once, at
  creation, and recorded on the credential.
- **The Anthropic interactive OAuth client**: Anthropic documents no OAuth
  client or refresh endpoint for use outside Claude Code, and states that
  subscription OAuth tokens may not be used in other tools. The `anthropic`
  template is the documented long-lived token, imported and never refreshed.
