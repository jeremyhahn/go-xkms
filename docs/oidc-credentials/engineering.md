# OIDC Credentials — Engineering

> **Status: NORMATIVE** · Feature: `oidc-credentials` · Repo: `go-xkms` · Last verified: 2026-10-08

## Packages

| Package | Role |
|---|---|
| `pkg/oidc` | Shared OIDC core (xkey's local OIDC and this service) |
| `pkg/oidc/credential` | The credential service and scheduler |
| `pkg/xkms` (`servicer_oidc_credential.go`) | Transport-facing servicer |
| `pkg/compose` (`BuildOIDCCredentialService`) | Construction for xkmsd and the module host |
| `pkg/api/apierrors` (`OIDCCredentialClassOf`) | The one error classification every transport uses |
| `sdk/go` (`oidc.go`) | Re-exports, `CodexAuthFile` |

## `pkg/oidc` additions

| Symbol | Purpose |
|---|---|
| `Client.StartDeviceAuthorization`, `Client.PollDeviceToken` | One device-flow step each. `ProviderConfig.DeviceStyle`: `rfc8628` (default) or `openai` |
| `ErrAuthorizationPending`, `ErrSlowDown`, `ErrDeviceAccessDenied`, `ErrDeviceCodeExpired`, `SlowDownStep` | RFC 8628 §3.5 outcomes |
| `NewEndpointProvider(issuer, Endpoints, *http.Client)` | Explicit endpoints, no discovery; only `Token` required; every endpoint https or loopback http |
| `DiscoverProvider(ctx, issuer, client)` | Discovery without client configuration |
| `Provider.DeviceAuthorizationEndpoint` | Discovered or explicit |
| `TokenResponse.InheritFrom(prev)` | Keep a rotated refresh token; inherit an omitted one (RFC 6749 §6) |
| `TokenResponse.ExpiresAt`, `JWTExpiry`, `UnverifiedClaims` | Expiry of tokens the endpoint gave none for (unverified, scheduling only) |
| `ReloginReason`, `ReloginRequired` | `invalid_grant`, `refresh_token_{expired,reused,invalidated}`, HTTP 401, no refresh token |
| `ParseCodexAuth`, `CodexAuthTokensFile`, `CodexAccountID` | codex `auth.json` import and `chatgptAuthTokens` projection |
| `ProviderTemplate.{Flows,NoRefresh,TokenLifetime,TokenEncoding,DeviceStyle}`, `SupportsFlow` | Template capabilities; empty `Flows` is the browser login only |

Exchange and refresh now need only a token endpoint (`Provider.HasTokenEndpoint`)
rather than a fully discovered provider; for xkey, whose providers are always
complete, nothing changes. Token error bodies are also read in OpenAI's
nested `{"error":{"code","message"}}` and top-level `code` shapes.

## `pkg/oidc/credential`

```go
svc, err := credential.New(credential.RegistryBarriers(registry),
    credential.WithLeases(qrdbClient.Coordination()),
    credential.WithLeaseContext(node.ServiceContext), // embedded node only
    credential.WithAudit(auditLog))
svc.Start(0)        // the scheduler; Close stops it
defer svc.Close()

svc.Create(ctx, principal, credential.Ref{Scope: scope.Tenant, Name: "codex"},
    credential.Config{Template: "openai"}, nil)
svc.StartDeviceLogin / PollDeviceLogin / ImportTokens / Get / List / Delete / Refresh
tok, err := svc.GetAccessToken(ctx, principal, ref)
unsubscribe := svc.Subscribe(func(ev credential.Event) { ... })
```

### Invariants

- A personal credential is served to its owner only (`scope.Principal.Authorize`
  with `scope.User`); a platform principal is refused like any other.
- Names: `[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}`. Scopes: `tenant`, `user`
  (`service` is refused).
- Every write is a compare-and-swap against the bytes read (`PutIfAbsent` to
  create, `CompareAndDelete` to delete); a lost race is `ErrConcurrentUpdate`.
- A refresh holds the credential's lock, re-reads, and refreshes only if
  still due unless forced; the provider call and the write run detached from
  the caller's context (60s bound).
- A `NoRefresh` provider never has a refresh token stored.
- Endpoints are discovered once, at creation, and stored.
- `ClientSecret` never leaves the service in a `Credential` view.
- Every lease call — a refresh lock's acquire and release, the scheduler's
  acquire, renew and release — runs on the context `WithLeaseContext`
  derives; nil runs it on the caller's. The leases are the service's own
  coordination, so over an embedded go-qrdb node (v0.46+, which refuses a
  call with no identity) the host passes `Node.ServiceContext` and they run
  as xkms's service principal (`docs/datastore/engineering.md`). A bind
  failure fails the lock before any lease call, and stops the scheduler.
  Provider requests and barrier access keep the caller's context.

### Status machine

| From | Event | To |
|---|---|---|
| — | `Create` without tokens | `pending` |
| any | `Create` with tokens, `ImportTokens`, device login approved | `active` (`expired` if the imported token is past expiry) |
| `active` | refresh rejected (re-login code) | `relogin_required` + `oidc_credential.relogin_required` |
| `active` | non-refreshable token past expiry | `expired` + `oidc_credential.expired` |
| `active` | refresh succeeds | `active` + `oidc_credential.refreshed` |

### Errors

| Error | Class |
|---|---|
| `ErrNotFound` | NotFound |
| `ErrExists` | AlreadyExists |
| `ErrInvalidName`, `ErrScopeUnsupported`, `ErrInvalidConfig` (`*ConfigError`), `ErrInvalidTokens`, `*scope.InvalidScopeError` | InvalidArgument |
| `scope.ErrRefused` | PermissionDenied |
| `ErrReloginRequired` (`*RefreshError{Relogin:true}`), `ErrNoLogin`, `ErrTokenExpired`, `ErrNotRefreshable`, `ErrNoDeviceLogin`, `ErrFlowUnsupported`, `ErrConcurrentUpdate` | FailedPrecondition |
| `*RefreshError{Relogin:false}` (provider down) | Unavailable |
| `ErrCorruptRecord` (`*RecordError`) | DataLoss |
| `seal.ErrSealed`, `xkms.ErrNotConfigured` | Unavailable |

## Permissions

`oidc_credentials:{create,get,list,update,delete,token}` — xkms-owned,
ScopeSelf (`pkg/apimodule/module_scopes.go`). Admin and Owner hold all;
the built-in User role holds `get`, `list` and `token` (consumers of the
tenant's shared credentials). `update` covers import, refresh and the device
login. `token` is the only verb that returns a secret.

## Composition

- **xkmsd**: built in `Server.composedStores` once the barrier registry and
  the embedded qrdb client exist (`pkg/server/oidc_credentials.go`), closed
  at shutdown. Its leases run as the node's service principal
  (`compose.OIDCCredentialParams.LeaseContext = s.qrdbNode.ServiceContext`).
- **Module host**: `compose.Deps.Leases` from the host's qrdb client
  (`Coordination()`); the feature needs both it and the barrier registry and
  is otherwise off with its reason recorded.

## Tests

| Test | Proves |
|---|---|
| `pkg/oidc/device_test.go` | RFC 8628 and OpenAI device flows against fake servers |
| `pkg/oidc/relogin_test.go` | Re-login classification, nested error bodies |
| `pkg/oidc/codex_test.go` | `auth.json` import and `chatgptAuthTokens` projection |
| `pkg/oidc/credential/service_test.go` | Discovery, import, rotation persisted, **exactly one refresh** for 16 concurrent callers, `invalid_grant`/`refresh_token_reused`/`refresh_token_expired` → re-login + event, transient failures, device login, expiry, **scope isolation** |
| `pkg/oidc/credential/scheduler_test.go` | Scheduler refreshes before expiry; only the lease holder refreshes and a follower takes over |
| `pkg/oidc/credential/standalone_node_test.go` | A real standalone qrdb node serves the locker's lease as the service principal, and refuses an unbound lease call |
| `pkg/oidc/credential/lease_context_test.go` | Lock and scheduler lease calls run on the `WithLeaseContext` context; a bind failure makes no lease call |
| `pkg/oidc/credential/faults_test.go` | Barrier faults and lost compare-and-swap races |
| `pkg/xkms/servicer_oidc_credential_test.go` | Servicer conversions and guards |
| transport tests (`*oidc_credential*_test.go`) | Every verb on every transport |
| `xkey/cmd/xkey/cmd/oidc_server_test.go` | xkey's server mode against a real xkmsd over Unix gRPC |
| `test/integration/oidccredentials` (`make integration-test-oidc-credentials`, devcontainer) | A real xkmsd on every transport (Unix gRPC, REST, gRPC, QUIC, MCP) driven by the real xkey and xkmsctl binaries after first-boot admin login; xkey's local backend untouched; and, over a real single-replica **raft** qrdb node, two services (as two nodes, each with its own in-process locks) racing one rotating refresh -- exactly one reaches the provider -- and scheduler leadership moving to the other node when the leader stops |
| `web/app/e2e/oidc-credentials.spec.ts` (Playwright) | The console view in a real browser: re-login status, codex auth.json import request, device login to completion |

The fake OAuth server (`pkg/oidc/credential/idp_test.go`) serves discovery,
RFC 8628, and a token endpoint whose refresh tokens rotate and whose reuse is
refused the way OpenAI refuses it.
