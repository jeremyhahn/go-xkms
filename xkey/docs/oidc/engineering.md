# OIDC — Engineering

Status: current. Last verified: 2026-09-22.

This document covers the CLI's token-store surface
(`cmd/xkey/cmd/oidc_token_store.go`, `cmd/xkey/cmd/oidc.go`). For the OIDC
protocol client, discovery, and DPoP, see `xkey/pkg/oidc`'s own doc
comments; for the GUI's storage wiring, see `pkg/gui/services/oidc_service.go`.

## Exported surface

`OIDCStoredToken` is unexported-field, method-accessed:

```go
type OIDCStoredToken struct {
	Provider  string    // display name; always == Issuer in this package
	Issuer    string    // the OIDC provider's issuer URL (JWT iss claim)
	ClientID  string    // the OAuth2 client ID the token was issued to
	ExpiresAt time.Time // the access token's calculated expiry
	Scopes    []string  // granted OAuth2 scopes

	// unexported: accessToken, refreshToken, idToken *secure.Buffer
}

func (t *OIDCStoredToken) SetAccessToken(s string) error
func (t *OIDCStoredToken) AccessToken() string
func (t *OIDCStoredToken) SetRefreshToken(s string) error
func (t *OIDCStoredToken) RefreshToken() string
func (t *OIDCStoredToken) HasRefreshToken() bool
func (t *OIDCStoredToken) SetIDToken(s string) error
func (t *OIDCStoredToken) IDToken() string
func (t *OIDCStoredToken) Destroy()
```

`MarshalJSON`/`UnmarshalJSON` are the one persistence boundary where the
protected fields materialize as plain strings (`oidcStoredTokenJSON`), the
instant before a `Put` and the instant after a `Get`. There is no other
place in this package that reads or writes the token strings as plain Go
values.

`openOIDCTokenStore(cmd *cobra.Command, storeFlagPath string) (*oidcCLITokenStore, error)`
is the one function that decides where the CLI's active session lives — see
[architecture.md](architecture.md) for the decision table. `storeToken`/
`loadToken` are thin `openOIDCTokenStore` + `Save`/`Load` convenience
wrappers kept for call-site brevity and used throughout the package's own
tests.

`*oidcCLITokenStore` (unexported — the CLI has no need to export it):

```go
func (s *oidcCLITokenStore) Save(token *OIDCStoredToken) error
func (s *oidcCLITokenStore) Load() (*OIDCStoredToken, error)
func (s *oidcCLITokenStore) Clear() (existed bool, err error)
```

## Invariants

- **A token's protected fields are never a plain Go string except at the
  `MarshalJSON`/`UnmarshalJSON` boundary and at true display/transport
  boundaries** (an HTTP request body, an exec payload, a `--show-full`
  display line). Every other read goes through `AccessToken()`/
  `RefreshToken()`/`IDToken()` and is used immediately, not retained.
- **`Destroy()` is called on every `OIDCStoredToken` a command or the
  auto-refresh loop obtains**, on every return path — including the error
  paths, via `defer`. The auto-refresh loop's per-tick token is loaded and
  destroyed inside a dedicated function call (`doTick`, a function literal
  wrapping one load → refresh → save → exec cycle) specifically so `defer
  token.Destroy()` fires at the end of *that* call rather than accumulating
  across the whole life of the loop.
- **`oidcCLITokenStore` is opened once per process invocation that uses it**
  — once in `runOIDCLogin` (foreground or before spawning the background
  process), once in `runBackgroundWorker` (the detached process), once in
  each of `runOIDCToken`/`runOIDCRefresh`/`runOIDCLogout` — and the handle is
  threaded through, never re-derived mid-command. `runAutoRefresh` takes a
  `*oidcCLITokenStore` parameter for exactly this reason: so the ticking loop
  cannot accidentally re-resolve (and, for a barrier-backed store,
  re-unseal) the store on every interval.
- **No plaintext fallback on a barrier that fails to open.** A barrier that
  is initialized but cannot be unsealed (wrong password, no password
  source available) is `ErrBarrierStoreOpenFailed` wrapped in
  `ErrOIDCTokenStoreFailed` — never a silent downgrade to the plain-file
  path. Only the *absence* of a barrier (no `xkey barrier init` ever run)
  takes the plain-file path, and only after logging the standard warning.
- **`Load` on a value that does not parse as `OIDCStoredToken`, or whose
  `Issuer` is empty, returns `ErrOIDCNoTokensFound`**, not a parse error —
  this is what makes "no migration" safe: a leftover pre-#4 file (or an
  empty `{}`) reads as "log in again," never a crash.

## Errors

| Sentinel | Meaning |
|---|---|
| `ErrOIDCNoTokensFound` | Nothing is stored, or what is stored does not parse as the current format |
| `ErrOIDCTokenStoreFailed` | `Save` failed, or `openOIDCTokenStore` could not resolve a backend (wraps the underlying cause — often `ErrBarrierStoreOpenFailed`) |
| `ErrOIDCTokenLoadFailed` | A command's `Load` call failed for a reason other than "not found" |
| `ErrOIDCProtectedMemory` | The mlocked allocation for a token field failed (`secure.NewBufferFromBytes` error) |
| `ErrBarrierStoreOpenFailed` | (`barrier_store.go`) An initialized barrier exists but could not be unsealed |
| `ErrOIDCInvalidRefreshToken` | `refresh` (or the auto-refresh loop) has no refresh token to use; the loop stops |

All are typed sentinels wrapped through `SentinelCauseError`
(`errors.go`), so `errors.Is` matches both the feature-level sentinel and
the underlying cause.

## Configuration

| Flag | Commands | Meaning |
|---|---|---|
| `--token-store <path>` | `login`, `token`, `refresh`, `logout`, `status`, `stop`, `providers ...` | Default `~/.xkey/tokens.json`, used verbatim by the derived provider-config/PID/log-file paths regardless of the barrier decision; an explicit `--token-store` also selects a plain file at exactly that path for the token content itself (bypasses barrier auto-detection) |
| `--barrier-password <pw>` | `login`, `token`, `refresh`, `logout` | Barrier password, plaintext on the command line (visible in `ps`; prefer the next two) |
| `--barrier-password-file <path>` | `login`, `token`, `refresh`, `logout` | First line of the named file |
| `XKEY_BARRIER_PASSWORD` | (environment) | Read when neither flag is set; the source the detached background worker relies on via environment inheritance |
| `--data-dir <path>` / `XKEY_DATA_DIR` | (shared, `resolveDataDir`) | Overrides where the barrier-backed and no-barrier-fallback stores are rooted |

Resolution order for the barrier password: `--barrier-password`, then
`--barrier-password-file`, then `XKEY_BARRIER_PASSWORD`, then an interactive
terminal prompt (`resolveBarrierPassword`, `extension_serve.go`) — the same
order and the same function every other barrier-aware CLI command uses.

## Tests

There is no separate `oidc_token_store_test.go`; `OIDCStoredToken`'s
protected-field accessors and `oidcCLITokenStore` are exercised directly by
the files below.

| File | Covers |
|---|---|
| `oidc_test.go` | Sealed round-trip through the explicit-file path (`TestStoreAndLoadToken`), not-found and empty-store handling, JSON marshal/unmarshal parity through the protected fields, file permissions |
| `oidc_cmds_test.go` | `login`/`token`/`refresh`/`logout` end-to-end against the explicit-file path, including refresh token rotation and provider-scoped manual-endpoint refresh |
| `oidc_barrier_test.go` | The barrier decision itself: no-barrier warning + plain-file fallback, barrier-encrypted round-trip across two independent `openOIDCTokenStore` calls (proving a fresh process can unseal and read), wrong-password and no-password typed refusals, `--token-store` bypassing barrier auto-detection, and `TestRunAutoRefresh_ReusesTheSameOpenBarrier_NotReopenedPerTick` — which invalidates the barrier password on the test's `cobra.Command` immediately after the store is opened, then proves three successful refresh ticks still complete, so any hypothetical re-resolution inside the loop would have failed |

Run just this package's tests:

```
cd xkey && GOTOOLCHAIN=auto GOWORK=off go test -tags 'ble codec_json' ./cmd/xkey/cmd/... -run OIDC
```

`oidc_barrier_test.go`'s tests drive a real passphrase barrier
(`services.NewBarrierService`), so they cost real key-derivation time
(roughly 1-3s per barrier-touching test) — the same tradeoff
`oath_barrier_test.go` already accepts for the identical reason: proving the
unseal path actually works end to end, not a mock.
