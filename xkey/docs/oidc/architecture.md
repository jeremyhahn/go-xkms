# OIDC — Architecture

Status: current. Last verified: 2026-09-23.

## Scope

xkey's `pkg/oidc` package is an OpenID Connect relying party: PKCE
authorization-code login against any OIDC-compliant provider, an AWS Console
native DPoP login, provider configuration management, and an access/refresh
token lifecycle including a background auto-refresh worker. This document
covers the CLI's (`xkey oidc ...`) session storage architecture specifically
— where the access, refresh, and ID tokens obtained from a provider live at
rest and in memory. The OIDC protocol client (`pkg/oidc/client.go`),
discovery (`pkg/oidc/provider.go`), and DPoP (`pkg/oidc/dpop.go`) are out of
scope here; see the package's own doc comments.

The xkey GUI's OIDC service (`pkg/gui/services/oidc_service.go`) is a
separate consumer of the same `pkg/oidc.TokenStore` interface with its own
storage wiring (`SetDataDir`/`SetBackend`); this document is about the CLI's
`xkey oidc login`/`token`/`refresh`/`logout` commands only.

The AWS login *mechanism* itself (not its storage) is shared rather than
duplicated: `xkey/pkg/oidc/aws.Login` runs the DPoP-bound PKCE authorization
flow — the callback listener, the browser hand-off, the code exchange — and
`aws.RefreshCredentials` runs one credential refresh. Both the CLI's `xkey
oidc aws` command and the GUI's `OIDCService.Login` (for an
`OIDCProviderTypeAWS` provider) call these; `xkey/pkg/oidc/handlers.NewForMode`
is the shared output-mode dispatch (`aws-credentials`/`json`/`exec`/`none`)
both use to turn the resulting credentials into a credentials-file write, a
JSON print, or an exec invocation. The CLI layers its own session
persistence, background-refresh process management and terminal output on
top; the GUI layers its own `OIDCLoginResult`/auto-refresh-goroutine wiring.
Neither reimplements the OAuth exchange itself.

## The problem

Before go-xkms#4, `cmd/xkey/cmd/oidc.go` persisted the CLI's active OIDC
session as plaintext JSON at a fixed path (`~/.xkey/tokens.json`), through a
hand-rolled `os.ReadFile`/`os.WriteFile` pair independent of every other
secret-bearing CLI store. That put an OAuth2 access token, refresh token,
and ID token — the CLI's most sensitive artifact, since the refresh token is
a durable bearer credential for the provider account — on disk unencrypted
whenever a barrier was available and protecting every other CLI secret
(`xkey oath`, `xkey fido2 --storage barrier`, the Noise pairing key), and
held them as ordinary Go strings in the process the whole time they were in
memory.

## The decision

The CLI OIDC token store moves behind the same barrier-first, warn-and-proceed
decision every other CLI secret store already makes, and holds the token
values in protected memory while resident in the process — two independent,
complementary properties:

1. **At rest**: `openOIDCTokenStore` (`cmd/xkey/cmd/oidc_token_store.go`)
   calls `resolveSecretStoreBackend` (`barrier_store.go`) — the exact
   function `xkey oath` and `xkey fido2` already call — to decide whether a
   barrier is initialized. A barrier-encrypted `xkms.StorageBackend` is used
   when one is; the historical unencrypted file is used, with the one
   standard "unencrypted at rest" warning `resolveSecretStoreBackend` already
   logs, when none is. There is no second encryption scheme, no separate
   wrapping key, and no code path that decides this question independently
   of `resolveSecretStoreBackend`.

2. **In memory**: `OIDCStoredToken`'s `AccessToken`, `RefreshToken`, and
   `IDToken` fields are `*secure.Buffer` (`sdk/go/secure`) — mlocked,
   guard-paged memory — rather than plain Go strings, reached only through
   accessor and setter methods. This mirrors `xkey/pkg/oath`'s `Credential`,
   which holds its shared TOTP/HOTP secret the same way. `Destroy()` wipes
   the buffers; every command path and the auto-refresh loop calls it once
   the token is no longer needed.

Both properties compose through one storage primitive:
`xkms.StorageBackend.Put`/`Get`/`Delete`, keyed at a single fixed key
(`oidc/tokens.json` when not overridden), holding the JSON serialization of
one `OIDCStoredToken`. Property 1 decides which concrete `StorageBackend`
implementation backs that key (barrier-encrypted vs. plain file); property 2
is orthogonal and applies either way.

## Why one active session, not one per issuer

`pkg/oidc.TokenStore` (used by the GUI) indexes tokens by issuer, supporting
multiple concurrent provider sessions. The CLI never adopted that model: a
`login` always replaces whatever was previously stored, `token`/`refresh`/
`logout` always operate on that one stored entry, and the `--provider` flag
on `refresh` selects which provider's *endpoints* to use, not which of
several stored sessions to update. `openOIDCTokenStore` keeps this
single-active-session behavior deliberately — extending the CLI to concurrent
multi-provider sessions is a product decision independent of go-xkms#4 and
is not made here. `oidcCLITokenStore` is therefore a single Put/Get/Delete
key, not the issuer-keyed `pkg/oidc.BackendTokenStore`/`FileTokenStore` the
GUI uses; reusing those would have required inventing a synthetic per-CLI
issuer key with no real meaning.

## No migration, by design

go-xkms#4 deletes the CLI's ad hoc plaintext format outright:
`storeToken`/`loadToken`/`saveTokenStore` over `os.WriteFile`/`os.ReadFile`
and the `OIDCTokenStore{Tokens []OIDCStoredToken}` envelope are gone, not
deprecated. `oidcCLITokenStore.Load` treats a value that fails to unmarshal
as the current format — including a file left over in the old shape, if one
happens to still exist at the (different) default location — the same as
"nothing stored": `ErrOIDCNoTokensFound`, prompting the operator to run
`xkey oidc login` again, never a hard parse failure. The stack's
pre-release-alpha policy (no deprecated fields, no legacy read paths, no
compat shims) makes this the correct choice rather than carrying a
migration path for a data format a handful of local CLI users held
temporarily.

## Where the store lives

| Condition | Location |
|---|---|
| No `--token-store` override, barrier initialized | `<xkey data dir>` via the barrier-backed `xkms.StorageBackend`, key `oidc/tokens.json` |
| No `--token-store` override, no barrier | `<xkey data dir>/oidc/tokens.json`, plain file |
| `--token-store <path>` explicitly set | `<path>` exactly, plain file — bypasses barrier auto-detection entirely, matching `xkey oath --store` |

`<xkey data dir>` is the shared `resolveDataDir("")` chain
(`cmd/xkey/cmd/datadir.go`): `--data-dir` flag, then `XKEY_DATA_DIR`, then
the `data_dir` config key, then `~/.xkey/data`. This is a deliberate change
from the pre-#4 fixed `~/.xkey/tokens.json`: the token store now lives
alongside every other barrier-aware CLI store instead of at its own special
top-level path.

The AWS DPoP session store (`--session-store`, default
`~/.xkey/aws-session.json`, `oidc_aws.go`) is a **separate** store holding
the AWS-specific DPoP signing key and refresh token; it is out of scope for
go-xkms#4 and is unaffected by this change — it remains the historical
plaintext file.

## The auto-refresh loop and the background worker

`runAutoRefresh` (`oidc.go`) is the ticking loop behind `xkey oidc login
--auto-refresh N` (foreground) and the detached process `--background`
starts (`runBackgroundWorker`, re-executing `xkey oidc login
--background-worker ...`). Both callers resolve the token store — and, for a
barrier-backed store, unseal the barrier — exactly **once**, before the loop
starts, and pass that one `*oidcCLITokenStore` handle into `runAutoRefresh`.
Every tick's `Load`/refresh/`Save` cycle reuses that same handle; nothing
inside the loop calls `openOIDCTokenStore` or `resolveBarrierPassword`
again. A barrier password prompt or `--barrier-password-file` read happens
once per process lifetime, not once per refresh interval.

The detached background process is a separate `os/exec` invocation with no
controlling terminal, so it cannot satisfy an interactive barrier password
prompt, and it has no standard input to read a piped
`--barrier-password-stdin` value from either (there is no `--barrier-password`
value flag to forward in the first place: a value on the command line would
be visible in that process's `ps` output to any local user).
`startBackgroundRefresh` forwards `--barrier-password-file <path>` on the
child's argv when the parent had it set, and `XKEY_BARRIER_PASSWORD` reaches
the child through ordinary environment inheritance (`exec.Command` with no
`Env` override inherits the parent's environment) rather than an explicit
argument.

## Rejected alternatives

- **A second, OIDC-specific encryption scheme** (e.g. `pkg/oidc.FileTokenStore`'s
  own AES-GCM keyed by a fixed or derived key). The GUI already does this for
  its own no-barrier fallback; the CLI's other secret stores (`xkey oath`,
  `xkey fido2 --storage barrier`) do not, and reusing `resolveSecretStoreBackend`
  instead keeps exactly one CLI mechanism that decides "is the barrier
  initialized," rather than a second, independently-drifting one.
- **Migrating the pre-#4 plaintext file automatically.** Rejected per the
  stack's no-backward-compatibility policy during the pre-release alpha: an
  automatic migration path is itself a legacy read path this stack does not
  carry.
- **Per-issuer token storage** (reusing `pkg/oidc.BackendTokenStore`
  directly). Rejected because the CLI's UX has never supported concurrent
  provider sessions; adopting it here would be a silent, unrequested product
  change bundled into a storage-hardening fix.

## See also

- [engineering.md](engineering.md) — exported surface, invariants, tests
- [cli.md](cli.md) — every `xkey oidc` verb and flag
- `xkey/pkg/oath` — `Credential`'s `*secure.Buffer` pattern this design mirrors
- `barrier_store.go` — `resolveSecretStoreBackend`, the shared barrier decision
