# OIDC — CLI

Status: current. Last verified: 2026-09-29.

`xkey oidc` performs browser-based OIDC login against any OIDC-compliant
provider (PKCE authorization code) or AWS Console native login (DPoP), and
manages the resulting session and saved provider configurations. See
[architecture.md](architecture.md) for where the session is stored and why;
this document is the flag reference.

## Server mode (an xkmsd configured)

With `--xkmsd-url`, `XKMSD_URL` or the config set, the commands act on the
server's OIDC credentials instead of this host's; `--local` (on every
`xkey oidc` command) keeps the local backend.

| Command | Server behaviour |
|---|---|
| `providers add --name N [--template T] [--scope user\|tenant] [--issuer/--client-id/--client-secret/--scopes/--token-endpoint/--authorization-endpoint/--device-endpoint/--token-encoding/--device-style]` | Creates server credential N |
| `providers list [--tenant T]` | Server credentials, then the local providers |
| `providers remove N [--scope ...]` | Deletes server credential N |
| `login --provider N [--scope ...]` | The provider's device login, run by the server; prints the code and URL and waits |
| `token --provider N [--show-full] [--codex-auth-out PATH]` | A current access token; or a codex `auth.json` (`chatgptAuthTokens` mode, no refresh token) |
| `refresh --provider N` | Refreshes now |
| `import N (--codex-auth PATH \| --access-token V [--refresh-token V]) [--create] [--template T]` | Imports a login (server only) |
| `logout` | Refused: remove the credential, or add `--local` |

`--scope` is `user` (personal, default) or `tenant` (shared); `--owner` and
`--tenant` address another owner's or tenant's credential where allowed.
Flags that only mean something to the local backend (`--exec`,
`--auto-refresh`, `--background`, `--no-browser`, `--redirect-url`,
`--jwks-uri`, the AWS flags, ...) are refused in server mode with a pointer
to `--local`. The full server reference is
[docs/oidc-credentials/cli.md](../../../docs/oidc-credentials/cli.md).

## Session storage flags (login, token, refresh, logout)

| Flag | Default | Meaning |
|---|---|---|
| `--token-store <dir>` | `~/.xkey/tokens` | Sets the directory every derived artifact (provider config, PID files, logs) is rooted under. Also, when explicitly set, the token content itself is written to an unencrypted go-qrdb file store in exactly this directory, bypassing barrier auto-detection (matches `xkey oath --store`). Left at its default, the token content instead follows the barrier decision below, independently of this path. |
| `--barrier-password-stdin` | `false` | Read the barrier password from standard input. There is no `--barrier-password` value flag; a value on the command line is visible in `ps`. |
| `--barrier-password-file <path>` | | Read the barrier password from the first line of this file. |

Environment: `XKEY_BARRIER_PASSWORD` is read when neither barrier flag is
set. `XKEY_DATA_DIR` (or `--data-dir` on commands that accept it) overrides
the directory the no-override barrier decision resolves under.

**What actually happens**, in order:

1. `--token-store` explicitly set → the token is read/written as an
   unencrypted store in exactly that directory. No barrier involved.
2. `--token-store` left at its default, a barrier is initialized (`xkey
   barrier init` has been run) → the token is barrier-encrypted; a barrier
   password is required (from a flag, a file, the environment, or an
   interactive prompt) or the command fails with a typed refusal rather than
   writing plaintext.
3. `--token-store` left at its default, no barrier initialized → the token
   is written unencrypted under the data directory (a warning is logged
   once, naming the store and suggesting `xkey barrier init`).

## `xkey oidc login`

Interactive browser-based OIDC login (PKCE).

```
xkey oidc login [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--provider` | | Use a saved provider configuration by name |
| `--issuer` | | OIDC provider issuer URL |
| `--client-id` | | OAuth2 client ID |
| `--client-secret` | | OAuth2 client secret (optional) |
| `--redirect-url` | `http://localhost:<oidc.callback_port>/callback` | Local callback URL; an explicit value keeps its own port |
| `--callback-host` | `oidc.callback_host` (`localhost`) | Host the local callback listener binds |
| `--callback-port` | `oidc.callback_port` (`8085`) | Port of the default redirect URL |
| `--scopes` | `openid,profile,email` | Scopes to request (comma-separated) |
| `--no-browser` | `false` | Print the authorization URL instead of opening a browser |
| `--exec` | | Execute a script after login (receives a JSON payload on stdin and as env vars) |
| `--auto-refresh` | `0` | Auto-refresh interval in seconds (0 disables) |
| `--background` | `false` | Run auto-refresh as a detached process (requires `--auto-refresh`) |
| `--log-file` | (auto-generated under `<token-store dir>/logs`) | Log file for background refresh |
| `--authorization-endpoint`, `--token-endpoint`, `--jwks-uri` | | Manual endpoints, supplied together, skip `.well-known` discovery entirely; `--userinfo-endpoint` is optional alongside them |
| `--token-encoding` | `form` | Token request body encoding: `form` or `json` |
| plus the session storage flags above | | |

`--provider <name>` loads a saved provider's issuer/client/scopes/manual
endpoints/token encoding/auto-refresh/background settings as defaults; any
of the flags above still override them. A provider of type `aws` is
delegated to the AWS DPoP flow automatically.

## `xkey oidc aws`

Direct AWS Console native login (DPoP). See `pkg/oidc`'s DPoP documentation
for the mechanism; this command's session (the DPoP private key and refresh
token) is stored separately from the standard OIDC session, in its own
barrier-or-fallback store — the same decision the session storage flags
table above describes for `--token-store`, applied to `--session-store`
instead (see [architecture.md](architecture.md) for the full "where the
store lives" table). In order:

1. `--session-store` explicitly set (directly here, or saved earlier on an
   AWS provider via `xkey oidc providers add --session-store`) → the session
   is read/written as an unencrypted store in exactly that directory. No
   barrier involved.
2. `--session-store` left at its default, a barrier is initialized → the
   session is barrier-encrypted; a barrier password is required (from a
   flag, a file, the environment, or an interactive prompt) or the command
   fails with a typed refusal rather than writing plaintext.
3. `--session-store` left at its default, no barrier initialized → the
   session is written unencrypted under the data directory (a warning is
   logged once, naming the store and suggesting `xkey barrier init`).

`--session-store`'s flag value is, in every case, also used to derive the
default log-file and PID-file directories for `--background`/
`--auto-refresh` — those are never secret, so they keep the historical
`~/.xkey/logs`/`~/.xkey/pids` layout regardless of where the session data
itself lands.

```
xkey oidc aws [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--region`, `-r` | (required) | AWS region; `a-z 0-9 -` only when written to the credentials file |
| `--profile` | `default` | AWS profile name to write credentials to; `A-Z a-z 0-9 . _ - @ + : /` only |
| `--cross-device` | `false` | Cross-device authentication flow |
| `--no-browser` | `false` | Print URL instead of opening a browser |
| `--output`, `-o` | `aws-credentials` | `aws-credentials`, `json`, `exec`, or `none` |
| `--credentials-file` | `~/.aws/credentials` | AWS credentials file path; replaced atomically with mode `0600`, other profiles kept |
| `--exec` | | Execute a script after login |
| `--auto-refresh` | `0` | Auto-refresh interval in seconds |
| `--session-store` | `~/.xkey/aws-session` | Session store directory; see the barrier-or-fallback decision above |
| `--barrier-password-stdin` | `false` | Read the barrier password from standard input |
| `--barrier-password-file <path>` | | Read the barrier password from the first line of this file |
| `--background` | `false` | Run auto-refresh in background |
| `--log-file` | (auto-generated) | Log file for background refresh |
| `--callback-host`, `--callback-port` | `oidc.callback_host`/`oidc.callback_port` | Local callback listener; AWS redirects to `127.0.0.1`, so only `localhost`, `127.0.0.1`, or `""` can serve it |

Environment: `XKEY_BARRIER_PASSWORD` is read when neither barrier flag is
set, the same as the session storage flags table above.

## `xkey oidc token`

Display the current session's token information.

```
xkey oidc token [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--show-full` | `false` | Show full access/ID/refresh token values instead of truncating |
| plus the session storage flags above | | |

## `xkey oidc refresh`

Refresh the access token using the stored refresh token.

```
xkey oidc refresh [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--provider` | | Use a saved provider's manual endpoints and token encoding; required when the session was established with manual endpoints |
| plus the session storage flags above | | |

Without `--provider`, refresh re-discovers the issuer's endpoints from
`.well-known` and posts form-encoded, exactly as `login` would without a
provider. With `--provider`, it reuses that provider's saved manual
endpoints and token encoding, so a session that skipped discovery at login
keeps working after refresh.

## `xkey oidc logout`

Clear the stored session (local only — does not revoke at the provider).

```
xkey oidc logout [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--all` | `false` | Kept for compatibility with earlier releases' flag set; the CLI keeps exactly one active session, so `--all` and the default form both remove that one entry |
| plus the session storage flags above | | |

## `xkey oidc status`

Show running background refresh processes (from PID/status files under
`<token-store dir>/pids`; unaffected by the barrier decision).

```
xkey oidc status
```

## `xkey oidc stop [provider]`

Stop a running background refresh process.

```
xkey oidc stop [provider] [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--all` | `false` | Stop all background refresh processes |

## `xkey oidc providers list` / `add` / `remove`

Manage saved provider configurations (`<token-store dir>/oidc-providers.json`
— unaffected by the barrier decision; provider configuration is out of
scope for go-xkms#4, which covers the token store only).

```
xkey oidc providers list
xkey oidc providers add --name <name> [flags]
xkey oidc providers remove <name>
```

`add`'s common flags: `--name` (required), `--type` (`oidc` default or
`aws`), `--exec`, `--auto-refresh`, `--background`, `--log-file`.
Standard-OIDC flags (`--type oidc`): `--issuer` (required), `--client-id`
(required), `--client-secret`, `--redirect-url`, `--callback-host`,
`--callback-port`, `--scopes`, `--authorization-endpoint`,
`--token-endpoint`, `--jwks-uri`, `--userinfo-endpoint`, `--token-encoding`.
AWS flags (`--type aws`): `--region`/`-r` (required), `--profile`,
`--credentials-file`, `--output`/`-o`, `--cross-device`, `--session-store`.
`remove` (aliases `rm`, `delete`) also stops any running background refresh
for that provider.

## Examples

```bash
# Save a provider, then log in by name
xkey oidc providers add --name okta --issuer https://example.okta.com --client-id CLIENT_ID
xkey oidc login --provider okta

# Barrier-encrypted session (barrier already initialized via `xkey barrier init`)
xkey oidc login --issuer https://example.okta.com --client-id CLIENT_ID --barrier-password-file ~/.xkey/barrier.pw

# Inspect and refresh
xkey oidc token
xkey oidc refresh

# Background auto-refresh every 14 minutes, barrier-backed, non-interactive
xkey oidc login --provider okta --auto-refresh 840 --background --barrier-password-file ~/.xkey/barrier.pw
xkey oidc status
xkey oidc stop okta

# Explicit file, bypassing the barrier entirely
xkey oidc login --provider okta --token-store /tmp/scratch-tokens

# Clear the session
xkey oidc logout
```
