# OIDC Credentials — CLI

> **Status: NORMATIVE** · Feature: `oidc-credentials` · Repo: `go-xkms` · Last verified: 2026-09-30

Two CLIs reach server credentials: `xkmsctl oidc` (always the server) and
`xkey oidc` (the server when an xkmsd is configured, its local backend
otherwise — see [xkey/docs/oidc](../../xkey/docs/oidc/)). The global
`xkmsctl` flags (`--server`, `--transport`, `--output json`, ...) are in
[key-management/cli.md](../key-management/cli.md).

## Reference flags

Every command that names one credential takes:

| Flag | Default | Meaning |
|---|---|---|
| `--scope` | `user` | `user` (personal, visible only to you) or `tenant` (shared) |
| `--owner` | you | owner of a personal credential |
| `--tenant` | your tenant | tenant holding the credential (a system caller reaches other tenants' shared credentials) |

## `xkmsctl oidc`

| Command | Does |
|---|---|
| `templates` | Lists provider templates and how a login for each is obtained (no server needed) |
| `create <name>` | Creates a credential (pending) |
| `login <name>` | Runs the provider's device login on the server: prints the code and URL, waits until approved |
| `import <name>` | Imports tokens or a codex `auth.json` |
| `list` | Lists the tenant's shared credentials and yours |
| `get <name>` | Shows one (never its tokens) |
| `token <name>` | Prints a current access token, or writes a codex `auth.json` |
| `refresh <name>` | Refreshes now |
| `delete <name>` | Deletes (tokens are not revoked at the provider) |

### `create` / `import` provider flags

| Flag | Meaning |
|---|---|
| `--template` | `openai`, `anthropic`, `google`, `microsoft`, `okta`, `auth0`, `keycloak` |
| `--issuer`, `--client-id` | Required without a template |
| `--client-secret` | Confidential client; `-` reads stdin |
| `--scopes` | Comma-separated |
| `--authorization-endpoint`, `--token-endpoint`, `--device-endpoint` | Explicit endpoints; `--token-endpoint` skips discovery |
| `--token-encoding` | `form` (default) or `json` |
| `--device-style` | `rfc8628` (default) or `openai` |
| `--refresh-margin` | Refresh this long before expiry (default `5m`) |

### `import` token flags

| Flag | Meaning |
|---|---|
| `--codex-auth PATH` | Import the ChatGPT login of a codex `auth.json` (template `openai` by default) |
| `--create` | Create the credential first |
| `--access-token`, `--refresh-token` | `-` reads stdin |
| `--id-token` | ID token |
| `--expires-at` | RFC 3339; default: the access token's `exp`, or the template's lifetime |

### `token` flags

| Flag | Meaning |
|---|---|
| `--codex-auth-out PATH` | Write a codex `auth.json` in the `chatgptAuthTokens` mode (mode 0600, no refresh token) instead of printing |

### Examples

```bash
# A shared ChatGPT login for the tenant, from an existing codex login
xkmsctl oidc import codex --scope tenant --codex-auth ~/.codex/auth.json --create

# ... or by device login, approved in any browser
xkmsctl oidc create codex --scope tenant --template openai
xkmsctl oidc login codex --scope tenant

# A Claude Code long-lived token (claude setup-token), tracked to expiry
claude setup-token | xkmsctl oidc import claude --scope tenant --create --template anthropic --access-token -

# A custom provider without discovery
xkmsctl oidc create corp --issuer https://idp.example.com --client-id cli \
    --token-endpoint https://idp.example.com/oauth/token --device-endpoint https://idp.example.com/oauth/device
xkmsctl oidc login corp

# Use it
curl -H "Authorization: Bearer $(xkmsctl oidc token corp)" https://api.example.com/
xkmsctl oidc token codex --scope tenant --codex-auth-out "$CODEX_HOME/auth.json"

xkmsctl oidc list
xkmsctl -o json oidc get codex --scope tenant
```

## `xkey oidc` with an xkmsd configured

With `--xkmsd-url`, `XKMSD_URL` or the config set, the existing commands act
on server credentials; `--local` keeps any of them on the local backend.

| Command | Server behaviour |
|---|---|
| `providers add --name N [--template T ...]` | `create` |
| `providers list` | Server credentials, then the local providers |
| `providers remove N` | `delete` |
| `login --provider N` | Device login on the server |
| `token --provider N [--show-full] [--codex-auth-out PATH]` | Current access token |
| `refresh --provider N` | Refresh now |
| `import N --codex-auth PATH \| --access-token V [--create]` | Import (server only) |
| `logout` | Refused: remove the credential, or add `--local` |

Local-only flags (`--exec`, `--auto-refresh`, `--background`, `--no-browser`,
the AWS flags, ...) are refused in server mode with a pointer to `--local`.
