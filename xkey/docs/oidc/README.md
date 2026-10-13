# OIDC OpenID Connect Authentication

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: background overview of xkey OIDC; the feature folder ([architecture.md](architecture.md), [cli.md](cli.md)) is normative.

xkey includes comprehensive support for OpenID Connect (OIDC) authentication with two distinct approaches:

1. **Standard OIDC** - Compatible with any OIDC-compliant identity provider (Google, Microsoft, Okta, Auth0, Keycloak)
2. **AWS Console Native Login** - Direct AWS authentication using DPoP (Demonstration of Proof-of-Possession)

All authorization flows use PKCE (Proof Key for Code Exchange) for secure public client authentication.

## Quick Start

### Standard OIDC (Any Provider)

```bash
# Add a provider (saves configuration for reuse)
xkey oidc providers add --name google \
  --issuer https://accounts.google.com \
  --client-id YOUR_CLIENT_ID

# Login using saved provider (simplest!)
xkey oidc login --provider google

# Or login with explicit flags
xkey oidc login --issuer https://accounts.google.com --client-id YOUR_CLIENT_ID

# View current token
xkey oidc token

# Refresh when expired
xkey oidc refresh

# Logout
xkey oidc logout
```

### AWS Console Native Login (DPoP)

```bash
# Direct AWS authentication (writes to ~/.aws/credentials)
xkey oidc aws --region us-east-1

# With specific profile
xkey oidc aws --region us-east-1 --profile production

# With auto-refresh in background
xkey oidc aws --region us-east-1 --auto-refresh 840 --background

# Or save as a provider for easy reuse
xkey oidc providers add --name aws-prod \
  --type aws \
  --region us-east-1 \
  --profile production \
  --auto-refresh 840 \
  --background

# Then simply:
xkey oidc login --provider aws-prod
```

---

## AWS Console Native Login

xkey supports direct AWS Console authentication using AWS's native OIDC signin endpoints with DPoP (Demonstrating Proof-of-Possession). This provides temporary AWS credentials without needing IAM identity providers or role trust policies.

### How It Works

1. xkey generates an EC P-256 DPoP key pair
2. Opens browser to AWS signin endpoint (`https://{region}.signin.aws.amazon.com`)
3. User authenticates with AWS credentials
4. Receives authorization code via callback
5. Exchanges code for DPoP-bound tokens
6. AWS returns temporary credentials (access key, secret key, session token)
7. Writes credentials to `~/.aws/credentials`

### DPoP (Demonstration of Proof-of-Possession)

DPoP (RFC 9449) is a security mechanism that binds tokens to a specific client by requiring proof of possession of a private key. This prevents token theft and replay attacks.

**How DPoP works:**

1. Client generates an ephemeral EC P-256 key pair
2. Each token request includes a DPoP proof JWT signed with the private key
3. The proof contains: HTTP method, target URL, unique identifier, and timestamp
4. Server validates the proof and binds the token to the client's public key
5. Subsequent requests must include proofs signed with the same private key

**DPoP Proof JWT Structure:**

```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "..."
  }
}
{
  "jti": "unique-id",
  "htm": "POST",
  "htu": "https://us-east-1.signin.aws.amazon.com/v1/token",
  "iat": 1706800000
}
```

### Command: `xkey oidc aws`

Direct AWS Console authentication with DPoP.

```
xkey oidc aws [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--region`, `-r` | (required) | AWS region (e.g., us-east-1, eu-west-1) |
| `--profile` | `default` | AWS profile name to write credentials to |
| `--cross-device` | `false` | Enable cross-device authentication flow |
| `--no-browser` | `false` | Print URL instead of opening browser |
| `--output`, `-o` | `aws-credentials` | Output mode: aws-credentials, json, exec, none |
| `--credentials-file` | `~/.aws/credentials` | Path to AWS credentials file |
| `--exec` | | Execute script after login |
| `--auto-refresh` | `0` | Auto-refresh interval in seconds |
| `--session-store` | `~/.xkey/aws-session` | Directory of an unencrypted AWS session store (bypasses the barrier when set) |
| `--background` | `false` | Run auto-refresh in background |
| `--log-file` | (auto-generated) | Log file for background refresh |
| `--callback-host` | `oidc.callback_host` (`localhost`) | Host the local callback listener binds; AWS redirects to `127.0.0.1`, so only `localhost`, `127.0.0.1` or `""` can serve it |
| `--callback-port` | `oidc.callback_port` (`8085`) | Port of the `http://127.0.0.1:<port>/oauth/callback` redirect URL (1-65535) |

### Examples

```bash
# Basic login (writes to ~/.aws/credentials default profile)
xkey oidc aws --region us-east-1

# Login to specific profile
xkey oidc aws --region us-east-1 --profile my-profile

# Cross-device login (shows URL for another device)
xkey oidc aws --region us-east-1 --cross-device

# Output credentials as JSON (for scripting)
xkey oidc aws --region us-east-1 --output json

# Auto-refresh credentials every 14 minutes (runs in foreground)
xkey oidc aws --region us-east-1 --auto-refresh 840

# Auto-refresh in background (doesn't block terminal)
xkey oidc aws --region us-east-1 --auto-refresh 840 --background

# Check background refresh status
xkey oidc status

# Stop background refresh
xkey oidc stop aws-us-east-1
```

### Output Modes

| Mode | Description |
|------|-------------|
| `aws-credentials` | Write to `~/.aws/credentials` file (default) |
| `json` | Output credentials as JSON to stdout |
| `exec` | Pass credentials to script via environment variables |
| `none` | Authenticate but don't output credentials |

**JSON Output Format:**

```json
{
  "access_key_id": "ASIAXXX...",
  "secret_access_key": "xxx...",
  "session_token": "xxx...",
  "expiration": "2025-02-01T18:00:00Z",
  "region": "us-east-1"
}
```

**Environment Variables (for --exec):**

| Variable | Description |
|----------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS access key ID |
| `AWS_SECRET_ACCESS_KEY` | AWS secret access key |
| `AWS_SESSION_TOKEN` | AWS session token |
| `AWS_REGION`, `AWS_DEFAULT_REGION` | AWS region (set when known) |
| `AWS_CREDENTIAL_EXPIRATION` | Credential expiration time, UTC (`xkey/pkg/oidc/handlers/exec.go:196`) |

### Session Storage

AWS sessions are stored for refresh token management:

```json
{
  "region": "us-east-1",
  "profile": "default",
  "access_key_id": "ASIAXXX...",
  "expiration": "2025-02-01T18:00:00Z",
  "refresh_token": "xxx...",
  "dpop_key_pem": "-----BEGIN EC PRIVATE KEY-----\n..."
}
```

The DPoP key is stored with the session because refresh requests must be signed with the same key that was used for the initial token request.

---

## Provider Types

xkey supports two types of OIDC providers:

### Standard OIDC (`--type oidc`)

Any OpenID Connect-compliant identity provider, with or without a
`.well-known/openid-configuration` discovery document (see
[Manual Endpoints](#manual-endpoints-skipping-discovery)).

**Required fields:**
- `--issuer` - Provider issuer URL. Used for discovery unless manual
  endpoints are supplied, and always checked against the ID token's `iss`
  claim.
- `--client-id` - OAuth2 client ID

**Optional fields:**
- `--client-secret` - For confidential clients
- `--redirect-url` - Callback URL (default: `http://localhost:<oidc.callback_port>/callback`)
- `--callback-host` - Host the local callback listener binds (default: `oidc.callback_host`, `localhost`: both loopback families)
- `--callback-port` - Port of the default redirect URL (default: `oidc.callback_port`, `8085`)
- `--scopes` - Scopes to request (default: `openid,profile,email`)
- `--authorization-endpoint`, `--token-endpoint`, `--jwks-uri`,
  `--userinfo-endpoint` - Manual endpoints; see
  [Manual Endpoints](#manual-endpoints-skipping-discovery)
- `--token-encoding` - Token request body encoding, `form` (default) or
  `json`; see [Token Encoding](#token-encoding)

### Manual Endpoints (skipping discovery)

Some providers publish no `.well-known/openid-configuration` document — for
example a CLI-only OAuth2 client that only ever hands out an authorization
and a token endpoint out of band. Supply `--authorization-endpoint`,
`--token-endpoint`, and `--jwks-uri` together (`--userinfo-endpoint` too, if
the provider has one) and `xkey oidc login` / `xkey oidc providers add`
never dial `.well-known` at all — the supplied endpoints are used directly.
This mirrors `pkg/oidc.ProviderConfig.SkipDiscovery` in the Go SDK, which the
xkey GUI and CLI both build on.

```bash
xkey oidc providers add --name no-discovery \
  --issuer https://auth.example.com \
  --client-id YOUR_CLIENT_ID \
  --authorization-endpoint https://auth.example.com/authorize \
  --token-endpoint https://auth.example.com/token \
  --jwks-uri https://auth.example.com/jwks

xkey oidc login --provider no-discovery
```

Supplying only some of the three required endpoints is refused before any
network request is made, naming exactly which flags are still missing:

```
$ xkey oidc providers add --name partial --issuer https://i --client-id c \
    --authorization-endpoint https://i/authorize
Error: oidc: incomplete manual endpoint configuration: --token-endpoint, --jwks-uri
```

A provider's manual endpoints are saved with it, so `xkey oidc refresh
--provider no-discovery` also skips discovery; refreshing without
`--provider` still falls back to the issuer's `.well-known` document.

### Token Encoding

Token requests (authorization-code exchange and refresh) are form-encoded
(`application/x-www-form-urlencoded`, RFC 6749) by default. A provider whose
token endpoint expects `application/json` instead sets
`--token-encoding json` on `xkey oidc providers add` (or `xkey oidc login`
for a one-off, unsaved provider):

```bash
xkey oidc providers add --name json-token-endpoint \
  --issuer https://auth.example.com \
  --client-id YOUR_CLIENT_ID \
  --token-encoding json
```

An unrecognized value (anything other than `form` or `json`) is refused
immediately. The encoding decision is made in one place,
`pkg/oidc.EncodeTokenRequestBody`, used by both the CLI and the `pkg/oidc`
library the GUI is built on, so the two never diverge.

### Callback listener

Both flows receive the authorization code on a local HTTP listener. Where it
binds is configuration, never a literal: the `oidc` section of the xkey config
(`oidc.callback_host`, `oidc.callback_port`; environment
`XKEY_OIDC_CALLBACK_HOST`, `XKEY_OIDC_CALLBACK_PORT`), overridden per command
by `--callback-host` and `--callback-port`. The listener binds the callback
host on the port of the redirect URL the browser is sent to, so an explicit
`--redirect-url` (or a saved provider's) decides the port and the callback
port only shapes the default redirect URL. The default host, `localhost`,
binds both loopback families (`127.0.0.1` and `::1` where present), because
the browser resolves the redirect host `localhost` to either; an address
binds that address; an empty string binds every interface. The default
redirect URL follows the host: `http://localhost:<port>/callback` for
`localhost` and the empty host, `http://<callback_host>:<port>/callback`
otherwise, so the browser is always sent where the listener is. An explicit
`--redirect-url` (or a saved provider's) must be plain `http`, because the
listener does not serve TLS, and the callback host must be able to serve its
host: a `localhost` redirect needs `localhost`, a loopback address or the
empty host; an IP redirect needs that address or the empty host; any other
name needs an explicit address or the empty host, never loopback. A
combination that cannot serve the redirect is refused before the browser
opens, as is a `--callback-port` outside 1-65535. The listener answers on the
redirect URL's path, whatever path the provider was registered with. The desktop GUI's OIDC
login uses the same `oidc` section and the same rules; it has no flags, so
the section is its only path. AWS always sends
the browser to `127.0.0.1`, so `xkey oidc aws` serves `127.0.0.1` for
`localhost`, `127.0.0.1` and the empty host, and refuses any other callback
host before opening the browser.

### AWS Provider (`--type aws`)

Direct AWS Console authentication using DPoP.

**Required fields:**
- `--region` - AWS region

**Optional fields:**
- `--profile` - AWS profile name (default: `default`)
- `--credentials-file` - AWS credentials file (default: `~/.aws/credentials`)
- `--output` - Output mode (default: `aws-credentials`)
- `--cross-device` - Enable cross-device authentication
- `--session-store` - Session store directory

### Adding Providers

```bash
# Standard OIDC provider
xkey oidc providers add --name google \
  --type oidc \
  --issuer https://accounts.google.com \
  --client-id YOUR_CLIENT_ID

# AWS provider with all settings
xkey oidc providers add --name aws-prod \
  --type aws \
  --region us-east-1 \
  --profile production \
  --auto-refresh 840 \
  --background \
  --log-file ~/.xkey/logs/aws-prod.log

# Login using saved provider
xkey oidc login --provider aws-prod
```

### Provider List Output

```
OIDC Providers (3):

  Name:         google
  Type:         oidc
  Issuer:       https://accounts.google.com
  Client ID:    123456.apps.googleusercontent.com
  Redirect URL: http://localhost:8085/callback
  Scopes:       openid, profile, email

  Name:         aws-prod
  Type:         aws
  Region:       us-east-1
  Profile:      production
  Credentials:  ~/.aws/credentials
  Output:       aws-credentials
  Auto-Refresh: 840 seconds
  Background:   yes
  Log File:     /home/user/.xkey/logs/aws-prod.log

  Name:         okta-aws
  Type:         oidc
  Issuer:       https://dev-123.okta.com
  Client ID:    0oa1234567
  Scopes:       openid, profile, email, offline_access
  Exec:         ./scripts/aws-oidc-login.sh
  Auto-Refresh: 2700 seconds
```

---

## Standard OIDC Providers

### Testing with Mock Server

The easiest way to test OIDC is with [navikt/mock-oauth2-server](https://github.com/navikt/mock-oauth2-server):

```bash
# Start the mock OIDC server
docker run -p 8080:8080 ghcr.io/navikt/mock-oauth2-server:latest

# Verify it's running
curl http://localhost:8080/default/.well-known/openid-configuration

# Test xkey
xkey oidc login \
  --issuer http://localhost:8080/default \
  --client-id test-client
```

### Google

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create OAuth client ID (Desktop app)
3. Add `http://localhost:8085/callback` to redirect URIs

```bash
xkey oidc providers add --name google \
  --issuer https://accounts.google.com \
  --client-id YOUR_CLIENT_ID.apps.googleusercontent.com

xkey oidc login --provider google
```

### Okta

1. Sign up at [developer.okta.com](https://developer.okta.com)
2. Create Native Application
3. Set redirect URI: `http://localhost:8085/callback`
4. Enable Refresh Token grant

```bash
xkey oidc providers add --name okta \
  --issuer https://dev-XXXXXX.okta.com \
  --client-id YOUR_CLIENT_ID \
  --scopes "openid,profile,email,offline_access"

xkey oidc login --provider okta
```

### Auth0

1. Sign up at [auth0.com](https://auth0.com)
2. Create Native application
3. Add `http://localhost:8085/callback` to Allowed Callback URLs

```bash
xkey oidc providers add --name auth0 \
  --issuer https://YOUR_TENANT.auth0.com \
  --client-id YOUR_CLIENT_ID \
  --scopes "openid,profile,email,offline_access"

xkey oidc login --provider auth0
```

---

## Command Reference

### oidc login

Perform interactive browser-based OIDC login.

```
xkey oidc login [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | | Use saved provider configuration by name |
| `--issuer` | | OIDC provider issuer URL |
| `--client-id` | | OAuth2 client ID |
| `--client-secret` | | OAuth2 client secret (optional) |
| `--redirect-url` | `http://localhost:<oidc.callback_port>/callback` | Local callback URL; an explicit value keeps its own port |
| `--callback-host` | `oidc.callback_host` (`localhost`) | Host the local callback listener binds; `localhost` is both loopback families |
| `--callback-port` | `oidc.callback_port` (`8085`) | Port of the default redirect URL |
| `--scopes` | `openid,profile,email` | Scopes to request |
| `--token-store` | `~/.xkey/tokens` | Directory of an unencrypted token store (bypasses the barrier when set) |
| `--no-browser` | `false` | Print URL instead of opening browser |
| `--exec` | | Execute script after login |
| `--auto-refresh` | `0` | Auto-refresh interval in seconds |
| `--background` | `false` | Run auto-refresh in background |
| `--log-file` | (auto-generated) | Log file for background refresh |
| `--authorization-endpoint` | | Manual authorization endpoint; skips discovery (requires `--token-endpoint` and `--jwks-uri`) |
| `--token-endpoint` | | Manual token endpoint; skips discovery (requires `--authorization-endpoint` and `--jwks-uri`) |
| `--jwks-uri` | | Manual JWKS URI; skips discovery (requires `--authorization-endpoint` and `--token-endpoint`) |
| `--userinfo-endpoint` | | Manual userinfo endpoint (optional, used only with manual endpoints) |
| `--token-encoding` | `form` | Token request body encoding: `form` or `json` |

**When `--provider` specifies an AWS provider, all AWS-specific settings are loaded and the AWS login flow is used automatically.**

**Providers with no `.well-known/openid-configuration` document:** supply
`--authorization-endpoint`, `--token-endpoint`, and `--jwks-uri` together (add
`--userinfo-endpoint` if the provider has one) and discovery is skipped
entirely — no request to `.well-known` is made. Supplying only some of the
three required endpoints is refused with an error naming exactly which flags
are still missing. See [Manual Endpoints](#manual-endpoints-skipping-discovery)
below.

### oidc aws

Direct AWS Console authentication with DPoP. See [AWS Console Native Login](#aws-console-native-login) section.

### oidc token

Display current token information.

```
xkey oidc token [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--token-store` | `~/.xkey/tokens` | Directory of an unencrypted token store (bypasses the barrier when set) |
| `--show-full` | `false` | Show full token values |

### oidc refresh

Refresh the access token using the stored refresh token.

```
xkey oidc refresh [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--token-store` | `~/.xkey/tokens` | Directory of an unencrypted token store (bypasses the barrier when set) |
| `--provider` | | Use a saved provider's manual endpoints and token encoding; required to refresh a provider added with manual endpoints |

Without `--provider`, refresh re-discovers the issuer's endpoints from its
`.well-known` document and posts a form-encoded request, exactly as before.
With `--provider`, it uses that provider's saved manual endpoints (skipping
discovery, same as login) and token encoding, so a provider configured
without discovery keeps working after the initial login.

### oidc logout

Clear stored tokens (local only - does not revoke at provider).

```
xkey oidc logout [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--all` | `false` | Kept for compatibility; the CLI keeps one active session, so `--all` and the default form both remove it (`xkey/cmd/xkey/cmd/oidc.go:1005`) |

### oidc status

Show running background refresh processes.

```
xkey oidc status [flags]
```

**Output:**

```
Background Refresh Processes (2):

  Provider:     aws-us-east-1
  PID:          12345
  Started:      2025-02-01 17:30:00 (45 minutes ago)
  Log file:     ~/.xkey/logs/aws-us-east-1.log

  Provider:     okta-aws
  PID:          12346
  Started:      2025-02-01 17:00:00 (1 hours 15 minutes ago)
  Log file:     ~/.xkey/logs/okta-aws.log
```

Log and PID files default to `logs/` and `pids/` beside the token store
directory (`getDefaultLogFile`, `getPIDDir` in `xkey/cmd/xkey/cmd/oidc.go:1933`,
`:1943`). With a status file present the block also shows `Last Refresh`,
`Next Refresh` and `Refreshes`.

### oidc stop

Stop a running background refresh process.

```
xkey oidc stop [provider] [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--all` | `false` | Stop all background refresh processes |

### oidc providers list

List all configured providers.

```
xkey oidc providers list [flags]
```

Aliases: `ls`

### oidc providers add

Add a new provider configuration.

```
xkey oidc providers add [flags]
```

**Common flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--name` | (required) | Provider name |
| `--type` | `oidc` | Provider type: `oidc` or `aws` |
| `--exec` | | Script to execute after login |
| `--auto-refresh` | `0` | Auto-refresh interval in seconds |
| `--background` | `false` | Run auto-refresh in background |
| `--log-file` | | Log file for background refresh |

**Standard OIDC flags (`--type oidc`):**

| Flag | Default | Description |
|------|---------|-------------|
| `--issuer` | (required) | OIDC provider issuer URL |
| `--client-id` | (required) | OAuth2 client ID |
| `--client-secret` | | OAuth2 client secret |
| `--redirect-url` | `http://localhost:<oidc.callback_port>/callback` | Callback URL saved with the provider |
| `--callback-host` | `oidc.callback_host` (`localhost`) | Host the local callback listener binds; `localhost` is both loopback families |
| `--callback-port` | `oidc.callback_port` (`8085`) | Port of the default redirect URL |
| `--scopes` | | Scopes to request |
| `--authorization-endpoint` | | Manual authorization endpoint; skips discovery (requires `--token-endpoint` and `--jwks-uri`) |
| `--token-endpoint` | | Manual token endpoint; skips discovery (requires `--authorization-endpoint` and `--jwks-uri`) |
| `--jwks-uri` | | Manual JWKS URI; skips discovery (requires `--authorization-endpoint` and `--token-endpoint`) |
| `--userinfo-endpoint` | | Manual userinfo endpoint (optional, used only with manual endpoints) |
| `--token-encoding` | `form` | Token request body encoding: `form` or `json` |

**AWS flags (`--type aws`):**

| Flag | Default | Description |
|------|---------|-------------|
| `--region`, `-r` | (required) | AWS region |
| `--profile` | `default` | AWS profile name |
| `--credentials-file` | `~/.aws/credentials` | AWS credentials file path |
| `--output`, `-o` | `aws-credentials` | Output mode |
| `--cross-device` | `false` | Enable cross-device authentication |
| `--session-store` | `~/.xkey/aws-session` | Session store directory |

### oidc providers remove

Remove a provider (automatically stops any running background refresh).

```
xkey oidc providers remove [name] [flags]
```

Aliases: `rm`, `delete`

---

## Authentication Flows

### Standard OIDC Authorization Code Flow with PKCE

1. Generates PKCE code verifier (43 bytes, base64url) and challenge (SHA-256)
2. Generates cryptographic state parameter (32 bytes)
3. Discovers endpoints via `/.well-known/openid-configuration`
4. Opens browser to authorization endpoint
5. Starts the local callback server on `oidc.callback_host` at the redirect URL's port
6. Receives authorization code and validates state
7. Exchanges code for tokens
8. Validates ID token and extracts claims
9. Stores tokens locally

### AWS DPoP Authorization Flow

1. Generates EC P-256 DPoP key pair
2. Generates PKCE code verifier and challenge (trimmed of `=` padding per AWS spec)
3. Generates cryptographic state parameter
4. Opens browser to `https://{region}.signin.aws.amazon.com/v1/authorize`
5. Starts the local callback server on `oidc.callback_host` for `http://127.0.0.1:<oidc.callback_port>/oauth/callback` (AWS requires the literal `127.0.0.1` host and `/oauth/callback` path; the port is configuration)
6. Receives authorization code
7. Generates DPoP proof JWT signed with private key
8. Exchanges code for tokens (includes DPoP header)
9. Handles `use_dpop_nonce` error with automatic retry (up to 3 times)
10. Receives AWS credentials (access key, secret key, session token)
11. Writes credentials to `~/.aws/credentials`

---

## Custom Script Execution (--exec)

The `--exec` flag runs a custom script after login, useful for:

- Exchanging OIDC tokens for cloud credentials
- Updating configuration files
- Triggering downstream automation

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OIDC_PROVIDER` | Provider issuer URL |
| `OIDC_ISSUER` | Issuer URL |
| `OIDC_CLIENT_ID` | OAuth2 client ID |
| `OIDC_ACCESS_TOKEN` | Access token |
| `OIDC_REFRESH_TOKEN` | Refresh token |
| `OIDC_ID_TOKEN` | ID token (JWT) |
| `OIDC_EXPIRES_AT` | Expiration (RFC3339) |
| `OIDC_EXPIRES_IN` | Seconds until expiration |
| `OIDC_SCOPES` | Granted scopes |
| `OIDC_SUBJECT` | User subject claim |
| `OIDC_EMAIL` | User email |
| `OIDC_NAME` | User name |

### JSON Payload (stdin)

```json
{
  "provider": "https://accounts.google.com",
  "issuer": "https://accounts.google.com",
  "client_id": "YOUR_CLIENT_ID",
  "access_token": "ya29...",
  "refresh_token": "1//...",
  "id_token": "eyJhbG...",
  "expires_at": "2025-02-01T17:00:00Z",
  "expires_in": 3600,
  "scopes": ["openid", "profile", "email"],
  "subject": "1234567890",
  "email": "user@example.com",
  "name": "John Doe"
}
```

### Examples

```bash
# Extract access token
xkey oidc login --provider google \
  --exec 'cat | jq -r .access_token > /tmp/token.txt'

# Debug - print full payload
xkey oidc login --provider google \
  --exec 'cat | jq .'

# AWS STS exchange (for OIDC providers, not AWS native)
xkey oidc login --provider okta \
  --exec './scripts/aws-oidc-login.sh'
```

---

## OIDC + AWS STS Integration

For exchanging OIDC tokens from third-party IdPs (Okta, Google, etc.) for AWS credentials via STS `AssumeRoleWithWebIdentity`:

### Setup

1. **Configure IdP as AWS OIDC Provider:**
   - AWS Console → IAM → Identity providers → Add provider
   - Provider type: OpenID Connect
   - Provider URL: Your IdP issuer
   - Audience: Your OAuth client ID

2. **Create IAM Role:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::ACCOUNT:oidc-provider/dev-XXX.okta.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "dev-XXX.okta.com:aud": "YOUR_CLIENT_ID"
      }
    }
  }]
}
```

3. **Use with xkey:**

```bash
export AWS_ROLE_ARN="arn:aws:iam::123456789012:role/OIDCRole"

xkey oidc login --provider okta \
  --exec ./scripts/aws-oidc-login.sh \
  --auto-refresh 2700
```

**Note:** For direct AWS Console authentication without STS, use `xkey oidc aws` instead.

---

## Storage

### Token Store

One active session, stored as a single JSON object under the key
`oidc/tokens.json`. It is barrier-encrypted when `xkey barrier init` has been
run. Otherwise it is an unencrypted go-qrdb file store under the xkey data
directory, or in exactly the `--token-store` directory when that flag is set.
The fields are `provider`, `issuer`, `client_id`, `access_token`,
`refresh_token`, `id_token`, `expires_at` and `scopes`
(`xkey/cmd/xkey/cmd/oidc_token_store.go:199`). See
[architecture.md](architecture.md#where-the-store-lives).

### Provider Configuration

Default: `~/.xkey/oidc-providers.json`

```json
{
  "providers": [
    {
      "name": "google",
      "type": "oidc",
      "issuer": "https://accounts.google.com",
      "client_id": "YOUR_CLIENT_ID"
    },
    {
      "name": "no-discovery",
      "type": "oidc",
      "issuer": "https://auth.example.com",
      "client_id": "YOUR_CLIENT_ID",
      "authorization_endpoint": "https://auth.example.com/authorize",
      "token_endpoint": "https://auth.example.com/token",
      "jwks_uri": "https://auth.example.com/jwks",
      "token_encoding": "json"
    },
    {
      "name": "aws-prod",
      "type": "aws",
      "aws_region": "us-east-1",
      "aws_profile": "production",
      "auto_refresh": 840,
      "background": true,
      "log_file": "/home/user/.xkey/logs/aws-prod.log"
    }
  ]
}
```

`authorization_endpoint`, `token_endpoint`, `jwks_uri`, and
`userinfo_endpoint` are omitted (or empty) for a normal discovery-based
provider; setting `authorization_endpoint`, `token_endpoint`, and `jwks_uri`
together skips discovery for that provider from then on, on both `login` and
`refresh --provider <name>`. `token_encoding` is `form` when omitted.

### AWS Session Store

Stores the DPoP private key and refresh token for AWS credential refresh.
Barrier-encrypted when `xkey barrier init` has been run, an unencrypted file
under the xkey data directory with one warning otherwise, or an unencrypted
store in exactly the directory `--session-store` names when it is explicitly set (directly, or saved on the
provider). See [architecture.md](architecture.md#where-the-store-lives) and
[cli.md](cli.md#xkey-oidc-aws) for the full decision.

---

## Quick Reference

### Direct AWS Login

```bash
# Basic
xkey oidc aws --region us-east-1

# With profile
xkey oidc aws --region us-east-1 --profile prod

# With background auto-refresh
xkey oidc aws --region us-east-1 --auto-refresh 840 --background

# Save as provider for reuse
xkey oidc providers add --name aws-prod --type aws --region us-east-1 --auto-refresh 840 --background
xkey oidc login --provider aws-prod
```

### Standard OIDC Login

```bash
# Using provider
xkey oidc login --provider google

# Explicit flags
xkey oidc login --issuer https://accounts.google.com --client-id ID

# With auto-refresh
xkey oidc login --provider okta --auto-refresh 1800 --background
```

### Provider Management

```bash
# Add standard OIDC
xkey oidc providers add --name google --issuer URL --client-id ID

# Add AWS
xkey oidc providers add --name aws-prod --type aws --region us-east-1

# List
xkey oidc providers list

# Remove
xkey oidc providers remove google
```

### Background Refresh

```bash
# Start
xkey oidc login --provider NAME --auto-refresh 1800 --background

# Status
xkey oidc status

# Stop specific
xkey oidc stop NAME

# Stop all
xkey oidc stop --all

# View logs
tail -f ~/.xkey/logs/NAME.log
```

---

## Security Considerations

- **PKCE** is mandatory for all flows, protecting against code interception
- **DPoP** binds tokens to the client's key, preventing token theft
- **State parameters** are cryptographically random (32 bytes) for CSRF protection
- The token and AWS session stores are barrier-encrypted at rest once `xkey barrier init` has been run
- DPoP private keys are stored in the session store for refresh operations
- Logout only clears local tokens - use provider's revocation endpoint for immediate invalidation
- When using `--exec`, tokens are passed via environment variables - avoid logging them

---

## Go SDK: Built-in Templates

The `pkg/oidc` package includes built-in provider templates that provide sensible defaults for common providers.

### Available Templates

| Template | Description | DPoP | Default Output |
|----------|-------------|------|----------------|
| `aws` | AWS Console credentials (native AWS OIDC) | Yes | aws-credentials |
| `aws-exec` | AWS Console credentials with exec script | Yes | exec |
| `google` | Google accounts | No | exec |
| `microsoft` | Microsoft Entra ID (Azure AD) | No | exec |
| `okta` | Okta (requires issuer URL) | No | exec |
| `auth0` | Auth0 (requires issuer URL) | No | exec |
| `keycloak` | Keycloak (requires issuer URL) | No | exec |
| `openai` | OpenAI ChatGPT login (the codex CLI's); device login or import | No | none |
| `anthropic` | Claude Code long-lived token; imported, never refreshed | No | none |

`BuiltinTemplates` in `pkg/oidc/templates.go:143` is the source of this table.

### Using Templates in Go

```go
import "github.com/jeremyhahn/go-xkms/pkg/oidc"

// Create config from template
config, err := oidc.NewExtendedProviderConfig("aws")
if err != nil {
    return err
}

// Set region (required for AWS)
config.Region = "us-east-1"

// Customize as needed
config.AWSProfile = "production"
config.AutoRefresh = 840
config.Background = true

// Validate
if err := config.Validate(); err != nil {
    return err
}

// Get template for endpoint resolution
template, err := oidc.GetTemplate("aws")
if err != nil {
    return err
}
authEndpoint, tokenEndpoint := config.ResolveEndpoints(template, config.Region)
```

### Template Properties

```go
type ProviderTemplate struct {
    Name                      string
    Description               string
    Issuer                    string      // For standard OIDC
    AuthorizeEndpointTemplate string      // May contain {region}
    TokenEndpointTemplate     string      // May contain {region}
    ClientID                  string
    ClientIDCrossDevice       string
    Scopes                    []string
    DPoP                      bool
    DefaultOutput             OutputMode
    DefaultAWSProfile         string
    DefaultAutoRefresh        int
    SupportsRemoteFlow        bool
    CustomResponseHandler     string
    RequiresRegion            bool
    TokenEncoding             TokenEncoding // empty means form
    DeviceStyle               DeviceStyle   // empty means RFC 8628
    Flows                     []Flow        // empty means authorization code only
    NoRefresh                 bool
    TokenLifetime             time.Duration
}
```

Field list from `pkg/oidc/templates.go:42`.

### DPoP Key Management

```go
import "github.com/jeremyhahn/go-xkms/pkg/oidc"

// Generate new DPoP key
dpopKey, err := oidc.GenerateDPoPKey()

// Generate proof for token request
proof, err := dpopKey.GenerateProof(&oidc.DPoPProofOptions{
    HTTPMethod: "POST",
    HTTPUri:    "https://us-east-1.signin.aws.amazon.com/v1/token",
    Nonce:      serverProvidedNonce,
})

// Serialize for storage
pemData, err := dpopKey.SerializePrivateKey()

// Deserialize
loadedKey, err := oidc.DeserializeDPoPKey(pemData)
```

### Output Handlers

```go
import (
    "github.com/jeremyhahn/go-xkms/xkey/pkg/oidc/handlers"
)

// AWS credentials handler
awsHandler := handlers.NewAWSCredentialsHandler("production").
    WithPath("~/.aws/credentials").
    WithRegion("us-east-1")

// JSON handler
jsonHandler := handlers.NewJSONHandler().
    WithAWSOnly()

// Exec handler
execHandler := handlers.NewExecHandler("./my-script.sh")

// Chain handlers
chain := handlers.NewChainHandler(awsHandler, execHandler)
if err := chain.Handle(ctx, tokenData); err != nil {
    return err
}
```

---

## See Also

- [xkey documentation index](../README.md)
- [AWS Signin OIDC](https://docs.aws.amazon.com/signin/latest/userguide/oidc-native.html)
- [DPoP RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
- [PKCE RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
- [Okta Developer Docs](https://developer.okta.com/docs/)
