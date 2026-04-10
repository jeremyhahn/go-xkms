# OIDC OpenID Connect Authentication

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
| `--session-store` | `~/.config/xkey/aws-session.json` | Path to session store |
| `--background` | `false` | Run auto-refresh in background |
| `--log-file` | (auto-generated) | Log file for background refresh |

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
| `AWS_REGION` | AWS region |
| `AWS_EXPIRATION` | Credential expiration time |

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

Any OpenID Connect-compliant identity provider with discovery support.

**Required fields:**
- `--issuer` - Provider issuer URL (must have `/.well-known/openid-configuration`)
- `--client-id` - OAuth2 client ID

**Optional fields:**
- `--client-secret` - For confidential clients
- `--redirect-url` - Callback URL (default: `http://localhost:8085/callback`)
- `--scopes` - Scopes to request (default: `openid,profile,email`)

### AWS Provider (`--type aws`)

Direct AWS Console authentication using DPoP.

**Required fields:**
- `--region` - AWS region

**Optional fields:**
- `--profile` - AWS profile name (default: `default`)
- `--credentials-file` - AWS credentials file (default: `~/.aws/credentials`)
- `--output` - Output mode (default: `aws-credentials`)
- `--cross-device` - Enable cross-device authentication
- `--session-store` - Session storage path

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
  --log-file ~/.config/xkey/logs/aws-prod.log

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
  Session Store: /home/user/.config/xkey/aws-session.json
  Auto-Refresh: 840 seconds
  Background:   yes
  Log File:     /home/user/.config/xkey/logs/aws-prod.log

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
| `--redirect-url` | `http://localhost:8085/callback` | Local callback URL |
| `--scopes` | `openid,profile,email` | Scopes to request |
| `--token-store` | `~/.config/xkey/tokens.json` | Path to token store |
| `--no-browser` | `false` | Print URL instead of opening browser |
| `--exec` | | Execute script after login |
| `--auto-refresh` | `0` | Auto-refresh interval in seconds |
| `--background` | `false` | Run auto-refresh in background |
| `--log-file` | (auto-generated) | Log file for background refresh |

**When `--provider` specifies an AWS provider, all AWS-specific settings are loaded and the AWS login flow is used automatically.**

### oidc aws

Direct AWS Console authentication with DPoP. See [AWS Console Native Login](#aws-console-native-login) section.

### oidc token

Display current token information.

```
xkey oidc token [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--token-store` | `~/.config/xkey/tokens.json` | Path to token store |
| `--show-full` | `false` | Show full token values |

### oidc refresh

Refresh the access token using the stored refresh token.

```
xkey oidc refresh [flags]
```

### oidc logout

Clear stored tokens (local only - does not revoke at provider).

```
xkey oidc logout [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--all` | `false` | Remove the entire token store file |

### oidc status

Show running background refresh processes.

```
xkey oidc status [flags]
```

**Output:**

```
Background Refresh Processes (2):

  Provider:   aws-us-east-1
  PID:        12345
  Started:    2025-02-01 17:30:00 (45 minutes ago)
  Log file:   ~/.config/xkey/logs/aws-us-east-1.log

  Provider:   okta-aws
  PID:        12346
  Started:    2025-02-01 17:00:00 (1 hour 15 minutes ago)
  Log file:   ~/.config/xkey/logs/okta-aws.log
```

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
| `--redirect-url` | `http://localhost:8085/callback` | Callback URL |
| `--scopes` | | Scopes to request |

**AWS flags (`--type aws`):**

| Flag | Default | Description |
|------|---------|-------------|
| `--region`, `-r` | (required) | AWS region |
| `--profile` | `default` | AWS profile name |
| `--credentials-file` | `~/.aws/credentials` | AWS credentials file path |
| `--output`, `-o` | `aws-credentials` | Output mode |
| `--cross-device` | `false` | Enable cross-device authentication |
| `--session-store` | `~/.config/xkey/aws-session.json` | Session store path |

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
5. Starts local callback server
6. Receives authorization code and validates state
7. Exchanges code for tokens
8. Validates ID token and extracts claims
9. Stores tokens locally

### AWS DPoP Authorization Flow

1. Generates EC P-256 DPoP key pair
2. Generates PKCE code verifier and challenge (trimmed of `=` padding per AWS spec)
3. Generates cryptographic state parameter
4. Opens browser to `https://{region}.signin.aws.amazon.com/v1/authorize`
5. Starts local callback server at `http://127.0.0.1:8085/oauth/callback`
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

Default: `~/.config/xkey/tokens.json`

```json
{
  "tokens": [{
    "provider": "https://accounts.google.com",
    "issuer": "https://accounts.google.com",
    "client_id": "YOUR_CLIENT_ID",
    "access_token": "eyJhbG...",
    "refresh_token": "1//0g...",
    "id_token": "eyJhbG...",
    "expires_at": "2025-01-31T13:00:00Z",
    "scopes": ["openid", "profile", "email"]
  }]
}
```

### Provider Configuration

Default: `~/.config/xkey/oidc-providers.json`

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
      "name": "aws-prod",
      "type": "aws",
      "aws_region": "us-east-1",
      "aws_profile": "production",
      "auto_refresh": 840,
      "background": true,
      "log_file": "/home/user/.config/xkey/logs/aws-prod.log"
    }
  ]
}
```

### AWS Session Store

Default: `~/.config/xkey/aws-session.json`

Stores DPoP key and refresh token for AWS credential refresh.

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
tail -f ~/.config/xkey/logs/NAME.log
```

---

## Security Considerations

- **PKCE** is mandatory for all flows, protecting against code interception
- **DPoP** binds tokens to the client's key, preventing token theft
- **State parameters** are cryptographically random (32 bytes) for CSRF protection
- Token store files are created with `0600` permissions
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

### Using Templates in Go

```go
import "github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"

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
template, _ := oidc.GetTemplate("aws")
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
}
```

### DPoP Key Management

```go
import "github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"

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
chain.Handle(ctx, tokenData)
```

---

## See Also

- [xkey Overview](README.md)
- [AWS Signin OIDC](https://docs.aws.amazon.com/signin/latest/userguide/oidc-native.html)
- [DPoP RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
- [PKCE RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
- [Okta Developer Docs](https://developer.okta.com/docs/)
