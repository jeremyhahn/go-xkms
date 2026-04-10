# Xkey OIDC Integration Tests

This directory contains integration tests for the Xkey OIDC functionality using a real ORY Hydra OIDC server.

## Overview

The OIDC integration tests validate the full OIDC functionality of the `pkg/oidc` package against a real OpenID Connect provider (ORY Hydra). These tests ensure compatibility with the OIDC specification and proper integration with real-world OIDC providers.

## Architecture

```
Docker Compose
├── hydra (ORY Hydra v2.2.0)
│   ├── Public API: port 4444
│   └── Admin API: port 4445
└── test-runner
    ├── setup-hydra.sh (creates OAuth2 clients)
    └── go test (runs integration tests)
```

## Test Coverage

### TestOIDC_ProviderDiscovery
- OIDC discovery endpoint (/.well-known/openid-configuration)
- Provider initialization
- Authorization/token endpoint discovery
- JWKS URI discovery
- Scope support detection
- PKCE support detection

### TestOIDC_ClientAuthCodeURL
- Authorization URL generation
- PKCE parameter inclusion
- Nonce parameter for ID tokens
- State parameter for CSRF protection

### TestOIDC_PKCEGeneration
- Code verifier generation (RFC 7636)
- Code challenge generation (S256)
- State generation
- Nonce generation
- Parameter uniqueness

### TestOIDC_TokenStore
- Memory token store operations
- File token store with encryption
- Token persistence across restarts
- CRUD operations (Save, Load, Delete, List)

### TestOIDC_TokenResponse
- Token validity checks
- Token expiration handling

### TestOIDC_ProviderConfig
- Configuration validation
- Scope handling
- Effective scopes (always includes openid)

### TestOIDC_LogoutURL
- End session URL generation

## Running Tests

### Via Make (Recommended)

```bash
make integration-test-xkey-oidc
```

This will:
1. Start ORY Hydra in dev mode
2. Create test OAuth2 clients
3. Run all OIDC integration tests
4. Clean up containers

### Manually with Docker Compose

```bash
cd test/integration/xkey/oidc
docker compose up --build
```

### Running Specific Tests

```bash
# Inside the test container or with Hydra running
go test -v -tags integration ./test/integration/xkey/oidc/... -run TestOIDC_ProviderDiscovery
```

## Test Clients

The `setup-hydra.sh` script creates three OAuth2 clients:

| Client | Grant Types | Scopes | Use Case |
|--------|-------------|--------|----------|
| xkey-test-client-credentials | client_credentials | api:read, api:write | Machine-to-machine |
| xkey-test-authcode | authorization_code, refresh_token | openid, profile, email, offline_access | Interactive login |
| xkey-test-oidc | client_credentials, refresh_token | openid, profile, email, offline_access | OIDC testing |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| XKEY_TEST_HYDRA_PUBLIC_URL | http://127.0.0.1:4444 | Hydra public API URL |
| XKEY_TEST_HYDRA_ADMIN_URL | http://127.0.0.1:4445 | Hydra admin API URL |
| XKEY_TEST_OIDC_CLIENT_ID | (from setup) | OIDC test client ID |
| XKEY_TEST_OIDC_CLIENT_SECRET | xkey-test-oidc-secret | OIDC test client secret |

## Known Limitations

1. **Client Credentials Flow**: Does not return ID tokens (no end-user involved)
2. **Authorization Code Flow**: Requires interactive login (tested for URL generation only)
3. **Hydra Dev Mode**: Accepts any username/password for password flow

## Troubleshooting

### Hydra Fails to Start
- Check if ports 4444/4445 are available
- Verify Docker is running
- Check `docker compose logs hydra`

### Tests Timeout
- Increase the healthcheck interval in docker-compose.yml
- Verify network connectivity between containers

### Client Creation Fails
- Check Hydra admin endpoint is accessible
- Verify jq is installed in the test container

## References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
- [ORY Hydra Documentation](https://www.ory.sh/docs/hydra/)
