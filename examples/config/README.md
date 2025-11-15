# Configuration Examples

This directory contains example configuration files for different go-keychain server deployments.

## Available Configurations

| File | Description | Protocols |
|------|-------------|-----------|
| config-server.yaml | Unified server | REST, gRPC, QUIC, MCP |
| config-rest.yaml | REST-only server | REST |
| config-grpc.yaml | gRPC-only server | gRPC |
| config-quic.yaml | QUIC-only server | QUIC |
| config-mcp.yaml | MCP-only server | MCP |

## Usage

### With Docker

1. Copy the desired config to `configs/config.yaml`:
   ```bash
   cp examples/config/config-server.yaml configs/config.yaml
   ```

2. Update paths and credentials in the config file

3. Run the container:
   ```bash
   docker run -d \
     -v $(PWD)/configs:/etc/keychain:ro \
     -p 8443:8443 \
     go-keychain/server:latest
   ```

### With Docker Compose

1. Copy configs to the appropriate names:
   ```bash
   cp examples/config/config-server.yaml configs/config.yaml
   cp examples/config/config-rest.yaml configs/config-rest.yaml
   cp examples/config/config-grpc.yaml configs/config-grpc.yaml
   ```

2. Start services:
   ```bash
   make compose-prod-up
   ```

## Configuration Sections

### Server

Defines host and port bindings:

```yaml
server:
  host: 0.0.0.0  # Listen on all interfaces
  rest_port: 8443
  grpc_port: 9443
  quic_port: 8444
  mcp_port: 9444
```

### Protocols

Enable/disable specific protocols:

```yaml
protocols:
  rest: true
  grpc: true
  quic: false  # Disable QUIC
  mcp: false   # Disable MCP
```

### TLS

Configure TLS/mTLS settings:

```yaml
tls:
  enabled: true
  cert_file: /etc/keychain/server.crt
  key_file: /etc/keychain/server.key
  client_auth: require_and_verify  # Enforce mTLS
  min_version: TLS1.2
```

### Authentication

Configure authentication method:

```yaml
auth:
  enabled: true
  type: mtls  # Options: noop, apikey, mtls, jwt

  # API Key example
  # type: apikey
  # api_keys:
  #   key123:
  #     subject: client1
  #     roles: [admin]

  # JWT example
  # type: jwt
  # jwt:
  #   secret: your-secret
  #   issuer: keychain
```

### Backends

Configure key storage backends:

```yaml
default_backend: pkcs8  # Default backend for operations

backends:
  pkcs8:
    enabled: true
    path: /var/lib/keychain/keys

  tpm2:
    enabled: true
    device_path: /dev/tpmrm0

  pkcs11:
    enabled: true
    library: /usr/lib/softhsm/libsofthsm2.so
    token_label: keychain-token
    pin: "1234"

  awskms:
    enabled: true
    region: us-east-1

  gcpkms:
    enabled: true
    project_id: my-project

  azurekv:
    enabled: true
    vault_url: https://my-vault.vault.azure.net/

  vault:
    enabled: true
    address: https://vault.example.com:8200
```

## Environment Variables

Use environment variables for sensitive data:

```yaml
backends:
  awskms:
    enabled: true
    region: us-east-1
    access_key_id: ${AWS_ACCESS_KEY_ID}
    secret_access_key: ${AWS_SECRET_ACCESS_KEY}
```

Then set in Docker:

```bash
docker run -d \
  -e AWS_ACCESS_KEY_ID=xxx \
  -e AWS_SECRET_ACCESS_KEY=yyy \
  go-keychain/server:latest
```

## Security Recommendations

1. **Always use TLS in production**:
   ```yaml
   tls:
     enabled: true
     min_version: TLS1.2
   ```

2. **Enable mTLS for client authentication**:
   ```yaml
   tls:
     client_auth: require_and_verify
   auth:
     type: mtls
   ```

3. **Use environment variables for secrets**:
   - Don't commit credentials to config files
   - Use Docker secrets, Kubernetes secrets, or env vars

4. **Enable rate limiting**:
   ```yaml
   ratelimit:
     enabled: true
     requests_per_min: 1000
   ```

5. **Mount configs as read-only**:
   ```bash
   -v $(PWD)/configs:/etc/keychain:ro
   ```

## Troubleshooting

### Invalid config

Check config syntax:
```bash
docker run --rm \
  -v $(PWD)/configs:/etc/keychain:ro \
  go-keychain/server:latest \
  --config /etc/keychain/config.yaml --validate
```

### Permission errors

Ensure correct ownership:
```bash
chown -R 1000:1000 configs/
```

### TLS errors

Verify certificate paths and permissions:
```bash
ls -la configs/*.crt configs/*.key
```

## Additional Resources

- [Main Documentation](../../README.md)
- [Docker Guide](../../docs/deployment/docker.md)
- [TLS Configuration](../../docs/tls.md)
- [Backend Configuration](../../docs/backends.md)
