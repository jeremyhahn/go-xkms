# cactl Command Reference

`cactl` is a multi-protocol CLI for administering the go-xkms server.

## Overview

cactl supports communication over multiple transport protocols:

| Protocol | Transport | Default Address | Use Case |
|----------|-----------|-----------------|----------|
| unix | gRPC over UDS | /run/trusted-ca-grpc.sock | Local operations (fastest) |
| rest | HTTP/HTTPS | https://localhost:8443 | Web clients, external systems |
| grpc | TCP | localhost:9443 | High-performance service-to-service |
| quic | UDP/HTTP3 | localhost:9444 | Low-latency, mobile clients |
| mcp | stdio/HTTP | localhost:9445 | AI/LLM integration |

## Transport Options

| Flag | Description |
|------|-------------|
| `--transport unix` | gRPC over Unix socket (default, fastest) |
| `--transport grpc` | gRPC over TCP |
| `--transport rest` | REST/HTTP |
| `--transport quic` | QUIC/UDP |
| `--transport mcp` | MCP (AI integration) |

### Unix Socket (Default)

Uses gRPC over Unix domain socket with SO_PEERCRED authentication.

```bash
cactl status
cactl --transport unix --address /run/trusted-ca-grpc.sock status
```

## Installation

Build from source:

```bash
make build
# Binary available at ./bin/cactl
```

Install to system:

```bash
sudo cp ./bin/cactl /usr/local/bin/
```

## Configuration

Configuration is resolved in order of priority:

1. Command-line flags (highest)
2. Environment variables (`CACTL_*` prefix)
3. Configuration file (`~/.cactl.yaml`)

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| CACTL_ADDRESS | Server address | /run/trusted-ca-grpc.sock |
| CACTL_TRANSPORT | Protocol (unix/rest/grpc/quic/mcp) | unix |
| CACTL_OUTPUT | Output format (json/yaml/table) | table |
| CACTL_TIMEOUT | Request timeout | 30s |
| CACTL_TOKEN | Authentication token | |
| CACTL_TLS_CA | CA certificate file | |
| CACTL_TLS_CERT | Client certificate file | |
| CACTL_TLS_KEY | Client private key file | |
| CACTL_LOG_LEVEL | Log level | info |

### Configuration File

Create `~/.cactl.yaml`:

```yaml
# Server connection
address: /run/trusted-ca-grpc.sock
transport: unix
timeout: 30s

# Output formatting
output: table
log-level: info

# Authentication
token: your-api-token

# TLS configuration (for rest/grpc/quic)
tls-ca: /etc/trusted-ca/ca.crt
tls-cert: /etc/trusted-ca/client.crt
tls-key: /etc/trusted-ca/client.key
```

## Global Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| --address | -a | Server address (socket path or host:port) | /run/trusted-ca-grpc.sock |
| --transport | -t | Protocol (unix/rest/grpc/quic/mcp) | unix |
| --output | -o | Output format (json/yaml/table) | table |
| --config | -c | Config file path | ~/.cactl.yaml |
| --timeout | | Request timeout | 30s |
| --token | | Authentication token for REST/gRPC | |
| --tls-ca | | CA certificate file for TLS verification | |
| --tls-cert | | Client TLS certificate file | |
| --tls-key | | Client TLS private key file | |
| --log-level | | Log level (debug/info/warn/error) | info |

## Commands

### status

Retrieve the current status of the Certificate Authority.

Displays information including:
- Identity and version
- Initialization state
- Cryptographic algorithms in use
- Root and intermediate CA information

```bash
cactl status [flags]
```

### stats

Retrieve statistics about the Certificate Authority.

Displays metrics including:
- Total, valid, revoked, and expired certificates
- Total and active accounts
- Total, pending, and completed orders

```bash
cactl stats [flags]
```

### cert

Manage certificates issued by the Certificate Authority.

#### cert list

List certificates with optional filtering and pagination.

```bash
cactl cert list [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| --status | Filter by status (valid/revoked/expired) | |
| --page | Page number | 1 |
| --per-page | Items per page | 20 |

#### cert get

Retrieve a certificate by serial number.

```bash
cactl cert get [serial] [flags]
```

Serial format: `01:02:03:04:05:06:07:08` or plain hex.

#### cert revoke

Revoke a certificate by serial number.

```bash
cactl cert revoke [serial] [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| --reason | Revocation reason (RFC 5280) | unspecified |

Valid reasons: `unspecified`, `keyCompromise`, `caCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `removeFromCRL`, `privilegeWithdrawn`, `aaCompromise`

### account

Manage ACME accounts registered with the Certificate Authority.

#### account list

List ACME accounts with optional filtering and pagination.

```bash
cactl account list [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| --status | Filter by status (valid/deactivated/revoked) | |
| --page | Page number | 1 |
| --per-page | Items per page | 20 |

#### account get

Retrieve an ACME account by ID.

```bash
cactl account get [account-id] [flags]
```

#### account disable

Disable an ACME account, preventing further certificate operations.

```bash
cactl account disable [account-id] [flags]
```

Disabling prevents:
- Creating new certificate orders
- Finalizing pending orders
- Renewing existing certificates

Existing certificates remain valid until expiration.

### tenant

Manage tenants for multi-tenant certificate management.

Tenants provide logical isolation for:
- Certificate management
- Policies
- External Account Bindings

#### tenant create

Create a new tenant.

```bash
cactl tenant create [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| --name | Tenant name (required) | |
| --domain | Tenant domain | |
| --enabled | Enable tenant | true |

#### tenant get

Retrieve tenant details.

```bash
cactl tenant get [tenant-id] [flags]
```

#### tenant update

Update tenant configuration.

```bash
cactl tenant update [tenant-id] [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| --name | Tenant name | |
| --domain | Tenant domain | |
| --enabled | Enable tenant | true |

#### tenant delete

Delete a tenant and all associated resources.

```bash
cactl tenant delete [tenant-id] [flags]
```

Warning: Irreversible. Deletes all certificates, accounts, and policies.

#### tenant list

List all tenants.

```bash
cactl tenant list [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| --page | Page number | 1 |
| --per-page | Items per page | 20 |

### tenant eab

Manage External Account Bindings for ACME account registration.

EAB credentials bind ACME accounts to pre-authorized identities for controlled account creation and TPM-based device enrollment.

#### tenant eab create

Create a new EAB credential.

```bash
cactl tenant eab create [tenant-id] [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| --contact | Contact email | |

Note: The MAC key is only displayed once. Store it securely.

#### tenant eab get

Retrieve EAB credential information.

```bash
cactl tenant eab get [tenant-id] [kid] [flags]
```

Note: MAC key is never returned after creation.

#### tenant eab delete

Delete an EAB credential.

```bash
cactl tenant eab delete [tenant-id] [kid] [flags]
```

#### tenant eab list

List EAB credentials for a tenant.

```bash
cactl tenant eab list [tenant-id] [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| --page | Page number | 1 |
| --per-page | Items per page | 20 |

### tenant policy

Manage Attribute-Based Access Control (ABAC) policies.

Policies define authorization rules based on subject attributes, resource properties, and environmental context.

#### tenant policy create

Create a new ABAC policy from a JSON file.

```bash
cactl tenant policy create [tenant-id] [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| --name | Policy name (required) | |
| --file | JSON policy file (required) | |

#### tenant policy get

Retrieve policy details.

```bash
cactl tenant policy get [tenant-id] [policy-name] [flags]
```

#### tenant policy update

Update an existing policy.

```bash
cactl tenant policy update [tenant-id] [policy-name] [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| --file | JSON policy file (required) | |

#### tenant policy delete

Delete a policy.

```bash
cactl tenant policy delete [tenant-id] [policy-name] [flags]
```

Warning: May affect access control for dependent resources.

#### tenant policy list

List policies for a tenant.

```bash
cactl tenant policy list [tenant-id] [flags]
```

### version

Display version information.

```bash
cactl version [flags]
```

Shows version number, git commit hash, build date, and Go version.

## Examples

### Unix Socket (Default)

```bash
# Check server status (uses gRPC over Unix socket)
cactl status

# List certificates in JSON
cactl cert list -o json

# Get CA statistics
cactl stats

# Explicit Unix socket path
cactl --transport unix --address /run/trusted-ca-grpc.sock status
```

### REST API

```bash
# Status via REST
cactl -t rest -a https://localhost:8443 status

# List certificates with authentication
cactl -t rest -a https://localhost:8443 --token $API_TOKEN cert list

# With TLS client certificates
cactl -t rest -a https://localhost:8443 \
  --tls-ca /etc/ca.crt \
  --tls-cert /etc/client.crt \
  --tls-key /etc/client.key \
  cert list
```

### gRPC

```bash
# Status via gRPC
cactl -t grpc -a localhost:9443 status

# Create tenant via gRPC
cactl -t grpc -a localhost:9443 tenant create --name "Example Corp"

# List accounts with pagination
cactl -t grpc -a localhost:9443 account list --page 2 --per-page 100
```

### QUIC

```bash
# Low-latency status check
cactl -t quic -a localhost:9444 status

# Certificate operations
cactl -t quic -a localhost:9444 cert list --status valid
```

### MCP (AI/LLM Integration)

```bash
# Status via MCP
cactl -t mcp -a localhost:9445 status

# JSON output for parsing
cactl -t mcp -a localhost:9445 stats -o json
```

### Multi-Tenant Operations

```bash
# Create tenant
cactl tenant create --name "Acme Inc" --domain acme.com

# Create EAB credential for device enrollment
cactl tenant eab create tenant-abc123 --contact admin@acme.com

# Create ABAC policy
cactl tenant policy create tenant-abc123 --name admin-access --file admin-policy.json

# List tenant certificates (via tenant-scoped admin)
cactl -t rest -a https://localhost:8443 --token $TENANT_TOKEN cert list
```

### Certificate Lifecycle

```bash
# List all valid certificates
cactl cert list --status valid

# Get certificate details
cactl cert get 01:02:03:04:05:06:07:08 -o json

# Revoke compromised certificate
cactl cert revoke 01:02:03:04:05:06:07:08 --reason keyCompromise

# Verify revocation
cactl cert get 01:02:03:04:05:06:07:08
```

### Shell Completion

Generate completion scripts:

```bash
# Bash
cactl completion bash > /etc/bash_completion.d/cactl

# Zsh
cactl completion zsh > "${fpath[1]}/_cactl"

# Fish
cactl completion fish > ~/.config/fish/completions/cactl.fish

# PowerShell
cactl completion powershell > cactl.ps1
```
