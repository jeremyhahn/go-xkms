# External Key Escrow

The `pkg/escrow` package provides a pluggable framework for external key escrow per NIST SP 800-57. Key material is always pre-wrapped (AES-KW or RSA-OAEP) before transmission -- the escrow agent never sees plaintext keys.

## Architecture

```
  go-xkms Server
       |
  key wrapping (AES-KW / RSA-OAEP)
       |
   EscrowAgent  ---- EscrowAgent
   (xkms)             (kmip)
       |                  |
  Remote XKMS        KMIP Server
  (mTLS/HTTPS)       (mTLS/KMIP)
```

## EscrowAgent Interface

| Method | Description |
|--------|-------------|
| `Type()` | Returns agent type (`"xkms"` or `"kmip"`) |
| `Available(ctx)` | Reports if agent is reachable |
| `EscrowKey(ctx, req)` | Sends wrapped key to escrow service |
| `RecoverKey(ctx, req)` | Retrieves wrapped key from escrow |
| `ListEscrowed(ctx)` | Lists all escrowed keys |
| `RevokeEscrow(ctx, id)` | Removes an escrowed key |
| `Close()` | Releases agent resources |

## Registry

The `Registry` manages multiple agents and provides two dispatch strategies:

**Belt-and-suspenders (escrow):** `EscrowKeyAll` sends to ALL registered agents. Succeeds if at least one agent accepts.

**Failover (recovery):** `RecoverKeyAny` tries each agent until one succeeds. Returns the first successful response.

| Registry Method | Description |
|-----------------|-------------|
| `Register(name, agent)` | Registers an agent by name |
| `Get(name)` | Returns agent by name |
| `Agents()` | Lists registered agent names |
| `EscrowKeyAll(ctx, req)` | Escrow to ALL agents |
| `RecoverKeyAny(ctx, req)` | Recover from ANY agent |
| `ListAll(ctx)` | Aggregated listing from all agents |
| `Close()` | Closes all agents |

## Implementations

### XKMS Federation (`pkg/escrow/xkms`)

Production implementation. Replicates wrapped keys to a remote go-xkms instance over mTLS/HTTPS.

```go
agent, _ := xkms.NewFederationAgent(&xkms.FederationConfig{
    Endpoint:   "https://dr-xkms.company.com:8443",
    ClientCert: "/etc/xkms/certs/client.pem",
    ClientKey:  "/etc/xkms/certs/client-key.pem",
    CACert:     "/etc/xkms/certs/ca.pem",
})
```

API endpoints: `POST /api/v1/escrow/keys`, `POST .../recover`, `GET .../keys`, `DELETE .../keys/{id}`

### KMIP Agent (`pkg/escrow/kmip`)

Stub implementation. All methods return `ErrNotImplemented` until `github.com/ovh/kmip-go` is added. When implemented, it will support KMIP Register, Get, Locate, and Destroy operations.

## Request/Response Types

| Type | Fields |
|------|--------|
| `EscrowRequest` | KeyID, WrappedKey, WrappingAlgorithm, KeyType, TenantID, Purpose, Metadata |
| `EscrowReceipt` | EscrowID, KeyID, Agent, EscrowedAt, ExpiresAt |
| `RecoverRequest` | EscrowID or KeyID (at least one required) |
| `RecoverResponse` | KeyID, WrappedKey, WrappingAlgorithm |
| `EscrowRecord` | Full metadata for listing |

## Configuration

```yaml
escrow:
  enabled: true
  agents:
    - type: xkms
      endpoint: "https://dr-xkms.company.com:8443"
      client_cert: /etc/xkms/certs/client.pem
      client_key: /etc/xkms/certs/client-key.pem
      ca_cert: /etc/xkms/certs/ca.pem
```

## Error Reference

| Error | Condition |
|-------|-----------|
| `ErrAgentNotConfigured` | Agent type missing or not configured |
| `ErrAgentUnavailable` | Agent unreachable |
| `ErrEscrowFailed` | Escrow operation failed (all agents) |
| `ErrRecoverFailed` | Recovery failed (all agents) |
| `ErrKeyNotFound` | Escrowed key does not exist |
| `ErrAlreadyEscrowed` | Key already escrowed (409 Conflict) |
| `ErrAuthenticationFailed` | mTLS or auth failure |
| `ErrNotImplemented` | KMIP stub (dependency not added) |
| `ErrRegistryEmpty` | No agents registered |
| `ErrNilWrappedKey` | Empty wrapped key material |

## Cross-References

- [Barrier Encryption Architecture](../seal/README.md) -- barrier root key can be escrowed
- [MFA Policy Engine](../auth/mfa-policy.md) -- `escrow_key` and `recover_key` require 3FA by default
- [Custodian Groups](../custodian/README.md) -- human custodians for key ceremonies
