# Configuration Documentation

> **Status: REFERENCE** · Last verified: 2026-10-12
> Index of configuration topics; each feature folder is normative for its own keys.

This directory contains configuration guides for various aspects of go-xkms.

## Configuration Topics

### Build Configuration
- [Build toggles](../crypto-backends/engineering.md#build-toggles) - Build tags and the `WITH_*` Makefile toggles

### Encryption Configuration
- [Symmetric Encryption & AEAD](../symmetric-aead/) - Algorithm auto-selection, per-key byte budgets and symmetric key usage

### Bootstrap Configuration
- [CA Bundle Bootstrap](../trust-bootstrap/engineering.md#configuration) - Noise bootstrap listener and the resolver's `trust:` section

### Barrier and PIN Configuration

The barrier encrypts the node's data plane at rest; the PIN manager governs
the user PIN. Both are top-level sections of the `xkmsd` configuration
(`pkg/config/config.go:56-57`).

#### Barrier Configuration

Keys of `BarrierConfig` (`pkg/config/config.go:161`):

```yaml
barrier:
  # Required: with the barrier off, ComplianceGaps reports it and the daemon
  # refuses to start.
  enabled: true

  # none | passphrase | shamir | tpm2 | pkcs11 | awskms | gcpkms | azurekv | vault
  # Empty defaults to passphrase. passphrase and shamir never auto-unseal:
  # the secret is supplied at initialize/unseal time, never in configuration.
  strategy: tpm2

  # Barrier root-key location in the seal store.
  root_key_path: ""

  # M-of-N quorum for the shamir strategy.
  shamir_threshold: 0
  shamir_total: 0

  # Order in which configured hardware backends are tried for sealing.
  preference_order: [tpm2, pkcs11]

  # Let the pre-unseal listener bind a non-loopback server.host (default false).
  sealed_window_allow_remote: false

  # How long the pre-unseal listener waits; empty = DefaultSealedWindowTimeout,
  # "0"/"none"/"disabled" = wait indefinitely, otherwise a Go duration.
  sealed_window_timeout: "10m"
```

#### PIN Configuration

Keys of `PINConfig` (`pkg/config/config.go:262`):

```yaml
pin:
  enabled: true
  # "" or auto | software | tpm2 (pkg/server/pin_manager.go:32)
  strategy: auto
  max_attempts: 5
  lockout_duration: 5m
```

PIN state is stored under `<datastore.path>/pin`, so `datastore.path` must be
set when the PIN manager is enabled (`pkg/server/pin_manager.go:61-67`).
`max_attempts` and `lockout_duration` are parsed but not read by the server.

**Related documentation:**
- [Sealing and Barrier](../sealing-and-barrier/architecture.md)
- [PIN Management](../pin-management/architecture.md)
- [CLI PIN Commands](../../xkey/docs/usage/cli/pin.md)

### Attested-Caller Gate

`attestation.peer_gate` (`pkg/config/attestation.go:59`) installs go-qrdb's
attested-caller gate on the embedded node:

```yaml
attestation:
  # off (default) | optional | required. optional admits a peer that has
  # never submitted evidence and refuses one whose evidence fails; required
  # refuses any gated call without fresh, passing evidence.
  peer_gate: required
```

Any value but `off` requires `datastore.mode: standalone`, and an unknown value
fails validation (`pkg/config/config.go:1801-1806`). The policy (anchors, PCR
baseline, gated permissions, maximum evidence age) is not configuration: the
embedder passes it with `server.WithAttestedCallerPolicy`. See
[Attested Peer](../attested-peer/api.md#installing-the-gate).

### Client Transport Security

A gRPC or REST client never sends a credential over a TLS-disabled TCP
channel (ruling 152). The constructors refuse a gRPC address with `TLSEnabled`
off that is not `unix:`, and any REST base URL that is not `https://`, with
`transport.ErrInsecureTransport` (`pkg/api/transport/errors.go:68`,
`pkg/api/transport/grpc/transport.go:95`, `pkg/api/transport/rest/transport.go:121`).
`SignImage` checks again before it sends registry credentials, because the
caller can change the config after construction
(`pkg/api/transport/grpc/transport_signing_key.go:96`,
`pkg/api/transport/rest/transport_signing_key.go:92`). The guard covers every
credential these clients carry: the JWT bearer token, the `Headers` (API
keys), the PINs and passwords in request bodies, and the registry username and
password.

| Setting | Where | Default |
|---------|-------|---------|
| `AllowInsecureTransport` | `transport.Config` (`pkg/api/transport/transport.go:105`), option `transport.WithAllowInsecureTransport`, SDK `BackendConfig` (`sdk/go/xkms.go:140`) | `false` |
| `XKMS_TRANSPORT_ALLOW_INSECURE_TRANSPORT` | environment (`pkg/api/transport/secure_channel.go:28`); when set it overrides the field, and an unparsable value keeps the guard on | unset |

The opt-out is for loopback tests and dev setups only, never production. It
mirrors the PKCS#11 module's `XKMS_PKCS11_ALLOW_INSECURE_TRANSPORT`, which the
module passes on to the transport (`pkg/pkcs11/module/module.go:1036`). QUIC
and MCP always use TLS, and unix sockets never leave the host, so neither
needs the opt-out.

### Backend-Specific Configuration
- [TPM2 Session Encryption](../tpm2/engineering.md#bus-protection) - TPM 2.0 session encryption (always on, not configurable)

### TPM Dashboard GUI

The xkey GUI's TPM view (`xkey/frontend/src/views/TPM.svelte`) is documented
in [xkey GUI](../../xkey/docs/gui/user.md); policy management is in
[TPM policies](../tpm-policies/user.md).

## Configuration Best Practices

1. **Security**: Always use hardware-backed storage for production environments
2. **Key Types**: Choose appropriate key types and algorithms for your use case
3. **Storage**: Configure appropriate storage backends for your deployment model

## See Also

- [Architecture Overview](../architecture/overview.md)
- [Backend Documentation](../crypto-backends/)
- [Getting Started Guide](../../xkey/docs/usage/getting-started.md)
