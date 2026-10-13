# Quick Start: First-Time Setup

> **Status: REFERENCE** · Last verified: 2026-10-13
> First-time setup walkthrough; the canonical references are [docs/pin-management/](../../../docs/pin-management/user.md), [docs/xkmsd-configuration/](../../../docs/xkmsd-configuration/user.md) and [docs/certificate-authority/](../../../docs/certificate-authority/cli.md). Where they disagree, the feature folders win.

This guide walks through the complete first-time setup of xkms, from installation through establishing your first admin connection. It covers barrier initialization, PIN setup, and the available authentication methods for initial system configuration.

## Prerequisites

- `xkmsd` server binary built and installed
- `xkmsctl` CLI binary on `$PATH`
- `xkey` binary on `$PATH` (for FIDO2/PIV admin setup)
- Configuration file created (see [Configuration Reference](../configuration/README.md))

## Step 1: Start the Server

Start xkmsd with your configuration file:

```bash
xkmsd --config /etc/xkms/xkmsd.yaml
```

On first boot, the server starts in a **sealed** state. No key operations are available until the barrier is initialized and unsealed.

## Step 2: Initialize the Barrier

The barrier provides transparent at-rest encryption for all stored key material. It belongs to go-qrdb: `xkmsd` initializes it from the `seal` configuration, and `xkmsctl` has no `barrier` verb. On a desktop, run `xkey barrier init` before `xkey tpm` or `xkey pin` on a fresh data directory.

> **Deep dive**: [Barrier Architecture](../seal/architecture.md)

## Step 3: Set Up PINs

The dual-PIN model controls access: the Security Officer (SO) PIN for admin operations, and the User PIN for day-to-day access.

```bash
# Set the SO PIN (master admin PIN)
xkmsctl pin so-set
# Enter new SO PIN: ********

# Set the User PIN (requires SO PIN authorization)
xkmsctl pin user-set
# Enter SO PIN: ********
# Enter new User PIN: ********

# Verify both PINs
xkmsctl pin user-verify
xkmsctl pin so-verify
```

Each PIN flag (`--new-pin`, `--so-pin`, `--pin`) accepts `-` to read stdin and
is prompted for when omitted (`cmd/xkmsctl/pin.go:500-519`).

> **Deep dive**: [PIN Management](../../../docs/pin-management/user.md) | [PIN CLI Reference](cli/pin.md)

## Step 4: Test Basic Operations

Confirm the system is operational by generating a test key:

```bash
xkmsctl key generate test-key --key-type signing --key-algorithm ed25519
xkmsctl key list
xkmsctl key sign test-key "hello world"
xkmsctl key delete test-key
```

If all commands succeed, the barrier, PIN, and backend layers are working correctly.

## Step 5: Establish Admin Connection

Choose one or more of the following authentication methods for your initial admin connection. These methods can be combined for defense in depth.

---

### Option A: Mutual TLS (mTLS)

mTLS provides certificate-based mutual authentication. Both the server and client present certificates signed by a shared CA.

**1. Generate CA and certificates:**

```bash
# Generate a self-signed CA (or use your existing PKI)
xkmsctl cert generate-ca --cn "xkms CA" --org MyOrg \
  --output /etc/xkms/tls/ca.pem --key-output /etc/xkms/tls/ca-key.pem

# Generate server certificate
xkmsctl cert issue \
  --ca-cert /etc/xkms/tls/ca.pem --ca-key /etc/xkms/tls/ca-key.pem \
  --cn xkmsd --org MyOrg --type server \
  --dns localhost --ip 127.0.0.1 \
  --output /etc/xkms/tls/server.pem --key-output /etc/xkms/tls/server-key.pem

# Generate admin client certificate
xkmsctl cert issue \
  --ca-cert /etc/xkms/tls/ca.pem --ca-key /etc/xkms/tls/ca-key.pem \
  --cn admin --org MyOrg --type client \
  --output /etc/xkms/tls/admin.pem --key-output /etc/xkms/tls/admin-key.pem
```

Flags: `cert generate-ca` at `cmd/xkmsctl/cert.go:1114-1124`, `cert issue` at
`cert.go:1128-1144`.

**2. Configure the server** (`xkmsd.yaml`):

```yaml
tls:
  enabled: true
  cert_file: /etc/xkms/tls/server.pem
  key_file: /etc/xkms/tls/server-key.pem
  ca_file: /etc/xkms/tls/ca.pem
  client_auth: require_and_verify
  client_cas:
    - /etc/xkms/tls/ca.pem

auth:
  enabled: true
  type: mtls
  mtls: true
  enable_rbac: true
```

**3. Connect with the admin certificate:**

```bash
xkmsctl --tls-cert /etc/xkms/tls/admin.pem \
        --tls-key /etc/xkms/tls/admin-key.pem \
        --tls-ca /etc/xkms/tls/ca.pem \
        admin status
```

> **Deep dive**: [Authentication Configuration](../../../docs/xkmsd-configuration/engineering.md#authentication-and-client-certificate-settings) | [TLS CLI Reference](../../../docs/certificate-authority/cli.md)

---

### Option B: PIV (Smart Card / YubiKey)

PIV provides hardware-backed certificate authentication using smart card slots. This is ideal for environments with PKCS#11-capable tokens.

**1. Generate a PIV authentication key:**

```bash
# List available PIV slots
xkmsctl piv list --backend pkcs11

# Generate key in the Authentication slot (9a)
xkmsctl piv generate 9a --backend pkcs11 --algorithm ecdsap256 --subject "CN=Admin"

# Generate a CSR for CA signing (optional, for enterprise PKI)
xkmsctl piv csr 9a --backend pkcs11 --subject "CN=Admin,O=MyOrg"
```

**2. Export the certificate for client auth:**

```bash
xkmsctl piv export 9a --backend pkcs11 > /etc/xkms/tls/admin-piv.pem
```

**3. Configure mTLS to trust the PIV CA** and connect using the PIV-backed certificate. The PKCS#11 module handles the private key operations on the hardware token.

> **Deep dive**: [PIV Documentation](../piv/user.md) | [PIV CLI Reference](cli/piv.md) | [PKCS#11 Backend](../../../docs/pkcs11-backend/user.md)

---

### Option C: FIDO2 / WebAuthn

FIDO2 provides passwordless authentication using security keys or the xkey virtual authenticator.

**1. Start the xkey FIDO2 virtual authenticator** (or use a hardware security key):

```bash
# Software backend for development
echo 123456 | sudo xkey fido2 --pin --set-pin-stdin

# Or with TPM-backed keys for production
echo 123456 | sudo xkey fido2 --backend tpm2 --pin --set-pin-stdin
```

**2. Register the admin FIDO2 credential:**

```bash
xkmsctl admin create admin --method fido2 --email admin@example.com
```

Follow the prompts to touch your security key or approve in the xkey terminal.

**3. Authenticate with FIDO2:**

```bash
xkmsctl auth login --method fido2
```

`--method` is one of `mtls`, `fido2`, `piv`, `pkcs11`
(`cmd/xkmsctl/auth_factor_handlers.go:303`).

> **Deep dive**: [WebAuthn Documentation](webauthn.md) | [FIDO2 CLI Reference](cli/fido2.md) | [xKey FIDO2](../fido2/architecture.md)

---

### Option D: xkey in Server Mode against xkmsd

xkey can reach an xkmsd server so that certificate and secret operations run
against the server's backends instead of locally. This is enabled by the global
`--xkmsd-url` flag — there is no `xkmsd` *backend* value.

**1. Point xkey at the server:**

```bash
# Unix socket
xkey ca info --xkmsd-url unix:///var/run/xkms/xkms.sock

# gRPC
xkey ca info --xkmsd-url grpc://localhost:9443

# gRPC over TLS
xkey ca info --xkmsd-url grpcs://xkms.example.com:8443
```

`--xkmsd-url` is a persistent root flag, so it applies to any subcommand. It
resolves in this order (`resolveXKMSdEndpoint`):

1. the explicit `--xkmsd-url` flag
2. `XKMSD_URL` / `XKEY_XKMSD_URL`
3. the `xkmsd_url` config key
4. the `xkmsd.address` key of the unified xkey config

The auth token is `XKMSD_TOKEN` when set; otherwise xkey presents the login
`xkey auth login` stored for that server (an expired login fails with the
`xkey auth refresh` command to run). The CA bundle comes from `--tls-ca`, then
`XKMSD_TLS_CA`, then `xkmsd.tls_ca_file`.

A stored login is bound to the server's identity, not to the URL it was made
through: the SPKI SHA-256 thumbprint of the TLS certificate the server
presents, read from a handshake verified by the same trust as the call. The
server presents one certificate on REST, gRPC, QUIC and MCP, so a login made
over `https://` serves `grpcs://`, `quic://` and `mcps://` to that server too,
whatever the port. A different certificate is a different server, even on the
same host, and never receives the login. When the server's key changes (a
reissued certificate), log in again. A Unix socket carries no certificate:
there, `XKMSD_SERVER_NAME` (or `xkmsd.server_name`) names the server, and the
login whose host matches is used; a name matching logins to two different
servers is refused rather than guessed.

`xkey auth login --piv` needs no prior `xkey auth register`: an unregistered
server is reached by the `--server` URL and verified by the xKey trust store,
the system roots and `--tls-ca`.

**2. The commands that use server mode** are `xkey ca`, `xkey password`,
`xkey platform-store` and `xkey agent`. `xkey agent start` *requires* it —
xkey never signs certificates locally:

```bash
xkey agent start --xkmsd-url unix:///var/run/xkmsd.sock
```

The global `--backend` flag selects which backend the *server* should use
(`software`, `tpm2`, `pkcs11`).

> **Note**: this is separate from the FIDO2 daemon's key backend.
> `xkey fido2 --backend` is a local flag that shadows the global one and accepts
> only `software`, `tpm2` or `phone`. The FIDO2 authenticator has no
> xkmsd-backed key mode — see [FIDO2 Daemon Configuration](../virtual-authenticator/cli.md).

> **Deep dive**: [xKey Overview](../README.md) | [xKey Phone Backend](../phone/README.md)

## Step 6: Daily Operations

The server unseals the barrier on each restart through the configured seal strategy; TPM 2.0 and PKCS#11 strategies need no passphrase.

## What's Next

| Topic | Document |
|-------|----------|
| Backend selection and Go API | [Getting Started](getting-started.md) |
| Full initialization procedures | [Initialization Guide](initialization.md) |
| Barrier encryption architecture | [Seal/Unseal Architecture](../seal/architecture.md) |
| Bootstrap for new nodes | [Bootstrap Configuration](../../../docs/trust-bootstrap/engineering.md#configuration) |
| CLI command reference | [CLI Overview](cli/README.md) |
| PIV slot management | [PIV Documentation](../piv/user.md) |
| xKey security key interface | [xKey Overview](../README.md) |
| Docker deployment | [Docker Quick Start](../../../docs/deployment/docker-quickstart.md) |
