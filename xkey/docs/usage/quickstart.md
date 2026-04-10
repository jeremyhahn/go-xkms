# Quick Start: First-Time Setup

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

The barrier provides transparent at-rest encryption for all stored key material using AES-256-GCM. Initialize it once:

```bash
# Auto-select the best available sealing strategy (prefers hardware)
xkmsctl barrier init

# Or specify a strategy explicitly
xkmsctl barrier init --strategy tpm2
xkmsctl barrier init --strategy software
```

For software strategy, you will be prompted for a passphrase. For hardware strategies (TPM 2.0, PKCS#11), no passphrase is needed.

Verify initialization:

```bash
xkmsctl barrier status
```

```
Barrier Status
  Sealed:          false
  Strategy:        software
  Hardware Backed: false
```

> **Deep dive**: [Barrier Architecture](../seal/README.md) | [Barrier CLI Reference](cli/barrier.md)

## Step 3: Set Up PINs

The dual-PIN model controls access: the Security Officer (SO) PIN for admin operations, and the User PIN for day-to-day access.

```bash
# Set the SO PIN (master admin PIN)
xkmsctl pin set-so
# Enter new SO PIN: ********
# Confirm SO PIN: ********

# Set the User PIN (requires SO PIN authorization)
xkmsctl pin set-user
# Enter SO PIN: ********
# Enter new User PIN: ********
# Confirm User PIN: ********

# Verify both PINs
xkmsctl pin verify
xkmsctl pin verify --type so
```

> **Deep dive**: [PIN Management](../seal/pin.md) | [PIN CLI Reference](cli/pin.md)

## Step 4: Test Basic Operations

Confirm the system is operational by generating a test key:

```bash
xkmsctl key generate test-key --key-type signing --algorithm ed25519
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
xkmsctl cert create-ca --subject "CN=xkms CA,O=MyOrg" --output /etc/xkms/tls/ca.pem

# Generate server certificate
xkmsctl cert issue \
  --ca /etc/xkms/tls/ca.pem \
  --subject "CN=xkmsd,O=MyOrg" \
  --san "DNS:localhost,IP:127.0.0.1" \
  --output /etc/xkms/tls/server.pem

# Generate admin client certificate
xkmsctl cert issue \
  --ca /etc/xkms/tls/ca.pem \
  --subject "CN=admin,O=MyOrg" \
  --output /etc/xkms/tls/admin.pem
```

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

> **Deep dive**: [Authentication Configuration](../configuration/auth.md) | [TLS CLI Reference](cli/tls.md)

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

> **Deep dive**: [PIV Documentation](../piv/README.md) | [PIV CLI Reference](cli/piv.md) | [PKCS#11 Backend](../backends/pkcs11.md)

---

### Option C: FIDO2 / WebAuthn

FIDO2 provides passwordless authentication using security keys or the xkey virtual authenticator.

**1. Start the xkey FIDO2 virtual authenticator** (or use a hardware security key):

```bash
# Software backend for development
sudo xkey fido2 --pin --set-pin 123456

# Or with TPM-backed keys for production
sudo xkey fido2 --backend tpm2 --pin --set-pin 123456
```

**2. Register the admin FIDO2 credential:**

```bash
xkmsctl admin create --auth fido2 --username admin
```

Follow the prompts to touch your security key or approve in the xkey terminal.

**3. Authenticate with FIDO2:**

```bash
xkmsctl --auth fido2 admin status
```

> **Deep dive**: [WebAuthn Documentation](webauthn.md) | [FIDO2 CLI Reference](cli/fido2.md) | [xKey FIDO2](../xkey/fido2.md)

---

### Option D: xkey with xkmsd Backend

xkey can connect directly to xkmsd and use the server's backends for all cryptographic operations. This enables centralized key management with xkey acting as the client interface.

**1. Configure xkey to use xkmsd:**

```bash
# Connect to xkmsd via REST
xkey fido2 --backend xkmsd --xkmsd-url https://localhost:8443

# Or via gRPC
xkey fido2 --backend xkmsd --xkmsd-url grpc://localhost:9090

# Or via Unix socket
xkey fido2 --backend xkmsd --xkmsd-url unix:///var/run/xkms/xkms.sock
```

**2. Use xkey for ongoing admin operations** with any supported transport (REST, gRPC, QUIC, Unix socket, MCP).

> **Deep dive**: [xKey Overview](../xkey/README.md) | [xKey Phone Backend](../xkey/phone-backend.md)

## Step 6: Daily Operations

After initial setup, the barrier must be unsealed on each server restart:

```bash
# Unseal (prompts for passphrase with software strategy)
xkmsctl barrier unseal

# TPM 2.0 or PKCS#11 strategies unseal automatically (no passphrase)
xkmsctl barrier unseal --strategy tpm2

# Scripted unseal
echo "$XKMS_PASSPHRASE" | xkmsctl barrier unseal
```

Before shutdown (optional but recommended):

```bash
xkmsctl barrier seal
```

## What's Next

| Topic | Document |
|-------|----------|
| Backend selection and Go API | [Getting Started](getting-started.md) |
| Full initialization procedures | [Initialization Guide](initialization.md) |
| Barrier encryption architecture | [Seal/Unseal Architecture](../seal/README.md) |
| Bootstrap for new nodes | [Bootstrap Configuration](../configuration/bootstrap.md) |
| CLI command reference | [CLI Overview](cli/README.md) |
| PIV slot management | [PIV Documentation](../piv/README.md) |
| xKey security key interface | [xKey Overview](../xkey/README.md) |
| Docker deployment | [Docker Quick Start](../deployment/docker-quickstart.md) |
