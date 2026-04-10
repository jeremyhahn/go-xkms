# Init System

PKCS#11-compliant SO PIN bootstrap for go-xkms server initialization.

## Problem

A key management server needs TLS certificates to accept connections, but generating those certificates requires the KMS itself. The classic setup-token approach works around this with a pre-shared secret, but it is non-standard and introduces an additional credential to manage.

`xkmsd init` solves this by combining PKCS#11 token initialization (`C_InitToken` + `C_InitPIN`) with barrier setup and TLS certificate generation in a single offline ceremony. The server transitions from uninitialized to fully operational with TLS, a sealed barrier, and a CA -- all before the first network listener starts.

## What `xkmsd init` Does

1. Loads configuration from `xkmsd.yaml`
2. Initializes PKCS#11 backends with SO PIN and User PIN (`C_InitToken` + `C_InitPIN`)
3. Initializes the barrier (AES-256-GCM encrypted storage for all sensitive data)
4. Seals the User PIN via the configured credential seal strategy (skipped for `manual`)
5. Creates a Certificate Authority on the selected backend
6. Generates a server TLS key pair and issues a server TLS certificate
7. Computes and prints the SPKI pin for trust-on-first-use
8. **Single admin**: writes SO certificate to the data directory
9. **M-of-N**: Shamir-splits the barrier root key, seals shares, signs SO CSRs, starts a temporary TLS listener for certificate and share claims

After `xkmsd init` completes, the server is ready for `xkmsd start`.

## Server State Machine

```
                   xkmsd init
                      |
                      v
 +-----------------+     +-------------+     +--------------+
 | awaiting_init   | --> | enrolling   | --> | operational  |
 | (no config, no  |     | (M-of-N     |     | (TLS active, |
 |  TLS, no CA)    |     |  claims     |     |  barrier     |
 +-----------------+     |  in flight) |     |  sealed/     |
                         +-------------+     |  unsealed)   |
                                             +--------------+
```

| State | Description |
|-------|-------------|
| `awaiting_init` | Fresh install. No CA, no TLS certificate, no barrier. |
| `enrolling` | M-of-N only. Temporary TLS listener running. SOs claim certificates and Shamir shares. Transitions to `operational` when all claims complete. |
| `operational` | Init complete. Server can start normally with `xkmsd start`. |

## Single Admin vs M-of-N

### Single Admin

One Security Officer controls the SO PIN and the barrier root key. Suitable for development, small deployments, or environments where split knowledge is not required.

```bash
xkmsd init --config /etc/xkms/xkmsd.yaml \
  --so-pin <PIN> --user-pin <PIN>
```

### M-of-N (Threshold)

The barrier root key is Shamir-split across N Security Officers. Any M of them must collaborate to unseal the barrier. Required for FIPS 140-2/3 Level 3 compliance and high-security production deployments.

```bash
xkmsd init --config /etc/xkms/xkmsd.yaml \
  --so-pin <PIN> --user-pin <PIN> \
  --threshold 2 \
  --so admin1@example.com:/path/to/admin1.csr \
  --so admin2@example.com:/path/to/admin2.csr \
  --so admin3@example.com:/path/to/admin3.csr
```

Each SO generates a CSR beforehand (RSA, ECDSA, or Ed25519). During init, the server signs each CSR against the newly created CA and holds the resulting certificates for claim via the challenge-response protocol.

## Quick Reference

```bash
# Single admin init
xkmsd init --config /etc/xkms/xkmsd.yaml --so-pin <PIN> --user-pin <PIN>

# M-of-N init (2-of-3)
xkmsd init --config /etc/xkms/xkmsd.yaml --so-pin <PIN> --user-pin <PIN> \
  --threshold 2 \
  --so admin1@example.com:/path/to/admin1.csr \
  --so admin2@example.com:/path/to/admin2.csr \
  --so admin3@example.com:/path/to/admin3.csr

# SO claims certificate (SPKI-pinned, no prior CA trust)
xkmsctl init claim-cert --server https://xkmsd:8443 --spki-pin <PIN> \
  --username admin2@example.com --key /path/to/csr-private-key.pem

# SO claims Shamir share (mTLS with newly claimed cert)
xkmsctl init claim-share --server https://xkmsd:8443 \
  --tls-cert so.pem --tls-key so-key.pem --tls-ca ca.pem \
  --username admin2@example.com

# Submit a credential (e.g., User PIN for auto-start)
xkmsctl credential submit --server https://xkmsd:8443 \
  --name "pkcs11-user-pin" --value "user123"

# M-of-N barrier unseal
xkmsctl barrier unseal-share --share "$(xkey share get barrier)"
```

## Documentation

| Document | Description |
|----------|-------------|
| [ceremony.md](ceremony.md) | Step-by-step init ceremony walkthrough, challenge-response protocol, share claims |
| [threshold.md](threshold.md) | M-of-N architecture, application-layer Shamir, HSM-layer threshold |
| [credentials.md](credentials.md) | Credential seal strategies, CredentialService architecture, configuration |
| [roles.md](roles.md) | FIPS 140-2/3 role model, operation matrix, separation of duties |

## Related Documentation

- [Architecture Overview](../architecture/overview.md)
- [RBAC](../architecture/rbac.md)
- [Configuration](../configuration/README.md)
- [Getting Started](../usage/getting-started.md)
- [PKCS#11 Backend](../backends/pkcs11.md)
- [TPM2 Backend](../backends/tpm2.md)
