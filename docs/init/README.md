# Init System

PKCS#11-compliant SO PIN bootstrap for the go-xkms server, plus the
ceremony harness shared with downstream consumers.

## Two State Machines, One Ceremony

xkms participates in **two** distinct bootstrap state machines, and the
docs in this folder describe the first one only. Keeping them separate
matters because they answer different questions about the server's
readiness.

| State Machine | Question Answered | Owner | Where It Runs |
|---------------|-------------------|-------|---------------|
| **KMS + CA bootstrap** | Does this server have a TPM/HSM/CA/TLS identity? | `cmd/xkmsd init` (xkms) | This document and `ceremony.md` |
| **IAM first-boot bootstrap** | Does this server have a system tenant, an admin user, and an admin certificate? | embedded qrdb node (in-process) | Documented in `auth/bootstrap.md` |

After Phase 5 the IAM half is delegated wholesale to qrdb. xkms no longer
owns user/tenant/role/admin-cert creation — it always embeds qrdb in-process
as its single datastore and drives the embedded node's first-boot path, so a
single canonical implementation runs in every binary that embeds the stack
(xkms, quicbaas, trusted-platform). xkms contributes the FIDO2/WebAuthn
attestation hook and the invitation flow on top of the embedded node's
first-boot output; the rest of `auth/bootstrap.md` covers the integration in
detail.

## Problem (KMS + CA half)

A key management server needs TLS certificates to accept connections, but
generating those certificates requires the KMS itself. The classic
setup-token approach works around this with a pre-shared secret, but it is
non-standard and introduces an additional credential to manage.

`xkmsd init` solves this by combining PKCS#11 token initialization
(`C_InitToken` + `C_InitPIN`) with barrier setup and TLS certificate
generation in a single offline ceremony. The server transitions from
uninitialized to fully operational with TLS, a sealed barrier, and a CA —
all before the first network listener starts.

## What `xkmsd init` Does

1. Loads configuration from `xkmsd.yaml`
2. Initializes PKCS#11 backends with SO PIN and User PIN (`C_InitToken` + `C_InitPIN`)
3. Initializes the barrier (AES-256-GCM by default; strategy selected from `--barrier-strategy`)
4. Seals the User PIN via the configured credential seal strategy (skipped for `manual`)
5. Constructs a software-backed `TrustedCA` in-process with role profiles for `custodian`, `security-officer`, `administrator`, `operator`, `user`, `auditor` (`cmd/xkmsd/init_ceremony.go:225`)
6. Runs `CeremonyService.Initialize(ctx, caInstance)` end-to-end (`cmd/xkmsd/init_ceremony.go:122`) — this is the call site Phase 9 wired up; there is no longer a `TODO` here
7. Persists the CA bundle to `<dataDir>/ca-bundle.pem` and the SPKI pin to `<dataDir>/spki-pin.txt`
8. Computes and prints the SPKI pin for trust-on-first-use
9. **Single admin**: writes the SO admin client bundle (cert + key, PEM-concatenated) to `--admin-bundle` (`-` = stdout)
10. **M-of-N**: Shamir-splits the barrier root key, seals shares, signs SO CSRs, starts a temporary TLS listener for certificate and share claims

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
| [../auth/bootstrap.md](../auth/bootstrap.md) | The IAM half: how xkms drives the embedded qrdb node's first-boot |
| [../trust/bootstrap.md](../trust/bootstrap.md) | Trust-bootstrap library used by clients to fetch the CA bundle produced here |

## Related Documentation

- [Architecture Overview](../architecture/overview.md)
- [RBAC](../architecture/rbac.md)
- [Configuration](../configuration/README.md)
- [Getting Started](../usage/getting-started.md)
- [PKCS#11 Backend](../backends/pkcs11.md)
- [TPM2 Backend](../backends/tpm2.md)
