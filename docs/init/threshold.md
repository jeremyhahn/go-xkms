# Threshold Architecture

M-of-N key splitting for barrier root key protection using Shamir's Secret Sharing and optional HSM-layer threshold mechanisms.

## Two Layers of Threshold Protection

go-xkms supports threshold operations at two distinct layers. These are complementary and can be combined for defense-in-depth.

### Layer 1: Application-Layer Shamir (Barrier Root Key)

The barrier root key (AES-256) is split using Shamir's Secret Sharing at the application level. This works with **any** backend -- software, TPM2, PKCS#11, or cloud KMS.

```
Barrier Root Key (AES-256)
        |
        | Shamir split (M-of-N)
        v
+-------+-------+-------+
| Share | Share | Share |  ...  Share N
|   1   |   2   |   3   |
+-------+-------+-------+
    |       |       |
    v       v       v
  SO 1    SO 2    SO 3     (sealed with each SO's public key)
```

**Properties:**
- Any M shares reconstruct the root key
- Fewer than M shares reveal nothing about the root key
- Shares are sealed with each SO's public key before delivery
- Works identically regardless of backend type
- No vendor-specific dependencies

**Configuration:**

```bash
xkmsd init --config /etc/xkms/xkmsd.yaml \
  --so-pin <PIN> --user-pin <PIN> \
  --threshold 2 \
  --so admin1@example.com:/path/to/admin1.csr \
  --so admin2@example.com:/path/to/admin2.csr \
  --so admin3@example.com:/path/to/admin3.csr
```

### Layer 2: HSM-Layer Threshold (Optional, Vendor-Specific)

Some HSM backends support native threshold mechanisms at the hardware level. This provides an additional layer of protection independent of the application-layer Shamir split.

```
PKCS#11 Backend
      |
      | Vendor-specific threshold protocol
      v
+-----+-----+-----+
| HSM | HSM | HSM |
|  1  |  2  |  3  |
+-----+-----+-----+
```

**Properties:**
- Enforced by hardware -- cannot be bypassed by software
- Vendor-specific protocols and tooling
- Optional -- not all backends support this
- Defense-in-depth when combined with application-layer Shamir

## Application-Layer Shamir Details

### Share Generation

During `xkmsd init` with `--threshold` flag:

1. The barrier root key is generated (32 bytes, AES-256)
2. The key is split into N shares using Shamir's Secret Sharing over GF(2^8)
3. Each share is sealed with the corresponding SO's public key (from their CSR)
4. Sealed shares are stored on the server pending claim
5. The original root key is zeroized from memory

### Share Format

Each share is a fixed-size byte slice containing:

| Field | Size | Description |
|-------|------|-------------|
| Share Index | 1 byte | Share number (1..N) |
| Threshold | 1 byte | M value required for reconstruction |
| Total | 1 byte | N total shares |
| Share Data | 32 bytes | The Shamir share polynomial evaluation |
| HMAC | 32 bytes | HMAC-SHA256 integrity check |

### Reconstruction

Barrier unsealing requires M shares submitted by M distinct SOs:

```bash
# Each SO submits their share
xkmsctl barrier unseal-share --share "$(xkey share get barrier)"
```

The server collects shares and reconstructs the root key when the threshold is met:

```
Share 1 (from SO 1) ─┐
                      ├── Lagrange interpolation ──> Barrier Root Key
Share 3 (from SO 3) ─┘
                           (M=2 of N=3 satisfied)
```

After reconstruction:
1. The barrier is unsealed with the recovered root key
2. All submitted shares are zeroized from memory
3. The root key is held in memory only while the barrier is active

### Zeroization Discipline

| Material | Zeroized When |
|----------|---------------|
| Original root key | Immediately after Shamir split |
| Sealed shares (server) | After SO claims and acknowledges |
| Plaintext shares (SO) | After storage in local secure storage |
| Submitted shares (server) | After barrier reconstruction |
| Reconstructed root key | On barrier seal or server shutdown |

## ThresholdInitializer Interface

Backend-specific threshold protocols implement the `ThresholdInitializer` interface:

```go
type ThresholdInitializer interface {
    // Name returns the backend identifier for registry lookup.
    Name() string

    // SupportsThreshold reports whether this backend has native threshold support.
    SupportsThreshold() bool

    // InitializeThreshold performs vendor-specific threshold setup.
    // The shares parameter contains the M-of-N configuration.
    InitializeThreshold(ctx context.Context, config ThresholdConfig) error

    // ImportThresholdShare imports a single share into the backend.
    ImportThresholdShare(ctx context.Context, share []byte) error

    // ThresholdStatus returns the current threshold state.
    ThresholdStatus(ctx context.Context) (*ThresholdStatus, error)
}
```

### Registry

Threshold initializers are registered at startup:

```go
func init() {
    threshold.Register("smartcard-hsm", NewSmartCardHSMThreshold)
    threshold.Register("luna", NewLunaThreshold)
}
```

The server selects the appropriate initializer based on the backend type configured in `xkmsd.yaml`.

## Vendor-Specific Protocols

### SmartCard-HSM DKEK (Device Key Encryption Key)

SmartCard-HSM (Nitrokey HSM, CardContact) supports native M-of-N key backup and restore using DKEK shares.

**How it works:**
1. A Device Key Encryption Key (DKEK) is generated inside the HSM
2. The DKEK is split into N shares using the device's built-in Shamir implementation
3. Each share is exported encrypted with a transport key
4. M shares are required to re-initialize the DKEK for key import/export

**Integration with go-xkms:**

```yaml
backends:
  - name: hsm
    type: pkcs11
    config:
      library_path: /usr/lib/opensc-pkcs11.so
      token_label: SmartCard-HSM
      threshold:
        enabled: true
        protocol: dkek
        m: 2
        n: 3
```

**DKEK share operations:**

```bash
# Export DKEK shares during init (handled by ThresholdInitializer)
# Each share is distributed to an SO via the standard claim protocol

# Import DKEK share for key restore
xkmsctl threshold import-share --backend hsm --share /path/to/dkek-share.bin
```

### Thales Luna (CA_* Commands)

Thales Luna HSMs support Cloning Domain-based key management with threshold PED authentication.

**How it works:**
1. A Cloning Domain is established across Luna partitions
2. `CA_GenerateMofN` creates M-of-N PED key splits
3. Each PED key holder presents their share via the PED device
4. M shares activate the partition for key operations

**Integration with go-xkms:**

```yaml
backends:
  - name: luna
    type: pkcs11
    config:
      library_path: /usr/safenet/lunaclient/lib/libCryptoki2.so
      token_label: production
      threshold:
        enabled: true
        protocol: luna_ca
        m: 2
        n: 3
```

Luna threshold operations are physical (PED-based) and require operator presence at the HSM. The `ThresholdInitializer` for Luna coordinates the PED ceremony prompts.

### Other HSM Vendors

The `ThresholdInitializer` registry is extensible. To add support for a new vendor:

1. Implement the `ThresholdInitializer` interface
2. Register it with `threshold.Register(name, factory)`
3. Document the vendor-specific configuration in `xkmsd.yaml`

## Combining Both Layers

For maximum security, combine application-layer Shamir with HSM-layer threshold:

```
Application Layer (Barrier Root Key)
  - Shamir 2-of-3 across SOs
  - Protects barrier encryption key
  - Works with any backend

HSM Layer (Key Material)
  - DKEK 2-of-3 on SmartCard-HSM
  - Protects key export/import operations
  - Hardware-enforced, cannot bypass via software
```

This provides defense-in-depth: even if the application-layer barrier is compromised, the HSM-layer threshold prevents unauthorized key extraction.

## Configuration Reference

### xkmsd.yaml threshold section

```yaml
# Application-layer Shamir (barrier root key)
# Configured via CLI flags during xkmsd init:
#   --threshold M
#   --so email:csr_path (repeated N times)

# HSM-layer threshold (optional, per-backend)
backends:
  - name: hsm
    type: pkcs11
    config:
      threshold:
        enabled: false          # Enable HSM-native threshold
        protocol: ""            # dkek | luna_ca | custom
        m: 0                    # Threshold (minimum shares)
        n: 0                    # Total shares
```

## Related Documentation

- [Init System Overview](README.md)
- [Init Ceremony](ceremony.md)
- [Credential Seal Strategies](credentials.md)
- [FIPS Roles](roles.md)
- [PKCS#11 Backend](../backends/pkcs11.md)
