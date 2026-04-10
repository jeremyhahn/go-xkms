# PIV Integration

The PKCS #11 module discovers PIV certificates from configured backends at initialization time and exposes them as standard PKCS #11 objects. This enables PKCS #11 clients (OpenSSL, SSH, pkcs11-tool, Java, NSS) to use PIV credentials without any PIV-specific logic.

## Configuration

### `piv_backends` Config Field

The `piv_backends` field lists backend names to scan for PIV certificates during module initialization. For each backend, `LoadPIVObjects` enumerates all PIV slots and creates PKCS #11 objects for every slot that contains a certificate.

Configuration file (`/etc/xkms/pkcs11.conf`):

```ini
target = unix:///var/run/xkms/xkms.sock
default_backend = software
piv_backends = software,tpm2
```

### `XKMS_PKCS11_PIV_BACKENDS` Environment Variable

A comma-separated list of backend names. Environment variables take precedence over the configuration file.

```bash
export XKMS_PKCS11_PIV_BACKENDS=software,tpm2,yubikey
```

When `piv_backends` is empty or unset, no PIV objects are loaded and the module operates with only its standard key objects.

## Object Mapping

For each occupied PIV slot, three PKCS #11 objects are created. All three share the same `CKA_ID` value, linking them as a credential set.

### CKA_ID Computation

```
CKA_ID = SHA-256(cert.RawSubjectPublicKeyInfo)[:20]
```

The first 20 bytes of the SHA-256 digest of the certificate's raw SubjectPublicKeyInfo. This is consistent with standard PIV-to-PKCS #11 mapping conventions and ensures the same key always produces the same identifier regardless of certificate renewal.

### CKO_CERTIFICATE

| Attribute              | Value                                      |
|------------------------|--------------------------------------------|
| `CKA_CLASS`            | `CKO_CERTIFICATE`                          |
| `CKA_CERTIFICATE_TYPE` | `CKC_X_509` (0x00000000)                  |
| `CKA_TOKEN`            | `CK_TRUE` (persistent object)              |
| `CKA_PRIVATE`          | `CK_FALSE` (public, no login required to read) |
| `CKA_LABEL`            | `piv:{slot}` (e.g., `piv:9a`)             |
| `CKA_ID`               | SHA-256(SPKI)[:20]                         |
| `CKA_VALUE`            | DER-encoded X.509 certificate              |
| `CKA_SUBJECT`          | DER-encoded subject name                   |
| `CKA_ISSUER`           | DER-encoded issuer name                    |
| `CKA_SERIAL_NUMBER`    | ASN.1-encoded serial number                |

### CKO_PUBLIC_KEY

| Attribute         | Value                                           |
|-------------------|-------------------------------------------------|
| `CKA_CLASS`       | `CKO_PUBLIC_KEY`                                |
| `CKA_KEY_TYPE`    | `CKK_RSA`, `CKK_EC`, or `CKK_EC_EDWARDS`       |
| `CKA_TOKEN`       | `CK_TRUE`                                       |
| `CKA_PRIVATE`     | `CK_FALSE`                                      |
| `CKA_LABEL`       | `piv:{slot}`                                    |
| `CKA_ID`          | SHA-256(SPKI)[:20]                              |
| `CKA_VERIFY`      | `CK_TRUE`                                       |
| `CKA_ENCRYPT`     | `CK_TRUE`                                       |

Algorithm-specific attributes:

**RSA keys:**

| Attribute              | Value                           |
|------------------------|---------------------------------|
| `CKA_MODULUS`          | RSA modulus N (big-endian bytes) |
| `CKA_PUBLIC_EXPONENT`  | RSA exponent e (big-endian bytes)|
| `CKA_MODULUS_BITS`     | Key size in bits (uint32 LE)    |

**EC keys (P-256, P-384, P-521):**

| Attribute       | Value                                              |
|-----------------|----------------------------------------------------|
| `CKA_EC_PARAMS` | DER-encoded ASN.1 OID of the named curve            |
| `CKA_EC_POINT`  | DER-encoded ASN.1 OCTET STRING of uncompressed point|

**Ed25519 keys:**

| Attribute       | Value                                    |
|-----------------|------------------------------------------|
| `CKA_EC_POINT`  | DER-encoded ASN.1 OCTET STRING of the key|

### CKO_PRIVATE_KEY

The private key object is a handle -- it contains no key material. All cryptographic operations are delegated to the backend through the SDK transport client.

| Attribute               | Value                                     |
|-------------------------|-------------------------------------------|
| `CKA_CLASS`             | `CKO_PRIVATE_KEY`                         |
| `CKA_KEY_TYPE`          | Matches public key type                   |
| `CKA_TOKEN`             | `CK_TRUE`                                 |
| `CKA_PRIVATE`           | `CK_TRUE` (login required)                |
| `CKA_SENSITIVE`         | `CK_TRUE`                                 |
| `CKA_LABEL`             | `piv:{slot}`                              |
| `CKA_ID`                | SHA-256(SPKI)[:20]                        |
| `CKA_SIGN`              | `CK_TRUE`                                 |
| `CKA_DECRYPT`           | `CK_TRUE`                                 |
| `CKA_EXTRACTABLE`       | `CK_FALSE`                                |
| `CKA_NEVER_EXTRACTABLE` | `CK_TRUE`                                 |
| `CKA_ALWAYS_SENSITIVE`  | `CK_TRUE`                                 |

The private key also carries the same algorithm-specific attributes as the public key (modulus, exponent, EC params, etc.) for mechanism compatibility checks.

### Internal Linking

Each PIV object carries two internal fields used for routing cryptographic operations:

- **KeyID** -- `piv/{slot}` (e.g., `piv/9a`), used in `transport.SignRequest.KeyID`
- **BackendName** -- the backend that owns the slot, used in `transport.SignRequest.Backend`

## Key Generation

When `C_GenerateKeyPair` is called with a `CKA_LABEL` starting with `piv:`, the module routes the operation through `GeneratePIVKeyPair`. This calls the backend's PIV key generation via the transport client and creates all three PKCS #11 objects from the resulting self-signed certificate.

```bash
# Generate an EC P-256 key in PIV slot 9a via pkcs11-tool
pkcs11-tool --module /usr/lib/libxkms_pkcs11.so \
  --login --pin 123456 \
  --keypairgen --key-type EC:secp256r1 \
  --label "piv:9a"
```

The label prefix `piv:` triggers PIV-aware generation. The slot identifier follows the colon. The generated objects use the label `piv:{slot}` and can be found with standard PKCS #11 search operations.

## Signing Operations

When a PKCS #11 client calls `C_SignInit` + `C_Sign` on a PIV private key object, the `CryptoManager` routes the signing request through `transport.Client.Sign()` using the object's `KeyID` (`piv/{slot}`) and `BackendName`. The backend performs the actual cryptographic operation and returns the signature.

```
Application           PKCS#11 Module            go-xkms Backend
    |                      |                          |
    |-- C_SignInit ------->|                          |
    |   (PIV priv handle)  |-- SignInit(piv/9a) ----->|
    |<-- CKR_OK -----------|                          |
    |                      |                          |
    |-- C_Sign ----------->|                          |
    |   (data)             |-- Sign(piv/9a, data) --->|
    |                      |                          |-- backend.Sign()
    |                      |<-- signature ------------|
    |<-- signature --------|                          |
```

This is the same code path used for all keys in the PKCS #11 module. PIV objects do not require special signing logic because the `KeyID` and `BackendName` are sufficient for the backend to resolve the correct key.

## Listing PIV Objects

```bash
# List all objects including PIV certificates
pkcs11-tool --module /usr/lib/libxkms_pkcs11.so \
  --login --pin 123456 \
  --list-objects

# Filter to certificates only
pkcs11-tool --module /usr/lib/libxkms_pkcs11.so \
  --list-objects --type cert

# Find objects by PIV label
pkcs11-tool --module /usr/lib/libxkms_pkcs11.so \
  --list-objects --label "piv:9a"
```

## Example: SSH Authentication with PIV Slot 9a

```bash
# Configure the module
export XKMS_PKCS11_TARGET=unix:///var/run/xkms/xkms.sock
export XKMS_PKCS11_PIV_BACKENDS=software

# Add PKCS#11 provider to SSH agent
ssh-add -s /usr/lib/libxkms_pkcs11.so

# SSH using the PIV authentication key
ssh -I /usr/lib/libxkms_pkcs11.so user@host
```

## See Also

- [PIV Overview](../../piv/README.md) -- PIV concepts and SDK usage
- [PKCS #11 Module Architecture](architecture.md) -- Module internals
- [PKCS #11 Module Configuration](configuration.md) -- Full configuration reference
- [PKCS #11 Module Usage](usage.md) -- Integration with OpenSSL, SSH, Java

## License

Dual-licensed under AGPL-3.0 and Commercial licenses.
