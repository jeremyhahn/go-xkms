# CLI Key Command Reference

## Overview

The `key` command group provides comprehensive key management operations for cryptographic keys across all supported backends. It supports both asymmetric (RSA, ECDSA, Ed25519) and symmetric (AES-GCM) key operations including generation, rotation, encryption, decryption, signing, verification, and secure import/export.

## Global Flags

All key commands support the following global flags:

- `--backend <name>` - Backend to use (default: "software")
- `--keydir <path>` - Key directory for file-based backends
- `--local` - Use direct backend access instead of keychaind server
- `--verbose` - Enable verbose output
- `--output <format>` - Output format: text, json (default: "text")

## Key Types

Keys can be categorized by their intended use case:

**General Purpose Keys:**
- `signing` - Digital signature operations
- `encryption` - Encryption/decryption operations
- `hmac` - HMAC keys for message authentication
- `secret` - General-purpose secret keys
- `tls` - TLS/SSL certificate keys
- `ca` - Certificate Authority keys

**TPM 2.0 Keys:**
- `endorsement` - Endorsement Key (EK) - TPM identity and attestation
- `attestation` - Initial Attestation Key (IAK) - Attestation operations
- `storage` - Storage Root Key (SRK) - Parent key for key hierarchies
- `idevid` - Initial Device Identity - Factory-provisioned device identity
- `ldevid` - Locally-sourced Device Identity - Locally-provisioned device identity
- `tpm` - Generic TPM key

## Algorithms

### Asymmetric Algorithms

**RSA:**
- `rsa` - RSA algorithm with configurable key size (2048, 3072, 4096 bits)

**ECDSA (Elliptic Curve):**
- `ecdsa-p256` - ECDSA with P-256 curve (256-bit)
- `ecdsa-p384` - ECDSA with P-384 curve (384-bit)
- `ecdsa-p521` - ECDSA with P-521 curve (521-bit)
- `ecdsa` - Generic ECDSA (use with `--curve` flag)

**Edwards Curve:**
- `ed25519` - EdDSA with Curve25519 (256-bit)

### Symmetric Algorithms

**AES-GCM (Advanced Encryption Standard with Galois/Counter Mode):**
- `aes128-gcm` - AES-128-GCM (128-bit key)
- `aes192-gcm` - AES-192-GCM (192-bit key)
- `aes256-gcm` - AES-256-GCM (256-bit key)

**ChaCha20-Poly1305:**
- `chacha20-poly1305` - ChaCha20-Poly1305 AEAD cipher (256-bit key)
- `xchacha20-poly1305` - XChaCha20-Poly1305 with extended nonce (256-bit key)

## Subcommands

### key generate

Generate a new cryptographic key with specified algorithm and parameters.

**Usage:**
```bash
keychain key generate <key-id> [flags]
```

**Flags:**
- `--key-type <type>` - Key type (see Key Types section below)
- `--key-algorithm <algo>` - Key algorithm (see Algorithms section below)
- `--algorithm <algo>` - Symmetric algorithm: aes128-gcm, aes192-gcm, aes256-gcm, chacha20-poly1305, xchacha20-poly1305
- `--key-size <bits>` - Key size in bits (default: 2048 for RSA, 128/192/256 for AES)
- `--curve <curve>` - Elliptic curve: P-256, P-384, P-521 (default: "P-256")
- `--exportable` - Allow the key to be exported (default: false)

**Examples:**

Generate an RSA-2048 key:
```bash
keychain key generate my-rsa-key --local
```

Generate an RSA-4096 key:
```bash
keychain key generate my-strong-key --key-algorithm rsa --key-size 4096 --local
```

Generate an ECDSA key with P-384 curve:
```bash
keychain key generate my-ecdsa-key --key-algorithm ecdsa --curve P-384 --local
```

Generate an Ed25519 signing key:
```bash
keychain key generate my-ed25519-key --key-algorithm ed25519 --key-type signing --local
```

Generate an exportable symmetric AES-256-GCM key:
```bash
keychain key generate my-aes-key --key-type symmetric --algorithm aes-256-gcm --key-size 256 --exportable --local
```

Generate an AES-128-GCM encryption key:
```bash
keychain key generate my-encryption-key --key-type encryption --algorithm aes-128-gcm --key-size 128 --local
```

---

### key list

List all cryptographic keys in the keystore.

**Usage:**
```bash
keychain key list [flags]
```

**Examples:**

List all keys in the default backend:
```bash
keychain key list --local
```

List keys in JSON format:
```bash
keychain key list --output json --local
```

List keys from a specific backend:
```bash
keychain key list --backend tpm2 --local
```

---

### key get

Display detailed information about a specific key.

**Usage:**
```bash
keychain key get <key-id> [flags]
```

**Flags:**
- `--key-type <type>` - Key type (default: "tls")
- `--key-algorithm <algo>` - Key algorithm (default: "rsa")
- `--key-size <bits>` - Key size in bits (default: 2048)
- `--curve <curve>` - Elliptic curve (default: "P-256")

**Examples:**

Get information about an RSA key:
```bash
keychain key get my-rsa-key --local
```

Get information about an ECDSA key:
```bash
keychain key get my-ecdsa-key --key-algorithm ecdsa --curve P-384 --local
```

Get key info in JSON format:
```bash
keychain key get my-key --output json --local
```

---

### key delete

Delete a cryptographic key from the keystore.

**Usage:**
```bash
keychain key delete <key-id> [flags]
```

**Flags:**
- `--key-type <type>` - Key type (default: "tls")
- `--key-algorithm <algo>` - Key algorithm (default: "rsa")
- `--key-size <bits>` - Key size in bits (default: 2048)
- `--curve <curve>` - Elliptic curve (default: "P-256")

**Examples:**

Delete an RSA key:
```bash
keychain key delete my-rsa-key --local
```

Delete an ECDSA key:
```bash
keychain key delete my-ecdsa-key --key-algorithm ecdsa --curve P-256 --local
```

Delete a symmetric key:
```bash
keychain key delete my-aes-key --key-algorithm aes256-gcm --key-size 256 --local
```

---

### key sign

Sign data using a cryptographic key.

**Usage:**
```bash
keychain key sign <key-id> <data> [flags]
```

**Flags:**
- `--key-type <type>` - Key type (default: "tls")
- `--key-algorithm <algo>` - Key algorithm (default: "rsa")
- `--key-size <bits>` - Key size in bits (default: 2048)
- `--curve <curve>` - Elliptic curve (default: "P-256")
- `--hash <algo>` - Hash algorithm: sha256, sha384, sha512 (default: "sha256")

**Output:** Base64-encoded signature

**Examples:**

Sign data with an RSA key using SHA-256:
```bash
keychain key sign my-rsa-key "Hello, World!" --local
```

Sign with ECDSA using SHA-384:
```bash
keychain key sign my-ecdsa-key "Important message" --key-algorithm ecdsa --hash sha384 --local
```

Sign with Ed25519 (uses raw message):
```bash
keychain key sign my-ed25519-key "Message to sign" --key-algorithm ed25519 --local
```

Store signature in a variable:
```bash
SIGNATURE=$(keychain key sign my-key "data" --output json --local | jq -r '.signature')
```

---

### key verify

Verify a signature against data using a key's public key.

**Usage:**
```bash
keychain key verify <key-id> <data> <signature> [flags]
```

**Flags:**
- `--key-type <type>` - Key type (default: "tls")
- `--key-algorithm <algo>` - Key algorithm (default: "rsa")
- `--key-size <bits>` - Key size in bits (default: 2048)
- `--curve <curve>` - Elliptic curve (default: "P-256")
- `--hash <algo>` - Hash algorithm: sha256, sha384, sha512 (default: "sha256")

**Examples:**

Verify an RSA signature:
```bash
SIGNATURE=$(keychain key sign my-rsa-key "Hello, World!" --local)
keychain key verify my-rsa-key "Hello, World!" "$SIGNATURE" --local
```

Verify an ECDSA signature with SHA-384:
```bash
keychain key verify my-ecdsa-key "data" "$SIGNATURE" --key-algorithm ecdsa --hash sha384 --local
```

Verify an Ed25519 signature:
```bash
keychain key verify my-ed25519-key "Message" "$SIGNATURE" --key-algorithm ed25519 --local
```

---

### key rotate

Rotate a key by generating a new version and invalidating the old one.

**Usage:**
```bash
keychain key rotate <key-id> [flags]
```

**Flags:**
- `--key-type <type>` - Key type (default: "tls")
- `--key-algorithm <algo>` - Key algorithm (default: "rsa")
- `--key-size <bits>` - Key size in bits (default: 2048)
- `--curve <curve>` - Elliptic curve (default: "P-256")

**Examples:**

Rotate an RSA key:
```bash
keychain key rotate my-rsa-key --local
```

Rotate an ECDSA key:
```bash
keychain key rotate my-ecdsa-key --key-algorithm ecdsa --curve P-256 --local
```

---

### key encrypt

Encrypt data using a symmetric (AES-GCM) key.

**Usage:**
```bash
keychain key encrypt <key-id> <plaintext> [flags]
```

**Flags:**
- `--key-type <type>` - Key type (default: "encryption")
- `--key-algorithm <algo>` - Key algorithm: aes128-gcm, aes192-gcm, aes256-gcm (default: "aes256-gcm")
- `--key-size <bits>` - Key size in bits: 128, 192, 256 (default: 256)
- `--aad <data>` - Additional authenticated data (optional)

**Output:** JSON with base64-encoded ciphertext, nonce, and authentication tag

**Examples:**

Encrypt data with AES-256-GCM:
```bash
keychain key encrypt my-aes-key "Secret message" --local
```

Output:
```json
{
  "ciphertext": "base64-encoded-ciphertext",
  "nonce": "base64-encoded-nonce",
  "tag": "base64-encoded-tag",
  "algorithm": "aes-256-gcm"
}
```

Encrypt with additional authenticated data:
```bash
keychain key encrypt my-aes-key "Secret" --aad "context-info" --local
```

Store encrypted output:
```bash
ENCRYPTED=$(keychain key encrypt my-aes-key "Secret" --output json --local)
CIPHERTEXT=$(echo $ENCRYPTED | jq -r '.ciphertext')
NONCE=$(echo $ENCRYPTED | jq -r '.nonce')
TAG=$(echo $ENCRYPTED | jq -r '.tag')
```

---

### key decrypt

Decrypt data using a symmetric key or asymmetric private key.

**Usage:**
```bash
keychain key decrypt <key-id> <ciphertext> [flags]
```

**Flags:**

For symmetric decryption (AES-GCM):
- `--key-type <type>` - Key type (default: "tls")
- `--key-algorithm <algo>` - Key algorithm (default: "rsa")
- `--key-size <bits>` - Key size in bits (default: 2048)
- `--nonce <base64>` - Nonce/IV (base64-encoded, required for symmetric)
- `--tag <base64>` - Authentication tag (base64-encoded, required for symmetric)
- `--aad <data>` - Additional authenticated data (if used during encryption)

For asymmetric decryption (RSA):
- `--curve <curve>` - Elliptic curve (default: "P-256")
- `--hash <algo>` - Hash algorithm for RSA OAEP decryption (e.g., sha256)

**Examples:**

Decrypt symmetric data (AES-GCM):
```bash
# Using output from encrypt command
ENCRYPTED=$(keychain key encrypt my-aes-key "Secret" --output json --local)
CIPHERTEXT=$(echo $ENCRYPTED | jq -r '.ciphertext')
NONCE=$(echo $ENCRYPTED | jq -r '.nonce')
TAG=$(echo $ENCRYPTED | jq -r '.tag')

keychain key decrypt my-aes-key "$CIPHERTEXT" --nonce "$NONCE" --tag "$TAG" --local
```

Decrypt with AAD:
```bash
keychain key decrypt my-aes-key "$CIPHERTEXT" --nonce "$NONCE" --tag "$TAG" --aad "context-info" --local
```

Decrypt with RSA OAEP:
```bash
keychain key decrypt my-rsa-key "$CIPHERTEXT" --hash sha256 --local
```

Decrypt with RSA PKCS1v15 (no hash specified):
```bash
keychain key decrypt my-rsa-key "$CIPHERTEXT" --local
```

---

### key encrypt-asym

Encrypt data using asymmetric (RSA) public key encryption with OAEP.

**Usage:**
```bash
keychain key encrypt-asym <key-id> <plaintext> [flags]
```

**Flags:**
- `--key-type <type>` - Key type (default: "tls")
- `--key-algorithm <algo>` - Key algorithm (default: "rsa")
- `--key-size <bits>` - Key size in bits (default: 2048)
- `--curve <curve>` - Elliptic curve (default: "P-256")
- `--hash <algo>` - Hash algorithm for OAEP: sha256, sha384, sha512 (default: "sha256")

**Output:** Base64-encoded ciphertext

**Examples:**

Encrypt with RSA using OAEP SHA-256:
```bash
keychain key encrypt-asym my-rsa-key "Secret message" --local
```

Encrypt with OAEP SHA-512:
```bash
keychain key encrypt-asym my-rsa-key "Sensitive data" --hash sha512 --local
```

Full encryption/decryption workflow:
```bash
# Encrypt
CIPHERTEXT=$(keychain key encrypt-asym my-rsa-key "Secret" --output json --local | jq -r '.ciphertext')

# Decrypt
keychain key decrypt my-rsa-key "$CIPHERTEXT" --hash sha256 --local
```

---

### key import

Import externally generated key material that has been wrapped for secure transport.

**Usage:**
```bash
keychain key import <key-id> <wrapped-key-file> [flags]
```

**Flags:**
- `--key-type <type>` - Key type (default: "tls")
- `--key-algorithm <algo>` - Key algorithm (default: "rsa")
- `--key-size <bits>` - Key size in bits (default: 2048)
- `--curve <curve>` - Elliptic curve (default: "P-256")

**File Format:** JSON file containing wrapped key material

**Examples:**

Import a wrapped RSA key:
```bash
keychain key import imported-key wrapped-key.json --local
```

Import an ECDSA key:
```bash
keychain key import ecdsa-imported wrapped-ecdsa.json --key-algorithm ecdsa --curve P-256 --local
```

**Wrapped Key File Format:**
```json
{
  "wrapped_key": "base64-encoded-wrapped-key-material",
  "algorithm": "RSAES_OAEP_SHA_256"
}
```

---

### key export

Export a key in wrapped form for secure transport to another system.

**Usage:**
```bash
keychain key export <key-id> <output-file> [flags]
```

**Flags:**
- `--key-type <type>` - Key type (default: "tls")
- `--key-algorithm <algo>` - Key algorithm (default: "rsa")
- `--key-size <bits>` - Key size in bits (default: 2048)
- `--curve <curve>` - Elliptic curve (default: "P-256")
- `--algorithm <algo>` - Wrapping algorithm (default: "RSAES_OAEP_SHA_256")

**Note:** The key must have been generated with the `--exportable` flag.

**Examples:**

Export an exportable key:
```bash
# First, generate an exportable key
keychain key generate exportable-key --exportable --local

# Export it
keychain key export exportable-key wrapped-export.json --local
```

Export with specific wrapping algorithm:
```bash
keychain key export my-key export.json --algorithm RSAES_OAEP_SHA_256 --local
```

Export an ECDSA key:
```bash
keychain key export my-ecdsa-key ecdsa-export.json --key-algorithm ecdsa --curve P-384 --local
```

---

### key copy

Copy an exportable key from one backend to another using secure wrapping.

**Usage:**
```bash
keychain key copy <source-key-id> [dest-key-id] [flags]
```

**Flags:**
- `--dest-backend <name>` - Destination backend (default: "software")
- `--dest-keydir <path>` - Destination key directory (for file-based backends)
- `--key-type <type>` - Key type (default: "tls")
- `--key-algorithm <algo>` - Key algorithm (default: "rsa")
- `--key-size <bits>` - Key size in bits (default: 2048)
- `--curve <curve>` - Elliptic curve (default: "P-256")
- `--algorithm <algo>` - Wrapping algorithm (default: "RSAES_OAEP_SHA_256")

**Note:** Source key must be exportable. If dest-key-id is omitted, uses the same ID as source.

**Examples:**

Copy a key to another backend:
```bash
keychain key copy my-key --dest-backend tpm2 --local
```

Copy with a different destination key ID:
```bash
keychain key copy source-key dest-key --dest-backend pkcs11 --local
```

Copy to a different directory:
```bash
keychain key copy my-key --dest-backend software --dest-keydir /secure/keys --local
```

Copy an ECDSA key:
```bash
keychain key copy ecdsa-key --dest-backend tpm2 --key-algorithm ecdsa --curve P-256 --local
```

---

### key get-import-params

Retrieve the wrapping public key and parameters needed to import a key securely.

**Usage:**
```bash
keychain key get-import-params <key-id> [flags]
```

**Flags:**
- `--key-type <type>` - Key type (default: "tls")
- `--key-algorithm <algo>` - Key algorithm (default: "rsa")
- `--key-size <bits>` - Key size in bits (default: 2048)
- `--curve <curve>` - Elliptic curve (default: "P-256")
- `--algorithm <algo>` - Wrapping algorithm (default: "RSAES_OAEP_SHA_256")
- `--output <file>` - Output file for import parameters (JSON)

**Examples:**

Get import parameters and display them:
```bash
keychain key get-import-params my-key --local
```

Save import parameters to a file:
```bash
keychain key get-import-params my-key --output import-params.json --local
```

Get parameters for TPM2 backend:
```bash
keychain key get-import-params tpm-key --backend tpm2 --output tpm-params.json --local
```

**Output Format:**
```json
{
  "wrapping_public_key": "base64-encoded-public-key-der",
  "algorithm": "RSAES_OAEP_SHA_256",
  "expires_at": "2024-01-01T00:00:00Z"
}
```

---

### key wrap

Wrap raw key material using import parameters for secure transport.

**Usage:**
```bash
keychain key wrap <key-material-file> <params-file> <output-file> [flags]
```

**Arguments:**
- `<key-material-file>` - File containing raw key material
- `<params-file>` - JSON file with import parameters (from get-import-params)
- `<output-file>` - Output file for wrapped key material

**Examples:**

Wrap key material for import:
```bash
# 1. Get import parameters from destination
keychain key get-import-params target-key --output params.json --backend tpm2 --local

# 2. Wrap your key material
keychain key wrap raw-key-material.bin params.json wrapped-key.json --local
```

Full workflow for secure key transfer:
```bash
# On destination system: get import parameters
keychain key get-import-params my-imported-key --output params.json --backend tpm2 --local

# Transfer params.json to source system

# On source system: wrap key material
openssl genrsa -out private-key.pem 2048
keychain key wrap private-key.pem params.json wrapped.json --local

# Transfer wrapped.json to destination system

# On destination system: import the wrapped key
keychain key import my-imported-key wrapped.json --backend tpm2 --local
```

---

### key unwrap

Unwrap previously wrapped key material.

**Usage:**
```bash
keychain key unwrap <wrapped-key-file> <params-file> <output-file> [flags]
```

**Arguments:**
- `<wrapped-key-file>` - JSON file containing wrapped key material
- `<params-file>` - JSON file with import parameters
- `<output-file>` - Output file for unwrapped key material

**Examples:**

Unwrap key material:
```bash
keychain key unwrap wrapped-key.json params.json unwrapped-key.bin --local
```

Full unwrap workflow:
```bash
# Unwrap
keychain key unwrap wrapped.json import-params.json key-material.bin --local

# Use the unwrapped key material
openssl rsa -in key-material.bin -text -noout
```

---

## Complete Workflows

### Workflow 1: Generate, Sign, and Verify

```bash
# Generate an RSA signing key
keychain key generate signing-key --key-type signing --exportable --local

# Sign a message
SIGNATURE=$(keychain key sign signing-key "Important message" --local)

# Verify the signature
keychain key verify signing-key "Important message" "$SIGNATURE" --local
```

### Workflow 2: Symmetric Encryption/Decryption

```bash
# Generate AES-256-GCM key
keychain key generate aes-key --key-type symmetric --algorithm aes-256-gcm --key-size 256 --local

# Encrypt data with AAD
ENCRYPTED=$(keychain key encrypt aes-key "Sensitive data" --aad "user123" --output json --local)
CIPHERTEXT=$(echo $ENCRYPTED | jq -r '.ciphertext')
NONCE=$(echo $ENCRYPTED | jq -r '.nonce')
TAG=$(echo $ENCRYPTED | jq -r '.tag')

# Decrypt data
PLAINTEXT=$(keychain key decrypt aes-key "$CIPHERTEXT" --nonce "$NONCE" --tag "$TAG" --aad "user123" --local)
echo "Decrypted: $PLAINTEXT"
```

### Workflow 3: Asymmetric Encryption/Decryption

```bash
# Generate RSA key
keychain key generate rsa-key --key-size 4096 --local

# Encrypt with public key
CIPHERTEXT=$(keychain key encrypt-asym rsa-key "Secret message" --hash sha256 --local)

# Decrypt with private key
PLAINTEXT=$(keychain key decrypt rsa-key "$CIPHERTEXT" --hash sha256 --local)
echo "Decrypted: $PLAINTEXT"
```

### Workflow 4: Cross-Backend Key Migration

```bash
# Generate exportable key in software backend
keychain key generate migratable-key --exportable --backend software --local

# Copy to TPM2 backend
keychain key copy migratable-key tpm-key --dest-backend tpm2 --local

# Verify the key exists in both backends
keychain key list --backend software --local
keychain key list --backend tpm2 --local

# Clean up source key
keychain key delete migratable-key --backend software --local
```

### Workflow 5: Secure Key Import

```bash
# On target system: get import parameters
keychain key get-import-params imported-key --output params.json --backend tpm2 --local

# Transfer params.json to source system

# On source system: generate and wrap key
openssl genrsa -out key.pem 2048
openssl rsa -in key.pem -outform DER -out key.der
keychain key wrap key.der params.json wrapped.json --local

# Transfer wrapped.json back to target system

# On target system: import the key
keychain key import imported-key wrapped.json --backend tpm2 --local

# Verify import
keychain key get imported-key --backend tpm2 --local
```

### Workflow 6: Key Rotation

```bash
# Generate initial key
keychain key generate rotatable-key --key-type signing --local

# Use the key for signing
SIGNATURE=$(keychain key sign rotatable-key "Message 1" --local)

# Rotate the key (generates new version)
keychain key rotate rotatable-key --local

# Old signatures should still verify
keychain key verify rotatable-key "Message 1" "$SIGNATURE" --local

# New signatures use the new key version
NEW_SIGNATURE=$(keychain key sign rotatable-key "Message 2" --local)
keychain key verify rotatable-key "Message 2" "$NEW_SIGNATURE" --local
```

### Workflow 7: Multi-Algorithm Key Management

```bash
# Generate different key types
keychain key generate rsa-key --key-algorithm rsa --key-size 4096 --local
keychain key generate ecdsa-key --key-algorithm ecdsa --curve P-384 --local
keychain key generate ed25519-key --key-algorithm ed25519 --local
keychain key generate aes-key --key-type symmetric --algorithm aes-256-gcm --key-size 256 --local

# List all keys
keychain key list --local

# Sign with each key type
keychain key sign rsa-key "Message" --hash sha384 --local
keychain key sign ecdsa-key "Message" --key-algorithm ecdsa --hash sha384 --local
keychain key sign ed25519-key "Message" --key-algorithm ed25519 --local

# Encrypt with symmetric key
keychain key encrypt aes-key "Secret" --local
```

## Backend-Specific Examples

### Software Backend

```bash
# Generate key in custom directory
keychain key generate my-key --backend software --keydir /secure/keys --local

# List keys from custom directory
keychain key list --backend software --keydir /secure/keys --local
```

### TPM2 Backend

```bash
# Generate key in TPM2
keychain key generate tpm-key --backend tpm2 --local

# TPM2 keys are automatically non-exportable
keychain key get tpm-key --backend tpm2 --local
```

### PKCS#11 Backend

```bash
# Generate key in HSM
keychain key generate hsm-key --backend pkcs11 --local

# Sign with HSM key
keychain key sign hsm-key "Important data" --backend pkcs11 --local
```

### Cloud KMS Backends

AWS KMS:
```bash
keychain key generate aws-key --backend awskms --local
keychain key sign aws-key "Message" --backend awskms --local
```

GCP KMS:
```bash
keychain key generate gcp-key --backend gcpkms --local
keychain key encrypt gcp-key "Secret" --backend gcpkms --local
```

Azure Key Vault:
```bash
keychain key generate azure-key --backend azurekv --local
keychain key rotate azure-key --backend azurekv --local
```

## Error Handling

Common errors and solutions:

**Key not found:**
```bash
# Error: key not found
# Solution: Verify key exists and parameters match
keychain key list --local
keychain key get my-key --key-algorithm ecdsa --curve P-256 --local
```

**Key not exportable:**
```bash
# Error: key is not exportable
# Solution: Regenerate with --exportable flag
keychain key generate exportable-key --exportable --local
keychain key export exportable-key output.json --local
```

**Invalid key size:**
```bash
# Error: RSA key size must be at least 2048 bits
# Solution: Use minimum 2048 bits for RSA
keychain key generate my-key --key-size 2048 --local
```

**Missing symmetric decryption parameters:**
```bash
# Error: nonce and tag required for symmetric decryption
# Solution: Include nonce and tag from encryption output
ENCRYPTED=$(keychain key encrypt my-aes-key "data" --output json --local)
keychain key decrypt my-aes-key "$(echo $ENCRYPTED | jq -r '.ciphertext')" \
  --nonce "$(echo $ENCRYPTED | jq -r '.nonce')" \
  --tag "$(echo $ENCRYPTED | jq -r '.tag')" --local
```

## Best Practices

1. **Always use --local flag for direct backend access** to avoid dependency on keychaind server during development

2. **Generate keys with appropriate sizes:**
   - RSA: minimum 2048 bits, 4096 recommended for long-term use
   - ECDSA: P-256 for general use, P-384/P-521 for high security
   - AES: 256 bits for maximum security

3. **Use --exportable sparingly:** Only mark keys exportable when cross-backend migration is required

4. **Store encrypted data components together:** Always save ciphertext, nonce, tag, and algorithm together

5. **Match hash algorithms:** Use the same hash algorithm for encryption/decryption and signing/verification

6. **Verify signatures immediately:** Always verify signatures after signing to catch configuration errors

7. **Use JSON output for automation:**
   ```bash
   keychain key list --output json --local | jq '.keys[].key_id'
   ```

8. **Clean up test keys:**
   ```bash
   # Delete test keys after experiments
   keychain key delete test-key --local
   ```

9. **Backup import parameters:** Save import parameters when doing secure key imports

10. **Use verbose mode for troubleshooting:**
    ```bash
    keychain key generate debug-key --verbose --local
    ```

## See Also

- [Getting Started Guide](../getting-started.md)
- [Key Import/Export Guide](../key-import-export.md)
- [Advanced Cryptography Guide](../advanced-crypto.md)
- [Backend Documentation](../../backends/README.md)
- [Certificate Management](../certificate-management.md)
