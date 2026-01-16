# Usage

This guide covers common usage patterns for the PKCS#11 module.

## pkcs11-tool Examples

The `pkcs11-tool` from OpenSC is the standard CLI for PKCS#11 operations.

### Module Path

```bash
# Set module path for all examples
export P11_MODULE=/usr/lib/libkeychain_pkcs11.so
```

### Slot and Token Information

```bash
# List available slots
pkcs11-tool --module $P11_MODULE --list-slots

# Show token information
pkcs11-tool --module $P11_MODULE --list-token-slots

# Show mechanism list
pkcs11-tool --module $P11_MODULE --list-mechanisms
```

### Key Generation

```bash
# Generate RSA 2048 key pair
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --keypairgen --key-type rsa:2048 \
  --label "my-rsa-key" \
  --id 01

# Generate RSA 4096 key pair
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --keypairgen --key-type rsa:4096 \
  --label "my-rsa-4096" \
  --id 02

# Generate ECDSA P-256 key pair
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --keypairgen --key-type EC:secp256r1 \
  --label "my-ec-key" \
  --id 03

# Generate ECDSA P-384 key pair
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --keypairgen --key-type EC:secp384r1 \
  --label "my-ec-384" \
  --id 04

# Generate Ed25519 key pair
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --keypairgen --key-type EC:ed25519 \
  --label "my-ed25519" \
  --id 05
```

### List Objects

```bash
# List all objects
pkcs11-tool --module $P11_MODULE --login --pin 123456 --list-objects

# List only private keys
pkcs11-tool --module $P11_MODULE --login --pin 123456 --list-objects --type privkey

# List only public keys
pkcs11-tool --module $P11_MODULE --list-objects --type pubkey

# List only certificates
pkcs11-tool --module $P11_MODULE --list-objects --type cert
```

### Signing Operations

```bash
# Sign with RSA PKCS#1 v1.5
echo "Hello, World!" > message.txt
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --sign --mechanism RSA-PKCS \
  --label "my-rsa-key" \
  --input-file message.txt \
  --output-file signature.bin

# Sign with RSA-PSS
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --sign --mechanism RSA-PKCS-PSS \
  --hash-algorithm SHA256 \
  --label "my-rsa-key" \
  --input-file message.txt \
  --output-file signature.bin

# Sign with ECDSA
sha256sum message.txt | xxd -r -p > hash.bin
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --sign --mechanism ECDSA \
  --label "my-ec-key" \
  --input-file hash.bin \
  --output-file signature.bin

# Sign with EdDSA
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --sign --mechanism EDDSA \
  --label "my-ed25519" \
  --input-file message.txt \
  --output-file signature.bin
```

### Verification

```bash
# Verify RSA signature
pkcs11-tool --module $P11_MODULE \
  --verify --mechanism RSA-PKCS \
  --label "my-rsa-key" \
  --input-file message.txt \
  --signature-file signature.bin
```

### Key Export

```bash
# Export public key
pkcs11-tool --module $P11_MODULE \
  --read-object --type pubkey \
  --label "my-rsa-key" \
  --output-file pubkey.der
```

### Delete Objects

```bash
# Delete key by label
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --delete-object --type privkey \
  --label "my-rsa-key"
```

## OpenSSL Integration

### Using libp11 Engine

The `libp11` engine enables OpenSSL to use PKCS#11 tokens.

```bash
# Install libp11
sudo apt install libengine-pkcs11-openssl

# Test engine
openssl engine pkcs11 -t
```

### Generate CSR

```bash
# Generate CSR using PKCS#11 key
openssl req -engine pkcs11 -keyform engine \
  -key "pkcs11:token=GO-KEYCHAIN;object=my-rsa-key;type=private" \
  -new -out request.csr \
  -subj "/CN=example.com"
```

### Sign Data

```bash
# Sign with OpenSSL using PKCS#11 key
openssl dgst -sha256 -engine pkcs11 -keyform engine \
  -sign "pkcs11:token=GO-KEYCHAIN;object=my-rsa-key;type=private" \
  -out signature.bin message.txt
```

### Verify Signature

```bash
# Export public key first
pkcs11-tool --module $P11_MODULE \
  --read-object --type pubkey \
  --label "my-rsa-key" \
  --output-file pubkey.der

# Convert to PEM
openssl rsa -pubin -inform DER -in pubkey.der -out pubkey.pem

# Verify
openssl dgst -sha256 -verify pubkey.pem -signature signature.bin message.txt
```

### TLS Server with PKCS#11

```bash
# Start TLS server using PKCS#11 key
openssl s_server -engine pkcs11 -keyform engine \
  -key "pkcs11:token=GO-KEYCHAIN;object=server-key;type=private" \
  -cert server.crt \
  -accept 4433
```

### TLS Client with PKCS#11

```bash
# Connect using PKCS#11 client certificate
openssl s_client -engine pkcs11 -keyform engine \
  -key "pkcs11:token=GO-KEYCHAIN;object=client-key;type=private" \
  -cert client.crt \
  -connect example.com:443
```

## SSH Integration

### SSH Agent

Some SSH implementations support PKCS#11:

```bash
# Add PKCS#11 provider to ssh-agent
ssh-add -s $P11_MODULE

# List keys from PKCS#11
ssh-add -L
```

### Direct SSH

```bash
# SSH with PKCS#11 key
ssh -I $P11_MODULE user@host
```

### SSH Configuration

Add to `~/.ssh/config`:

```
Host example.com
    PKCS11Provider /usr/lib/libkeychain_pkcs11.so
    User myuser
```

## p11-kit Integration

Register the module with p11-kit for system-wide availability:

```bash
# Create module file
sudo tee /etc/pkcs11/modules/keychain.module << EOF
module: /usr/lib/libkeychain_pkcs11.so
managed: yes
priority: 10
EOF
```

Then applications using p11-kit will automatically discover the module:

```bash
# List all p11-kit modules
p11-kit list-modules

# Use via p11-kit URI
openssl req -engine pkcs11 \
  -key "pkcs11:token=GO-KEYCHAIN;object=my-key" \
  -new -out request.csr
```

## NSS Integration

For Firefox and other NSS-based applications:

```bash
# Add module to NSS database
modutil -add "go-keychain" \
  -libfile /usr/lib/libkeychain_pkcs11.so \
  -dbdir sql:$HOME/.pki/nssdb
```

## Java Integration

Use with Java via the SunPKCS11 provider:

```java
// pkcs11.cfg
name = GoKeychain
library = /usr/lib/libkeychain_pkcs11.so
slot = 0
```

```java
import java.security.*;
import sun.security.pkcs11.SunPKCS11;

Provider p = new SunPKCS11("pkcs11.cfg");
Security.addProvider(p);

KeyStore ks = KeyStore.getInstance("PKCS11", p);
ks.load(null, "123456".toCharArray());
```

## Verification Commands

Test that the module is working correctly:

```bash
# Verify module loads
pkcs11-tool --module $P11_MODULE --show-info

# Verify slot access
pkcs11-tool --module $P11_MODULE --list-slots

# Verify mechanism support
pkcs11-tool --module $P11_MODULE --list-mechanisms

# Test key generation
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --keypairgen --key-type rsa:2048 \
  --label test-key

# Test signing
echo "test" | pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --sign --mechanism RSA-PKCS \
  --label test-key

# Clean up test key
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --delete-object --type privkey \
  --label test-key
```

## Backend Mode Testing

Test each communication mode:

```bash
# Test all modes
for mode in embedded unix rest grpc quic; do
  echo "Testing $mode mode..."
  export KEYCHAIN_PKCS11_MODE=$mode
  pkcs11-tool --module $P11_MODULE --list-slots
done
```
