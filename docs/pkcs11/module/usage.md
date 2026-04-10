# Usage Guide

This guide covers common usage patterns for the PKCS#11 module.

## pkcs11-tool

The `pkcs11-tool` from OpenSC is the standard CLI for PKCS#11 operations.

### Setup

```bash
# Set module path
export P11_MODULE=/usr/lib/libxkms_pkcs11.so

# Set xkms target
export XKMS_PKCS11_TARGET=unix:///var/run/xkms/xkms.sock
```

### Slot Information

```bash
# List slots
pkcs11-tool --module $P11_MODULE --list-slots

# Show token info
pkcs11-tool --module $P11_MODULE --list-token-slots

# Show mechanisms
pkcs11-tool --module $P11_MODULE --list-mechanisms
```

### Key Generation

```bash
# RSA 2048
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --keypairgen --key-type rsa:2048 \
  --label "my-rsa-key" --id 01

# RSA 4096
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --keypairgen --key-type rsa:4096 \
  --label "my-rsa-4096" --id 02

# ECDSA P-256
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --keypairgen --key-type EC:secp256r1 \
  --label "my-ec-key" --id 03

# ECDSA P-384
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --keypairgen --key-type EC:secp384r1 \
  --label "my-ec-384" --id 04
```

### List Objects

```bash
# All objects
pkcs11-tool --module $P11_MODULE --login --pin 123456 --list-objects

# Private keys only
pkcs11-tool --module $P11_MODULE --login --pin 123456 \
  --list-objects --type privkey

# Public keys only
pkcs11-tool --module $P11_MODULE --list-objects --type pubkey

# Certificates
pkcs11-tool --module $P11_MODULE --list-objects --type cert
```

### Signing

```bash
# Create test message
echo "Hello, World!" > message.txt

# RSA PKCS#1 v1.5
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --sign --mechanism RSA-PKCS \
  --label "my-rsa-key" \
  --input-file message.txt \
  --output-file signature.bin

# RSA PSS
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --sign --mechanism RSA-PKCS-PSS \
  --hash-algorithm SHA256 \
  --label "my-rsa-key" \
  --input-file message.txt \
  --output-file signature.bin

# ECDSA (requires pre-hashed data)
sha256sum message.txt | xxd -r -p > hash.bin
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --sign --mechanism ECDSA \
  --label "my-ec-key" \
  --input-file hash.bin \
  --output-file signature.bin
```

### Verification

```bash
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

### Delete Keys

```bash
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --delete-object --type privkey \
  --label "my-rsa-key"
```

## OpenSSL Integration

### Using libp11 Engine

```bash
# Install libp11
sudo apt install libengine-pkcs11-openssl

# Test engine
openssl engine pkcs11 -t
```

### Generate CSR

```bash
openssl req -engine pkcs11 -keyform engine \
  -key "pkcs11:token=GO-XKMS;object=my-rsa-key;type=private" \
  -new -out request.csr \
  -subj "/CN=example.com"
```

### Sign Data

```bash
openssl dgst -sha256 -engine pkcs11 -keyform engine \
  -sign "pkcs11:token=GO-XKMS;object=my-rsa-key;type=private" \
  -out signature.bin message.txt
```

### Verify Signature

```bash
# Export public key
pkcs11-tool --module $P11_MODULE \
  --read-object --type pubkey \
  --label "my-rsa-key" \
  --output-file pubkey.der

# Convert to PEM
openssl rsa -pubin -inform DER -in pubkey.der -out pubkey.pem

# Verify
openssl dgst -sha256 -verify pubkey.pem \
  -signature signature.bin message.txt
```

### TLS Server

```bash
openssl s_server -engine pkcs11 -keyform engine \
  -key "pkcs11:token=GO-XKMS;object=server-key;type=private" \
  -cert server.crt \
  -accept 4433
```

### TLS Client

```bash
openssl s_client -engine pkcs11 -keyform engine \
  -key "pkcs11:token=GO-XKMS;object=client-key;type=private" \
  -cert client.crt \
  -connect example.com:443
```

## SSH Integration

### SSH Agent

```bash
# Add PKCS#11 provider
ssh-add -s $P11_MODULE

# List keys
ssh-add -L
```

### Direct SSH

```bash
ssh -I $P11_MODULE user@host
```

### SSH Config

Add to `~/.ssh/config`:

```
Host example.com
    PKCS11Provider /usr/lib/libxkms_pkcs11.so
    User myuser
```

## p11-kit Integration

Register the module for system-wide availability:

```bash
# Create module file
sudo tee /etc/pkcs11/modules/xkms.module << EOF
module: /usr/lib/libxkms_pkcs11.so
managed: yes
priority: 10
EOF
```

List modules:

```bash
p11-kit list-modules
```

## NSS Integration

For Firefox and other NSS-based applications:

```bash
modutil -add "go-xkms" \
  -libfile /usr/lib/libxkms_pkcs11.so \
  -dbdir sql:$HOME/.pki/nssdb
```

## Java Integration

SunPKCS11 provider configuration (pkcs11.cfg):

```
name = GoXKMS
library = /usr/lib/libxkms_pkcs11.so
slot = 0
```

Java code:

```java
// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

import java.security.*;
import sun.security.pkcs11.SunPKCS11;

Provider p = new SunPKCS11("pkcs11.cfg");
Security.addProvider(p);

KeyStore ks = KeyStore.getInstance("PKCS11", p);
ks.load(null, "123456".toCharArray());
```

## Go Library Usage

```go
// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
    "fmt"

    "github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

func main() {
    // Get global module
    m := module.GetGlobalModule()

    // Initialize
    rv := m.Initialize(nil)
    if rv != module.CKR_OK {
        panic(fmt.Sprintf("init failed: %s", rv))
    }
    defer m.Finalize()

    // List slots
    slots, rv := m.GetSlotList(true)
    if rv != module.CKR_OK {
        panic(fmt.Sprintf("get slots failed: %s", rv))
    }
    fmt.Printf("Slots: %v\n", slots)

    // Open session
    handle, rv := m.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
    if rv != module.CKR_OK {
        panic(fmt.Sprintf("open session failed: %s", rv))
    }
    defer m.CloseSession(handle)

    // Login
    rv = m.Login(handle, module.CKU_USER, []byte("123456"))
    if rv != module.CKR_OK {
        panic(fmt.Sprintf("login failed: %s", rv))
    }
    defer m.Logout(handle)

    // Generate key pair
    pubHandle, privHandle, rv := m.GenerateKeyPair(
        handle,
        &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN},
        []module.Attribute{
            {Type: module.CKA_LABEL, Value: []byte("my-key")},
            {Type: module.CKA_MODULUS_BITS, Value: module.Uint32ToBytes(2048)},
        },
        []module.Attribute{
            {Type: module.CKA_LABEL, Value: []byte("my-key")},
        },
    )
    if rv != module.CKR_OK {
        panic(fmt.Sprintf("keygen failed: %s", rv))
    }
    fmt.Printf("Generated key pair: pub=%d, priv=%d\n", pubHandle, privHandle)
}
```

## Verification Commands

Test the module:

```bash
# Module info
pkcs11-tool --module $P11_MODULE --show-info

# Slot access
pkcs11-tool --module $P11_MODULE --list-slots

# Mechanism support
pkcs11-tool --module $P11_MODULE --list-mechanisms

# Full test
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --keypairgen --key-type rsa:2048 --label test-key

echo "test" | pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --sign --mechanism RSA-PKCS --label test-key

pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --delete-object --type privkey --label test-key
```

## Troubleshooting

### Debug Logging

```bash
export XKMS_DEBUG=true
export XKMS_LOG_FILE=/tmp/pkcs11.log
```

### Common Issues

| Error | Cause | Solution |
|-------|-------|----------|
| CKR_TOKEN_NOT_PRESENT | xKMS daemon not running | Start daemon |
| CKR_DEVICE_ERROR | Connection failed | Check target config |
| CKR_PIN_INCORRECT | Wrong PIN | Verify PIN |
| CKR_SESSION_HANDLE_INVALID | Stale session | Reopen session |
| CKR_KEY_HANDLE_INVALID | Key not found | Check key label |
