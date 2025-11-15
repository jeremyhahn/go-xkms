# Symmetric Encryption

go-keychain provides symmetric encryption capabilities using AES-GCM across all backends that support it.

## Supported Backends

The following backends implement symmetric encryption:

- **AES Backend** - Software-based AES encryption
- **AWS KMS** - AES-256-GCM using AWS symmetric keys
- **GCP KMS** - AES-256-GCM using GCP symmetric keys
- **Azure Key Vault** - AES-256-GCM using Azure symmetric keys
- **HashiCorp Vault** - AES encryption via Transit engine
- **PKCS#11** - AES encryption using HSM
- **TPM2** - AES encryption using TPM symmetric keys

## Key Algorithms

- `ALG_AES128_GCM` - AES-128-GCM
- `ALG_AES192_GCM` - AES-192-GCM
- `ALG_AES256_GCM` - AES-256-GCM

## Usage

### Generate Symmetric Key

```go
attrs := &backend.KeyAttributes{
    CN:           "my-encryption-key",
    KeyType:      backend.KEY_TYPE_SECRET,
    StoreType:    backend.STORE_SW,
    KeyAlgorithm: backend.ALG_AES256_GCM,
    AESAttributes: &backend.AESAttributes{
        KeySize: 256,
    },
}

key, err := keystore.GenerateAES(attrs)
```

### Encrypt Data

```go
encrypter, err := keystore.SymmetricEncrypter(attrs)

encrypted, err := encrypter.Encrypt(plaintext, &backend.EncryptOptions{
    AdditionalData: []byte("context"),
})
```

### Decrypt Data

```go
plaintext, err := encrypter.Decrypt(encrypted, &backend.DecryptOptions{
    AdditionalData: []byte("context"),
})
```

## Password Protection

Keys can be encrypted with a password:

```go
attrs := &backend.KeyAttributes{
    CN:           "protected-key",
    KeyType:      backend.KEY_TYPE_SECRET,
    StoreType:    backend.STORE_SW,
    KeyAlgorithm: backend.ALG_AES256_GCM,
    Password:     backend.StaticPassword([]byte("secret")),
    AESAttributes: &backend.AESAttributes{KeySize: 256},
}
```

## Security

- Uses AES-GCM for authenticated encryption
- 12-byte nonces generated with crypto/rand
- 16-byte authentication tags
- Password-protected keys use Argon2id key derivation
- Cloud backends (AWS, GCP, Azure) keep keys in HSM

## Backend Limitations

- **AWS KMS**: Only supports AES-256
- **GCP KMS**: Only supports AES-256
- **Azure Key Vault**: Requires Premium tier for HSM-backed keys
