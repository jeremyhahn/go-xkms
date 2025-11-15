# Encoding Integration Tests Fix Summary

## Problem
The encoding integration tests in `test/integration/encoding/` were using incorrect go-keychain APIs:
- Referenced `keychain.NewKeyStore()` which doesn't exist
- Used `fs.NewMemFS()` instead of correct memory storage
- Tried to use non-existent `CertStorage` and `BlobStorage` fields in `software.Config`

## Solution
1. Created `helpers_test.go` with shared test utilities
2. Updated to use backend API directly with `KeyAttributes`
3. Use `memory.NewKeyStorage()` for in-memory testing

## Fixed Files
- ✅ `/test/integration/encoding/helpers_test.go` - NEW helper file with shared utilities
- ✅ `/test/integration/encoding/jwk_integration_test.go` - COMPLETE, tested and working

## Files Needing Update
- `/test/integration/encoding/jwt_integration_test.go`
- `/test/integration/encoding/jwe_integration_test.go` 
- `/test/integration/encoding/interop_integration_test.go`

## Pattern to Follow

### Old (Incorrect) Pattern:
```go
memFS := fs.NewMemFS()
backendCfg := &software.Config{
    KeyStorage:  memFS,
    CertStorage: memFS,  // WRONG - doesn't exist
    BlobStorage: memFS,  // WRONG - doesn't exist
}
backend, err := software.NewBackend(backendCfg)
ks := keychain.NewKeyStore(backend)  // WRONG - doesn't exist
err := ks.GenerateKey(keyID, "RSA", 2048)  // WRONG - method doesn't exist
```

### New (Correct) Pattern:
```go
setup := createTestBackend(t)
defer setup.Close()

// Generate keys
err := setup.GenerateRSAKey("my-key", 2048)
err := setup.GenerateECDSAKey("my-key", elliptic.P256())
err := setup.GenerateEd25519Key("my-key")

// Get keys
key, err := setup.GetKeyByID("my-key")
signer, err := setup.GetSignerByID("my-key")
decrypter, err := setup.GetDecrypterByID("my-key")
pubKey, err := setup.GetPublicKeyByID("my-key")
```

## Helper Functions Available
From `helpers_test.go`:
- `createTestBackend(t)` - Creates backend with memory storage
- `setup.GenerateRSAKey(cn, keySize)` - Generate RSA key
- `setup.GenerateECDSAKey(cn, curve)` - Generate ECDSA key
- `setup.GenerateEd25519Key(cn)` - Generate Ed25519 key
- `setup.GetKeyByID(cn)` - Get crypto.PrivateKey
- `setup.GetSignerByID(cn)` - Get crypto.Signer
- `setup.GetDecrypterByID(cn)` - Get crypto.Decrypter
- `setup.GetPublicKeyByID(cn)` - Get crypto.PublicKey
- `setup.Close()` - Close backend

## Key Changes Required

### For JWT tests:
Replace:
```go
ks := keychain.NewKeyStore(backend)
err := ks.GenerateKey(keyID, "RSA", 2048)
key, err := ks.GetKeyByID(keyID)
```

With:
```go
setup := createTestBackend(t)
defer setup.Close()
err := setup.GenerateRSAKey("jwt-rsa-2048", 2048)
key, err := setup.GetKeyByID("jwt-rsa-2048")
```

### For JWE tests:
Replace:
```go
key, err := ks.GetKeyByID(keyID)
pubKey := key.(crypto.Signer).Public()
```

With:
```go
pubKey, err := setup.GetPublicKeyByID("jwe-rsa-oaep")
```

### For Interop tests:
Same pattern - replace all `keychain.NewKeyStore()` calls with `createTestBackend()`.

## Verification
Run tests with:
```bash
go test -tags=integration -v ./test/integration/encoding/...
```

Each test should:
1. Compile without errors
2. Run successfully
3. Maintain comprehensive test coverage
4. Use correct backend APIs
