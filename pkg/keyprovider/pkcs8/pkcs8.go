// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package pkcs8

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	ecdhpkg "github.com/jeremyhahn/go-xkms/pkg/crypto/ecdh"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/x25519"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/youmark/pkcs8"
)

// PKCS8Backend implements the Backend interface using PKCS#8 encoding
// for key storage. Keys are stored using the provided storage Backend implementation.
//
// This backend is software-based and supports RSA, ECDSA, and Ed25519 keys.
// Keys can be optionally encrypted with a password using PKCS#8 encryption.
//
// Security: by default the backend is fail-closed — GenerateKey returns
// ErrPlaintextKeyNotAllowed when no password is provided. Set
// Config.AllowPlaintextKeys to opt into unencrypted persistence.
//
// Thread-safe: Yes, uses a read-write mutex for concurrent access.
type PKCS8Backend struct {
	storage        storage.Backend
	closed         bool
	allowPlaintext bool
	mu             sync.RWMutex
}

// Type returns the backend type identifier.
func (b *PKCS8Backend) Type() types.BackendType {
	return types.BackendTypeSoftware
}

// Capabilities returns what features this backend supports.
func (b *PKCS8Backend) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:                true,
		HardwareBacked:      false,
		Signing:             true,
		Decryption:          true,
		KeyRotation:         true,
		SymmetricEncryption: false,
		Import:              true, // PKCS#8 supports key import via standard encoding
		Export:              true, // PKCS#8 supports key export via standard encoding
		KeyAgreement:        true, // PKCS#8 supports ECDH key agreement (P-256, P-384, P-521, X25519)
		ECIES:               false,
	}
}

// GenerateKey generates a new private key with the given attributes.
// The key is encoded in PKCS#8 format and stored using the KeyStorage.
//
// Supported algorithms:
//   - RSA: Requires RSAAttributes with KeySize (minimum 2048 bits)
//   - ECDSA: Requires ECCAttributes with Curve (P-256, P-384, P-521)
//   - Ed25519: No additional attributes required
//
// X25519 keys are supported via CustomKeyAlgorithm when X25519Attributes are present.
//
// If attrs.Password is provided, the key will be encrypted using PKCS#8 encryption.
func (b *PKCS8Backend) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// b.mu serializes the encode+store+metadata sequence within this process and
	// guards b.closed. It is no longer the uniqueness mechanism: the
	// authoritative key-ID uniqueness guard is the storage layer's atomic
	// PutIfAbsent (storage.SaveKeyIfAbsent), which a replicated/clustered Backend
	// makes linearizable across nodes — something an in-process lock cannot do.
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	keyID := attrs.ID()

	// Generate key based on algorithm
	var privateKey crypto.PrivateKey
	var err error

	// Check for X25519 key agreement key
	if attrs.X25519Attributes != nil {
		privateKey, err = b.generateX25519Key()
	} else {
		switch attrs.KeyAlgorithm {
		case x509.RSA:
			privateKey, err = b.generateRSAKey(attrs.RSAAttributes)
		case x509.ECDSA:
			privateKey, err = b.generateECDSAKey(attrs.ECCAttributes)
		case x509.Ed25519:
			privateKey, err = b.generateEd25519Key()
		default:
			return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("%s", attrs.KeyAlgorithm)}
		}
	}

	if err != nil {
		return nil, &errs.Wrapped{Msg: "key generation failed", Err: err}
	}

	// Encode the key, then store it atomically only if its ID is unused. The
	// PutIfAbsent result is the authoritative uniqueness decision.
	keyData, err := b.encodeKey(privateKey, attrs.Password)
	if err != nil {
		return nil, err
	}
	stored, err := storage.SaveKeyIfAbsent(ctx, b.storage, keyID, keyData)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to store key", Err: err}
	}
	if !stored {
		return nil, &errs.Detail{Err: backend.ErrKeyAlreadyExists, Detail: fmt.Sprintf("%s", keyID)}
	}

	// Store metadata (including exportable flag). Metadata is non-authoritative.
	metadata := map[string]interface{}{
		"cn":            attrs.CN,
		"key_type":      attrs.KeyType.String(),
		"store_type":    string(attrs.StoreType),
		"key_algorithm": attrs.KeyAlgorithm.String(),
		"exportable":    attrs.Exportable,
	}
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to marshal metadata", Err: err}
	}
	metaKey := "meta/" + keyID
	if err := b.storage.Put(ctx, metaKey, metadataBytes); err != nil {
		// Roll back the key blob so a failed generation does not leave an
		// orphaned key that blocks regenerating under the same ID.
		if delErr := storage.DeleteKey(ctx, b.storage, keyID); delErr != nil {
			return nil, &errs.Affix{Prefix: "failed to store metadata: ", Err: err, Suffix: fmt.Sprintf(" (rollback of key %s also failed: %v)", keyID, delErr)}
		}
		return nil, &errs.Wrapped{Msg: "failed to store metadata", Err: err}
	}

	return privateKey, nil
}

// GetKey retrieves an existing private key by its attributes.
// Returns an error if the key does not exist.
func (b *PKCS8Backend) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	keyID := attrs.ID()
	keyData, err := storage.GetKey(ctx, b.storage, keyID)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s", keyID)}
		}
		return nil, &errs.Wrapped{Msg: "failed to retrieve key", Err: err}
	}

	// Decode the key
	privateKey, err := b.decodeKey(keyData, attrs.Password)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// DeleteKey removes a key identified by its attributes.
// Returns an error if the key does not exist.
func (b *PKCS8Backend) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	keyID := attrs.ID()
	if err := storage.DeleteKey(ctx, b.storage, keyID); err != nil {
		if err == storage.ErrNotFound {
			return &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s", keyID)}
		}
		return &errs.Wrapped{Msg: "failed to delete key", Err: err}
	}

	return nil
}

// ListKeys returns attributes for all keys managed by this backend.
// Returns an empty slice if no keys exist.
//
// Note: This implementation returns key IDs as CommonNames.
// Full attribute reconstruction may require additional metadata storage.
func (b *PKCS8Backend) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	keyIDs, err := storage.ListKeys(ctx, b.storage)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to list keys", Err: err}
	}

	// Parse key ID to extract attributes
	// Format: [partition:]storetype:keytype:cn:algorithm
	// Example: sw:tls:my-key:rsa or partition:sw:signing:my-key:ecdsa
	// Also supports format like: pkcs8:tls:my-key:rsa
	attrs := make([]*types.KeyAttributes, 0, len(keyIDs))
	for _, id := range keyIDs {
		parts := strings.Split(id, ":")
		var cn string
		var keyTypeStr string
		var storeTypeStr string
		var algorithmStr string

		if len(parts) >= 4 {
			// Has all required parts
			// For format without partition: storetype:keytype:cn:algorithm (4 parts)
			// For format with partition: partition:storetype:keytype:cn:algorithm (5 parts)
			if len(parts) == 4 {
				// storetype:keytype:cn:algorithm
				storeTypeStr = parts[0]
				keyTypeStr = parts[1]
				cn = parts[2]
				algorithmStr = parts[3]
			} else {
				// partition:storetype:keytype:cn:algorithm
				storeTypeStr = parts[1]
				keyTypeStr = parts[2]
				cn = parts[3]
				algorithmStr = parts[4]
			}
		} else {
			// Fallback to using the whole ID as CN
			cn = id
			keyTypeStr = "tls"     // Default to TLS
			storeTypeStr = "pkcs8" // Default to pkcs8
			algorithmStr = "rsa"   // Default to RSA
		}

		// Skip symmetric keys - they are handled by the symmetric backend
		if strings.ToLower(keyTypeStr) == "secret" {
			continue
		}

		// Skip quantum keys - they are handled by the quantum backend
		algoLower := strings.ToLower(algorithmStr)
		if strings.HasPrefix(algoLower, "ml-dsa") || strings.HasPrefix(algoLower, "ml-kem") {
			continue
		}

		attr := &types.KeyAttributes{
			CN:        cn,
			KeyType:   types.ParseKeyType(keyTypeStr),
			StoreType: types.ParseStoreType(storeTypeStr),
		}

		// Parse key algorithm
		switch strings.ToLower(algorithmStr) {
		case "rsa":
			attr.KeyAlgorithm = x509.RSA
			attr.RSAAttributes = &types.RSAAttributes{KeySize: 2048} // Default
		case "ecdsa":
			attr.KeyAlgorithm = x509.ECDSA
			curve, _ := types.ParseCurve("P-256") // Default curve
			attr.ECCAttributes = &types.ECCAttributes{Curve: curve}
		case "ed25519":
			attr.KeyAlgorithm = x509.Ed25519
		}

		// Ensure we have valid defaults
		if attr.KeyType == 0 {
			attr.KeyType = types.KeyTypeTLS
		}
		if attr.StoreType == "" {
			attr.StoreType = types.StoreSoftware
		}
		if attr.KeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
			attr.KeyAlgorithm = x509.RSA
			attr.RSAAttributes = &types.RSAAttributes{KeySize: 2048}
		}

		// Load metadata to get exportable flag
		metaKey := "meta/" + id
		if metaData, err := b.storage.Get(ctx, metaKey); err == nil {
			var metadata map[string]interface{}
			if json.Unmarshal(metaData, &metadata) == nil {
				if exportable, ok := metadata["exportable"].(bool); ok {
					attr.Exportable = exportable
				}
			}
		} else {
			// Metadata is non-authoritative; a missing record only loses the
			// exportable flag, so log at debug and keep listing.
			slog.Debug("pkcs8: failed to load key metadata",
				"keyID", id, "metaKey", metaKey, "error", err)
		}

		attrs = append(attrs, attr)
	}

	return attrs, nil
}

// Signer returns a crypto.Signer for the key identified by attrs.
// This allows the key to be used for signing operations without
// exposing the private key material.
func (b *PKCS8Backend) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	key, err := b.GetKey(ctx, attrs)
	if err != nil {
		return nil, err
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, ErrKeyNotSigner
	}

	return signer, nil
}

// Decrypter returns a crypto.Decrypter for the key identified by attrs.
// This allows the key to be used for decryption operations without
// exposing the private key material.
func (b *PKCS8Backend) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	key, err := b.GetKey(ctx, attrs)
	if err != nil {
		return nil, err
	}

	decrypter, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, ErrKeyNotDecrypter
	}

	return decrypter, nil
}

// Close releases any resources held by the backend.
// After calling Close, the backend should not be used.
func (b *PKCS8Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true
	return b.storage.Close()
}

// generateRSAKey generates a new RSA private key.
func (b *PKCS8Backend) generateRSAKey(attrs *types.RSAAttributes) (*rsa.PrivateKey, error) {
	if attrs == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "RSA attributes are required"}
	}

	if attrs.KeySize < 2048 {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "RSA key size must be at least 2048 bits"}
	}

	return rsa.GenerateKey(rand.Reader, attrs.KeySize)
}

// generateECDSAKey generates a new ECDSA private key.
func (b *PKCS8Backend) generateECDSAKey(attrs *types.ECCAttributes) (*ecdsa.PrivateKey, error) {
	if attrs == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "ECC attributes are required"}
	}

	if attrs.Curve == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "curve is required"}
	}

	return ecdsa.GenerateKey(attrs.Curve, rand.Reader)
}

// generateEd25519Key generates a new Ed25519 private key.
func (b *PKCS8Backend) generateEd25519Key() (ed25519.PrivateKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	return privateKey, err
}

// generateX25519Key generates a new X25519 private key for key agreement.
func (b *PKCS8Backend) generateX25519Key() (crypto.PrivateKey, error) {
	ka := x25519.New()
	keyPair, err := ka.GenerateKey()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "X25519 key generation failed", Err: err}
	}

	// Wrap the X25519 private key to implement crypto.PrivateKey
	wrappedKey, err := x25519.NewPrivateKeyStorage(keyPair.PrivateKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to wrap X25519 private key", Err: err}
	}

	return wrappedKey, nil
}

// encodeKey encodes a private key in PKCS#8 format. When password is non-empty
// the encrypted-PKCS#8 form is produced; otherwise the unencrypted form is
// used. X25519 wrapped keys are unwrapped to their raw ecdh.PrivateKey before
// encoding. It performs no storage I/O.
func (b *PKCS8Backend) encodeKey(privateKey crypto.PrivateKey, password types.Password) ([]byte, error) {
	// Unwrap X25519 wrapped key if needed
	actualPrivateKey := privateKey
	if wrapped, ok := privateKey.(*x25519.PrivateKeyStorage); ok {
		// For X25519, store the raw ecdh.PrivateKey
		actualPrivateKey = wrapped.PrivateKey()
	}

	// Get password bytes if provided
	var passwordBytes []byte
	if password != nil {
		passwordBytes = password.Bytes()
	}

	// Encode the key
	if len(passwordBytes) > 0 {
		// Encrypted PKCS#8
		keyData, err := pkcs8.MarshalPrivateKey(actualPrivateKey, passwordBytes, nil)
		if err != nil {
			return nil, &errs.Detail{Err: ErrKeyEncodingFailed, Detail: fmt.Sprintf("%v", err)}
		}
		return keyData, nil
	}

	// Fail-closed: refuse unencrypted persistence unless explicitly opted in.
	// This protects CA signing keys and any other sensitive material that has
	// not been given a password. Callers that intentionally want plaintext
	// storage (e.g., ephemeral test backends, volume-encrypted deployments)
	// must set AllowPlaintextKeys: true in Config.
	if !b.allowPlaintext {
		return nil, ErrPlaintextKeyNotAllowed
	}

	// Unencrypted PKCS#8 — AllowPlaintextKeys is explicitly true.
	keyData, err := x509.MarshalPKCS8PrivateKey(actualPrivateKey)
	if err != nil {
		return nil, &errs.Detail{Err: ErrKeyEncodingFailed, Detail: fmt.Sprintf("%v", err)}
	}
	return keyData, nil
}

// decodeKey decodes a PKCS#8 encoded private key.
// X25519 keys are automatically wrapped in PrivateKeyStorage for consistency.
func (b *PKCS8Backend) decodeKey(keyData []byte, password types.Password) (crypto.PrivateKey, error) {
	var passwordBytes []byte
	var err error

	if password != nil {
		passwordBytes = password.Bytes()
	}

	var privateKey crypto.PrivateKey

	// Try encrypted PKCS#8 if password provided
	if len(passwordBytes) > 0 {
		privateKey, err = pkcs8.ParsePKCS8PrivateKey(keyData, passwordBytes)
		if err != nil {
			return nil, &errs.Detail{Err: ErrKeyDecodingFailed, Detail: fmt.Sprintf("%v", err)}
		}
	} else {
		// Try unencrypted PKCS#8
		privateKey, err = x509.ParsePKCS8PrivateKey(keyData)
		if err != nil {
			// If a password interface was provided but returned empty/nil, and
			// unencrypted parsing failed, this likely means password retrieval
			// failed (e.g., TPM unseal error) and the key is actually encrypted.
			if password != nil {
				return nil, &errs.Detail{Err: ErrKeyDecodingFailed, Detail: fmt.Sprintf("unencrypted parsing failed and password retrieval returned empty (possible TPM unseal failure or key is encrypted): %v", err)}
			}
			return nil, &errs.Detail{Err: ErrKeyDecodingFailed, Detail: fmt.Sprintf("%v", err)}
		}
	}

	// Wrap X25519 keys for consistency
	if ecdhPrivKey, ok := privateKey.(*ecdh.PrivateKey); ok {
		if ecdhPrivKey.Curve() == ecdh.X25519() {
			wrapped, err := x25519.NewPrivateKeyStorage(ecdhPrivKey)
			if err != nil {
				return nil, &errs.Wrapped{Msg: "failed to wrap X25519 key", Err: err}
			}
			return wrapped, nil
		}
	}

	return privateKey, nil
}

// Public returns the public key corresponding to the private key.
// This is a helper method for signing operations.
func (b *PKCS8Backend) Public(ctx context.Context, attrs *types.KeyAttributes) (crypto.PublicKey, error) {
	key, err := b.GetKey(ctx, attrs)
	if err != nil {
		return nil, err
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	case *x25519.PrivateKeyStorage:
		return k.Public(), nil
	default:
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("%T", key)}
	}
}

// Sign signs digest with the private key identified by attrs.
// This is a convenience method that wraps Signer().
func (b *PKCS8Backend) Sign(ctx context.Context, attrs *types.KeyAttributes, rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signer, err := b.Signer(ctx, attrs)
	if err != nil {
		return nil, err
	}
	return signer.Sign(rand, digest, opts)
}

// RotateKey rotates/updates a key identified by attrs.
// For PKCS#8 software keys, rotation means generating a new key and replacing the old one.
func (b *PKCS8Backend) RotateKey(ctx context.Context, attrs *types.KeyAttributes) error {
	if attrs == nil {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "attributes cannot be nil"}
	}

	// Delete the old key
	if err := b.DeleteKey(ctx, attrs); err != nil && !errors.Is(err, backend.ErrKeyNotFound) {
		return &errs.Wrapped{Msg: "failed to delete old key", Err: err}
	}

	// Generate a new key with the same attributes
	_, err := b.GenerateKey(ctx, attrs)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to generate new key", Err: err}
	}

	return nil
}

// DeriveSharedSecret performs ECDH key agreement between the private key
// identified by attrs and the provided public key.
//
// Supports:
//   - X25519 keys for key agreement (32 bytes)
//   - NIST curves (P-256, P-384, P-521) via ECDSA keys
//
// Both keys must be compatible (same curve).
// The shared secret is the raw output of ECDH - use a KDF to derive encryption keys.
func (b *PKCS8Backend) DeriveSharedSecret(ctx context.Context, attrs *types.KeyAttributes, publicKey crypto.PublicKey) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if attrs == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "attributes cannot be nil"}
	}

	if publicKey == nil {
		return nil, &errs.Message{Msg: "public key cannot be nil"}
	}

	// Get the private key
	privateKey, err := b.GetKey(ctx, attrs)
	if err != nil {
		return nil, err
	}

	// Handle different key types
	switch privKey := privateKey.(type) {
	case *x25519.PrivateKeyStorage:
		// X25519 key agreement
		pubKeyStorage, ok := publicKey.(*x25519.PublicKeyStorage)
		if !ok {
			return nil, &errs.Message{Msg: "public key must be X25519 for X25519 private key"}
		}
		ka := x25519.New()
		return ka.DeriveSharedSecret(privKey.PrivateKey(), pubKeyStorage.PublicKey())

	case *ecdsa.PrivateKey:
		// NIST curve ECDH (P-256, P-384, P-521)
		pubKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, &errs.Message{Msg: "public key must be ECDSA for ECDSA private key"}
		}
		// Use the ECDH package from pkg/crypto/ecdh
		return deriveECDHSharedSecret(privKey, pubKeyECDSA)

	default:
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("%T does not support key agreement", privateKey)}
	}
}

// deriveECDHSharedSecret is a helper that performs ECDH with NIST curves (P-256, P-384, P-521).
func deriveECDHSharedSecret(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, error) {
	// Check that curves match
	if privateKey.Curve != publicKey.Curve {
		return nil, &errs.Message{Msg: fmt.Sprintf("curve mismatch: private key uses %s, public key uses %s", privateKey.Curve.Params().Name, publicKey.Curve.Params().Name)}
	}

	// Use the ecdh package from pkg/crypto/ecdh for NIST curves
	return ecdhpkg.DeriveSharedSecret(privateKey, publicKey)
}

// Verify interface compliance at compile time.
var _ types.KeyProvider = (*PKCS8Backend)(nil)
var _ types.KeyAgreement = (*PKCS8Backend)(nil)
