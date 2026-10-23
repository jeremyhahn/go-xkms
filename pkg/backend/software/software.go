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

package software

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/importtoken"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/pkcs8"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/quantum"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/symmetric"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// SoftwareBackend provides a unified interface for both asymmetric and symmetric
// cryptographic operations using software-based implementations.
//
// This backend uses the Composite/Facade design pattern, delegating:
//   - Asymmetric operations (RSA, ECDSA, Ed25519) to PKCS8Backend
//   - Symmetric operations (AES-GCM, ChaCha20-Poly1305) to symmetric.Backend
//   - Quantum-safe operations (ML-DSA, ML-KEM) to quantum.QuantumBackend
//
// This design provides a consistent interface similar to cloud backends
// (AWS KMS, GCP KMS, Azure Key Vault) which also support both operation types.
//
// # Memory discipline
//
// The only sensitive material the backend holds directly (as opposed to
// delegating to pkcs8Backend / symmetricBackend / quantumBackend) is the
// ephemeral RSA wrapping key pair used during the import ceremony. That
// private key lives inside a *secure.Secret for its entire 24-hour TTL;
// every unwrap operation opens the enclave, parses the PKCS#8 DER into
// an ephemeral *rsa.PrivateKey on the stack, runs the wrapping logic,
// and destroys the Buffer before returning. No plaintext of the
// wrapping private key ever outlives a single stack frame.
//
// Thread-safe: Yes, uses a read-write mutex for concurrent access.
type SoftwareBackend struct {
	pkcs8Backend     *pkcs8.PKCS8Backend     // Handles asymmetric operations
	symmetricBackend *symmetric.Backend      // Handles symmetric operations
	quantumBackend   *quantum.QuantumBackend // Handles quantum operations (ML-DSA, ML-KEM)
	storage          storage.Backend         // Direct access to storage for import operations
	closed           bool
	mu               sync.RWMutex

	// Import/export state: a bounded, TTL-enforced, single-use store for
	// the wrapping keypair each in-progress import ceremony holds between
	// GetImportParameters and UnwrapKey (go-xkms#1261). See
	// importtoken.Store's doc comment for why it is bounded and swept
	// rather than a plain map.
	importTokens *importtoken.Store[*importTokenData]
}

// importTokenData holds the ephemeral wrapping key pair for an
// in-progress import ceremony, plus the metadata GetImportParameters
// generated it with. The keypair itself is a *importtoken.SealedRSAKey,
// which keeps the private half sealed inside a *secure.Secret for its
// entire TTL; only Use opens it, and only for the duration of one call.
type importTokenData struct {
	wrappingKey *importtoken.SealedRSAKey
	algorithm   backend.WrappingAlgorithm
	keySpec     string
}

// destroy releases the sealed wrapping keypair. Safe to call on a nil
// receiver or the zero value. It is the importTokens Store's destroy
// callback, so it runs on every eviction path: sweep, Take, Delete, and
// Close.
func (t *importTokenData) destroy() {
	if t == nil {
		return
	}
	t.wrappingKey.Destroy()
}

// SoftwareBackendWithKeyAgreement extends the software backend with KeyAgreement capabilities.
// This interface is used internally by the Software backend to provide ECDH support.
type SoftwareBackendWithKeyAgreement interface {
	types.SymmetricKeyProvider
	types.KeyAgreement
}

// NewBackend creates a new unified software backend with the given configuration.
//
// Example usage:
//
//	storage := storage.New()
//	config := &software.Config{
//	    KeyStorage: storage,
//	}
//	backend, err := software.NewBackend(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer backend.Close()
//
//	// Generate an RSA key (asymmetric)
//	rsaAttrs := &types.KeyAttributes{
//	    CN:           "example.com",
//	    KeyType:      backend.KEY_TYPE_TLS,
//	    StoreType:    backend.STORE_SW,
//	    KeyAlgorithm: x509.RSA,
//	    RSAAttributes: &types.RSAAttributes{
//	        KeySize: 2048,
//	    },
//	}
//	rsaKey, err := backend.GenerateKey(rsaAttrs)
//
//	// Generate an AES key (symmetric) with AEAD safety tracking
//	aesAttrs := &types.KeyAttributes{
//	    CN:                "my-secret-key",
//	    KeyType:           backend.KEY_TYPE_SECRET,
//	    StoreType:         backend.STORE_SW,
//	    SymmetricAlgorithm: types.SymmetricAES256GCM,
//	    AEADOptions:       nil, // Use defaults (nonce tracking + bytes tracking enabled)
//	}
//	aesKey, err := backend.GenerateSymmetricKey(aesAttrs)
func NewBackend(config *Config) (types.SymmetricKeyProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, &errs.Wrapped{Msg: "invalid config", Err: err}
	}

	// Create PKCS8 backend for asymmetric operations.
	// SoftwareBackend is a general-purpose backend used for TLS keys, ACME
	// keys, and other non-CA material that may not carry individual
	// passwords. CA signing keys that require at-rest encryption should use
	// a raw pkcs8.Backend (via xkms.RegisterPKCS8Backend) with a per-key
	// password wired through KeyConfig.Password → KeyAttributesFromConfig.
	pkcs8Config := &pkcs8.Config{
		KeyStorage:         config.KeyStorage,
		AllowPlaintextKeys: true,
	}
	pkcs8Backend, err := pkcs8.NewBackend(pkcs8Config)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create PKCS8 backend", Err: err}
	}

	// Create AEAD tracker for symmetric operations
	// Use config tracker if provided, otherwise create default
	tracker := config.Tracker
	if tracker == nil {
		tracker = backend.NewMemoryAEADTracker()
	}

	// Create symmetric backend for symmetric operations with tracking
	symmetricConfig := &symmetric.Config{
		KeyStorage: config.KeyStorage,
		Tracker:    tracker,
	}
	symmetricBackend, err := symmetric.NewBackend(symmetricConfig)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create symmetric backend", Err: err}
	}

	// Create quantum backend for post-quantum operations (ML-DSA, ML-KEM)
	quantumBackend, err := quantum.New(config.KeyStorage)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create quantum backend", Err: err}
	}

	return &SoftwareBackend{
		pkcs8Backend:     pkcs8Backend.(*pkcs8.PKCS8Backend),
		symmetricBackend: symmetricBackend.(*symmetric.Backend),
		quantumBackend:   quantumBackend,
		storage:          config.KeyStorage,
		closed:           false,
		importTokens:     importtoken.New[*importTokenData](0, 0, (*importTokenData).destroy),
	}, nil
}

// Type returns the backend type identifier.
func (b *SoftwareBackend) Type() types.BackendType {
	return types.BackendTypeSoftware
}

// Capabilities returns what features this backend supports.
// The unified software backend supports BOTH asymmetric and symmetric operations.
// SecurityLevel is Low - keys are protected by software encryption on disk.
func (b *SoftwareBackend) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:                true,
		HardwareBacked:      false,
		Signing:             true,  // Asymmetric signing via PKCS8
		Decryption:          true,  // Asymmetric decryption via PKCS8
		KeyRotation:         true,  // Supported by PKCS8
		SymmetricEncryption: true,  // Symmetric operations via AES
		Import:              true,  // Software backend supports key import
		Export:              true,  // Software backend supports key export
		KeyAgreement:        true,  // ECDH key agreement via PKCS8 (X25519, P-256, P-384, P-521)
		ECIES:               false, // Not currently supported
		Sealing:             true,  // Sealing via PKCS8 (HKDF-derived key + AES-GCM)
		QuantumSigning:      true,  // Post-quantum signatures via ML-DSA
		KeyEncapsulation:    true,  // Key encapsulation via ML-KEM
		SecurityLevel:       types.SecurityLevelLow,
		KeyAlgorithms:       b.keyAlgorithms(),
	}
}

// keyAlgorithms joins the asymmetric keys of the PKCS#8 provider and the
// symmetric keys of the symmetric provider.
func (b *SoftwareBackend) keyAlgorithms() types.KeyAlgorithms {
	algorithms := b.pkcs8Backend.Capabilities().KeyAlgorithms
	symmetricKeys := b.symmetricBackend.Capabilities().KeyAlgorithms
	algorithms.Symmetric = symmetricKeys.Symmetric
	algorithms.HMAC = symmetricKeys.HMAC
	return algorithms
}

// GenerateKey generates a new asymmetric private key with the given attributes.
// This operation is delegated to the PKCS8 backend.
//
// Supported algorithms:
//   - RSA: Requires RSAAttributes with KeySize (minimum 2048 bits)
//   - ECDSA: Requires ECCAttributes with Curve (P-256, P-384, P-521)
//   - Ed25519: No additional attributes required
func (b *SoftwareBackend) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if attrs.QuantumAttributes != nil {
		return b.quantumBackend.GenerateKey(ctx, attrs)
	}

	return b.pkcs8Backend.GenerateKey(ctx, attrs)
}

// GetKey retrieves an existing asymmetric private key by its attributes.
// This operation is delegated to the PKCS8 backend.
func (b *SoftwareBackend) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if attrs.QuantumAttributes != nil {
		return b.quantumBackend.GetKey(ctx, attrs)
	}

	return b.pkcs8Backend.GetKey(ctx, attrs)
}

// DeleteKey removes a key identified by its attributes.
// This works for both asymmetric and symmetric keys.
func (b *SoftwareBackend) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	// The routing below reads a different field from the one that decides the
	// key's identity, so contradictory attributes operate on a key they do not
	// name. See requireSingleAlgorithmFamily (go-xkms#158).
	if err := requireSingleAlgorithmFamily(attrs); err != nil {
		return err
	}

	if attrs.QuantumAttributes != nil {
		return b.quantumBackend.DeleteKey(ctx, attrs)
	}

	// Determine if this is a symmetric or asymmetric key
	if attrs.IsSymmetric() {
		return b.symmetricBackend.DeleteKey(ctx, attrs)
	}
	return b.pkcs8Backend.DeleteKey(ctx, attrs)
}

// ListKeys returns attributes for all keys managed by this backend.
// This includes asymmetric, symmetric, and quantum keys.
func (b *SoftwareBackend) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	// Get keys from all three backends
	pkcs8Keys, err := b.pkcs8Backend.ListKeys(ctx)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to list PKCS8 keys", Err: err}
	}

	symmetricKeys, err := b.symmetricBackend.ListKeys(ctx)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to list symmetric keys", Err: err}
	}

	quantumKeys, err := b.quantumBackend.ListKeys(ctx)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to list quantum keys", Err: err}
	}

	// Combine the results
	allKeys := make([]*types.KeyAttributes, 0, len(pkcs8Keys)+len(symmetricKeys)+len(quantumKeys))
	allKeys = append(allKeys, pkcs8Keys...)
	allKeys = append(allKeys, symmetricKeys...)
	allKeys = append(allKeys, quantumKeys...)

	return allKeys, nil
}

// Signer creates a crypto.Signer for the given asymmetric key.
// This operation is delegated to the appropriate backend.
func (b *SoftwareBackend) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if attrs.QuantumAttributes != nil {
		return b.quantumBackend.Signer(ctx, attrs)
	}

	return b.pkcs8Backend.Signer(ctx, attrs)
}

// Decrypter creates a crypto.Decrypter for the given asymmetric key.
// This operation is delegated to the PKCS8 backend.
func (b *SoftwareBackend) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	return b.pkcs8Backend.Decrypter(ctx, attrs)
}

// RotateKey generates a new version of the key, keeping the same key ID.
// This operation is delegated to the appropriate backend.
func (b *SoftwareBackend) RotateKey(ctx context.Context, attrs *types.KeyAttributes) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	// The routing below reads a different field from the one that decides the
	// key's identity, so contradictory attributes operate on a key they do not
	// name. See requireSingleAlgorithmFamily (go-xkms#158).
	if err := requireSingleAlgorithmFamily(attrs); err != nil {
		return err
	}

	if attrs.QuantumAttributes != nil {
		return b.quantumBackend.RotateKey(ctx, attrs)
	}

	if attrs.IsSymmetric() {
		return b.symmetricBackend.RotateKey(ctx, attrs)
	}
	return b.pkcs8Backend.RotateKey(ctx, attrs)
}

// Close releases any resources held by the backend.
// This closes both the PKCS8 and symmetric backends and destroys any
// in-flight wrapping-key enclaves.
func (b *SoftwareBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true

	// Destroy any pending import-token enclaves before releasing
	// storage so leftover wrapping keys cannot survive a shutdown.
	b.importTokens.Close()

	// Close both backends (but only close storage once)
	// Note: Both backends share the same storage, so we only need to close
	// one of them to close the storage. The second Close() will be a no-op.
	if err := b.pkcs8Backend.Close(); err != nil {
		return &errs.Wrapped{Msg: "failed to close PKCS8 backend", Err: err}
	}

	// The storage is already closed by pkcs8Backend.Close(), so this will
	// return immediately without error.
	if err := b.symmetricBackend.Close(); err != nil {
		return &errs.Wrapped{Msg: "failed to close symmetric backend", Err: err}
	}

	if err := b.quantumBackend.Close(); err != nil {
		return &errs.Wrapped{Msg: "failed to close quantum backend", Err: err}
	}

	return nil
}

// GenerateSymmetricKey generates a new symmetric AES key with the given attributes.
// This operation is delegated to the symmetric backend.
//
// Supported key sizes: 128, 192, 256 bits
func (b *SoftwareBackend) GenerateSymmetricKey(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	return b.symmetricBackend.GenerateSymmetricKey(ctx, attrs)
}

// GetSymmetricKey retrieves an existing symmetric key by its attributes.
// This operation is delegated to the symmetric backend.
func (b *SoftwareBackend) GetSymmetricKey(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	return b.symmetricBackend.GetSymmetricKey(ctx, attrs)
}

// DeriveFromSymmetricKey runs the key derivation function selected by params
// over the symmetric key named by attrs, implementing
// types.SymmetricKeyDeriver. It is what answers PKCS#11 C_DeriveKey
// (v3.2 §5.18.5) for this backend.
//
// Like every other symmetric operation here it is delegated to the symmetric
// backend, which owns the key material: the derivation runs where the key
// lives, and the base key's bytes never reach this facade or any caller of it.
func (b *SoftwareBackend) DeriveFromSymmetricKey(ctx context.Context, attrs *types.KeyAttributes, params *kdf.KDFParams) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	return b.symmetricBackend.DeriveFromSymmetricKey(ctx, attrs, params)
}

// SymmetricEncrypter creates a SymmetricEncrypter for the given key.
// This operation is delegated to the symmetric backend.
func (b *SoftwareBackend) SymmetricEncrypter(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	return b.symmetricBackend.SymmetricEncrypter(ctx, attrs)
}

// GetImportParameters generates a wrapping key pair and returns the public key
// along with an import token for later import operations.
//
// For the software backend, we generate a 2048-bit RSA key pair and seal
// it into a *importtoken.SealedRSAKey; only the public key stays in
// plaintext. The import token is a UUID that identifies this wrapping key
// pair. b.importTokens (a *importtoken.Store) enforces the ceremony's
// 24-hour TTL and a hard cap on how many ceremonies can be in flight at
// once, sweeping expired ones on every Put; UnwrapKey consumes the token
// (single use), and on expiry, on eviction, or on backend Close, the
// enclave is destroyed rather than left to linger (go-xkms#1261).
func (b *SoftwareBackend) GetImportParameters(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	b.mu.RLock()
	closed := b.closed
	b.mu.RUnlock()
	if closed {
		return nil, ErrStorageClosed
	}

	// Validate algorithm
	if !isValidWrappingAlgorithm(algorithm) {
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: algorithm.String()}
	}

	// Generate a 2048-bit RSA key pair for wrapping.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate wrapping key", Err: err}
	}

	// Seal the private key; only the public key stays in plaintext. See
	// importtoken.SealedRSAKey for the seal/open/destroy handling.
	wrappingKey, err := importtoken.NewSealedRSAKey(ctx, privateKey)
	if err != nil {
		return nil, err
	}
	publicKey := wrappingKey.PublicKey()

	// Generate import token (UUID)
	tokenUUID := uuid.New().String()
	importToken := []byte(tokenUUID)

	// Determine key spec based on key attributes
	keySpec := determineKeySpec(attrs)

	// Store the sealed private key and metadata. Put enforces the
	// store's TTL and hard cap (go-xkms#1261) and sweeps expired
	// ceremonies before inserting this one.
	expiresAt, err := b.importTokens.Put(tokenUUID, &importTokenData{
		wrappingKey: wrappingKey,
		algorithm:   algorithm,
		keySpec:     keySpec,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to store import token", Err: err}
	}

	return &backend.ImportParameters{
		WrappingPublicKey: publicKey,
		ImportToken:       importToken,
		Algorithm:         algorithm,
		ExpiresAt:         &expiresAt,
		KeySpec:           keySpec,
	}, nil
}

// WrapKey wraps key material using the specified import parameters.
// This uses the pkg/crypto/wrapping functions to wrap the key.
func (b *SoftwareBackend) WrapKey(ctx context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if len(keyMaterial) == 0 {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "key material cannot be nil or empty"}
	}
	if params == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "import parameters cannot be nil"}
	}

	// Extract the RSA public key
	publicKey, ok := params.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: "wrapping public key must be an RSA public key"}
	}

	var wrappedKey []byte
	var err error

	// Use the appropriate wrapping algorithm
	switch params.Algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1, backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		wrappedKey, err = wrapping.WrapRSAOAEP(keyMaterial, publicKey, params.Algorithm)
	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		wrappedKey, err = wrapping.WrapRSAAES(keyMaterial, publicKey, params.Algorithm)
	default:
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: params.Algorithm.String()}
	}

	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to wrap key", Err: err}
	}

	return &backend.WrappedKeyMaterial{
		WrappedKey:  wrappedKey,
		Algorithm:   params.Algorithm,
		ImportToken: params.ImportToken,
		Metadata:    make(map[string]string),
	}, nil
}

// UnwrapKey unwraps key material that was previously wrapped.
// For the software backend, we can perform unwrapping since we have
// access to the sealed wrapping private key.
//
// The import token is single-use: a successful call, whether made
// directly or as part of ImportKey, consumes it via the importTokens
// Store's Take, so it cannot be replayed against a second (or
// concurrent) wrap of different key material. A failed unwrap — wrong
// algorithm, corrupted payload — also consumes it rather than leaving it
// live for another guess, because the wrapping key was already opened to
// discover the failure (go-xkms#1261).
//
// Flow: take the token → open the Secret into a Buffer → parse the
// PKCS#8 DER into an ephemeral *rsa.PrivateKey → call the wrapping
// library → destroy the Buffer and the sealed key. The parsed
// *rsa.PrivateKey is only referenced inside this function's stack frame.
func (b *SoftwareBackend) UnwrapKey(ctx context.Context, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	if wrapped == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "wrapped key material cannot be nil"}
	}
	if params == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "import parameters cannot be nil"}
	}

	b.mu.RLock()
	closed := b.closed
	b.mu.RUnlock()
	if closed {
		return nil, ErrStorageClosed
	}

	return b.unwrapKey(ctx, wrapped)
}

// unwrapKey is UnwrapKey's token-consuming core, without the closed check.
// ImportKey calls it directly rather than calling UnwrapKey, because
// ImportKey already checked b.closed under its own b.mu.Lock(); UnwrapKey's
// closed check takes b.mu.RLock(), and sync.RWMutex is not reentrant, so
// calling UnwrapKey from inside an already-held b.mu.Lock() would deadlock.
func (b *SoftwareBackend) unwrapKey(ctx context.Context, wrapped *backend.WrappedKeyMaterial) ([]byte, error) {
	// Get the import token UUID
	tokenUUID := string(wrapped.ImportToken)
	if tokenUUID == "" {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "import token cannot be empty"}
	}

	// Take the stored wrapping key: unknown, already-consumed, and
	// expired tokens are indistinguishable, and this call owns
	// destroying whatever it took.
	tokenData, err := b.importTokens.Take(tokenUUID)
	if err != nil {
		return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: "invalid or expired import token"}
	}
	defer tokenData.destroy()

	// importtoken.Unwrap refuses wrapped.Algorithm unless it matches
	// tokenData.algorithm -- the algorithm GetImportParameters issued
	// this token for -- before it ever opens the wrapping key's enclave.
	return importtoken.Unwrap(ctx, tokenData.wrappingKey, tokenData.algorithm, wrapped.Algorithm, wrapped.WrappedKey)
}

// ImportKey imports externally generated key material into the backend.
// The key material is unwrapped and then stored based on the key type.
func (b *SoftwareBackend) ImportKey(ctx context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	if attrs == nil {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "key attributes cannot be nil"}
	}
	if wrapped == nil {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "wrapped key material cannot be nil"}
	}

	// Import routes on the family and stores under the identifier a different
	// resolution of it builds, so contradictory attributes write material under
	// an identifier that does not describe it (go-xkms#158).
	if err := requireSingleAlgorithmFamily(attrs); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	// Unwrap the key material. This calls the token-consuming core
	// directly, not the public UnwrapKey, since UnwrapKey's own closed
	// check would re-take b.mu.RLock() while this call already holds
	// b.mu.Lock() -- see unwrapKey's doc comment.
	keyMaterial, err := b.unwrapKey(ctx, wrapped)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to unwrap key material", Err: err}
	}
	// The unwrapped private or symmetric key is a plain heap slice, and the
	// garbage collector neither zeroes it nor promises to reuse the pages
	// promptly. Wipe it on EVERY exit -- success as much as failure -- so its
	// residency is bounded by this call rather than by the collector.
	//
	// Wiping after the import completes is safe because every reachable
	// Backend.Put consumes the value before returning. That is a documented
	// requirement of the interface, not an incidental property of today's
	// backends: storage.Backend.Put states it, and carries the per-engine
	// audit that shows each one satisfies it. A backend added later that
	// retained the caller's slice by reference would make this wipe destroy
	// the stored key, which is why the rule lives on the interface where an
	// implementer will read it.
	defer secure.Wipe(keyMaterial)

	// Parse and store the key based on type
	if attrs.IsSymmetric() {
		// For symmetric keys, the key material is raw bytes
		return b.importSymmetricKey(ctx, attrs, keyMaterial)
	}

	// For asymmetric keys, parse the PKCS8 private key
	return b.importAsymmetricKey(ctx, attrs, keyMaterial)
}

// ExportKey exports a key in wrapped form for secure transport.
func (b *SoftwareBackend) ExportKey(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	// Refused before the sub-backend is chosen: the export below reads the key
	// through the family's store while ID() addresses it through another, so a
	// contradictory descriptor exports a key it does not name (go-xkms#158).
	if err := requireSingleAlgorithmFamily(attrs); err != nil {
		return nil, err
	}

	// Check if backend supports export
	if !b.Capabilities().Export {
		return nil, backend.ErrExportNotSupported
	}

	// Check if key is marked as exportable
	if !attrs.Exportable {
		return nil, backend.ErrKeyNotExportable
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	// Validate algorithm
	if !isValidWrappingAlgorithm(algorithm) {
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: algorithm.String()}
	}

	keyMaterial, err := b.exportableKeyMaterial(ctx, attrs)
	if err != nil {
		return nil, err
	}

	// Generate import parameters for wrapping
	params, err := b.GetImportParameters(ctx, attrs, algorithm)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate import parameters", Err: err}
	}

	// Wrap the key material
	wrapped, err := b.WrapKey(ctx, keyMaterial, params)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to wrap key", Err: err}
	}

	return wrapped, nil
}

// ExportKeyTo exports a key wrapped for dstParams -- the DESTINATION's own
// import parameters -- instead of a wrapping key this backend mints and
// tracks for itself. See backend.ExportBackend.ExportKeyTo.
//
// WrapKey is a pure cryptographic operation over the ImportParameters it is
// given: it reads params.WrappingPublicKey and params.Algorithm and touches
// none of this backend's own state, so wrapping under a caller-supplied
// destination's public key is exactly as sound as wrapping under this
// backend's own self-minted one. That is what makes a real cross-backend
// copy possible: the material this method returns can only be unwrapped by
// whichever backend produced dstParams (go-xkms#154).
func (b *SoftwareBackend) ExportKeyTo(ctx context.Context, attrs *types.KeyAttributes, dstParams *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}
	if dstParams == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "destination import parameters cannot be nil"}
	}

	// Refused before the sub-backend is chosen: see ExportKey's identical
	// guard (go-xkms#158).
	if err := requireSingleAlgorithmFamily(attrs); err != nil {
		return nil, err
	}

	if !b.Capabilities().Export {
		return nil, backend.ErrExportNotSupported
	}
	if !attrs.Exportable {
		return nil, backend.ErrKeyNotExportable
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if !isValidWrappingAlgorithm(dstParams.Algorithm) {
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: dstParams.Algorithm.String()}
	}

	keyMaterial, err := b.exportableKeyMaterial(ctx, attrs)
	if err != nil {
		return nil, err
	}

	wrapped, err := b.WrapKey(ctx, keyMaterial, dstParams)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to wrap key for destination", Err: err}
	}

	return wrapped, nil
}

// exportableKeyMaterial reads attrs' private key material in the shape
// WrapKey expects: raw bytes for a symmetric key, PKCS#8 DER for an
// asymmetric one. It is the common core of ExportKey and ExportKeyTo, which
// differ only in which ImportParameters they wrap the result under.
func (b *SoftwareBackend) exportableKeyMaterial(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error) {
	if attrs.IsSymmetric() {
		key, err := b.symmetricBackend.GetSymmetricKey(ctx, attrs)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to get symmetric key", Err: err}
		}
		raw, err := key.Raw()
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to get raw key material", Err: err}
		}
		return raw, nil
	}

	privateKey, err := b.pkcs8Backend.GetKey(ctx, attrs)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get private key", Err: err}
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to marshal private key", Err: err}
	}
	return der, nil
}

// ExportKeyMaterial returns the raw key material for extractable symmetric keys only.
// This method provides direct access to the plaintext key bytes without wrapping.
//
// Security restrictions:
//   - ONLY works for symmetric keys (AES, ChaCha20, etc.)
//   - Returns ErrAsymmetricKeyExportNotAllowed for asymmetric keys (RSA, ECDSA, Ed25519)
//   - Key must have Exportable=true (equivalent to PKCS#11 CKA_EXTRACTABLE=true)
//   - Returns ErrKeyNotExportable if the key is not marked as exportable
//
// For secure key transport between backends, prefer ExportKey which wraps the material.
func (b *SoftwareBackend) ExportKeyMaterial(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	// The asymmetric refusal below consults IsSymmetric, which a descriptor
	// naming BOTH families satisfies -- so it walks through that guard and
	// reaches the symmetric store holding an identifier ID() resolved from the
	// asymmetric half (go-xkms#158). Placed first for uniformity with the other
	// four routing sites and because it is the more specific diagnosis; either
	// order refuses, because a contradictory descriptor passes the guard.
	if err := requireSingleAlgorithmFamily(attrs); err != nil {
		return nil, err
	}

	// Security check: Reject asymmetric keys
	// Exporting raw asymmetric private key material is a security risk
	if !attrs.IsSymmetric() {
		return nil, backend.ErrAsymmetricKeyExportNotAllowed
	}

	// Check if key is marked as exportable (CKA_EXTRACTABLE equivalent)
	if !attrs.Exportable {
		return nil, backend.ErrKeyNotExportable
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	// Get the symmetric key
	key, err := b.symmetricBackend.GetSymmetricKey(ctx, attrs)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get symmetric key", Err: err}
	}

	// Extract the raw key material
	keyMaterial, err := key.Raw()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get raw key material", Err: err}
	}

	return keyMaterial, nil
}

// importSymmetricKey imports a symmetric key from raw key material
func (b *SoftwareBackend) importSymmetricKey(ctx context.Context, attrs *types.KeyAttributes, keyMaterial []byte) error {
	// Validate key size
	expectedSize := attrs.SymmetricAlgorithm.KeySize() / 8
	if len(keyMaterial) != expectedSize {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("invalid key material size expected %d bytes, got %d", expectedSize, len(keyMaterial))}
	}

	keyID := attrs.ID()

	// Refuse rather than overwrite, for the reason importAsymmetricKey gives
	// (go-xkms#165). The symmetric key provider's own ImportKey already
	// refuses this collision with backend.ErrKeyAlreadyExists; this path stores
	// the bytes itself rather than delegating to it, so it has to refuse the
	// collision itself too.
	if err := b.refuseIfKeyExists(ctx, keyID); err != nil {
		return err
	}

	// Store the raw key material directly (symmetric backend stores raw bytes)
	if err := storage.SaveKey(ctx, b.storage, keyID, keyMaterial); err != nil {
		return &errs.Wrapped{Msg: "failed to store symmetric key", Err: err}
	}

	// The key identifier encodes only partition, store type, CN and algorithm,
	// so anything else about the key -- Exportable in particular -- has to be
	// recorded alongside it or it is lost the moment the attributes are
	// reconstructed. This path stores the bytes itself instead of delegating to
	// the symmetric backend's own ImportKey, so it has to record the metadata
	// itself too; omitting it made every key imported through C_UnwrapKey read
	// back as non-exportable regardless of what the caller requested.
	if err := b.symmetricBackend.SaveKeyMetadata(ctx, keyID, attrs); err != nil {
		// Roll the key blob back, the way importAsymmetricKey does. Returning
		// an error while the bytes stay committed leaves a key that exists
		// under defaults the caller never asked for -- loadKeyMetadata reads a
		// missing record as Exportable=false, Sensitive=true -- and, because
		// the collision check above refuses a second attempt, the orphan
		// blocks its own recovery under the same ID.
		if delErr := storage.DeleteKey(ctx, b.storage, keyID); delErr != nil {
			return &errs.Affix{
				Prefix: "failed to store symmetric key metadata: ",
				Err:    err,
				Suffix: fmt.Sprintf(" (rollback of key %s also failed: %v)", keyID, delErr),
			}
		}
		return &errs.Wrapped{Msg: "failed to store symmetric key metadata", Err: err}
	}

	return nil
}

// importAsymmetricKey imports an asymmetric key from PKCS8-encoded key material
// parsePKCS8ForImport is the parse step of importAsymmetricKey, as a variable
// so a test can hold a reference to the value it returns.
//
// It is a seam for reachability, not for convenience. The parsed key is a
// local that never escapes importAsymmetricKey, which made the zeroization
// below unobservable from outside the function -- and unobservable means
// untested: deleting the `defer zeroizeParsedPrivateKey` line left the entire
// suite green (measured 2026-08-27). Capturing the parsed value lets a test
// assert the real property, that the scalar's storage is erased when the
// function returns, rather than the weaker one that some function was called.
//
// Production always runs x509.ParsePKCS8PrivateKey; only an in-package test
// replaces it, and it restores it on cleanup.
var parsePKCS8ForImport = x509.ParsePKCS8PrivateKey

func (b *SoftwareBackend) importAsymmetricKey(ctx context.Context, attrs *types.KeyAttributes, keyMaterial []byte) error {
	// Parse the PKCS8 private key
	privateKey, err := parsePKCS8ForImport(keyMaterial)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to parse PKCS8 private key", Err: err}
	}
	// Parsing materialises a SECOND copy of the secret -- freshly allocated
	// big.Ints or key bytes, independent of the DER ImportKey wipes -- and this
	// function only ever reads it, to check the key against its declared
	// attributes. What is stored is the DER, never this value, so the parsed
	// copy is discarded here and its residency is bounded rather than left to
	// the collector. What the wipe cannot reach is named in
	// zeroizeParsedPrivateKey's doc comment.
	defer zeroizeParsedPrivateKey(privateKey)

	// Validate the key type matches the attributes
	if err := validateKeyType(privateKey, attrs); err != nil {
		return &errs.Wrapped{Msg: "key type validation failed", Err: err}
	}

	keyID := attrs.ID()

	// An import must never destroy a key that is already there. Generation has
	// always refused this collision; import silently overwrote instead, and for
	// an asymmetric key that loss is unrecoverable -- every certificate issued
	// against the old public key is orphaned and anything the key protected
	// becomes undecryptable (go-xkms#165). Replacing a key is an explicit
	// delete followed by an import, never a side effect of importing.
	if err := b.refuseIfKeyExists(ctx, keyID); err != nil {
		return err
	}

	// Store the PKCS8-encoded key material directly
	if err := storage.SaveKey(ctx, b.storage, keyID, keyMaterial); err != nil {
		return &errs.Wrapped{Msg: "failed to store asymmetric key", Err: err}
	}

	// Write the metadata record alongside it, the way generation does.
	// Without this an imported key has no record at all, and ListKeys — which
	// reads the record for the attributes the identifier cannot express —
	// reports neither the tenant, the exportability, nor the origin of any key
	// that arrived by import. The origin matters most: a consumer that refuses
	// to attest an imported key reads it, and a missing record would answer
	// "unknown" for a key that is definitely imported.
	if err := pkcs8.WriteKeyMetadata(ctx, b.storage, keyID, attrs); err != nil {
		// Roll the key blob back rather than leaving material whose
		// provenance cannot be established.
		if delErr := storage.DeleteKey(ctx, b.storage, keyID); delErr != nil {
			return &errs.Affix{
				Prefix: "failed to store key metadata: ",
				Err:    err,
				Suffix: fmt.Sprintf(" (rollback of key %s also failed: %v)", keyID, delErr),
			}
		}
		return err
	}

	return nil
}

// refuseIfKeyExists returns backend.ErrKeyAlreadyExists when keyID already
// holds key material, and nil when the identifier is free.
//
// Presence is decided by reading the key rather than by storage.KeyExists or
// storage.SaveKeyIfAbsent, because neither is usable across the storage
// engines this backend runs on. Measured on all four:
//
//   - Exists returns true for a key that was never written on the file, pebble
//     and qrdb engines -- every one that reaches the embedded qrdb client --
//     so a KeyExists check refuses every import on them. Only the in-memory
//     engine answers it correctly.
//   - PutIfAbsent fails outright on those same engines with "embedded:
//     TransactionServicer must not be nil", which is also why GenerateKey
//     cannot run against them as constructed.
//
// Get is the one primitive that separates the two states everywhere, though
// not by the same signal: the in-memory engine reports storage.ErrNotFound for
// an absent key, while the qrdb-backed engines report no error and no bytes.
// Treating "no error AND non-empty" as present is therefore the portable test,
// and it is the whole reason this is a read rather than the obvious
// PutIfAbsent. The Exists behaviour is a defect in its own right and is filed
// separately; this function must not wait on it.
//
// ImportKey holds b.mu for the whole call, so the window between this check
// and the write that follows is closed against every other caller of this
// backend. It is not closed against a second process sharing the same storage
// -- the same exposure the symmetric key provider's own ImportKey accepts.
func (b *SoftwareBackend) refuseIfKeyExists(ctx context.Context, keyID string) error {
	existing, err := storage.GetKey(ctx, b.storage, keyID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return &errs.Wrapped{Msg: "failed to check for an existing key", Err: err}
	}
	if len(existing) > 0 {
		return &errs.Detail{Err: backend.ErrKeyAlreadyExists, Detail: keyID}
	}
	return nil
}

// Helper functions

func isValidWrappingAlgorithm(algorithm backend.WrappingAlgorithm) bool {
	switch algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		return true
	default:
		return false
	}
}

func determineKeySpec(attrs *types.KeyAttributes) string {
	if attrs == nil {
		return "UNKNOWN"
	}

	if attrs.IsSymmetric() {
		keySize := attrs.SymmetricAlgorithm.KeySize()
		if keySize > 0 {
			return fmt.Sprintf("AES_%d", keySize)
		}
		return "AES_256" // default
	}

	// Asymmetric keys
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		if attrs.RSAAttributes != nil {
			return fmt.Sprintf("RSA_%d", attrs.RSAAttributes.KeySize)
		}
		return "RSA_2048" // default
	case x509.ECDSA:
		if attrs.ECCAttributes != nil {
			curveName := types.CurveName(attrs.ECCAttributes.Curve)
			switch curveName {
			case "P-256":
				return "ECC_NIST_P256"
			case "P-384":
				return "ECC_NIST_P384"
			case "P-521":
				return "ECC_NIST_P521"
			}
		}
		return "ECC_NIST_P256" // default
	case x509.Ed25519:
		return "ED25519"
	default:
		return "UNKNOWN"
	}
}

// validateKeyType checks parsed key material against the attributes the caller
// declared for it, and refuses the pair when they disagree.
//
// The import path is where a caller-supplied description meets real key
// material, and everything downstream reasons from the description rather than
// from the key: the storage identifier types.KeyAttributes.ID builds, the key
// spec determineKeySpec reports, the algorithm a later operation selects. A key
// stored under a false description poisons every one of them, so each supported
// key type has an arm here and a type no arm recognises is refused.
//
// Until go-xkms#53 only RSA was checked. ECDSA and Ed25519 fell through a
// default arm commented "basic validation is sufficient" -- which validated
// nothing -- so an Ed25519 private key declared as ECDSA-P256 imported
// successfully. Those two are the algorithms the signing policy uses (ed25519
// by default, ECDSA-P256 under FIPS), so the unvalidated pair was the pair that
// mattered.
//
// # The declared curve is NOT compared against the key's own
//
// go-xkms#53 asks for it and it is deliberately absent, because no legitimate
// producer can satisfy the comparison today. PKCS8Backend.ListKeys reconstructs
// attributes from the storage key identifier, which carries no curve, and
// hardcodes P-256 for every ECDSA key. Both CopyKey paths, the migrator and the
// PKCS#11 C_UnwrapKey path all reach this validator through attributes built
// that way, so comparing curves refuses every copy, migrate and unwrap of a
// non-P-256 EC key -- the export succeeds and the import refuses. A check a
// legitimate producer structurally cannot satisfy rejects working paths rather
// than catching wrong ones.
//
// What that leaves open, stated rather than implied: a P-384 key can be
// imported while declaring P-256. That is inert today -- the curve is not part
// of the identifier and Signer recovers it from the DER -- and stops being
// inert the moment anything trusts attrs.ECCAttributes for a decision.
// go-xkms#156 carries the caveat and the ListKeys fix the comparison needs.
//
// The RSA size comparison below is kept because it predates go-xkms#53:
// removing it would delete a control the backend already has. Its nil guard is
// load-bearing for the same reason the curve check is absent -- several
// backends reconstruct KeyAlgorithm with the attribute block left nil.
func validateKeyType(privateKey crypto.PrivateKey, attrs *types.KeyAttributes) error {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		if attrs.KeyAlgorithm != x509.RSA {
			return &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("expected RSA key but attributes specify %s", attrs.KeyAlgorithm)}
		}
		if attrs.RSAAttributes != nil && key.N.BitLen() != attrs.RSAAttributes.KeySize {
			return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("RSA key size mismatch key is %d bits but attributes specify %d", key.N.BitLen(), attrs.RSAAttributes.KeySize)}
		}
	case *ecdsa.PrivateKey:
		if attrs.KeyAlgorithm != x509.ECDSA {
			return &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("expected ECDSA key but attributes specify %s", attrs.KeyAlgorithm)}
		}
	case ed25519.PrivateKey:
		if attrs.KeyAlgorithm != x509.Ed25519 {
			return &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("expected Ed25519 key but attributes specify %s", attrs.KeyAlgorithm)}
		}
	case *ecdh.PrivateKey:
		// X25519 agreement keys are declared by X25519Attributes rather than by
		// KeyAlgorithm, which has no x509 constant for them (see
		// PKCS8Backend.GenerateKey), and x509.ParsePKCS8PrivateKey returns an
		// *ecdh.PrivateKey for them. Without this arm the refusing default
		// below would break a key type the backend supports.
		if attrs.X25519Attributes == nil {
			return &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("expected an ECDH agreement key to declare X25519Attributes but attributes specify %s", attrs.KeyAlgorithm)}
		}
		if key.Curve() != ecdh.X25519() {
			return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "ECDH key is not on curve X25519"}
		}
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, *ecdh.PublicKey:
		return &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: "expected private key but got public key"}
	default:
		// Refusing the unknown case is the point. This validation is the
		// backstop against a key stored under a false algorithm description,
		// and a description no arm above recognises cannot be checked against
		// anything -- so it is rejected, not blessed.
		return &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("unsupported private key type %T", privateKey)}
	}
	return nil
}

// GetTracker returns the AEAD safety tracker from the underlying symmetric backend.
// This allows external code to inspect tracking state and configuration.
func (b *SoftwareBackend) GetTracker() types.AEADSafetyTracker {
	return b.symmetricBackend.GetTracker()
}

// DeriveSharedSecret performs ECDH key agreement between the private key
// identified by attrs and the provided public key.
//
// This method delegates to the underlying PKCS8Backend, which supports:
//   - X25519 keys for fast key agreement
//   - NIST curves (P-256, P-384, P-521) via ECDSA keys
//
// The shared secret is the raw output of ECDH - use a KDF to derive encryption keys.
func (b *SoftwareBackend) DeriveSharedSecret(ctx context.Context, attrs *types.KeyAttributes, publicKey crypto.PublicKey) ([]byte, error) {
	return b.pkcs8Backend.DeriveSharedSecret(ctx, attrs, publicKey)
}

// CanSeal returns true if this backend supports sealing operations.
// Software backend supports sealing via its internal PKCS#8 backend.
func (b *SoftwareBackend) CanSeal() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return false
	}

	return b.pkcs8Backend.CanSeal()
}

// Seal encrypts/protects data using HKDF-derived key and AES-GCM.
// This operation is delegated to the PKCS8 backend.
//
// The sealing process:
//  1. Load the private key specified in opts.KeyAttributes
//  2. Derive a sealing key using HKDF from the private key material
//  3. Encrypt the data using AES-256-GCM with a random nonce
//
// Security Note: This is a software-only sealing mechanism. The private key
// is loaded into memory during the sealing process. For secrets that should
// never touch system memory, use hardware-backed backends (TPM, HSM).
func (b *SoftwareBackend) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	// Delegate to PKCS8 backend which implements the sealing logic
	sealed, err := b.pkcs8Backend.Seal(ctx, data, opts)
	if err != nil {
		return nil, err
	}

	// Update backend type to reflect it came from software backend
	sealed.Backend = types.BackendTypeSoftware

	return sealed, nil
}

// Unseal decrypts/recovers data using HKDF-derived key and AES-GCM.
// This operation is delegated to the PKCS8 backend.
//
// This method accepts sealed data from both Software and PKCS8 backends,
// since Software backend delegates sealing to PKCS8 internally.
//
// Sealed data that is not the software backend's matches
// types.ErrSealedDataAuthentication; everything else is classified by
// PKCS8Backend.Unseal.
func (b *SoftwareBackend) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, &errs.Message{Msg: "sealed data is required"}
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Verify this is a software backend sealed data
	if sealed.Backend != types.BackendTypeSoftware {
		return nil, types.SealedDataAuthenticationError(
			fmt.Sprintf("sealed data was not created by software backend (got %s)", sealed.Backend), nil)
	}

	return b.pkcs8Backend.Unseal(ctx, sealed, opts)
}

// Verify interface compliance at compile time
var _ types.KeyProvider = (*SoftwareBackend)(nil)
var _ types.SymmetricKeyProvider = (*SoftwareBackend)(nil)
var _ types.SymmetricKeyDeriver = (*SoftwareBackend)(nil)
var _ types.SymmetricKeyProviderWithTracking = (*SoftwareBackend)(nil)
var _ types.KeyAgreement = (*SoftwareBackend)(nil)
var _ backend.ImportExportBackend = (*SoftwareBackend)(nil)
var _ types.Sealer = (*SoftwareBackend)(nil)
