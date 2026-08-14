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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
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

	// Import/export state
	importTokens map[string]*importTokenData // Map of import token UUID to wrapping key data
	importMu     sync.RWMutex                // Separate mutex for import token operations
}

// importTokenData holds the ephemeral wrapping key pair for an
// in-progress import ceremony.
//
// privateKey is the PKCS#8 DER of the RSA wrapping private key, sealed
// inside a *secure.Secret. Every consumer opens this, parses the DER
// inside a Buffer, performs its crypto in that scope, and destroys the
// Buffer before returning — the plaintext private key never outlives a
// single stack frame.
//
// publicKey is kept in a plain pointer because RSA public keys are
// non-sensitive and callers need cheap repeated access (e.g., to
// populate ImportParameters).
type importTokenData struct {
	privateKey *secure.Secret
	publicKey  *rsa.PublicKey
	algorithm  backend.WrappingAlgorithm
	expiresAt  time.Time
	keySpec    string
}

// destroy wipes the enclave holding the wrapping private key. Safe to
// call on a nil receiver. Invoked when a token expires or on backend
// Close so the 24-hour-TTL material doesn't linger across shutdowns.
func (t *importTokenData) destroy() {
	if t == nil {
		return
	}
	if t.privateKey != nil {
		t.privateKey.Destroy()
		t.privateKey = nil
	}
	// publicKey is non-sensitive; dropping the reference is sufficient.
	t.publicKey = nil
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
		importTokens:     make(map[string]*importTokenData),
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
	}
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
	b.importMu.Lock()
	for _, td := range b.importTokens {
		td.destroy()
	}
	b.importTokens = nil
	b.importMu.Unlock()

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
// For the software backend, we generate a 2048-bit RSA key pair, marshal
// the private key into PKCS#8 DER, and seal the DER bytes into a
// *secure.Secret. Only the public key pointer is retained in plaintext.
// The import token is a UUID that identifies this wrapping key pair.
// The ceremony expires in 24 hours; on expiry (or on Close), the
// enclave is destroyed.
func (b *SoftwareBackend) GetImportParameters(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	b.importMu.Lock()
	defer b.importMu.Unlock()

	if b.closed {
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

	// Marshal the private key into PKCS#8 DER and seal it. We wipe the
	// intermediate slice after sealing as belt-and-suspenders; NewSecret
	// also wipes its input.
	der, marshalErr := x509.MarshalPKCS8PrivateKey(privateKey)
	if marshalErr != nil {
		return nil, &errs.Wrapped{Msg: "failed to marshal wrapping key", Err: marshalErr}
	}
	publicKey := &privateKey.PublicKey
	// Best-effort: zero out the live *rsa.PrivateKey fields so it
	// doesn't sit on the heap next to our enclaved copy. crypto/rsa's
	// PrecomputedValues aren't safely zeroable without invalidating
	// the key, so we settle for dropping the reference. After this
	// function returns, GC is the only mechanism for reclaiming the
	// privateKey heap allocation; the authoritative copy of the key
	// material now lives inside the enclave.
	_ = privateKey
	sealed, sealErr := secure.NewSecret(der)
	if sealErr != nil {
		return nil, &errs.Wrapped{Msg: "failed to seal wrapping key", Err: sealErr}
	}
	// NewSecret wipes `der` on entry; this is defense in depth.
	secure.Wipe(der)

	// Generate import token (UUID)
	tokenUUID := uuid.New().String()
	importToken := []byte(tokenUUID)

	// Set expiration to 24 hours from now
	expiresAt := time.Now().Add(24 * time.Hour)

	// Determine key spec based on key attributes
	keySpec := determineKeySpec(attrs)

	// Store the sealed private key and metadata.
	b.importTokens[tokenUUID] = &importTokenData{
		privateKey: sealed,
		publicKey:  publicKey,
		algorithm:  algorithm,
		expiresAt:  expiresAt,
		keySpec:    keySpec,
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
// Flow: look up the token → open the Secret into a Buffer → parse the
// PKCS#8 DER into an ephemeral *rsa.PrivateKey → call the wrapping
// library → destroy the Buffer. The parsed *rsa.PrivateKey is only
// referenced inside this function's stack frame.
func (b *SoftwareBackend) UnwrapKey(ctx context.Context, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	if wrapped == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "wrapped key material cannot be nil"}
	}
	if params == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "import parameters cannot be nil"}
	}

	b.importMu.RLock()
	defer b.importMu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	// Get the import token UUID
	tokenUUID := string(wrapped.ImportToken)
	if tokenUUID == "" {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "import token cannot be empty"}
	}

	// Look up the stored private key
	tokenData, ok := b.importTokens[tokenUUID]
	if !ok {
		return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: "invalid import token"}
	}

	// Check expiration
	if time.Now().After(tokenData.expiresAt) {
		return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: "import token has expired"}
	}

	// Verify algorithm matches
	if wrapped.Algorithm != tokenData.algorithm {
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("wrapped with %s but token expects %s", wrapped.Algorithm, tokenData.algorithm)}
	}

	// Open the enclaved wrapping private key into a Buffer, parse the
	// DER, run the unwrap, destroy the Buffer.
	privBuf, openErr := tokenData.privateKey.Open()
	if openErr != nil {
		return nil, &errs.Wrapped{Msg: "failed to open wrapping key enclave", Err: openErr}
	}
	defer privBuf.Destroy()

	parsed, parseErr := x509.ParsePKCS8PrivateKey(privBuf.Bytes())
	if parseErr != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse wrapping key", Err: parseErr}
	}
	privateKey, rsaOK := parsed.(*rsa.PrivateKey)
	if !rsaOK {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: "wrapping key is not RSA"}
	}

	var unwrapped []byte
	var err error

	// Unwrap using the appropriate algorithm
	switch wrapped.Algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1, backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		unwrapped, err = wrapping.UnwrapRSAOAEP(wrapped.WrappedKey, privateKey, wrapped.Algorithm)
	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		unwrapped, err = wrapping.UnwrapRSAAES(wrapped.WrappedKey, privateKey, wrapped.Algorithm)
	default:
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: wrapped.Algorithm.String()}
	}

	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to unwrap key", Err: err}
	}

	return unwrapped, nil
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

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	// Get the import parameters to unwrap the key
	tokenUUID := string(wrapped.ImportToken)
	if tokenUUID == "" {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "import token cannot be empty"}
	}

	// Look up the stored token metadata (with read lock). The private
	// key itself stays inside its enclave — UnwrapKey is the only
	// codepath that opens it.
	b.importMu.RLock()
	tokenData, ok := b.importTokens[tokenUUID]
	b.importMu.RUnlock()

	if !ok {
		return &errs.Detail{Err: backend.ErrKeyNotFound, Detail: "invalid import token"}
	}

	// Check expiration
	if time.Now().After(tokenData.expiresAt) {
		return &errs.Detail{Err: backend.ErrKeyNotFound, Detail: "import token has expired"}
	}

	// Create import parameters for unwrapping. The public key is
	// non-sensitive so we expose it directly.
	params := &backend.ImportParameters{
		WrappingPublicKey: tokenData.publicKey,
		ImportToken:       wrapped.ImportToken,
		Algorithm:         tokenData.algorithm,
		ExpiresAt:         &tokenData.expiresAt,
		KeySpec:           tokenData.keySpec,
	}

	// Unwrap the key material
	keyMaterial, err := b.UnwrapKey(ctx, wrapped, params)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to unwrap key material", Err: err}
	}

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

	// Get the key material
	var keyMaterial []byte
	var err error

	if attrs.IsSymmetric() {
		// Get symmetric key
		key, err := b.symmetricBackend.GetSymmetricKey(ctx, attrs)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to get symmetric key", Err: err}
		}
		keyMaterial, err = key.Raw()
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to get raw key material", Err: err}
		}
	} else {
		// Get asymmetric key and marshal to PKCS8
		privateKey, err := b.pkcs8Backend.GetKey(ctx, attrs)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to get private key", Err: err}
		}
		keyMaterial, err = x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to marshal private key", Err: err}
		}
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

	// Store the raw key material directly (symmetric backend stores raw bytes)
	keyID := attrs.ID()
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
		return &errs.Wrapped{Msg: "failed to store symmetric key metadata", Err: err}
	}

	return nil
}

// importAsymmetricKey imports an asymmetric key from PKCS8-encoded key material
func (b *SoftwareBackend) importAsymmetricKey(ctx context.Context, attrs *types.KeyAttributes, keyMaterial []byte) error {
	// Parse the PKCS8 private key
	privateKey, err := x509.ParsePKCS8PrivateKey(keyMaterial)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to parse PKCS8 private key", Err: err}
	}

	// Validate the key type matches the attributes
	if err := validateKeyType(privateKey, attrs); err != nil {
		return &errs.Wrapped{Msg: "key type validation failed", Err: err}
	}

	// Store the PKCS8-encoded key material directly
	keyID := attrs.ID()
	if err := storage.SaveKey(ctx, b.storage, keyID, keyMaterial); err != nil {
		return &errs.Wrapped{Msg: "failed to store asymmetric key", Err: err}
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

func validateKeyType(privateKey crypto.PrivateKey, attrs *types.KeyAttributes) error {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		if attrs.KeyAlgorithm != x509.RSA {
			return &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("expected RSA key but attributes specify %s", attrs.KeyAlgorithm)}
		}
		if attrs.RSAAttributes != nil && key.N.BitLen() != attrs.RSAAttributes.KeySize {
			return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("RSA key size mismatch key is %d bits but attributes specify %d", key.N.BitLen(), attrs.RSAAttributes.KeySize)}
		}
	case *rsa.PublicKey:
		return &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: "expected private key but got public key"}
	default:
		// For other key types (ECDSA, Ed25519), basic validation is sufficient
		// More detailed validation can be added if needed
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
func (b *SoftwareBackend) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, &errs.Message{Msg: "sealed data is required"}
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	// Verify this is a software backend sealed data
	if sealed.Backend != types.BackendTypeSoftware {
		return nil, &errs.Message{Msg: fmt.Sprintf("sealed data was not created by software backend (got %s)", sealed.Backend)}
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
