// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build pkcs11

package pkcs11

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/miekg/pkcs11"
)

// Note: Backend implements SymmetricBackend interface methods:
// - GenerateSymmetricKey
// - GetSymmetricKey
// - SymmetricEncrypter

// pkcs11SymmetricKey implements types.SymmetricKey for PKCS#11 AES keys.
// The actual key material never leaves the HSM hardware.
type pkcs11SymmetricKey struct {
	algorithm string
	keySize   int
	handle    pkcs11.ObjectHandle
	backend   *Backend
}

// Algorithm returns the symmetric algorithm identifier.
func (k *pkcs11SymmetricKey) Algorithm() string {
	return k.algorithm
}

// KeySize returns the key size in bits.
func (k *pkcs11SymmetricKey) KeySize() int {
	return k.keySize
}

// Raw returns an error because PKCS#11 keys cannot expose raw key material.
// The key material is sealed in the HSM and can only be used through HSM operations.
func (k *pkcs11SymmetricKey) Raw() ([]byte, error) {
	return nil, fmt.Errorf("%w: PKCS#11 symmetric keys do not expose raw key material", backend.ErrNotSupported)
}

// pkcs11SymmetricEncrypter implements types.SymmetricEncrypter for PKCS#11 HSMs.
// All encryption/decryption operations are performed on the HSM hardware.
type pkcs11SymmetricEncrypter struct {
	backend *Backend
	attrs   *types.KeyAttributes
	handle  pkcs11.ObjectHandle
}

// Encrypt encrypts plaintext using the symmetric key on the HSM.
// For AES-GCM, this provides authenticated encryption with additional data support.
func (e *pkcs11SymmetricEncrypter) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	if opts == nil {
		opts = &types.EncryptOptions{}
	}

	// Get key ID for tracking
	label := createKeyID(e.attrs)

	// STEP 1: Check bytes limit
	if e.backend.tracker != nil {
		if err := e.backend.tracker.IncrementBytes(label, int64(len(plaintext))); err != nil {
			return nil, fmt.Errorf("AEAD safety check failed: %w", err)
		}
	}

	// Initialize PKCS#11 context if needed
	if e.backend.p11ctx == nil {
		return nil, fmt.Errorf("PKCS#11 context not initialized")
	}

	// Get token slot
	slots, err := e.backend.p11ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get slot list: %w", err)
	}
	if len(slots) == 0 {
		return nil, ErrTokenNotFound
	}

	slot := slots[0]
	if e.backend.config.Slot != nil {
		slot = uint(*e.backend.config.Slot)
	}

	// Open session
	session, err := e.backend.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session: %w", err)
	}
	defer e.backend.p11ctx.CloseSession(session)

	// Login as user
	// Note: We don't logout because C_Logout affects ALL sessions, not just this one
	if err := e.backend.p11ctx.Login(session, pkcs11.CKU_USER, e.backend.config.PIN); err != nil {
		if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			return nil, fmt.Errorf("failed to login: %w", err)
		}
	}
	// DO NOT LOGOUT - it would logout from all sessions including crypto11's session

	// STEP 2: Generate or use provided nonce
	nonceSize := 12 // Standard GCM nonce size
	var nonce []byte
	if opts.Nonce != nil {
		nonce = opts.Nonce
	} else {
		nonce = make([]byte, nonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %w", err)
		}
	}

	// STEP 3: Check nonce uniqueness BEFORE encryption
	if e.backend.tracker != nil {
		if err := e.backend.tracker.CheckNonce(label, nonce); err != nil {
			return nil, fmt.Errorf("AEAD safety check failed: %w", err)
		}
	}

	// Set up GCM parameters
	// For PKCS#11 AES-GCM, we need to construct CK_GCM_PARAMS
	// Note: Not all HSMs support GCM parameters with AAD
	// We'll use a software-based approach for better compatibility

	// Get the key material (if extractable) or use software encryption
	// Since PKCS#11 keys are typically non-extractable, we'll perform
	// encryption using PKCS#11 C_Encrypt with CKM_AES_GCM mechanism

	// Prepare GCM parameters
	// PKCS#11 NewGCMParams expects tag size in BITS, not bytes
	tagBits := 128 // GCM tag size in bits (16 bytes)
	gcmParams := pkcs11.NewGCMParams(nonce, opts.AdditionalData, tagBits)

	// Find the key handle in THIS session (handles are session-specific)
	// We must find the key in the same session where we'll use it
	// (label already defined above for tracking)
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	if err := e.backend.p11ctx.FindObjectsInit(session, template); err != nil {
		return nil, fmt.Errorf("failed to init object search: %w", err)
	}

	handles, _, err := e.backend.p11ctx.FindObjects(session, 1)
	if err != nil {
		e.backend.p11ctx.FindObjectsFinal(session) // Clean up even on error
		return nil, fmt.Errorf("failed to find objects: %w", err)
	}

	// Must finalize BEFORE starting encryption operation
	if err := e.backend.p11ctx.FindObjectsFinal(session); err != nil {
		return nil, fmt.Errorf("failed to finalize object search: %w", err)
	}

	if len(handles) == 0 {
		return nil, fmt.Errorf("key not found: %s", e.attrs.CN)
	}

	handle := handles[0]

	// Create mechanism with GCM parameters
	mechanism := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcmParams),
	}

	// Initialize encryption
	if err := e.backend.p11ctx.EncryptInit(session, mechanism, handle); err != nil {
		return nil, fmt.Errorf("failed to initialize encryption: %w", err)
	}

	// STEP 4: Perform encryption
	// For GCM, the output will include the ciphertext + tag
	ciphertext, err := e.backend.p11ctx.Encrypt(session, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// GCM appends the tag to the ciphertext
	// Extract tag (last tagBytes bytes)
	// For GCM, even with empty plaintext, we should get at least the tag (16 bytes)
	tagBytes := tagBits / 8 // Convert bits to bytes for slicing
	if len(ciphertext) < tagBytes {
		return nil, fmt.Errorf("ciphertext too short: got %d bytes, expected at least %d bytes (tag size)", len(ciphertext), tagBytes)
	}

	tag := ciphertext[len(ciphertext)-tagBytes:]
	ciphertextOnly := ciphertext[:len(ciphertext)-tagBytes]

	// STEP 5: Record nonce after successful encryption
	if e.backend.tracker != nil {
		if err := e.backend.tracker.RecordNonce(label, nonce); err != nil {
			fmt.Printf("warning: failed to record nonce: %v\n", err)
		}
	}

	return &types.EncryptedData{
		Ciphertext: ciphertextOnly,
		Nonce:      nonce,
		Tag:        tag,
		Algorithm:  string(e.attrs.SymmetricAlgorithm),
	}, nil
}

// Decrypt decrypts ciphertext using the symmetric key on the HSM.
// For AES-GCM, this verifies authentication before decrypting.
func (e *pkcs11SymmetricEncrypter) Decrypt(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	if opts == nil {
		opts = &types.DecryptOptions{}
	}

	// Initialize PKCS#11 context if needed
	if e.backend.p11ctx == nil {
		return nil, fmt.Errorf("PKCS#11 context not initialized")
	}

	// Get token slot
	slots, err := e.backend.p11ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get slot list: %w", err)
	}
	if len(slots) == 0 {
		return nil, ErrTokenNotFound
	}

	slot := slots[0]
	if e.backend.config.Slot != nil {
		slot = uint(*e.backend.config.Slot)
	}

	// Open session
	session, err := e.backend.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session: %w", err)
	}
	defer e.backend.p11ctx.CloseSession(session)

	// Login as user
	// Note: We don't logout because C_Logout affects ALL sessions, not just this one
	if err := e.backend.p11ctx.Login(session, pkcs11.CKU_USER, e.backend.config.PIN); err != nil {
		if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			return nil, fmt.Errorf("failed to login: %w", err)
		}
	}
	// DO NOT LOGOUT - it would logout from all sessions including crypto11's session

	// Prepare GCM parameters for decryption
	// PKCS#11 NewGCMParams expects tag size in BITS, not bytes
	tagBits := len(data.Tag) * 8 // Convert bytes to bits for PKCS#11
	gcmParams := pkcs11.NewGCMParams(data.Nonce, opts.AdditionalData, tagBits)

	// Find the key handle in THIS session (handles are session-specific)
	// We must find the key in the same session where we'll use it
	label := createKeyID(e.attrs)
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	if err := e.backend.p11ctx.FindObjectsInit(session, template); err != nil {
		return nil, fmt.Errorf("failed to init object search: %w", err)
	}

	handles, _, err := e.backend.p11ctx.FindObjects(session, 1)
	if err != nil {
		e.backend.p11ctx.FindObjectsFinal(session) // Clean up even on error
		return nil, fmt.Errorf("failed to find objects: %w", err)
	}

	// Must finalize BEFORE starting decryption operation
	if err := e.backend.p11ctx.FindObjectsFinal(session); err != nil {
		return nil, fmt.Errorf("failed to finalize object search: %w", err)
	}

	if len(handles) == 0 {
		return nil, fmt.Errorf("key not found: %s", e.attrs.CN)
	}

	handle := handles[0]

	// Create mechanism with GCM parameters
	mechanism := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcmParams),
	}

	// Initialize decryption
	if err := e.backend.p11ctx.DecryptInit(session, mechanism, handle); err != nil {
		return nil, fmt.Errorf("failed to initialize decryption: %w", err)
	}

	// Reconstruct full ciphertext with tag appended
	fullCiphertext := append(data.Ciphertext, data.Tag...)

	// Decrypt the data
	plaintext, err := e.backend.p11ctx.Decrypt(session, fullCiphertext)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (authentication error): %w", err)
	}

	return plaintext, nil
}

// GenerateSymmetricKey generates a new AES symmetric key on the HSM.
// The key material never leaves the hardware security module.
func (b *Backend) GenerateSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.ctx == nil {
		return nil, ErrNotInitialized
	}

	if err := attrs.Validate(); err != nil {
		return nil, fmt.Errorf("invalid attributes: %w", err)
	}

	if !attrs.IsSymmetric() {
		return nil, fmt.Errorf("%w: attributes specify asymmetric algorithm %s", backend.ErrInvalidAlgorithm, attrs.KeyAlgorithm)
	}

	// Get key size from attributes
	keySize := attrs.SymmetricAlgorithm.KeySize()
	if keySize != 128 && keySize != 192 && keySize != 256 {
		return nil, fmt.Errorf("%w: AES key size %d bits (only 128, 192, and 256 are supported)", backend.ErrInvalidAlgorithm, keySize)
	}

	// Generate the secret key on the HSM
	handle, err := b.GenerateSecretKey(attrs, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate symmetric key: %w", err)
	}

	// Initialize AEAD tracking options after successful key generation
	keyID := createKeyID(attrs)
	if b.tracker != nil {
		aeadOpts := types.DefaultAEADOptions()
		if err := b.tracker.SetAEADOptions(keyID, aeadOpts); err != nil {
			fmt.Printf("Warning: failed to set AEAD options: %v\n", err)
		}
	}

	return &pkcs11SymmetricKey{
		algorithm: attrs.KeyAlgorithm.String(),
		keySize:   keySize,
		handle:    handle,
		backend:   b,
	}, nil
}

// GetSymmetricKey retrieves an existing symmetric key from the HSM.
func (b *Backend) GetSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.ctx == nil {
		return nil, ErrNotInitialized
	}

	if err := attrs.Validate(); err != nil {
		return nil, fmt.Errorf("invalid attributes: %w", err)
	}

	if !attrs.IsSymmetric() {
		return nil, fmt.Errorf("%w: attributes specify asymmetric algorithm %s", backend.ErrInvalidAlgorithm, attrs.KeyAlgorithm)
	}

	// Find the secret key on the HSM
	handle, err := b.FindSecretKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to find symmetric key: %w", err)
	}

	keySize := attrs.SymmetricAlgorithm.KeySize()
	if keySize == 0 {
		return nil, fmt.Errorf("%w: cannot determine key size for algorithm %s", backend.ErrInvalidAlgorithm, attrs.SymmetricAlgorithm)
	}

	return &pkcs11SymmetricKey{
		algorithm: string(attrs.SymmetricAlgorithm),
		keySize:   keySize,
		handle:    handle,
		backend:   b,
	}, nil
}

// SymmetricEncrypter returns a SymmetricEncrypter for the specified key.
// This allows encryption/decryption operations without exposing key material.
func (b *Backend) SymmetricEncrypter(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	// Get the symmetric key to ensure it exists and get the handle
	key, err := b.GetSymmetricKey(attrs)
	if err != nil {
		return nil, err
	}

	// Type assert to get the PKCS#11-specific key
	pkcs11Key, ok := key.(*pkcs11SymmetricKey)
	if !ok {
		return nil, fmt.Errorf("unexpected key type")
	}

	return &pkcs11SymmetricEncrypter{
		backend: b,
		attrs:   attrs,
		handle:  pkcs11Key.handle,
	}, nil
}

// softwareEncrypter is a fallback software-based encrypter when PKCS#11
// operations are not available or fail. This should only be used for testing.
type softwareEncrypter struct {
	key   []byte
	attrs *types.KeyAttributes
}

// Encrypt implements software-based AES-GCM encryption.
func (e *softwareEncrypter) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	if opts == nil {
		opts = &types.EncryptOptions{}
	}

	// Create AES cipher
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate or use provided nonce
	var nonce []byte
	if opts.Nonce != nil {
		nonce = opts.Nonce
	} else {
		nonce = make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %w", err)
		}
	}

	// Encrypt with authentication
	ciphertext := gcm.Seal(nil, nonce, plaintext, opts.AdditionalData)

	// GCM appends the tag to ciphertext, extract it
	tagSize := gcm.Overhead()
	tag := ciphertext[len(ciphertext)-tagSize:]
	ciphertextOnly := ciphertext[:len(ciphertext)-tagSize]

	return &types.EncryptedData{
		Ciphertext: ciphertextOnly,
		Nonce:      nonce,
		Tag:        tag,
		Algorithm:  string(e.attrs.SymmetricAlgorithm),
	}, nil
}

// Decrypt implements software-based AES-GCM decryption.
func (e *softwareEncrypter) Decrypt(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	if opts == nil {
		opts = &types.DecryptOptions{}
	}

	// Create AES cipher
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Reconstruct ciphertext with tag (GCM expects tag appended)
	fullCiphertext := append(data.Ciphertext, data.Tag...)

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, data.Nonce, fullCiphertext, opts.AdditionalData)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (authentication error): %w", err)
	}

	return plaintext, nil
}
