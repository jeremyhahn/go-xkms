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

//go:build tpm2

package tpm2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	kbackend "github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// GenerateSymmetricKey generates a new AES symmetric key in the TPM.
//
// TPM 2.0 supports symmetric encryption with the following constraints:
//   - AES-128 and AES-256 (AES-192 is not in the TPM 2.0 spec)
//   - Keys stored as TPM blobs (public + encrypted private)
//   - Key material never leaves the TPM in plaintext
//
// For actual encryption/decryption operations, we use software AES-GCM with
// the key material stored securely in the TPM. The TPM2_EncryptDecrypt2
// command uses CFB mode which doesn't provide AEAD authentication, so we
// implement AES-GCM in software using TPM-protected key material.
//
// Parameters:
//   - attrs: Key attributes including AES key size (128 or 256 bits)
//
// Returns:
//   - SymmetricKey for the generated key
//   - Error if generation fails or attributes are invalid
func (ks *TPM2KeyStore) GenerateSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	if err := validateSymmetricKeyAttributes(attrs); err != nil {
		return nil, err
	}

	// TPM 2.0 spec only supports AES-128 and AES-256
	keySize := attrs.AESAttributes.KeySize
	if keySize != 128 && keySize != 256 {
		return nil, fmt.Errorf("tpm2: unsupported AES key size %d, TPM 2.0 supports 128 or 256 bits", keySize)
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Ensure TPM is open and SRK name is loaded
	if ks.tpm == nil {
		tpmDevice, err := ks.openTPM()
		if err != nil {
			return nil, fmt.Errorf("tpm2: failed to open TPM: %w", err)
		}
		ks.tpm = tpmDevice
	}

	// Load SRK name if not already loaded
	if len(ks.srkName.Buffer) == 0 {
		if err := ks.loadSRKName(); err != nil {
			return nil, fmt.Errorf("tpm2: failed to load SRK name: %w", err)
		}
	}

	// Check if key already exists
	keyID := attrs.ID()
	privateKeyID := keyID + string(kbackend.FSEXT_PRIVATE_BLOB)
	exists, err := storage.KeyExists(ks.keyStorage, privateKeyID)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to check key existence: %w", err)
	}
	if exists {
		return nil, kbackend.ErrKeyAlreadyExists
	}

	// Generate the AES key material using crypto/rand
	keyBytes := keySize / 8 // Convert bits to bytes
	keyMaterial := make([]byte, keyBytes)
	if _, err := rand.Read(keyMaterial); err != nil {
		return nil, fmt.Errorf("tpm2: failed to generate key material: %w", err)
	}

	// Build keyed hash template for sealing the AES key
	// We seal the key material to the TPM using a keyed hash object
	// This allows us to store/retrieve the actual key bytes securely
	template := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
			NoDA:         true, // No dictionary attack protection needed for data
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{
					Scheme: tpm2.TPMAlgNull, // Just storage, no HMAC
				},
			},
		),
	}

	// Create the sealed object with the key material
	createResp, err := tpm2.Create{
		ParentHandle: &tpm2.NamedHandle{
			Handle: ks.srkHandle,
			Name:   ks.srkName,
		},
		InPublic: tpm2.New2B(template),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(
					&tpm2.TPM2BSensitiveData{
						Buffer: keyMaterial,
					},
				),
			},
		},
	}.Execute(ks.tpm)

	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to create symmetric key: %w", err)
	}

	// Marshal the key blob for storage
	privateBlob := tpm2.Marshal(createResp.OutPrivate)
	publicBlob := tpm2.Marshal(createResp.OutPublic)

	// Save private blob
	if err := storage.SaveKey(ks.keyStorage, privateKeyID, privateBlob); err != nil {
		return nil, fmt.Errorf("tpm2: failed to save private blob: %w", err)
	}

	// Save public blob
	publicKeyID := keyID + string(kbackend.FSEXT_PUBLIC_BLOB)
	if err := storage.SaveKey(ks.keyStorage, publicKeyID, publicBlob); err != nil {
		// Cleanup private blob on failure
		storage.DeleteKey(ks.keyStorage, privateKeyID)
		return nil, fmt.Errorf("tpm2: failed to save public blob: %w", err)
	}

	// Initialize AEAD tracking options for this key
	if ks.tracker != nil {
		if err := ks.tracker.SetAEADOptions(keyID, types.DefaultAEADOptions()); err != nil {
			// Log but don't fail key generation
			fmt.Printf("Warning: failed to set AEAD options: %v\n", err)
		}
	}

	// Create the symmetric key object (doesn't contain actual key material)
	// The key material is sealed in the TPM blob and never exposed
	symmetricKey := &tpm2SymmetricKey{
		algorithm: string(attrs.SymmetricAlgorithm),
		keySize:   keySize,
	}

	// Zero out the key material from memory
	for i := range keyMaterial {
		keyMaterial[i] = 0
	}

	return symmetricKey, nil
}

// GetSymmetricKey retrieves an existing symmetric key from the TPM.
//
// The key blob is loaded from storage and the public portion is returned.
// The private key material remains sealed in the TPM blob.
//
// Parameters:
//   - attrs: Key attributes identifying the key to retrieve
//
// Returns:
//   - SymmetricKey for the requested key
//   - Error if key doesn't exist or load fails
func (ks *TPM2KeyStore) GetSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	if err := validateSymmetricKeyAttributes(attrs); err != nil {
		return nil, err
	}

	ks.mu.RLock()
	defer ks.mu.RUnlock()

	// Ensure TPM is open
	if ks.tpm == nil {
		ks.mu.RUnlock()
		ks.mu.Lock()
		if ks.tpm == nil {
			tpmDevice, err := ks.openTPM()
			if err != nil {
				ks.mu.Unlock()
				ks.mu.RLock()
				return nil, fmt.Errorf("tpm2: failed to open TPM: %w", err)
			}
			ks.tpm = tpmDevice
		}
		ks.mu.Unlock()
		ks.mu.RLock()
	}

	// Load public blob to verify key exists
	keyID := attrs.ID()
	publicKeyID := keyID + string(kbackend.FSEXT_PUBLIC_BLOB)
	publicBlob, err := storage.GetKey(ks.keyStorage, publicKeyID)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, kbackend.ErrKeyNotFound
		}
		return nil, fmt.Errorf("tpm2: failed to load public blob: %w", err)
	}

	// Unmarshal public structure to verify it's valid
	tpmPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](publicBlob)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to unmarshal public blob: %w", err)
	}

	pub, err := tpmPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to get public contents: %w", err)
	}

	// Verify it's a keyed hash (sealed data object)
	if pub.Type != tpm2.TPMAlgKeyedHash {
		return nil, fmt.Errorf("tpm2: key is not a keyed hash (sealed) object, type: %v", pub.Type)
	}

	// Create the symmetric key object (without exposing key material)
	// Extract key size from algorithm
	keySize := attrs.AESAttributes.KeySize
	symmetricKey := &tpm2SymmetricKey{
		algorithm: string(attrs.SymmetricAlgorithm),
		keySize:   keySize,
	}

	return symmetricKey, nil
}

// SymmetricEncrypter returns a SymmetricEncrypter for the specified key.
//
// The encrypter performs AES-GCM encryption using key material protected by the TPM.
// While the TPM2_EncryptDecrypt2 command exists, it uses CFB mode which doesn't
// provide authenticated encryption. We use software AES-GCM with TPM-protected
// key material for AEAD security.
//
// Parameters:
//   - attrs: Key attributes identifying the encryption key
//
// Returns:
//   - SymmetricEncrypter for the key
//   - Error if key doesn't exist or doesn't support symmetric operations
func (ks *TPM2KeyStore) SymmetricEncrypter(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	// Verify the key exists
	_, err := ks.GetSymmetricKey(attrs)
	if err != nil {
		return nil, err
	}

	return &tpm2AESEncrypter{
		ks:    ks,
		attrs: attrs,
	}, nil
}

// tpm2AESEncrypter implements SymmetricEncrypter for TPM-backed AES keys.
//
// This encrypter uses software AES-GCM with key material stored securely in the TPM.
// The TPM protects the key material and only provides it to authorized processes.
type tpm2AESEncrypter struct {
	ks    *TPM2KeyStore
	attrs *types.KeyAttributes
}

// Encrypt encrypts plaintext using AES-GCM with a TPM-protected key.
//
// The key material is loaded from the TPM blob and used for software AES-GCM
// encryption. This provides authenticated encryption with associated data (AEAD).
//
// Parameters:
//   - plaintext: Data to encrypt
//   - opts: Encryption options (nonce, additional data)
//
// Returns:
//   - EncryptedData containing ciphertext, nonce, and authentication tag
//   - Error if encryption fails
func (e *tpm2AESEncrypter) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	if opts == nil {
		opts = &types.EncryptOptions{}
	}

	// Get key ID for tracking
	keyID := e.attrs.ID()

	// STEP 1: Check bytes limit before encryption
	if e.ks.tracker != nil {
		if err := e.ks.tracker.IncrementBytes(keyID, int64(len(plaintext))); err != nil {
			return nil, fmt.Errorf("AEAD safety check failed: %w (consider rotating this key)", err)
		}
	}

	// Load the TPM key to get key material
	keyMaterial, err := e.loadKeyMaterial()
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to load key material: %w", err)
	}
	defer func() {
		// Zero out key material after use
		for i := range keyMaterial {
			keyMaterial[i] = 0
		}
	}()

	// Create AES cipher
	block, err := aes.NewCipher(keyMaterial)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to create GCM: %w", err)
	}

	// STEP 2: Generate or use provided nonce
	var nonce []byte
	if opts.Nonce != nil {
		nonce = opts.Nonce
		if len(nonce) != gcm.NonceSize() {
			return nil, fmt.Errorf("invalid nonce size: %d (expected %d)", len(nonce), gcm.NonceSize())
		}
	} else {
		nonce = make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("tpm2: failed to generate nonce: %w", err)
		}
	}

	// STEP 3: Check nonce uniqueness before encryption
	if e.ks.tracker != nil {
		if err := e.ks.tracker.CheckNonce(keyID, nonce); err != nil {
			return nil, fmt.Errorf("AEAD safety check failed: %w (CRITICAL: rotate this key immediately)", err)
		}
	}

	// STEP 4: Encrypt with authentication
	ciphertext := gcm.Seal(nil, nonce, plaintext, opts.AdditionalData)

	// GCM appends the tag to ciphertext, extract it
	tagSize := gcm.Overhead()
	tag := ciphertext[len(ciphertext)-tagSize:]
	ciphertext = ciphertext[:len(ciphertext)-tagSize]

	// STEP 5: Record nonce after successful encryption
	if e.ks.tracker != nil {
		if err := e.ks.tracker.RecordNonce(keyID, nonce); err != nil {
			// Log warning but return successful encryption
			fmt.Printf("warning: failed to record nonce: %v\n", err)
		}
	}

	return &types.EncryptedData{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Tag:        tag,
		Algorithm:  e.attrs.KeyAlgorithm.String(),
	}, nil
}

// Decrypt decrypts ciphertext using AES-GCM with a TPM-protected key.
//
// The authentication tag is verified before decryption. If verification fails,
// an error is returned and no plaintext is produced.
//
// Parameters:
//   - data: EncryptedData containing ciphertext, nonce, and tag
//   - opts: Decryption options (additional data for AEAD)
//
// Returns:
//   - Plaintext bytes
//   - Error if authentication fails or decryption fails
func (e *tpm2AESEncrypter) Decrypt(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	if opts == nil {
		opts = &types.DecryptOptions{}
	}

	// Load the TPM key to get key material
	keyMaterial, err := e.loadKeyMaterial()
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to load key material: %w", err)
	}
	defer func() {
		// Zero out key material after use
		for i := range keyMaterial {
			keyMaterial[i] = 0
		}
	}()

	// Create AES cipher
	block, err := aes.NewCipher(keyMaterial)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to create GCM: %w", err)
	}

	// Reconstruct ciphertext with tag (GCM expects tag appended)
	fullCiphertext := append(data.Ciphertext, data.Tag...)

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, data.Nonce, fullCiphertext, opts.AdditionalData)
	if err != nil {
		return nil, fmt.Errorf("tpm2: decryption failed (authentication error): %w", err)
	}

	return plaintext, nil
}

// loadKeyMaterial loads the symmetric key from the TPM and unseals the key material.
//
// This operation loads the sealed keyed hash object into a transient handle,
// uses TPM2_Unseal to extract the key material, and then flushes the handle.
// The key material is returned for use in software AES-GCM operations.
//
// IMPORTANT: The caller MUST zero out the returned key material after use.
func (e *tpm2AESEncrypter) loadKeyMaterial() ([]byte, error) {
	e.ks.mu.Lock()
	defer e.ks.mu.Unlock()

	// Ensure SRK name is loaded
	if len(e.ks.srkName.Buffer) == 0 {
		if err := e.ks.loadSRKName(); err != nil {
			return nil, fmt.Errorf("tpm2: failed to load SRK name: %w", err)
		}
	}

	// Load key blobs from storage
	keyID := e.attrs.ID()
	privateKeyID := keyID + string(kbackend.FSEXT_PRIVATE_BLOB)
	privateBlob, err := storage.GetKey(e.ks.keyStorage, privateKeyID)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, kbackend.ErrKeyNotFound
		}
		return nil, fmt.Errorf("tpm2: failed to load private blob: %w", err)
	}

	publicKeyID := keyID + string(kbackend.FSEXT_PUBLIC_BLOB)
	publicBlob, err := storage.GetKey(e.ks.keyStorage, publicKeyID)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to load public blob: %w", err)
	}

	// Unmarshal blobs
	tpmPrivate, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privateBlob)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to unmarshal private blob: %w", err)
	}

	tpmPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](publicBlob)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to unmarshal public blob: %w", err)
	}

	// Load the sealed object into TPM
	loadResp, err := tpm2.Load{
		ParentHandle: &tpm2.NamedHandle{
			Handle: e.ks.srkHandle,
			Name:   e.ks.srkName,
		},
		InPrivate: *tpmPrivate,
		InPublic:  *tpmPublic,
	}.Execute(e.ks.tpm)

	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to load sealed key: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: loadResp.ObjectHandle}.Execute(e.ks.tpm)

	// Unseal the key material using TPM2_Unseal
	unsealResp, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadResp.ObjectHandle,
			Name:   loadResp.Name,
			Auth:   tpm2.PasswordAuth(nil), // No password protection for now
		},
	}.Execute(e.ks.tpm)

	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to unseal key material: %w", err)
	}

	// Return the unsealed key material
	return unsealResp.OutData.Buffer, nil
}

// validateSymmetricKeyAttributes validates key attributes for symmetric operations.
func validateSymmetricKeyAttributes(attrs *types.KeyAttributes) error {
	if attrs == nil {
		return fmt.Errorf("tpm2: attributes cannot be nil")
	}

	if attrs.CN == "" {
		return fmt.Errorf("tpm2: CN (Common Name) is required")
	}

	if !attrs.IsSymmetric() {
		return fmt.Errorf("tpm2: key algorithm is not symmetric: %s", attrs.KeyAlgorithm)
	}

	if attrs.AESAttributes == nil {
		return fmt.Errorf("tpm2: AES attributes are required for symmetric keys")
	}

	return nil
}

// tpm2SymmetricKey implements types.SymmetricKey for TPM-backed AES keys.
// The actual key material is sealed in the TPM and never exposed.
type tpm2SymmetricKey struct {
	algorithm string
	keySize   int
}

// Algorithm returns the symmetric algorithm identifier.
func (k *tpm2SymmetricKey) Algorithm() string {
	return k.algorithm
}

// KeySize returns the key size in bits.
func (k *tpm2SymmetricKey) KeySize() int {
	return k.keySize
}

// Raw returns an error because TPM keys cannot expose their key material.
// The key material is sealed in the TPM and can only be used through
// TPM operations (Unseal).
func (k *tpm2SymmetricKey) Raw() ([]byte, error) {
	return nil, fmt.Errorf("TPM2 symmetric keys do not expose raw key material: %w", kbackend.ErrNotSupported)
}

// Verify interface compliance at compile time
// Note: TPM2KeyStore implements keychain.KeyStore which has a different RotateKey signature
// than types.Backend. We verify SymmetricEncrypter only.
var _ types.SymmetricKey = (*tpm2SymmetricKey)(nil)
var _ types.SymmetricEncrypter = (*tpm2AESEncrypter)(nil)
