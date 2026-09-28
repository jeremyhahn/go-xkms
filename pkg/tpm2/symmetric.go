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

package tpm2

import (
	"crypto/aes"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/google/go-tpm/tpm2"

	kbackend "github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"

	"github.com/jeremyhahn/go-enclave"
)

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
	return nil, &errs.Wrapped{Msg: "TPM2 symmetric keys do not expose raw key material", Err: kbackend.ErrNotSupported}
}

// tpm2AESEncrypter implements SymmetricEncrypter for TPM-backed AES keys.
//
// This encrypter uses software AES-GCM with key material stored securely in the TPM.
// The TPM protects the key material and only provides it to authorized processes.
type tpm2AESEncrypter struct {
	tpm   *TPM2
	attrs *types.KeyAttributes
	mu    sync.Mutex
}

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
//   - attrs: Key attributes including symmetric algorithm and key size (128 or 256 bits)
//
// Returns:
//   - SymmetricKey for the generated key
//   - Error if generation fails or attributes are invalid
func (tpm *TPM2) GenerateSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	if err := validateSymmetricKeyAttributes(attrs); err != nil {
		return nil, err
	}

	// TPM 2.0 spec only supports AES-128 and AES-256
	keySize := attrs.SymmetricAlgorithm.KeySize()
	if keySize != 128 && keySize != 256 {
		return nil, &errs.Message{Msg: fmt.Sprintf("tpm2: unsupported AES key size %d, TPM 2.0 supports 128 or 256 bits", keySize)}
	}

	if tpm.transport == nil {
		return nil, ErrNotInitialized
	}

	// Get SRK handle and name
	srkHandle := tpm2.TPMHandle(tpm.config.SSRK.Handle)
	srkName, _, err := tpm.ReadHandle(srkHandle)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to read SRK", Err: err}
	}

	// Check if key already exists by trying to load the private blob
	_, err = tpm.backend.Get(attrs, ".priv")
	if err == nil {
		// Key already exists
		return nil, kbackend.ErrKeyAlreadyExists
	}

	// Generate the AES key material using the configured RNG
	keyBytes := keySize / 8 // Convert bits to bytes
	keyMaterial := make([]byte, keyBytes)
	if _, err := tpm.random.Read(keyMaterial); err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to generate key material", Err: err}
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

	// The key material is encrypted on its way into the TPM by a salted
	// session.
	encSession, closeEncSession, err := tpm.encryptionSession(encryptIn)
	if err != nil {
		return nil, err
	}
	defer tpm.closeSession(closeEncSession, "symmetric key creation encryption")

	// Create the sealed object with the key material
	createResp, err := tpm2.Create{
		ParentHandle: &tpm2.NamedHandle{
			Handle: srkHandle,
			Name:   srkName,
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
	}.Execute(tpm.transport, encSession)

	if err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to create symmetric key", Err: err}
	}

	// Marshal the key blob for storage
	privateBlob := tpm2.Marshal(createResp.OutPrivate)
	publicBlob := tpm2.Marshal(createResp.OutPublic)

	// Save private blob
	if err := tpm.backend.Save(attrs, privateBlob, ".priv", false); err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to save private blob", Err: err}
	}

	// Save public blob
	if err := tpm.backend.Save(attrs, publicBlob, ".pub", false); err != nil {
		// Cleanup private blob on failure. A failed cleanup is joined onto the
		// save error rather than discarded, since it leaves an orphaned
		// private blob behind with no public half.
		deleteErr := tpm.backend.Delete(attrs)
		return nil, errors.Join(&errs.Wrapped{Msg: "tpm2: failed to save public blob", Err: err}, deleteErr)
	}

	// Initialize AEAD tracking options for this key
	keyID := attrs.ID()
	if tpm.tracker != nil {
		if err := tpm.tracker.SetAEADOptions(keyID, types.DefaultAEADOptions()); err != nil {
			// Log but don't fail key generation
			tpm.logger.Warn("failed to set AEAD options", slog.String("error", err.Error()))
		}
	}

	// Create the symmetric key object (doesn't contain actual key material)
	// The key material is sealed in the TPM blob and never exposed
	symmetricKey := &tpm2SymmetricKey{
		algorithm: string(attrs.SymmetricAlgorithm),
		keySize:   keySize,
	}

	// Zero out the key material from memory
	enclave.Wipe(keyMaterial)

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
//   - backend.ErrKeyNotFound if the key blob genuinely does not exist;
//     ErrKeyRetrievalFailed if the store returned some other error and
//     existence could not be determined
func (tpm *TPM2) GetSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	if err := validateSymmetricKeyAttributes(attrs); err != nil {
		return nil, err
	}

	if tpm.transport == nil {
		return nil, ErrNotInitialized
	}

	// Load public blob to verify key exists. Only a genuine "no such
	// object" result from the underlying store (surfaced as
	// storage.ErrNotFound through tpm.backend.Get) is reported as
	// backend.ErrKeyNotFound. Any other failure -- a permission error, a
	// transient I/O fault, a corrupt or partially written blob -- becomes
	// ErrKeyRetrievalFailed instead, so callers such as getOrGenerateCAKey
	// never mistake "could not read the key" for "the key does not exist
	// yet" and silently generate a replacement.
	publicBlob, err := tpm.backend.Get(attrs, ".pub")
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, &errs.Detail{Err: kbackend.ErrKeyNotFound, Detail: attrs.CN}
		}
		return nil, &errs.Detail{Err: ErrKeyRetrievalFailed, Detail: fmt.Sprintf("%s: %v", attrs.CN, err)}
	}

	// Unmarshal public structure to verify it's valid
	tpmPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](publicBlob)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to unmarshal public blob", Err: err}
	}

	pub, err := tpmPublic.Contents()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to get public contents", Err: err}
	}

	// Verify it's a keyed hash (sealed data object)
	if pub.Type != tpm2.TPMAlgKeyedHash {
		return nil, &errs.Message{Msg: fmt.Sprintf("tpm2: key is not a keyed hash (sealed) object, type: %v", pub.Type)}
	}

	// Create the symmetric key object (without exposing key material)
	// Extract key size from algorithm
	keySize := attrs.SymmetricAlgorithm.KeySize()
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
//   - types.SymmetricEncrypter for the key
//   - backend.ErrKeyNotFound if the key genuinely does not exist, or
//     ErrKeyRetrievalFailed if GetSymmetricKey could not determine that
//     (both propagated from GetSymmetricKey, which does the classification)
func (tpm *TPM2) SymmetricEncrypter(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	// Verify the key exists
	_, err := tpm.GetSymmetricKey(attrs)
	if err != nil {
		return nil, err
	}

	return &tpm2AESEncrypter{
		tpm:   tpm,
		attrs: attrs,
	}, nil
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
	e.mu.Lock()
	defer e.mu.Unlock()

	if opts == nil {
		opts = &types.EncryptOptions{}
	}

	// Get key ID for tracking
	keyID := e.attrs.ID()

	// STEP 1: Check bytes limit before encryption
	if e.tpm.tracker != nil {
		if err := e.tpm.tracker.IncrementBytes(keyID, int64(len(plaintext))); err != nil {
			return nil, &errs.Affix{Prefix: "AEAD safety check failed: ", Err: err, Suffix: " (consider rotating this key)"}
		}
	}

	// Load the TPM key to get key material
	keyMaterial, err := e.loadKeyMaterial()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to load key material", Err: err}
	}
	// Zero out key material after use
	defer enclave.Wipe(keyMaterial)

	// Create AES cipher
	block, err := aes.NewCipher(keyMaterial)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to create cipher", Err: err}
	}

	// Create GCM mode at the requested tag length. NIST SP 800-38D section
	// 5.2.1.2 defines a t-bit tag as the leading t bits of the full tag; a
	// caller that asked for one and got 128 bits back has a ciphertext its
	// peer cannot authenticate.
	//
	// Under GODEBUG=fips140=only, Go refuses every AES-GCM construction that
	// accepts a caller- or process-supplied IV, so when opts.Nonce is unset
	// this substitutes cipher.NewGCMWithRandomNonce (randomNonce true) and
	// reports it via GCMNonceMode so Decrypt reconstructs the same
	// construction later. See pkg/crypto/aead.NewGCMForFreshEncrypt.
	gcm, randomNonce, err := aead.NewGCMForFreshEncrypt(block, opts.TagSize, opts.Nonce != nil)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to create GCM", Err: err}
	}

	var nonce, ciphertext, tag []byte

	if randomNonce {
		// gcm's NonceSize is 0: it generates the nonce itself and prepends
		// it to Seal's output, so Seal is called with a nil nonce argument
		// and the nonce is not known until this returns.
		sealed := gcm.Seal(nil, nil, plaintext, opts.AdditionalData)
		nonce, ciphertext, tag, err = aead.SplitGCMWithRandomNonce(sealed)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "tpm2: failed to split random-nonce GCM output", Err: err}
		}

		// STEP 3: Check nonce uniqueness. Unlike the explicit-nonce path,
		// the nonce cannot be checked before Seal produces it.
		if e.tpm.tracker != nil {
			if err := e.tpm.tracker.CheckNonce(keyID, nonce); err != nil {
				return nil, &errs.Affix{Prefix: "AEAD safety check failed: ", Err: err, Suffix: " (CRITICAL: rotate this key immediately)"}
			}
		}
	} else {
		// STEP 2: Generate or use provided nonce
		if opts.Nonce != nil {
			nonce = opts.Nonce
			if len(nonce) != gcm.NonceSize() {
				return nil, &errs.Message{Msg: fmt.Sprintf("invalid nonce size: %d (expected %d)", len(nonce), gcm.NonceSize())}
			}
		} else {
			nonce = make([]byte, gcm.NonceSize())
			if _, err := e.tpm.random.Read(nonce); err != nil {
				return nil, &errs.Wrapped{Msg: "tpm2: failed to generate nonce", Err: err}
			}
		}

		// STEP 3: Check nonce uniqueness before encryption
		if e.tpm.tracker != nil {
			if err := e.tpm.tracker.CheckNonce(keyID, nonce); err != nil {
				return nil, &errs.Affix{Prefix: "AEAD safety check failed: ", Err: err, Suffix: " (CRITICAL: rotate this key immediately)"}
			}
		}

		// STEP 4: Encrypt with authentication
		sealedWithTag := gcm.Seal(nil, nonce, plaintext, opts.AdditionalData)

		// GCM appends the tag to ciphertext, extract it
		tagSize := gcm.Overhead()
		tag = sealedWithTag[len(sealedWithTag)-tagSize:]
		ciphertext = sealedWithTag[:len(sealedWithTag)-tagSize]
	}

	// STEP 5: Record nonce after successful encryption
	if e.tpm.tracker != nil {
		if err := e.tpm.tracker.RecordNonce(keyID, nonce); err != nil {
			// Log warning but return successful encryption
			e.tpm.logger.Warn("failed to record nonce", slog.String("error", err.Error()))
		}
	}

	nonceMode := types.GCMNonceModeExplicit
	if randomNonce {
		nonceMode = types.GCMNonceModeRandom
	}

	return &types.EncryptedData{
		Ciphertext:   ciphertext,
		Nonce:        nonce,
		Tag:          tag,
		Algorithm:    e.attrs.KeyAlgorithm.String(),
		GCMNonceMode: nonceMode,
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
	e.mu.Lock()
	defer e.mu.Unlock()

	if opts == nil {
		opts = &types.DecryptOptions{}
	}

	if data == nil {
		return nil, &errs.Message{Msg: "tpm2: encrypted data is nil"}
	}

	// Load the TPM key to get key material
	keyMaterial, err := e.loadKeyMaterial()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to load key material", Err: err}
	}
	// Zero out key material after use
	defer enclave.Wipe(keyMaterial)

	// Create AES cipher
	block, err := aes.NewCipher(keyMaterial)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to create cipher", Err: err}
	}

	// The tag length comes from the request, never from the tag that arrived:
	// SP 800-38D section 5.2.2 verifies a t-bit tag by recomputing it at t
	// bits, and inferring t from the bundle would let an attacker choose how
	// many bits get checked.
	//
	// The construction is selected by data.GCMNonceMode, not by the current
	// process's FIPS posture, so a random-nonce ciphertext a fips140=only
	// process wrote still opens under fips140=on (and a classic
	// explicit-nonce ciphertext still opens on any process that can
	// construct arbitrary-IV GCM). See pkg/crypto/aead.NewGCMForDecrypt.
	randomNonce := data.GCMNonceMode == types.GCMNonceModeRandom
	gcm, err := aead.NewGCMForDecrypt(block, opts.TagSize, randomNonce)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to create GCM", Err: err}
	}

	if randomNonce {
		// gcm is cipher.NewGCMWithRandomNonce: NonceSize is 0 and Overhead
		// is nonce+tag combined, so the wire-carried fields are checked
		// against the fixed random-nonce framing rather than against gcm's
		// own (zero) NonceSize.
		if len(data.Tag) != aead.GCMFullTagSize {
			return nil, &errs.Message{Msg: fmt.Sprintf(
				"tpm2: authentication tag is %d bytes, want %d", len(data.Tag), aead.GCMFullTagSize)}
		}
		if len(data.Nonce) != aead.GCMRandomNonceSize {
			return nil, &errs.Message{Msg: fmt.Sprintf(
				"tpm2: nonce is %d bytes, want %d", len(data.Nonce), aead.GCMRandomNonceSize)}
		}

		// Decrypt and verify: Open reads its nonce from the front of the
		// input rather than accepting one as a parameter.
		joined := aead.JoinGCMWithRandomNonce(data.Nonce, data.Ciphertext, data.Tag)
		plaintext, err := gcm.Open(nil, nil, joined, opts.AdditionalData)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "tpm2: decryption failed (authentication error)", Err: err}
		}
		return plaintext, nil
	}

	if len(data.Tag) != gcm.Overhead() {
		return nil, &errs.Message{Msg: fmt.Sprintf(
			"tpm2: authentication tag is %d bytes, want %d", len(data.Tag), gcm.Overhead())}
	}

	// crypto/cipher panics rather than returning an error when the nonce is
	// not exactly NonceSize bytes. The nonce arrives from the caller, so
	// without this check any request carrying a short nonce takes the whole
	// daemon down.
	if len(data.Nonce) != gcm.NonceSize() {
		return nil, &errs.Message{Msg: fmt.Sprintf(
			"tpm2: nonce is %d bytes, want %d", len(data.Nonce), gcm.NonceSize())}
	}

	// Reconstruct ciphertext with tag (GCM expects tag appended)
	fullCiphertext := slices.Concat(data.Ciphertext, data.Tag)

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, data.Nonce, fullCiphertext, opts.AdditionalData)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: decryption failed (authentication error)", Err: err}
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
	// Get SRK handle and name
	srkHandle := tpm2.TPMHandle(e.tpm.config.SSRK.Handle)
	srkName, _, err := e.tpm.ReadHandle(srkHandle)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to read SRK", Err: err}
	}

	// Load key blobs from storage
	privateBlob, err := e.tpm.backend.Get(e.attrs, ".priv")
	if err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to load private blob", Err: err}
	}

	publicBlob, err := e.tpm.backend.Get(e.attrs, ".pub")
	if err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to load public blob", Err: err}
	}

	// Unmarshal blobs
	tpmPrivate, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privateBlob)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to unmarshal private blob", Err: err}
	}

	tpmPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](publicBlob)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to unmarshal public blob", Err: err}
	}

	// Load the sealed object into TPM
	loadResp, err := tpm2.Load{
		ParentHandle: &tpm2.NamedHandle{
			Handle: srkHandle,
			Name:   srkName,
		},
		InPrivate: *tpmPrivate,
		InPublic:  *tpmPublic,
	}.Execute(e.tpm.transport)

	if err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to load sealed key", Err: err}
	}
	// Flush logs its own failure (tpm.Flush); a discarded FlushContext error
	// here would otherwise leave a leaked transient handle unreported.
	defer e.tpm.Flush(loadResp.ObjectHandle)

	// Unseal the key material using TPM2_Unseal. The key material leaves
	// the TPM encrypted under a salted session.
	encSession, closeEncSession, err := e.tpm.encryptionSession(encryptOut)
	if err != nil {
		return nil, err
	}
	defer e.tpm.closeSession(closeEncSession, "symmetric key unseal encryption")
	unsealResp, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadResp.ObjectHandle,
			Name:   loadResp.Name,
			Auth:   tpm2.PasswordAuth(nil), // No password protection for now
		},
	}.Execute(e.tpm.transport, encSession)

	if err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to unseal key material", Err: err}
	}

	// Return the unsealed key material
	return unsealResp.OutData.Buffer, nil
}

// validateSymmetricKeyAttributes validates key attributes for symmetric operations.
func validateSymmetricKeyAttributes(attrs *types.KeyAttributes) error {
	if attrs == nil {
		return &errs.Message{Msg: "tpm2: attributes cannot be nil"}
	}

	if attrs.CN == "" {
		return &errs.Message{Msg: "tpm2: CN (Common Name) is required"}
	}

	if !attrs.IsSymmetric() {
		return &errs.Message{Msg: fmt.Sprintf("tpm2: key algorithm is not symmetric: %s", attrs.KeyAlgorithm)}
	}

	return nil
}

// Tracker returns the AEAD safety tracker for this TPM instance.
func (tpm *TPM2) Tracker() types.AEADSafetyTracker {
	return tpm.tracker
}

// Verify interface compliance at compile time
var _ types.SymmetricKey = (*tpm2SymmetricKey)(nil)
var _ types.SymmetricEncrypter = (*tpm2AESEncrypter)(nil)
