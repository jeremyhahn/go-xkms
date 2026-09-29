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
	"context"
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
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
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

// claimNonce atomically claims (keyMaterial, nonce) against the shared,
// optionally-persistent aead.KeyNonceGuard, in one step, replacing the old
// STEP 3 check / STEP 5 record pair the per-backend AEADSafetyTracker used
// to perform non-atomically (go-xkms#1201). keyMaterial is the same bytes
// loadKeyMaterial already unsealed for this encryption, identifying the key
// by its own material exactly as every other in-process-material backend
// does, rather than by a name a second TPM object could share.
//
// wasCallerSupplied distinguishes a nonce the immediate caller of Encrypt
// provided (opts.Nonce != nil) from one this encrypter generated itself: a
// generated nonce still encrypts once the guard's bounded in-memory tracker
// is full, because it is fresh by construction and cannot itself be a
// repeat; see backend.ClaimGeneratedAEADNonce.
func (e *tpm2AESEncrypter) claimNonce(wasCallerSupplied bool, keyMaterial, nonce []byte) error {
	claim := kbackend.ClaimGeneratedAEADNonce
	if wasCallerSupplied {
		claim = kbackend.ClaimAEADNonce
	}
	if err := claim(context.Background(), keyMaterial, nil, e.attrs.ID(), nonce); err != nil {
		return &errs.Affix{Prefix: "AEAD safety check failed: ", Err: err, Suffix: " (CRITICAL: rotate this key immediately)"}
	}
	return nil
}

// GenerateSymmetricKey generates a new AES symmetric key and seals it in the
// TPM under the Platform SRK.
//
// TPM 2.0 supports symmetric encryption with the following constraints:
//   - AES-128 and AES-256 (AES-192 is not in the TPM 2.0 spec)
//   - The key is stored as a sealed keyed-hash object (public + encrypted
//     private blob) whose parent is the Platform SRK
//
// The key object is created by sealKeyInternal, the same path every other
// secret go-xkms seals under the Platform SRK takes (see symmetricSealAttrs):
// creating it, and later loading it, is authorized by the Platform SRK's
// USER PIN or its platform PCR policy, and the object's own authorization
// is attrs.Password and, when attrs.PlatformPolicy is set, the platform
// policy. The key material enters the TPM encrypted under a salted session.
//
// Encryption and decryption run AES-GCM in Go over the unsealed key (see
// loadKeyMaterial): TPM2_EncryptDecrypt2 offers no AEAD mode.
//
// Parameters:
//   - attrs: Key attributes including symmetric algorithm and key size (128
//     or 256 bits). attrs.Parent names the Platform SRK and carries its USER
//     PIN; nil selects the Platform SRK's own attributes.
//
// Returns:
//   - SymmetricKey for the generated key
//   - ErrSymmetricKeyParent if attrs.Parent is not the Platform SRK
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

	sealAttrs, err := tpm.symmetricSealAttrs(attrs)
	if err != nil {
		return nil, err
	}

	// Check if key already exists by trying to load the public blob
	if _, err := tpm.backend.Get(attrs, store.FSEXT_PUBLIC_BLOB); err == nil {
		return nil, kbackend.ErrKeyAlreadyExists
	}

	// Generate the AES key material using the configured RNG
	keyMaterial := make([]byte, keySize/8)
	defer enclave.Wipe(keyMaterial)
	if _, err := tpm.random.Read(keyMaterial); err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to generate key material", Err: err}
	}

	sealAttrs.SealData = types.NewSealData(keyMaterial)
	defer sealAttrs.SealData.Clear()

	if _, err := tpm.sealKeyInternal(sealAttrs, tpm.backend, false); err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to create symmetric key", Err: err}
	}

	// Initialize AEAD tracking options for this key
	keyID := attrs.ID()
	if tpm.tracker != nil {
		if err := tpm.tracker.SetAEADOptions(keyID, types.DefaultAEADOptions()); err != nil {
			// Log but don't fail key generation
			tpm.logger.Warn("failed to set AEAD options", slog.String("error", err.Error()))
		}
	}

	// The returned key object carries no key material: it stays sealed in
	// the TPM blob.
	return &tpm2SymmetricKey{
		algorithm: string(attrs.SymmetricAlgorithm),
		keySize:   keySize,
	}, nil
}

// symmetricSealAttrs returns the attributes the sealed object behind the
// symmetric key attrs is created, loaded and unsealed under.
//
// The parent is attrs.Parent, or the Platform SRK's own attributes when the
// caller named none, and it must be the Platform SRK: go-xkms never parents
// its secrets on the Shared SRK. Its USER PIN (Parent.Password) or, without
// one, its platform PCR policy authorizes TPM2_Create and TPM2_Load exactly as
// for every other object sealKeyInternal seals (see CreateSession).
//
// The object's own authorization is attrs.Password and attrs.PlatformPolicy,
// as seal.go applies them. The template is always KeyedHashTemplate, so a
// caller-supplied TPMAttributes cannot reintroduce NoDA or drop the policy.
// The result is a copy: sealKeyInternal records the transient handle and
// template on it, and GenerateSymmetricKey attaches the key material to it,
// neither of which may reach the caller's attributes.
func (tpm *TPM2) symmetricSealAttrs(attrs *types.KeyAttributes) (*types.KeyAttributes, error) {
	parent := attrs.Parent
	if parent == nil {
		psrk, err := tpm.PlatformSRKAttributes()
		if err != nil {
			return nil, &errs.Joined{Lead: ErrSymmetricKeyParent, Detail: "no usable Platform SRK", Cause: err}
		}
		parent = psrk
	}

	psrkHandle := platformSRKHandle(tpm.config)
	if parent.TPMAttributes == nil || parent.TPMAttributes.Handle != psrkHandle {
		var got tpm2.TPMHandle
		if parent.TPMAttributes != nil {
			got = parent.TPMAttributes.Handle
		}
		return nil, &errs.Detail{
			Err:    ErrSymmetricKeyParent,
			Detail: fmt.Sprintf("%s: parent handle 0x%x, Platform SRK 0x%x", attrs.CN, uint32(got), uint32(psrkHandle)),
		}
	}

	sealAttrs := *attrs
	sealAttrs.Parent = parent
	sealAttrs.TPMAttributes = nil
	sealAttrs.SealData = nil
	return &sealAttrs, nil
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
	publicBlob, err := tpm.backend.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, &errs.Detail{Err: kbackend.ErrKeyNotFound, Detail: attrs.CN}
		}
		return nil, &errs.Detail{Err: ErrKeyRetrievalFailed, Detail: fmt.Sprintf("%s: %v", attrs.CN, err)}
	}

	// The public area is stored as SaveKeyPair writes it and LoadKeyPair
	// reads it: the bare TPMT_PUBLIC.
	tpmPublic := tpm2.BytesAs2B[tpm2.TPMTPublic](publicBlob)
	pub, err := tpmPublic.Contents()
	if err != nil {
		if unprotectedSymmetricKeyBlob(publicBlob) {
			// Name the file to delete: DeleteKey cannot unseal a
			// pre-#1148 blob to authorize its own removal, so this
			// message is the only place an operator learns which file
			// on disk still holds the unprotected key (go-xkms#1168).
			return nil, &errs.Detail{
				Err:    ErrUnprotectedSymmetricKey,
				Detail: fmt.Sprintf("%s: delete %s%s from the TPM2 key directory", attrs.CN, attrs.CN, store.FSEXT_LEGACY_PRIVATE_BLOB),
			}
		}
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

		// STEP 3: Claim nonce uniqueness. Unlike the explicit-nonce path,
		// the nonce cannot be claimed before Seal produces it. opts.Nonce
		// is nil on this branch by construction (randomNonce requires it),
		// so the claim always tolerates a full guard; see claimNonce.
		if err := e.claimNonce(false, keyMaterial, nonce); err != nil {
			return nil, err
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

		// STEP 3: Claim (key, nonce) uniqueness before encryption
		if err := e.claimNonce(opts.Nonce != nil, keyMaterial, nonce); err != nil {
			return nil, err
		}

		// STEP 4: Encrypt with authentication
		sealedWithTag := gcm.Seal(nil, nonce, plaintext, opts.AdditionalData)

		// GCM appends the tag to ciphertext, extract it
		tagSize := gcm.Overhead()
		tag = sealedWithTag[len(sealedWithTag)-tagSize:]
		ciphertext = sealedWithTag[:len(sealedWithTag)-tagSize]
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

// loadKeyMaterial unseals the symmetric key's material from the TPM.
//
// It is unsealKeyInternal over the attributes symmetricSealAttrs resolves:
// TPM2_Load under the Platform SRK is authorized by its USER PIN or platform
// PCR policy, TPM2_Unseal by the key object's own authorization, and the
// unsealed material leaves the TPM encrypted under a salted session
// (encryptOut), so it never crosses the TPM bus in the clear.
//
// IMPORTANT: The caller MUST zero out the returned key material after use.
func (e *tpm2AESEncrypter) loadKeyMaterial() ([]byte, error) {
	sealAttrs, err := e.tpm.symmetricSealAttrs(e.attrs)
	if err != nil {
		return nil, err
	}
	keyMaterial, err := e.tpm.unsealKeyInternal(sealAttrs, e.tpm.backend)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "tpm2: failed to unseal key material", Err: err}
	}
	return keyMaterial, nil
}

// unprotectedSymmetricKeyBlob reports whether publicBlob is the public area
// of a symmetric key written before symmetric keys moved under the Platform
// SRK. Those releases stored it as a size-prefixed TPM2B_PUBLIC of a keyed-hash
// object with NoDA set, parented on the Shared SRK with no authorization. It
// is recognised only so GetSymmetricKey can refuse it by name
// (ErrUnprotectedSymmetricKey); it is never loaded.
func unprotectedSymmetricKeyBlob(publicBlob []byte) bool {
	legacy, err := tpm2.Unmarshal[tpm2.TPM2BPublic](publicBlob)
	if err != nil {
		return false
	}
	pub, err := legacy.Contents()
	if err != nil {
		return false
	}
	return pub.Type == tpm2.TPMAlgKeyedHash && pub.ObjectAttributes.NoDA
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
