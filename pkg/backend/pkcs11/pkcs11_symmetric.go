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

//go:build pkcs11

package pkcs11

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/miekg/pkcs11"
)

// Note: Backend implements SymmetricBackend interface methods:
// - GenerateSymmetricKey
// - GetSymmetricKey
// - SymmetricEncrypter

// AES-GCM parameters this backend produces and accepts. PKCS#11 v3.2 6.13.7
// permits any ulIvLen from 1 to 2^32-1 and any ulTagBits from 0 to 128, but a
// backend that emits 96-bit nonces and 128-bit tags must also refuse to consume
// anything else: a short tag weakens forgery resistance, and a nonce length
// this encrypter would never produce can only have come from a confused or
// hostile caller.
const (
	// gcmNonceSize is the 96-bit GCM nonce length, in bytes. It is the length
	// PKCS#11 v3.2 6.13.7 recommends and the only length crypto/cipher's GCM
	// accepts by default, which keeps ciphertext produced here decryptable by
	// every other backend in the stack.
	gcmNonceSize = 12

	// gcmTagSize is the full 128-bit GCM authentication tag length, in bytes.
	// It is the default; types.EncryptOptions.TagSize selects a shorter one
	// from the set SP 800-38D approves. CK_GCM_PARAMS.ulTagBits carries the
	// chosen length to the token in bits, not bytes.
	gcmTagSize = 16
)

var (
	// ErrInvalidNonceLength is returned when a caller supplies an AEAD nonce
	// that is not exactly gcmNonceSize bytes.
	//
	// This is a denial-of-service guard as much as a correctness one:
	// crypto/cipher's AEAD.Seal and AEAD.Open panic rather than returning an
	// error when the nonce length differs from NonceSize(), so a nonce that
	// reaches them straight from a request kills the process.
	ErrInvalidNonceLength = errors.New("pkcs11: invalid AEAD nonce length")

	// ErrInvalidTagLength is returned when encrypted data carries an
	// authentication tag whose length is not the one the request selected.
	// The length comes from types.DecryptOptions.TagSize, never from the tag
	// itself: inferring it would let a caller -- or an attacker who can
	// reshape a ciphertext bundle -- downgrade forgery resistance by handing
	// over fewer tag bits than the encryptor produced.
	ErrInvalidTagLength = errors.New("pkcs11: invalid AEAD authentication tag length")

	// ErrInvalidTagSize is returned when a requested tag length is not one
	// PKCS#11 v3.2 section 6.13.7 and NIST SP 800-38D section 5.2.1.2
	// approve for AES-GCM: 96, 104, 112, 120 or 128 bits.
	ErrInvalidTagSize = errors.New("pkcs11: unsupported AEAD authentication tag size")

	// ErrNilEncryptedData is returned when Decrypt is handed a nil
	// *types.EncryptedData, which would otherwise be a nil-pointer panic.
	ErrNilEncryptedData = errors.New("pkcs11: encrypted data is nil")

	// ErrUnsupportedCipherMode is returned when a caller requests a
	// types.CipherMode this encrypter does not implement at all (anything
	// other than the AEAD default, CBC, CBC-Pad or ECB). Silently encrypting
	// in a different mode than the caller asked for is worse than failing:
	// encrypt and decrypt would agree with each other while producing
	// unauthenticated output the caller believed was authenticated, or the
	// reverse.
	ErrUnsupportedCipherMode = errors.New("pkcs11: unsupported cipher mode")

	// ErrMechanismNotSupported is returned when a cipher mode this encrypter
	// implements in general is not available on the connected token, because
	// the token's mechanism list does not advertise the CKM_* mechanism the
	// mode requires. It is always joined with backend.ErrOperationNotSupported
	// (see requireCipherMechanism) so the service layer classifies it as a
	// capability boundary -- reported as 501 / Unimplemented -- rather than a
	// fault.
	ErrMechanismNotSupported = errors.New("pkcs11: mechanism not supported by token")

	// ErrAdditionalDataNotSupported is returned when AdditionalData is
	// supplied for a non-AEAD cipher mode (CBC, CBC-Pad or ECB). None of the
	// three authenticate anything, so silently accepting and ignoring
	// additional data would misrepresent the operation actually performed.
	ErrAdditionalDataNotSupported = errors.New("pkcs11: additional data is not supported for this cipher mode")

	// ErrTagSizeNotSupported is returned when a tag length is requested of a
	// non-AEAD cipher mode. CBC, CBC-Pad and ECB produce no authentication
	// tag at all.
	ErrTagSizeNotSupported = errors.New("pkcs11: this cipher mode produces no authentication tag")

	// ErrIVNotSupported is returned when an IV accompanies AES-ECB. ECB
	// enciphers every block independently (PKCS#11 v3.2 6.10.4 gives
	// CKM_AES_ECB no mechanism parameter at all), so an IV can only mean the
	// caller expects a chained mode.
	ErrIVNotSupported = errors.New("pkcs11: an IV is not supported for this cipher mode")

	// ErrInvalidIVSize is returned when a caller-supplied AES-CBC / AES-CBC-Pad
	// IV is not exactly one AES block (16 bytes), which is what
	// CK_MECHANISM.pParameter must carry for CKM_AES_CBC and CKM_AES_CBC_PAD
	// (PKCS#11 v3.2 6.10.3). Validating here turns a malformed caller-supplied
	// IV into a typed error instead of a token-dependent CKR_MECHANISM_PARAM_INVALID.
	ErrInvalidIVSize = errors.New("pkcs11: invalid IV size")

	// ErrPlaintextNotBlockAligned is returned by unpadded AES-CBC
	// (types.CipherModeCBC) encryption when the plaintext length is zero or
	// not a whole number of AES blocks, and by AES-ECB encryption for the
	// same reason. Unpadded CBC and ECB have no way to encode a partial final
	// block.
	ErrPlaintextNotBlockAligned = errors.New("pkcs11: plaintext is not a whole number of AES blocks")

	// ErrCiphertextNotBlockAligned is returned by AES-CBC (padded or
	// unpadded) and AES-ECB decryption when the ciphertext length is zero or
	// not a whole number of AES blocks.
	ErrCiphertextNotBlockAligned = errors.New("pkcs11: ciphertext is not a whole number of AES blocks")

	// ErrInvalidPadding is returned when the token reports a padding failure
	// while decrypting AES-CBC-Pad ciphertext. PKCS#7 padding removal runs
	// inside the HSM for CKM_AES_CBC_PAD (PKCS#11 v3.2 6.10.3), so this
	// package never inspects the padding bytes itself; it only reclassifies
	// the token's failure under one typed sentinel, matching the software
	// symmetric provider's ErrInvalidPadding so both backends answer a
	// padding-oracle probe identically at the API layer.
	ErrInvalidPadding = errors.New("pkcs11: invalid padding")
)

// cbcIVSize is the AES-CBC and AES-CBC-Pad IV length PKCS#11 v3.2 6.10.3
// requires: exactly one AES block.
const cbcIVSize = aes.BlockSize

// requireCipherMechanism maps a non-AEAD types.CipherMode onto the CKM_*
// mechanism that implements it, refusing a mode this encrypter does not
// implement at all with ErrUnsupportedCipherMode and a mode the connected
// token does not advertise with an error that joins
// backend.ErrOperationNotSupported -- so a genuinely unavailable mechanism is
// classified as a capability boundary (501 / Unimplemented) at the service
// layer rather than surfacing as a 500 or an opaque CKR_MECHANISM_INVALID.
func (b *Backend) requireCipherMechanism(mode types.CipherMode) (uint, error) {
	var mechanism uint
	var mechanismName string
	var supported bool

	switch mode {
	case types.CipherModeCBC:
		mechanism, mechanismName, supported = pkcs11.CKM_AES_CBC, "CKM_AES_CBC", b.supportsAESCBC
	case types.CipherModeCBCPad:
		mechanism, mechanismName, supported = pkcs11.CKM_AES_CBC_PAD, "CKM_AES_CBC_PAD", b.supportsAESCBCPad
	case types.CipherModeECB:
		mechanism, mechanismName, supported = pkcs11.CKM_AES_ECB, "CKM_AES_ECB", b.supportsAESECB
	default:
		return 0, &errs.Detail{Err: ErrUnsupportedCipherMode, Detail: fmt.Sprintf("%q", mode)}
	}

	if !supported {
		return 0, &errs.Joined{
			Lead:   backend.ErrOperationNotSupported,
			Detail: fmt.Sprintf("token does not advertise %s (cipher mode %q)", mechanismName, mode),
			Cause:  ErrMechanismNotSupported,
		}
	}
	return mechanism, nil
}

// requireGCMNonce validates a caller-supplied AEAD nonce length.
func requireGCMNonce(nonce []byte) error {
	if len(nonce) == gcmNonceSize {
		return nil
	}
	return &errs.Detail{Err: ErrInvalidNonceLength, Detail: fmt.Sprintf(
		"nonce is %d bytes, want %d", len(nonce), gcmNonceSize)}
}

// requireGCMTag validates the authentication tag length carried by encrypted
// data against the length the request selected.
func requireGCMTag(tag []byte, tagSize int) error {
	if len(tag) == tagSize {
		return nil
	}
	return &errs.Detail{Err: ErrInvalidTagLength, Detail: fmt.Sprintf(
		"tag is %d bytes, want %d", len(tag), tagSize)}
}

// gcmTagSizes are the AES-GCM authentication tag lengths in bytes that
// PKCS#11 v3.2 section 6.13.7 and NIST SP 800-38D section 5.2.1.2 approve:
// t of 96, 104, 112, 120 and 128 bits.
var gcmTagSizes = map[int]struct{}{
	12: {}, 13: {}, 14: {}, 15: {}, 16: {},
}

// resolveGCMTagSize maps a requested tag length in bytes onto the length this
// encrypter will ask the token for. Zero selects the full 128-bit tag.
//
// CK_GCM_PARAMS.ulTagBits carries the length to the token, which produces the
// leading ulTagBits bits of the full tag (SP 800-38D section 5.2.1.2), so a
// truncated tag is a genuine capability here rather than something to be
// emulated. A length outside the approved set is refused: substituting the
// nearest permitted one would hand back a tag the caller's peer cannot verify.
func resolveGCMTagSize(requested int) (int, error) {
	if requested == 0 {
		return gcmTagSize, nil
	}
	if _, ok := gcmTagSizes[requested]; !ok {
		return 0, &errs.Detail{Err: ErrInvalidTagSize, Detail: fmt.Sprintf(
			"%d bytes; AES-GCM permits 12, 13, 14, 15 or 16", requested)}
	}
	return requested, nil
}

// concatCiphertextAndTag returns ciphertext||tag in a freshly allocated slice.
//
// The obvious append(ciphertext, tag...) aliases: Encrypt hands back a
// Ciphertext and a Tag that are two windows onto one array, so appending
// writes through the caller's own buffer whenever it has spare capacity.
// Copying keeps Decrypt free of side effects on its argument.
func concatCiphertextAndTag(ciphertext, tag []byte) []byte {
	full := make([]byte, 0, len(ciphertext)+len(tag))
	full = append(full, ciphertext...)
	return append(full, tag...)
}

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
	return nil, &errs.Detail{Err: backend.ErrNotSupported, Detail: "PKCS#11 symmetric keys do not expose raw key material"}
}

// pkcs11SymmetricEncrypter implements types.SymmetricEncrypter for PKCS#11 HSMs.
// All encryption/decryption operations are performed on the HSM hardware.
type pkcs11SymmetricEncrypter struct {
	backend *Backend
	attrs   *types.KeyAttributes
	handle  pkcs11.ObjectHandle
}

// claimNonce atomically claims (this key, nonce) against the shared,
// optionally-persistent aead.KeyNonceGuard, in one step, replacing the old
// STEP 3 check / STEP 5 record pair the per-backend AEADSafetyTracker used
// to perform non-atomically (go-xkms#1201).
//
// A PKCS#11 key's material never leaves the token -- backend.ErrNotSupported
// is passed literally rather than obtained from a Raw() call, since none
// exists for this backend -- so the claim identifies the key by
// e.attrs.ID() instead, which already encodes the tenant, partition, backend
// (StoreType), key type, common name and algorithm.
//
// wasCallerSupplied distinguishes a nonce the caller of Encrypt provided
// (opts.Nonce != nil) from one this encrypter generated itself: a generated
// nonce still encrypts once the guard's bounded in-memory tracker is full,
// because it is fresh by construction and cannot itself be a repeat; see
// backend.ClaimGeneratedAEADNonce.
func (e *pkcs11SymmetricEncrypter) claimNonce(wasCallerSupplied bool, nonce []byte) error {
	claim := backend.ClaimGeneratedAEADNonce
	if wasCallerSupplied {
		claim = backend.ClaimAEADNonce
	}
	if err := claim(context.Background(), nil, backend.ErrNotSupported, e.attrs.ID(), nonce); err != nil {
		return &errs.Wrapped{Msg: "AEAD safety check failed", Err: err}
	}
	return nil
}

// Encrypt encrypts plaintext using the symmetric key on the HSM.
// For AES-GCM, this provides authenticated encryption with additional data support.
func (e *pkcs11SymmetricEncrypter) Encrypt(plaintext []byte, opts *types.EncryptOptions) (encrypted *types.EncryptedData, err error) {
	if opts == nil {
		opts = &types.EncryptOptions{}
	}

	// STEP 0: Route non-AEAD cipher modes to their own implementation before
	// any of the AEAD-specific validation below runs -- CBC, CBC-Pad and ECB
	// take a different code path entirely (no tag, no AEAD nonce/AAD, no AEAD
	// safety tracking, since the NIST SP 800-38D nonce-reuse and byte-limit
	// rules are specific to GCM and do not apply to them).
	switch opts.Mode {
	case "":
		// Fall through to the AEAD path below (existing default behavior).
	case types.CipherModeCBC, types.CipherModeCBCPad:
		return e.encryptCBC(plaintext, opts)
	case types.CipherModeECB:
		return e.encryptECB(plaintext, opts)
	default:
		return nil, &errs.Detail{Err: ErrUnsupportedCipherMode, Detail: fmt.Sprintf("%q", opts.Mode)}
	}

	// STEP 0b: Reject a malformed request before it can consume any of the
	// key's AEAD byte budget or reach the token. A caller-supplied nonce is
	// untrusted input all the way from the wire.
	if opts.Nonce != nil {
		if err := requireGCMNonce(opts.Nonce); err != nil {
			return nil, err
		}
	}
	tagSize, err := resolveGCMTagSize(opts.TagSize)
	if err != nil {
		return nil, err
	}

	// Get key ID for tracking
	label := createKeyID(e.attrs)

	// STEP 1: Check bytes limit
	if e.backend.tracker != nil {
		if err := e.backend.tracker.IncrementBytes(label, int64(len(plaintext))); err != nil {
			return nil, &errs.Wrapped{Msg: "AEAD safety check failed", Err: err}
		}
	}

	// Initialize PKCS#11 context if needed
	if e.backend.p11ctx == nil {
		return nil, &errs.Message{Msg: "PKCS#11 context not initialized"}
	}

	// Resolve the token slot the same way every other operation on this
	// backend does. Taking the first enumerated slot would ignore the
	// configured TokenLabel and silently operate on whichever token the module
	// happens to list first, which on a multi-token host is not the caller's.
	slot, slotErr := e.backend.resolveSlot()
	if slotErr != nil {
		return nil, slotErr
	}

	// Open session
	session, err := e.backend.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to open session", Err: err}
	}
	defer func() {
		if closeErr := e.backend.p11ctx.CloseSession(session); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	// Login as user
	// Note: We don't logout because C_Logout affects ALL sessions, not just this one
	userPIN, err := e.backend.userPIN()
	if err != nil {
		return nil, err
	}
	if err := e.backend.p11ctx.Login(session, pkcs11.CKU_USER, userPIN); err != nil {
		if !isCKR(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			return nil, &errs.Wrapped{Msg: "failed to login", Err: err}
		}
	}
	// DO NOT LOGOUT - C_Logout affects ALL sessions on this token

	// STEP 2: Generate or use provided nonce. A caller-supplied nonce has
	// already been length-checked above.
	var nonce []byte
	if opts.Nonce != nil {
		nonce = opts.Nonce
	} else {
		nonce = make([]byte, gcmNonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, &errs.Wrapped{Msg: "failed to generate nonce", Err: err}
		}
	}

	// STEP 3: Claim (key, nonce) uniqueness BEFORE encryption
	if err := e.claimNonce(opts.Nonce != nil, nonce); err != nil {
		return nil, err
	}

	// Set up GCM parameters
	// For PKCS#11 AES-GCM, we need to construct CK_GCM_PARAMS
	// Note: Not all HSMs support GCM parameters with AAD
	// We'll use a software-based approach for better compatibility

	// Get the key material (if extractable) or use software encryption
	// Since PKCS#11 keys are typically non-extractable, we'll perform
	// encryption using PKCS#11 C_Encrypt with CKM_AES_GCM mechanism

	// Prepare GCM parameters. CK_GCM_PARAMS.ulTagBits is in bits, not bytes.
	//
	// NewGCMParams allocates the IV and AAD in C memory that the library
	// deliberately does not free automatically, so that an HSM which writes
	// its own IV back can be read after the operation. Every caller therefore
	// owns the Free(); without it each encryption leaks the nonce and AAD.
	gcmParams := pkcs11.NewGCMParams(nonce, opts.AdditionalData, tagSize*8)
	defer gcmParams.Free()

	// Find the key handle in THIS session (handles are session-specific)
	// We must find the key in the same session where we'll use it
	// (label already defined above for tracking)
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	if err := e.backend.p11ctx.FindObjectsInit(session, template); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to init object search", Err: err}
	}

	handles, _, err := e.backend.p11ctx.FindObjects(session, 1)
	if err != nil {
		findFinalErr := e.backend.p11ctx.FindObjectsFinal(session) // Clean up even on error
		return nil, errors.Join(&errs.Wrapped{Msg: "failed to find objects", Err: err}, findFinalErr)
	}

	// Must finalize BEFORE starting encryption operation
	if err := e.backend.p11ctx.FindObjectsFinal(session); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to finalize object search", Err: err}
	}

	if len(handles) == 0 {
		return nil, &errs.Message{Msg: fmt.Sprintf("key not found: %s", e.attrs.CN)}
	}

	handle := handles[0]

	// Create mechanism with GCM parameters
	mechanism := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcmParams),
	}

	// Initialize encryption
	if err := e.backend.p11ctx.EncryptInit(session, mechanism, handle); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to initialize encryption", Err: err}
	}

	// STEP 4: Perform encryption
	// For GCM, the output will include the ciphertext + tag
	ciphertext, err := e.backend.p11ctx.Encrypt(session, plaintext)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "encryption failed", Err: err}
	}

	// PKCS#11 v3.2 6.13.2 has C_Encrypt return the ciphertext with the
	// authentication tag appended, so even an empty plaintext yields at least
	// gcmTagSize bytes. A token that returns less is malfunctioning, and the
	// split below would panic on it, so check before slicing.
	if len(ciphertext) < tagSize {
		return nil, &errs.Detail{Err: ErrInvalidTagLength, Detail: fmt.Sprintf(
			"token returned %d bytes of ciphertext, expected at least %d (tag size)", len(ciphertext), tagSize)}
	}

	tag := ciphertext[len(ciphertext)-tagSize:]
	ciphertextOnly := ciphertext[:len(ciphertext)-tagSize]

	return &types.EncryptedData{
		Ciphertext: ciphertextOnly,
		Nonce:      nonce,
		Tag:        tag,
		Algorithm:  string(e.attrs.SymmetricAlgorithm),
	}, nil
}

// Decrypt decrypts ciphertext using the symmetric key on the HSM.
// For AES-GCM, this verifies authentication before decrypting.
func (e *pkcs11SymmetricEncrypter) Decrypt(data *types.EncryptedData, opts *types.DecryptOptions) (plaintextOut []byte, err error) {
	if opts == nil {
		opts = &types.DecryptOptions{}
	}

	// Validate the whole request before touching the token. Every field read
	// below is attacker-controlled in a daemon that decrypts on request: a nil
	// struct is a nil-pointer panic, an empty nonce becomes a NULL pIv with
	// ulIvLen 0 which PKCS#11 v3.2 6.13.7 does not permit (1 to 2^32-1), and a
	// short tag would silently weaken forgery resistance.
	if data == nil {
		return nil, ErrNilEncryptedData
	}

	// Route non-AEAD cipher modes to their own implementation, mirroring
	// Encrypt's dispatch above.
	switch opts.Mode {
	case "":
		// Fall through to the AEAD path below (existing default behavior).
	case types.CipherModeCBC, types.CipherModeCBCPad:
		return e.decryptCBC(data, opts)
	case types.CipherModeECB:
		return e.decryptECB(data, opts)
	default:
		return nil, &errs.Detail{Err: ErrUnsupportedCipherMode, Detail: fmt.Sprintf("%q", opts.Mode)}
	}

	if err := requireGCMNonce(data.Nonce); err != nil {
		return nil, err
	}
	tagSize, err := resolveGCMTagSize(opts.TagSize)
	if err != nil {
		return nil, err
	}
	if err := requireGCMTag(data.Tag, tagSize); err != nil {
		return nil, err
	}

	// Initialize PKCS#11 context if needed
	if e.backend.p11ctx == nil {
		return nil, &errs.Message{Msg: "PKCS#11 context not initialized"}
	}

	// Resolve the token slot the same way every other operation on this
	// backend does. Taking the first enumerated slot would ignore the
	// configured TokenLabel and silently operate on whichever token the module
	// happens to list first, which on a multi-token host is not the caller's.
	slot, err := e.backend.resolveSlot()
	if err != nil {
		return nil, err
	}

	// Open session
	session, err := e.backend.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to open session", Err: err}
	}
	defer func() {
		if closeErr := e.backend.p11ctx.CloseSession(session); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	// Login as user
	// Note: We don't logout because C_Logout affects ALL sessions, not just this one
	userPIN, err := e.backend.userPIN()
	if err != nil {
		return nil, err
	}
	if err := e.backend.p11ctx.Login(session, pkcs11.CKU_USER, userPIN); err != nil {
		if !isCKR(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			return nil, &errs.Wrapped{Msg: "failed to login", Err: err}
		}
	}
	// DO NOT LOGOUT - C_Logout affects ALL sessions on this token

	// Prepare GCM parameters for decryption. CK_GCM_PARAMS.ulTagBits is in
	// bits, not bytes, and the C allocations behind it are the caller's to
	// free (see the matching comment in Encrypt).
	gcmParams := pkcs11.NewGCMParams(data.Nonce, opts.AdditionalData, tagSize*8)
	defer gcmParams.Free()

	// Find the key handle in THIS session (handles are session-specific)
	// We must find the key in the same session where we'll use it
	label := createKeyID(e.attrs)
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	if err := e.backend.p11ctx.FindObjectsInit(session, template); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to init object search", Err: err}
	}

	handles, _, err := e.backend.p11ctx.FindObjects(session, 1)
	if err != nil {
		findFinalErr := e.backend.p11ctx.FindObjectsFinal(session) // Clean up even on error
		return nil, errors.Join(&errs.Wrapped{Msg: "failed to find objects", Err: err}, findFinalErr)
	}

	// Must finalize BEFORE starting decryption operation
	if err := e.backend.p11ctx.FindObjectsFinal(session); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to finalize object search", Err: err}
	}

	if len(handles) == 0 {
		return nil, &errs.Message{Msg: fmt.Sprintf("key not found: %s", e.attrs.CN)}
	}

	handle := handles[0]

	// Create mechanism with GCM parameters
	mechanism := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcmParams),
	}

	// PKCS#11 v3.2 6.13.2: C_Decrypt takes the ciphertext with the tag
	// appended.
	fullCiphertext := concatCiphertextAndTag(data.Ciphertext, data.Tag)

	// Decrypt the data. A refusal that is about the ciphertext -- rather than
	// the token, the session or the key -- carries ErrCiphertextRejected so
	// Unseal can report it as sealed-data authentication (see decryptGCM).
	return decryptGCM(e.backend.p11ctx, session, mechanism, handle, fullCiphertext)
}

// withKeySession opens a session on the token's resolved slot, logs in, finds
// the object handle for e.attrs' key, and calls fn with the session and
// handle. The session is closed when this returns. It exists so the
// open/login/find-object sequence -- and the rule that this backend never
// calls C_Logout, because that affects every session on the token, not just
// this one -- is written once for the three non-AEAD cipher modes, instead of
// once per mode as Encrypt and Decrypt do for AES-GCM above.
func (e *pkcs11SymmetricEncrypter) withKeySession(fn func(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) error) (err error) {
	if e.backend.p11ctx == nil {
		return &errs.Message{Msg: "PKCS#11 context not initialized"}
	}

	slot, err := e.backend.resolveSlot()
	if err != nil {
		return err
	}

	session, err := e.backend.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to open session", Err: err}
	}
	defer func() {
		if closeErr := e.backend.p11ctx.CloseSession(session); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	userPIN, err := e.backend.userPIN()
	if err != nil {
		return err
	}
	if err := e.backend.p11ctx.Login(session, pkcs11.CKU_USER, userPIN); err != nil {
		if !isCKR(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			return &errs.Wrapped{Msg: "failed to login", Err: err}
		}
	}

	label := createKeyID(e.attrs)
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	if err := e.backend.p11ctx.FindObjectsInit(session, template); err != nil {
		return &errs.Wrapped{Msg: "failed to init object search", Err: err}
	}

	handles, _, err := e.backend.p11ctx.FindObjects(session, 1)
	if err != nil {
		findFinalErr := e.backend.p11ctx.FindObjectsFinal(session) // Clean up even on error
		return errors.Join(&errs.Wrapped{Msg: "failed to find objects", Err: err}, findFinalErr)
	}

	if err := e.backend.p11ctx.FindObjectsFinal(session); err != nil {
		return &errs.Wrapped{Msg: "failed to finalize object search", Err: err}
	}

	if len(handles) == 0 {
		return &errs.Message{Msg: fmt.Sprintf("key not found: %s", e.attrs.CN)}
	}

	return fn(session, handles[0])
}

// encryptCBC implements types.CipherModeCBC (unpadded, CKM_AES_CBC) and
// types.CipherModeCBCPad (PKCS#7-padded, CKM_AES_CBC_PAD) on the HSM. Neither
// is an AEAD mode: they produce no authentication tag and accept no
// additional authenticated data. Padding for CipherModeCBCPad is applied by
// the token itself (PKCS#11 v3.2 6.10.3), never in this process, matching the
// property that the key material and its plaintext never leave the HSM.
func (e *pkcs11SymmetricEncrypter) encryptCBC(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	mechanism, err := e.backend.requireCipherMechanism(opts.Mode)
	if err != nil {
		return nil, err
	}
	if len(opts.AdditionalData) > 0 {
		return nil, ErrAdditionalDataNotSupported
	}
	// AES-CBC and AES-CBC-Pad produce no authentication tag, so a tag length
	// is not something either mode can honour.
	if opts.TagSize != 0 {
		return nil, ErrTagSizeNotSupported
	}

	iv := opts.IV
	if len(iv) == 0 {
		iv = make([]byte, cbcIVSize)
		if _, err := rand.Read(iv); err != nil {
			return nil, &errs.Wrapped{Msg: "failed to generate IV", Err: err}
		}
	} else if len(iv) != cbcIVSize {
		return nil, &errs.Detail{Err: ErrInvalidIVSize, Detail: fmt.Sprintf("got %d bytes, want %d", len(iv), cbcIVSize)}
	}

	// Unpadded CBC requires block-aligned plaintext; CKM_AES_CBC_PAD pads on
	// the token and accepts any length, including zero.
	if opts.Mode == types.CipherModeCBC && (len(plaintext) == 0 || len(plaintext)%aes.BlockSize != 0) {
		return nil, ErrPlaintextNotBlockAligned
	}

	var ciphertext []byte
	err = e.withKeySession(func(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) error {
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, iv)}
		if err := e.backend.p11ctx.EncryptInit(session, mech, handle); err != nil {
			return &errs.Wrapped{Msg: "failed to initialize encryption", Err: err}
		}
		var encErr error
		ciphertext, encErr = e.backend.p11ctx.Encrypt(session, plaintext)
		if encErr != nil {
			return &errs.Wrapped{Msg: "encryption failed", Err: encErr}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &types.EncryptedData{
		Ciphertext: ciphertext,
		IV:         iv,
		Algorithm:  string(e.attrs.SymmetricAlgorithm),
	}, nil
}

// decryptCBC implements types.CipherModeCBC and types.CipherModeCBCPad
// decryption, the inverse of encryptCBC. PKCS#7 padding removal for
// CipherModeCBCPad runs inside the HSM; a padding failure is reported by the
// token as a decryption error and reclassified here as ErrInvalidPadding.
func (e *pkcs11SymmetricEncrypter) decryptCBC(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	mechanism, err := e.backend.requireCipherMechanism(opts.Mode)
	if err != nil {
		return nil, err
	}
	if len(opts.AdditionalData) > 0 {
		return nil, ErrAdditionalDataNotSupported
	}
	if len(data.Tag) > 0 {
		return nil, &errs.Message{Msg: "pkcs11: tag is not supported for AES-CBC modes"}
	}
	if opts.TagSize != 0 {
		return nil, ErrTagSizeNotSupported
	}
	if len(data.IV) != cbcIVSize {
		return nil, &errs.Detail{Err: ErrInvalidIVSize, Detail: fmt.Sprintf("got %d bytes, want %d", len(data.IV), cbcIVSize)}
	}
	if len(data.Ciphertext) == 0 || len(data.Ciphertext)%aes.BlockSize != 0 {
		return nil, ErrCiphertextNotBlockAligned
	}

	var plaintext []byte
	err = e.withKeySession(func(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) error {
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, data.IV)}
		if err := e.backend.p11ctx.DecryptInit(session, mech, handle); err != nil {
			return &errs.Wrapped{Msg: "failed to initialize decryption", Err: err}
		}
		var decErr error
		plaintext, decErr = e.backend.p11ctx.Decrypt(session, data.Ciphertext)
		if decErr != nil {
			if opts.Mode == types.CipherModeCBCPad {
				return &errs.Detail{Err: ErrInvalidPadding, Detail: decErr.Error()}
			}
			return &errs.Wrapped{Msg: "decryption failed", Err: decErr}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// encryptECB implements types.CipherModeECB (CKM_AES_ECB) on the HSM. Each
// 16-byte block is enciphered independently: there is no IV, no chaining and
// no authentication tag.
//
// SECURITY: ECB is deterministic -- two identical plaintext blocks produce
// two identical ciphertext blocks under the same key, the structure leak the
// mode is known for. It is implemented because PKCS#11 v3.2 6.10.4 defines
// the mechanism and this backend now advertises every cipher mode the
// software symmetric provider does; a mechanism that is advertised and then
// quietly served by some other mode is worse than either offering it or
// refusing it, because the ciphertext no peer can reproduce still looks like
// success.
func (e *pkcs11SymmetricEncrypter) encryptECB(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	mechanism, err := e.backend.requireCipherMechanism(opts.Mode)
	if err != nil {
		return nil, err
	}
	if len(opts.AdditionalData) > 0 {
		return nil, ErrAdditionalDataNotSupported
	}
	if opts.TagSize != 0 {
		return nil, ErrTagSizeNotSupported
	}
	if len(opts.IV) > 0 {
		return nil, ErrIVNotSupported
	}
	if len(plaintext) == 0 || len(plaintext)%aes.BlockSize != 0 {
		return nil, ErrPlaintextNotBlockAligned
	}

	var ciphertext []byte
	err = e.withKeySession(func(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) error {
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, nil)}
		if err := e.backend.p11ctx.EncryptInit(session, mech, handle); err != nil {
			return &errs.Wrapped{Msg: "failed to initialize encryption", Err: err}
		}
		var encErr error
		ciphertext, encErr = e.backend.p11ctx.Encrypt(session, plaintext)
		if encErr != nil {
			return &errs.Wrapped{Msg: "encryption failed", Err: encErr}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &types.EncryptedData{
		Ciphertext: ciphertext,
		Algorithm:  string(e.attrs.SymmetricAlgorithm),
	}, nil
}

// decryptECB implements types.CipherModeECB decryption, the inverse of
// encryptECB.
func (e *pkcs11SymmetricEncrypter) decryptECB(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	mechanism, err := e.backend.requireCipherMechanism(opts.Mode)
	if err != nil {
		return nil, err
	}
	if len(opts.AdditionalData) > 0 {
		return nil, ErrAdditionalDataNotSupported
	}
	if len(data.Tag) > 0 {
		return nil, &errs.Message{Msg: "pkcs11: tag is not supported for AES-ECB"}
	}
	if opts.TagSize != 0 {
		return nil, ErrTagSizeNotSupported
	}
	// An IV on the wire means the ciphertext was produced by some other mode,
	// or the caller believes ECB uses one. Either way, decrypting it as ECB
	// would return plausible-looking garbage rather than an error.
	if len(data.IV) > 0 {
		return nil, ErrIVNotSupported
	}
	if len(data.Ciphertext) == 0 || len(data.Ciphertext)%aes.BlockSize != 0 {
		return nil, ErrCiphertextNotBlockAligned
	}

	var plaintext []byte
	err = e.withKeySession(func(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) error {
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, nil)}
		if err := e.backend.p11ctx.DecryptInit(session, mech, handle); err != nil {
			return &errs.Wrapped{Msg: "failed to initialize decryption", Err: err}
		}
		var decErr error
		plaintext, decErr = e.backend.p11ctx.Decrypt(session, data.Ciphertext)
		if decErr != nil {
			return &errs.Wrapped{Msg: "decryption failed", Err: decErr}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// aesGCMAlgorithms are the symmetric algorithms this backend implements.
//
// Every operation here runs CKM_AES_KEY_GEN and CKM_AES_GCM, so only AES-GCM
// belongs in the set. The ChaCha20-Poly1305 algorithms must not be silently
// accepted: types.SymmetricAlgorithm.KeySize reports 256 bits for them, so
// without this check a request for XChaCha20-Poly1305 would generate an AES key
// and encrypt it under AES-GCM with a 12-byte nonce instead of XChaCha20's
// 24-byte nonce, while reporting the caller's algorithm back to them.
var aesGCMAlgorithms = map[types.SymmetricAlgorithm]struct{}{
	types.SymmetricAES128GCM: {},
	types.SymmetricAES192GCM: {},
	types.SymmetricAES256GCM: {},
}

// requireAESGCMAlgorithm rejects any symmetric algorithm other than AES-GCM.
func requireAESGCMAlgorithm(algorithm types.SymmetricAlgorithm) error {
	if _, ok := aesGCMAlgorithms[algorithm]; ok {
		return nil
	}
	return &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf(
		"%s; the PKCS#11 backend implements AES-GCM only", algorithm)}
}

// GenerateSymmetricKey generates a new AES symmetric key on the HSM.
// The key material never leaves the hardware security module.
func (b *Backend) GenerateSymmetricKey(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	if err := attrs.Validate(); err != nil {
		return nil, &errs.Wrapped{Msg: "invalid attributes", Err: err}
	}

	if !attrs.IsSymmetric() {
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("attributes specify asymmetric algorithm %s", attrs.KeyAlgorithm)}
	}
	if err := requireAESGCMAlgorithm(attrs.SymmetricAlgorithm); err != nil {
		return nil, err
	}

	// requireAESGCMAlgorithm above restricts the algorithm to the three AES-GCM
	// variants, so the key size is one of 128, 192 or 256 by construction.
	// GenerateSecretKey remains the single authority on which of those the
	// token key generation path actually accepts.
	keySize := attrs.SymmetricAlgorithm.KeySize()

	// Generate the secret key on the HSM
	handle, err := b.GenerateSecretKey(attrs, keySize)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate symmetric key", Err: err}
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
		algorithm: string(attrs.SymmetricAlgorithm),
		keySize:   keySize,
		handle:    handle,
		backend:   b,
	}, nil
}

// GetSymmetricKey retrieves an existing symmetric key from the HSM.
func (b *Backend) GetSymmetricKey(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	if err := attrs.Validate(); err != nil {
		return nil, &errs.Wrapped{Msg: "invalid attributes", Err: err}
	}

	if !attrs.IsSymmetric() {
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("attributes specify asymmetric algorithm %s", attrs.KeyAlgorithm)}
	}
	if err := requireAESGCMAlgorithm(attrs.SymmetricAlgorithm); err != nil {
		return nil, err
	}

	// Find the secret key on the HSM
	handle, err := b.FindSecretKey(attrs)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to find symmetric key", Err: err}
	}

	// requireAESGCMAlgorithm above has already established that the algorithm
	// is one of the three AES-GCM variants, so the key size is known.
	keySize := attrs.SymmetricAlgorithm.KeySize()

	return &pkcs11SymmetricKey{
		algorithm: string(attrs.SymmetricAlgorithm),
		keySize:   keySize,
		handle:    handle,
		backend:   b,
	}, nil
}

// SymmetricEncrypter returns a SymmetricEncrypter for the specified key.
// This allows encryption/decryption operations without exposing key material.
func (b *Backend) SymmetricEncrypter(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	// Get the symmetric key to ensure it exists and get the handle
	key, err := b.GetSymmetricKey(ctx, attrs)
	if err != nil {
		return nil, err
	}

	// Type assert to get the PKCS#11-specific key
	pkcs11Key, ok := key.(*pkcs11SymmetricKey)
	if !ok {
		return nil, &errs.Message{Msg: "unexpected key type"}
	}

	return &pkcs11SymmetricEncrypter{
		backend: b,
		attrs:   attrs,
		handle:  pkcs11Key.handle,
	}, nil
}

// GetTracker returns the AEAD safety tracker for this backend.
// This allows external code to inspect tracking state and configuration.
func (b *Backend) GetTracker() types.AEADSafetyTracker {
	return b.tracker
}

// Verify interface compliance at compile time
var _ types.SymmetricKeyProvider = (*Backend)(nil)
var _ types.SymmetricKeyProviderWithTracking = (*Backend)(nil)
var _ types.SymmetricKey = (*pkcs11SymmetricKey)(nil)
var _ types.SymmetricEncrypter = (*pkcs11SymmetricEncrypter)(nil)
