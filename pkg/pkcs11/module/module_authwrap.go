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

// Package module provides PKCS#11 (Cryptoki) v3.2 authenticated key wrapping operations.
//
// This file implements the PKCS#11 v3.2 C_WrapKeyAuthenticated and
// C_UnwrapKeyAuthenticated functions using AES-GCM as the AEAD mechanism.
// Authenticated wrapping integrates the authentication tag into the ciphertext,
// with optional associated data for additional authenticated context.
//
// Mechanism parameter handling:
//
// PKCS#11 v3.2 section 5.18.6 defines C_WrapKeyAuthenticated and
// C_UnwrapKeyAuthenticated in terms of the CK_*_MESSAGE_PARAMS structures, and
// its own example passes CK_GCM_MESSAGE_PARAMS. That is the structure the C
// ABI hands this file, and it is the framing a spec-conforming application
// gets: AESGCMMessageParams. The older AESGCMParams (CK_GCM_PARAMS, the
// structure C_EncryptInit takes) is still accepted for Go callers inside this
// repository, and a mechanism carrying no parameter at all is accepted too.
//
// The authentication tag length is the one named by ulTagBits (v3.2 section
// 6.13.5 for CK_GCM_MESSAGE_PARAMS, section 6.13.7 for CK_GCM_PARAMS),
// defaulting to the full 128 bits when the caller names none; authWrapTagSize
// resolves it for the wrap, the unwrap and the size query alike, always from
// the mechanism the caller supplied and never from the wrapped blob that
// arrived.
//
// Output framing, which follows from who owns the IV:
//
//   - CK_GCM_MESSAGE_PARAMS: the wrapped blob is always
//
//     ciphertext || GCM tag
//
//     The IV is never prepended. When ivGenerator is CKG_NO_GENERATE the
//     caller supplied it; otherwise the token generates it and writes it back
//     through pIv, which section 6.13.5 makes an output of the call. This is
//     the framing every other PKCS#11 token produces, and it is what lets a
//     token-generated IV -- the construction that cannot be replayed -- be the
//     default for a spec-conforming application.
//
//   - CK_GCM_PARAMS with a non-empty IV: ciphertext || GCM tag, for the same
//     reason: the caller already knows the IV.
//
//   - CK_GCM_PARAMS with no IV, or no mechanism parameter at all: there is
//     nowhere to hand a generated IV back, so it is carried in the blob:
//
//     nonce (12 bytes) || ciphertext || GCM tag
//
//     This framing is local to this module. It exists only for the two forms
//     that cannot return an IV out of band, and UnwrapKeyAuthenticated reads
//     it back under exactly the same two forms.
//
// Nonce reuse:
//
// AES-GCM is performed in this file rather than through CryptoManager, so the
// reuse check CryptoManager applies to C_Encrypt does not cover it. Every wrap
// here consults the process-wide aead.SharedAEADNonceGuard instead, keyed by
// the wrapping key's own material, before it seals. Two wraps under one
// (key, IV) leak the XOR of their plaintexts (NIST SP 800-38D section 8.2),
// and the plaintext of a key wrap is key material, so the pair is refused with
// CKR_MECHANISM_PARAM_INVALID rather than performed.
//
// Functions:
//   - WrapKeyAuthenticated: C_WrapKeyAuthenticated -- wrap a key with AES-GCM AEAD
//   - WrapKeyAuthenticatedSize: size query for C_WrapKeyAuthenticated (pWrappedKey == NULL)
//   - UnwrapKeyAuthenticated: C_UnwrapKeyAuthenticated -- unwrap a key with AES-GCM AEAD verification
//
// References:
//   - OASIS PKCS#11 v3.2: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html
//   - NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: GCM
package module

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
)

// validAESKeySize reports whether keyLen is a valid AES key length (16, 24, or 32 bytes).
func validAESKeySize(keyLen int) bool {
	return keyLen == 16 || keyLen == 24 || keyLen == 32
}

// requireWrappingKeyStrength refuses a wrap whose key encryption key is weaker
// than the key it would carry.
//
// The confidentiality of a wrapped key is the confidentiality of the KEK, so an
// AES-128 KEK over an AES-256 key exports that key at 128-bit strength while the
// application still believes it holds a 256-bit secret -- and the token reported
// CKR_OK. NIST SP 800-57 Part 1 Rev. 5 §5.6.2 states the rule directly: a key
// shall not be protected by a key of lesser strength.
//
// Both values are AES key material here, so comparing byte lengths compares
// strengths. The code is CKR_WRAPPING_KEY_SIZE_RANGE because it names what the
// caller has to change -- a longer wrapping key.
func requireWrappingKeyStrength(wrappingKeyValue, targetKeyValue []byte) error {
	if len(wrappingKeyValue) >= len(targetKeyValue) {
		return nil
	}
	return NewPKCS11ErrorWithMessage(CKR_WRAPPING_KEY_SIZE_RANGE,
		"the wrapping key is shorter than the key being wrapped; a key must not be protected by a key of lesser strength")
}

// authWrapTagSize resolves the AES-GCM authentication tag length, in bytes,
// that an authenticated wrap or unwrap must frame with, from the mechanism's
// CK_GCM_PARAMS.ulTagBits (PKCS#11 v3.2 §6.13.3). A mechanism that carries no
// parameters, or names no tag length, gets the full 128-bit tag.
//
// The length comes from the mechanism the CALLER supplied on this call, never
// from the wrapped blob that arrived. Sizing the tag from the bundle would let
// whoever produced it choose how many bits get verified: SP 800-38D §5.2.2
// authenticates by recomputing the tag at t bits and comparing, so a forgery
// carrying a short tag would be checked at exactly the strength the forger
// picked. Deriving t from the request instead means a bundle whose tag is not
// the length this session asked for fails, which is the intended outcome.
//
// Wrap and unwrap resolve through this one function, and the size query
// resolves through it too, so the three cannot disagree about the length of
// the same tag -- a disagreement that presents as CKR_AEAD_DECRYPT_FAILED on
// a round trip that was never tampered with.
//
// It shares resolveGCMTagSize with the ordinary C_Encrypt/C_Decrypt path
// rather than restating the approved lengths, so there is one tag-length
// vocabulary in the module and not two.
func authWrapTagSize(mechanism *Mechanism) (int, error) {
	tagBits, ok := authWrapTagBits(mechanism)
	if !ok {
		return GCMTagSize, nil
	}
	size, err := resolveGCMTagSize(tagBits)
	if err != nil {
		return 0, err
	}
	return gcmTagSize(size), nil
}

// authWrapTagBits returns the ulTagBits field of whichever GCM parameter
// structure the mechanism carries, and false when it carries neither.
//
// The authenticated wrap verbs take CK_GCM_MESSAGE_PARAMS (PKCS#11 v3.2
// section 5.18.6, whose example passes exactly that structure) and this module
// additionally accepts CK_GCM_PARAMS from its Go callers. Both name the tag
// length in a ulTagBits field with the same meaning, so the length is read
// through one function and the two structures cannot resolve it differently.
func authWrapTagBits(mechanism *Mechanism) (uint32, bool) {
	if params, ok := mechanism.GetAESGCMMessageParams(); ok {
		return params.TagBits, true
	}
	if params, ok := mechanism.GetAESGCMParams(); ok {
		return params.TagBits, true
	}
	return 0, false
}

// generateGCMNonce returns a fresh random 12-byte AES-GCM nonce.
//
// Twelve bytes is the length NIST SP 800-38D section 8.2.2 defines the random
// IV construction for, and the only length this module accepts, so a
// token-generated nonce and a caller-supplied one are interchangeable
// everywhere below.
func generateGCMNonce() ([]byte, error) {
	nonce := make([]byte, GCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, NewPKCS11ErrorFull(CKR_RANDOM_NO_RNG, "failed to generate nonce", err)
	}
	return nonce, nil
}

// guardGCMNonce refuses an AES-GCM (key material, nonce) pair that has already
// been sealed under in this process.
//
// This file performs AES-GCM in process, so the reuse check CryptoManager
// applies to C_Encrypt never sees these nonces: the guard consulted here is
// the process-wide one in pkg/crypto/aead, which every AES-GCM path that
// accepts a caller-supplied IV can reach regardless of which object owns it.
// This file's callers key it by the wrapping key's own CKA_VALUE rather than by
// its handle, because the same key material reachable under two handles, two
// sessions or two slots is one key as far as NIST SP 800-38D section 8.2 is
// concerned.
//
// It is not this file's guard alone. CryptoManager.checkGCMNonce (crypto.go)
// delegates here for C_Encrypt and C_WrapKey, keying on the domain-separated
// (backend, key id) identity of a key whose material this process never holds.
// The refusal therefore has to read for every AES-GCM operation that consumes a
// nonce, not for a wrap alone.
//
// The code is CKR_MECHANISM_PARAM_INVALID, which is both what the C_Encrypt
// path answers for the same condition and the accurate description: the IV in
// the mechanism parameter is the field the caller has to change.
func guardGCMNonce(keyMaterial, nonce []byte) error {
	guard, err := aead.SharedAEADNonceGuard()
	if err != nil {
		return NewPKCS11ErrorFull(CKR_RANDOM_NO_RNG,
			"failed to initialize the AES-GCM IV reuse guard", err)
	}

	useErr := guard.Use(keyMaterial, nonce)
	switch {
	case useErr == nil:
		return nil
	case errors.Is(useErr, aead.ErrNonceReuse):
		return NewPKCS11ErrorFull(CKR_MECHANISM_PARAM_INVALID,
			"AES-GCM IV has already been used for this key; a fresh IV is required for every encryption or wrap under it", useErr)
	case errors.Is(useErr, aead.ErrNonceTrackerFull):
		return NewPKCS11ErrorFull(CKR_MECHANISM_PARAM_INVALID,
			"the AES-GCM IV reuse tracker is full; reinitialize the module or rotate the wrapping key", useErr)
	default:
		return NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"failed to check the AES-GCM IV for reuse", useErr)
	}
}

// authWrapFIPSRefusal returns the refusal for an authenticated wrap or unwrap
// this process cannot perform, or nil.
//
// Under GODEBUG=fips140=only crypto/cipher seals GCM only through
// cipher.NewGCMWithRandomNonce: the module's approved DRBG draws the 96-bit IV
// (the RBG-based construction of NIST SP 800-38D section 8.2.2) and the tag is
// the full 128 bits. A token-generated IV is that construction, so it is still
// sealed; a caller-supplied IV and a truncated tag are not available to seal
// with, and are refused here as the parameters this token cannot honour. An
// unwrap opens any 12-byte IV, but only under the full tag. Outside
// fips140=only every form stays available.
//
// The gate is a runtime probe rather than a FIPS predicate because no exported
// predicate distinguishes fips140=only from fips140=on, where an arbitrary IV
// still works; see aead.ArbitraryIVGCMUsable. A tag length that does not
// resolve is left for authWrapTagSize to report in its own position.
func authWrapFIPSRefusal(mechanism *Mechanism, sealing bool) error {
	if aead.ArbitraryIVGCMUsable() {
		return nil
	}
	tagSize, err := authWrapTagSize(mechanism)
	if err != nil {
		return nil
	}
	if tagSize != aead.GCMFullTagSize {
		return NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"this FIPS 140-only process authenticates CKM_AES_GCM wrapping with the full 128-bit tag only")
	}
	if sealing && authWrapCallerIV(mechanism) {
		return NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"this FIPS 140-only process seals CKM_AES_GCM wrapping only under a token-generated IV")
	}
	return nil
}

// authWrapCallerIV reports whether the mechanism asks a wrap to seal under an
// IV the caller supplies rather than one the token generates.
func authWrapCallerIV(mechanism *Mechanism) bool {
	if msgParams, ok := mechanism.GetAESGCMMessageParams(); ok {
		return msgParams.IVGenerator == CKG_NO_GENERATE
	}
	if gcmParams, ok := mechanism.GetAESGCMParams(); ok {
		return len(gcmParams.IV) > 0
	}
	return false
}

// sealAuthWrap seals plaintext under block and returns the nonce it sealed
// under and ciphertext||tag. A nil nonce asks the token to generate one:
// through cipher.NewGCMWithRandomNonce in a FIPS 140-only process, and from
// crypto/rand otherwise.
//
// The (key, nonce) pair is claimed before it is released: sealing twice under
// one pair leaks the XOR of the two plaintexts, and here both plaintexts are
// key material. Where the token draws the nonce itself it is claimed before
// sealing, so a wrap refused for reuse burns nothing; where the stdlib draws
// it the claim follows the seal and a refused output is wiped unreleased.
func sealAuthWrap(block cipher.Block, tagSize int, keyMaterial, nonce, plaintext, aad []byte) (usedNonce, sealed []byte, err error) {
	gcm, randomNonce, err := aead.NewGCMForFreshEncrypt(block, tagSize, nonce != nil)
	if err != nil {
		return nil, nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED, "failed to create GCM", err)
	}

	if randomNonce {
		out := gcm.Seal(nil, nil, plaintext, aad)
		usedNonce = out[:aead.GCMRandomNonceSize]
		if err := guardGCMNonce(keyMaterial, usedNonce); err != nil {
			enclave.Wipe(out)
			return nil, nil, err
		}
		return usedNonce, out[aead.GCMRandomNonceSize:], nil
	}

	if nonce == nil {
		nonce, err = generateGCMNonce()
		if err != nil {
			return nil, nil, err
		}
	}
	if err := guardGCMNonce(keyMaterial, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

// openAuthWrap opens ciphertext||tag sealed under nonce. A FIPS 140-only
// process opens it through cipher.NewGCMWithRandomNonce, which verifies any
// 12-byte nonce carried at the head of its input; authWrapFIPSRefusal has
// already limited that case to the full tag.
func openAuthWrap(block cipher.Block, tagSize int, nonce, ciphertextWithTag, aad []byte) ([]byte, error) {
	randomNonce := !aead.ArbitraryIVGCMUsable()
	gcm, err := aead.NewGCMForDecrypt(block, tagSize, randomNonce)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED, "failed to create GCM", err)
	}

	var plaintext []byte
	if randomNonce {
		plaintext, err = gcm.Open(nil, nil, aead.JoinGCMWithRandomNonce(nonce, ciphertextWithTag, nil), aad)
	} else {
		plaintext, err = gcm.Open(nil, nonce, ciphertextWithTag, aad)
	}
	if err != nil {
		return nil, NewPKCS11Error(CKR_AEAD_DECRYPT_FAILED)
	}
	return plaintext, nil
}

// authWrapNonce resolves the AES-GCM nonce a wrap seals with, the AAD it
// authenticates, and whether the nonce has to be carried in the wrapped blob.
//
// prefixNonce is true only for the two parameter forms that give the token
// nowhere to hand a generated IV back -- CK_GCM_PARAMS with an empty IV, and
// no mechanism parameter at all. The CK_GCM_MESSAGE_PARAMS form of PKCS#11
// v3.2 section 5.18.6 always returns ciphertext||tag, because section 6.13.5
// makes pIv an output of the call whenever ivGenerator asks the token to
// generate one.
//
// nonce is nil when the token generates the IV: sealAuthWrap draws it, and
// WrapKeyAuthenticated writes it back into CK_GCM_MESSAGE_PARAMS.pIv, which is
// what the C ABI copies into the caller's buffer after a successful wrap.
func authWrapNonce(mechanism *Mechanism, associatedData []byte) (nonce, aad []byte, prefixNonce bool, err error) {
	aad = associatedData

	if msgParams, ok := mechanism.GetAESGCMMessageParams(); ok {
		nonce, err = messageParamsWrapNonce(msgParams)
		if err != nil {
			return nil, nil, false, err
		}
		// CK_GCM_MESSAGE_PARAMS has no AAD field: C_WrapKeyAuthenticated
		// carries the associated data in its own pAssociatedData argument
		// (v3.2 section 5.18.6), which is what aad already holds.
		return nonce, aad, false, nil
	}

	if gcmParams, ok := mechanism.GetAESGCMParams(); ok {
		// AAD from the parameter takes precedence over the function argument.
		if gcmParams.AAD != nil {
			aad = gcmParams.AAD
		}
		if len(gcmParams.IV) > 0 {
			if len(gcmParams.IV) != GCMNonceSize {
				return nil, nil, false, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
					"GCM IV must be 12 bytes")
			}
			nonce = make([]byte, GCMNonceSize)
			copy(nonce, gcmParams.IV)
			return nonce, aad, false, nil
		}
	}

	return nil, aad, true, nil
}

// messageParamsWrapNonce resolves the nonce for a CK_GCM_MESSAGE_PARAMS wrap.
// It returns nil when the token is the one generating it; the generated IV is
// written back into the parameter after sealing so the caller can learn it
// (PKCS#11 v3.2 section 6.13.5 makes pIv an output whenever ivGenerator is not
// CKG_NO_GENERATE).
//
// A token-generated IV is refused when the caller left no buffer for it: the
// wrap would otherwise succeed and produce a blob whose IV nobody can ever
// recover, which is a wrapped key that can never be unwrapped.
//
// ulIvFixedBits and CKG_GENERATE_COUNTER are refused rather than ignored.
// Preserving caller-fixed leading bits, or counting, are IV constructions this
// token does not implement, and quietly substituting a fully random IV would
// report a request as honoured that was not -- for a counter construction it
// would also hide that the token holds no durable counter state across
// restarts, which is precisely how a counter IV repeats.
func messageParamsWrapNonce(params *AESGCMMessageParams) ([]byte, error) {
	if params.IVGenerator == CKG_NO_GENERATE {
		if len(params.IV) != GCMNonceSize {
			return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
				"CK_GCM_MESSAGE_PARAMS.pIv must supply a 12-byte IV when ivGenerator is CKG_NO_GENERATE")
		}
		nonce := make([]byte, GCMNonceSize)
		copy(nonce, params.IV)
		return nonce, nil
	}

	if params.IVGenerator == CKG_GENERATE_COUNTER {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CKG_GENERATE_COUNTER is not supported; this token generates random 12-byte IVs")
	}
	if params.IVFixedBits != 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CK_GCM_MESSAGE_PARAMS.ulIvFixedBits must be 0; this token cannot preserve caller-fixed IV bits")
	}

	if len(params.IV) < GCMNonceSize {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CK_GCM_MESSAGE_PARAMS.pIv must supply a buffer of at least 12 bytes for a token-generated IV")
	}

	return nil, nil
}

// authUnwrapNonce resolves the nonce an unwrap verifies with and splits the
// wrapped blob accordingly. It is the exact inverse of authWrapNonce: the two
// parameter forms that let the wrap prepend the nonce are the two forms that
// read it back out of the blob here.
func authUnwrapNonce(mechanism *Mechanism, wrappedKey []byte, tagSize int, associatedData []byte) (nonce, ciphertextWithTag, aad []byte, err error) {
	aad = associatedData

	if msgParams, ok := mechanism.GetAESGCMMessageParams(); ok {
		// Decryption never generates an IV (v3.2 section 6.13.5): the caller
		// must present the exact nonce the wrap used, or the blob cannot be
		// opened at all.
		if msgParams.IVGenerator != CKG_NO_GENERATE {
			return nil, nil, nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
				"CK_GCM_MESSAGE_PARAMS.ivGenerator must be CKG_NO_GENERATE when unwrapping")
		}
		if len(msgParams.IV) != GCMNonceSize {
			return nil, nil, nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
				"CK_GCM_MESSAGE_PARAMS.pIv must supply the 12-byte IV the wrap used")
		}
		if len(wrappedKey) < tagSize+1 {
			return nil, nil, nil, NewPKCS11Error(CKR_WRAPPED_KEY_INVALID)
		}
		nonce = make([]byte, GCMNonceSize)
		copy(nonce, msgParams.IV)
		return nonce, wrappedKey, aad, nil
	}

	// CK_GCM_PARAMS.pAAD takes precedence over the associatedData argument on
	// this side exactly as it does in WrapKeyAuthenticated, and independently
	// of whether the caller also supplied an IV. The precedence used to be
	// nested inside the caller-supplied-IV branch below, so a caller that put
	// its AAD in the mechanism and let the token generate the IV -- the
	// documented default framing -- sealed under that AAD and then verified
	// under none. Every such round trip failed with CKR_AEAD_DECRYPT_FAILED,
	// which reads as a forgery rather than as the two halves authenticating
	// different inputs.
	gcmParams, hasGCMParams := mechanism.GetAESGCMParams()
	if hasGCMParams && gcmParams.AAD != nil {
		aad = gcmParams.AAD
	}

	if hasGCMParams && len(gcmParams.IV) > 0 {
		// Caller-supplied nonce: wrappedKey is just ciphertext||tag.
		if len(gcmParams.IV) != GCMNonceSize {
			return nil, nil, nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
				"GCM IV must be 12 bytes")
		}
		// Minimum: at least 1 byte ciphertext + the tag length resolved above.
		if len(wrappedKey) < tagSize+1 {
			return nil, nil, nil, NewPKCS11Error(CKR_WRAPPED_KEY_INVALID)
		}
		nonce = make([]byte, GCMNonceSize)
		copy(nonce, gcmParams.IV)
		return nonce, wrappedKey, aad, nil
	}

	// No caller-supplied nonce: extract from the wrappedKey prefix.
	// Minimum: nonce (12) + at least 1 byte ciphertext + the tag length
	// resolved above. Holding this at the full-tag GCMMinCiphertextSize
	// rejected every legitimate short-tag bundle in the 12-byte window
	// between the two lengths, before the tag was ever verified.
	if len(wrappedKey) < GCMNonceSize+tagSize+1 {
		return nil, nil, nil, NewPKCS11Error(CKR_WRAPPED_KEY_INVALID)
	}
	return wrappedKey[:GCMNonceSize], wrappedKey[GCMNonceSize:], aad, nil
}

// WrapKeyAuthenticated wraps a key using an AEAD mechanism, providing both
// confidentiality and integrity protection for the exported key material.
// The authentication tag is integrated into the returned wrapped key ciphertext.
//
// This implements C_WrapKeyAuthenticated per PKCS#11 v3.2 specification.
// Optional associated data provides additional authenticated context that
// is integrity-protected but not encrypted.
//
// The session must be logged in when the token advertises
// CKF_LOGIN_REQUIRED, and it must be read-write. The wrapping key must have
// CKA_WRAP set to true, the target key must have CKA_EXTRACTABLE set to true,
// and a target marked CKA_WRAP_WITH_TRUSTED may only be wrapped by a key the
// token has marked CKA_TRUSTED (v3.2 §4.9). These are the gates C_WrapKey
// applies, enforced here in the same order and with the same return codes.
//
// Only AES-GCM (CKM_AES_GCM) is supported as the wrapping mechanism. The
// wrapping key must be a valid AES key (16, 24, or 32 bytes of CKA_VALUE).
//
// When the mechanism carries AESGCMParams with a non-empty IV, that IV is
// used directly and the output is ciphertext || tag (no nonce prefix).
// When AESGCMParams provides AAD, it takes precedence over the associatedData
// function argument.
//
// When no AESGCMParams are provided (or the IV is empty), a random 12-byte
// nonce is generated and the output format is:
//
//	nonce (12 bytes) || ciphertext || GCM tag (CK_GCM_WRAP_PARAMS.ulTagBits, 16 bytes by default)
//
// Parameters:
//   - sessionHandle: the session handle
//   - mechanism: the wrapping mechanism (must be CKM_AES_GCM)
//   - wrappingKeyHandle: handle to the AES key used for wrapping
//   - keyHandle: handle to the key to be wrapped (must be extractable)
//   - associatedData: optional additional authenticated data (AAD); may be nil
//
// Returns:
//   - []byte: the wrapped key material
//   - error: nil on success, or a PKCS11Error
func (m *Module) WrapKeyAuthenticated(sessionHandle SessionHandle, mechanism *Mechanism, wrappingKeyHandle ObjectHandle, keyHandle ObjectHandle, associatedData []byte) ([]byte, error) {
	if !m.initialized.Load() {
		return nil, NewPKCS11Error(CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	// A read lock is the right lock here: this function mutates no module-level
	// state. It reads m.sessionManagers and m.objectManager, and an RWMutex read
	// lock already excludes every writer -- C_SetAttributeValue, C_WrapKey and
	// C_Finalize all take m.mu.Lock -- so none of them can interleave with the
	// wrap. Two concurrent authenticated wraps may proceed together, which is
	// safe because neither writes anything: see UnwrapKeyAuthenticated for the
	// side that does mutate and why its own locks cover it.
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Validate session exists and is R/W
	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}

	// The token's CKF_LOGIN_REQUIRED gates key management just as it gates the
	// crypto operations; which verb the caller uses must not change the policy.
	// C_WrapKeyAuthenticated is an export path for key material, so the
	// authenticated form cannot be the one that skips authentication: without
	// this an unauthenticated session reached the same wrapped key bytes
	// C_WrapKey refuses it. It sits immediately after the session lookup, the
	// position C_WrapKey puts it in, so the two functions refuse in the same
	// order.
	if rv := m.requireLogin(slotID, session); rv != CKR_OK {
		return nil, NewPKCS11Error(rv)
	}

	// Validate mechanism is provided
	if mechanism == nil {
		return nil, NewPKCS11Error(CKR_ARGUMENTS_BAD)
	}

	// Validate mechanism type is AES-GCM
	if mechanism.Type != CKM_AES_GCM {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"authenticated wrapping requires CKM_AES_GCM mechanism")
	}

	// Under GODEBUG=fips140=only the token seals only the wrap forms the
	// stdlib can build; see authWrapFIPSRefusal. The mechanism descriptor is
	// deliberately NOT withheld: CKM_AES_GCM's C_Encrypt/C_Decrypt/C_WrapKey
	// surface performs its GCM in the service process, whose own FIPS posture
	// governs it.
	if err := authWrapFIPSRefusal(mechanism, true); err != nil {
		return nil, err
	}

	// Validate session is read-write
	if !session.IsReadWrite() {
		return nil, NewPKCS11Error(CKR_SESSION_READ_ONLY)
	}

	// Resolve both handles through the session's access context. Wrapping is an
	// export path, so an unauthenticated or cross-slot session must not be able
	// to name a private key here and carry its material out.
	access := NewAccessContext(sessionHandle, session)

	wrappingKey, err := m.objectManager.GetObjectFor(access, wrappingKeyHandle)
	if err != nil {
		return nil, NewPKCS11Error(CKR_WRAPPING_KEY_HANDLE_INVALID)
	}

	targetKey, err := m.objectManager.GetObjectFor(access, keyHandle)
	if err != nil {
		return nil, NewPKCS11Error(CKR_KEY_HANDLE_INVALID)
	}

	// Validate wrapping key has CKA_WRAP attribute set to true.
	//
	// The code is CKR_KEY_FUNCTION_NOT_PERMITTED, for the reason C_WrapKey
	// gives: PKCS#11 v3.2 §5.1.6 defines it as a key used for a purpose its
	// attributes do not allow, and defines CKR_WRAPPING_KEY_TYPE_INCONSISTENT
	// as a key type inconsistent with the mechanism, which a correctly typed
	// key lacking CKA_WRAP is not (§5.1.7, §5.18.6).
	if !isBoolAttributeTrue(wrappingKey, CKA_WRAP) {
		return nil, NewPKCS11ErrorWithMessage(CKR_KEY_FUNCTION_NOT_PERMITTED,
			"wrapping key does not have CKA_WRAP set to true")
	}

	// CKA_EXTRACTABLE MUST be CK_TRUE on the key being wrapped. Wrapping is an
	// export path, so a key that was never marked extractable must not leave.
	//
	// The code is CKR_KEY_UNEXTRACTABLE, which is what C_WrapKey answers for the
	// same condition and what v3.2 §5.1 defines it as. CKR_KEY_NOT_WRAPPABLE
	// means the opposite -- the key is extractable but the token cannot wrap it
	// as requested -- so answering with it here told an application to change
	// the mechanism when what it had to change was the key's attributes, and
	// made the two wrap verbs report different causes for one condition.
	if !boolAttributeIsTrue(targetKey.GetAttribute(CKA_EXTRACTABLE)) {
		return nil, NewPKCS11Error(CKR_KEY_UNEXTRACTABLE)
	}

	// A key marked CKA_WRAP_WITH_TRUSTED may only be wrapped by a key the token
	// itself has marked CKA_TRUSTED (v3.2 §4.9). The attribute exists precisely
	// to name the small set of wrapping keys a sensitive key may be exported
	// under; a wrap verb that does not consult it hands the material to any key
	// carrying CKA_WRAP, which is every wrapping key on the token.
	if boolAttributeIsTrue(targetKey.GetAttribute(CKA_WRAP_WITH_TRUSTED)) &&
		!boolAttributeIsTrue(wrappingKey.GetAttribute(CKA_TRUSTED)) {
		return nil, NewPKCS11ErrorWithMessage(CKR_KEY_NOT_WRAPPABLE,
			"target key is CKA_WRAP_WITH_TRUSTED and the wrapping key is not CKA_TRUSTED")
	}

	// CKA_WRAP_TEMPLATE partitions a wrapping key so it may wrap only the
	// subset of keys whose attributes match (v3.2 §5.14.3).
	if tmplErr := wrappingKey.CheckWrapTemplate(targetKey); tmplErr != nil {
		return nil, tmplErr
	}

	// CKA_ALLOWED_MECHANISMS on the wrapping key names the mechanisms that key
	// may be used with, authenticated wrapping included (v3.2 §4.8.2).
	if mechErr := wrappingKey.CheckAllowedMechanism(mechanism.Type); mechErr != nil {
		return nil, mechErr
	}

	// Get wrapping key material (CKA_VALUE) and copy to a local buffer
	// so the deferred enclave.Wipe does not corrupt the object store.
	wrappingKeyRef := wrappingKey.GetAttribute(CKA_VALUE)
	if len(wrappingKeyRef) == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_WRAPPING_KEY_HANDLE_INVALID,
			"wrapping key has no CKA_VALUE")
	}
	wrappingKeyValue := make([]byte, len(wrappingKeyRef))
	copy(wrappingKeyValue, wrappingKeyRef)
	defer enclave.Wipe(wrappingKeyValue)

	// Validate AES key size (16, 24, or 32 bytes)
	if !validAESKeySize(len(wrappingKeyValue)) {
		return nil, NewPKCS11Error(CKR_WRAPPING_KEY_SIZE_RANGE)
	}

	// Get target key material to wrap (CKA_VALUE) and copy to a local buffer
	// so the deferred enclave.Wipe does not corrupt the object store.
	targetKeyRef := targetKey.GetAttribute(CKA_VALUE)
	if len(targetKeyRef) == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_KEY_NOT_WRAPPABLE,
			"target key has no CKA_VALUE to wrap")
	}
	targetKeyValue := make([]byte, len(targetKeyRef))
	copy(targetKeyValue, targetKeyRef)
	defer enclave.Wipe(targetKeyValue)

	if err := requireWrappingKeyStrength(wrappingKeyValue, targetKeyValue); err != nil {
		return nil, err
	}

	// The tag length the caller asked for in CK_GCM_WRAP_PARAMS.ulTagBits.
	// Resolved before the cipher is built, because it is what the cipher is
	// built with: sealing at a fixed 128 bits and reporting the request as
	// honoured produced a bundle no peer expecting the requested length could
	// authenticate.
	tagSize, err := authWrapTagSize(mechanism)
	if err != nil {
		return nil, err
	}

	// Perform AES-GCM AEAD wrapping
	block, err := aes.NewCipher(wrappingKeyValue)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED, "failed to create AES cipher", err)
	}

	// Resolve the nonce, the AAD and the output framing from whichever GCM
	// parameter structure the mechanism carries.
	nonce, aad, prefixNonce, err := authWrapNonce(mechanism, associatedData)
	if err != nil {
		return nil, err
	}

	nonce, sealed, err := sealAuthWrap(block, tagSize, wrappingKeyValue, nonce, targetKeyValue, aad)
	if err != nil {
		return nil, err
	}

	// A token-generated IV is handed back through CK_GCM_MESSAGE_PARAMS.pIv
	// (v3.2 section 5.18.6); the other forms carry it in the blob or already
	// hold it.
	if msgParams, ok := mechanism.GetAESGCMMessageParams(); ok && msgParams.IVGenerator != CKG_NO_GENERATE {
		msgParams.IV = nonce
	}

	// The nonce is carried in the blob only for the parameter forms that give
	// the token no way to hand it back out of band; see the framing table in
	// this file's package comment.
	if !prefixNonce {
		return sealed, nil
	}

	result := make([]byte, GCMNonceSize+len(sealed))
	copy(result[:GCMNonceSize], nonce)
	copy(result[GCMNonceSize:], sealed)

	return result, nil
}

// WrapKeyAuthenticatedSize returns the expected wrapped key output size
// without performing the actual AES-GCM wrapping operation. This supports
// the PKCS#11 size query pattern where pWrappedKey is NULL.
//
// When the mechanism carries AESGCMParams with a non-empty IV, the nonce is
// not prepended to the output (the caller manages the IV externally), so
// the output size is: ciphertext (same as plaintext length) + the GCM tag
// length named by CK_GCM_WRAP_PARAMS.ulTagBits (16 bytes by default).
//
// When no IV is provided in the parameters, the output format is:
//
//	nonce (12 bytes) || ciphertext || GCM tag (CK_GCM_WRAP_PARAMS.ulTagBits, 16 bytes by default)
func (m *Module) WrapKeyAuthenticatedSize(sessionHandle SessionHandle, mechanism *Mechanism, wrappingKeyHandle ObjectHandle, keyHandle ObjectHandle) (uint64, error) {
	if !m.initialized.Load() {
		return 0, NewPKCS11Error(CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Validate session exists
	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return 0, NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}

	// The login requirement is checked here for the same reason the attribute
	// checks below are: a size query must answer with the same code the wrap
	// itself would. It also keeps the query from telling an unauthenticated
	// session the length of a wrap, which is the length of the key material.
	if rv := m.requireLogin(slotID, session); rv != CKR_OK {
		return 0, NewPKCS11Error(rv)
	}

	// Validate mechanism
	if mechanism == nil {
		return 0, NewPKCS11Error(CKR_ARGUMENTS_BAD)
	}
	if mechanism.Type != CKM_AES_GCM {
		return 0, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"authenticated wrapping requires CKM_AES_GCM mechanism")
	}

	// A size query must answer with the same code the wrap itself would, so
	// the fips140=only gate fires here in the same position it holds in
	// WrapKeyAuthenticated.
	if err := authWrapFIPSRefusal(mechanism, true); err != nil {
		return 0, err
	}

	// The read-write requirement is checked here for the same reason the
	// attribute checks below are: a size query must answer with the same code
	// the wrap itself would (v3.2 §5.14.3). WrapKeyAuthenticated rejects a
	// read-only session with CKR_SESSION_READ_ONLY, so a size query that
	// succeeded there handed the application a buffer size for a call that can
	// only fail. The check sits after the mechanism validation so the two
	// functions reject in the same order.
	if !session.IsReadWrite() {
		return 0, NewPKCS11Error(CKR_SESSION_READ_ONLY)
	}

	// Resolve through the session's access context: a size query must not
	// become an oracle for the existence of objects the session cannot see.
	access := NewAccessContext(sessionHandle, session)

	// Validate wrapping key exists and has CKA_WRAP
	wrappingKey, err := m.objectManager.GetObjectFor(access, wrappingKeyHandle)
	if err != nil {
		return 0, NewPKCS11Error(CKR_WRAPPING_KEY_HANDLE_INVALID)
	}
	// CKR_KEY_FUNCTION_NOT_PERMITTED, for the reason given in
	// WrapKeyAuthenticated: the size query must answer with the same code the
	// wrap itself would.
	if !isBoolAttributeTrue(wrappingKey, CKA_WRAP) {
		return 0, NewPKCS11ErrorWithMessage(CKR_KEY_FUNCTION_NOT_PERMITTED,
			"wrapping key does not have CKA_WRAP set to true")
	}

	// Validate wrapping key material size
	wrappingKeyValue := wrappingKey.GetAttribute(CKA_VALUE)
	if len(wrappingKeyValue) == 0 {
		return 0, NewPKCS11ErrorWithMessage(CKR_WRAPPING_KEY_HANDLE_INVALID,
			"wrapping key has no CKA_VALUE")
	}
	if !validAESKeySize(len(wrappingKeyValue)) {
		return 0, NewPKCS11Error(CKR_WRAPPING_KEY_SIZE_RANGE)
	}

	// Validate target key exists and is extractable
	targetKey, err := m.objectManager.GetObjectFor(access, keyHandle)
	if err != nil {
		return 0, NewPKCS11Error(CKR_KEY_HANDLE_INVALID)
	}
	if !boolAttributeIsTrue(targetKey.GetAttribute(CKA_EXTRACTABLE)) {
		return 0, NewPKCS11Error(CKR_KEY_UNEXTRACTABLE)
	}

	// CKA_WRAP_WITH_TRUSTED is checked here for the reason given on the
	// CKA_WRAP check above (v3.2 §4.9): a size query that answered CKR_OK for a
	// wrap the token will refuse hands the application a buffer size for a call
	// that can only fail.
	if boolAttributeIsTrue(targetKey.GetAttribute(CKA_WRAP_WITH_TRUSTED)) &&
		!boolAttributeIsTrue(wrappingKey.GetAttribute(CKA_TRUSTED)) {
		return 0, NewPKCS11ErrorWithMessage(CKR_KEY_NOT_WRAPPABLE,
			"target key is CKA_WRAP_WITH_TRUSTED and the wrapping key is not CKA_TRUSTED")
	}

	// CKA_WRAP_TEMPLATE and CKA_ALLOWED_MECHANISMS are checked here too, for
	// the reason given on the CKA_WRAP check above: a size query must answer
	// with the same code the wrap itself would, or an application sizes a
	// buffer for a call that can only fail (v3.2 §5.14.3, §4.8.2).
	if tmplErr := wrappingKey.CheckWrapTemplate(targetKey); tmplErr != nil {
		return 0, tmplErr
	}
	if mechErr := wrappingKey.CheckAllowedMechanism(mechanism.Type); mechErr != nil {
		return 0, mechErr
	}

	// Get target key material to compute output size
	targetKeyValue := targetKey.GetAttribute(CKA_VALUE)
	if len(targetKeyValue) == 0 {
		return 0, NewPKCS11ErrorWithMessage(CKR_KEY_NOT_WRAPPABLE,
			"target key has no CKA_VALUE to wrap")
	}

	// The strength check runs here for the reason the checks above do: a size
	// query that answered CKR_OK for a wrap the token will refuse hands the
	// application a buffer size for a call that can only fail.
	if err := requireWrappingKeyStrength(wrappingKeyValue, targetKeyValue); err != nil {
		return 0, err
	}

	// Whether the nonce lands in the output is decided by the mechanism
	// parameters, exactly as it is in WrapKeyAuthenticated: a
	// CK_GCM_MESSAGE_PARAMS wrap returns its IV through pIv and a CK_GCM_PARAMS
	// wrap with a caller-supplied IV needs no prefix either, so both are
	// ciphertext||tag and only the generated-IV forms pay the 12 bytes. The two
	// functions must agree here or the size query hands the application a
	// buffer length the wrap then overruns.
	nonceOverhead := GCMNonceSize
	if _, ok := mechanism.GetAESGCMMessageParams(); ok {
		nonceOverhead = 0
	} else if gcmParams, ok := mechanism.GetAESGCMParams(); ok && len(gcmParams.IV) > 0 {
		nonceOverhead = 0
	}

	// The tag length is the one WrapKeyAuthenticated will actually seal with,
	// resolved from the same CK_GCM_WRAP_PARAMS.ulTagBits through the same
	// helper. A size query answered with a hardcoded 128-bit tag overstated
	// the output of every truncated-tag wrap, which is a buffer-sizing answer
	// an application has no way to check before it allocates.
	tagSize, err := authWrapTagSize(mechanism)
	if err != nil {
		return 0, err
	}

	// Output = optional nonce + ciphertext (same as plaintext length) + tag
	size := uint64(nonceOverhead + len(targetKeyValue) + tagSize)
	return size, nil
}

// UnwrapKeyAuthenticated unwraps a key by decrypting AES-GCM AEAD-wrapped key material
// and verifying the integrated authentication tag. If verification fails, the
// operation fails with CKR_AEAD_DECRYPT_FAILED.
//
// This implements C_UnwrapKeyAuthenticated per PKCS#11 v3.2 specification.
// The associated data must match what was provided during wrapping for the
// AEAD verification to succeed.
//
// The session must be logged in when the token advertises
// CKF_LOGIN_REQUIRED, and it must be read-write. The unwrapping key must have
// CKA_UNWRAP set to true. The template must include CKA_CLASS for the new
// object. These are the gates C_UnwrapKey applies, enforced here in the same
// order and with the same return codes.
//
// When the mechanism carries AESGCMParams with a non-empty IV, that IV is
// used as the nonce and the entire wrappedKey blob is treated as
// ciphertext || tag. When AESGCMParams provides AAD, it takes precedence
// over the associatedData function argument.
//
// When no AESGCMParams IV is provided, the nonce is extracted from the
// first 12 bytes of the wrappedKey blob:
//
//	nonce (12 bytes) || ciphertext || GCM tag (CK_GCM_WRAP_PARAMS.ulTagBits, 16 bytes by default)
//
// Per PKCS#11 v3.2, unwrapped keys are marked with:
//   - CKA_LOCAL = CK_FALSE (the key was not generated locally)
//   - CKA_ALWAYS_SENSITIVE = CK_FALSE (the key existed outside the token)
//   - CKA_NEVER_EXTRACTABLE = CK_FALSE (the key was transported)
//
// Parameters:
//   - sessionHandle: the session handle
//   - mechanism: the unwrapping mechanism (must be CKM_AES_GCM)
//   - unwrappingKeyHandle: handle to the AES key used for unwrapping
//   - wrappedKey: the wrapped key material
//   - template: attributes for the unwrapped key object (must include CKA_CLASS)
//   - associatedData: optional additional authenticated data (AAD); must match wrapping AAD
//
// Returns:
//   - ObjectHandle: handle to the unwrapped key object
//   - error: nil on success, or a PKCS11Error
func (m *Module) UnwrapKeyAuthenticated(sessionHandle SessionHandle, mechanism *Mechanism, unwrappingKeyHandle ObjectHandle, wrappedKey []byte, template []Attribute, associatedData []byte) (ObjectHandle, error) {
	if !m.initialized.Load() {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	// A read lock suffices even though this function creates an object. Every
	// piece of state it mutates carries its own lock: the object store is
	// inserted into under ObjectManager.mu, and the context-specific
	// authorization is consumed under Session.mu in one atomic check-and-delete,
	// so its single-use guarantee survives concurrent readers. The module-level
	// fields read here cannot change underneath, because an RWMutex read lock
	// excludes every writer.
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Validate session exists and is R/W
	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}

	// The token's CKF_LOGIN_REQUIRED gates key management just as it gates the
	// crypto operations; which verb the caller uses must not change the policy.
	// C_UnwrapKey checks it in this position, so the two unwrap verbs refuse in
	// the same order.
	if rv := m.requireLogin(slotID, session); rv != CKR_OK {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(rv)
	}

	// Validate mechanism is provided
	if mechanism == nil {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_ARGUMENTS_BAD)
	}

	// Validate mechanism type is AES-GCM
	if mechanism.Type != CKM_AES_GCM {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"authenticated unwrapping requires CKM_AES_GCM mechanism")
	}

	// Opening is gated for the same reason sealing is; see
	// authWrapFIPSRefusal for what fips140=only leaves available.
	if err := authWrapFIPSRefusal(mechanism, false); err != nil {
		return ObjectHandle(InvalidHandle), err
	}

	// Validate unwrapping key handle exists and is visible to this session.
	access := NewAccessContext(sessionHandle, session)
	unwrappingKey, err := m.objectManager.GetObjectFor(access, unwrappingKeyHandle)
	if err != nil {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_UNWRAPPING_KEY_HANDLE_INVALID)
	}

	// Validate wrapped key is provided
	if len(wrappedKey) == 0 {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_WRAPPED_KEY_INVALID)
	}

	// Validate session is read-write
	if !session.IsReadWrite() {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_SESSION_READ_ONLY)
	}

	// Validate unwrapping key has CKA_UNWRAP attribute set to true.
	//
	// The code is CKR_KEY_FUNCTION_NOT_PERMITTED, for the reason C_UnwrapKey
	// gives: the key's type is consistent with the mechanism, so §5.1.6's
	// CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT does not apply, and only the
	// attribute is wrong (§5.1.7, §5.18.7).
	if !isBoolAttributeTrue(unwrappingKey, CKA_UNWRAP) {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorWithMessage(CKR_KEY_FUNCTION_NOT_PERMITTED,
			"unwrapping key does not have CKA_UNWRAP set to true")
	}

	// CKA_ALWAYS_AUTHENTICATE deliberately does not gate this call. PKCS#11 v3.2
	// §4.10 defines the "use" it protects as "a cryptographic operation such as
	// sign or decrypt" and gives re-authentication exactly one form: "calling
	// C_Login with userType set to CKU_CONTEXT_SPECIFIC immediately after a
	// cryptographic operation using the key has been initiated (e.g. after
	// C_SignInit)". C_UnwrapKeyAuthenticated has no Init phase, so there is no
	// moment at which an application could issue that login for this call --
	// C_Login answers CKR_OPERATION_NOT_INITIALIZED -- and gating on it would
	// refuse every correctly configured key outright.
	//
	// A gate here was not merely unsatisfiable, it was harmful. It could fire
	// only when an operation of the same category was already active on this
	// same key, and the one grant it then found belonged to that other
	// operation: an application that ran C_DecryptInit, re-authenticated for it,
	// and unwrapped with the same key in between had its decryption grant
	// consumed by the unwrap, and its C_Decrypt failed CKR_USER_NOT_LOGGED_IN
	// with nothing to distinguish that from a wrong PIN. That is the same
	// cross-operation theft requireContextAuthentication's key binding exists to
	// prevent, one verb further out.
	//
	// C_UnwrapKey and C_DecapsulateKey drop it for the same reason, so the three
	// key-management verbs answer alike.

	// CKA_ALLOWED_MECHANISMS on the unwrapping key names the mechanisms that
	// key may be used with, authenticated unwrapping included (v3.2 §4.8.2).
	if mechErr := unwrappingKey.CheckAllowedMechanism(mechanism.Type); mechErr != nil {
		return ObjectHandle(InvalidHandle), mechErr
	}

	// CKA_UNWRAP_TEMPLATE adds the unwrapping key's attribute set to the
	// caller's template for the key about to be unwrapped (v3.2 §5.14.4).
	template, err = unwrappingKey.ApplyAttributeTemplate(CKA_UNWRAP_TEMPLATE, template)
	if err != nil {
		return ObjectHandle(InvalidHandle), err
	}

	// Get unwrapping key material (CKA_VALUE) and copy to a local buffer
	// so the deferred enclave.Wipe does not corrupt the object store.
	unwrappingKeyRef := unwrappingKey.GetAttribute(CKA_VALUE)
	if len(unwrappingKeyRef) == 0 {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorWithMessage(CKR_UNWRAPPING_KEY_HANDLE_INVALID,
			"unwrapping key has no CKA_VALUE")
	}
	unwrappingKeyValue := make([]byte, len(unwrappingKeyRef))
	copy(unwrappingKeyValue, unwrappingKeyRef)
	defer enclave.Wipe(unwrappingKeyValue)

	// Validate AES key size (16, 24, or 32 bytes)
	if !validAESKeySize(len(unwrappingKeyValue)) {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_WRAPPING_KEY_SIZE_RANGE)
	}

	// The tag length this unwrap will verify at, taken from the caller's
	// CK_GCM_WRAP_PARAMS.ulTagBits and not from the bundle -- see
	// authWrapTagSize for why inferring it from what arrived would let the
	// producer of a forgery choose its own verification strength. It is the
	// same value WrapKeyAuthenticated sealed with for the same parameters,
	// which is what makes the round trip close.
	tagSize, err := authWrapTagSize(mechanism)
	if err != nil {
		return ObjectHandle(InvalidHandle), err
	}

	// Resolve the nonce, the ciphertext and the AAD from whichever GCM
	// parameter structure the mechanism carries. This is the inverse of the
	// framing WrapKeyAuthenticated applied for the same parameters.
	nonce, ciphertextWithTag, aad, err := authUnwrapNonce(mechanism, wrappedKey, tagSize, associatedData)
	if err != nil {
		return ObjectHandle(InvalidHandle), err
	}

	// Perform AES-GCM AEAD unwrapping
	block, err := aes.NewCipher(unwrappingKeyValue)
	if err != nil {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"failed to create AES cipher", err)
	}

	// Open decrypts and verifies the ciphertext+tag; a tag mismatch is
	// CKR_AEAD_DECRYPT_FAILED.
	plaintext, err := openAuthWrap(block, tagSize, nonce, ciphertextWithTag, aad)
	if err != nil {
		return ObjectHandle(InvalidHandle), err
	}
	defer enclave.Wipe(plaintext)

	// Build the attribute template for the new key object, injecting CKA_VALUE
	// with the unwrapped key material and PKCS#11-mandated unwrap attributes.
	newTemplate := make([]Attribute, 0, len(template)+4)
	hasValue := false
	for _, attr := range template {
		if attr.Type == CKA_VALUE {
			hasValue = true
			// Override any CKA_VALUE in the template with the unwrapped material
			newTemplate = append(newTemplate, NewAttribute(CKA_VALUE, plaintext))
		} else {
			newTemplate = append(newTemplate, attr)
		}
	}
	if !hasValue {
		newTemplate = append(newTemplate, NewAttribute(CKA_VALUE, plaintext))
	}

	// A CKA_TOKEN key this store could not give back afterwards is refused
	// before it is created rather than persisted as a shell.
	if persistErr := unwrappedKeyPersistenceError(newTemplate); persistErr != nil {
		return ObjectHandle(InvalidHandle), persistErr
	}

	// An unwrapped key is not token-generated, so CKA_LOCAL,
	// CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE are all CK_FALSE. Those
	// are token-computed attributes a template may never carry, so
	// CreateDerivedObject derives them from the unwrapping key instead.
	keyType, _ := unwrapTargetKeyType(newTemplate)
	newHandle, err := m.objectManager.CreateDerivedObject(
		access, unwrappingKey, unwrapTargetClass(newTemplate), keyType, newTemplate)
	if err != nil {
		// The template failure keeps the code object creation determined —
		// CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT,
		// CKR_ATTRIBUTE_READ_ONLY or CKR_ATTRIBUTE_VALUE_INVALID, all of which
		// are in C_UnwrapKeyAuthenticated's return table. Collapsing them into
		// CKR_FUNCTION_FAILED told an application whose template was merely
		// wrong that the token had failed, and hid which attribute to fix.
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorFull(
			FromError(err), "failed to create unwrapped key object", err)
	}

	// A CKA_TOKEN object exists on the token, which means across restarts. The
	// object manager holds it in memory only, so without this the key was
	// findable for the life of the process, reported CKA_TOKEN=CK_TRUE the
	// whole time, and was simply gone at the next C_Initialize -- a divergence
	// between what the token says it holds and what it holds. The store's
	// refusal is returned rather than logged, and persistNewObject destroys the
	// object again so the application is not left with a handle it never
	// received.
	if persistErr := m.persistNewObject(access, newHandle, sessionHandle); persistErr != nil {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorFull(CKR_DEVICE_ERROR,
			"failed to persist unwrapped key object", persistErr)
	}

	return newHandle, nil
}

// unwrappedKeyPersistenceError refuses a C_UnwrapKeyAuthenticated result this
// token could not give back after a restart.
//
// This verb decrypts in process and puts the recovered material straight into
// CKA_VALUE, with no KeyID naming a backend copy, so CKA_VALUE is the only copy
// of the key that exists. ModuleStorage.SaveObject withholds every attribute
// IsSensitiveAttribute names -- CKA_VALUE among them -- from a key object that
// protects its material, because the token store is a plaintext file and
// writing the key there would place in the clear exactly the bytes
// CKA_SENSITIVE and CKA_EXTRACTABLE=CK_FALSE promise never leave the token.
//
// The two rules meet on a CKA_TOKEN=CK_TRUE unwrap the caller also asks to be
// protected: what persists is a key-shaped shell with no key in it, and every
// use of it after the restart fails on a handle the application had every
// reason to believe was a key. Refusing is the only answer that does not
// silently destroy the key, and it is the answer
// sharedSecretPersistenceError gives for the same collision on the KEM path.
//
// The CKA_SENSITIVE fallback is the class default, not a fixed CK_FALSE: this
// verb resolves its class through unwrapTargetClass, which may be
// CKO_PRIVATE_KEY, and applyClassDefaults makes a private key CKA_SENSITIVE by
// default. A fallback of CK_FALSE would let a token private-key unwrap that
// states neither attribute through, and store the shell this function exists to
// prevent.
//
// CKR_TEMPLATE_INCONSISTENT is in C_UnwrapKeyAuthenticated's return table and
// v3.2 section 5.1 defines it as a template carrying conflicting attributes,
// which asking this token both to keep a key and to protect its only copy of
// that key is.
func unwrappedKeyPersistenceError(template []Attribute) error {
	if !templateBoolIsTrue(template, CKA_TOKEN, false) {
		return nil
	}

	sensitive := templateBoolIsTrue(template, CKA_SENSITIVE,
		unwrapTargetClass(template) == CKO_PRIVATE_KEY)
	extractable := templateBoolIsTrue(template, CKA_EXTRACTABLE, true)
	if !sensitive && extractable {
		return nil
	}

	return NewPKCS11ErrorWithMessage(CKR_TEMPLATE_INCONSISTENT,
		"a CKA_TOKEN unwrapped key must be CKA_SENSITIVE=CK_FALSE and CKA_EXTRACTABLE=CK_TRUE: this token cannot persist protected key material")
}
