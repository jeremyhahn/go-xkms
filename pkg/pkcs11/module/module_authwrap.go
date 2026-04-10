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
// Mechanism parameter handling (CK_GCM_PARAMS / AESGCMParams):
//
// When the mechanism carries an AESGCMParams typed parameter, the IV and AAD
// fields are extracted from that parameter. A caller-specified IV is used
// as-is; otherwise (nil or empty IV) a random 12-byte nonce is generated.
// When the mechanism has no typed parameter, a random nonce is generated
// and the associatedData function argument is used as AAD.
//
// For WrapKeyAuthenticated, when a caller-specified IV is provided through
// AESGCMParams, the nonce is NOT prepended to the output -- the caller
// already knows the IV. The output format in that case is:
//
//	ciphertext || GCM tag (16 bytes)
//
// When the nonce is auto-generated (no AESGCMParams IV), the format is:
//
//	nonce (12 bytes) || ciphertext || GCM tag (16 bytes)
//
// For UnwrapKeyAuthenticated, when AESGCMParams provides an IV, the entire
// wrappedKey blob is treated as ciphertext||tag (no nonce prefix). When no
// IV is in the params, the nonce is extracted from the first 12 bytes of
// the wrappedKey blob.
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
	"io"
)

// validAESKeySize reports whether keyLen is a valid AES key length (16, 24, or 32 bytes).
func validAESKeySize(keyLen int) bool {
	return keyLen == 16 || keyLen == 24 || keyLen == 32
}

// WrapKeyAuthenticated wraps a key using an AEAD mechanism, providing both
// confidentiality and integrity protection for the exported key material.
// The authentication tag is integrated into the returned wrapped key ciphertext.
//
// This implements C_WrapKeyAuthenticated per PKCS#11 v3.2 specification.
// Optional associated data provides additional authenticated context that
// is integrity-protected but not encrypted.
//
// The wrapping key must have CKA_WRAP set to true, and the target key must
// have CKA_EXTRACTABLE set to true. The session must be read-write.
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
//	nonce (12 bytes) || ciphertext || GCM tag (16 bytes)
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

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Validate session exists and is R/W
	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return nil, NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
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

	// Validate session is read-write
	if !session.IsReadWrite() {
		return nil, NewPKCS11Error(CKR_SESSION_READ_ONLY)
	}

	// Validate wrapping key handle exists
	wrappingKey, err := m.objectManager.GetObject(wrappingKeyHandle)
	if err != nil {
		return nil, NewPKCS11Error(CKR_WRAPPING_KEY_HANDLE_INVALID)
	}

	// Validate key handle to be wrapped exists
	targetKey, err := m.objectManager.GetObject(keyHandle)
	if err != nil {
		return nil, NewPKCS11Error(CKR_KEY_HANDLE_INVALID)
	}

	// Validate wrapping key has CKA_WRAP attribute set to true
	if !isBoolAttributeTrue(wrappingKey, CKA_WRAP) {
		return nil, NewPKCS11ErrorWithMessage(CKR_KEY_FUNCTION_NOT_PERMITTED,
			"wrapping key does not have CKA_WRAP set to true")
	}

	// Validate target key has CKA_EXTRACTABLE attribute set to true
	if !targetKey.IsExtractable {
		return nil, NewPKCS11Error(CKR_KEY_NOT_WRAPPABLE)
	}

	// Get wrapping key material (CKA_VALUE) and copy to a local buffer
	// so the deferred zeroize does not corrupt the object store.
	wrappingKeyRef := wrappingKey.GetAttribute(CKA_VALUE)
	if len(wrappingKeyRef) == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_WRAPPING_KEY_HANDLE_INVALID,
			"wrapping key has no CKA_VALUE")
	}
	wrappingKeyValue := make([]byte, len(wrappingKeyRef))
	copy(wrappingKeyValue, wrappingKeyRef)
	defer zeroize(wrappingKeyValue)

	// Validate AES key size (16, 24, or 32 bytes)
	if !validAESKeySize(len(wrappingKeyValue)) {
		return nil, NewPKCS11Error(CKR_WRAPPING_KEY_SIZE_RANGE)
	}

	// Get target key material to wrap (CKA_VALUE) and copy to a local buffer
	// so the deferred zeroize does not corrupt the object store.
	targetKeyRef := targetKey.GetAttribute(CKA_VALUE)
	if len(targetKeyRef) == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_KEY_NOT_WRAPPABLE,
			"target key has no CKA_VALUE to wrap")
	}
	targetKeyValue := make([]byte, len(targetKeyRef))
	copy(targetKeyValue, targetKeyRef)
	defer zeroize(targetKeyValue)

	// Perform AES-GCM AEAD wrapping
	block, err := aes.NewCipher(wrappingKeyValue)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED, "failed to create AES cipher", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED, "failed to create GCM", err)
	}

	// Resolve nonce and AAD from mechanism parameters (CK_GCM_PARAMS).
	// When the mechanism carries AESGCMParams with a non-empty IV, use it
	// directly and do not prepend the nonce to the output (the caller owns it).
	// When AESGCMParams provides AAD, it takes precedence over the function argument.
	var nonce []byte
	callerSuppliedNonce := false
	aad := associatedData

	if gcmParams, ok := mechanism.GetAESGCMParams(); ok {
		if len(gcmParams.IV) > 0 {
			// Validate caller-supplied IV length matches GCM nonce size
			if len(gcmParams.IV) != GCMNonceSize {
				return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
					"GCM IV must be 12 bytes")
			}
			nonce = make([]byte, GCMNonceSize)
			copy(nonce, gcmParams.IV)
			callerSuppliedNonce = true
		}
		// AAD from params takes precedence over the function argument
		if gcmParams.AAD != nil {
			aad = gcmParams.AAD
		}
	}

	// If no caller-supplied nonce, generate a random 12-byte nonce
	if nonce == nil {
		nonce = make([]byte, GCMNonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, NewPKCS11ErrorFull(CKR_RANDOM_NO_RNG, "failed to generate nonce", err)
		}
	}

	// Seal encrypts and authenticates the plaintext, appending the result to dst.
	// gcm.Seal returns ciphertext+tag when dst is nil.
	sealed := gcm.Seal(nil, nonce, targetKeyValue, aad)

	// When the caller supplied the nonce via mechanism parameters, they already
	// know the IV, so we return only ciphertext || tag.
	// When we auto-generated the nonce, prepend it so the unwrapper can extract it.
	if callerSuppliedNonce {
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
// the output size is: ciphertext (same as plaintext length) + GCM tag (16 bytes).
//
// When no IV is provided in the parameters, the output format is:
//
//	nonce (12 bytes) || ciphertext || GCM tag (16 bytes)
func (m *Module) WrapKeyAuthenticatedSize(sessionHandle SessionHandle, mechanism *Mechanism, wrappingKeyHandle ObjectHandle, keyHandle ObjectHandle) (uint64, error) {
	if !m.initialized.Load() {
		return 0, NewPKCS11Error(CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Validate session exists
	_, _, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return 0, NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}

	// Validate mechanism
	if mechanism == nil {
		return 0, NewPKCS11Error(CKR_ARGUMENTS_BAD)
	}
	if mechanism.Type != CKM_AES_GCM {
		return 0, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"authenticated wrapping requires CKM_AES_GCM mechanism")
	}

	// Validate wrapping key exists and has CKA_WRAP
	wrappingKey, err := m.objectManager.GetObject(wrappingKeyHandle)
	if err != nil {
		return 0, NewPKCS11Error(CKR_WRAPPING_KEY_HANDLE_INVALID)
	}
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
	targetKey, err := m.objectManager.GetObject(keyHandle)
	if err != nil {
		return 0, NewPKCS11Error(CKR_KEY_HANDLE_INVALID)
	}
	if !targetKey.IsExtractable {
		return 0, NewPKCS11Error(CKR_KEY_NOT_WRAPPABLE)
	}

	// Get target key material to compute output size
	targetKeyValue := targetKey.GetAttribute(CKA_VALUE)
	if len(targetKeyValue) == 0 {
		return 0, NewPKCS11ErrorWithMessage(CKR_KEY_NOT_WRAPPABLE,
			"target key has no CKA_VALUE to wrap")
	}

	// Determine whether a caller-supplied nonce is present.
	// When the caller provides the IV via AESGCMParams, the nonce is not
	// prepended to the output, so the size is smaller.
	nonceOverhead := GCMNonceSize
	if gcmParams, ok := mechanism.GetAESGCMParams(); ok && len(gcmParams.IV) > 0 {
		nonceOverhead = 0
	}

	// Output = optional nonce + ciphertext (same as plaintext length) + tag (16)
	size := uint64(nonceOverhead + len(targetKeyValue) + GCMTagSize)
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
// The unwrapping key must have CKA_UNWRAP set to true. The session must be
// read-write. The template must include CKA_CLASS for the new object.
//
// When the mechanism carries AESGCMParams with a non-empty IV, that IV is
// used as the nonce and the entire wrappedKey blob is treated as
// ciphertext || tag. When AESGCMParams provides AAD, it takes precedence
// over the associatedData function argument.
//
// When no AESGCMParams IV is provided, the nonce is extracted from the
// first 12 bytes of the wrappedKey blob:
//
//	nonce (12 bytes) || ciphertext || GCM tag (16 bytes)
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

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Validate session exists and is R/W
	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
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

	// Validate unwrapping key handle exists
	unwrappingKey, err := m.objectManager.GetObject(unwrappingKeyHandle)
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

	// Validate unwrapping key has CKA_UNWRAP attribute set to true
	if !isBoolAttributeTrue(unwrappingKey, CKA_UNWRAP) {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorWithMessage(CKR_KEY_FUNCTION_NOT_PERMITTED,
			"unwrapping key does not have CKA_UNWRAP set to true")
	}

	// Get unwrapping key material (CKA_VALUE) and copy to a local buffer
	// so the deferred zeroize does not corrupt the object store.
	unwrappingKeyRef := unwrappingKey.GetAttribute(CKA_VALUE)
	if len(unwrappingKeyRef) == 0 {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorWithMessage(CKR_UNWRAPPING_KEY_HANDLE_INVALID,
			"unwrapping key has no CKA_VALUE")
	}
	unwrappingKeyValue := make([]byte, len(unwrappingKeyRef))
	copy(unwrappingKeyValue, unwrappingKeyRef)
	defer zeroize(unwrappingKeyValue)

	// Validate AES key size (16, 24, or 32 bytes)
	if !validAESKeySize(len(unwrappingKeyValue)) {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_WRAPPING_KEY_SIZE_RANGE)
	}

	// Resolve nonce and AAD from mechanism parameters (CK_GCM_PARAMS).
	// When the mechanism carries AESGCMParams with a non-empty IV, use it
	// as the nonce and treat the entire wrappedKey as ciphertext||tag.
	// When no IV is in the params, extract the nonce from the wrappedKey prefix.
	var nonce []byte
	var ciphertextWithTag []byte
	aad := associatedData

	if gcmParams, ok := mechanism.GetAESGCMParams(); ok && len(gcmParams.IV) > 0 {
		// Caller-supplied nonce: wrappedKey is just ciphertext||tag
		if len(gcmParams.IV) != GCMNonceSize {
			return ObjectHandle(InvalidHandle), NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
				"GCM IV must be 12 bytes")
		}
		nonce = make([]byte, GCMNonceSize)
		copy(nonce, gcmParams.IV)
		ciphertextWithTag = wrappedKey

		// Minimum: at least 1 byte ciphertext + tag (16) = 17
		if len(wrappedKey) < GCMTagSize+1 {
			return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_WRAPPED_KEY_INVALID)
		}

		// AAD from params takes precedence over the function argument
		if gcmParams.AAD != nil {
			aad = gcmParams.AAD
		}
	} else {
		// No caller-supplied nonce: extract from wrappedKey prefix.
		// Minimum: nonce (12) + at least 1 byte ciphertext + tag (16) = 29
		if len(wrappedKey) < GCMMinCiphertextSize+1 {
			return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_WRAPPED_KEY_INVALID)
		}
		nonce = wrappedKey[:GCMNonceSize]
		ciphertextWithTag = wrappedKey[GCMNonceSize:]
	}

	// Perform AES-GCM AEAD unwrapping
	block, err := aes.NewCipher(unwrappingKeyValue)
	if err != nil {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"failed to create AES cipher", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"failed to create GCM", err)
	}

	// Open decrypts and verifies the ciphertext+tag
	plaintext, err := gcm.Open(nil, nonce, ciphertextWithTag, aad)
	if err != nil {
		// Authentication tag mismatch or decryption failure
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_AEAD_DECRYPT_FAILED)
	}
	defer zeroize(plaintext)

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

	// Per PKCS#11 v3.2 specification, unwrapped keys must carry these attributes
	// to indicate the key was imported rather than generated locally:
	//   CKA_LOCAL = CK_FALSE: key was not generated on this token
	//   CKA_ALWAYS_SENSITIVE = CK_FALSE: key existed in plaintext outside the token
	//   CKA_NEVER_EXTRACTABLE = CK_FALSE: key was transported (wrapped/unwrapped)
	newTemplate = append(newTemplate,
		NewBoolAttribute(CKA_LOCAL, false),
		NewBoolAttribute(CKA_ALWAYS_SENSITIVE, false),
		NewBoolAttribute(CKA_NEVER_EXTRACTABLE, false),
	)

	// Create new key object from template with unwrapped material
	newHandle, err := m.objectManager.CreateObject(sessionHandle, newTemplate)
	if err != nil {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorFull(
			CKR_FUNCTION_FAILED, "failed to create unwrapped key object", err)
	}

	return newHandle, nil
}
