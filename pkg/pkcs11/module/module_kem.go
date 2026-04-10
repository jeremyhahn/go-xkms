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

// Package module provides PKCS#11 (Cryptoki) v3.2 KEM (Key Encapsulation Mechanism) operations.
//
// This file implements the PKCS#11 v3.2 C_EncapsulateKey and C_DecapsulateKey functions
// for post-quantum key encapsulation. KEM operations enable key agreement through
// encapsulation of a shared secret using a recipient's public key, and decapsulation
// using the corresponding private key.
//
// The actual cryptographic operations are delegated to build-tag-gated helper
// functions (kemEncapsulate / kemDecapsulate) that dispatch to the QuantumCryptoManager
// when built with the "quantum" tag, or return CKR_MECHANISM_INVALID otherwise.
//
// Functions:
//   - EncapsulateKey: C_EncapsulateKey -- create a shared secret and ciphertext from a public key
//   - DecapsulateKey: C_DecapsulateKey -- recover a shared secret from ciphertext using a private key
//
// References:
//   - OASIS PKCS#11 v3.2: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html
package module

import "encoding/binary"

// zeroize overwrites a byte slice with zeros to prevent sensitive key material
// from lingering in memory after use.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// EncapsulateKey creates a shared secret key and ciphertext using a public key
// and a KEM mechanism. The shared secret is stored as a new key object described
// by the provided template.
//
// This implements C_EncapsulateKey per PKCS#11 v3.2 specification.
//
// Parameters:
//   - sessionHandle: the session handle
//   - mechanism: the KEM mechanism to use (must support CKF_ENCAPSULATE)
//   - publicKeyHandle: handle to the recipient's public key
//   - template: attributes for the created shared secret key object
//
// Returns:
//   - ObjectHandle: handle to the newly created shared secret key
//   - []byte: the KEM ciphertext to send to the decapsulator
//   - error: nil on success, or a PKCS11Error
func (m *Module) EncapsulateKey(sessionHandle SessionHandle, mechanism *Mechanism, publicKeyHandle ObjectHandle, template []Attribute) (ObjectHandle, []byte, error) {
	if !m.initialized.Load() {
		return ObjectHandle(InvalidHandle), nil, NewPKCS11Error(CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Validate session exists and is R/W (encapsulation creates a key object)
	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return ObjectHandle(InvalidHandle), nil, NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}
	if !session.IsReadWrite() {
		return ObjectHandle(InvalidHandle), nil, NewPKCS11Error(CKR_SESSION_READ_ONLY)
	}

	// Validate mechanism is provided
	if mechanism == nil {
		return ObjectHandle(InvalidHandle), nil, NewPKCS11Error(CKR_ARGUMENTS_BAD)
	}

	// Validate that the mechanism supports encapsulation.
	// Check both the global mechanism registry (standard v3.2 flags) and
	// the quantum registry (vendor mechanisms with category-based dispatch).
	if !isEncapsulateMechanism(mechanism.Type) {
		return ObjectHandle(InvalidHandle), nil, NewPKCS11ErrorWithMessage(
			CKR_MECHANISM_INVALID, "mechanism does not support encapsulation")
	}

	// Validate public key handle exists and retrieve the object
	pubKeyObj, err := m.objectManager.GetObject(publicKeyHandle)
	if err != nil {
		return ObjectHandle(InvalidHandle), nil, NewPKCS11Error(CKR_KEY_HANDLE_INVALID)
	}

	// Validate the key is a public key (CKO_PUBLIC_KEY)
	if pubKeyObj.Class != CKO_PUBLIC_KEY {
		return ObjectHandle(InvalidHandle), nil, NewPKCS11ErrorWithMessage(
			CKR_KEY_HANDLE_INVALID, "key is not a public key")
	}

	// Validate CKA_ENCAPSULATE attribute is set on the public key
	if !isBoolAttributeTrue(pubKeyObj, CKA_ENCAPSULATE) {
		return ObjectHandle(InvalidHandle), nil, NewPKCS11ErrorWithMessage(
			CKR_KEY_FUNCTION_NOT_PERMITTED, "public key does not permit encapsulation")
	}

	// Retrieve public key material from CKA_VALUE
	pubKeyValue := pubKeyObj.GetAttribute(CKA_VALUE)
	if len(pubKeyValue) == 0 {
		return ObjectHandle(InvalidHandle), nil, NewPKCS11ErrorWithMessage(
			CKR_KEY_HANDLE_INVALID, "public key has no CKA_VALUE")
	}

	// Delegate to build-tag-gated crypto dispatch
	sharedSecret, ciphertext, err := kemEncapsulate(m.quantumCrypto, mechanism, publicKeyHandle, pubKeyValue)
	if err != nil {
		return ObjectHandle(InvalidHandle), nil, err
	}
	defer zeroize(sharedSecret)

	// Build the secret key object template from the caller's template,
	// injecting the shared secret as CKA_VALUE and ensuring required
	// secret key attributes are present.
	// CKA_LOCAL is true for encapsulation: the shared secret was generated locally.
	secretKeyAttrs := buildSecretKeyTemplate(template, sharedSecret, mechanism.Type, true)

	// Create the secret key object
	keyHandle, err := m.objectManager.CreateObject(sessionHandle, secretKeyAttrs)
	if err != nil {
		return ObjectHandle(InvalidHandle), nil, NewPKCS11ErrorFull(
			CKR_FUNCTION_FAILED, "failed to create shared secret key object", err)
	}

	return keyHandle, ciphertext, nil
}

// DecapsulateKey recovers a shared secret key from KEM ciphertext using a private key.
// The recovered shared secret is stored as a new key object described by the
// provided template.
//
// This implements C_DecapsulateKey per PKCS#11 v3.2 specification.
// Per the OASIS spec, the template precedes the ciphertext in the parameter list.
//
// Parameters:
//   - sessionHandle: the session handle
//   - mechanism: the KEM mechanism to use (must match encapsulation mechanism)
//   - privateKeyHandle: handle to the decapsulator's private key
//   - template: attributes for the created shared secret key object
//   - ciphertext: the KEM ciphertext received from the encapsulator
//
// Returns:
//   - ObjectHandle: handle to the recovered shared secret key
//   - error: nil on success, or a PKCS11Error
func (m *Module) DecapsulateKey(sessionHandle SessionHandle, mechanism *Mechanism, privateKeyHandle ObjectHandle, template []Attribute, ciphertext []byte) (ObjectHandle, error) {
	if !m.initialized.Load() {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Validate session exists and is R/W (decapsulation creates a key object)
	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}
	if !session.IsReadWrite() {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_SESSION_READ_ONLY)
	}

	// Validate mechanism is provided
	if mechanism == nil {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_ARGUMENTS_BAD)
	}

	// Validate that the mechanism supports decapsulation
	if !isDecapsulateMechanism(mechanism.Type) {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorWithMessage(
			CKR_MECHANISM_INVALID, "mechanism does not support decapsulation")
	}

	// Validate ciphertext is provided
	if len(ciphertext) == 0 {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_ARGUMENTS_BAD)
	}

	// Validate private key handle exists and retrieve the object.
	// Per PKCS#11 spec, DecapsulateKey returns CKR_UNWRAPPING_KEY_HANDLE_INVALID
	// for invalid private key handles (analogous to C_UnwrapKey).
	privKeyObj, err := m.objectManager.GetObject(privateKeyHandle)
	if err != nil {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_UNWRAPPING_KEY_HANDLE_INVALID)
	}

	// Validate the key is a private key (CKO_PRIVATE_KEY)
	if privKeyObj.Class != CKO_PRIVATE_KEY {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorWithMessage(
			CKR_UNWRAPPING_KEY_HANDLE_INVALID, "key is not a private key")
	}

	// Validate CKA_DECAPSULATE attribute is set on the private key
	if !isBoolAttributeTrue(privKeyObj, CKA_DECAPSULATE) {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorWithMessage(
			CKR_KEY_FUNCTION_NOT_PERMITTED, "private key does not permit decapsulation")
	}

	// Retrieve private key material from CKA_VALUE and copy to a local buffer
	// so the deferred zeroize does not corrupt the object store.
	privKeyRef := privKeyObj.GetAttribute(CKA_VALUE)
	if len(privKeyRef) == 0 {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorWithMessage(
			CKR_UNWRAPPING_KEY_HANDLE_INVALID, "private key has no CKA_VALUE")
	}
	privKeyValue := make([]byte, len(privKeyRef))
	copy(privKeyValue, privKeyRef)
	defer zeroize(privKeyValue)

	// Delegate to build-tag-gated crypto dispatch
	sharedSecret, err := kemDecapsulate(m.quantumCrypto, mechanism, privateKeyHandle, privKeyValue, ciphertext)
	if err != nil {
		return ObjectHandle(InvalidHandle), err
	}
	defer zeroize(sharedSecret)

	// Build the secret key object template from the caller's template,
	// injecting the shared secret as CKA_VALUE.
	// CKA_LOCAL is false for decapsulation: the shared secret came from external encapsulation.
	secretKeyAttrs := buildSecretKeyTemplate(template, sharedSecret, mechanism.Type, false)

	// Create the secret key object
	keyHandle, err := m.objectManager.CreateObject(sessionHandle, secretKeyAttrs)
	if err != nil {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorFull(
			CKR_FUNCTION_FAILED, "failed to create shared secret key object", err)
	}

	return keyHandle, nil
}

// isEncapsulateMechanism checks whether a mechanism type supports encapsulation.
// It checks the global mechanism registry for CKF_ENCAPSULATE flag (v3.2 standard)
// and falls back to checking vendor mechanism categories via the quantum registry.
func isEncapsulateMechanism(mechType MechanismType) bool {
	// Check global registry for standard v3.2 CKF_ENCAPSULATE flag
	if desc := GetMechanismDescriptor(mechType); desc != nil {
		if desc.Flags&CKF_ENCAPSULATE != 0 {
			return true
		}
		// Check category-based vendor mechanisms
		for _, cat := range desc.Categories {
			if cat == MechanismCategory(10) { // CategoryEncapsulate = 10
				return true
			}
		}
	}
	return false
}

// isDecapsulateMechanism checks whether a mechanism type supports decapsulation.
// It checks the global mechanism registry for CKF_DECAPSULATE flag (v3.2 standard)
// and falls back to checking vendor mechanism categories via the quantum registry.
func isDecapsulateMechanism(mechType MechanismType) bool {
	// Check global registry for standard v3.2 CKF_DECAPSULATE flag
	if desc := GetMechanismDescriptor(mechType); desc != nil {
		if desc.Flags&CKF_DECAPSULATE != 0 {
			return true
		}
		// Check category-based vendor mechanisms
		for _, cat := range desc.Categories {
			if cat == MechanismCategory(11) { // CategoryDecapsulate = 11
				return true
			}
		}
	}
	return false
}

// isBoolAttributeTrue checks if a boolean attribute on an object is set to true.
// Returns false if the attribute is not present or its value is zero.
func isBoolAttributeTrue(obj *Object, attrType AttributeType) bool {
	val := obj.GetAttribute(attrType)
	return len(val) >= 1 && val[0] != 0
}

// buildSecretKeyTemplate constructs the attribute list for a new CKO_SECRET_KEY object
// from the caller-provided template, injecting the shared secret as CKA_VALUE and
// ensuring all PKCS#11-required secret key attributes are present.
//
// The local parameter controls CKA_LOCAL: true for EncapsulateKey (the shared secret
// was generated locally), false for DecapsulateKey (the shared secret was recovered
// from externally-provided ciphertext).
//
// Per PKCS#11 v3.2, the following attributes are set automatically:
//   - CKA_LOCAL: true for encapsulation, false for decapsulation
//   - CKA_EXTRACTABLE: defaults to false unless the caller template sets it to true
//   - CKA_ALWAYS_SENSITIVE: true if CKA_SENSITIVE is true in the template
//   - CKA_NEVER_EXTRACTABLE: true if CKA_EXTRACTABLE is false (after defaults)
//   - CKA_KEY_GEN_MECHANISM: the KEM mechanism that produced this key
func buildSecretKeyTemplate(template []Attribute, sharedSecret []byte, mechType MechanismType, local bool) []Attribute {
	// Start with required attributes; reserve extra capacity for injected attrs
	attrs := make([]Attribute, 0, len(template)+10)

	// Track which attributes the caller already provided
	hasClass := false
	hasKeyType := false
	hasValue := false
	hasValueLen := false
	hasExtractable := false
	hasSensitive := false

	// Track the caller-provided values for computing derived attributes
	extractable := false // default per PKCS#11 spec for generated secret keys
	sensitive := false

	for _, attr := range template {
		switch attr.Type {
		case CKA_CLASS:
			hasClass = true
		case CKA_KEY_TYPE:
			hasKeyType = true
		case CKA_VALUE:
			hasValue = true
			// Override caller's CKA_VALUE with the actual shared secret
			continue
		case CKA_VALUE_LEN:
			hasValueLen = true
		case CKA_EXTRACTABLE:
			hasExtractable = true
			if len(attr.Value) >= 1 && attr.Value[0] != 0 {
				extractable = true
			}
		case CKA_SENSITIVE:
			hasSensitive = true
			if len(attr.Value) >= 1 && attr.Value[0] != 0 {
				sensitive = true
			}
		}
		attrs = append(attrs, attr)
	}

	// Ensure CKA_CLASS is CKO_SECRET_KEY
	if !hasClass {
		attrs = append(attrs, NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)))
	}

	// Ensure CKA_KEY_TYPE is set; default to CKK_GENERIC_SECRET
	if !hasKeyType {
		attrs = append(attrs, NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)))
	}

	// Always set CKA_VALUE to the shared secret (ignore caller-provided value)
	_ = hasValue
	attrs = append(attrs, NewAttribute(CKA_VALUE, sharedSecret))

	// Set CKA_VALUE_LEN if not already provided.
	// PKCS#11 CK_ULONG is 4 bytes on most platforms.
	if !hasValueLen {
		valLenBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(valLenBuf, uint32(len(sharedSecret)))
		attrs = append(attrs, Attribute{Type: CKA_VALUE_LEN, Value: valLenBuf})
	}

	// Set CKA_EXTRACTABLE default if not provided by caller.
	// Per PKCS#11 spec, generated secret keys default to non-extractable.
	if !hasExtractable {
		attrs = append(attrs, NewBoolAttribute(CKA_EXTRACTABLE, false))
	}

	// Set CKA_SENSITIVE default if not provided by caller
	if !hasSensitive {
		attrs = append(attrs, NewBoolAttribute(CKA_SENSITIVE, false))
	}

	// CKA_LOCAL: true for EncapsulateKey (locally generated), false for DecapsulateKey
	attrs = append(attrs, NewBoolAttribute(CKA_LOCAL, local))

	// CKA_ALWAYS_SENSITIVE: true if CKA_SENSITIVE is true at creation time.
	// This is a read-only history attribute that tracks whether the key has ever
	// had CKA_SENSITIVE set to false.
	attrs = append(attrs, NewBoolAttribute(CKA_ALWAYS_SENSITIVE, sensitive))

	// CKA_NEVER_EXTRACTABLE: true if CKA_EXTRACTABLE is false at creation time.
	// This is a read-only history attribute that tracks whether the key has ever
	// had CKA_EXTRACTABLE set to true.
	attrs = append(attrs, NewBoolAttribute(CKA_NEVER_EXTRACTABLE, !extractable))

	// Set CKA_KEY_GEN_MECHANISM to the KEM mechanism that produced this key
	attrs = append(attrs, NewUint32Attribute(CKA_KEY_GEN_MECHANISM, uint32(mechType)))

	return attrs
}

// KEMCiphertextSize returns the expected ciphertext size for the given KEM
// mechanism without performing any cryptographic operation. This is used by
// the CGO layer to handle PKCS#11 size queries (pCiphertext=NULL) without
// performing a full encapsulation or creating key objects.
//
// Parameters:
//   - sessionHandle: the session handle (validated for existence)
//   - mechanism: the KEM mechanism
//   - publicKeyHandle: handle to the public key (validated for existence and permissions)
//
// Returns:
//   - uint64: the expected ciphertext length in bytes
//   - error: nil on success, or a PKCS11Error
func (m *Module) KEMCiphertextSize(sessionHandle SessionHandle, mechanism *Mechanism, publicKeyHandle ObjectHandle) (uint64, error) {
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

	// Validate mechanism is provided
	if mechanism == nil {
		return 0, NewPKCS11Error(CKR_ARGUMENTS_BAD)
	}

	// Validate mechanism supports encapsulation
	if !isEncapsulateMechanism(mechanism.Type) {
		return 0, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"mechanism does not support encapsulation")
	}

	// Validate public key handle
	pubKeyObj, err := m.objectManager.GetObject(publicKeyHandle)
	if err != nil {
		return 0, NewPKCS11Error(CKR_KEY_HANDLE_INVALID)
	}
	if pubKeyObj.Class != CKO_PUBLIC_KEY {
		return 0, NewPKCS11ErrorWithMessage(CKR_KEY_HANDLE_INVALID, "key is not a public key")
	}
	if !isBoolAttributeTrue(pubKeyObj, CKA_ENCAPSULATE) {
		return 0, NewPKCS11ErrorWithMessage(CKR_KEY_FUNCTION_NOT_PERMITTED,
			"public key does not permit encapsulation")
	}

	// Delegate to build-tag-gated size lookup
	return kemCiphertextSize(mechanism)
}
