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

import "github.com/jeremyhahn/go-enclave"

// mlkemEncapsulateVendorMechanism maps a resolved ML-KEM security level to
// the legacy per-level vendor mechanism that implements C_EncapsulateKey for
// that level. It is used to route the PKCS#11 v3.2 standard CKM_ML_KEM
// mechanism to a concrete implementation once its parameter set has been
// resolved from the public key object.
//
// All three FIPS 203 parameter sets are present. 768 and 1024 come from Go's
// crypto/mlkem; 512, which crypto/mlkem does not ship, is provided by
// pkg/quantum/mlkem512 wrapping CIRCL's FIPS 203 implementation (see
// generateMLKEM512KeyPair / encapsulateMLKEM512 in crypto_quantum.go). Do not
// remove the 512 entry: it is exercised end to end by
// TestMLKEM512EncapsulateDecapsulateRoundTrip, and dropping it would make the
// standard CKM_ML_KEM mechanism answer CKR_MECHANISM_PARAM_INVALID for a
// parameter set the token advertises and can perform. See resolveMLKEMLevel.
var mlkemEncapsulateVendorMechanism = map[int]MechanismType{
	512:  CKM_VENDOR_ML_KEM_512_ENCAPSULATE,
	768:  CKM_VENDOR_ML_KEM_768_ENCAPSULATE,
	1024: CKM_VENDOR_ML_KEM_1024_ENCAPSULATE,
}

// mlkemDecapsulateVendorMechanism is the decapsulation analog of
// mlkemEncapsulateVendorMechanism.
var mlkemDecapsulateVendorMechanism = map[int]MechanismType{
	512:  CKM_VENDOR_ML_KEM_512_DECAPSULATE,
	768:  CKM_VENDOR_ML_KEM_768_DECAPSULATE,
	1024: CKM_VENDOR_ML_KEM_1024_DECAPSULATE,
}

// mlkemCiphertextSizeByLevel maps a resolved ML-KEM security level to its
// FIPS 203 ciphertext size in bytes.
var mlkemCiphertextSizeByLevel = map[int]uint64{
	512:  MLKEM512CiphertextSize,
	768:  MLKEM768CiphertextSize,
	1024: MLKEM1024CiphertextSize,
}

// resolveMLKEMLevel determines the concrete ML-KEM security level (512, 768,
// or 1024) for an operation using the PKCS#11 v3.2 standard CKM_ML_KEM
// mechanism. Per spec section 6.68.5, CKM_ML_KEM carries no mechanism
// parameter -- the parameter set is instead carried by the key object's
// CKA_PARAMETER_SET attribute, which takes priority when present.
//
// When CKA_PARAMETER_SET is absent (e.g. a legacy caller that predates the
// v3.2 KEM attribute), the level is inferred from fallbackLen, which the
// caller supplies as the length of whichever FIPS 203-sized value it already
// has on hand: the public key for encapsulation, or the ciphertext for
// decapsulation. ML-KEM public key and ciphertext sizes never collide across
// security levels, so this inference is unambiguous whenever fallbackLen
// matches a real FIPS 203 size.
//
// If resolution is still ambiguous (fallbackLen matches no known size, e.g.
// synthetic test data), ML-KEM-768 is used as the mandatory baseline
// parameter set; the crypto backend then rejects malformed key material on
// its own merits rather than this function guessing a level that happens to
// mask the real error.
//
// ML-KEM-512 resolves to nothing. Go's crypto/mlkem implements only 768 and
// 1024, so a key or ciphertext sized for 512 falls through to the baseline and
// is rejected there on its merits, rather than resolving to a level whose
// encapsulation, decapsulation and key generation all return
// CKR_MECHANISM_INVALID.
func resolveMLKEMLevel(keyObj *Object, fallbackLen int) int {
	if parameterSet, ok := parameterSetFromAttributeValue(keyObj.GetAttribute(CKA_PARAMETER_SET)); ok {
		switch parameterSet {
		case CKP_ML_KEM_512:
			return 512
		case CKP_ML_KEM_768:
			return 768
		case CKP_ML_KEM_1024:
			return 1024
		}
	}
	// The length fallback only helps for a key that carries no CKA_PARAMETER_SET,
	// and it can only distinguish levels for material whose length differs
	// between them: public keys and ciphertexts do, private keys do not, since
	// every level stores the same 64-byte seed. A private key without a
	// parameter set is therefore indistinguishable here and takes the default.
	switch fallbackLen {
	case MLKEM512PublicKeySize, MLKEM512CiphertextSize:
		return 512
	case MLKEM768PublicKeySize, MLKEM768CiphertextSize:
		return 768
	case MLKEM1024PublicKeySize: // == MLKEM1024CiphertextSize (1568 bytes)
		return 1024
	default:
		return 768
	}
}

// resolveKEMDispatchMechanism returns the mechanism to use when dispatching
// to the quantum crypto backend. When mechanism is the PKCS#11 v3.2 standard
// CKM_ML_KEM, it resolves the concrete per-level vendor mechanism (which the
// backend's GetMLKEMSecurityLevel already understands) via resolveMLKEMLevel
// and vendorMechanisms; otherwise mechanism is returned unchanged, so
// legacy vendor-mechanism callers are unaffected.
//
// The original mechanism -- not the resolved one -- must still be used when
// recording CKA_KEY_GEN_MECHANISM-style bookkeeping, since that should
// reflect what the caller actually invoked.
func resolveKEMDispatchMechanism(mechanism *Mechanism, keyObj *Object, fallbackLen int, vendorMechanisms map[int]MechanismType) (*Mechanism, error) {
	if mechanism.Type != CKM_ML_KEM {
		return mechanism, nil
	}
	level := resolveMLKEMLevel(keyObj, fallbackLen)
	vendorType, ok := vendorMechanisms[level]
	if !ok {
		return nil, NewPKCS11ErrorWithMessage(
			CKR_MECHANISM_PARAM_INVALID, "unable to resolve ML-KEM parameter set")
	}
	return &Mechanism{
		Type:           vendorType,
		Parameter:      mechanism.Parameter,
		TypedParameter: mechanism.TypedParameter,
	}, nil
}

// EncapsulateKey creates a shared secret key and ciphertext using a public key
// and a KEM mechanism. The shared secret is stored as a new key object described
// by the provided template.
//
// This implements C_EncapsulateKey per PKCS#11 v3.2 specification §5.18.8.
//
// The session must be logged in when the token advertises CKF_LOGIN_REQUIRED,
// and it must be read-write because the call creates a key object. The public
// key must carry CKA_ENCAPSULATE, must admit the mechanism through
// CKA_ALLOWED_MECHANISMS, and contributes its CKA_ENCAPSULATE_TEMPLATE to the
// caller's template. These are the gates C_WrapKey applies, enforced here in
// the same order and with the codes C_EncapsulateKey's return table lists.
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

	// Validate session exists
	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return ObjectHandle(InvalidHandle), nil, NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}

	// The token's CKF_LOGIN_REQUIRED gates key management just as it gates the
	// crypto operations; which verb the caller uses must not change the policy.
	// C_EncapsulateKey both creates a key object on the token and emits the
	// ciphertext that binds it, so an unauthenticated session that reached it
	// obtained a usable shared secret through a verb C_WrapKey and
	// C_UnwrapKey refuse it. The check sits immediately after the session
	// lookup, the position C_WrapKey puts it in, so the wrap and KEM families
	// refuse in the same order.
	if rv := m.requireLogin(slotID, session); rv != CKR_OK {
		return ObjectHandle(InvalidHandle), nil, NewPKCS11Error(rv)
	}

	// Encapsulation creates a key object, so it needs a read-write session.
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

	// Resolve through the session's access context so a session cannot
	// encapsulate to a key on another slot or one it may not see.
	pubKeyObj, err := m.objectManager.GetObjectFor(NewAccessContext(sessionHandle, session), publicKeyHandle)
	if err != nil {
		return ObjectHandle(InvalidHandle), nil, NewPKCS11Error(CKR_KEY_HANDLE_INVALID)
	}

	// Validate the key is a public key (CKO_PUBLIC_KEY)
	if pubKeyObj.Class != CKO_PUBLIC_KEY {
		return ObjectHandle(InvalidHandle), nil, NewPKCS11ErrorWithMessage(
			CKR_KEY_HANDLE_INVALID, "key is not a public key")
	}

	// Validate CKA_ENCAPSULATE attribute is set on the public key.
	//
	// The code is CKR_KEY_FUNCTION_NOT_PERMITTED, for the reason C_DeriveKey
	// gives for CKA_DERIVE. PKCS#11 v3.2 §5.1.6 defines it as "an attempt has
	// been made to use a key for a cryptographic purpose that the key's
	// attributes are not set to allow it to do", and defines
	// CKR_KEY_TYPE_INCONSISTENT as "the specified key is not the correct type of
	// key to use with the specified mechanism" -- a different fault, since an
	// ML-KEM key under CKM_ML_KEM is the right type. §5.18.8's return list
	// omits the code, but §5.1.7 lets any applicable code be returned.
	if !isBoolAttributeTrue(pubKeyObj, CKA_ENCAPSULATE) {
		return ObjectHandle(InvalidHandle), nil, NewPKCS11ErrorWithMessage(
			CKR_KEY_FUNCTION_NOT_PERMITTED, "public key does not permit encapsulation")
	}

	// CKA_ALLOWED_MECHANISMS on the public key names the mechanisms that key
	// may be used with, encapsulation included (v3.2 §4.8.2). The mechanism
	// tested is the one the caller named, not the per-level vendor mechanism
	// resolved below, because the caller's is what the key's list is written
	// against.
	if mechErr := pubKeyObj.CheckAllowedMechanism(mechanism.Type); mechErr != nil {
		return ObjectHandle(InvalidHandle), nil, mechErr
	}

	// CKA_ENCAPSULATE_TEMPLATE adds the public key's attribute set to the
	// caller's template for the shared secret about to be created (v3.2
	// §5.18.8, by the C_UnwrapKey rule of §5.14.4).
	template, err = pubKeyObj.ApplyAttributeTemplate(CKA_ENCAPSULATE_TEMPLATE, template)
	if err != nil {
		return ObjectHandle(InvalidHandle), nil, err
	}

	// Refuse before encapsulating: a shared secret this token could not give
	// back after a restart must not be created at all, and encapsulating first
	// would emit to the peer a ciphertext for a key about to be discarded. The
	// merged template is the one tested, because CKA_ENCAPSULATE_TEMPLATE can
	// itself be what asks for the combination that cannot be stored.
	if persistErr := sharedSecretPersistenceError(template); persistErr != nil {
		return ObjectHandle(InvalidHandle), nil, persistErr
	}

	// Retrieve public key material from CKA_VALUE
	pubKeyValue := pubKeyObj.GetAttribute(CKA_VALUE)
	if len(pubKeyValue) == 0 {
		return ObjectHandle(InvalidHandle), nil, NewPKCS11ErrorWithMessage(
			CKR_KEY_HANDLE_INVALID, "public key has no CKA_VALUE")
	}

	// Resolve the PKCS#11 v3.2 standard CKM_ML_KEM mechanism to a concrete
	// per-level vendor mechanism using the public key's CKA_PARAMETER_SET
	// attribute (falling back to the public key length). Vendor mechanisms
	// pass through unchanged.
	dispatchMechanism, err := resolveKEMDispatchMechanism(
		mechanism, pubKeyObj, len(pubKeyValue), mlkemEncapsulateVendorMechanism)
	if err != nil {
		return ObjectHandle(InvalidHandle), nil, err
	}

	// Delegate to build-tag-gated crypto dispatch
	sharedSecret, ciphertext, err := kemEncapsulate(m.quantumCrypto, dispatchMechanism, publicKeyHandle, pubKeyValue)
	if err != nil {
		return ObjectHandle(InvalidHandle), nil, err
	}
	defer enclave.Wipe(sharedSecret)

	// Build the secret key object template from the caller's template,
	// injecting the shared secret as CKA_VALUE and ensuring required
	// secret key attributes are present.
	secretKeyAttrs := buildSecretKeyTemplate(template, sharedSecret)

	// Create the secret key object via CreateDerivedObject rather than the
	// application-facing CreateObject. C_EncapsulateKey's result is neither
	// a C_CreateObject import nor a C_GenerateKey/C_GenerateKeyPair product
	// (v3.2 5.18.8), so its provenance attributes -- CKA_LOCAL,
	// CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE -- must be computed by the
	// token itself, not supplied through the template. CreateObject's
	// computedAttributes guard exists precisely to stop a caller from
	// forging those claims, so it correctly rejects a template that carries
	// them regardless of who the caller is; the token's own creation paths
	// use CreateDerivedObject instead, which computes them from the public
	// key that seeded the encapsulation (see its doc comment and
	// object.go's completeKeyTemplate).
	access := NewAccessContext(sessionHandle, session)
	keyHandle, err := m.objectManager.CreateDerivedObject(
		access, pubKeyObj, CKO_SECRET_KEY, CKK_GENERIC_SECRET, secretKeyAttrs)
	if err != nil {
		// The template failure keeps the code object creation determined —
		// CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT,
		// CKR_ATTRIBUTE_READ_ONLY or CKR_ATTRIBUTE_VALUE_INVALID, all of which
		// are in C_EncapsulateKey's return table. Collapsing them into
		// CKR_FUNCTION_FAILED told an application whose template was merely
		// wrong that the token had failed, and hid which attribute to fix.
		return ObjectHandle(InvalidHandle), nil, NewPKCS11ErrorFull(
			FromError(err), "failed to create shared secret key object", err)
	}

	// A CKA_TOKEN shared secret is on the token only once the store holds it
	// (v3.2 §4.4). Object creation used to be the last step, so C_EncapsulateKey
	// returned a handle and a ciphertext for a key the next process start would
	// not find — and the peer, holding the matching ciphertext, had no way to
	// learn that. The check above admitted only secrets this store can hold
	// whole, so a failure here is the store itself failing.
	if persistErr := m.persistNewObject(access, keyHandle, sessionHandle); persistErr != nil {
		return ObjectHandle(InvalidHandle), nil, NewPKCS11ErrorFull(
			CKR_DEVICE_ERROR, "failed to persist shared secret key object", persistErr)
	}

	return keyHandle, ciphertext, nil
}

// DecapsulateKey recovers a shared secret key from KEM ciphertext using a private key.
// The recovered shared secret is stored as a new key object described by the
// provided template.
//
// This implements C_DecapsulateKey per PKCS#11 v3.2 specification §5.18.9.
// Per the OASIS spec, the template precedes the ciphertext in the parameter list.
//
// The session must be logged in when the token advertises CKF_LOGIN_REQUIRED,
// and it must be read-write because the call creates a key object. The private
// key must carry CKA_DECAPSULATE and must admit the mechanism through
// CKA_ALLOWED_MECHANISMS. These are the gates C_UnwrapKey applies, enforced
// here in the same order and with the codes C_DecapsulateKey's return table
// lists.
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

	// Validate session exists
	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}

	// The token's CKF_LOGIN_REQUIRED gates key management just as it gates the
	// crypto operations; which verb the caller uses must not change the policy.
	// C_DecapsulateKey turns caller-supplied ciphertext into a key object on
	// the token using a private key it names, which is what C_UnwrapKey does
	// and refuses to do for an unauthenticated session. The check sits
	// immediately after the session lookup, the position C_UnwrapKey puts it
	// in, so the two import paths refuse in the same order.
	if rv := m.requireLogin(slotID, session); rv != CKR_OK {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(rv)
	}

	// Decapsulation creates a key object, so it needs a read-write session.
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
	privKeyObj, err := m.objectManager.GetObjectFor(NewAccessContext(sessionHandle, session), privateKeyHandle)
	if err != nil {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_UNWRAPPING_KEY_HANDLE_INVALID)
	}

	// CKA_ALWAYS_AUTHENTICATE deliberately does not gate this call. PKCS#11 v3.2
	// §4.10 defines the "use" it protects as "a cryptographic operation such as
	// sign or decrypt" and gives re-authentication exactly one form: "calling
	// C_Login with userType set to CKU_CONTEXT_SPECIFIC immediately after a
	// cryptographic operation using the key has been initiated (e.g. after
	// C_SignInit)". C_DecapsulateKey has no Init phase, so there is no moment at
	// which an application could issue that login for this call -- C_Login
	// answers CKR_OPERATION_NOT_INITIALIZED -- and gating on it would refuse
	// every correctly configured key outright.
	//
	// A gate here was not merely unsatisfiable, it was harmful. It could fire
	// only when a decryption was already active on this same private key, and
	// the one grant it then found belonged to that decryption: the
	// decapsulation consumed it and the application's own C_Decrypt then failed
	// CKR_USER_NOT_LOGGED_IN. C_UnwrapKey and C_UnwrapKeyAuthenticated drop it
	// for the same reason, so the three key-management verbs answer alike.

	// Validate the key is a private key (CKO_PRIVATE_KEY)
	if privKeyObj.Class != CKO_PRIVATE_KEY {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorWithMessage(
			CKR_UNWRAPPING_KEY_HANDLE_INVALID, "key is not a private key")
	}

	// Validate CKA_DECAPSULATE attribute is set on the private key.
	//
	// The code is CKR_KEY_FUNCTION_NOT_PERMITTED, for the reason
	// C_EncapsulateKey gives for CKA_ENCAPSULATE (§5.1.6, §5.1.7, §5.18.9).
	if !isBoolAttributeTrue(privKeyObj, CKA_DECAPSULATE) {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorWithMessage(
			CKR_KEY_FUNCTION_NOT_PERMITTED, "private key does not permit decapsulation")
	}

	// CKA_ALLOWED_MECHANISMS on the private key names the mechanisms that key
	// may be used with, decapsulation included (v3.2 §4.8.2). The mechanism
	// tested is the one the caller named, not the per-level vendor mechanism
	// resolved below, because the caller's is what the key's list is written
	// against.
	if mechErr := privKeyObj.CheckAllowedMechanism(mechanism.Type); mechErr != nil {
		return ObjectHandle(InvalidHandle), mechErr
	}

	// CKA_DECAPSULATE_TEMPLATE adds the private key's attribute set to the
	// caller's template for the shared secret about to be created (v3.2
	// §5.18.9, by the C_UnwrapKey rule of §5.14.4).
	template, err = privKeyObj.ApplyAttributeTemplate(CKA_DECAPSULATE_TEMPLATE, template)
	if err != nil {
		return ObjectHandle(InvalidHandle), err
	}

	// Refuse before decapsulating, for the reason EncapsulateKey gives: a shared
	// secret this token could not give back after a restart must not be created
	// at all. The merged template is the one tested, because
	// CKA_DECAPSULATE_TEMPLATE can itself be what asks for the combination that
	// cannot be stored.
	if persistErr := sharedSecretPersistenceError(template); persistErr != nil {
		return ObjectHandle(InvalidHandle), persistErr
	}

	// Retrieve private key material from CKA_VALUE and copy to a local buffer
	// so the deferred enclave.Wipe does not corrupt the object store.
	privKeyRef := privKeyObj.GetAttribute(CKA_VALUE)
	if len(privKeyRef) == 0 {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorWithMessage(
			CKR_UNWRAPPING_KEY_HANDLE_INVALID, "private key has no CKA_VALUE")
	}
	privKeyValue := make([]byte, len(privKeyRef))
	copy(privKeyValue, privKeyRef)
	defer enclave.Wipe(privKeyValue)

	// Resolve the PKCS#11 v3.2 standard CKM_ML_KEM mechanism to a concrete
	// per-level vendor mechanism using the private key's CKA_PARAMETER_SET
	// attribute (falling back to the ciphertext length, since this module
	// stores all ML-KEM private keys as a fixed-size seed that cannot itself
	// disambiguate the security level). Vendor mechanisms pass through
	// unchanged.
	dispatchMechanism, err := resolveKEMDispatchMechanism(
		mechanism, privKeyObj, len(ciphertext), mlkemDecapsulateVendorMechanism)
	if err != nil {
		return ObjectHandle(InvalidHandle), err
	}

	// Delegate to build-tag-gated crypto dispatch
	sharedSecret, err := kemDecapsulate(m.quantumCrypto, dispatchMechanism, privateKeyHandle, privKeyValue, ciphertext)
	if err != nil {
		return ObjectHandle(InvalidHandle), err
	}
	defer enclave.Wipe(sharedSecret)

	// Build the secret key object template from the caller's template,
	// injecting the shared secret as CKA_VALUE.
	secretKeyAttrs := buildSecretKeyTemplate(template, sharedSecret)

	// Create the secret key object via CreateDerivedObject; see the parallel
	// comment in EncapsulateKey for why CreateObject cannot be used here.
	// The private key that seeded the decapsulation is the base object,
	// so a private key that was itself never-extractable/always-sensitive
	// keeps the resulting shared secret's history attributes honest rather
	// than laundering them through the KEM operation (v3.2 5.18.9).
	access := NewAccessContext(sessionHandle, session)
	keyHandle, err := m.objectManager.CreateDerivedObject(
		access, privKeyObj, CKO_SECRET_KEY, CKK_GENERIC_SECRET, secretKeyAttrs)
	if err != nil {
		// The template failure keeps the code object creation determined —
		// CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT,
		// CKR_ATTRIBUTE_READ_ONLY or CKR_ATTRIBUTE_VALUE_INVALID, all of which
		// are in C_DecapsulateKey's return table. Collapsing them into
		// CKR_FUNCTION_FAILED told an application whose template was merely
		// wrong that the token had failed, and hid which attribute to fix.
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorFull(
			FromError(err), "failed to create shared secret key object", err)
	}

	// A CKA_TOKEN shared secret is on the token only once the store holds it
	// (v3.2 §4.4), for the reason EncapsulateKey gives. The ciphertext is still
	// in the caller's hands, so a token failure reported here is one it can
	// retry; a handle to an object that was never stored is not.
	if persistErr := m.persistNewObject(access, keyHandle, sessionHandle); persistErr != nil {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorFull(
			CKR_DEVICE_ERROR, "failed to persist shared secret key object", persistErr)
	}

	return keyHandle, nil
}

// sharedSecretPersistenceError refuses a KEM shared secret that this token could
// not give back after a restart.
//
// A shared secret is not like a C_UnwrapKey result. C_UnwrapKey unwraps inside
// the backend and gives its object a KeyID, so the object is metadata and the
// material stays where the backend keeps it; a KEM shared secret is created by
// CreateDerivedObject with no KeyID and no backend name, so the only copy of it
// is CKA_VALUE on the object itself. ModuleStorage.SaveObject withholds every
// attribute IsSensitiveAttribute names — CKA_VALUE among them — from a key
// object that protects its material, because the token store is a plaintext
// file and writing the secret there would place in the clear exactly the bytes
// CKA_SENSITIVE and CKA_EXTRACTABLE=CK_FALSE promise never leave the token.
//
// The two rules meet on a CKA_TOKEN=CK_TRUE shared secret the caller also asks
// to be protected: what persists is a key-shaped shell with no key in it, and
// every use of it after the restart fails on a handle the application had every
// reason to believe was a key. That is the same defect
// quantumPrivateKeyPersistenceError refuses for a post-quantum private key, and
// it is refused here for the same reason rather than persisted, because
// persisting it is what produces the shell.
//
// CKR_TEMPLATE_INCONSISTENT is in C_EncapsulateKey's and C_DecapsulateKey's
// return tables (v3.2 §5.18.8, §5.18.9), and §5.1 defines it as a template
// carrying conflicting attributes — which asking this token both to keep a key
// and to protect its only copy of that key is.
//
// The combination that IS storable stays allowed, and it is the default: a
// shared secret is created through buildSecretKeyTemplate, which supplies
// CKA_SENSITIVE=CK_FALSE and CKA_EXTRACTABLE=CK_TRUE for a template that states
// neither — which is why those, and not the class defaults, are the fallbacks
// used here. Such a secret makes no promise a plaintext store would break, so
// its CKA_VALUE persists like any other attribute and it comes back usable.
func sharedSecretPersistenceError(template []Attribute) error {
	if !templateBoolIsTrue(template, CKA_TOKEN, false) {
		return nil
	}

	sensitive := templateBoolIsTrue(template, CKA_SENSITIVE, false)
	extractable := templateBoolIsTrue(template, CKA_EXTRACTABLE, true)
	if !sensitive && extractable {
		return nil
	}

	return NewPKCS11ErrorWithMessage(CKR_TEMPLATE_INCONSISTENT,
		"a CKA_TOKEN KEM shared secret must be CKA_SENSITIVE=CK_FALSE and CKA_EXTRACTABLE=CK_TRUE: this token cannot persist protected key material")
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
			if cat == CategoryEncapsulate {
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
			if cat == CategoryDecapsulate {
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
// This function only ever emits attributes an application is allowed to
// specify in a creation template. CKA_LOCAL, CKA_ALWAYS_SENSITIVE and
// CKA_NEVER_EXTRACTABLE are token-computed provenance attributes (v3.2
// section 4.9) that object.go's computedAttributes guard rejects from any
// creation template; EncapsulateKey/DecapsulateKey pass the returned
// attributes to ObjectManager.CreateDerivedObject, which computes those
// three attributes itself from the base key that seeded the KEM operation,
// exactly as it does for C_DeriveKey and C_UnwrapKey results.
//
// Per PKCS#11 v3.2 sections 5.18.8/5.18.9:
//   - CKA_EXTRACTABLE: the value from the input template, defaulting to
//     CK_TRUE if the caller does not supply one.
func buildSecretKeyTemplate(template []Attribute, sharedSecret []byte) []Attribute {
	// Start with required attributes; reserve extra capacity for injected attrs
	attrs := make([]Attribute, 0, len(template)+6)

	// Track which attributes the caller already provided, to decide whether
	// a default must be injected.
	hasClass := false
	hasKeyType := false
	hasValueLen := false
	hasExtractable := false
	hasSensitive := false

	for _, attr := range template {
		switch attr.Type {
		case CKA_CLASS:
			hasClass = true
		case CKA_KEY_TYPE:
			hasKeyType = true
		case CKA_VALUE:
			// Override caller's CKA_VALUE with the actual shared secret
			continue
		case CKA_VALUE_LEN:
			hasValueLen = true
		case CKA_EXTRACTABLE:
			hasExtractable = true
		case CKA_SENSITIVE:
			hasSensitive = true
		}
		attrs = append(attrs, attr)
	}

	// Ensure CKA_CLASS is CKO_SECRET_KEY. CK_OBJECT_CLASS, CK_KEY_TYPE and
	// CK_ULONG-valued CKA_VALUE_LEN below are all written at the native CK_ULONG
	// width: these are values the token supplies for a caller who did not, and
	// C_GetAttributeValue must hand back a whole CK_ULONG to an application that
	// allocated sizeof(CK_ULONG) for one. See normalizeULongWidth.
	if !hasClass {
		attrs = append(attrs, NewULongAttribute(CKA_CLASS, uint64(CKO_SECRET_KEY)))
	}

	// Ensure CKA_KEY_TYPE is set; default to CKK_GENERIC_SECRET
	if !hasKeyType {
		attrs = append(attrs, NewULongAttribute(CKA_KEY_TYPE, uint64(CKK_GENERIC_SECRET)))
	}

	// Always set CKA_VALUE to the shared secret (ignore caller-provided value)
	attrs = append(attrs, NewAttribute(CKA_VALUE, sharedSecret))

	// Set CKA_VALUE_LEN if not already provided. PKCS#11 v3.2 §6.10.3 types it
	// as a CK_ULONG, which is ckULongSize bytes here.
	if !hasValueLen {
		attrs = append(attrs, NewULongAttribute(CKA_VALUE_LEN, uint64(len(sharedSecret))))
	}

	// CKA_EXTRACTABLE: defaults to CK_TRUE per 5.18.8/5.18.9 unless the
	// caller's template already set it (handled in the loop above).
	if !hasExtractable {
		attrs = append(attrs, NewBoolAttribute(CKA_EXTRACTABLE, true))
	}

	// CKA_SENSITIVE default if not provided by caller (module-general default)
	if !hasSensitive {
		attrs = append(attrs, NewBoolAttribute(CKA_SENSITIVE, false))
	}

	// CKA_LOCAL, CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE are
	// deliberately not set here: they are token-computed (v3.2 section 4.9)
	// and CreateDerivedObject sets them itself once this template reaches it.
	return attrs
}

// KEMCiphertextSize returns the expected ciphertext size for the given KEM
// mechanism without performing any cryptographic operation. This is used by
// the CGO layer to handle PKCS#11 size queries (pCiphertext=NULL) without
// performing a full encapsulation or creating key objects.
//
// Every gate C_EncapsulateKey applies is applied here too, because this is the
// function the C ABI reaches first: exports_v32.go's C_EncapsulateKey calls it
// on the NULL-pCiphertext probe and again as a buffer pre-check before the real
// encapsulation, so a gate present only in EncapsulateKey is never the one a C
// caller meets. A size query must therefore answer with the same code the
// encapsulation itself would (v3.2 §5.18.8), or an application sizes a buffer
// for a call that can only fail.
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
	slotID, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return 0, NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}

	// The login requirement is checked here for the same reason the attribute
	// checks below are: a size query must answer with the same code the
	// encapsulation itself would. It carries more weight than the others,
	// because the C ABI calls this function before EncapsulateKey on both the
	// probe and the real call -- so for a C caller this is where
	// CKF_LOGIN_REQUIRED is actually enforced. It also keeps the query from
	// telling an unauthenticated session the ciphertext length, which names the
	// ML-KEM parameter set of a key it has not authenticated to use.
	if rv := m.requireLogin(slotID, session); rv != CKR_OK {
		return 0, NewPKCS11Error(rv)
	}

	// The read-write requirement is checked here for the same reason the
	// attribute checks below are: a size query must answer with the same code
	// the encapsulation itself would (v3.2 §4.8.2). EncapsulateKey creates a
	// key object and so rejects a read-only session with
	// CKR_SESSION_READ_ONLY; a size query that succeeded there handed the
	// application a buffer size for a call that can only fail. The check sits
	// immediately after session lookup so the two functions reject in the same
	// order.
	if !session.IsReadWrite() {
		return 0, NewPKCS11Error(CKR_SESSION_READ_ONLY)
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

	// Validate public key handle through the session's access context, so a
	// size query cannot become an existence oracle for hidden objects.
	pubKeyObj, err := m.objectManager.GetObjectFor(NewAccessContext(sessionHandle, session), publicKeyHandle)
	if err != nil {
		return 0, NewPKCS11Error(CKR_KEY_HANDLE_INVALID)
	}
	if pubKeyObj.Class != CKO_PUBLIC_KEY {
		return 0, NewPKCS11ErrorWithMessage(CKR_KEY_HANDLE_INVALID, "key is not a public key")
	}
	// CKR_KEY_FUNCTION_NOT_PERMITTED, for the reason given in EncapsulateKey:
	// the size query must answer with the same code the encapsulation itself
	// would.
	if !isBoolAttributeTrue(pubKeyObj, CKA_ENCAPSULATE) {
		return 0, NewPKCS11ErrorWithMessage(CKR_KEY_FUNCTION_NOT_PERMITTED,
			"public key does not permit encapsulation")
	}

	// CKA_ALLOWED_MECHANISMS is checked here too, for the reason given just
	// above: a size query must answer with the same code the encapsulation
	// itself would, or an application sizes a buffer for a call that can only
	// fail (v3.2 §4.8.2).
	if mechErr := pubKeyObj.CheckAllowedMechanism(mechanism.Type); mechErr != nil {
		return 0, mechErr
	}

	// For the PKCS#11 v3.2 standard CKM_ML_KEM mechanism, resolve the
	// concrete parameter set from the public key (CKA_PARAMETER_SET, falling
	// back to the public key length) so the reported size actually matches
	// the queried key, rather than assuming a fixed level regardless of key.
	if mechanism.Type == CKM_ML_KEM {
		level := resolveMLKEMLevel(pubKeyObj, len(pubKeyObj.GetAttribute(CKA_VALUE)))
		size, ok := mlkemCiphertextSizeByLevel[level]
		if !ok {
			return 0, NewPKCS11ErrorWithMessage(
				CKR_MECHANISM_INVALID, "unable to resolve ML-KEM parameter set")
		}
		return size, nil
	}

	// Delegate to build-tag-gated size lookup for legacy vendor mechanisms.
	return kemCiphertextSize(mechanism)
}
