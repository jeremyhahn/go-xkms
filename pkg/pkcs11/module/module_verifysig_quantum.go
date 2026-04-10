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

// Package module provides build-tag-gated quantum signature-first verification helpers.
//
// When built with the "quantum" build tag, these functions delegate to the
// QuantumCryptoManager for ML-DSA signature-first verification operations
// as specified in PKCS#11 v3.2.
package module

// verifySigInit initializes a quantum signature-first verification operation
// by delegating to QuantumCryptoManager.QuantumVerifyInit.
//
// Parameters:
//   - quantumCrypto: the Module's quantumCrypto field (typed as any)
//   - mech: the PKCS#11 mechanism for verification
//   - keyHandle: the object handle of the verification key
//   - publicKey: the raw public key bytes (CKA_VALUE from the key object)
//
// Returns:
//   - interface{}: the initialized QuantumVerifyOperation (stored in session CryptoOp)
//   - error: nil on success, or a PKCS11Error
func verifySigInit(quantumCrypto any, mech *Mechanism, keyHandle ObjectHandle, publicKey []byte) (interface{}, error) {
	qcm, ok := quantumCrypto.(*QuantumCryptoManager)
	if !ok || qcm == nil {
		return nil, NewPKCS11Error(CKR_MECHANISM_INVALID)
	}
	return qcm.QuantumVerifyInit(mech, keyHandle, "verifysig", "quantum", publicKey)
}

// verifySigVerify performs quantum signature-first verification by delegating to
// QuantumCryptoManager.QuantumVerify.
//
// Parameters:
//   - quantumCrypto: the Module's quantumCrypto field (typed as any)
//   - op: the QuantumVerifyOperation initialized by verifySigInit
//   - data: the data to verify the signature against
//   - signature: the signature (provided at init time for signature-first flow)
//
// Returns:
//   - error: nil if the signature is valid, CKR_SIGNATURE_INVALID if not, or another PKCS11Error
func verifySigVerify(quantumCrypto any, op interface{}, data, signature []byte) error {
	qcm, ok := quantumCrypto.(*QuantumCryptoManager)
	if !ok || qcm == nil {
		return NewPKCS11Error(CKR_MECHANISM_INVALID)
	}
	verifyOp, ok := op.(*QuantumVerifyOperation)
	if !ok {
		return NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}
	return qcm.QuantumVerify(verifyOp, data, signature)
}
