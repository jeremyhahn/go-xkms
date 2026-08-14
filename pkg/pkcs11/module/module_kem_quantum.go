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

// Package module provides the quantum-enabled KEM dispatch functions for
// the PKCS#11 v3.2 C_EncapsulateKey and C_DecapsulateKey operations.
//
// When built with the "quantum" build tag, these functions type-assert the
// quantumCrypto field to *QuantumCryptoManager and delegate to the
// EncapsulateInit/Encapsulate and DecapsulateInit/Decapsulate methods.
//
// References:
//   - NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
//   - OASIS PKCS#11 v3.2: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html
package module

// kemEncapsulate performs KEM encapsulation using the QuantumCryptoManager.
// It initializes an encapsulation operation and executes it to produce
// a shared secret and ciphertext.
//
// Parameters:
//   - quantumCrypto: the module's quantumCrypto field (type-asserted to *QuantumCryptoManager)
//   - mechanism: the KEM mechanism specifying algorithm and security level
//   - publicKey: the recipient's public key material (CKA_VALUE)
//
// Returns:
//   - sharedSecret: the encapsulated shared secret for key derivation
//   - ciphertext: the KEM ciphertext to send to the decapsulator
//   - err: nil on success, or a PKCS11Error
func kemEncapsulate(quantumCrypto any, mechanism *Mechanism, publicKeyHandle ObjectHandle, publicKey []byte) (sharedSecret []byte, ciphertext []byte, err error) {
	qcm, ok := quantumCrypto.(*QuantumCryptoManager)
	if !ok || qcm == nil {
		return nil, nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"quantum crypto manager not available")
	}

	op, err := qcm.EncapsulateInit(mechanism, publicKeyHandle, "kem", "quantum", publicKey)
	if err != nil {
		return nil, nil, err
	}

	result, err := qcm.Encapsulate(op)
	if err != nil {
		return nil, nil, err
	}

	return result.SharedSecret, result.Ciphertext, nil
}

// kemDecapsulate performs KEM decapsulation using the QuantumCryptoManager.
// It initializes a decapsulation operation and executes it to recover
// the shared secret from the ciphertext.
//
// Parameters:
//   - quantumCrypto: the module's quantumCrypto field (type-asserted to *QuantumCryptoManager)
//   - mechanism: the KEM mechanism specifying algorithm and security level
//   - secretKey: the decapsulator's private key material (CKA_VALUE)
//   - ciphertext: the KEM ciphertext received from the encapsulator
//
// Returns:
//   - sharedSecret: the recovered shared secret
//   - err: nil on success, or a PKCS11Error
func kemDecapsulate(quantumCrypto any, mechanism *Mechanism, privateKeyHandle ObjectHandle, secretKey []byte, ciphertext []byte) (sharedSecret []byte, err error) {
	qcm, ok := quantumCrypto.(*QuantumCryptoManager)
	if !ok || qcm == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"quantum crypto manager not available")
	}

	op, err := qcm.DecapsulateInit(mechanism, privateKeyHandle, "kem", "quantum", secretKey)
	if err != nil {
		return nil, err
	}

	return qcm.Decapsulate(op, ciphertext)
}

// kemCiphertextSize returns the known ciphertext size for a KEM mechanism.
// This enables size queries without performing the actual encapsulation.
//
// The per-level vendor mechanisms resolve through the same table the dispatch
// path uses, rather than through a switch of their own. Listing only ML-KEM-768
// here made ML-KEM-1024 unreachable through the C ABI entirely: exports_v32.go
// calls KEMCiphertextSize before EncapsulateKey on both the NULL-buffer probe
// and the real call, so C_EncapsulateKey answered CKR_MECHANISM_INVALID for a
// mechanism the registry advertises and the crypto layer implements.
func kemCiphertextSize(mechanism *Mechanism) (uint64, error) {
	if level := GetMLKEMSecurityLevel(mechanism.Type); level != 0 {
		if size, ok := mlkemCiphertextSizeByLevel[level]; ok {
			return size, nil
		}
	}

	if mechanism.Type == CKM_ML_KEM {
		// The standard v3.2 mechanism carries no parameter set of its own; the
		// key object's CKA_PARAMETER_SET decides, and this function has no key.
		// ML-KEM-768 is FIPS 203's mandatory baseline and the level
		// resolveMLKEMLevel falls back to, so the two agree.
		return MLKEM768CiphertextSize, nil
	}

	return 0, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
		"unknown KEM mechanism for ciphertext size query")
}
