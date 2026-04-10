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

// Package module provides PKCS#11 (Cryptoki) v3.2 signature-first verification operations.
//
// This file implements the PKCS#11 v3.2 "signature-first" verification pattern where the
// signature is provided before the data. This ordering is essential for post-quantum
// cryptographic (PQC) algorithms that require the signature to initialize the verification
// state machine before streaming data through it.
//
// Single-part operations:
//   - VerifySignatureInit: C_VerifySignatureInit -- initialize with mechanism, key, and signature
//   - VerifySignature: C_VerifySignature -- single-part verification
//
// Multi-part operations:
//   - VerifySignatureUpdate: C_VerifySignatureUpdate -- feed data incrementally
//   - VerifySignatureFinal: C_VerifySignatureFinal -- finalize and get result
//
// Cancellation:
//   - Calling VerifySignatureInit with a nil mechanism cancels any active operation
//
// References:
//   - OASIS PKCS#11 v3.2: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html
package module

// VerifySignatureInit initializes a signature-first verification operation.
// The signature is provided at initialization time, before the data, enabling
// streaming verification for PQC algorithms.
//
// This implements C_VerifySignatureInit per PKCS#11 v3.2 specification.
//
// Parameters:
//   - sessionHandle: the session handle
//   - mechanism: the verification mechanism
//   - keyHandle: handle to the verification (public) key
//   - signature: the signature to verify against
//
// Returns:
//   - error: nil on success, or a PKCS11Error
func (m *Module) VerifySignatureInit(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle, signature []byte) error {
	if !m.initialized.Load() {
		return NewPKCS11Error(CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Validate session exists
	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}

	// Per PKCS#11 v3.2 spec section 5.15.7: calling C_VerifySignatureInit
	// with a NULL mechanism cancels an active signature-first verification
	// operation and returns CKR_OK.
	if mechanism == nil {
		if session.HasOperationType(OperationVerifySignature) {
			session.ClearOperationType(OperationVerifySignature)
		}
		return nil
	}

	// Validate key handle exists and retrieve the key object
	keyObj, err := m.objectManager.GetObject(keyHandle)
	if err != nil {
		return NewPKCS11Error(CKR_KEY_HANDLE_INVALID)
	}

	// Validate signature is provided
	if len(signature) == 0 {
		return NewPKCS11Error(CKR_ARGUMENTS_BAD)
	}

	// Validate key has CKA_VERIFY attribute set to true
	if !isBoolAttributeTrue(keyObj, CKA_VERIFY) {
		return NewPKCS11Error(CKR_KEY_FUNCTION_NOT_PERMITTED)
	}

	// Fast-fail if an operation is already active (spec-required error priority)
	if session.HasOperationType(OperationVerifySignature) {
		return NewPKCS11Error(CKR_OPERATION_ACTIVE)
	}

	// Retrieve the public key material for quantum verification
	publicKey := keyObj.GetAttribute(CKA_VALUE)

	// Initialize the quantum verification operation via build-tag-gated helper.
	// This is side-effect-free and safe to run before claiming the operation slot.
	cryptoOp, initErr := verifySigInit(m.quantumCrypto, mechanism, keyHandle, publicKey)
	if initErr != nil {
		return initErr
	}

	// Store the signature and crypto operation in session state.
	// SetOperationIfAbsent atomically checks for absence and sets, preventing
	// TOCTOU races where concurrent Init calls both pass the HasOperationType check.
	sigCopy := make([]byte, len(signature))
	copy(sigCopy, signature)

	return session.SetOperationIfAbsent(OperationVerifySignature, &OperationState{
		Mechanism: mechanism.Type,
		KeyHandle: keyHandle,
		Data:      sigCopy,
		CryptoOp:  cryptoOp,
	})
}

// VerifySignature performs single-part signature-first verification.
// The signature must have been provided in a preceding VerifySignatureInit call.
//
// This implements C_VerifySignature per PKCS#11 v3.2 specification.
//
// Parameters:
//   - sessionHandle: the session handle
//   - data: the data to verify the signature against
//
// Returns:
//   - error: nil if the signature is valid, or a PKCS11Error
func (m *Module) VerifySignature(sessionHandle SessionHandle, data []byte) error {
	if !m.initialized.Load() {
		return NewPKCS11Error(CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Validate session exists
	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}

	// Atomically consume and remove the operation state in a single lock hold.
	// ConsumeOperation prevents TOCTOU races where a concurrent VerifySignatureInit
	// could set a new operation between extract and clear.
	op, err := session.ConsumeOperation(OperationVerifySignature)
	if err != nil {
		return err
	}

	// Perform verification with the stored signature and the provided data
	return verifySigVerify(m.quantumCrypto, op.CryptoOp, data, op.Data)
}

// VerifySignatureUpdate feeds data to a multi-part signature-first verification
// operation. Must be called after VerifySignatureInit and before VerifySignatureFinal.
//
// This implements C_VerifySignatureUpdate per PKCS#11 v3.2 specification.
//
// Parameters:
//   - sessionHandle: the session handle
//   - part: a chunk of data to feed into the verification
//
// Returns:
//   - error: nil on success, or a PKCS11Error
func (m *Module) VerifySignatureUpdate(sessionHandle SessionHandle, part []byte) error {
	if !m.initialized.Load() {
		return NewPKCS11Error(CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Validate session exists
	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}

	// Accumulate the data chunk in the live operation's multi-part state.
	// WithOperation returns CKR_OPERATION_NOT_INITIALIZED if no operation
	// is active, so no separate check is needed.
	//
	// Per PKCS#11 v3.2 spec section 5.15.9: if an error is returned by
	// C_VerifySignatureUpdate, the active multi-part operation is terminated
	// and the session is ready for a new operation.
	err := session.WithOperation(OperationVerifySignature, func(op *OperationState) error {
		acc, ok := op.CryptoOp.(*verifySigMultiPartState)
		if !ok {
			return NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
		}
		acc.accumulatedData = append(acc.accumulatedData, part...)
		return nil
	})
	if err != nil {
		// Terminate the active operation on error per spec.
		// CKR_OPERATION_NOT_INITIALIZED means there was no operation to clear.
		session.ClearOperationType(OperationVerifySignature)
	}
	return err
}

// VerifySignatureFinal completes a multi-part signature-first verification
// operation and returns the verification result.
//
// This implements C_VerifySignatureFinal per PKCS#11 v3.2 specification.
//
// Parameters:
//   - sessionHandle: the session handle
//
// Returns:
//   - error: nil if the signature is valid, or a PKCS11Error
func (m *Module) VerifySignatureFinal(sessionHandle SessionHandle) error {
	if !m.initialized.Load() {
		return NewPKCS11Error(CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Validate session exists
	_, session, rv := m.findSession(sessionHandle)
	if rv != CKR_OK {
		return NewPKCS11Error(CKR_SESSION_HANDLE_INVALID)
	}

	// Atomically consume and remove the operation state in a single lock hold.
	op, err := session.ConsumeOperation(OperationVerifySignature)
	if err != nil {
		return err
	}

	// Extract multi-part accumulator
	acc, ok := op.CryptoOp.(*verifySigMultiPartState)
	if !ok {
		return NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	// Perform verification with the accumulated data and stored signature
	return verifySigVerify(m.quantumCrypto, acc.quantumOp, acc.accumulatedData, op.Data)
}

// verifySigMultiPartState wraps the quantum operation and an accumulation buffer
// for multi-part signature-first verification. Single-part operations store the
// raw quantum operation directly; multi-part operations use this wrapper so that
// data can be accumulated across VerifySignatureUpdate calls while keeping the
// signature in OperationState.Data.
type verifySigMultiPartState struct {
	quantumOp       interface{}
	accumulatedData []byte
}
