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

// Package module provides quantum-safe cryptographic operations for PKCS#11.
//
// This file implements ML-DSA (signing) and ML-KEM (encapsulation) operations
// using pure-Go implementations: cloudflare/circl for ML-DSA and crypto/mlkem
// for ML-KEM.
//
// References:
//   - NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
//   - NIST FIPS 204: Module-Lattice-Based Digital Signature Standard
package module

import (
	"bytes"

	"github.com/jeremyhahn/go-xkms/pkg/quantum/dilithium2"
	"github.com/jeremyhahn/go-xkms/pkg/quantum/kyber768"
	"github.com/jeremyhahn/go-xkms/pkg/quantum/mldsa65"
	"github.com/jeremyhahn/go-xkms/pkg/quantum/mldsa87"
	"github.com/jeremyhahn/go-xkms/pkg/quantum/mlkem1024"
)

// Seed sizes for quantum key storage. The PKCS#11 module stores seeds (not
// expanded private keys) as the CKA_VALUE for private key objects. These are
// distinct from the NIST spec expanded key sizes defined in mechanism_quantum.go.
const (
	// mldsaSeedSize is the ML-DSA seed size in bytes (all security levels).
	mldsaSeedSize = 32

	// mlkemSeedSize is the ML-KEM seed size in bytes (all security levels).
	mlkemSeedSize = 64
)

// QuantumSignOperation represents the state of a quantum signing operation.
type QuantumSignOperation struct {
	baseOperation
	keyHandle   ObjectHandle
	keyID       string
	backend     string
	data        *bytes.Buffer
	securityLvl int
	secretKey   []byte
}

// Type returns the operation type.
func (q *QuantumSignOperation) Type() OperationType {
	return OperationSign
}

// Reset resets the operation state.
func (q *QuantumSignOperation) Reset() {
	q.data.Reset()
	q.finalized = false
}

// KeyHandle returns the key handle for this operation.
func (q *QuantumSignOperation) KeyHandle() ObjectHandle {
	return q.keyHandle
}

// KeyID returns the key ID for this operation.
func (q *QuantumSignOperation) KeyID() string {
	return q.keyID
}

// Backend returns the backend for this operation.
func (q *QuantumSignOperation) Backend() string {
	return q.backend
}

// SecurityLevel returns the ML-DSA security level (44, 65, or 87).
func (q *QuantumSignOperation) SecurityLevel() int {
	return q.securityLvl
}

// newQuantumSignOperation creates a new quantum signing operation.
func newQuantumSignOperation(mech *Mechanism, keyHandle ObjectHandle, keyID, backend string, secretKey []byte) *QuantumSignOperation {
	return &QuantumSignOperation{
		baseOperation: baseOperation{mechanism: mech},
		keyHandle:     keyHandle,
		keyID:         keyID,
		backend:       backend,
		data:          new(bytes.Buffer),
		securityLvl:   GetMLDSASecurityLevel(mech.Type),
		secretKey:     secretKey,
	}
}

// QuantumVerifyOperation represents the state of a quantum verification operation.
type QuantumVerifyOperation struct {
	baseOperation
	keyHandle   ObjectHandle
	keyID       string
	backend     string
	data        *bytes.Buffer
	securityLvl int
	publicKey   []byte
}

// Type returns the operation type.
func (q *QuantumVerifyOperation) Type() OperationType {
	return OperationVerify
}

// Reset resets the operation state.
func (q *QuantumVerifyOperation) Reset() {
	q.data.Reset()
	q.finalized = false
}

// KeyHandle returns the key handle for this operation.
func (q *QuantumVerifyOperation) KeyHandle() ObjectHandle {
	return q.keyHandle
}

// KeyID returns the key ID for this operation.
func (q *QuantumVerifyOperation) KeyID() string {
	return q.keyID
}

// Backend returns the backend for this operation.
func (q *QuantumVerifyOperation) Backend() string {
	return q.backend
}

// SecurityLevel returns the ML-DSA security level (44, 65, or 87).
func (q *QuantumVerifyOperation) SecurityLevel() int {
	return q.securityLvl
}

// newQuantumVerifyOperation creates a new quantum verification operation.
func newQuantumVerifyOperation(mech *Mechanism, keyHandle ObjectHandle, keyID, backend string, publicKey []byte) *QuantumVerifyOperation {
	return &QuantumVerifyOperation{
		baseOperation: baseOperation{mechanism: mech},
		keyHandle:     keyHandle,
		keyID:         keyID,
		backend:       backend,
		data:          new(bytes.Buffer),
		securityLvl:   GetMLDSASecurityLevel(mech.Type),
		publicKey:     publicKey,
	}
}

// EncapsulateOperation represents the state of a KEM encapsulation operation.
type EncapsulateOperation struct {
	baseOperation
	keyHandle   ObjectHandle
	keyID       string
	backend     string
	securityLvl int
	publicKey   []byte
}

// Type returns the operation type.
func (e *EncapsulateOperation) Type() OperationType {
	return OperationType(CategoryEncapsulate)
}

// Reset resets the operation state.
func (e *EncapsulateOperation) Reset() {
	e.finalized = false
}

// KeyHandle returns the key handle for this operation.
func (e *EncapsulateOperation) KeyHandle() ObjectHandle {
	return e.keyHandle
}

// KeyID returns the key ID for this operation.
func (e *EncapsulateOperation) KeyID() string {
	return e.keyID
}

// Backend returns the backend for this operation.
func (e *EncapsulateOperation) Backend() string {
	return e.backend
}

// SecurityLevel returns the ML-KEM security level (768 or 1024).
func (e *EncapsulateOperation) SecurityLevel() int {
	return e.securityLvl
}

// newEncapsulateOperation creates a new encapsulation operation.
func newEncapsulateOperation(mech *Mechanism, keyHandle ObjectHandle, keyID, backend string, publicKey []byte) *EncapsulateOperation {
	return &EncapsulateOperation{
		baseOperation: baseOperation{mechanism: mech},
		keyHandle:     keyHandle,
		keyID:         keyID,
		backend:       backend,
		securityLvl:   GetMLKEMSecurityLevel(mech.Type),
		publicKey:     publicKey,
	}
}

// DecapsulateOperation represents the state of a KEM decapsulation operation.
type DecapsulateOperation struct {
	baseOperation
	keyHandle   ObjectHandle
	keyID       string
	backend     string
	securityLvl int
	secretKey   []byte
}

// Type returns the operation type.
func (d *DecapsulateOperation) Type() OperationType {
	return OperationType(CategoryDecapsulate)
}

// Reset resets the operation state.
func (d *DecapsulateOperation) Reset() {
	d.finalized = false
}

// KeyHandle returns the key handle for this operation.
func (d *DecapsulateOperation) KeyHandle() ObjectHandle {
	return d.keyHandle
}

// KeyID returns the key ID for this operation.
func (d *DecapsulateOperation) KeyID() string {
	return d.keyID
}

// Backend returns the backend for this operation.
func (d *DecapsulateOperation) Backend() string {
	return d.backend
}

// SecurityLevel returns the ML-KEM security level (768 or 1024).
func (d *DecapsulateOperation) SecurityLevel() int {
	return d.securityLvl
}

// newDecapsulateOperation creates a new decapsulation operation.
func newDecapsulateOperation(mech *Mechanism, keyHandle ObjectHandle, keyID, backend string, secretKey []byte) *DecapsulateOperation {
	return &DecapsulateOperation{
		baseOperation: baseOperation{mechanism: mech},
		keyHandle:     keyHandle,
		keyID:         keyID,
		backend:       backend,
		securityLvl:   GetMLKEMSecurityLevel(mech.Type),
		secretKey:     secretKey,
	}
}

// QuantumKeyPair holds a quantum key pair.
type QuantumKeyPair struct {
	PublicKey  []byte
	SecretKey  []byte
	KeyType    KeyType
	Mechanism  MechanismType
	PublicSize int
	SecretSize int
}

// QuantumCryptoManager provides quantum-safe cryptographic operations.
type QuantumCryptoManager struct {
	// No state needed - operations are stateless
}

// NewQuantumCryptoManager creates a new QuantumCryptoManager.
func NewQuantumCryptoManager() *QuantumCryptoManager {
	return &QuantumCryptoManager{}
}

// ---------------------------------------------------------------------------
// ML-DSA Key Generation
// ---------------------------------------------------------------------------

// GenerateMLDSAKeyPair generates an ML-DSA key pair for the specified security level.
// Supports ML-DSA-44 (level 44), ML-DSA-65 (level 65), and ML-DSA-87 (level 87).
func (qcm *QuantumCryptoManager) GenerateMLDSAKeyPair(securityLevel int) (*QuantumKeyPair, error) {
	switch securityLevel {
	case 44:
		return qcm.generateMLDSA44KeyPair()
	case 65:
		return qcm.generateMLDSA65KeyPair()
	case 87:
		return qcm.generateMLDSA87KeyPair()
	default:
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"invalid ML-DSA security level")
	}
}

// generateMLDSA44KeyPair generates an ML-DSA-44 (Dilithium2) key pair.
func (qcm *QuantumCryptoManager) generateMLDSA44KeyPair() (*QuantumKeyPair, error) {
	signer, err := dilithium2.New()
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"failed to initialize ML-DSA-44", err)
	}

	publicKey, err := signer.GenerateKeyPair()
	if err != nil {
		signer.Clean()
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"failed to generate ML-DSA-44 key pair", err)
	}

	// ExportSecretKey returns the 32-byte seed. Copy it before Clean()
	// zeroes the internal state.
	exportedKey := signer.ExportSecretKey()
	if exportedKey == nil {
		signer.Clean()
		return nil, NewPKCS11ErrorWithMessage(CKR_FUNCTION_FAILED,
			"failed to export ML-DSA-44 seed")
	}

	seedCopy := make([]byte, len(exportedKey))
	copy(seedCopy, exportedKey)

	pubKeyCopy := make([]byte, len(publicKey))
	copy(pubKeyCopy, publicKey)

	signer.Clean()

	return &QuantumKeyPair{
		PublicKey:  pubKeyCopy,
		SecretKey:  seedCopy,
		KeyType:    CKK_VENDOR_ML_DSA,
		Mechanism:  CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN,
		PublicSize: MLDSA44PublicKeySize,
		SecretSize: mldsaSeedSize,
	}, nil
}

// generateMLDSA65KeyPair generates an ML-DSA-65 key pair.
func (qcm *QuantumCryptoManager) generateMLDSA65KeyPair() (*QuantumKeyPair, error) {
	signer, err := mldsa65.New()
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"failed to initialize ML-DSA-65", err)
	}

	publicKey, err := signer.GenerateKeyPair()
	if err != nil {
		signer.Clean()
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"failed to generate ML-DSA-65 key pair", err)
	}

	exportedKey := signer.ExportSecretKey()
	if exportedKey == nil {
		signer.Clean()
		return nil, NewPKCS11ErrorWithMessage(CKR_FUNCTION_FAILED,
			"failed to export ML-DSA-65 seed")
	}

	seedCopy := make([]byte, len(exportedKey))
	copy(seedCopy, exportedKey)

	pubKeyCopy := make([]byte, len(publicKey))
	copy(pubKeyCopy, publicKey)

	signer.Clean()

	return &QuantumKeyPair{
		PublicKey:  pubKeyCopy,
		SecretKey:  seedCopy,
		KeyType:    CKK_VENDOR_ML_DSA,
		Mechanism:  CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN,
		PublicSize: MLDSA65PublicKeySize,
		SecretSize: mldsaSeedSize,
	}, nil
}

// generateMLDSA87KeyPair generates an ML-DSA-87 key pair.
func (qcm *QuantumCryptoManager) generateMLDSA87KeyPair() (*QuantumKeyPair, error) {
	signer, err := mldsa87.New()
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"failed to initialize ML-DSA-87", err)
	}

	publicKey, err := signer.GenerateKeyPair()
	if err != nil {
		signer.Clean()
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"failed to generate ML-DSA-87 key pair", err)
	}

	exportedKey := signer.ExportSecretKey()
	if exportedKey == nil {
		signer.Clean()
		return nil, NewPKCS11ErrorWithMessage(CKR_FUNCTION_FAILED,
			"failed to export ML-DSA-87 seed")
	}

	seedCopy := make([]byte, len(exportedKey))
	copy(seedCopy, exportedKey)

	pubKeyCopy := make([]byte, len(publicKey))
	copy(pubKeyCopy, publicKey)

	signer.Clean()

	return &QuantumKeyPair{
		PublicKey:  pubKeyCopy,
		SecretKey:  seedCopy,
		KeyType:    CKK_VENDOR_ML_DSA,
		Mechanism:  CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN,
		PublicSize: MLDSA87PublicKeySize,
		SecretSize: mldsaSeedSize,
	}, nil
}

// ---------------------------------------------------------------------------
// ML-KEM Key Generation
// ---------------------------------------------------------------------------

// GenerateMLKEMKeyPair generates an ML-KEM key pair for the specified security level.
// Supports ML-KEM-768 (level 768) and ML-KEM-1024 (level 1024).
func (qcm *QuantumCryptoManager) GenerateMLKEMKeyPair(securityLevel int) (*QuantumKeyPair, error) {
	switch securityLevel {
	case 768:
		return qcm.generateMLKEM768KeyPair()
	case 1024:
		return qcm.generateMLKEM1024KeyPair()
	default:
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"invalid ML-KEM security level (supported: 768, 1024)")
	}
}

// generateMLKEM768KeyPair generates an ML-KEM-768 (Kyber768) key pair.
func (qcm *QuantumCryptoManager) generateMLKEM768KeyPair() (*QuantumKeyPair, error) {
	kem, err := kyber768.New()
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"failed to initialize ML-KEM-768", err)
	}

	publicKey, err := kem.GenerateKeyPair()
	if err != nil {
		kem.Clean()
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"failed to generate ML-KEM-768 key pair", err)
	}

	// ExportSecretKey returns the 64-byte seed. Copy before Clean().
	exportedKey := kem.ExportSecretKey()
	if exportedKey == nil {
		kem.Clean()
		return nil, NewPKCS11ErrorWithMessage(CKR_FUNCTION_FAILED,
			"failed to export ML-KEM-768 seed")
	}

	secretKey := make([]byte, len(exportedKey))
	copy(secretKey, exportedKey)

	pubKeyCopy := make([]byte, len(publicKey))
	copy(pubKeyCopy, publicKey)

	kem.Clean()

	return &QuantumKeyPair{
		PublicKey:  pubKeyCopy,
		SecretKey:  secretKey,
		KeyType:    CKK_VENDOR_ML_KEM,
		Mechanism:  CKM_VENDOR_ML_KEM_768_KEY_GEN,
		PublicSize: MLKEM768PublicKeySize,
		SecretSize: mlkemSeedSize,
	}, nil
}

// generateMLKEM1024KeyPair generates an ML-KEM-1024 key pair.
func (qcm *QuantumCryptoManager) generateMLKEM1024KeyPair() (*QuantumKeyPair, error) {
	kem, err := mlkem1024.New()
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"failed to initialize ML-KEM-1024", err)
	}

	publicKey, err := kem.GenerateKeyPair()
	if err != nil {
		kem.Clean()
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"failed to generate ML-KEM-1024 key pair", err)
	}

	exportedKey := kem.ExportSecretKey()
	if exportedKey == nil {
		kem.Clean()
		return nil, NewPKCS11ErrorWithMessage(CKR_FUNCTION_FAILED,
			"failed to export ML-KEM-1024 seed")
	}

	secretKey := make([]byte, len(exportedKey))
	copy(secretKey, exportedKey)

	pubKeyCopy := make([]byte, len(publicKey))
	copy(pubKeyCopy, publicKey)

	kem.Clean()

	return &QuantumKeyPair{
		PublicKey:  pubKeyCopy,
		SecretKey:  secretKey,
		KeyType:    CKK_VENDOR_ML_KEM,
		Mechanism:  CKM_VENDOR_ML_KEM_1024_KEY_GEN,
		PublicSize: MLKEM1024PublicKeySize,
		SecretSize: mlkemSeedSize,
	}, nil
}

// ---------------------------------------------------------------------------
// ML-DSA Signing
// ---------------------------------------------------------------------------

// QuantumSignInit initializes a quantum signing operation.
func (qcm *QuantumCryptoManager) QuantumSignInit(mech *Mechanism, keyHandle ObjectHandle, keyID, backend string, secretKey []byte) (*QuantumSignOperation, error) {
	if mech == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "mechanism is nil")
	}

	if keyHandle == 0 {
		return nil, NewPKCS11Error(CKR_KEY_HANDLE_INVALID)
	}

	if !IsMLDSAMechanism(mech.Type) {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"not an ML-DSA mechanism")
	}

	desc := GetQuantumMechanismDescriptor(mech.Type)
	if desc == nil {
		return nil, NewPKCS11Error(CKR_MECHANISM_INVALID)
	}

	if desc.Flags&CKF_SIGN == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"mechanism does not support signing")
	}

	if len(secretKey) == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_KEY_HANDLE_INVALID,
			"secret key is required for signing")
	}

	return newQuantumSignOperation(mech, keyHandle, keyID, backend, secretKey), nil
}

// QuantumSign performs a quantum signing operation.
func (qcm *QuantumCryptoManager) QuantumSign(op *QuantumSignOperation, data []byte) ([]byte, error) {
	if op == nil {
		return nil, NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return nil, NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	op.finalized = true

	switch op.securityLvl {
	case 44:
		return qcm.signMLDSA44(op.secretKey, data)
	case 65:
		return qcm.signMLDSA65(op.secretKey, data)
	case 87:
		return qcm.signMLDSA87(op.secretKey, data)
	default:
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"invalid ML-DSA security level")
	}
}

// signMLDSA44 signs data using ML-DSA-44.
func (qcm *QuantumCryptoManager) signMLDSA44(secretKey, data []byte) ([]byte, error) {
	signer, err := dilithium2.Create(secretKey)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_KEY_HANDLE_INVALID,
			"failed to create ML-DSA-44 signer", err)
	}
	defer signer.Clean()

	signature, err := signer.Sign(data)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"ML-DSA-44 signing failed", err)
	}

	return signature, nil
}

// signMLDSA65 signs data using ML-DSA-65.
func (qcm *QuantumCryptoManager) signMLDSA65(secretKey, data []byte) ([]byte, error) {
	signer, err := mldsa65.Create(secretKey)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_KEY_HANDLE_INVALID,
			"failed to create ML-DSA-65 signer", err)
	}
	defer signer.Clean()

	signature, err := signer.Sign(data)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"ML-DSA-65 signing failed", err)
	}

	return signature, nil
}

// signMLDSA87 signs data using ML-DSA-87.
func (qcm *QuantumCryptoManager) signMLDSA87(secretKey, data []byte) ([]byte, error) {
	signer, err := mldsa87.Create(secretKey)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_KEY_HANDLE_INVALID,
			"failed to create ML-DSA-87 signer", err)
	}
	defer signer.Clean()

	signature, err := signer.Sign(data)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"ML-DSA-87 signing failed", err)
	}

	return signature, nil
}

// QuantumSignUpdate adds data to a multi-part quantum signing operation.
func (qcm *QuantumCryptoManager) QuantumSignUpdate(op *QuantumSignOperation, data []byte) error {
	if op == nil {
		return NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	_, err := op.data.Write(data)
	if err != nil {
		return NewPKCS11ErrorFull(CKR_HOST_MEMORY, "failed to buffer data", err)
	}

	return nil
}

// QuantumSignFinal completes a multi-part quantum signing operation.
func (qcm *QuantumCryptoManager) QuantumSignFinal(op *QuantumSignOperation) ([]byte, error) {
	if op == nil {
		return nil, NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return nil, NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	data := op.data.Bytes()
	return qcm.QuantumSign(op, data)
}

// ---------------------------------------------------------------------------
// ML-DSA Verification
// ---------------------------------------------------------------------------

// QuantumVerifyInit initializes a quantum verification operation.
func (qcm *QuantumCryptoManager) QuantumVerifyInit(mech *Mechanism, keyHandle ObjectHandle, keyID, backend string, publicKey []byte) (*QuantumVerifyOperation, error) {
	if mech == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "mechanism is nil")
	}

	if keyHandle == 0 {
		return nil, NewPKCS11Error(CKR_KEY_HANDLE_INVALID)
	}

	if !IsMLDSAMechanism(mech.Type) {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"not an ML-DSA mechanism")
	}

	desc := GetQuantumMechanismDescriptor(mech.Type)
	if desc == nil {
		return nil, NewPKCS11Error(CKR_MECHANISM_INVALID)
	}

	if desc.Flags&CKF_VERIFY == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"mechanism does not support verification")
	}

	if len(publicKey) == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_KEY_HANDLE_INVALID,
			"public key is required for verification")
	}

	return newQuantumVerifyOperation(mech, keyHandle, keyID, backend, publicKey), nil
}

// QuantumVerify performs a quantum verification operation.
func (qcm *QuantumCryptoManager) QuantumVerify(op *QuantumVerifyOperation, data, signature []byte) error {
	if op == nil {
		return NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	op.finalized = true

	switch op.securityLvl {
	case 44:
		return qcm.verifyMLDSA44(op.publicKey, data, signature)
	case 65:
		return qcm.verifyMLDSA65(op.publicKey, data, signature)
	case 87:
		return qcm.verifyMLDSA87(op.publicKey, data, signature)
	default:
		return NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"invalid ML-DSA security level")
	}
}

// verifyMLDSA44 verifies a signature using ML-DSA-44.
func (qcm *QuantumCryptoManager) verifyMLDSA44(publicKey, data, signature []byte) error {
	verifier, err := dilithium2.New()
	if err != nil {
		return NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"failed to create ML-DSA-44 verifier", err)
	}
	defer verifier.Clean()

	valid, err := verifier.Verify(data, signature, publicKey)
	if err != nil {
		return NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"ML-DSA-44 verification error", err)
	}

	if !valid {
		return NewPKCS11Error(CKR_SIGNATURE_INVALID)
	}

	return nil
}

// verifyMLDSA65 verifies a signature using ML-DSA-65.
func (qcm *QuantumCryptoManager) verifyMLDSA65(publicKey, data, signature []byte) error {
	verifier, err := mldsa65.New()
	if err != nil {
		return NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"failed to create ML-DSA-65 verifier", err)
	}
	defer verifier.Clean()

	valid, err := verifier.Verify(data, signature, publicKey)
	if err != nil {
		return NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"ML-DSA-65 verification error", err)
	}

	if !valid {
		return NewPKCS11Error(CKR_SIGNATURE_INVALID)
	}

	return nil
}

// verifyMLDSA87 verifies a signature using ML-DSA-87.
func (qcm *QuantumCryptoManager) verifyMLDSA87(publicKey, data, signature []byte) error {
	verifier, err := mldsa87.New()
	if err != nil {
		return NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"failed to create ML-DSA-87 verifier", err)
	}
	defer verifier.Clean()

	valid, err := verifier.Verify(data, signature, publicKey)
	if err != nil {
		return NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"ML-DSA-87 verification error", err)
	}

	if !valid {
		return NewPKCS11Error(CKR_SIGNATURE_INVALID)
	}

	return nil
}

// QuantumVerifyUpdate adds data to a multi-part quantum verification operation.
func (qcm *QuantumCryptoManager) QuantumVerifyUpdate(op *QuantumVerifyOperation, data []byte) error {
	if op == nil {
		return NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	_, err := op.data.Write(data)
	if err != nil {
		return NewPKCS11ErrorFull(CKR_HOST_MEMORY, "failed to buffer data", err)
	}

	return nil
}

// QuantumVerifyFinal completes a multi-part quantum verification operation.
func (qcm *QuantumCryptoManager) QuantumVerifyFinal(op *QuantumVerifyOperation, signature []byte) error {
	if op == nil {
		return NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	data := op.data.Bytes()
	return qcm.QuantumVerify(op, data, signature)
}

// ---------------------------------------------------------------------------
// ML-KEM Encapsulation
// ---------------------------------------------------------------------------

// EncapsulateInit initializes a KEM encapsulation operation.
func (qcm *QuantumCryptoManager) EncapsulateInit(mech *Mechanism, keyHandle ObjectHandle, keyID, backend string, publicKey []byte) (*EncapsulateOperation, error) {
	if mech == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "mechanism is nil")
	}

	if keyHandle == 0 {
		return nil, NewPKCS11Error(CKR_KEY_HANDLE_INVALID)
	}

	if !IsMLKEMMechanism(mech.Type) {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"not an ML-KEM mechanism")
	}

	desc := GetQuantumMechanismDescriptor(mech.Type)
	if desc == nil {
		return nil, NewPKCS11Error(CKR_MECHANISM_INVALID)
	}

	if len(publicKey) == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_KEY_HANDLE_INVALID,
			"public key is required for encapsulation")
	}

	return newEncapsulateOperation(mech, keyHandle, keyID, backend, publicKey), nil
}

// EncapsulateResult contains the result of a KEM encapsulation.
type EncapsulateResult struct {
	Ciphertext   []byte
	SharedSecret []byte
}

// Encapsulate performs a KEM encapsulation operation.
func (qcm *QuantumCryptoManager) Encapsulate(op *EncapsulateOperation) (*EncapsulateResult, error) {
	if op == nil {
		return nil, NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return nil, NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	op.finalized = true

	switch op.securityLvl {
	case 768:
		return qcm.encapsulateMLKEM768(op.publicKey)
	case 1024:
		return qcm.encapsulateMLKEM1024(op.publicKey)
	default:
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"invalid ML-KEM security level")
	}
}

// encapsulateMLKEM768 performs encapsulation using ML-KEM-768.
func (qcm *QuantumCryptoManager) encapsulateMLKEM768(publicKey []byte) (*EncapsulateResult, error) {
	kem, err := kyber768.New()
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"failed to initialize ML-KEM-768", err)
	}
	defer kem.Clean()

	ciphertext, sharedSecret, err := kem.Encapsulate(publicKey)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"ML-KEM-768 encapsulation failed", err)
	}

	return &EncapsulateResult{
		Ciphertext:   ciphertext,
		SharedSecret: sharedSecret,
	}, nil
}

// encapsulateMLKEM1024 performs encapsulation using ML-KEM-1024.
func (qcm *QuantumCryptoManager) encapsulateMLKEM1024(publicKey []byte) (*EncapsulateResult, error) {
	kem, err := mlkem1024.New()
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"failed to initialize ML-KEM-1024", err)
	}
	defer kem.Clean()

	ciphertext, sharedSecret, err := kem.Encapsulate(publicKey)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"ML-KEM-1024 encapsulation failed", err)
	}

	return &EncapsulateResult{
		Ciphertext:   ciphertext,
		SharedSecret: sharedSecret,
	}, nil
}

// ---------------------------------------------------------------------------
// ML-KEM Decapsulation
// ---------------------------------------------------------------------------

// DecapsulateInit initializes a KEM decapsulation operation.
func (qcm *QuantumCryptoManager) DecapsulateInit(mech *Mechanism, keyHandle ObjectHandle, keyID, backend string, secretKey []byte) (*DecapsulateOperation, error) {
	if mech == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "mechanism is nil")
	}

	if keyHandle == 0 {
		return nil, NewPKCS11Error(CKR_KEY_HANDLE_INVALID)
	}

	if !IsMLKEMMechanism(mech.Type) {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"not an ML-KEM mechanism")
	}

	desc := GetQuantumMechanismDescriptor(mech.Type)
	if desc == nil {
		return nil, NewPKCS11Error(CKR_MECHANISM_INVALID)
	}

	if len(secretKey) == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_KEY_HANDLE_INVALID,
			"secret key is required for decapsulation")
	}

	return newDecapsulateOperation(mech, keyHandle, keyID, backend, secretKey), nil
}

// Decapsulate performs a KEM decapsulation operation.
func (qcm *QuantumCryptoManager) Decapsulate(op *DecapsulateOperation, ciphertext []byte) ([]byte, error) {
	if op == nil {
		return nil, NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return nil, NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	op.finalized = true

	switch op.securityLvl {
	case 768:
		return qcm.decapsulateMLKEM768(op.secretKey, ciphertext)
	case 1024:
		return qcm.decapsulateMLKEM1024(op.secretKey, ciphertext)
	default:
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"invalid ML-KEM security level")
	}
}

// decapsulateMLKEM768 performs decapsulation using ML-KEM-768.
func (qcm *QuantumCryptoManager) decapsulateMLKEM768(secretKey, ciphertext []byte) ([]byte, error) {
	kem, err := kyber768.Create(secretKey)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_KEY_HANDLE_INVALID,
			"failed to create ML-KEM-768 decapsulator", err)
	}
	defer kem.Clean()

	sharedSecret, err := kem.Decapsulate(ciphertext)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"ML-KEM-768 decapsulation failed", err)
	}

	return sharedSecret, nil
}

// decapsulateMLKEM1024 performs decapsulation using ML-KEM-1024.
func (qcm *QuantumCryptoManager) decapsulateMLKEM1024(secretKey, ciphertext []byte) ([]byte, error) {
	kem, err := mlkem1024.Create(secretKey)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_KEY_HANDLE_INVALID,
			"failed to create ML-KEM-1024 decapsulator", err)
	}
	defer kem.Clean()

	sharedSecret, err := kem.Decapsulate(ciphertext)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED,
			"ML-KEM-1024 decapsulation failed", err)
	}

	return sharedSecret, nil
}
