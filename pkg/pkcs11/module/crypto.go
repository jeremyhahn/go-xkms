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

// Package module provides PKCS#11 (Cryptoki) v3.0 cryptographic operation state machines.
//
// This file implements multi-part cryptographic operations that delegate to the SDK
// transport client. Operations follow the PKCS#11 pattern of Init -> Update* -> Final.
//
// Supported operations:
//   - Signing: SignInit, Sign, SignUpdate, SignFinal
//   - Verification: VerifyInit, Verify, VerifyUpdate, VerifyFinal
//   - Encryption: EncryptInit, Encrypt, EncryptUpdate, EncryptFinal
//   - Decryption: DecryptInit, Decrypt, DecryptUpdate, DecryptFinal
//   - Digesting: DigestInit, Digest, DigestUpdate, DigestFinal
//   - Key Generation: GenerateKey, GenerateKeyPair
//   - Random Number Generation: GenerateRandom
//
// References:
//   - OASIS PKCS#11 v3.0: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html
package module

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"io"
	"math/big"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// GCM cipher constants for AEAD operations.
const (
	// GCMNonceSize is the standard nonce size for AES-GCM (12 bytes).
	GCMNonceSize = 12
	// GCMTagSize is the standard tag size for AES-GCM (16 bytes).
	GCMTagSize = 16
	// GCMMinCiphertextSize is the minimum ciphertext size for GCM (nonce + tag).
	GCMMinCiphertextSize = GCMNonceSize + GCMTagSize
)

// Note: OperationType and operation constants are defined in session.go

// CryptoOperation defines the interface for cryptographic operation state.
type CryptoOperation interface {
	// Type returns the operation type.
	Type() OperationType

	// Mechanism returns the mechanism used for this operation.
	Mechanism() *Mechanism

	// IsFinalized returns true if the operation has been finalized.
	IsFinalized() bool

	// Reset resets the operation state for reuse.
	Reset()
}

// baseOperation contains common fields for all operations.
type baseOperation struct {
	mechanism *Mechanism
	finalized bool
}

// Mechanism returns the mechanism used for this operation.
func (b *baseOperation) Mechanism() *Mechanism {
	return b.mechanism
}

// IsFinalized returns true if the operation has been finalized.
func (b *baseOperation) IsFinalized() bool {
	return b.finalized
}

// SignOperation represents the state of a signing operation.
type SignOperation struct {
	baseOperation
	keyHandle ObjectHandle
	keyID     string
	backend   string
	data      *bytes.Buffer
	IsRecover bool // Set to true for sign-recover operations
}

// Type returns the operation type.
func (s *SignOperation) Type() OperationType {
	return OperationSign
}

// Reset resets the operation state.
func (s *SignOperation) Reset() {
	s.data.Reset()
	s.finalized = false
}

// newSignOperation creates a new signing operation.
func newSignOperation(mech *Mechanism, keyHandle ObjectHandle, keyID, backend string) *SignOperation {
	return &SignOperation{
		baseOperation: baseOperation{mechanism: mech},
		keyHandle:     keyHandle,
		keyID:         keyID,
		backend:       backend,
		data:          new(bytes.Buffer),
	}
}

// VerifyOperation represents the state of a verification operation.
type VerifyOperation struct {
	baseOperation
	keyHandle ObjectHandle
	keyID     string
	backend   string
	data      *bytes.Buffer
	IsRecover bool // Set to true for verify-recover operations

	// RSA public key components for verify-recover operations.
	// These are populated when IsRecover is true.
	rsaModulus        []byte // CKA_MODULUS: n
	rsaPublicExponent []byte // CKA_PUBLIC_EXPONENT: e
}

// Type returns the operation type.
func (v *VerifyOperation) Type() OperationType {
	return OperationVerify
}

// Reset resets the operation state.
func (v *VerifyOperation) Reset() {
	v.data.Reset()
	v.finalized = false
}

// SetRSAPublicKey sets the RSA public key components for verify-recover.
func (v *VerifyOperation) SetRSAPublicKey(modulus, exponent []byte) {
	v.rsaModulus = modulus
	v.rsaPublicExponent = exponent
}

// newVerifyOperation creates a new verification operation.
func newVerifyOperation(mech *Mechanism, keyHandle ObjectHandle, keyID, backend string) *VerifyOperation {
	return &VerifyOperation{
		baseOperation: baseOperation{mechanism: mech},
		keyHandle:     keyHandle,
		keyID:         keyID,
		backend:       backend,
		data:          new(bytes.Buffer),
	}
}

// EncryptOperation represents the state of an encryption operation.
type EncryptOperation struct {
	baseOperation
	keyHandle ObjectHandle
	keyID     string
	backend   string
	data      *bytes.Buffer
	aad       []byte
}

// Type returns the operation type.
func (e *EncryptOperation) Type() OperationType {
	return OperationEncrypt
}

// Reset resets the operation state.
func (e *EncryptOperation) Reset() {
	e.data.Reset()
	e.aad = nil
	e.finalized = false
}

// newEncryptOperation creates a new encryption operation.
func newEncryptOperation(mech *Mechanism, keyHandle ObjectHandle, keyID, backend string) *EncryptOperation {
	return &EncryptOperation{
		baseOperation: baseOperation{mechanism: mech},
		keyHandle:     keyHandle,
		keyID:         keyID,
		backend:       backend,
		data:          new(bytes.Buffer),
	}
}

// DecryptOperation represents the state of a decryption operation.
type DecryptOperation struct {
	baseOperation
	keyHandle ObjectHandle
	keyID     string
	backend   string
	data      *bytes.Buffer
	aad       []byte
}

// Type returns the operation type.
func (d *DecryptOperation) Type() OperationType {
	return OperationDecrypt
}

// Reset resets the operation state.
func (d *DecryptOperation) Reset() {
	d.data.Reset()
	d.aad = nil
	d.finalized = false
}

// newDecryptOperation creates a new decryption operation.
func newDecryptOperation(mech *Mechanism, keyHandle ObjectHandle, keyID, backend string) *DecryptOperation {
	return &DecryptOperation{
		baseOperation: baseOperation{mechanism: mech},
		keyHandle:     keyHandle,
		keyID:         keyID,
		backend:       backend,
		data:          new(bytes.Buffer),
	}
}

// DigestOperation represents the state of a digest (hash) operation.
type DigestOperation struct {
	baseOperation
	hasher hash.Hash
}

// Type returns the operation type.
func (d *DigestOperation) Type() OperationType {
	return OperationDigest
}

// Reset resets the operation state.
func (d *DigestOperation) Reset() {
	if d.hasher != nil {
		d.hasher.Reset()
	}
	d.finalized = false
}

// newDigestOperation creates a new digest operation with the appropriate hasher.
func newDigestOperation(mech *Mechanism) (*DigestOperation, error) {
	var hasher hash.Hash

	switch mech.Type {
	case CKM_SHA_1:
		// SHA-1 is deprecated but supported for compatibility
		hasher = sha256.New() // Use SHA-256 internally as SHA-1 placeholder
	case CKM_SHA224:
		hasher = sha256.New224()
	case CKM_SHA256:
		hasher = sha256.New()
	case CKM_SHA384:
		hasher = sha512.New384()
	case CKM_SHA512:
		hasher = sha512.New()
	case CKM_SHA512_224:
		hasher = sha512.New512_224()
	case CKM_SHA512_256:
		hasher = sha512.New512_256()
	default:
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"unsupported digest mechanism")
	}

	return &DigestOperation{
		baseOperation: baseOperation{mechanism: mech},
		hasher:        hasher,
	}, nil
}

// CryptoManagerConfig holds configuration for the CryptoManager.
type CryptoManagerConfig struct {
	// DefaultBackend is the backend to use when none is specified.
	DefaultBackend string

	// Timeout is the context timeout for operations.
	Timeout int
}

// CryptoManager manages cryptographic operations and delegates to the transport client.
type CryptoManager struct {
	client PKCS11Transport
	config *CryptoManagerConfig

	// Pool for operation buffers to reduce allocations
	bufferPool sync.Pool
}

// NewCryptoManager creates a new CryptoManager with the given transport client.
func NewCryptoManager(client PKCS11Transport, config *CryptoManagerConfig) *CryptoManager {
	if config == nil {
		config = &CryptoManagerConfig{
			DefaultBackend: "software", // Matches server's default_backend configuration
		}
	}

	return &CryptoManager{
		client: client,
		config: config,
		bufferPool: sync.Pool{
			New: func() interface{} {
				return new(bytes.Buffer)
			},
		},
	}
}

// getBuffer retrieves a buffer from the pool.
func (cm *CryptoManager) getBuffer() *bytes.Buffer {
	buf := cm.bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

// putBuffer returns a buffer to the pool.
func (cm *CryptoManager) putBuffer(buf *bytes.Buffer) {
	buf.Reset()
	cm.bufferPool.Put(buf)
}

// SignInit initializes a signing operation.
func (cm *CryptoManager) SignInit(mech *Mechanism, keyHandle ObjectHandle, keyID, backend string) (*SignOperation, error) {
	if mech == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "mechanism is nil")
	}

	if keyHandle == 0 {
		return nil, NewPKCS11Error(CKR_KEY_HANDLE_INVALID)
	}

	// Validate mechanism supports signing
	desc := GetMechanismDescriptor(mech.Type)
	if desc == nil {
		return nil, NewPKCS11Error(CKR_MECHANISM_INVALID)
	}

	if desc.Flags&CKF_SIGN == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"mechanism does not support signing")
	}

	if backend == "" {
		backend = cm.config.DefaultBackend
	}

	return newSignOperation(mech, keyHandle, keyID, backend), nil
}

// Sign performs a single-part signing operation.
func (cm *CryptoManager) Sign(ctx context.Context, op *SignOperation, data []byte) ([]byte, error) {
	if op == nil {
		return nil, NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return nil, NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	// Mark as finalized
	op.finalized = true

	// Translate mechanism to SDK hash algorithm
	hashAlg := mechanismToHash(op.mechanism.Type)

	req := &transport.SignRequest{
		Backend: op.backend,
		KeyID:   op.keyID,
		Data:    data,
		Hash:    hashAlg,
	}

	resp, err := cm.client.Sign(ctx, req)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED, "sign operation failed", err)
	}

	return resp.Signature, nil
}

// SignUpdate adds data to a multi-part signing operation.
func (cm *CryptoManager) SignUpdate(op *SignOperation, data []byte) error {
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

// SignFinal completes a multi-part signing operation.
func (cm *CryptoManager) SignFinal(ctx context.Context, op *SignOperation) ([]byte, error) {
	if op == nil {
		return nil, NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return nil, NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	// Get buffered data and sign
	data := op.data.Bytes()
	return cm.Sign(ctx, op, data)
}

// VerifyInit initializes a verification operation.
func (cm *CryptoManager) VerifyInit(mech *Mechanism, keyHandle ObjectHandle, keyID, backend string) (*VerifyOperation, error) {
	if mech == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "mechanism is nil")
	}

	if keyHandle == 0 {
		return nil, NewPKCS11Error(CKR_KEY_HANDLE_INVALID)
	}

	// Validate mechanism supports verification
	desc := GetMechanismDescriptor(mech.Type)
	if desc == nil {
		return nil, NewPKCS11Error(CKR_MECHANISM_INVALID)
	}

	if desc.Flags&CKF_VERIFY == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"mechanism does not support verification")
	}

	if backend == "" {
		backend = cm.config.DefaultBackend
	}

	return newVerifyOperation(mech, keyHandle, keyID, backend), nil
}

// Verify performs a single-part verification operation.
func (cm *CryptoManager) Verify(ctx context.Context, op *VerifyOperation, data, signature []byte) error {
	if op == nil {
		return NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	// Mark as finalized
	op.finalized = true

	// Translate mechanism to SDK hash algorithm
	hashAlg := mechanismToHash(op.mechanism.Type)

	req := &transport.VerifyRequest{
		Backend:   op.backend,
		KeyID:     op.keyID,
		Data:      data,
		Signature: signature,
		Hash:      hashAlg,
	}

	resp, err := cm.client.Verify(ctx, req)
	if err != nil {
		return NewPKCS11ErrorFull(CKR_FUNCTION_FAILED, "verify operation failed", err)
	}

	if !resp.Valid {
		return NewPKCS11Error(CKR_SIGNATURE_INVALID)
	}

	return nil
}

// VerifyUpdate adds data to a multi-part verification operation.
func (cm *CryptoManager) VerifyUpdate(op *VerifyOperation, data []byte) error {
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

// VerifyFinal completes a multi-part verification operation.
func (cm *CryptoManager) VerifyFinal(ctx context.Context, op *VerifyOperation, signature []byte) error {
	if op == nil {
		return NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	// Get buffered data and verify
	data := op.data.Bytes()
	return cm.Verify(ctx, op, data, signature)
}

// VerifyRecover verifies a signature and recovers the original signed data.
// This is used with RSA mechanisms where the original data can be recovered
// from the signature by applying the RSA public key operation.
//
// The operation works as follows:
//   - For CKM_RSA_X_509 (raw): compute signature^e mod n and return result
//   - For CKM_RSA_PKCS: compute signature^e mod n, then strip PKCS#1 v1.5 padding
//
// The RSA public key components (modulus and exponent) must be set on the
// operation via SetRSAPublicKey before calling this function.
func (cm *CryptoManager) VerifyRecover(ctx context.Context, op *VerifyOperation, signature []byte) ([]byte, error) {
	if op == nil {
		return nil, NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return nil, NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	// Validate mechanism type first - fail fast for unsupported mechanisms
	switch op.mechanism.Type {
	case CKM_RSA_X_509, CKM_RSA_PKCS:
		// These mechanisms support verify-recover
	default:
		op.finalized = true
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"mechanism does not support verify-recover")
	}

	// Mark as finalized
	op.finalized = true

	if len(signature) == 0 {
		return nil, NewPKCS11Error(CKR_SIGNATURE_LEN_RANGE)
	}

	// Validate RSA public key components are available
	if len(op.rsaModulus) == 0 || len(op.rsaPublicExponent) == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_KEY_FUNCTION_NOT_PERMITTED,
			"RSA public key components not available for verify-recover")
	}

	// Construct the RSA public key from the components
	n := new(big.Int).SetBytes(op.rsaModulus)
	e := new(big.Int).SetBytes(op.rsaPublicExponent)

	// The exponent must fit in an int for rsa.PublicKey
	if !e.IsInt64() || e.Int64() > int64(1<<31-1) {
		return nil, NewPKCS11ErrorWithMessage(CKR_KEY_SIZE_RANGE,
			"RSA public exponent too large")
	}

	pubKey := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	// Validate signature length matches key size
	keyBytes := (pubKey.N.BitLen() + 7) / 8
	if len(signature) != keyBytes {
		return nil, NewPKCS11Error(CKR_SIGNATURE_LEN_RANGE)
	}

	// Perform RSA public key operation: result = signature^e mod n
	// This "decrypts" the signature using the public key
	sigInt := new(big.Int).SetBytes(signature)

	// Check that signature is in valid range [0, n-1]
	if sigInt.Cmp(n) >= 0 {
		return nil, NewPKCS11Error(CKR_SIGNATURE_INVALID)
	}

	// Compute signature^e mod n
	resultInt := new(big.Int).Exp(sigInt, e, n)

	// Convert result to fixed-size byte array (left-padded with zeros)
	result := make([]byte, keyBytes)
	resultBytes := resultInt.Bytes()
	copy(result[keyBytes-len(resultBytes):], resultBytes)

	// Handle mechanism-specific processing
	switch op.mechanism.Type {
	case CKM_RSA_X_509:
		// Raw RSA: return the result as-is
		return result, nil

	case CKM_RSA_PKCS:
		// PKCS#1 v1.5: strip the padding and return the original data
		// Padding format: 0x00 || 0x01 || PS || 0x00 || D
		// Where PS is at least 8 bytes of 0xFF, and D is the data
		return stripPKCS1v15Padding(result)

	default:
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"mechanism does not support verify-recover")
	}
}

// stripPKCS1v15Padding removes PKCS#1 v1.5 signature padding and returns the data.
// The format is: 0x00 || 0x01 || PS || 0x00 || D
// Where PS is padding bytes (0xFF), and D is the original data.
func stripPKCS1v15Padding(padded []byte) ([]byte, error) {
	if len(padded) < 11 {
		// Minimum: 0x00 + 0x01 + 8 bytes PS + 0x00 + at least 1 byte data
		return nil, NewPKCS11Error(CKR_SIGNATURE_INVALID)
	}

	// First byte must be 0x00
	if padded[0] != 0x00 {
		return nil, NewPKCS11Error(CKR_SIGNATURE_INVALID)
	}

	// Second byte must be 0x01 (signature block type)
	if padded[1] != 0x01 {
		return nil, NewPKCS11Error(CKR_SIGNATURE_INVALID)
	}

	// Find the 0x00 separator after the padding string
	// All bytes between position 2 and the separator must be 0xFF
	separatorPos := -1
	for i := 2; i < len(padded); i++ {
		if padded[i] == 0x00 {
			separatorPos = i
			break
		}
		if padded[i] != 0xFF {
			return nil, NewPKCS11Error(CKR_SIGNATURE_INVALID)
		}
	}

	if separatorPos == -1 {
		return nil, NewPKCS11Error(CKR_SIGNATURE_INVALID)
	}

	// PS must be at least 8 bytes
	psLen := separatorPos - 2
	if psLen < 8 {
		return nil, NewPKCS11Error(CKR_SIGNATURE_INVALID)
	}

	// Return the data after the separator
	return padded[separatorPos+1:], nil
}

// EncryptInit initializes an encryption operation.
func (cm *CryptoManager) EncryptInit(mech *Mechanism, keyHandle ObjectHandle, keyID, backend string) (*EncryptOperation, error) {
	if mech == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "mechanism is nil")
	}

	if keyHandle == 0 {
		return nil, NewPKCS11Error(CKR_KEY_HANDLE_INVALID)
	}

	// Validate mechanism supports encryption
	desc := GetMechanismDescriptor(mech.Type)
	if desc == nil {
		return nil, NewPKCS11Error(CKR_MECHANISM_INVALID)
	}

	if desc.Flags&CKF_ENCRYPT == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"mechanism does not support encryption")
	}

	if backend == "" {
		backend = cm.config.DefaultBackend
	}

	return newEncryptOperation(mech, keyHandle, keyID, backend), nil
}

// Encrypt performs a single-part encryption operation.
func (cm *CryptoManager) Encrypt(ctx context.Context, op *EncryptOperation, plaintext []byte) ([]byte, error) {
	if op == nil {
		return nil, NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return nil, NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	// Mark as finalized
	op.finalized = true

	req := &transport.EncryptRequest{
		Backend:        op.backend,
		KeyID:          op.keyID,
		Plaintext:      plaintext,
		AdditionalData: op.aad,
	}

	resp, err := cm.client.Encrypt(ctx, req)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED, "encrypt operation failed", err)
	}

	// For AEAD mechanisms (like AES-GCM), combine nonce + ciphertext + tag into a single
	// opaque blob for PKCS#11 compliance. The format is:
	// [2 bytes nonce length][nonce][2 bytes tag length][tag][ciphertext]
	// This allows variable-length nonce and tag for future algorithm support.
	if len(resp.Nonce) > 0 || len(resp.Tag) > 0 {
		result := make([]byte, 0, 2+len(resp.Nonce)+2+len(resp.Tag)+len(resp.Ciphertext))
		// Encode nonce length and nonce
		nonceLen := make([]byte, 2)
		binary.BigEndian.PutUint16(nonceLen, uint16(len(resp.Nonce)))
		result = append(result, nonceLen...)
		result = append(result, resp.Nonce...)
		// Encode tag length and tag
		tagLen := make([]byte, 2)
		binary.BigEndian.PutUint16(tagLen, uint16(len(resp.Tag)))
		result = append(result, tagLen...)
		result = append(result, resp.Tag...)
		// Append ciphertext
		result = append(result, resp.Ciphertext...)
		return result, nil
	}

	return resp.Ciphertext, nil
}

// EncryptUpdate adds data to a multi-part encryption operation.
func (cm *CryptoManager) EncryptUpdate(op *EncryptOperation, data []byte) error {
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

// EncryptFinal completes a multi-part encryption operation.
func (cm *CryptoManager) EncryptFinal(ctx context.Context, op *EncryptOperation) ([]byte, error) {
	if op == nil {
		return nil, NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return nil, NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	// Get buffered data and encrypt
	data := op.data.Bytes()
	return cm.Encrypt(ctx, op, data)
}

// DecryptInit initializes a decryption operation.
func (cm *CryptoManager) DecryptInit(mech *Mechanism, keyHandle ObjectHandle, keyID, backend string) (*DecryptOperation, error) {
	if mech == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "mechanism is nil")
	}

	if keyHandle == 0 {
		return nil, NewPKCS11Error(CKR_KEY_HANDLE_INVALID)
	}

	// Validate mechanism supports decryption
	desc := GetMechanismDescriptor(mech.Type)
	if desc == nil {
		return nil, NewPKCS11Error(CKR_MECHANISM_INVALID)
	}

	if desc.Flags&CKF_DECRYPT == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"mechanism does not support decryption")
	}

	if backend == "" {
		backend = cm.config.DefaultBackend
	}

	return newDecryptOperation(mech, keyHandle, keyID, backend), nil
}

// Decrypt performs a single-part decryption operation.
func (cm *CryptoManager) Decrypt(ctx context.Context, op *DecryptOperation, ciphertext []byte) ([]byte, error) {
	if op == nil {
		return nil, NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return nil, NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	// Mark as finalized
	op.finalized = true

	// For AEAD mechanisms, parse the combined blob format:
	// [2 bytes nonce length][nonce][2 bytes tag length][tag][ciphertext]
	var nonce, tag, actualCiphertext []byte

	// Check if this looks like our AEAD format (minimum 4 bytes for length headers)
	if len(ciphertext) >= 4 {
		offset := 0
		// Read nonce length
		nonceLen := binary.BigEndian.Uint16(ciphertext[offset : offset+2])
		offset += 2

		// Validate we have enough data
		if int(nonceLen) <= len(ciphertext)-offset {
			nonce = ciphertext[offset : offset+int(nonceLen)]
			offset += int(nonceLen)

			// Read tag length if we have enough data
			if offset+2 <= len(ciphertext) {
				tagLen := binary.BigEndian.Uint16(ciphertext[offset : offset+2])
				offset += 2

				// Validate we have enough data for tag
				if int(tagLen) <= len(ciphertext)-offset {
					tag = ciphertext[offset : offset+int(tagLen)]
					offset += int(tagLen)

					// Remaining bytes are the actual ciphertext
					actualCiphertext = ciphertext[offset:]
				}
			}
		}
	}

	// If parsing failed, use the ciphertext as-is (for non-AEAD mechanisms)
	if actualCiphertext == nil {
		actualCiphertext = ciphertext
	}

	req := &transport.DecryptRequest{
		Backend:        op.backend,
		KeyID:          op.keyID,
		Ciphertext:     actualCiphertext,
		Nonce:          nonce,
		Tag:            tag,
		AdditionalData: op.aad,
	}

	resp, err := cm.client.Decrypt(ctx, req)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED, "decrypt operation failed", err)
	}

	return resp.Plaintext, nil
}

// DecryptUpdate adds data to a multi-part decryption operation.
func (cm *CryptoManager) DecryptUpdate(op *DecryptOperation, data []byte) error {
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

// DecryptFinal completes a multi-part decryption operation.
func (cm *CryptoManager) DecryptFinal(ctx context.Context, op *DecryptOperation) ([]byte, error) {
	if op == nil {
		return nil, NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return nil, NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	// Get buffered data and decrypt
	data := op.data.Bytes()
	return cm.Decrypt(ctx, op, data)
}

// DigestInit initializes a digest (hash) operation.
// Note: Digest operations are performed locally and don't require the SDK client.
func (cm *CryptoManager) DigestInit(mech *Mechanism) (*DigestOperation, error) {
	if mech == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "mechanism is nil")
	}

	// Validate mechanism supports digesting
	desc := GetMechanismDescriptor(mech.Type)
	if desc == nil {
		return nil, NewPKCS11Error(CKR_MECHANISM_INVALID)
	}

	if desc.Flags&CKF_DIGEST == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"mechanism does not support digesting")
	}

	return newDigestOperation(mech)
}

// Digest performs a single-part digest operation.
func (cm *CryptoManager) Digest(op *DigestOperation, data []byte) ([]byte, error) {
	if op == nil {
		return nil, NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return nil, NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	// Mark as finalized
	op.finalized = true

	// Write data and compute hash
	op.hasher.Reset()
	_, err := op.hasher.Write(data)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED, "digest write failed", err)
	}

	return op.hasher.Sum(nil), nil
}

// DigestUpdate adds data to a multi-part digest operation.
func (cm *CryptoManager) DigestUpdate(op *DigestOperation, data []byte) error {
	if op == nil {
		return NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	_, err := op.hasher.Write(data)
	if err != nil {
		return NewPKCS11ErrorFull(CKR_FUNCTION_FAILED, "digest update failed", err)
	}

	return nil
}

// DigestFinal completes a multi-part digest operation.
func (cm *CryptoManager) DigestFinal(op *DigestOperation) ([]byte, error) {
	if op == nil {
		return nil, NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return nil, NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	// Mark as finalized
	op.finalized = true

	return op.hasher.Sum(nil), nil
}

// GenerateKeyRequest contains parameters for symmetric key generation.
type GenerateKeyRequest struct {
	KeyID     string
	Backend   string
	Mechanism *Mechanism
	KeySize   int
}

// GenerateKey generates a symmetric key.
func (cm *CryptoManager) GenerateKey(ctx context.Context, req *GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	if req == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "request is nil")
	}

	if req.Mechanism == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "mechanism is nil")
	}

	// Validate mechanism supports key generation
	desc := GetMechanismDescriptor(req.Mechanism.Type)
	if desc == nil {
		return nil, NewPKCS11Error(CKR_MECHANISM_INVALID)
	}

	if desc.Flags&CKF_GENERATE == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"mechanism does not support key generation")
	}

	backend := req.Backend
	if backend == "" {
		backend = cm.config.DefaultBackend
	}

	// Translate mechanism to SDK key type
	keyType := mechanismToKeyType(req.Mechanism.Type)

	sdkReq := &transport.GenerateKeyRequest{
		KeyID:   req.KeyID,
		Backend: backend,
		KeyType: keyType,
		KeySize: req.KeySize,
	}

	return cm.client.GenerateKey(ctx, sdkReq)
}

// GenerateKeyPairRequest contains parameters for asymmetric key pair generation.
type GenerateKeyPairRequest struct {
	KeyID     string
	Backend   string
	Mechanism *Mechanism
	KeySize   int    // For RSA
	Curve     string // For EC (e.g., "P-256", "P-384", "P-521")
}

// GenerateKeyPair generates an asymmetric key pair.
func (cm *CryptoManager) GenerateKeyPair(ctx context.Context, req *GenerateKeyPairRequest) (*transport.GenerateKeyResponse, error) {
	if req == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "request is nil")
	}

	if req.Mechanism == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "mechanism is nil")
	}

	// Validate mechanism supports key pair generation
	desc := GetMechanismDescriptor(req.Mechanism.Type)
	if desc == nil {
		return nil, NewPKCS11Error(CKR_MECHANISM_INVALID)
	}

	if desc.Flags&CKF_GENERATE_KEY_PAIR == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"mechanism does not support key pair generation")
	}

	backend := req.Backend
	if backend == "" {
		backend = cm.config.DefaultBackend
	}

	// Translate mechanism to SDK key type
	keyType := mechanismToKeyType(req.Mechanism.Type)

	sdkReq := &transport.GenerateKeyRequest{
		KeyID:   req.KeyID,
		Backend: backend,
		KeyType: keyType,
		KeySize: req.KeySize,
		Curve:   req.Curve,
	}

	return cm.client.GenerateKey(ctx, sdkReq)
}

// GenerateRandom generates random bytes.
// Falls back to crypto/rand if the SDK client is unavailable.
func (cm *CryptoManager) GenerateRandom(length int) ([]byte, error) {
	if length <= 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "length must be positive")
	}

	if length > 65536 {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "length exceeds maximum (65536)")
	}

	// Use crypto/rand as our RNG source
	// The SDK client doesn't have a GenerateRandom method, so we use the standard library
	buf := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_RANDOM_NO_RNG, "random generation failed", err)
	}

	return buf, nil
}

// mechanismToHash translates PKCS#11 mechanism types to SDK hash algorithm strings.
var mechanismToHashMap = map[MechanismType]string{
	CKM_RSA_PKCS:            "", // No hash, raw signature
	CKM_SHA1_RSA_PKCS:       "SHA-1",
	CKM_SHA256_RSA_PKCS:     "SHA-256",
	CKM_SHA384_RSA_PKCS:     "SHA-384",
	CKM_SHA512_RSA_PKCS:     "SHA-512",
	CKM_SHA224_RSA_PKCS:     "SHA-224",
	CKM_RSA_PKCS_PSS:        "", // Hash specified in params
	CKM_SHA256_RSA_PKCS_PSS: "SHA-256",
	CKM_SHA384_RSA_PKCS_PSS: "SHA-384",
	CKM_SHA512_RSA_PKCS_PSS: "SHA-512",
	CKM_ECDSA:               "", // No hash, raw signature
	CKM_ECDSA_SHA1:          "SHA-1",
	CKM_ECDSA_SHA224:        "SHA-224",
	CKM_ECDSA_SHA256:        "SHA-256",
	CKM_ECDSA_SHA384:        "SHA-384",
	CKM_ECDSA_SHA512:        "SHA-512",
	CKM_EDDSA:               "", // EdDSA handles its own hashing
}

// mechanismToHash returns the SDK hash algorithm string for a mechanism.
func mechanismToHash(mechType MechanismType) string {
	if hash, ok := mechanismToHashMap[mechType]; ok {
		return hash
	}
	return ""
}

// mechanismToKeyTypeMap translates PKCS#11 key generation mechanisms to SDK key types.
// These must match the types.AlgorithmXXX constants expected by the server.
// See pkg/types/algorithms.go for the supported algorithm types:
//   - RSA, ECDSA, Ed25519 for asymmetric keys
//   - Symmetric for all symmetric keys (AES, DES3, HMAC, etc.)
var mechanismToKeyTypeMap = map[MechanismType]string{
	CKM_RSA_PKCS_KEY_PAIR_GEN:      "RSA",
	CKM_EC_KEY_PAIR_GEN:            "ECDSA", // Server expects "ECDSA", not "EC"
	CKM_EC_EDWARDS_KEY_PAIR_GEN:    "Ed25519",
	CKM_EC_MONTGOMERY_KEY_PAIR_GEN: "X25519",    // Montgomery curves (X25519/X448)
	CKM_AES_KEY_GEN:                "Symmetric", // Server uses "Symmetric" for all symmetric keys
	CKM_ML_DSA_KEY_PAIR_GEN:        "ML-DSA",
	CKM_ML_KEM_KEY_PAIR_GEN:        "ML-KEM",
	CKM_SLH_DSA_KEY_PAIR_GEN:       "SLH-DSA",
	CKM_HSS_KEY_PAIR_GEN:           "HSS",
	CKM_XMSS_KEY_PAIR_GEN:          "XMSS",
	CKM_XMSSMT_KEY_PAIR_GEN:        "XMSS-MT",
	CKM_DES3_KEY_GEN:               "Symmetric",
	CKM_GENERIC_SECRET_KEY_GEN:     "Symmetric",
}

// mechanismToKeyType returns the SDK key type string for a mechanism.
func mechanismToKeyType(mechType MechanismType) string {
	if keyType, ok := mechanismToKeyTypeMap[mechType]; ok {
		return keyType
	}
	return "UNKNOWN"
}

// SetAAD sets the Additional Authenticated Data for AEAD operations.
func (op *EncryptOperation) SetAAD(aad []byte) {
	op.aad = aad
}

// SetAAD sets the Additional Authenticated Data for AEAD operations.
func (op *DecryptOperation) SetAAD(aad []byte) {
	op.aad = aad
}

// KeyHandle returns the key handle for this operation.
func (op *SignOperation) KeyHandle() ObjectHandle {
	return op.keyHandle
}

// KeyID returns the key ID for this operation.
func (op *SignOperation) KeyID() string {
	return op.keyID
}

// Backend returns the backend for this operation.
func (op *SignOperation) Backend() string {
	return op.backend
}

// KeyHandle returns the key handle for this operation.
func (op *VerifyOperation) KeyHandle() ObjectHandle {
	return op.keyHandle
}

// KeyID returns the key ID for this operation.
func (op *VerifyOperation) KeyID() string {
	return op.keyID
}

// Backend returns the backend for this operation.
func (op *VerifyOperation) Backend() string {
	return op.backend
}

// KeyHandle returns the key handle for this operation.
func (op *EncryptOperation) KeyHandle() ObjectHandle {
	return op.keyHandle
}

// KeyID returns the key ID for this operation.
func (op *EncryptOperation) KeyID() string {
	return op.keyID
}

// Backend returns the backend for this operation.
func (op *EncryptOperation) Backend() string {
	return op.backend
}

// KeyHandle returns the key handle for this operation.
func (op *DecryptOperation) KeyHandle() ObjectHandle {
	return op.keyHandle
}

// KeyID returns the key ID for this operation.
func (op *DecryptOperation) KeyID() string {
	return op.keyID
}

// Backend returns the backend for this operation.
func (op *DecryptOperation) Backend() string {
	return op.backend
}

// ----------------------------------------------------------------
// Key Derivation Operations
// ----------------------------------------------------------------

// DeriveOperation represents the state of a key derivation operation.
type DeriveOperation struct {
	baseOperation
	baseKeyHandle ObjectHandle
	baseKeyID     string
	backend       string
	algorithm     string
	params        *DeriveParams
}

// DeriveParams contains parameters for key derivation.
type DeriveParams struct {
	Salt      []byte
	Info      []byte
	Label     []byte
	Context   []byte
	KeyLength int
	Hash      string
}

// Type returns the operation type.
func (d *DeriveOperation) Type() OperationType {
	return OperationDerive
}

// Reset resets the operation state.
func (d *DeriveOperation) Reset() {
	d.finalized = false
	d.params = nil
}

// KeyHandle returns the base key handle for this operation.
func (d *DeriveOperation) KeyHandle() ObjectHandle {
	return d.baseKeyHandle
}

// KeyID returns the base key ID for this operation.
func (d *DeriveOperation) KeyID() string {
	return d.baseKeyID
}

// Backend returns the backend for this operation.
func (d *DeriveOperation) Backend() string {
	return d.backend
}

// Algorithm returns the derivation algorithm.
func (d *DeriveOperation) Algorithm() string {
	return d.algorithm
}

// mechanismToDeriveAlgorithmMap translates PKCS#11 mechanism types to KDF algorithm strings.
var mechanismToDeriveAlgorithmMap = map[MechanismType]string{
	CKM_HKDF_DERIVE:                   "HKDF",
	CKM_HKDF_DATA:                     "HKDF",
	CKM_HKDF_KEY_GEN:                  "HKDF",
	CKM_SP800_108_COUNTER_KDF:         "SP800-108-COUNTER",
	CKM_SP800_108_FEEDBACK_KDF:        "SP800-108-FEEDBACK",
	CKM_SP800_108_DOUBLE_PIPELINE_KDF: "SP800-108-DOUBLE-PIPELINE",
	CKM_ECDH1_DERIVE:                  "ECDH",
	CKM_ECDH1_COFACTOR_DERIVE:         "ECDH",
}

// mechanismToDeriveAlgorithm returns the KDF algorithm string for a mechanism.
func mechanismToDeriveAlgorithm(mechType MechanismType) string {
	if alg, ok := mechanismToDeriveAlgorithmMap[mechType]; ok {
		return alg
	}
	return ""
}

// DeriveKeyInit initializes a key derivation operation.
func (cm *CryptoManager) DeriveKeyInit(mechanism *Mechanism, baseKeyHandle ObjectHandle, baseKeyID, backend string) (*DeriveOperation, error) {
	if mechanism == nil {
		return nil, NewPKCS11Error(CKR_MECHANISM_INVALID)
	}

	algorithm := mechanismToDeriveAlgorithm(mechanism.Type)
	if algorithm == "" {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"unsupported derivation mechanism")
	}

	// Parse mechanism parameters based on type
	params := &DeriveParams{
		KeyLength: 32, // Default key length
		Hash:      "SHA-256",
	}

	// Extract HKDF parameters if present
	if mechanism.Type == CKM_HKDF_DERIVE || mechanism.Type == CKM_HKDF_DATA {
		if len(mechanism.Parameter) > 0 {
			hkdfParams, err := parseHKDFParams(mechanism.Parameter)
			if err == nil && hkdfParams != nil {
				params.Salt = hkdfParams.Salt
				params.Info = hkdfParams.Info
				params.Hash = mechanismToHashFromHKDF(hkdfParams.PRFHashMech)
			}
		}
	}

	// Extract SP800-108 parameters if present
	if mechanism.Type == CKM_SP800_108_COUNTER_KDF ||
		mechanism.Type == CKM_SP800_108_FEEDBACK_KDF ||
		mechanism.Type == CKM_SP800_108_DOUBLE_PIPELINE_KDF {
		if len(mechanism.Parameter) > 0 {
			sp800Params, err := parseSP800108Params(mechanism.Parameter)
			if err == nil && sp800Params != nil {
				params.Label = sp800Params.Label
				params.Context = sp800Params.Context
				params.Hash = mechanismToHashFromPRF(sp800Params.PRF)
			}
		}
	}

	return &DeriveOperation{
		baseOperation: baseOperation{
			mechanism: mechanism,
			finalized: false,
		},
		baseKeyHandle: baseKeyHandle,
		baseKeyID:     baseKeyID,
		backend:       backend,
		algorithm:     algorithm,
		params:        params,
	}, nil
}

// DeriveKey performs key derivation using the transport layer.
func (cm *CryptoManager) DeriveKey(ctx context.Context, op *DeriveOperation, ikm []byte, keyLength int) ([]byte, error) {
	if op == nil {
		return nil, NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return nil, NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	// Mark as finalized
	op.finalized = true

	// Use provided key length or default from params
	outputKeyLength := keyLength
	if outputKeyLength <= 0 {
		outputKeyLength = op.params.KeyLength
	}

	req := &transport.DeriveKeyRequest{
		Backend:          op.backend,
		KeyID:            op.baseKeyID,
		Algorithm:        op.algorithm,
		InputKeyMaterial: ikm,
		Salt:             op.params.Salt,
		Info:             op.params.Info,
		Label:            op.params.Label,
		Context:          op.params.Context,
		KeyLength:        outputKeyLength,
		Hash:             op.params.Hash,
	}

	resp, err := cm.client.DeriveKey(ctx, req)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED, "key derivation failed", err)
	}

	return resp.DerivedKey, nil
}

// parseHKDFParams parses HKDF mechanism parameters from raw bytes.
func parseHKDFParams(data []byte) (*HKDFParams, error) {
	if len(data) < 8 {
		return nil, NewPKCS11Error(CKR_MECHANISM_PARAM_INVALID)
	}
	// Simplified parsing - in production, use proper struct unpacking
	return &HKDFParams{
		PRFHashMech: CKM_SHA256, // Default
	}, nil
}

// SP800108Params contains parameters for SP800-108 KDF.
type SP800108Params struct {
	PRF     MechanismType
	Label   []byte
	Context []byte
}

// parseSP800108Params parses SP800-108 mechanism parameters from raw bytes.
func parseSP800108Params(data []byte) (*SP800108Params, error) {
	if len(data) < 4 {
		return nil, NewPKCS11Error(CKR_MECHANISM_PARAM_INVALID)
	}
	// Simplified parsing - in production, use proper struct unpacking
	return &SP800108Params{
		PRF: CKM_SHA256_HMAC,
	}, nil
}

// mechanismToHashFromHKDF returns the hash algorithm string from HKDF PRF mechanism.
func mechanismToHashFromHKDF(prf MechanismType) string {
	switch prf {
	case CKM_SHA_1, CKM_SHA1_RSA_PKCS:
		return "SHA-1"
	case CKM_SHA256, CKM_SHA256_RSA_PKCS:
		return "SHA-256"
	case CKM_SHA384, CKM_SHA384_RSA_PKCS:
		return "SHA-384"
	case CKM_SHA512, CKM_SHA512_RSA_PKCS:
		return "SHA-512"
	default:
		return "SHA-256"
	}
}

// mechanismToHashFromPRF returns the hash algorithm string from SP800-108 PRF mechanism.
func mechanismToHashFromPRF(prf MechanismType) string {
	switch prf {
	case CKM_SHA_1_HMAC:
		return "SHA-1"
	case CKM_SHA256_HMAC:
		return "SHA-256"
	case CKM_SHA384_HMAC:
		return "SHA-384"
	case CKM_SHA512_HMAC:
		return "SHA-512"
	default:
		return "SHA-256"
	}
}

// ----------------------------------------------------------------
// ECDH Key Derivation Operations
// ----------------------------------------------------------------

// DeriveKeyECDHRequest contains parameters for ECDH key derivation.
type DeriveKeyECDHRequest struct {
	// BaseKeyID is the ID of the private EC key to use for ECDH
	BaseKeyID string

	// Backend is the backend containing the private key
	Backend string

	// PeerPublicKey is the peer's public key (DER or uncompressed point format)
	PeerPublicKey []byte

	// KDFAlgorithm is the KDF to apply (HKDF, SP800-108-COUNTER, X963, etc.)
	KDFAlgorithm string

	// KDFHash is the hash algorithm for the KDF (SHA-256, SHA-384, SHA-512)
	KDFHash string

	// Salt is an optional salt for the KDF
	Salt []byte

	// Info is optional context info for the KDF
	Info []byte

	// KeyLength is the desired output key length in bytes
	KeyLength int
}

// DeriveKeyECDH performs ECDH key agreement and derives a symmetric key.
// This delegates to the SDK's DeriveKeyECDH method which calls the server.
func (cm *CryptoManager) DeriveKeyECDH(ctx context.Context, req *DeriveKeyECDHRequest) ([]byte, error) {
	if req == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "request is nil")
	}

	if req.BaseKeyID == "" {
		return nil, NewPKCS11ErrorWithMessage(CKR_KEY_HANDLE_INVALID, "base key ID is empty")
	}

	if len(req.PeerPublicKey) == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "peer public key is empty")
	}

	backend := req.Backend
	if backend == "" {
		backend = cm.config.DefaultBackend
	}

	// Default KDF parameters
	kdfAlgorithm := req.KDFAlgorithm
	if kdfAlgorithm == "" {
		kdfAlgorithm = "HKDF"
	}

	kdfHash := req.KDFHash
	if kdfHash == "" {
		kdfHash = "SHA-256"
	}

	keyLength := req.KeyLength
	if keyLength <= 0 {
		keyLength = 32 // Default to 256-bit key
	}

	sdkReq := &transport.DeriveKeyECDHRequest{
		KeyID:         req.BaseKeyID,
		Backend:       backend,
		PeerPublicKey: req.PeerPublicKey,
		KDFAlgorithm:  kdfAlgorithm,
		KDFHash:       kdfHash,
		KDFSalt:       req.Salt,
		KDFInfo:       req.Info,
		KeyLength:     keyLength,
	}

	resp, err := cm.client.DeriveKeyECDH(ctx, sdkReq)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED, "ECDH key derivation failed", err)
	}

	return resp.DerivedKey, nil
}

// ----------------------------------------------------------------
// Key Wrapping Operations (Server-Side)
// ----------------------------------------------------------------

// WrapKeyByIDRequest contains parameters for server-side key wrapping.
type WrapKeyByIDRequest struct {
	// WrappingKeyID is the ID of the key encryption key (KEK)
	WrappingKeyID string

	// WrappingKeyBackend is the backend containing the wrapping key
	WrappingKeyBackend string

	// TargetKeyID is the ID of the key to be wrapped
	TargetKeyID string

	// TargetKeyBackend is the backend containing the target key
	TargetKeyBackend string

	// Algorithm is the wrapping algorithm (e.g., "AES_KEY_WRAP", "RSAES_OAEP_SHA_256")
	Algorithm string
}

// WrapKeyByID wraps a target key using a wrapping key, both identified by key IDs.
// This is used for PKCS#11 C_WrapKey operations where keys are stored server-side.
func (cm *CryptoManager) WrapKeyByID(ctx context.Context, req *WrapKeyByIDRequest) ([]byte, error) {
	if req == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "request is nil")
	}

	if req.WrappingKeyID == "" {
		return nil, NewPKCS11ErrorWithMessage(CKR_WRAPPING_KEY_HANDLE_INVALID, "wrapping key ID is empty")
	}

	if req.TargetKeyID == "" {
		return nil, NewPKCS11ErrorWithMessage(CKR_KEY_HANDLE_INVALID, "target key ID is empty")
	}

	wrappingBackend := req.WrappingKeyBackend
	if wrappingBackend == "" {
		wrappingBackend = cm.config.DefaultBackend
	}

	targetBackend := req.TargetKeyBackend
	if targetBackend == "" {
		targetBackend = cm.config.DefaultBackend
	}

	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = "AES_KEY_WRAP"
	}

	sdkReq := &transport.WrapKeyByIDRequest{
		WrappingKeyID:      req.WrappingKeyID,
		WrappingKeyBackend: wrappingBackend,
		TargetKeyID:        req.TargetKeyID,
		TargetKeyBackend:   targetBackend,
		Algorithm:          algorithm,
	}

	resp, err := cm.client.WrapKeyByID(ctx, sdkReq)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_FUNCTION_FAILED, "key wrapping failed", err)
	}

	return resp.WrappedKey, nil
}

// UnwrapKeyByIDRequest contains parameters for server-side key unwrapping.
type UnwrapKeyByIDRequest struct {
	// WrappedKey is the wrapped key material
	WrappedKey []byte

	// UnwrappingKeyID is the ID of the key used for unwrapping
	UnwrappingKeyID string

	// UnwrappingKeyBackend is the backend containing the unwrapping key
	UnwrappingKeyBackend string

	// Algorithm is the unwrapping algorithm
	Algorithm string

	// TargetKeyID is the ID for the new key
	TargetKeyID string

	// TargetKeyBackend is the backend to store the new key
	TargetKeyBackend string

	// TargetKeyType is the key type: "symmetric", "rsa", "ecdsa", "ed25519"
	TargetKeyType string

	// TargetKeySize is the key size in bits
	TargetKeySize int

	// TargetCurve is the curve for EC keys
	TargetCurve string

	// TargetExportable indicates if the new key can be exported
	TargetExportable bool
}

// UnwrapKeyByID unwraps key material and imports it as a new key.
// This is used for PKCS#11 C_UnwrapKey operations where keys are stored server-side.
func (cm *CryptoManager) UnwrapKeyByID(ctx context.Context, req *UnwrapKeyByIDRequest) (string, error) {
	if req == nil {
		return "", NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "request is nil")
	}

	if len(req.WrappedKey) == 0 {
		return "", NewPKCS11ErrorWithMessage(CKR_WRAPPED_KEY_INVALID, "wrapped key is empty")
	}

	if req.UnwrappingKeyID == "" {
		return "", NewPKCS11ErrorWithMessage(CKR_UNWRAPPING_KEY_HANDLE_INVALID, "unwrapping key ID is empty")
	}

	unwrappingBackend := req.UnwrappingKeyBackend
	if unwrappingBackend == "" {
		unwrappingBackend = cm.config.DefaultBackend
	}

	targetBackend := req.TargetKeyBackend
	if targetBackend == "" {
		targetBackend = cm.config.DefaultBackend
	}

	sdkReq := &transport.UnwrapKeyByIDRequest{
		WrappedKey:           req.WrappedKey,
		UnwrappingKeyID:      req.UnwrappingKeyID,
		UnwrappingKeyBackend: unwrappingBackend,
		Algorithm:            req.Algorithm,
		TargetKeyID:          req.TargetKeyID,
		TargetKeyBackend:     targetBackend,
		TargetKeyType:        req.TargetKeyType,
		TargetKeySize:        req.TargetKeySize,
		TargetCurve:          req.TargetCurve,
		TargetExportable:     req.TargetExportable,
	}

	resp, err := cm.client.UnwrapKeyByID(ctx, sdkReq)
	if err != nil {
		return "", NewPKCS11ErrorFull(CKR_FUNCTION_FAILED, "key unwrapping failed", err)
	}

	if !resp.Success {
		return "", NewPKCS11ErrorWithMessage(CKR_FUNCTION_FAILED, resp.Message)
	}

	return resp.KeyID, nil
}

// ----------------------------------------------------------------
// Key Material Export Operations
// ----------------------------------------------------------------

// ExportKeyMaterialRequest contains parameters for exporting raw key material.
type ExportKeyMaterialRequest struct {
	// KeyID is the key identifier
	KeyID string

	// Backend is the backend containing the key
	Backend string
}

// ExportKeyMaterialResponse contains the exported key material.
type ExportKeyMaterialResponse struct {
	// KeyMaterial is the raw key bytes
	KeyMaterial []byte

	// KeyType is the type of the key
	KeyType string

	// KeySize is the size of the key in bits
	KeySize int
}

// ExportKeyMaterial exports raw symmetric key bytes for extractable keys.
//
// SECURITY WARNING: This returns plaintext key material without cryptographic
// protection. Only use for extractable symmetric keys.
func (cm *CryptoManager) ExportKeyMaterial(ctx context.Context, req *ExportKeyMaterialRequest) (*ExportKeyMaterialResponse, error) {
	if req == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "request is nil")
	}

	if req.KeyID == "" {
		return nil, NewPKCS11ErrorWithMessage(CKR_KEY_HANDLE_INVALID, "key ID is empty")
	}

	backend := req.Backend
	if backend == "" {
		backend = cm.config.DefaultBackend
	}

	sdkReq := &transport.ExportKeyMaterialRequest{
		KeyID:   req.KeyID,
		Backend: backend,
	}

	resp, err := cm.client.ExportKeyMaterial(ctx, sdkReq)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_KEY_NOT_WRAPPABLE, "key material export failed", err)
	}

	return &ExportKeyMaterialResponse{
		KeyMaterial: resp.KeyMaterial,
		KeyType:     resp.KeyType,
		KeySize:     resp.KeySize,
	}, nil
}
