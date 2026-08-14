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
	"crypto/sha1" //nolint:gosec // CKM_SHA_1 is a PKCS#11-defined mechanism this module advertises
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"hash"
	"io"
	"math/big"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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

	// ecFieldLen is the byte width of one field element of the signing key's
	// curve, or 0 when the key is not an EC key or its curve was not
	// recognised. It sizes the raw r || s encoding PKCS#11 v3.2 §6.3.1
	// requires; see SetECFieldLen.
	ecFieldLen int
}

// SetECFieldLen records the byte width of one field element of the signing
// key's curve, so the raw ECDSA signature is sized from the KEY rather than
// from the magnitudes of the numbers in the signature.
//
// PKCS#11 v3.2 §6.3.1 defines the signature as r || s with each half exactly
// this wide. Inferring the width from the components instead picks the
// narrowest advertised curve that happens to hold them: correct for
// P-256/384/521 with overwhelming probability, but wrong for every other curve
// -- a P-224 key yielded 64 bytes where 56 is required -- and wrong by chance
// whenever both components of a larger curve's signature fall below the next
// size down.
func (s *SignOperation) SetECFieldLen(n int) {
	s.ecFieldLen = n
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
	// ecFieldLen is the byte width of one field element of the verifying key's
	// curve, or 0 when unknown. See SignOperation.SetECFieldLen.
	ecFieldLen int
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

	// iv holds the resolved initialization vector for this operation:
	// the caller-supplied CK_GCM_PARAMS.pIv / CK_MECHANISM.pParameter (CBC),
	// or, for AES-GCM with no caller-supplied IV, a nonce this module
	// generated with crypto/rand. Nil for mechanisms with no IV/nonce.
	iv []byte

	// ivGenerated is true when iv was generated by this module rather than
	// supplied by the caller. Per PKCS#11 v3.2 section 6.13.7, a
	// module-generated AES-GCM IV must be made available to the caller
	// after C_EncryptInit returns; callers of IV() use this to decide
	// whether the value needs to be written back into CK_GCM_PARAMS.pIv.
	ivGenerated bool

	// tagSize is the AEAD authentication tag length in bytes this operation
	// asked for, resolved once from CK_GCM_PARAMS.ulTagBits at Init. Zero
	// means the caller named no length and the backend's full-length tag
	// applies. It is read at Encrypt time so the request carries the same
	// length the matching decrypt will frame with; see resolveGCMTagSize.
	tagSize int
}

// Type returns the operation type.
func (e *EncryptOperation) Type() OperationType {
	return OperationEncrypt
}

// Reset resets the operation state.
func (e *EncryptOperation) Reset() {
	e.data.Reset()
	e.aad = nil
	e.iv = nil
	e.ivGenerated = false
	e.finalized = false
}

// IV returns the resolved initialization vector or AEAD nonce for this
// operation (nil if the mechanism takes none).
func (e *EncryptOperation) IV() []byte {
	return e.iv
}

// IVGenerated reports whether IV() was generated by this module rather than
// supplied by the caller. Per PKCS#11 v3.2 section 6.13.7, the caller must
// be able to retrieve a module-generated AES-GCM IV after C_EncryptInit.
func (e *EncryptOperation) IVGenerated() bool {
	return e.ivGenerated
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

	// iv holds the resolved initialization vector for this operation: the
	// caller-supplied CK_GCM_PARAMS.pIv / CK_MECHANISM.pParameter (CBC).
	// Unlike EncryptOperation, this is never generated -- decryption always
	// requires the exact IV/nonce used at encryption time.
	iv []byte

	// tagSize is the AEAD authentication tag length in bytes this operation
	// asked for, resolved once from CK_GCM_PARAMS.ulTagBits at Init. Zero
	// means the caller named no length and the backend's full-length tag
	// applies. Decrypt uses it for two things that must agree: splitting
	// ciphertext||tag, and telling the backend how many tag bits to verify.
	tagSize int
}

// Type returns the operation type.
func (d *DecryptOperation) Type() OperationType {
	return OperationDecrypt
}

// Reset resets the operation state.
func (d *DecryptOperation) Reset() {
	d.data.Reset()
	d.aad = nil
	d.iv = nil
	d.finalized = false
}

// IV returns the resolved initialization vector or AEAD nonce for this
// operation (nil if the mechanism takes none).
func (d *DecryptOperation) IV() []byte {
	return d.iv
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
		// SHA-1 is cryptographically weak, but C_GetMechanismList and
		// C_GetMechanismInfo both advertise CKM_SHA_1 with CKF_DIGEST, so
		// C_Digest must return an actual SHA-1 digest. Substituting another
		// algorithm would hand the caller 32 bytes of SHA-256 under a SHA-1
		// label with CKR_OK, which no caller can detect.
		hasher = sha1.New() //nolint:gosec // the caller explicitly requested CKM_SHA_1
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

	// The AES-GCM (key, IV) pairs this manager consumes are recorded in the
	// process-wide guard reached by checkGCMNonce, not in a field here. A
	// per-manager tracker was worse than no tracker in the case that matters:
	// a host that builds two CryptoManagers -- or that also wraps through the
	// in-process AES-GCM of C_WrapKeyAuthenticated -- got two independent maps
	// and neither could see the IV the other had just consumed.
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

	if isRSAPSSMechanism(mech.Type) {
		params, _ := mech.TypedParameter.(*RSAPSSParams)
		if err := validateRSAPSSParams(mech.Type, params); err != nil {
			return nil, err
		}
	}

	if mech.Type == CKM_EDDSA {
		if params, ok := mech.TypedParameter.(*EdDSAParams); ok {
			if err := validateEdDSAParams(params); err != nil {
				return nil, err
			}
		}
	}

	if backend == "" {
		backend = cm.config.DefaultBackend
	}

	return newSignOperation(mech, keyHandle, keyID, backend), nil
}

// validateEdDSAParams checks a parsed CK_EDDSA_PARAMS against the structural
// bound v3.2 section 6.24 places on the context data: 0 <= ulContextDataLen
// <= 255. A nil params is valid (it means no CK_EDDSA_PARAMS was parsed,
// i.e. pure Ed25519/Ed448 was requested) and is not checked here.
func validateEdDSAParams(params *EdDSAParams) error {
	if params == nil {
		return nil
	}
	if len(params.Context) > 255 {
		return NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CK_EDDSA_PARAMS.ulContextDataLen must be 0-255")
	}
	return nil
}

// backendCKRV resolves the CK_RV a backend rejection should be reported as,
// preserving any determinate code the error already carries and falling back
// to the caller's code only for an error that names none.
//
// The codes that matter most here are the ones a caller can act on:
// CKR_USER_NOT_LOGGED_IN says re-authenticate, CKR_SESSION_HANDLE_INVALID says
// reopen the session, and both are in C_Sign's return table (v3.2 §5.13.2) as
// well as C_Encrypt's and C_Decrypt's. Hardcoding CKR_FUNCTION_FAILED at these
// call sites discarded them: an operation caught by a concurrent C_Logout came
// back indistinguishable from a device malfunction or an escaped panic, which
// is precisely the value the C ABI's own panic recovery substitutes.
//
// FromError already performs this classification, so the mapping is not
// restated here. Its one ambiguity is CKR_GENERAL_ERROR, which it returns both
// for an error genuinely carrying that code and for one it could not classify
// at all; only the latter takes the fallback.
func backendCKRV(err error, fallback CK_RV) CK_RV {
	if err == nil {
		return CKR_OK
	}
	if rv := FromError(err); rv != CKR_GENERAL_ERROR {
		return rv
	}
	if rv, ok := IsPKCS11Error(err); ok {
		return rv
	}
	if errors.Is(err, ErrGeneralError) {
		return CKR_GENERAL_ERROR
	}
	return fallback
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

	// The generic CKM_RSA_PKCS_PSS mechanism carries no hash of its own --
	// CK_RSA_PKCS_PSS_PARAMS.hashAlg is authoritative. The hash-specific PSS
	// mechanisms (CKM_SHA256_RSA_PKCS_PSS, etc.) still require matching
	// params; validateRSAPSSParams (called from SignInit) already rejected
	// a mismatch, so resolving from params here is safe for all four.
	if isRSAPSSMechanism(op.mechanism.Type) {
		if params, ok := op.mechanism.TypedParameter.(*RSAPSSParams); ok {
			if name, ok := rsaHashMechanismNames[params.HashAlg]; ok {
				hashAlg = name
			}
		}
	}

	padding, saltLen := rsaPaddingForMechanism(op.mechanism)

	req := &transport.SignRequest{
		Backend:    op.backend,
		KeyID:      op.keyID,
		Data:       data,
		Hash:       hashAlg,
		Padding:    padding,
		SaltLength: saltLen,
		// Data is already the digest for the mechanisms in
		// preHashedSignMechanisms. Hash still names which digest produced it,
		// which is what CKM_RSA_PKCS_PSS needs for MGF1 and the salt length
		// while requiring the data itself be left alone (v3.2 §6.1.9,
		// §6.1.10).
		DataIsDigest: mechanismDataIsDigest(op.mechanism.Type),
	}

	// CK_EDDSA_PARAMS selects among Ed25519ctx, Ed25519ph, Ed448 and
	// Ed448ph (RFC 8032 Table 73); thread phFlag/pContextData through so
	// the backend signs under the scheme the caller asked for instead of
	// always falling back to pure Ed25519/Ed448.
	if op.mechanism.Type == CKM_EDDSA {
		if params, ok := op.mechanism.TypedParameter.(*EdDSAParams); ok && params != nil {
			req.PreHash = params.PreHash
			req.Context = params.Context
		}
	}

	resp, err := cm.client.Sign(ctx, req)
	if err != nil {
		return nil, NewPKCS11ErrorFull(backendCKRV(err, CKR_FUNCTION_FAILED),
			"sign operation failed", err)
	}

	signature := resp.Signature

	// PKCS#11 v3.2 section 6.3.1 requires ECDSA signatures on the wire to be
	// the raw concatenation r || s, each padded to the curve's field-element
	// width -- never ASN.1 DER. Normalize here so every ECDSA-producing
	// backend (DER-only or already-raw) yields a spec-conformant signature.
	if isECDSAMechanism(op.mechanism.Type) {
		raw, convErr := normalizeECDSASignatureToRaw(signature, op.ecFieldLen)
		if convErr != nil {
			return nil, convErr
		}
		signature = raw
	}

	return signature, nil
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

	// This constructor serves both C_VerifyInit and C_VerifyRecoverInit, which
	// are different capabilities with different flags, so it admits a mechanism
	// that can do either and leaves the choice between them to the Module layer
	// -- the only layer that knows which verb the application called.
	// CKM_RSA_X_509 is the case that separates them: it can verify-recover and
	// must not plain-verify.
	if desc.Flags&(CKF_VERIFY|CKF_VERIFY_RECOVER) == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"mechanism does not support verification")
	}

	if isRSAPSSMechanism(mech.Type) {
		params, _ := mech.TypedParameter.(*RSAPSSParams)
		if err := validateRSAPSSParams(mech.Type, params); err != nil {
			return nil, err
		}
	}

	if mech.Type == CKM_EDDSA {
		if params, ok := mech.TypedParameter.(*EdDSAParams); ok {
			if err := validateEdDSAParams(params); err != nil {
				return nil, err
			}
		}
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

	// Reject an empty or otherwise unusable signature locally instead of
	// making a round trip the backend can only fail. Mirrors the
	// C_VerifySignatureInit length check in module_verifysig.go.
	if len(signature) == 0 {
		return NewPKCS11Error(CKR_SIGNATURE_LEN_RANGE)
	}

	// Mark as finalized
	op.finalized = true

	// Translate mechanism to SDK hash algorithm
	hashAlg := mechanismToHash(op.mechanism.Type)

	// See the matching comment in Sign: the generic PSS mechanism's hash
	// comes only from CK_RSA_PKCS_PSS_PARAMS.
	if isRSAPSSMechanism(op.mechanism.Type) {
		if params, ok := op.mechanism.TypedParameter.(*RSAPSSParams); ok {
			if name, ok := rsaHashMechanismNames[params.HashAlg]; ok {
				hashAlg = name
			}
		}
	}

	// PKCS#11 v3.2 section 6.3.1 delivers ECDSA signatures on the wire as
	// raw r || s. This module's backends verify via crypto/ecdsa, which
	// expects ASN.1 DER, so convert before the round trip. A signature that
	// is already DER (a non-conformant but tolerated caller) is passed
	// through unchanged.
	verifySig := signature
	if isECDSAMechanism(op.mechanism.Type) {
		der, convErr := normalizeECDSASignatureToDER(signature, op.ecFieldLen)
		if convErr != nil {
			return convErr
		}
		verifySig = der
	}

	// Verification must use the same padding the signature was produced with,
	// or a valid PSS signature is rejected as an invalid v1.5 one.
	padding, saltLen := rsaPaddingForMechanism(op.mechanism)

	req := &transport.VerifyRequest{
		Backend:    op.backend,
		KeyID:      op.keyID,
		Data:       data,
		Signature:  verifySig,
		Hash:       hashAlg,
		Padding:    padding,
		SaltLength: saltLen,
		// Must match what Sign sent for the same mechanism, or a signature
		// this module produced fails against a digest hashed one extra time.
		DataIsDigest: mechanismDataIsDigest(op.mechanism.Type),
	}

	// See the matching comment in Sign: thread the EdDSA variant selection
	// through so verification checks the signature against the same
	// scheme it was produced under.
	if op.mechanism.Type == CKM_EDDSA {
		if params, ok := op.mechanism.TypedParameter.(*EdDSAParams); ok && params != nil {
			req.PreHash = params.PreHash
			req.Context = params.Context
		}
	}

	resp, err := cm.client.Verify(ctx, req)
	if err != nil {
		return NewPKCS11ErrorFull(backendCKRV(err, CKR_FUNCTION_FAILED),
			"verify operation failed", err)
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

// ----------------------------------------------------------------
// ECDSA signature wire-format normalization
// ----------------------------------------------------------------

// isECDSAMechanism reports whether mechType is one of the ECDSA signing
// mechanisms, all of which share the same PKCS#11 v3.2 section 6.3.1 wire
// format for their signature: raw r || s, never ASN.1 DER.
func isECDSAMechanism(mechType MechanismType) bool {
	switch mechType {
	case CKM_ECDSA, CKM_ECDSA_SHA1, CKM_ECDSA_SHA224, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512:
		return true
	default:
		return false
	}
}

// ecdsaDERSignature mirrors the ASN.1 SEQUENCE { r INTEGER, s INTEGER }
// encoding produced by crypto/ecdsa.SignASN1 and consumed by
// crypto/ecdsa.VerifyASN1, per X.690 and RFC 3279 section 2.2.3.
type ecdsaDERSignature struct {
	R, S *big.Int
}

// ecdsaCurveOrderSizes lists, in ascending order, the field-element byte
// width (nLen) of every EC curve this module advertises for key generation
// (see CryptoManager.GenerateKeyPair's Curve parameter: P-256, P-384,
// P-521). It is used to size the fixed-width raw r || s encoding required
// by PKCS#11 v3.2 section 6.3.1 when the signing/verification path has no
// independent source of the key's curve.
var ecdsaCurveOrderSizes = []int{32, 48, 66} // P-256, P-384, P-521

// ecdsaNLenForComponents picks the narrowest of ecdsaCurveOrderSizes that
// can hold both DER-decoded signature components without truncation. If
// neither component fits any advertised curve (a curve this module does not
// generate keys for), the components' own length is used so no data is
// lost.
func ecdsaNLenForComponents(rLen, sLen int) int {
	maxLen := rLen
	if sLen > maxLen {
		maxLen = sLen
	}
	for _, n := range ecdsaCurveOrderSizes {
		if maxLen <= n {
			return n
		}
	}
	return maxLen
}

// SetECFieldLen records the byte width of one field element of the verifying
// key's curve. See SignOperation.SetECFieldLen.
func (v *VerifyOperation) SetECFieldLen(n int) {
	v.ecFieldLen = n
}

// isECDSADERSignature reports whether sig parses as the ASN.1 DER
// SEQUENCE { INTEGER, INTEGER } encoding of an ECDSA signature, as opposed
// to the raw r || s concatenation PKCS#11 v3.2 section 6.3.1 requires on
// the wire.
func isECDSADERSignature(sig []byte) bool {
	if len(sig) < 8 || sig[0] != 0x30 {
		return false
	}
	var parsed ecdsaDERSignature
	rest, err := asn1.Unmarshal(sig, &parsed)
	return err == nil && len(rest) == 0 && parsed.R != nil && parsed.S != nil
}

// normalizeECDSASignatureToRaw converts a DER-encoded ECDSA signature to the
// PKCS#11 wire format (raw r || s, each padded to a common nLen), per v3.2
// section 6.3.1. A signature that is not DER-encoded is returned unchanged,
// on the assumption that a spec-conformant backend already produced the raw
// form.
func normalizeECDSASignatureToRaw(sig []byte, nLen int) ([]byte, error) {
	if !isECDSADERSignature(sig) {
		return sig, nil
	}

	var parsed ecdsaDERSignature
	if _, err := asn1.Unmarshal(sig, &parsed); err != nil {
		return nil, NewPKCS11ErrorFull(CKR_SIGNATURE_INVALID, "failed to parse DER ECDSA signature", err)
	}
	if parsed.R.Sign() < 0 || parsed.S.Sign() < 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_SIGNATURE_INVALID, "ECDSA signature component is negative")
	}

	rBytes := parsed.R.Bytes()
	sBytes := parsed.S.Bytes()
	// The key's own field width is authoritative. It is only inferred from the
	// components when the caller could not resolve the curve, or when the
	// resolved width cannot hold what the signature actually carries -- padding
	// to a width smaller than a component would truncate it.
	if nLen < len(rBytes) || nLen < len(sBytes) {
		nLen = ecdsaNLenForComponents(len(rBytes), len(sBytes))
	}

	raw := make([]byte, 2*nLen)
	copy(raw[nLen-len(rBytes):nLen], rBytes)
	copy(raw[2*nLen-len(sBytes):], sBytes)
	return raw, nil
}

// normalizeECDSASignatureToDER converts a raw r || s ECDSA signature (the
// PKCS#11 wire format) to ASN.1 DER, for backends whose verifier expects DER
// (this module's server-side verification path uses crypto/ecdsa.VerifyASN1,
// which requires it). A signature that already parses as DER is returned
// unchanged, so a non-conformant caller that already sends DER is tolerated
// rather than double-encoded.
func normalizeECDSASignatureToDER(sig []byte, keyFieldLen int) ([]byte, error) {
	if isECDSADERSignature(sig) {
		return sig, nil
	}
	if len(sig) == 0 || len(sig)%2 != 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_SIGNATURE_LEN_RANGE,
			"raw ECDSA signature must have a non-zero, even length (r || s)")
	}
	// When the key's curve is known, the signature's length is fixed at twice
	// its field width (v3.2 §6.3.1), and a signature of any other length is
	// invalid on its face. §5.15.2 gives CKR_SIGNATURE_LEN_RANGE for exactly
	// this and ranks it above CKR_SIGNATURE_INVALID. Splitting an unexpected
	// length down the middle instead silently reinterpreted the bytes as a
	// different curve's r and s.
	if keyFieldLen > 0 && len(sig) != 2*keyFieldLen {
		return nil, NewPKCS11ErrorWithMessage(CKR_SIGNATURE_LEN_RANGE,
			"raw ECDSA signature length does not match the verifying key's curve")
	}

	nLen := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:nLen])
	s := new(big.Int).SetBytes(sig[nLen:])

	der, err := asn1.Marshal(ecdsaDERSignature{R: r, S: s})
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_SIGNATURE_INVALID, "failed to encode DER ECDSA signature", err)
	}
	return der, nil
}

// ----------------------------------------------------------------
// RSA-PSS parameter validation
// ----------------------------------------------------------------

// isRSAPSSMechanism reports whether mechType is one of the RSA-PSS signing
// mechanisms, every one of which requires a CK_RSA_PKCS_PSS_PARAMS
// mechanism parameter per PKCS#11 v3.2 section 6.4.3 -- including the
// hash-specific variants, since the mechanism name alone does not carry a
// salt length or mask-generation function.
func isRSAPSSMechanism(mechType MechanismType) bool {
	switch mechType {
	case CKM_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS:
		return true
	default:
		return false
	}
}

// rsaPSSImpliedHash maps each hash-specific PSS mechanism to the RSA digest
// algorithm its name implies, so CK_RSA_PKCS_PSS_PARAMS.hashAlg can be
// checked for consistency. CKM_RSA_PKCS_PSS (generic) has no implied hash --
// hashAlg is authoritative for that mechanism.
var rsaPSSImpliedHash = map[MechanismType]MechanismType{
	CKM_SHA256_RSA_PKCS_PSS: CKM_SHA256,
	CKM_SHA384_RSA_PKCS_PSS: CKM_SHA384,
	CKM_SHA512_RSA_PKCS_PSS: CKM_SHA512,
}

// rsaHashMechanismNames maps a bare hash mechanism (as carried in
// CK_RSA_PKCS_PSS_PARAMS.hashAlg) to the SDK hash algorithm string used on
// transport.SignRequest.Hash / transport.VerifyRequest.Hash.
var rsaHashMechanismNames = map[MechanismType]string{
	CKM_SHA_1:  "SHA-1",
	CKM_SHA224: "SHA-224",
	CKM_SHA256: "SHA-256",
	CKM_SHA384: "SHA-384",
	CKM_SHA512: "SHA-512",
}

// oaepDefaultHash is the digest an OAEP operation carries when the caller
// supplied no CK_RSA_PKCS_OAEP_PARAMS to name one.
//
// PKCS#1 v2.2 (RFC 8017 appendix A.2.1) makes SHA-1 OAEP's default, and
// PKCS#11 v3.2 §6.1.11 takes the digest from the parameters rather than
// restating one. This module cannot honour that default: the service layer
// refuses SHA-1 OAEP outright (XKMSService.EncryptAsym, asymDecrypterOpts), so
// sending SHA-1 would turn every unparameterized OAEP call into a hard failure.
// It names SHA-256 instead, and names it explicitly rather than leaving the
// field empty, so both halves of the operation are on the same digest by
// construction instead of by each defaulting separately.
const oaepDefaultHash = "SHA-256"

// rsaOAEPForMechanism reports the padding, digest and label a request must
// carry for CKM_RSA_PKCS_OAEP, taking them from CK_RSA_PKCS_OAEP_PARAMS.
// It returns empty values for every other mechanism, which leaves the request
// on its PKCS#1 v1.5 default.
//
// A hashAlg the module has no name for is an error rather than a substitution.
// The field is otherwise dropped, the request goes out naming no digest, and
// the service layer resolves that to its own default -- so a caller that asked
// for a digest this module does not implement is answered with a working
// operation under a different one, which its peer cannot reproduce.
func rsaOAEPForMechanism(mech *Mechanism) (padding, hash string, label []byte, err error) {
	if mech == nil || mech.Type != CKM_RSA_PKCS_OAEP {
		return "", "", nil, nil
	}
	params, ok := mech.TypedParameter.(*RSAOAEPParams)
	if !ok || params == nil {
		// The mechanism is OAEP even when the caller supplied no parameters.
		return "oaep", oaepDefaultHash, nil, nil
	}
	name, known := rsaHashMechanismNames[params.HashAlg]
	if !known {
		return "", "", nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CK_RSA_PKCS_OAEP_PARAMS.hashAlg names a digest this token does not implement for RSA-OAEP")
	}
	// mgf and source are validated through the same helper the wrap path uses,
	// so C_Encrypt, C_Decrypt, C_WrapKey and C_UnwrapKey cannot disagree about
	// which OAEP parameter combinations this token can serve.
	if err := ValidateRSAOAEPParams(params); err != nil {
		return "", "", nil, err
	}
	return "oaep", name, params.SourceData, nil
}

// rsaPaddingForMechanism reports the signature padding the request must carry
// and, for PSS, the salt length.
//
// The padding has to be stated explicitly: the service layer defaults to
// PKCS#1 v1.5, so leaving it unset for a PSS mechanism silently produces a
// v1.5 signature. That failure is invisible to a caller checking only that
// signing succeeded — the signature is well-formed, just not the scheme that
// was asked for.
func rsaPaddingForMechanism(mech *Mechanism) (padding string, saltLen int) {
	if !isRSAPSSMechanism(mech.Type) {
		return "", 0
	}
	if params, ok := mech.TypedParameter.(*RSAPSSParams); ok && params != nil {
		// sLen of 0 never reaches here: validateRSAPSSParams refuses it at
		// *Init, because crypto/rsa has no encoding for a zero-length salt and
		// passing 0 through would silently mean "auto".
		return "pss", int(params.SaltLen)
	}
	// No parameters at all: the caller expressed no preference, so the service's
	// automatic salt length applies.
	return "pss", 0
}

// validateRSAPSSParams checks CK_RSA_PKCS_PSS_PARAMS against mechType, per
// PKCS#11 v3.2 section 6.1.9: params must be present, and for a hash-specific
// PSS mechanism, params.HashAlg must match the hash the mechanism name
// implies.
//
// The parameters this validates are all forwarded:
// rsaPaddingForMechanism carries the padding mode and params.SaltLen into
// SignRequest.Padding / SaltLength, and Sign resolves params.HashAlg into
// SignRequest.Hash alongside DataIsDigest.
func validateRSAPSSParams(mechType MechanismType, params *RSAPSSParams) error {
	if params == nil {
		return NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CK_RSA_PKCS_PSS_PARAMS is required for RSA-PSS mechanisms")
	}
	if impliedHash, ok := rsaPSSImpliedHash[mechType]; ok && params.HashAlg != impliedHash {
		return NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CK_RSA_PKCS_PSS_PARAMS.hashAlg does not match the mechanism's hash algorithm")
	}
	if _, ok := rsaHashMechanismNames[params.HashAlg]; !ok {
		return NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CK_RSA_PKCS_PSS_PARAMS.hashAlg is not a supported hash algorithm")
	}
	// mgf is independent of hashAlg in the structure, but rsa.SignPSS derives
	// MGF1 from the digest it is given and takes no separate argument -- so a
	// caller naming CKG_MGF1_SHA1 alongside hashAlg=CKM_SHA256 would have its
	// request performed under MGF1-SHA-256 and reported as honoured, producing a
	// signature the verifier cannot reproduce. OAEP already refuses this
	// combination through ValidateRSAOAEPParams; PSS decoded the field and
	// dropped it, so the two halves of the same policy disagreed.
	if params.MGF != 0 && params.MGF != GetMGFForHash(params.HashAlg) {
		return NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CK_RSA_PKCS_PSS_PARAMS.mgf must be the MGF1 variant matching hashAlg; "+
				"this token cannot use an independent mask generation function")
	}
	// A zero-length salt is refused rather than approximated.
	//
	// RFC 8017 §9.1 permits sLen = 0 and some profiles require it, but
	// crypto/rsa cannot express it: rsa.PSSOptions.SaltLength reads 0 as
	// PSSSaltLengthAuto, -1 as PSSSaltLengthEqualsHash, and only a POSITIVE
	// value as a byte count. There is no encoding for "exactly zero".
	//
	// Passing it through therefore signed under the largest salt the modulus
	// allows, and -- the half that matters -- verified a signature carrying ANY
	// salt length for a caller that had asked the token to require none. That is
	// the substitution this module refuses everywhere else, so it refuses it
	// here: an application that names sLen=0 learns the token cannot do it,
	// instead of receiving a signature no strict verifier will accept and an
	// acceptance no attacker need work for.
	if params.SaltLen == 0 {
		return NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CK_RSA_PKCS_PSS_PARAMS.sLen of 0 requests a zero-length salt, which this token cannot perform")
	}
	return nil
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

	op := newEncryptOperation(mech, keyHandle, keyID, backend)

	switch mech.Type {
	case CKM_AES_GCM:
		// A caller-supplied CK_GCM_PARAMS.pIv is carried to the backend in
		// EncryptRequest.Nonce. When the caller supplies none, the backend
		// generates one and Encrypt reports it back through
		// EncryptOperation.IV() from EncryptResponse.Nonce.
		if params, ok := mech.GetAESGCMParams(); ok {
			if len(params.IV) > 0 {
				if len(params.IV) != GCMNonceSize {
					return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
						"AES-GCM IV must be 12 bytes")
				}
				op.iv = params.IV
			}

			// CK_GCM_PARAMS.pAAD and ulTagBits must be honoured here, not only
			// on the message-based path. C_EncryptInit is where a single-part
			// AEAD caller supplies them, and dropping them was silent: the
			// ciphertext body still matched, so a round trip through this
			// module succeeded while the tag authenticated nothing. Any caller
			// binding ciphertext to a header, tenant or key id got no integrity
			// from it, and the output did not interoperate with any other
			// implementation.
			if len(params.AAD) > 0 {
				op.SetAAD(params.AAD)
			}
			if err := applyGCMTagBits(op, params.TagBits); err != nil {
				return nil, err
			}
		}

	case CKM_AES_CBC, CKM_AES_CBC_PAD:
		// CBC requires the caller's 16-byte IV, carried to the backend in the
		// same request field.
		iv, ivErr := resolveCBCIV(mech)
		if ivErr != nil {
			return nil, ivErr
		}
		op.iv = iv

	case CKM_RSA_PKCS_OAEP:
		// Validate CK_RSA_PKCS_OAEP_PARAMS at Init rather than deferring to
		// Encrypt: §5.9.1 lists CKR_MECHANISM_PARAM_INVALID as a valid
		// C_EncryptInit return, and every other parameterized mechanism here
		// fails fast. rsaOAEPForMechanism is the same validator the wrap and
		// crypto paths use, so all four cannot disagree about what OAEP
		// parameter combinations the token serves.
		if _, _, _, err := rsaOAEPForMechanism(mech); err != nil {
			return nil, err
		}
	}

	return op, nil
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

	// A caller-supplied IV must reach the backend verbatim: ciphertext produced
	// under a different, backend-chosen IV would be undecryptable by a peer
	// using the IV the caller actually specified.
	if len(op.iv) > 0 && op.mechanism.Type == CKM_AES_GCM {
		if err := cm.checkGCMNonce(op.backend, op.keyID, op.iv); err != nil {
			op.finalized = true
			return nil, err
		}
	}

	// Mark as finalized
	op.finalized = true

	// CKM_RSA_PKCS_OAEP wraps/encrypts under a public key with no shared
	// symmetric-key material, so it is served by the dedicated asymmetric
	// -encrypt RPC (see PKCS11Transport.EncryptAsym) rather than the request
	// built below, which has no digest-selector field for the caller's
	// CK_RSA_PKCS_OAEP_PARAMS.hashAlg to travel in on.
	//
	// C_WrapKey no longer reaches this path. It used to, through a local
	// fallback that encrypted a module-held target key here instead of sending
	// it to the service, and that fallback is gone: it framed its output
	// differently from the blob C_UnwrapKey parses. WrapKeyByID sends
	// TargetKeyMaterial instead, so every wrap is framed by the one
	// implementation in the service.
	if op.mechanism.Type == CKM_RSA_PKCS_OAEP {
		return cm.encryptRSAOAEP(ctx, op, plaintext)
	}

	mode, nonce, iv := applyCipherMode(op.mechanism.Type, op.iv)
	req := &transport.EncryptRequest{
		Backend:        op.backend,
		KeyID:          op.keyID,
		Plaintext:      plaintext,
		AdditionalData: op.aad,
		Nonce:          nonce,
		Mode:           mode,
		IV:             iv,
		// The tag length the caller asked for in CK_GCM_PARAMS.ulTagBits,
		// resolved at EncryptInit. Zero leaves the backend's full-length tag
		// in force. Sending it is what makes the returned tag actually the
		// length the caller requested rather than a 128-bit tag reported as
		// though the request had been honoured.
		TagSize: op.tagSize,
	}

	resp, err := cm.client.Encrypt(ctx, req)
	if err != nil {
		return nil, NewPKCS11ErrorFull(backendCKRV(err, CKR_FUNCTION_FAILED),
			"encrypt operation failed", err)
	}

	if op.mechanism.Type == CKM_AES_GCM {
		// When the caller supplied no IV, the backend generated one. Record it
		// on the operation so the caller can recover it via
		// EncryptOperation.IV() -- per PKCS#11 v3.2 section 6.13.7 a
		// token-generated AES-GCM IV must be retrievable after
		// C_EncryptInit/C_Encrypt -- and guard against ever seeing the same
		// nonce reused under this key (see checkGCMNonce).
		//
		// A caller-supplied IV was already checked for reuse before the
		// request went out, and stays on the operation as-is.
		if len(op.iv) == 0 {
			if len(resp.Nonce) == 0 {
				return nil, NewPKCS11ErrorWithMessage(CKR_DEVICE_ERROR,
					"backend did not return an AES-GCM IV for a generated-IV encryption")
			}
			if err := cm.checkGCMNonce(op.backend, op.keyID, resp.Nonce); err != nil {
				return nil, err
			}
			op.iv = resp.Nonce
			op.ivGenerated = true
		}

		// PKCS#11 v3.2 section 6.13.7: the AES-GCM ciphertext on the wire
		// is ciphertext || tag.
		if len(resp.Tag) > 0 {
			result := make([]byte, 0, len(resp.Ciphertext)+len(resp.Tag))
			result = append(result, resp.Ciphertext...)
			result = append(result, resp.Tag...)
			return result, nil
		}
	}

	return resp.Ciphertext, nil
}

// symmetricCipherModes maps the block-cipher mechanisms to the wire mode name
// the service layer dispatches on.
//
// A mechanism absent from this map uses the transport's default AEAD mode, so
// only the modes that are genuinely something else need an entry.
var symmetricCipherModes = map[MechanismType]string{
	CKM_AES_CBC:     "cbc",
	CKM_AES_CBC_PAD: "cbc-pad",
	// CKM_AES_ECB (PKCS#11 v3.2 §6.10.4) must name its mode here for the same
	// reason CKM_AES_CBC must. Absent from this map it took the branch below,
	// which sends no mode at all and so selects the backend's default AEAD:
	// the token answered a request for ECB with AES-GCM, enciphering two
	// identical plaintext blocks to two different ciphertext blocks, and the
	// generated nonce and authentication tag were both dropped on the way
	// back (Encrypt reassembles those only for CKM_AES_GCM), so the token
	// could not decrypt its own output. Every symptom of that defect is the
	// missing entry.
	CKM_AES_ECB: "ecb",
}

// applyCipherMode routes an operation's IV to the field the requested mode
// reads it from.
//
// Nonce and IV are deliberately separate on the wire: a GCM nonce carries an
// authentication role and is 12 bytes, a CBC IV carries none and is 16. Putting
// a CBC IV in Nonce is what made every CKM_AES_CBC request fail — the backend
// saw no mode, built AES-GCM, and rejected the 16-byte value as a malformed
// nonce, even though CKM_AES_CBC is advertised with CKF_ENCRYPT.
//
// CKM_AES_ECB is a block mode with no IV at all, so it takes the same branch
// and carries an empty IV field; EncryptInit and DecryptInit never resolve one
// for it, and a backend that is handed one anyway refuses the operation rather
// than enciphering under a mode the caller did not select.
func applyCipherMode(mechType MechanismType, iv []byte) (mode string, nonceField, ivField []byte) {
	mode, isBlockMode := symmetricCipherModes[mechType]
	if isBlockMode {
		return mode, nil, iv
	}
	return "", iv, nil
}

// encryptRSAOAEP performs a CKM_RSA_PKCS_OAEP encryption via the dedicated
// EncryptAsym RPC. The digest comes from the caller's CK_RSA_PKCS_OAEP_PARAMS
// when present, and from oaepDefaultHash when the mechanism carries no
// parameters, through rsaOAEPForMechanism -- the same helper Decrypt uses, so
// the two halves of an OAEP operation cannot drift onto different digests. A
// hashAlg the module does not implement is refused there rather than replaced.
func (cm *CryptoManager) encryptRSAOAEP(ctx context.Context, op *EncryptOperation, plaintext []byte) ([]byte, error) {
	_, hash, label, err := rsaOAEPForMechanism(op.mechanism)
	if err != nil {
		return nil, err
	}

	resp, err := cm.client.EncryptAsym(ctx, &transport.EncryptAsymRequest{
		Backend:   op.backend,
		KeyID:     op.keyID,
		Plaintext: plaintext,
		Hash:      hash,
		// The caller's CK_RSA_PKCS_OAEP_PARAMS.pSourceData. Decrypt sends the
		// same value through the same helper, so the two halves of an OAEP
		// operation cannot drift onto different labels.
		Label: label,
	})
	if err != nil {
		return nil, NewPKCS11ErrorFull(backendCKRV(err, CKR_FUNCTION_FAILED),
			"encrypt operation failed", err)
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

// MessageDecryptInit initializes a message-based decryption operation.
//
// It differs from DecryptInit in one respect: it does not demand an IV. A
// message-based operation binds only the mechanism and the key
// (PKCS#11 v3.2 §5.11.1); the per-message parameters, including the AES-GCM IV
// and authentication tag, ride on each C_DecryptMessage call in
// CK_GCM_MESSAGE_PARAMS. Requiring the IV here is what made
// C_MessageDecryptInit reject every CKM_AES_GCM caller with
// CKR_MECHANISM_PARAM_INVALID while C_MessageEncryptInit accepted them.
func (cm *CryptoManager) MessageDecryptInit(mech *Mechanism, keyHandle ObjectHandle, keyID, backend string) (*DecryptOperation, error) {
	if mech == nil {
		return nil, NewPKCS11Error(CKR_MECHANISM_INVALID)
	}

	// Resolve through GetMechanismDescriptor, not the raw registry, so this
	// path honours the FIPS choke point like every other *Init. Reading
	// mechanismRegistry directly would admit a non-approved mechanism under
	// FIPS mode to any caller that reaches MessageDecryptInit directly.
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

	op := newDecryptOperation(mech, keyHandle, keyID, backend)

	// An IV on the Init is honoured when the caller supplied one. Only its
	// absence is tolerated: deferring unconditionally would silently discard an
	// IV a caller had every right to set there, leaving the operation with no
	// IV at all if it then sent no per-message parameters.
	if mech.Type == CKM_AES_GCM {
		if params, ok := mech.GetAESGCMParams(); ok {
			if len(params.IV) > 0 {
				op.iv = copyBytes(params.IV)
			}

			// The decrypt side must consume CK_GCM_PARAMS.pAAD for the same
			// reason the encrypt side must produce it. Without this a
			// ciphertext authenticated over AAD could never be opened, and
			// symmetrically the module's own output verified against no AAD at
			// all — which is what made the missing encrypt-side handling
			// invisible to a round-trip test.
			if len(params.AAD) > 0 {
				op.SetAAD(params.AAD)
			}

			// CK_GCM_PARAMS.ulTagBits is resolved here for the same reason
			// DecryptInit resolves it: the message-based path reattaches the
			// per-message tag and then reuses CryptoManager.Decrypt's framing,
			// which splits at this length.
			if err := applyGCMTagBitsDecrypt(op, params.TagBits); err != nil {
				return nil, err
			}
		}
	}

	return op, nil
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

	op := newDecryptOperation(mech, keyHandle, keyID, backend)

	switch mech.Type {
	case CKM_AES_GCM:
		iv, ivErr := resolveAEADDecryptIV(mech)
		if ivErr != nil {
			return nil, ivErr
		}
		op.iv = iv

		// CK_GCM_PARAMS.pAAD must be consumed here for the same reason
		// EncryptInit consumes it. This is the single-part decrypt path, and
		// omitting it while the encrypt side supplied AAD makes the tag
		// authenticate different inputs on the two halves, so every AEAD round
		// trip with associated data fails with CKR_ENCRYPTED_DATA_INVALID —
		// a failure that reads like corrupt ciphertext rather than a missing
		// parameter.
		//
		// CK_GCM_PARAMS.ulTagBits has to be consumed on this side too, and for
		// the same reason: C_Decrypt splits the trailing tag off the ciphertext
		// at this length before sending it on, so a decrypt that resolved a
		// different length from its encrypt hands the backend a mis-split
		// buffer and every round trip at a truncated tag length fails.
		if params, ok := mech.GetAESGCMParams(); ok {
			if len(params.AAD) > 0 {
				op.SetAAD(params.AAD)
			}
			if err := applyGCMTagBitsDecrypt(op, params.TagBits); err != nil {
				return nil, err
			}
		}

	case CKM_AES_CBC, CKM_AES_CBC_PAD:
		iv, ivErr := resolveCBCIV(mech)
		if ivErr != nil {
			return nil, ivErr
		}
		op.iv = iv

	case CKM_RSA_PKCS_OAEP:
		// Fail fast on a malformed CK_RSA_PKCS_OAEP_PARAMS at C_DecryptInit
		// (§5.10.1 permits CKR_MECHANISM_PARAM_INVALID) rather than deferring
		// to C_Decrypt. Same validator as the encrypt and wrap paths.
		if _, _, _, err := rsaOAEPForMechanism(mech); err != nil {
			return nil, err
		}
	}

	return op, nil
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

	// PKCS#11 v3.2 section 6.13.7: an AES-GCM ciphertext on the wire is
	// ciphertext || tag, with the tag length taken from the mechanism's
	// CK_GCM_PARAMS.ulTagBits (defaulting to the full 128-bit/16-byte tag).
	// The length comes from the operation, where DecryptInit resolved and
	// validated it once, so the split here and the TagSize sent below are the
	// same number by construction.
	// This framing is gated strictly on the mechanism actually being
	// CKM_AES_GCM -- unlike the previous implementation, non-AEAD
	// ciphertext is never inspected for a length-prefixed header.
	var tag, actualCiphertext []byte
	if op.mechanism.Type == CKM_AES_GCM {
		tagSize := gcmTagSize(op.tagSize)
		if len(ciphertext) < tagSize {
			return nil, NewPKCS11Error(CKR_ENCRYPTED_DATA_LEN_RANGE)
		}
		if len(op.iv) == 0 {
			// DecryptInit always resolves the IV for CKM_AES_GCM or fails;
			// reaching here with none means the operation bypassed DecryptInit.
			return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
				"AES-GCM decryption requires an IV resolved by DecryptInit")
		}
		split := len(ciphertext) - tagSize
		actualCiphertext = ciphertext[:split]
		tag = ciphertext[split:]
	} else {
		actualCiphertext = ciphertext
	}

	// Mark as finalized
	op.finalized = true

	// An OAEP decrypt must name its padding and digest. Without them the
	// service layer falls back to PKCS#1 v1.5 and the decrypt fails with what
	// looks like a corrupt-ciphertext error rather than a padding mismatch.
	oaepPadding, oaepHash, oaepLabel, oaepErr := rsaOAEPForMechanism(op.mechanism)
	if oaepErr != nil {
		return nil, oaepErr
	}

	req := &transport.DecryptRequest{
		Backend:        op.backend,
		KeyID:          op.keyID,
		Ciphertext:     actualCiphertext,
		Tag:            tag,
		AdditionalData: op.aad,
		Padding:        oaepPadding,
		Hash:           oaepHash,
		Label:          oaepLabel,
		// The same length the tag was split off at above, so the backend
		// recomputes and compares exactly that many tag bits (NIST SP 800-38D
		// section 5.2.2). Splitting at a truncated length while asking the
		// backend to verify a full-length tag is the failure mode this field
		// exists to prevent: it presents as CKR_ENCRYPTED_DATA_INVALID on
		// every round trip, which reads like corruption rather than a
		// mismatched parameter.
		TagSize: op.tagSize,
	}
	mode, nonce, iv := applyCipherMode(op.mechanism.Type, op.iv)
	req.Mode = mode
	if len(nonce) > 0 {
		req.Nonce = nonce
	}
	if len(iv) > 0 {
		req.IV = iv
	}

	resp, err := cm.client.Decrypt(ctx, req)
	if err != nil {
		// A decryption that fails on the ciphertext itself -- a wrong AEAD tag,
		// bad padding, a wrong key -- is CKR_ENCRYPTED_DATA_INVALID, which v3.2
		// §3.2 defines as "the encrypted input to a decryption operation has
		// been determined to be invalid ciphertext" and §5.10.2 lists among
		// C_Decrypt's return values. Collapsing it into CKR_FUNCTION_FAILED
		// left a caller unable to tell an attack from a device malfunction,
		// which are the two things it most needs to distinguish: one warrants a
		// retry, the other warrants an alert.
		//
		// CKR_AEAD_DECRYPT_FAILED is deliberately not used here: §5.10.6/§5.10.8
		// scope it to the message-based functions, not C_Decrypt.
		//
		// CKR_ENCRYPTED_DATA_INVALID is the fallback, not the verdict: a
		// rejection that already names its own condition -- a session torn down
		// by a concurrent C_Logout, above all -- keeps that code, because
		// telling a caller its ciphertext is invalid when the real answer is
		// "log in again" sends it looking for an attack that is not there.
		return nil, NewPKCS11ErrorFull(backendCKRV(err, CKR_ENCRYPTED_DATA_INVALID),
			"decrypt operation failed", err)
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

// ----------------------------------------------------------------
// AES-GCM / AES-CBC mechanism parameter handling
// ----------------------------------------------------------------

// gcmTagBitLengths are the CK_GCM_PARAMS.ulTagBits values this module
// accepts, mapped to the tag length in bytes it carries to the backend.
//
// PKCS#11 v3.2 §6.13.7 itself says ulTagBits "can be any value between 0 and
// 128", but the tag it describes is GCM's, and NIST SP 800-38D §5.2.1.2
// approves only t of 128, 120, 112, 104 and 96 bits. The module enforces the
// intersection: every length here is one both documents allow, and one
// crypto/cipher's NewGCMWithTagSize can actually produce, so a request that is
// accepted is a request that is honoured end to end.
var gcmTagBitLengths = map[uint32]int{
	96:  12,
	104: 13,
	112: 14,
	120: 15,
	128: 16,
}

// resolveGCMTagSize translates a caller-supplied CK_GCM_PARAMS.ulTagBits into
// the tag length in bytes the operation will use, returning zero when the
// caller named no length and the backend's own default applies.
//
// SP 800-38D §5.2.1.2 defines a t-bit tag as the leading t bits of the full
// 128-bit tag, so truncation is a real construction rather than a weakening
// improvised here -- but both halves of a round trip must agree on t. The
// resolved length is stored on the operation and travels to the backend on
// every request, which is what keeps C_Encrypt's output framing and
// C_Decrypt's input framing the same size.
//
// A length outside the approved set is CKR_MECHANISM_PARAM_INVALID rather
// than a rounding to the nearest permitted value: v3.2 §5.10.1 lists that
// code for C_EncryptInit, and a silently substituted tag length produces
// output no peer that took the request seriously can authenticate.
func resolveGCMTagSize(tagBits uint32) (int, error) {
	if tagBits == 0 {
		return 0, nil
	}
	size, ok := gcmTagBitLengths[tagBits]
	if !ok {
		return 0, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CK_GCM_PARAMS.ulTagBits must be 96, 104, 112, 120 or 128")
	}
	return size, nil
}

// applyGCMTagBits resolves a caller-supplied CK_GCM_PARAMS.ulTagBits onto an
// encryption operation, so C_Encrypt asks the backend for exactly the tag
// length the caller requested.
func applyGCMTagBits(op *EncryptOperation, tagBits uint32) error {
	size, err := resolveGCMTagSize(tagBits)
	if err != nil {
		return err
	}
	op.tagSize = size
	return nil
}

// applyGCMTagBitsDecrypt is applyGCMTagBits for the decrypt side. Both
// directions must resolve the same way from the same parameter: C_Decrypt
// splits ciphertext||tag at this length before sending, and the backend
// verifies the tag at this length after receiving, so a decrypt that
// resolved differently from its encrypt fails authentication in a way that
// reads like corrupt ciphertext.
func applyGCMTagBitsDecrypt(op *DecryptOperation, tagBits uint32) error {
	size, err := resolveGCMTagSize(tagBits)
	if err != nil {
		return err
	}
	op.tagSize = size
	return nil
}

// gcmTagSize returns the AES-GCM authentication tag length in bytes an
// operation frames with: the length resolved from CK_GCM_PARAMS.ulTagBits at
// Init, or the full 128-bit (16-byte) tag when the caller named none.
func gcmTagSize(opTagSize int) int {
	if opTagSize > 0 {
		return opTagSize
	}
	return GCMTagSize
}

// resolveAEADDecryptIV extracts the caller-supplied AES-GCM nonce required
// to decrypt, per PKCS#11 v3.2 section 6.13.7. Unlike encryption,
// decryption never generates an IV: the caller must supply the exact nonce
// used to produce the ciphertext, or decryption is impossible.
func resolveAEADDecryptIV(mech *Mechanism) ([]byte, error) {
	params, ok := mech.GetAESGCMParams()
	if !ok || len(params.IV) == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CKM_AES_GCM decryption requires the CK_GCM_PARAMS.pIv used at encryption time")
	}
	iv := make([]byte, len(params.IV))
	copy(iv, params.IV)
	return iv, nil
}

// resolveCBCIV extracts and validates the 16-byte initialization vector
// CKM_AES_CBC and CKM_AES_CBC_PAD require as their mechanism parameter, per
// PKCS#11 v3.2 sections 6.10.5 and 6.10.6. For these mechanisms,
// CK_MECHANISM.pParameter points directly at the raw IV bytes -- there is no
// wrapping struct -- so mech.Parameter is used when no typed parameter was
// supplied.
func resolveCBCIV(mech *Mechanism) ([]byte, error) {
	if mech == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CKM_AES_CBC/CKM_AES_CBC_PAD requires a 16-byte IV mechanism parameter")
	}

	if params, ok := mech.TypedParameter.(*AESCBCParams); ok {
		iv := make([]byte, 16)
		copy(iv, params.IV[:])
		return iv, nil
	}

	if len(mech.Parameter) != 16 {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CKM_AES_CBC/CKM_AES_CBC_PAD requires a 16-byte IV mechanism parameter")
	}
	iv := make([]byte, 16)
	copy(iv, mech.Parameter)
	return iv, nil
}

// remoteKeyGuardDomain separates the identities of keys this module does not
// hold the material for from every other input the AES-GCM nonce guard is
// given, so an identifier can never be mistaken for a key's own bytes.
const remoteKeyGuardDomain = "go-xkms/pkcs11 remote key\x00"

// remoteKeyGuardIdentity encodes which key a (key, IV) claim belongs to when
// the key lives in a backend and its material is never present in this
// process.
//
// The guard hashes whatever identity it is handed, so an identifier serves as
// long as two different keys cannot produce one identity. The fields are
// joined with a NUL, which neither a backend name nor a key id may contain, so
// ("a", "b\x00c") and ("a\x00b", "c") stay distinct.
//
// An identity taken from a name is strictly weaker than one taken from key
// material: it cannot see that two names denote one key. That case is closed
// where the material actually is -- the service claims the same pair again,
// keyed by the key's bytes, before it performs the AEAD (see wrapAESGCM in
// pkg/xkms) -- so an aliased key is refused there whether the service is
// embedded in this process or reached over a transport.
func remoteKeyGuardIdentity(backend, keyID string) []byte {
	return []byte(remoteKeyGuardDomain + backend + "\x00" + keyID)
}

// checkGCMNonce atomically claims nonce for an AES-GCM encryption under the
// key named by (backend, keyID), and refuses the operation when that exact
// pair has already been consumed anywhere in this process.
//
// NIST SP 800-38D section 8.2 requires that a (key, IV) pair never repeat.
// Two encryptions under one pair expose the XOR of their plaintexts, and the
// GHASH subkey H both messages share additionally makes tag forgery under that
// key feasible; PKCS#11 v3.2 section 6.13.7 leaves the IV in the caller's
// hands for CKM_AES_GCM, so nothing but this check stands between a caller
// that repeats one and that outcome.
//
// The claim goes to the process-wide guard in pkg/crypto/aead, through the
// same guardGCMNonce the authenticated wrap verbs use. It used to go to a
// sync.Map owned by this CryptoManager, which meant a host that constructed
// two managers had, in effect, no guard at all: neither map could see what the
// other had just consumed, and the in-process AES-GCM of
// C_WrapKeyAuthenticated was invisible to both. One guard, one tracker, one
// vocabulary.
func (cm *CryptoManager) checkGCMNonce(backend, keyID string, nonce []byte) error {
	return guardGCMNonce(remoteKeyGuardIdentity(backend, keyID), nonce)
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

	// Exportable carries the template's CKA_EXTRACTABLE to the backend.
	//
	// PKCS#11 v3.2 Table 30 defines CKA_EXTRACTABLE as "CK_TRUE if key is
	// extractable and can be wrapped", and the backend refuses to release
	// material for a key it was not told is exportable. Leaving this unset
	// stored every generated key as unexportable, so C_WrapKey failed on keys
	// whose template had asked for exactly that capability.
	Exportable bool

	// Sensitive carries the template's CKA_SENSITIVE to the backend.
	//
	// The module keeps this attribute on its own object too, so that
	// C_GetAttributeValue can answer without a round trip, but that copy lives
	// in client-side storage. Sending it means the backend's key record holds
	// the authoritative copy and refuses to release the plaintext of a
	// sensitive key regardless of what the module later asks for.
	Sensitive bool
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
		KeyID:      req.KeyID,
		Backend:    backend,
		KeyType:    keyType,
		KeySize:    req.KeySize,
		Exportable: req.Exportable,
		Sensitive:  req.Sensitive,
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
	// "NONE" is the wire sentinel for "the caller already produced the digest;
	// do not hash again". An empty string means "unspecified", which the
	// service layer resolves to its SHA-256 default — for CKM_RSA_PKCS that
	// would re-hash the DigestInfo the caller built and sign the wrong bytes,
	// producing a signature that verifies against nothing.
	CKM_RSA_PKCS:            "NONE",
	CKM_SHA1_RSA_PKCS:       "SHA-1",
	CKM_SHA256_RSA_PKCS:     "SHA-256",
	CKM_SHA384_RSA_PKCS:     "SHA-384",
	CKM_SHA512_RSA_PKCS:     "SHA-512",
	CKM_SHA224_RSA_PKCS:     "SHA-224",
	CKM_RSA_PKCS_PSS:        "", // Hash specified in params
	CKM_SHA256_RSA_PKCS_PSS: "SHA-256",
	CKM_SHA384_RSA_PKCS_PSS: "SHA-384",
	CKM_SHA512_RSA_PKCS_PSS: "SHA-512",
	CKM_ECDSA:               "NONE", // Caller supplies the digest
	CKM_ECDSA_SHA1:          "SHA-1",
	CKM_ECDSA_SHA224:        "SHA-224",
	CKM_ECDSA_SHA256:        "SHA-256",
	CKM_ECDSA_SHA384:        "SHA-384",
	CKM_ECDSA_SHA512:        "SHA-512",

	// The HMAC mechanisms name their digest in the mechanism itself
	// (PKCS#11 v3.2 §6.22: CKM_SHA256_HMAC, CKM_SHA384_HMAC and
	// CKM_SHA512_HMAC are "general-length SHA-n-HMAC" with the digest fixed by
	// the mechanism, not by a parameter). Nothing else on the wire carries it:
	// transport.SignRequest has no mechanism field, so if the digest is not in
	// Hash, three different mechanisms over one key build a byte-identical
	// request and the token cannot express which MAC was asked for.
	CKM_SHA256_HMAC: "SHA-256",
	CKM_SHA384_HMAC: "SHA-384",
	CKM_SHA512_HMAC: "SHA-512",

	// CKM_AES_CMAC (v3.2 §6.13.6) is a block-cipher MAC: there is no digest
	// to name and the message must not be hashed before the MAC is computed.
	// "NONE" says exactly that; "" would have the service layer hash the
	// message with SHA-256 first and MAC the digest.
	CKM_AES_CMAC: "NONE",

	// Raw RSA (v3.2 §6.1.5): the input is the number to be enciphered, not a
	// message to digest. Leaving this unspecified had the service layer hash
	// the caller's bytes with SHA-256 first, so the recovered value under
	// C_VerifyRecover was a digest the caller never sent.
	CKM_RSA_X_509: "NONE",

	// Signature schemes that hash internally as part of the scheme. Their
	// C_Sign input is the message, and pre-hashing it in the service layer
	// makes the signature verify only against the digest -- never against the
	// message a conformant peer holds. EdDSA (v3.2 §6.3.14), ML-DSA
	// (§6.5.5, pure Sign), SLH-DSA (§6.6.4, pure Sign), XEdDSA (§6.3.15),
	// HSS (§6.8) and XMSS/XMSS^MT (§6.9) are all in this class.
	//
	// EdDSA reaches the service layer's Ed25519 branch before any hash is
	// resolved, so its value is inert today; it is "NONE" so it stays correct
	// if that branch ever moves, and so this table reads consistently.
	CKM_EDDSA:            "NONE",
	CKM_XEDDSA:           "NONE",
	CKM_ML_DSA:           "NONE",
	CKM_SLH_DSA:          "NONE",
	CKM_HSS:              "NONE",
	CKM_XMSS:             "NONE",
	CKM_XMSSMT:           "NONE",
	CKM_VENDOR_ML_DSA_44: "NONE",
	CKM_VENDOR_ML_DSA_65: "NONE",
	CKM_VENDOR_ML_DSA_87: "NONE",
}

// mechanismToHash returns the SDK hash algorithm string for a mechanism.
func mechanismToHash(mechType MechanismType) string {
	if hash, ok := mechanismToHashMap[mechType]; ok {
		return hash
	}
	return ""
}

// preHashedSignMechanisms are the signature mechanisms whose C_Sign/C_Verify
// input is already a digest the application produced, rather than the message
// to be digested. They set SignRequest.DataIsDigest so the backend signs the
// bytes it was handed.
//
// The three differ in why:
//
//   - CKM_RSA_PKCS is raw PKCS#1 v1.5 block formatting over a DigestInfo the
//     application built (v3.2 §6.1.6). There is no digest identity at all, so
//     it also sends the "NONE" hash sentinel.
//   - CKM_ECDSA takes the hash as its input and truncates it to the curve's
//     order (v3.2 §6.3.4); the identity is likewise not needed, so it too
//     sends "NONE".
//   - CKM_RSA_PKCS_PSS "corresponds only to the part of PKCS #1 that involves
//     block formatting and RSA, given a hash value; it does not compute a hash
//     value on the message to be signed" (v3.2 §6.1.10), yet PSS still needs
//     the digest's identity for MGF1 and the salt length -- §6.1.9 says
//     CK_RSA_PKCS_PSS_PARAMS.hashAlg "must be the mechanism used by the
//     application to generate the message hash" precisely when the signature
//     mechanism does not hash. That is the case "NONE" cannot express, and
//     the reason DataIsDigest exists as a separate field: naming the hash used
//     to be read as an instruction to apply it, so the module hashed the
//     caller's digest a second time and produced signatures that verified
//     against nothing but themselves.
//
// The hash-prefixed variants (CKM_SHA256_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS,
// CKM_ECDSA_SHA256 and so on) do compute the digest themselves and are
// deliberately absent: for those the module hands over the message, not a
// digest, and the backend must hash it.
var preHashedSignMechanisms = map[MechanismType]struct{}{
	CKM_RSA_PKCS:     {},
	CKM_RSA_PKCS_PSS: {},
	CKM_ECDSA:        {},
}

// mechanismDataIsDigest reports whether a mechanism's C_Sign/C_Verify input is
// already a digest that must not be hashed again.
func mechanismDataIsDigest(mechType MechanismType) bool {
	_, ok := preHashedSignMechanisms[mechType]
	return ok
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

// SetIV sets the initialization vector for a message-based decryption.
//
// C_DecryptInit takes its IV from the mechanism, but a message-based operation
// binds mechanism and key once and then carries a fresh IV on every
// C_DecryptMessage (PKCS#11 v3.2 §5.11.2, CK_GCM_MESSAGE_PARAMS). The IV is
// therefore supplied per message rather than at Init.
func (op *DecryptOperation) SetIV(iv []byte) {
	op.iv = iv
}

// SetIV sets the initialization vector for a message-based encryption.
//
// Leaving it empty asks the backend to generate one, which is what
// CK_GCM_MESSAGE_PARAMS.ivGenerator selects; the generated value is then
// readable through EncryptOperation.IV.
func (op *EncryptOperation) SetIV(iv []byte) {
	op.iv = iv
}

// SetTagSize resolves a per-message CK_GCM_MESSAGE_PARAMS.ulTagBits onto the
// operation.
//
// C_EncryptInit takes ulTagBits from CK_GCM_PARAMS once, but a message-based
// operation binds only the mechanism and the key (v3.2 §5.9.1) and carries a
// fresh tag length on every C_EncryptMessage in CK_GCM_MESSAGE_PARAMS (§6.13.5).
// Without this, the length resolved at Init applied to every message -- and a
// conforming caller passes NO parameter to C_MessageEncryptInit, so there was
// nothing to resolve and every message got the full 128-bit tag regardless of
// what it asked for.
func (op *EncryptOperation) SetTagSize(tagBits uint32) error {
	return applyGCMTagBits(op, tagBits)
}

// SetTagSize is SetTagSize for the decrypt side. Both directions must resolve
// the same way from the same per-message parameter: Decrypt splits
// ciphertext||tag at this length before sending it on, so a mismatch hands the
// backend ciphertext bytes as tag material and every message fails as though it
// had been tampered with.
func (op *DecryptOperation) SetTagSize(tagBits uint32) error {
	return applyGCMTagBitsDecrypt(op, tagBits)
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

	switch mechanism.Type {
	case CKM_HKDF_DERIVE, CKM_HKDF_DATA:
		hkdfParams, err := parseHKDFParams(mechanism)
		if err != nil {
			return nil, err
		}

		if !hkdfParams.Extract && !hkdfParams.Expand {
			return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
				"CK_HKDF_PARAMS must set bExtract, bExpand, or both")
		}
		if hkdfParams.Extract != hkdfParams.Expand {
			// The derivation backend always performs RFC 5869's full
			// extract-then-expand construction; honoring only one phase
			// would silently derive different key material than the
			// caller's flags requested.
			return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
				"extract-only or expand-only HKDF is not supported")
		}

		switch hkdfParams.SaltType {
		case CKF_HKDF_SALT_NULL:
			// No salt: the backend falls back to RFC 5869's zero-salt
			// default.
		case CKF_HKDF_SALT_DATA:
			params.Salt = hkdfParams.Salt
		default:
			// CKF_HKDF_SALT_KEY requires resolving hSaltKey to another
			// object's CKA_VALUE, which this layer has no key-object
			// access to perform.
			return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
				"CKF_HKDF_SALT_KEY is not supported")
		}

		params.Info = hkdfParams.Info

		hash, ok := mechanismToHashFromHKDF(hkdfParams.PRFHashMech)
		if !ok {
			return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
				"unsupported HKDF prfHashMechanism")
		}
		params.Hash = hash

	case CKM_SP800_108_COUNTER_KDF, CKM_SP800_108_FEEDBACK_KDF, CKM_SP800_108_DOUBLE_PIPELINE_KDF:
		sp800Params, err := parseSP800108Params(mechanism)
		if err != nil {
			return nil, err
		}

		label, context, dpErr := sp800108LabelContext(sp800Params.DataParams)
		if dpErr != nil {
			return nil, dpErr
		}
		params.Label = label
		params.Context = context

		if mechanism.Type == CKM_SP800_108_FEEDBACK_KDF {
			// transport.DeriveKeyRequest has no distinct IV field;
			// feedback mode's K(0) initial value rides on Salt by
			// convention (mirroring buildECDHKDFParams's usesSaltAsIV).
			params.Salt = sp800Params.IV
		} else if len(sp800Params.IV) > 0 {
			return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
				"pIV is not an input to this SP800-108 mode")
		}

		hash, ok := mechanismToHashFromPRF(sp800Params.PRF)
		if !ok {
			return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
				"unsupported SP800-108 PRF: only HMAC-based PRFs are supported")
		}
		params.Hash = hash
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
//
// ikm is the base key's own material and is sent only when the module actually
// holds it — that is, when the application supplied the key through
// C_CreateObject and its CKA_VALUE is on the object. When ikm is empty the base
// key's IDENTITY travels instead (the backend name and key identifier the
// operation was initialized with) and the KDF runs inside the backend, over the
// key the backend holds.
//
// The two are mutually exclusive on the wire. They name two different base
// keys, and a request carrying both would let the service layer choose one and
// return a key derived from material the caller did not select, in a response
// indistinguishable from the one it wanted; the service layer refuses such a
// request, and this function never builds one. It is also why the identity is
// not sent "as well, just in case": there is no in-case, and the identifier is
// not a secret.
func (cm *CryptoManager) DeriveKey(ctx context.Context, op *DeriveOperation, ikm []byte, keyLength int) ([]byte, error) {
	if op == nil {
		return nil, NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	if op.finalized {
		return nil, NewPKCS11ErrorWithMessage(CKR_OPERATION_NOT_INITIALIZED,
			"operation already finalized")
	}

	// A base key that resolves to neither material nor an identity cannot be
	// derived from. Module.DeriveKey rejects that before reaching here; the
	// check is repeated because this is the function that would otherwise send
	// a request with no base key at all, and the service layer would answer it
	// with CKR_FUNCTION_FAILED instead of naming the real problem.
	if len(ikm) == 0 && op.baseKeyID == "" {
		return nil, NewPKCS11ErrorWithMessage(CKR_KEY_HANDLE_INVALID,
			"the base key has neither CKA_VALUE nor a backend key identifier")
	}

	// Mark as finalized
	op.finalized = true

	// Use provided key length or default from params
	outputKeyLength := keyLength
	if outputKeyLength <= 0 {
		outputKeyLength = op.params.KeyLength
	}

	req := &transport.DeriveKeyRequest{
		Backend:   op.backend,
		Algorithm: op.algorithm,
		Salt:      op.params.Salt,
		Info:      op.params.Info,
		Label:     op.params.Label,
		Context:   op.params.Context,
		KeyLength: outputKeyLength,
		Hash:      op.params.Hash,
	}
	if len(ikm) > 0 {
		req.InputKeyMaterial = ikm
	} else {
		req.KeyID = op.baseKeyID
	}

	resp, err := cm.client.DeriveKey(ctx, req)
	if err != nil {
		return nil, NewPKCS11ErrorFull(backendCKRV(err, CKR_FUNCTION_FAILED),
			"key derivation failed", err)
	}

	return resp.DerivedKey, nil
}

// parseHKDFParams extracts CK_HKDF_PARAMS from a mechanism's typed
// parameter, as populated at the cgo boundary by convertCMechanismToGo
// (cmd/pkcs11-module/exports.go). CKM_HKDF_DERIVE and CKM_HKDF_DATA require
// this parameter (v3.2 section 6.62.2): it is the only carrier for the
// caller's salt, info and PRF hash mechanism, so a mechanism without one
// parsed is rejected rather than derived under fabricated defaults.
func parseHKDFParams(mech *Mechanism) (*HKDFParams, error) {
	params, ok := mech.GetHKDFParams()
	if !ok || params == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CK_HKDF_PARAMS is required for CKM_HKDF_DERIVE/CKM_HKDF_DATA")
	}
	return params, nil
}

// parseSP800108Params extracts CK_SP800_108_KDF_PARAMS /
// CK_SP800_108_FEEDBACK_KDF_PARAMS from a mechanism's typed parameter, as
// populated at the cgo boundary by convertCMechanismToGo. All three
// SP800-108 derive mechanisms require this parameter (v3.2 section 6.42).
func parseSP800108Params(mech *Mechanism) (*SP800108KDFParams, error) {
	params, ok := mech.GetSP800108KDFParams()
	if !ok || params == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CK_SP800_108_KDF_PARAMS is required for CKM_SP800_108_* mechanisms")
	}
	return params, nil
}

// sp800108LabelContext extracts the Label and Context byte strings from an
// SP800-108 PRF input array (CK_PRF_DATA_PARAM[], v3.2 section 6.42). Only
// CK_SP800_108_BYTE_ARRAY segments, and a default (empty)
// CK_SP800_108_ITERATION_VARIABLE placeholder, are honored. This mirrors the
// spec's own canonical usage example for CK_SP800_108_KDF_PARAMS:
//
//	{ CK_SP800_108_ITERATION_VARIABLE, &counterFormat, sizeof(counterFormat) },
//	{ CK_SP800_108_BYTE_ARRAY, baLabel,   ulLabelLen   },
//	{ CK_SP800_108_BYTE_ARRAY, {0x00},    1            },
//	{ CK_SP800_108_BYTE_ARRAY, baContext, ulContextLen },
//
// where the first byte array is Label, the lone 0x00 entry is the
// Label/Context separator the derivation backend already inserts
// internally (see types.KDFParams.Label/Context doc: "Label || 0x00 ||
// Context || [L]_2"), and any remaining byte arrays concatenate into
// Context.
//
// CK_SP800_108_COUNTER, CK_SP800_108_DKM_LENGTH and CK_SP800_108_KEY_HANDLE
// segments -- and any explicit, non-default CK_SP800_108_ITERATION_VARIABLE
// encoding -- describe an exact PRF wire format (a custom counter width and
// endianness, an encoded DKM length, or another key's raw value mixed into
// the PRF input) that this module's derivation backend has no way to
// reproduce. Honoring them approximately would silently derive different
// key material than a conformant token would, so they are refused instead.
func sp800108LabelContext(dataParams []SP800108DataParam) (label, context []byte, err error) {
	var byteArrays [][]byte

	for _, dp := range dataParams {
		switch dp.Type {
		case SP800108ByteArray:
			byteArrays = append(byteArrays, dp.Value)
		case SP800108IterationVariable:
			if len(dp.Value) > 0 {
				return nil, nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
					"explicit CK_SP800_108_COUNTER_FORMAT for the iteration variable is not supported")
			}
		default:
			return nil, nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
				"unsupported SP800-108 PRF data field type")
		}
	}

	switch len(byteArrays) {
	case 0:
		return nil, nil, nil
	case 1:
		return byteArrays[0], nil, nil
	default:
		label = byteArrays[0]
		for _, seg := range byteArrays[1:] {
			if len(seg) == 1 && seg[0] == 0x00 {
				// Label/Context separator; the backend inserts this
				// itself and must not receive it twice.
				continue
			}
			context = append(context, seg...)
		}
		return label, context, nil
	}
}

// mechanismToHashFromHKDF returns the hash algorithm name for an HKDF
// prfHashMechanism (CK_HKDF_PARAMS.prfHashMechanism). It reports ok=false
// for any mechanism that is not one of the plain hash mechanisms HKDF's PRF
// is built from, so an unrecognized value is refused rather than silently
// treated as SHA-256.
func mechanismToHashFromHKDF(prf MechanismType) (hash string, ok bool) {
	switch prf {
	case CKM_SHA_1:
		return "SHA-1", true
	case CKM_SHA224:
		return "SHA-224", true
	case CKM_SHA256:
		return "SHA-256", true
	case CKM_SHA384:
		return "SHA-384", true
	case CKM_SHA512:
		return "SHA-512", true
	case CKM_SHA3_224:
		return "SHA3-224", true
	case CKM_SHA3_256:
		return "SHA3-256", true
	case CKM_SHA3_384:
		return "SHA3-384", true
	case CKM_SHA3_512:
		return "SHA3-512", true
	default:
		return "", false
	}
}

// mechanismToHashFromPRF returns the hash algorithm name for an SP800-108
// PRF mechanism (CK_SP800_108_KDF_PARAMS.prfType). It reports ok=false for
// any PRF this module's derivation backend does not implement: v3.2 Table
// 196 also lists CKM_AES_CMAC and CKM_DES3_CMAC as valid SP800-108 PRFs,
// but the backend (pkg/crypto/kdf) only implements the HMAC-based
// construction, so a CMAC request is refused rather than silently derived
// under the wrong PRF.
func mechanismToHashFromPRF(prf MechanismType) (hash string, ok bool) {
	switch prf {
	case CKM_SHA_1_HMAC:
		return "SHA-1", true
	case CKM_SHA224_HMAC:
		return "SHA-224", true
	case CKM_SHA256_HMAC:
		return "SHA-256", true
	case CKM_SHA384_HMAC:
		return "SHA-384", true
	case CKM_SHA512_HMAC:
		return "SHA-512", true
	case CKM_SHA3_224_HMAC:
		return "SHA3-224", true
	case CKM_SHA3_256_HMAC:
		return "SHA3-256", true
	case CKM_SHA3_384_HMAC:
		return "SHA3-384", true
	case CKM_SHA3_512_HMAC:
		return "SHA3-512", true
	default:
		return "", false
	}
}

// ----------------------------------------------------------------
// ECDH Key Derivation Operations
// ----------------------------------------------------------------

// KDFAlgorithmRaw is the wire-level KDF name that applies no key derivation
// function: the ECDH shared secret itself, truncated to the requested length.
//
// It is what PKCS#11's CKD_NULL asks for (v3.2, CK_ECDH1_DERIVE_PARAMS), and
// it is the form TLS key exchange and OpenSSL's pkcs11-provider request, which
// makes it the most common ECDH derivation rather than an exotic one.
//
// It exists as a name rather than as the absence of one because
// DeriveKeyECDH resolves an unnamed KDF to HKDF: "no KDF" and "no preference"
// have to be distinguishable, or a caller asking for the raw secret is handed
// an HKDF expansion of it under CKR_OK.
const KDFAlgorithmRaw = "RAW"

// DeriveKeyECDHRequest contains parameters for ECDH key derivation.
type DeriveKeyECDHRequest struct {
	// BaseKeyID is the ID of the private EC key to use for ECDH
	BaseKeyID string

	// Backend is the backend containing the private key
	Backend string

	// PeerPublicKey is the peer's public key (DER or uncompressed point format)
	PeerPublicKey []byte

	// KDFAlgorithm is the KDF to apply (HKDF, SP800-108-COUNTER, X963, etc.),
	// or KDFAlgorithmRaw for CKD_NULL, which applies none.
	KDFAlgorithm string

	// KDFHash is the hash algorithm for the KDF (SHA-256, SHA-384, SHA-512).
	// It must be empty for KDFAlgorithmRaw, which runs no pseudorandom
	// function and therefore consumes no digest.
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

	// Default KDF parameters. An unnamed KDF means the caller expressed no
	// preference and gets HKDF; KDFAlgorithmRaw is a name, so it is forwarded
	// untouched. The distinction is the whole reason the raw sentinel is
	// spelled out rather than left empty: mapping CKD_NULL onto "" here would
	// answer a request for the unmodified shared secret with an HKDF expansion
	// of it, under CKR_OK, and no peer could reproduce the key.
	kdfAlgorithm := req.KDFAlgorithm
	if kdfAlgorithm == "" {
		kdfAlgorithm = "HKDF"
	}

	// The raw KDF runs no pseudorandom function, so it takes no digest.
	// Defaulting one in would name a derivation step that does not happen,
	// and the service layer refuses a hash it has no input for.
	kdfHash := req.KDFHash
	if kdfHash == "" && kdfAlgorithm != KDFAlgorithmRaw {
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
		return nil, NewPKCS11ErrorFull(backendCKRV(err, CKR_FUNCTION_FAILED),
			"ECDH key derivation failed", err)
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

	// TargetKeyID is the ID of the key to be wrapped. Exactly one of
	// TargetKeyID and TargetKeyMaterial must be set.
	TargetKeyID string

	// TargetKeyBackend is the backend containing the target key
	TargetKeyBackend string

	// TargetKeyMaterial is the plaintext of a key this module holds locally,
	// for a C_WrapKey whose target was imported with C_CreateObject and
	// CKA_VALUE and so has no backend key ID. See WrapKey in module.go.
	TargetKeyMaterial []byte

	// Algorithm is the wrapping algorithm (e.g., "AES_KEY_WRAP", "RSAES_OAEP_SHA_256")
	Algorithm string

	// Params carries the CK_MECHANISM parameters the caller supplied.
	Params WrapMechanismParams
}

// WrapMechanismParams is the subset of a CK_MECHANISM's pParameter that
// C_WrapKey and C_UnwrapKey must carry to the service.
//
// mechanismToAlgorithm reduces a CK_MECHANISM to an algorithm name, which
// names the construction and (for OAEP) the digest and nothing else. Every
// other parameter the caller supplied used to stop there. That was silent for
// the one that matters most: an OAEP wrap under
// CK_RSA_PKCS_OAEP_PARAMS.pSourceData encrypted under the empty label and
// reported success, and a round trip through this module still passed because
// C_UnwrapKey dropped the label too.
type WrapMechanismParams struct {
	// IV is CK_GCM_PARAMS.pIv, or the 16-byte CK_AES_CBC_PARAMS IV. Empty asks
	// the token to generate one, which the wrapped blob then carries.
	IV []byte

	// AAD is CK_GCM_PARAMS.pAAD. It is authenticated but not encrypted, so it
	// is never carried in the blob and C_UnwrapKey must repeat it.
	AAD []byte

	// TagBits is CK_GCM_PARAMS.ulTagBits. Zero selects the full-length tag.
	TagBits int

	// OAEPLabel is CK_RSA_PKCS_OAEP_PARAMS.pSourceData.
	OAEPLabel []byte
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

	if req.TargetKeyID == "" && len(req.TargetKeyMaterial) == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_KEY_HANDLE_INVALID,
			"neither a target key ID nor target key material was supplied")
	}

	if req.TargetKeyID != "" && len(req.TargetKeyMaterial) > 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD,
			"a target key ID and target key material are mutually exclusive")
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

	// CKM_AES_GCM is the one wrapping mechanism here whose safety rests on the
	// caller-supplied IV, and the plaintext of a wrap is key material: two
	// wraps under one (KEK, IV) let anyone holding both blobs compute
	// ct_a XOR ct_b XOR pt_a and read BOTH wrapped keys, on top of disclosing
	// the GHASH subkey the two share (NIST SP 800-38D section 8.2). C_WrapKey
	// (PKCS#11 v3.2 section 5.18.3) passes that IV through untouched, so the
	// pair is claimed here or nowhere on this side of the transport.
	//
	// The claim is made after every check this module makes and immediately
	// before the request goes out. Claiming earlier would burn the IV of a
	// wrap that was going to be refused anyway, leaving the caller's corrected
	// retry -- with the same IV it had prepared -- refused as a reuse of a wrap
	// that never happened.
	//
	// An empty IV asks the service to generate the nonce and is deliberately
	// not claimed here: the module never sees that value, and the service
	// claims what it generated against this same process-wide guard before it
	// returns the blob.
	if algorithm == string(types.WrapAESGCM) && len(req.Params.IV) > 0 {
		if err := cm.checkGCMNonce(wrappingBackend, req.WrappingKeyID, req.Params.IV); err != nil {
			return nil, err
		}
	}

	sdkReq := &transport.WrapKeyByIDRequest{
		WrappingKeyID:      req.WrappingKeyID,
		WrappingKeyBackend: wrappingBackend,
		TargetKeyID:        req.TargetKeyID,
		TargetKeyBackend:   targetBackend,
		TargetKeyMaterial:  req.TargetKeyMaterial,
		Algorithm:          algorithm,
		IV:                 req.Params.IV,
		AAD:                req.Params.AAD,
		TagBits:            req.Params.TagBits,
		OAEPLabel:          req.Params.OAEPLabel,
	}

	resp, err := cm.client.WrapKeyByID(ctx, sdkReq)
	if err != nil {
		return nil, NewPKCS11ErrorFull(backendCKRV(err, CKR_FUNCTION_FAILED),
			"key wrapping failed", err)
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

	// Params carries the CK_MECHANISM parameters the caller supplied. Both
	// halves of a wrap must resolve them identically; see WrapMechanismParams.
	Params WrapMechanismParams

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
		IV:                   req.Params.IV,
		AAD:                  req.Params.AAD,
		TagBits:              req.Params.TagBits,
		OAEPLabel:            req.Params.OAEPLabel,
		TargetKeyID:          req.TargetKeyID,
		TargetKeyBackend:     targetBackend,
		TargetKeyType:        req.TargetKeyType,
		TargetKeySize:        req.TargetKeySize,
		TargetCurve:          req.TargetCurve,
		TargetExportable:     req.TargetExportable,
	}

	resp, err := cm.client.UnwrapKeyByID(ctx, sdkReq)
	if err != nil {
		return "", NewPKCS11ErrorFull(backendCKRV(err, CKR_FUNCTION_FAILED),
			"key unwrapping failed", err)
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
		return nil, NewPKCS11ErrorFull(backendCKRV(err, CKR_KEY_NOT_WRAPPABLE),
			"key material export failed", err)
	}

	return &ExportKeyMaterialResponse{
		KeyMaterial: resp.KeyMaterial,
		KeyType:     resp.KeyType,
		KeySize:     resp.KeySize,
	}, nil
}

// ----------------------------------------------------------------
// Key Material Import Operations
// ----------------------------------------------------------------

// importSymmetricKeySizes maps a secret key's material length in bytes to the
// key size in bits the import request must name.
//
// It doubles as the set of lengths this module will import at all. The service
// resolves a symmetric import through a fixed table of AES sizes, so material
// of any other length -- a generic secret of 20 bytes, say -- has no algorithm
// to be imported as, and offering it would fail in the backend rather than
// here. ImportKeyMaterial reports such a length as unsupported so
// C_CreateObject can keep the key local instead.
var importSymmetricKeySizes = map[int]int{
	16: 128,
	24: 192,
	32: 256,
}

// ImportKeyMaterialRequest contains parameters for importing plaintext secret
// key material into a backend.
type ImportKeyMaterialRequest struct {
	// KeyID is the identifier the imported key takes in the backend.
	KeyID string

	// Backend names the backend to import into. Empty selects the default.
	Backend string

	// KeyMaterial is the plaintext secret key. It is wrapped before it leaves
	// this process and is never sent in the clear.
	KeyMaterial []byte
}

// ImportKeyMaterial imports plaintext secret key material into a backend and
// reports the key identifier it was given.
//
// This is what makes a key an application supplied with C_CreateObject and
// CKA_VALUE into a key the token really holds, rather than an attribute map in
// this process. Everything the service does with a key it names by (backend,
// key id) -- C_Encrypt, C_Decrypt, C_Sign, and above all C_WrapKey and
// C_UnwrapKey, whose KEK must be resolvable server-side -- is unreachable for a
// key that has no such id. See Module.CreateObject for the object-level rules.
//
// The material is wrapped here, in this process, under the public key the
// service returns from GetImportParameters, and only the ciphertext crosses the
// transport. That is the same BYOK ceremony xkmsctl and the SDK already use
// (PKCS#11 v3.2 §6.1 describes the equivalent for a token), and it is why this
// needed no new wire capability: both halves already exist on every transport.
// Sending the plaintext to a "please import this" RPC would have been shorter
// and would have put a secret key on the wire for a backend -- a TPM, an HSM, a
// cloud KMS -- whose entire purpose is that plaintext key material never
// crosses that boundary.
//
// A backend that cannot import at all is reported as
// CKR_FUNCTION_NOT_SUPPORTED so the caller can distinguish "this token will
// never do this" from "this attempt failed"; Module.CreateObject relies on that
// distinction to fall back to a local object rather than fail the call.
func (cm *CryptoManager) ImportKeyMaterial(ctx context.Context, req *ImportKeyMaterialRequest) (string, error) {
	if req == nil {
		return "", NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "request is nil")
	}
	if req.KeyID == "" {
		return "", NewPKCS11ErrorWithMessage(CKR_ARGUMENTS_BAD, "key ID is empty")
	}
	if len(req.KeyMaterial) == 0 {
		return "", NewPKCS11ErrorWithMessage(CKR_ATTRIBUTE_VALUE_INVALID, "key material is empty")
	}

	keySize, ok := importSymmetricKeySizes[len(req.KeyMaterial)]
	if !ok {
		return "", NewPKCS11ErrorWithMessage(CKR_FUNCTION_NOT_SUPPORTED,
			"this token imports only 16, 24 or 32 byte secret keys")
	}

	backendName := req.Backend
	if backendName == "" {
		backendName = cm.config.DefaultBackend
	}

	// The algorithm is fixed rather than negotiated: RSA-OAEP with SHA-256 is
	// the one wrapping algorithm every ImportExportBackend implements, and it
	// is what pkg/xkms uses for the same ceremony on the server side.
	const algorithm = string(types.WrapRSAOAEPSHA256)

	params, err := cm.client.GetImportParameters(ctx, &transport.GetImportParametersRequest{
		Backend:   backendName,
		KeyID:     req.KeyID,
		Algorithm: algorithm,
		KeyType:   string(types.AlgorithmSymmetric),
		KeySize:   keySize,
	})
	if err != nil {
		// A backend with no import support answers here, before any material
		// has been prepared. Mapping it to CKR_FUNCTION_NOT_SUPPORTED is what
		// lets C_CreateObject tell that apart from a transient failure.
		return "", NewPKCS11ErrorFull(backendCKRV(err, CKR_FUNCTION_NOT_SUPPORTED),
			"failed to obtain key import parameters", err)
	}
	if len(params.WrappingPublicKey) == 0 {
		return "", NewPKCS11ErrorWithMessage(CKR_DEVICE_ERROR,
			"the backend returned no wrapping public key for the import")
	}

	wrapped, err := wrapForImport(params.WrappingPublicKey, req.KeyMaterial)
	if err != nil {
		return "", err
	}

	resp, err := cm.client.ImportKey(ctx, &transport.ImportKeyRequest{
		Backend:            backendName,
		KeyID:              req.KeyID,
		KeyType:            string(types.AlgorithmSymmetric),
		KeySize:            keySize,
		WrappedKeyMaterial: wrapped,
		Algorithm:          params.Algorithm,
		ImportToken:        params.ImportToken,
	})
	if err != nil {
		return "", NewPKCS11ErrorFull(backendCKRV(err, CKR_DEVICE_ERROR),
			"key material import failed", err)
	}
	if !resp.Success {
		return "", NewPKCS11ErrorWithMessage(CKR_DEVICE_ERROR, resp.Message)
	}

	// The service echoes the id it stored the key under. Trusting the response
	// over the request keeps the object's KeyID pointing at the key that
	// actually exists, should a backend ever normalize the name it was given.
	if resp.KeyID != "" {
		return resp.KeyID, nil
	}
	return req.KeyID, nil
}

// wrapForImport encrypts key material under a DER-encoded PKIX RSA public key,
// using RSA-OAEP with SHA-256.
//
// GetImportParameters returns the wrapping key marshalled with
// x509.MarshalPKIXPublicKey, so it is parsed the same way here. Only RSA is
// accepted because the import ceremony's parameters model an RSA wrapping key
// and nothing else; a backend that returned any other kind would produce a
// wrap the service could not reverse.
func wrapForImport(wrappingPublicKeyDER, keyMaterial []byte) ([]byte, error) {
	parsed, err := x509.ParsePKIXPublicKey(wrappingPublicKeyDER)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_DEVICE_ERROR,
			"failed to parse the backend's wrapping public key", err)
	}

	rsaPub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, NewPKCS11ErrorWithMessage(CKR_DEVICE_ERROR,
			"the backend's wrapping public key is not an RSA key")
	}

	wrapped, err := wrapping.WrapRSAOAEP(keyMaterial, rsaPub, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		return nil, NewPKCS11ErrorFull(CKR_DEVICE_ERROR,
			"failed to wrap key material for import", err)
	}

	return wrapped, nil
}
