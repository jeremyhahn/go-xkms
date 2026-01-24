// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package tpm2 provides a TPM 2.0 backed FIDO2 key backend.
package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/hex"
	"hash"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-keychain/pkg/fido2/authenticator/keybackend"
)

// COSE algorithm constants.
const (
	COSEAlgES256 = -7
	COSEAlgES384 = -35
	COSEAlgRS256 = -257 // TPM supports RSA
)

// COSE key type and curve constants.
const (
	COSEKeyTypeEC2 = 2
	COSEKeyTypeRSA = 3

	COSECurveP256 = 1
	COSECurveP384 = 2
)

// TPMInterface defines the interface required from TPM operations.
// This allows integration with the existing go-keychain TPM implementation.
type TPMInterface interface {
	GenerateECDSAKey(curve elliptic.Curve) (crypto.PrivateKey, error)
	Sign(privateKey crypto.PrivateKey, digest []byte) ([]byte, error)
	Close() error
}

// tpm2KeyHandle holds a reference to a TPM-backed key.
type tpm2KeyHandle struct {
	credentialID []byte
	algorithm    int
	publicKey    crypto.PublicKey
	// tpmHandle is the internal TPM handle (implementation-specific)
	tpmHandle interface{}
}

// CredentialID returns the credential ID associated with this key.
func (h *tpm2KeyHandle) CredentialID() []byte {
	return h.credentialID
}

// Algorithm returns the COSE algorithm identifier.
func (h *tpm2KeyHandle) Algorithm() int {
	return h.algorithm
}

// TPM2KeyBackend provides hardware-backed FIDO2 key operations via TPM 2.0.
type TPM2KeyBackend struct {
	mu         sync.RWMutex
	tpm        TPMInterface
	devicePath string
	keys       map[string]*tpm2KeyHandle // hex(credentialID) -> handle
	closed     atomic.Bool
}

// TPM2Config contains configuration for the TPM2 key backend.
type TPM2Config struct {
	// DevicePath is the TPM device path (e.g., "/dev/tpmrm0")
	DevicePath string
	// TPM is an optional pre-initialized TPM interface
	TPM TPMInterface
}

// NewTPM2KeyBackend creates a new TPM2-backed key backend.
func NewTPM2KeyBackend(cfg *TPM2Config) (*TPM2KeyBackend, error) {
	if cfg == nil {
		return nil, keybackend.ErrInvalidKeyHandle
	}

	backend := &TPM2KeyBackend{
		devicePath: cfg.DevicePath,
		keys:       make(map[string]*tpm2KeyHandle),
	}

	if cfg.TPM != nil {
		backend.tpm = cfg.TPM
	}
	// Note: If cfg.TPM is nil, we would need to open the TPM device
	// This would integrate with the existing go-keychain/pkg/tpm2 package

	return backend, nil
}

// Type returns the backend type.
func (b *TPM2KeyBackend) Type() keybackend.FIDO2KeyBackendType {
	return keybackend.BackendTypeTPM2
}

// Capabilities returns what this TPM backend supports.
func (b *TPM2KeyBackend) Capabilities() keybackend.FIDO2KeyCapabilities {
	return keybackend.FIDO2KeyCapabilities{
		SupportedAlgorithms: []int{COSEAlgES256, COSEAlgES384}, // TPM typically supports ECDSA
		SupportsExport:      false,                             // Hardware keys cannot be exported
		SupportsImport:      false,                             // Hardware keys cannot be imported
		SupportsAttestation: true,
		HardwareBacked:      true,
	}
}

// GenerateCredentialKey creates a new TPM-backed key.
func (b *TPM2KeyBackend) GenerateCredentialKey(algorithm int, credentialID []byte) (keybackend.KeyHandle, []byte, error) {
	if b.closed.Load() {
		return nil, nil, keybackend.ErrBackendClosed
	}
	if len(credentialID) == 0 {
		return nil, nil, keybackend.ErrInvalidCredentialID
	}

	var curve elliptic.Curve
	switch algorithm {
	case COSEAlgES256:
		curve = elliptic.P256()
	case COSEAlgES384:
		curve = elliptic.P384()
	default:
		return nil, nil, keybackend.ErrUnsupportedAlgorithm
	}

	// Generate key in TPM
	if b.tpm == nil {
		return nil, nil, keybackend.ErrKeyGenerationFailed
	}

	privateKey, err := b.tpm.GenerateECDSAKey(curve)
	if err != nil {
		return nil, nil, keybackend.ErrKeyGenerationFailed
	}

	ecKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, keybackend.ErrKeyGenerationFailed
	}

	// Encode public key to COSE format
	publicKeyCOSE, err := encodeCOSEEC2Key(&ecKey.PublicKey, algorithm)
	if err != nil {
		return nil, nil, keybackend.ErrKeyGenerationFailed
	}

	handle := &tpm2KeyHandle{
		credentialID: credentialID,
		algorithm:    algorithm,
		publicKey:    &ecKey.PublicKey,
		tpmHandle:    privateKey, // Store the TPM handle reference
	}

	b.mu.Lock()
	b.keys[hex.EncodeToString(credentialID)] = handle
	b.mu.Unlock()

	return handle, publicKeyCOSE, nil
}

// ecdsaSignature represents an ASN.1/DER encoded ECDSA signature.
type ecdsaSignature struct {
	R, S *big.Int
}

// convertP1363ToASN1DER converts a P1363 (r || s) signature to ASN.1/DER
// format with low-S normalization.
func convertP1363ToASN1DER(sig []byte, algorithm int) ([]byte, error) {
	var curve elliptic.Curve
	switch algorithm {
	case COSEAlgES256:
		curve = elliptic.P256()
	case COSEAlgES384:
		curve = elliptic.P384()
	default:
		return nil, keybackend.ErrUnsupportedAlgorithm
	}

	keySize := (curve.Params().BitSize + 7) / 8
	if len(sig) != keySize*2 {
		return nil, keybackend.ErrSigningFailed
	}

	r := new(big.Int).SetBytes(sig[:keySize])
	s := new(big.Int).SetBytes(sig[keySize:])

	// Normalize S to low-S form
	n := curve.Params().N
	halfN := new(big.Int).Rsh(n, 1)
	if s.Cmp(halfN) > 0 {
		s = new(big.Int).Sub(n, s)
	}

	return asn1.Marshal(ecdsaSignature{R: r, S: s})
}

// Sign creates a signature using the TPM.
func (b *TPM2KeyBackend) Sign(handle keybackend.KeyHandle, algorithm int, data []byte) ([]byte, error) {
	if b.closed.Load() {
		return nil, keybackend.ErrBackendClosed
	}
	if b.tpm == nil {
		return nil, keybackend.ErrSigningFailed
	}

	tpmHandle, ok := handle.(*tpm2KeyHandle)
	if !ok {
		return nil, keybackend.ErrInvalidKeyHandle
	}

	// Hash the data based on algorithm
	var hasher hash.Hash
	switch algorithm {
	case COSEAlgES256:
		hasher = sha256.New()
	case COSEAlgES384:
		hasher = sha512.New384()
	default:
		return nil, keybackend.ErrUnsupportedAlgorithm
	}

	hasher.Write(data)
	digest := hasher.Sum(nil)

	// Sign using TPM
	privateKey, ok := tpmHandle.tpmHandle.(crypto.PrivateKey)
	if !ok {
		return nil, keybackend.ErrInvalidKeyHandle
	}

	sig, err := b.tpm.Sign(privateKey, digest)
	if err != nil {
		return nil, keybackend.ErrSigningFailed
	}

	// Convert P1363 (r || s) to ASN.1/DER with low-S normalization
	derSig, err := convertP1363ToASN1DER(sig, algorithm)
	if err != nil {
		return nil, keybackend.ErrSigningFailed
	}

	return derSig, nil
}

// LoadKey loads a previously generated TPM key.
func (b *TPM2KeyBackend) LoadKey(credentialID []byte, algorithm int) (keybackend.KeyHandle, error) {
	if b.closed.Load() {
		return nil, keybackend.ErrBackendClosed
	}

	b.mu.RLock()
	handle, ok := b.keys[hex.EncodeToString(credentialID)]
	b.mu.RUnlock()

	if !ok {
		return nil, keybackend.ErrKeyNotFound
	}
	if handle.algorithm != algorithm {
		return nil, keybackend.ErrUnsupportedAlgorithm
	}

	return handle, nil
}

// DeleteKey removes a TPM key reference.
func (b *TPM2KeyBackend) DeleteKey(handle keybackend.KeyHandle) error {
	if b.closed.Load() {
		return keybackend.ErrBackendClosed
	}

	tpmHandle, ok := handle.(*tpm2KeyHandle)
	if !ok {
		return keybackend.ErrInvalidKeyHandle
	}

	b.mu.Lock()
	delete(b.keys, hex.EncodeToString(tpmHandle.credentialID))
	b.mu.Unlock()

	return nil
}

// ExportPrivateKey is not supported for TPM keys.
func (b *TPM2KeyBackend) ExportPrivateKey(handle keybackend.KeyHandle) ([]byte, error) {
	return nil, keybackend.ErrExportNotSupported
}

// ImportPrivateKey is not supported for TPM keys.
func (b *TPM2KeyBackend) ImportPrivateKey(credentialID []byte, algorithm int, pkcs8Key []byte) (keybackend.KeyHandle, error) {
	return nil, keybackend.ErrImportNotSupported
}

// Close releases TPM resources.
func (b *TPM2KeyBackend) Close() error {
	b.closed.Store(true)
	b.mu.Lock()
	b.keys = nil
	b.mu.Unlock()

	if b.tpm != nil {
		return b.tpm.Close()
	}
	return nil
}

// encodeCOSEEC2Key encodes an ECDSA public key to COSE format.
func encodeCOSEEC2Key(publicKey *ecdsa.PublicKey, algorithm int) ([]byte, error) {
	var curve int
	switch algorithm {
	case COSEAlgES256:
		curve = COSECurveP256
	case COSEAlgES384:
		curve = COSECurveP384
	default:
		return nil, keybackend.ErrUnsupportedAlgorithm
	}

	keySize := (publicKey.Curve.Params().BitSize + 7) / 8
	x := make([]byte, keySize)
	y := make([]byte, keySize)
	xBytes := publicKey.X.Bytes()
	yBytes := publicKey.Y.Bytes()
	copy(x[keySize-len(xBytes):], xBytes)
	copy(y[keySize-len(yBytes):], yBytes)

	coseKey := map[int]interface{}{
		1:  COSEKeyTypeEC2, // kty: EC2
		3:  algorithm,      // alg
		-1: curve,          // crv
		-2: x,              // x
		-3: y,              // y
	}

	return cbor.Marshal(coseKey)
}

// Ensure TPM2KeyBackend implements FIDO2KeyBackend
var _ keybackend.FIDO2KeyBackend = (*TPM2KeyBackend)(nil)
