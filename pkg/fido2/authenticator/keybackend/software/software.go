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

// Package software provides a software-based FIDO2 key backend.
package software

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
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
	COSEAlgES512 = -36
	COSEAlgEdDSA = -8
)

// COSE key type and curve constants.
const (
	COSEKeyTypeEC2 = 2
	COSEKeyTypeOKP = 1

	COSECurveP256    = 1
	COSECurveP384    = 2
	COSECurveP521    = 3
	COSECurveEd25519 = 6
)

// softwareKeyHandle holds a reference to a software key.
type softwareKeyHandle struct {
	credentialID []byte
	algorithm    int
	privateKey   crypto.PrivateKey
	publicKey    crypto.PublicKey
}

func (h *softwareKeyHandle) CredentialID() []byte {
	return h.credentialID
}

func (h *softwareKeyHandle) Algorithm() int {
	return h.algorithm
}

// SoftwareKeyBackend stores keys in memory with PKCS#8 serialization support.
type SoftwareKeyBackend struct {
	mu     sync.RWMutex
	keys   map[string]*softwareKeyHandle // hex(credentialID) -> handle
	closed atomic.Bool
}

// NewSoftwareKeyBackend creates a new software key backend.
func NewSoftwareKeyBackend() *SoftwareKeyBackend {
	return &SoftwareKeyBackend{
		keys: make(map[string]*softwareKeyHandle),
	}
}

// Type returns the backend type.
func (b *SoftwareKeyBackend) Type() keybackend.FIDO2KeyBackendType {
	return keybackend.BackendTypeSoftware
}

// Capabilities returns the backend capabilities.
func (b *SoftwareKeyBackend) Capabilities() keybackend.FIDO2KeyCapabilities {
	return keybackend.FIDO2KeyCapabilities{
		SupportedAlgorithms: []int{COSEAlgES256, COSEAlgES384, COSEAlgES512, COSEAlgEdDSA},
		SupportsExport:      true,
		SupportsImport:      true,
		SupportsAttestation: false, // Software backend uses "none" attestation
		HardwareBacked:      false,
	}
}

// GenerateCredentialKey creates a new key pair.
func (b *SoftwareKeyBackend) GenerateCredentialKey(algorithm int, credentialID []byte) (keybackend.KeyHandle, []byte, error) {
	if b.closed.Load() {
		return nil, nil, keybackend.ErrBackendClosed
	}
	if len(credentialID) == 0 {
		return nil, nil, keybackend.ErrInvalidCredentialID
	}

	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey
	var err error

	switch algorithm {
	case COSEAlgES256:
		privateKey, publicKey, err = generateECDSAKey(elliptic.P256())
	case COSEAlgES384:
		privateKey, publicKey, err = generateECDSAKey(elliptic.P384())
	case COSEAlgES512:
		privateKey, publicKey, err = generateECDSAKey(elliptic.P521())
	case COSEAlgEdDSA:
		privateKey, publicKey, err = generateEdDSAKey()
	default:
		return nil, nil, keybackend.ErrUnsupportedAlgorithm
	}

	if err != nil {
		return nil, nil, keybackend.ErrKeyGenerationFailed
	}

	// Encode public key to COSE format
	publicKeyCOSE, err := encodeCOSEPublicKey(publicKey, algorithm)
	if err != nil {
		return nil, nil, keybackend.ErrKeyGenerationFailed
	}

	handle := &softwareKeyHandle{
		credentialID: credentialID,
		algorithm:    algorithm,
		privateKey:   privateKey,
		publicKey:    publicKey,
	}

	b.mu.Lock()
	b.keys[hex.EncodeToString(credentialID)] = handle
	b.mu.Unlock()

	return handle, publicKeyCOSE, nil
}

// Sign creates a signature.
func (b *SoftwareKeyBackend) Sign(handle keybackend.KeyHandle, algorithm int, data []byte) ([]byte, error) {
	if b.closed.Load() {
		return nil, keybackend.ErrBackendClosed
	}

	softHandle, ok := handle.(*softwareKeyHandle)
	if !ok {
		return nil, keybackend.ErrInvalidKeyHandle
	}

	switch algorithm {
	case COSEAlgES256:
		return signECDSA(softHandle.privateKey.(*ecdsa.PrivateKey), sha256.New(), data)
	case COSEAlgES384:
		return signECDSA(softHandle.privateKey.(*ecdsa.PrivateKey), sha512.New384(), data)
	case COSEAlgES512:
		return signECDSA(softHandle.privateKey.(*ecdsa.PrivateKey), sha512.New(), data)
	case COSEAlgEdDSA:
		return signEdDSA(softHandle.privateKey.(ed25519.PrivateKey), data)
	default:
		return nil, keybackend.ErrUnsupportedAlgorithm
	}
}

// LoadKey loads a key by credential ID.
func (b *SoftwareKeyBackend) LoadKey(credentialID []byte, algorithm int) (keybackend.KeyHandle, error) {
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

// DeleteKey removes a key.
func (b *SoftwareKeyBackend) DeleteKey(handle keybackend.KeyHandle) error {
	if b.closed.Load() {
		return keybackend.ErrBackendClosed
	}

	softHandle, ok := handle.(*softwareKeyHandle)
	if !ok {
		return keybackend.ErrInvalidKeyHandle
	}

	b.mu.Lock()
	delete(b.keys, hex.EncodeToString(softHandle.credentialID))
	b.mu.Unlock()

	return nil
}

// ExportPrivateKey exports the key in PKCS#8 format.
func (b *SoftwareKeyBackend) ExportPrivateKey(handle keybackend.KeyHandle) ([]byte, error) {
	if b.closed.Load() {
		return nil, keybackend.ErrBackendClosed
	}

	softHandle, ok := handle.(*softwareKeyHandle)
	if !ok {
		return nil, keybackend.ErrInvalidKeyHandle
	}

	return x509.MarshalPKCS8PrivateKey(softHandle.privateKey)
}

// ImportPrivateKey imports a PKCS#8 encoded key.
func (b *SoftwareKeyBackend) ImportPrivateKey(credentialID []byte, algorithm int, pkcs8Key []byte) (keybackend.KeyHandle, error) {
	if b.closed.Load() {
		return nil, keybackend.ErrBackendClosed
	}
	if len(credentialID) == 0 {
		return nil, keybackend.ErrInvalidCredentialID
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(pkcs8Key)
	if err != nil {
		return nil, keybackend.ErrInvalidPKCS8Key
	}

	var publicKey crypto.PublicKey
	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		publicKey = k.Public()
	case ed25519.PrivateKey:
		publicKey = k.Public()
	default:
		return nil, keybackend.ErrInvalidPKCS8Key
	}

	handle := &softwareKeyHandle{
		credentialID: credentialID,
		algorithm:    algorithm,
		privateKey:   privateKey,
		publicKey:    publicKey,
	}

	b.mu.Lock()
	b.keys[hex.EncodeToString(credentialID)] = handle
	b.mu.Unlock()

	return handle, nil
}

// Close releases resources.
func (b *SoftwareKeyBackend) Close() error {
	b.closed.Store(true)
	b.mu.Lock()
	b.keys = nil
	b.mu.Unlock()
	return nil
}

// Helper functions

func generateECDSAKey(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func generateEdDSAKey() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, pub, err
}

// ecdsaSignature holds the R and S components of an ECDSA signature
// for ASN.1/DER encoding.
type ecdsaSignature struct {
	R, S *big.Int
}

func signECDSA(privateKey *ecdsa.PrivateKey, hasher hash.Hash, data []byte) ([]byte, error) {
	hasher.Write(data)
	digest := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
	if err != nil {
		return nil, err
	}

	// Normalize S to low-S form per BIP-62 / WebAuthn requirements.
	// If S > n/2, replace S with n - S.
	n := privateKey.Curve.Params().N
	halfN := new(big.Int).Rsh(n, 1)
	if s.Cmp(halfN) > 0 {
		s = new(big.Int).Sub(n, s)
	}

	// Encode as ASN.1/DER
	sig, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func signEdDSA(privateKey ed25519.PrivateKey, data []byte) ([]byte, error) {
	return ed25519.Sign(privateKey, data), nil
}

func encodeCOSEPublicKey(publicKey crypto.PublicKey, algorithm int) ([]byte, error) {
	switch algorithm {
	case COSEAlgES256, COSEAlgES384, COSEAlgES512:
		ecKey := publicKey.(*ecdsa.PublicKey)
		return encodeCOSEEC2Key(ecKey, algorithm)
	case COSEAlgEdDSA:
		edKey := publicKey.(ed25519.PublicKey)
		return encodeCOSEOKPKey(edKey)
	default:
		return nil, keybackend.ErrUnsupportedAlgorithm
	}
}

func encodeCOSEEC2Key(publicKey *ecdsa.PublicKey, algorithm int) ([]byte, error) {
	var curve int
	switch algorithm {
	case COSEAlgES256:
		curve = COSECurveP256
	case COSEAlgES384:
		curve = COSECurveP384
	case COSEAlgES512:
		curve = COSECurveP521
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

func encodeCOSEOKPKey(publicKey ed25519.PublicKey) ([]byte, error) {
	coseKey := map[int]interface{}{
		1:  COSEKeyTypeOKP,    // kty: OKP
		3:  COSEAlgEdDSA,      // alg
		-1: COSECurveEd25519,  // crv
		-2: []byte(publicKey), // x
	}

	return cbor.Marshal(coseKey)
}

// Ensure SoftwareKeyBackend implements FIDO2KeyBackend
var _ keybackend.FIDO2KeyBackend = (*SoftwareKeyBackend)(nil)
