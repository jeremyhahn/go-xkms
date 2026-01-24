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

package authenticator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"math/big"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// PIN Protocol V1 constants.
const (
	// aesBlockSize is the AES block size (16 bytes).
	aesBlockSize = 16

	// ecdhP256CoordSize is the size of P-256 coordinates (32 bytes).
	ecdhP256CoordSize = 32

	// pinAuthSize is the size of the truncated HMAC for PIN auth (16 bytes).
	pinAuthSize = 16

	// COSEAlgECDHESHKDF256 is the COSE algorithm for ECDH-ES+HKDF-256.
	COSEAlgECDHESHKDF256 = -25
)

// PIN Protocol V1 specific errors.
var (
	// ErrInvalidPKCS7Padding indicates invalid PKCS7 padding during decryption.
	ErrInvalidPKCS7Padding = errors.New("authenticator: invalid PKCS7 padding")

	// ErrInvalidCOSEKeyAgreement indicates the COSE key is not valid for key agreement.
	ErrInvalidCOSEKeyAgreement = errors.New("authenticator: invalid COSE key for key agreement")
)

// PINProtocolV1 implements CTAP2 PIN Protocol Version 1.
//
// PIN Protocol V1 uses:
//   - ECDH with P-256 curve for key agreement
//   - SHA-256 for shared secret derivation
//   - AES-256-CBC with zero IV for encryption
//   - HMAC-SHA-256 (truncated to 16 bytes) for authentication
//
// Reference: FIDO CTAP2 specification, section 6.5.4
type PINProtocolV1 struct {
	mu sync.RWMutex

	// privateKey is the authenticator's ephemeral private key.
	privateKey *ecdsa.PrivateKey

	// publicKey is the authenticator's ephemeral public key.
	publicKey *ecdsa.PublicKey

	// sharedSecret is the derived shared secret (32 bytes).
	sharedSecret []byte

	// initialized indicates whether Initialize() has been called.
	initialized bool
}

// NewPINProtocolV1 creates a new PIN Protocol Version 1 instance.
// The instance must be initialized by calling Initialize() before use.
func NewPINProtocolV1() *PINProtocolV1 {
	return &PINProtocolV1{}
}

// Version returns the PIN protocol version number (1).
func (p *PINProtocolV1) Version() int {
	return PINProtocolVersion1
}

// Initialize generates a new ephemeral P-256 key pair for key agreement.
// This must be called before any other operations.
func (p *PINProtocolV1) Initialize() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ErrKeyGenerationFailed
	}

	p.privateKey = privateKey
	p.publicKey = &privateKey.PublicKey
	p.sharedSecret = nil
	p.initialized = true

	return nil
}

// GetKeyAgreementKey returns the COSE-encoded public key for key agreement.
// The returned key format is a CBOR map with:
//   - kty (1): 2 (EC2)
//   - alg (3): -25 (ECDH-ES+HKDF-256)
//   - crv (-1): 1 (P-256)
//   - x (-2): x-coordinate (32 bytes)
//   - y (-3): y-coordinate (32 bytes)
func (p *PINProtocolV1) GetKeyAgreementKey() ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.initialized || p.publicKey == nil {
		return nil, ErrPINProtocolNotInitialized
	}

	// Encode public key as COSE_Key
	coseKey := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   padCoordinate(p.publicKey.X.Bytes(), ecdhP256CoordSize),
		coseKeyLabelY:   padCoordinate(p.publicKey.Y.Bytes(), ecdhP256CoordSize),
	}

	return cbor.Marshal(coseKey)
}

// SetPeerPublicKey sets the peer's public key and derives the shared secret.
// The peerKey must be a COSE-encoded EC2 public key on the P-256 curve.
//
// Shared secret derivation for PIN Protocol V1:
//  1. Perform ECDH: Z = peer_public_key * our_private_key
//  2. Take x-coordinate of Z
//  3. SharedSecret = SHA-256(x-coordinate)
func (p *PINProtocolV1) SetPeerPublicKey(peerKey []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.initialized || p.privateKey == nil {
		return ErrPINProtocolNotInitialized
	}

	// Decode COSE key
	peerPublicKey, err := p.decodeCOSEKeyAgreementKey(peerKey)
	if err != nil {
		return err
	}

	// Perform ECDH to derive shared secret
	sharedSecret, err := p.performECDH(peerPublicKey)
	if err != nil {
		return err
	}

	p.sharedSecret = sharedSecret
	return nil
}

// decodeCOSEKeyAgreementKey decodes a COSE-encoded EC2 public key for key agreement.
func (p *PINProtocolV1) decodeCOSEKeyAgreementKey(data []byte) (*ecdsa.PublicKey, error) {
	if len(data) == 0 {
		return nil, ErrInvalidCOSEKeyAgreement
	}

	var coseKey map[int]interface{}
	if err := cbor.Unmarshal(data, &coseKey); err != nil {
		return nil, ErrInvalidCOSEKeyAgreement
	}

	// Verify key type is EC2
	ktyRaw, ok := coseKey[coseKeyLabelKty]
	if !ok {
		return nil, ErrInvalidCOSEKeyAgreement
	}
	kty, err := toInt(ktyRaw)
	if err != nil || kty != COSEKeyTypeEC2 {
		return nil, ErrInvalidCOSEKeyAgreement
	}

	// Verify curve is P-256
	crvRaw, ok := coseKey[coseKeyLabelCrv]
	if !ok {
		return nil, ErrInvalidCOSEKeyAgreement
	}
	crv, err := toInt(crvRaw)
	if err != nil || crv != COSECurveP256 {
		return nil, ErrInvalidCOSEKeyAgreement
	}

	// Extract x coordinate
	xRaw, ok := coseKey[coseKeyLabelX]
	if !ok {
		return nil, ErrInvalidCOSEKeyAgreement
	}
	xBytes, ok := xRaw.([]byte)
	if !ok || len(xBytes) == 0 {
		return nil, ErrInvalidCOSEKeyAgreement
	}

	// Extract y coordinate
	yRaw, ok := coseKey[coseKeyLabelY]
	if !ok {
		return nil, ErrInvalidCOSEKeyAgreement
	}
	yBytes, ok := yRaw.([]byte)
	if !ok || len(yBytes) == 0 {
		return nil, ErrInvalidCOSEKeyAgreement
	}

	// Construct public key
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// Verify point is on curve
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, ErrInvalidPeerPublicKey
	}

	return pubKey, nil
}

// performECDH performs ECDH key agreement and returns the shared secret.
// For PIN Protocol V1: SharedSecret = SHA-256(x-coordinate of ECDH result)
func (p *PINProtocolV1) performECDH(peerPublicKey *ecdsa.PublicKey) ([]byte, error) {
	// Perform scalar multiplication: Z = peerPublicKey * privateKey
	x, _ := elliptic.P256().ScalarMult(peerPublicKey.X, peerPublicKey.Y, p.privateKey.D.Bytes())

	// For PIN Protocol V1, shared secret is SHA-256 of x-coordinate
	xBytes := padCoordinate(x.Bytes(), ecdhP256CoordSize)
	hash := sha256.Sum256(xBytes)

	return hash[:], nil
}

// Encapsulate encrypts plaintext using AES-256-CBC with PKCS7 padding.
// Per CTAP2 spec, PIN Protocol V1 uses a zero IV.
func (p *PINProtocolV1) Encapsulate(plaintext []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.sharedSecret == nil {
		return nil, ErrSharedSecretNotEstablished
	}

	// Apply PKCS7 padding
	padded := pkcs7Pad(plaintext, aesBlockSize)

	// Create AES cipher with shared secret as key
	block, err := aes.NewCipher(p.sharedSecret)
	if err != nil {
		return nil, ErrPINEncryptionFailed
	}

	// PIN Protocol V1 uses zero IV
	iv := make([]byte, aesBlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)

	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)

	return ciphertext, nil
}

// Decapsulate decrypts ciphertext using AES-256-CBC with PKCS7 padding.
// Per CTAP2 spec, PIN Protocol V1 uses a zero IV.
func (p *PINProtocolV1) Decapsulate(ciphertext []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.sharedSecret == nil {
		return nil, ErrSharedSecretNotEstablished
	}

	// Verify ciphertext length is a multiple of block size
	if len(ciphertext) == 0 || len(ciphertext)%aesBlockSize != 0 {
		return nil, ErrPINDecryptionFailed
	}

	// Create AES cipher with shared secret as key
	block, err := aes.NewCipher(p.sharedSecret)
	if err != nil {
		return nil, ErrPINDecryptionFailed
	}

	// PIN Protocol V1 uses zero IV
	iv := make([]byte, aesBlockSize)
	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	unpadded, err := pkcs7Unpad(plaintext)
	if err != nil {
		return nil, err
	}

	return unpadded, nil
}

// Authenticate computes the PIN authentication token over the given data.
// Returns HMAC-SHA-256(sharedSecret[0:16], data)[0:16].
// PIN Protocol V1 uses only the first 16 bytes of shared secret as HMAC key.
func (p *PINProtocolV1) Authenticate(data []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.sharedSecret == nil {
		return nil, ErrSharedSecretNotEstablished
	}

	// PIN Protocol V1: Use first 16 bytes of shared secret as HMAC key
	hmacKey := p.sharedSecret[:pinAuthSize]
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(data)
	fullMAC := mac.Sum(nil)

	// Return first 16 bytes
	return fullMAC[:pinAuthSize], nil
}

// Verify verifies a PIN authentication token.
// Returns nil if valid, ErrPINAuthenticationFailed otherwise.
func (p *PINProtocolV1) Verify(data, pinAuth []byte) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.sharedSecret == nil {
		return ErrSharedSecretNotEstablished
	}

	if len(pinAuth) != pinAuthSize {
		return ErrPINAuthenticationFailed
	}

	// Compute expected pinAuth
	hmacKey := p.sharedSecret[:pinAuthSize]
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(data)
	expected := mac.Sum(nil)[:pinAuthSize]

	// Constant-time comparison
	if subtle.ConstantTimeCompare(pinAuth, expected) != 1 {
		return ErrPINAuthenticationFailed
	}

	return nil
}

// ResetSharedSecret clears the shared secret but retains the key pair.
// This should be called after PIN operations complete or on error.
// The key agreement pair is retained for subsequent operations.
func (p *PINProtocolV1) ResetSharedSecret() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Clear sensitive shared secret data
	if p.sharedSecret != nil {
		for i := range p.sharedSecret {
			p.sharedSecret[i] = 0
		}
		p.sharedSecret = nil
	}
}

// Reset clears the ephemeral key pair and shared secret.
// After Reset, Initialize() must be called before using the protocol again.
func (p *PINProtocolV1) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Clear sensitive shared secret data
	if p.sharedSecret != nil {
		for i := range p.sharedSecret {
			p.sharedSecret[i] = 0
		}
		p.sharedSecret = nil
	}

	p.privateKey = nil
	p.publicKey = nil
	p.initialized = false
}

// pkcs7Pad applies PKCS7 padding to the input data.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padBytes := make([]byte, padding)
	for i := range padBytes {
		padBytes[i] = byte(padding)
	}
	return append(data, padBytes...)
}

// pkcs7Unpad removes PKCS7 padding from the input data.
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrInvalidPKCS7Padding
	}

	padding := int(data[len(data)-1])

	// Validate padding
	if padding == 0 || padding > aesBlockSize || padding > len(data) {
		return nil, ErrInvalidPKCS7Padding
	}

	// Verify all padding bytes are correct
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, ErrInvalidPKCS7Padding
		}
	}

	return data[:len(data)-padding], nil
}
