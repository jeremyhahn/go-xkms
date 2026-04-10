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
	"io"
	"math/big"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/hkdf"
)

// HKDF info strings for PIN Protocol V2 key derivation.
// Reference: FIDO CTAP2.1 specification, section 6.5.6.
const (
	hkdfInfoHMACKey = "CTAP2 HMAC key"
	hkdfInfoAESKey  = "CTAP2 AES key"
	hkdfSaltSize    = 32

	// pinAuthSizeV2 is the full HMAC-SHA-256 output size for V2 (32 bytes).
	pinAuthSizeV2 = 32
)

// PINProtocolV2 implements CTAP2.1 PIN Protocol Version 2.
//
// PIN Protocol V2 uses:
//   - ECDH with P-256 curve for key agreement
//   - HKDF-SHA-256 for key derivation (separate hmacKey and aesKey)
//   - AES-256-CBC with random IV for encryption (IV prepended to ciphertext)
//   - HMAC-SHA-256 with full 32-byte output for authentication
//
// Key differences from V1:
//   - Shared secret derivation uses HKDF instead of SHA-256
//   - Two separate keys derived: hmacKey for authentication, aesKey for encryption
//   - Encryption uses a random IV prepended to the ciphertext
//   - Authentication returns full 32-byte HMAC (not truncated to 16)
//
// Reference: FIDO CTAP2.1 specification, section 6.5.6
type PINProtocolV2 struct {
	mu sync.RWMutex

	// privateKey is the authenticator's ephemeral private key.
	privateKey *ecdsa.PrivateKey

	// publicKey is the authenticator's ephemeral public key.
	publicKey *ecdsa.PublicKey

	// hmacKey is the HKDF-derived key for HMAC authentication (32 bytes).
	hmacKey []byte

	// aesKey is the HKDF-derived key for AES encryption (32 bytes).
	aesKey []byte

	// initialized indicates whether Initialize() has been called.
	initialized bool
}

// NewPINProtocolV2 creates a new PIN Protocol Version 2 instance.
// The instance must be initialized by calling Initialize() before use.
func NewPINProtocolV2() *PINProtocolV2 {
	return &PINProtocolV2{}
}

// Version returns the PIN protocol version number (2).
func (p *PINProtocolV2) Version() int {
	return PINProtocolVersion2
}

// Initialize generates a new ephemeral P-256 key pair for key agreement.
// This must be called before any other operations.
func (p *PINProtocolV2) Initialize() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ErrKeyGenerationFailed
	}

	p.privateKey = privateKey
	p.publicKey = &privateKey.PublicKey
	p.hmacKey = nil
	p.aesKey = nil
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
func (p *PINProtocolV2) GetKeyAgreementKey() ([]byte, error) {
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

// SetPeerPublicKey sets the peer's public key and derives the HKDF keys.
// The peerKey must be a COSE-encoded EC2 public key on the P-256 curve.
//
// Key derivation for PIN Protocol V2:
//  1. Perform ECDH: Z = peer_public_key * our_private_key
//  2. Take x-coordinate of Z (raw, NOT hashed)
//  3. hmacKey = HKDF-SHA-256(salt=zeros(32), IKM=x, info="CTAP2 HMAC key", L=32)
//  4. aesKey = HKDF-SHA-256(salt=zeros(32), IKM=x, info="CTAP2 AES key", L=32)
func (p *PINProtocolV2) SetPeerPublicKey(peerKey []byte) error {
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

	// Perform ECDH and derive HKDF keys
	hmacKey, aesKey, err := p.performECDHAndDerive(peerPublicKey)
	if err != nil {
		return err
	}

	p.hmacKey = hmacKey
	p.aesKey = aesKey
	return nil
}

// decodeCOSEKeyAgreementKey decodes a COSE-encoded EC2 public key for key agreement.
func (p *PINProtocolV2) decodeCOSEKeyAgreementKey(data []byte) (*ecdsa.PublicKey, error) {
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

// performECDHAndDerive performs ECDH key agreement and derives hmacKey and aesKey
// using HKDF-SHA-256.
//
// For PIN Protocol V2:
//
//	IKM = raw x-coordinate of ECDH result (NOT hashed)
//	Salt = 32 zero bytes
//	hmacKey = HKDF(SHA-256, IKM, salt, info="CTAP2 HMAC key", L=32)
//	aesKey  = HKDF(SHA-256, IKM, salt, info="CTAP2 AES key", L=32)
func (p *PINProtocolV2) performECDHAndDerive(peerPublicKey *ecdsa.PublicKey) ([]byte, []byte, error) {
	// Perform scalar multiplication: Z = peerPublicKey * privateKey
	x, _ := elliptic.P256().ScalarMult(peerPublicKey.X, peerPublicKey.Y, p.privateKey.D.Bytes())

	// Use raw x-coordinate as IKM (NOT hashed, unlike V1)
	xBytes := padCoordinate(x.Bytes(), ecdhP256CoordSize)

	// HKDF salt: 32 zero bytes
	salt := make([]byte, hkdfSaltSize)

	// Derive hmacKey
	hmacKeyReader := hkdf.New(sha256.New, xBytes, salt, []byte(hkdfInfoHMACKey))
	hmacKeyDerived := make([]byte, pinAuthSizeV2)
	if _, err := io.ReadFull(hmacKeyReader, hmacKeyDerived); err != nil {
		return nil, nil, ErrSharedSecretNotEstablished
	}

	// Derive aesKey
	aesKeyReader := hkdf.New(sha256.New, xBytes, salt, []byte(hkdfInfoAESKey))
	aesKeyDerived := make([]byte, pinAuthSizeV2)
	if _, err := io.ReadFull(aesKeyReader, aesKeyDerived); err != nil {
		return nil, nil, ErrSharedSecretNotEstablished
	}

	return hmacKeyDerived, aesKeyDerived, nil
}

// Encapsulate encrypts plaintext using AES-256-CBC with PKCS7 padding.
// Per CTAP2.1 spec, PIN Protocol V2 uses a random 16-byte IV prepended
// to the ciphertext.
func (p *PINProtocolV2) Encapsulate(plaintext []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.aesKey == nil {
		return nil, ErrSharedSecretNotEstablished
	}

	// Generate random IV
	iv := make([]byte, aesBlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, ErrPINEncryptionFailed
	}

	// Apply PKCS7 padding
	padded := pkcs7Pad(plaintext, aesBlockSize)

	// Create AES cipher with aesKey
	block, err := aes.NewCipher(p.aesKey)
	if err != nil {
		return nil, ErrPINEncryptionFailed
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)

	// Return IV || ciphertext
	return append(iv, ciphertext...), nil
}

// Decapsulate decrypts ciphertext using AES-256-CBC with PKCS7 padding.
// Per CTAP2.1 spec, the first 16 bytes of the input are the IV.
func (p *PINProtocolV2) Decapsulate(ciphertext []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.aesKey == nil {
		return nil, ErrSharedSecretNotEstablished
	}

	// Need at least IV (16 bytes) + one block (16 bytes)
	if len(ciphertext) < 2*aesBlockSize || len(ciphertext)%aesBlockSize != 0 {
		return nil, ErrPINDecryptionFailed
	}

	// Extract IV from the first 16 bytes
	iv := ciphertext[:aesBlockSize]
	encrypted := ciphertext[aesBlockSize:]

	// Create AES cipher with aesKey
	block, err := aes.NewCipher(p.aesKey)
	if err != nil {
		return nil, ErrPINDecryptionFailed
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(encrypted))
	mode.CryptBlocks(plaintext, encrypted)

	// Remove PKCS7 padding
	unpadded, err := pkcs7Unpad(plaintext)
	if err != nil {
		return nil, err
	}

	return unpadded, nil
}

// Authenticate computes the PIN authentication token over the given data.
// Returns HMAC-SHA-256(hmacKey, data) as the full 32-byte tag.
// PIN Protocol V2 uses the HKDF-derived hmacKey and returns the full
// 32-byte HMAC output (unlike V1 which truncates to 16 bytes).
func (p *PINProtocolV2) Authenticate(data []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.hmacKey == nil {
		return nil, ErrSharedSecretNotEstablished
	}

	mac := hmac.New(sha256.New, p.hmacKey)
	mac.Write(data)

	// V2 returns full 32-byte HMAC
	return mac.Sum(nil), nil
}

// Verify verifies a PIN authentication token.
// Returns nil if valid, ErrPINAuthenticationFailed otherwise.
// PIN Protocol V2 expects a full 32-byte HMAC tag.
func (p *PINProtocolV2) Verify(data, pinAuth []byte) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.hmacKey == nil {
		return ErrSharedSecretNotEstablished
	}

	// V2 expects full 32-byte tag
	if len(pinAuth) != pinAuthSizeV2 {
		return ErrPINAuthenticationFailed
	}

	// Compute expected pinAuth
	mac := hmac.New(sha256.New, p.hmacKey)
	mac.Write(data)
	expected := mac.Sum(nil)

	// Constant-time comparison
	if subtle.ConstantTimeCompare(pinAuth, expected) != 1 {
		return ErrPINAuthenticationFailed
	}

	return nil
}

// ResetSharedSecret clears the derived keys but retains the key pair.
// This should be called after PIN operations complete or on error.
// The key agreement pair is retained for subsequent operations.
func (p *PINProtocolV2) ResetSharedSecret() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Clear sensitive hmacKey data
	if p.hmacKey != nil {
		for i := range p.hmacKey {
			p.hmacKey[i] = 0
		}
		p.hmacKey = nil
	}

	// Clear sensitive aesKey data
	if p.aesKey != nil {
		for i := range p.aesKey {
			p.aesKey[i] = 0
		}
		p.aesKey = nil
	}
}

// Reset clears the ephemeral key pair and derived keys.
// After Reset, Initialize() must be called before using the protocol again.
func (p *PINProtocolV2) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Clear sensitive hmacKey data
	if p.hmacKey != nil {
		for i := range p.hmacKey {
			p.hmacKey[i] = 0
		}
		p.hmacKey = nil
	}

	// Clear sensitive aesKey data
	if p.aesKey != nil {
		for i := range p.aesKey {
			p.aesKey[i] = 0
		}
		p.aesKey = nil
	}

	p.privateKey = nil
	p.publicKey = nil
	p.initialized = false
}
