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

//go:build pkcs11

package canokey

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"

	"filippo.io/edwards25519"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Note: Backend implements SymmetricBackend interface methods via envelope encryption:
// - GenerateSymmetricKey
// - GetSymmetricKey
// - SymmetricEncrypter
//
// Envelope Encryption Pattern (per Google's recommendation):
// 1. Generate a random DEK (Data Encryption Key) using CanoKey's hardware RNG
// 2. Encrypt the data with software AES-256-GCM using the DEK
// 3. Encrypt the DEK with the CanoKey's key using algorithm-specific wrapping:
//    - RSA: RSA-OAEP with SHA256
//    - ECDSA: ECIES pattern (ECDH + HKDF + AES-256-GCM)
//    - Ed25519: Convert to X25519, then use X25519 + HKDF + AES-256-GCM
// 4. Store the encrypted DEK alongside the ciphertext with algorithm metadata

const (
	// Wrapping algorithm identifiers stored in metadata
	wrapAlgoRSAOAEP   = "rsa-oaep-sha256"
	wrapAlgoECIESP256 = "ecies-p256"
	wrapAlgoECIESP384 = "ecies-p384"
	wrapAlgoX25519    = "x25519"

	// HKDF info strings for domain separation
	hkdfInfoECIES  = "go-keychain-ecies-dek-wrap"
	hkdfInfoX25519 = "go-keychain-x25519-dek-wrap"

	// DEK size for AES-256
	dekSize = 32
)

var _ types.SymmetricBackend = (*Backend)(nil)

// canokeySymmetricKey implements types.SymmetricKey for CanoKey envelope encryption.
// The actual key material is a software DEK that gets encrypted with a key in a PIV slot.
type canokeySymmetricKey struct {
	algorithm        string
	keySize          int
	wrappingKeyAttrs *types.KeyAttributes // Reference to PIV slot key used as KEK
	backend          *Backend
}

// Algorithm returns the symmetric algorithm identifier.
func (k *canokeySymmetricKey) Algorithm() string {
	return k.algorithm
}

// KeySize returns the key size in bits.
func (k *canokeySymmetricKey) KeySize() int {
	return k.keySize
}

// Raw returns an error because CanoKey-backed symmetric keys use envelope encryption
// and don't expose the raw DEK material - each encryption generates a new DEK.
func (k *canokeySymmetricKey) Raw() ([]byte, error) {
	return nil, fmt.Errorf("%w: CanoKey symmetric keys use envelope encryption and don't expose raw key material", backend.ErrNotSupported)
}

// canokeySymmetricEncrypter implements types.SymmetricEncrypter using envelope encryption.
// All encryption/decryption operations use a randomly generated DEK that is wrapped with
// the CanoKey's key using the appropriate algorithm.
type canokeySymmetricEncrypter struct {
	backend          *Backend
	attrs            *types.KeyAttributes
	wrappingKeyAttrs *types.KeyAttributes // Attributes of the PIV slot key
}

// Encrypt encrypts plaintext using envelope encryption:
// 1. Generate random 32-byte DEK via CanoKey's hardware RNG
// 2. Encrypt plaintext with AES-256-GCM using the DEK
// 3. Encrypt DEK with CanoKey's key using appropriate algorithm (RSA/ECIES/X25519)
// 4. Return encrypted data with encrypted DEK and algorithm in metadata
func (e *canokeySymmetricEncrypter) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	if opts == nil {
		opts = &types.EncryptOptions{}
	}

	// STEP 1: Generate random 32-byte DEK using CanoKey's hardware RNG
	dek, err := e.backend.GenerateRandom(dekSize)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to generate DEK: %w", err)
	}
	defer func() {
		// Zero out DEK after use
		for i := range dek {
			dek[i] = 0
		}
	}()

	// STEP 2: Encrypt plaintext with AES-256-GCM using the DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to create GCM: %w", err)
	}

	// Generate or use provided nonce
	var nonce []byte
	if opts.Nonce != nil {
		nonce = opts.Nonce
	} else {
		nonce = make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("canokey: failed to generate nonce: %w", err)
		}
	}

	// Encrypt with authentication (GCM Seal)
	ciphertext := gcm.Seal(nil, nonce, plaintext, opts.AdditionalData)

	// GCM appends the tag to ciphertext, extract it
	tagSize := gcm.Overhead()
	if len(ciphertext) < tagSize {
		return nil, fmt.Errorf("%w: got %d bytes, expected at least %d bytes (tag size)", ErrCiphertextTooShort, len(ciphertext), tagSize)
	}
	tag := ciphertext[len(ciphertext)-tagSize:]
	ciphertextOnly := ciphertext[:len(ciphertext)-tagSize]

	// STEP 3: Encrypt DEK with CanoKey's key using appropriate algorithm
	// Get the wrapping key's decrypter to access the public key
	decrypter, err := e.backend.Decrypter(e.wrappingKeyAttrs)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to get wrapping key decrypter: %w", err)
	}

	pubKey := decrypter.Public()

	var encryptedDEK []byte
	var wrapAlgo string

	// Determine wrapping algorithm based on key type
	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		encryptedDEK, err = wrapDEKWithRSA(pub, dek)
		wrapAlgo = wrapAlgoRSAOAEP

	case *ecdsa.PublicKey:
		encryptedDEK, err = wrapDEKWithECIES(pub, dek)
		// Determine curve-specific algorithm identifier
		switch pub.Curve.Params().Name {
		case "P-256":
			wrapAlgo = wrapAlgoECIESP256
		case "P-384":
			wrapAlgo = wrapAlgoECIESP384
		default:
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedCurve, pub.Curve.Params().Name)
		}

	case ed25519.PublicKey:
		// Check firmware version before proceeding
		if !e.backend.SupportsX25519() {
			return nil, ErrFirmwareRequired
		}
		encryptedDEK, err = wrapDEKWithX25519(pub, dek)
		wrapAlgo = wrapAlgoX25519

	default:
		return nil, fmt.Errorf("%w: wrapping key type %T (must be RSA, ECDSA, or Ed25519)", ErrUnsupportedAlgorithm, pubKey)
	}

	if err != nil {
		return nil, fmt.Errorf("canokey: failed to wrap DEK: %w", err)
	}

	// STEP 4: Store encrypted DEK and wrap algorithm in metadata
	metadata := make(map[string][]byte)
	metadata["encryptedDEK"] = []byte(base64.StdEncoding.EncodeToString(encryptedDEK))
	metadata["wrapAlgorithm"] = []byte(wrapAlgo)

	return &types.EncryptedData{
		Ciphertext: ciphertextOnly,
		Nonce:      nonce,
		Tag:        tag,
		Algorithm:  "aes256-gcm-envelope",
		Metadata:   metadata,
	}, nil
}

// Decrypt decrypts ciphertext using envelope encryption:
// 1. Extract encrypted DEK and wrap algorithm from metadata
// 2. Decrypt DEK using CanoKey's key with appropriate algorithm
// 3. Decrypt ciphertext with AES-256-GCM using the DEK
func (e *canokeySymmetricEncrypter) Decrypt(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	if opts == nil {
		opts = &types.DecryptOptions{}
	}

	// Validate algorithm
	if data.Algorithm != "aes256-gcm-envelope" {
		return nil, fmt.Errorf("%w: %s (expected aes256-gcm-envelope)", ErrUnsupportedAlgorithm, data.Algorithm)
	}

	// STEP 1: Extract encrypted DEK and wrap algorithm from metadata
	if data.Metadata == nil {
		return nil, ErrMissingMetadata
	}

	encryptedDEKB64, ok := data.Metadata["encryptedDEK"]
	if !ok {
		return nil, ErrMissingEncryptedDEK
	}

	encryptedDEK, err := base64.StdEncoding.DecodeString(string(encryptedDEKB64))
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to decode encrypted DEK: %w", err)
	}

	// Get wrap algorithm (default to RSA for backward compatibility)
	wrapAlgo := wrapAlgoRSAOAEP
	if wrapAlgoBytes, ok := data.Metadata["wrapAlgorithm"]; ok {
		wrapAlgo = string(wrapAlgoBytes)
	}

	// STEP 2: Decrypt DEK using CanoKey's key with appropriate algorithm
	decrypter, err := e.backend.Decrypter(e.wrappingKeyAttrs)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to get wrapping key decrypter: %w", err)
	}

	var dekBytes []byte

	switch wrapAlgo {
	case wrapAlgoRSAOAEP:
		dekBytes, err = unwrapDEKWithRSA(decrypter, encryptedDEK)

	case wrapAlgoECIESP256:
		dekBytes, err = unwrapDEKWithECIES(decrypter, encryptedDEK, elliptic.P256())

	case wrapAlgoECIESP384:
		dekBytes, err = unwrapDEKWithECIES(decrypter, encryptedDEK, elliptic.P384())

	case wrapAlgoX25519:
		// Check firmware version before proceeding
		if !e.backend.SupportsX25519() {
			return nil, ErrFirmwareRequired
		}
		dekBytes, err = unwrapDEKWithX25519(decrypter, encryptedDEK)

	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, wrapAlgo)
	}

	if err != nil {
		return nil, fmt.Errorf("canokey: failed to unwrap DEK: %w", err)
	}

	defer func() {
		// Zero out DEK after use
		for i := range dekBytes {
			dekBytes[i] = 0
		}
	}()

	// Validate DEK size
	if len(dekBytes) != dekSize {
		return nil, fmt.Errorf("%w: got %d bytes, expected %d", ErrInvalidDEKSize, len(dekBytes), dekSize)
	}

	// STEP 3: Decrypt ciphertext with AES-256-GCM using the DEK
	block, err := aes.NewCipher(dekBytes)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to create GCM: %w", err)
	}

	// Reconstruct full ciphertext with tag (GCM expects tag appended)
	fullCiphertext := append(data.Ciphertext, data.Tag...)

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, data.Nonce, fullCiphertext, opts.AdditionalData)
	if err != nil {
		return nil, fmt.Errorf("canokey: decryption failed (authentication error): %w", err)
	}

	return plaintext, nil
}

// wrapDEKWithRSA encrypts a DEK using RSA-OAEP with SHA256.
func wrapDEKWithRSA(pubKey *rsa.PublicKey, dek []byte) ([]byte, error) {
	encryptedDEK, err := rsa.EncryptOAEP(
		crypto.SHA256.New(),
		rand.Reader,
		pubKey,
		dek,
		nil, // no label
	)
	if err != nil {
		return nil, fmt.Errorf("canokey: RSA-OAEP encryption failed: %w", err)
	}
	return encryptedDEK, nil
}

// unwrapDEKWithRSA decrypts a DEK using RSA-OAEP with SHA256.
func unwrapDEKWithRSA(decrypter crypto.Decrypter, encryptedDEK []byte) ([]byte, error) {
	dekBytes, err := decrypter.Decrypt(rand.Reader, encryptedDEK, &rsa.OAEPOptions{
		Hash: crypto.SHA256,
	})
	if err != nil {
		return nil, fmt.Errorf("canokey: RSA-OAEP decryption failed: %w", err)
	}
	return dekBytes, nil
}

// wrapDEKWithECIES encrypts a DEK using ECIES pattern (ECDH + HKDF + AES-256-GCM).
// The encrypted DEK format is: ephemeralPubKey || nonce || ciphertext || tag
func wrapDEKWithECIES(pubKey *ecdsa.PublicKey, dek []byte) ([]byte, error) {
	curve := pubKey.Curve

	// Generate ephemeral ECDSA key pair on same curve
	ephemeralPriv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to generate ephemeral key: %w", err)
	}

	// Perform ECDH to derive shared secret
	sharedX, _ := curve.ScalarMult(pubKey.X, pubKey.Y, ephemeralPriv.D.Bytes())
	sharedSecret := sharedX.Bytes()

	// Derive encryption key using HKDF-SHA256
	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte(hkdfInfoECIES))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, derivedKey); err != nil {
		return nil, fmt.Errorf("canokey: HKDF failed: %w", err)
	}
	defer func() {
		for i := range derivedKey {
			derivedKey[i] = 0
		}
	}()

	// Encrypt DEK with AES-256-GCM
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("canokey: failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, dek, nil)

	// Extract tag (last 16 bytes of ciphertext)
	tagSize := gcm.Overhead()
	tag := ciphertext[len(ciphertext)-tagSize:]
	ciphertextOnly := ciphertext[:len(ciphertext)-tagSize]

	// Marshal ephemeral public key
	ephemeralPubBytes := elliptic.Marshal(curve, ephemeralPriv.PublicKey.X, ephemeralPriv.PublicKey.Y)

	// Construct encrypted DEK: ephemeralPub || nonce || ciphertext || tag
	result := make([]byte, 0, len(ephemeralPubBytes)+len(nonce)+len(ciphertextOnly)+len(tag))
	result = append(result, ephemeralPubBytes...)
	result = append(result, nonce...)
	result = append(result, ciphertextOnly...)
	result = append(result, tag...)

	return result, nil
}

// unwrapDEKWithECIES decrypts a DEK using ECIES pattern (ECDH + HKDF + AES-256-GCM).
func unwrapDEKWithECIES(decrypter crypto.Decrypter, encryptedDEK []byte, curve elliptic.Curve) ([]byte, error) {
	// Calculate expected ephemeral public key size
	pubKeySize := (curve.Params().BitSize+7)/8*2 + 1 // Uncompressed format: 0x04 || X || Y

	// Validate minimum size: pubKey + nonce(12) + ciphertext + tag(16)
	minSize := pubKeySize + 12 + dekSize + 16
	if len(encryptedDEK) < minSize {
		return nil, fmt.Errorf("%w: got %d bytes, expected at least %d", ErrEncryptedDEKTooShort, len(encryptedDEK), minSize)
	}

	// Extract components
	ephemeralPubBytes := encryptedDEK[:pubKeySize]
	nonce := encryptedDEK[pubKeySize : pubKeySize+12]

	// Remaining is ciphertext + tag
	ciphertextAndTag := encryptedDEK[pubKeySize+12:]
	if len(ciphertextAndTag) < 16 {
		return nil, ErrCiphertextTooShort
	}

	tag := ciphertextAndTag[len(ciphertextAndTag)-16:]
	ciphertextOnly := ciphertextAndTag[:len(ciphertextAndTag)-16]

	// Unmarshal ephemeral public key
	ephemeralX, ephemeralY := elliptic.Unmarshal(curve, ephemeralPubBytes)
	if ephemeralX == nil {
		return nil, ErrInvalidEphemeralKey
	}

	// Get our private key
	privKey, ok := decrypter.(interface{ PrivateKey() crypto.PrivateKey })
	if !ok {
		// Try type assertion to *ecdsa.PrivateKey directly
		return nil, ErrDecrypterNoPrivateKey
	}

	ecdsaPriv, ok := privKey.PrivateKey().(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w, got %T", ErrNotECDSAKey, privKey.PrivateKey())
	}

	// Perform ECDH to derive shared secret
	sharedX, _ := curve.ScalarMult(ephemeralX, ephemeralY, ecdsaPriv.D.Bytes())
	sharedSecret := sharedX.Bytes()

	// Derive decryption key using HKDF-SHA256
	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte(hkdfInfoECIES))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, derivedKey); err != nil {
		return nil, fmt.Errorf("canokey: HKDF failed: %w", err)
	}
	defer func() {
		for i := range derivedKey {
			derivedKey[i] = 0
		}
	}()

	// Decrypt DEK with AES-256-GCM
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to create GCM: %w", err)
	}

	// Reconstruct full ciphertext with tag
	fullCiphertext := append(ciphertextOnly, tag...)

	// Decrypt and verify
	dek, err := gcm.Open(nil, nonce, fullCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("canokey: GCM decryption failed: %w", err)
	}

	return dek, nil
}

// wrapDEKWithX25519 encrypts a DEK using X25519 key agreement + HKDF + AES-256-GCM.
// The Ed25519 public key is converted to X25519, then used for key agreement.
// The encrypted DEK format is: ephemeralPubKey(32) || nonce(12) || ciphertext || tag(16)
func wrapDEKWithX25519(edPubKey ed25519.PublicKey, dek []byte) ([]byte, error) {
	// Convert Ed25519 public key to X25519
	x25519PubKey, err := ed25519PublicKeyToX25519(edPubKey)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to convert Ed25519 to X25519: %w", err)
	}

	// Generate ephemeral X25519 key pair
	ephemeralPub, ephemeralPriv, err := generateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to generate ephemeral X25519 key: %w", err)
	}
	defer func() {
		for i := range ephemeralPriv {
			ephemeralPriv[i] = 0
		}
	}()

	// Perform X25519 key agreement
	sharedSecret, err := curve25519.X25519(ephemeralPriv, x25519PubKey)
	if err != nil {
		return nil, fmt.Errorf("canokey: X25519 key agreement failed: %w", err)
	}

	// Derive encryption key using HKDF-SHA256
	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte(hkdfInfoX25519))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, derivedKey); err != nil {
		return nil, fmt.Errorf("canokey: HKDF failed: %w", err)
	}
	defer func() {
		for i := range derivedKey {
			derivedKey[i] = 0
		}
	}()

	// Encrypt DEK with AES-256-GCM
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("canokey: failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, dek, nil)

	// Extract tag (last 16 bytes of ciphertext)
	tagSize := gcm.Overhead()
	tag := ciphertext[len(ciphertext)-tagSize:]
	ciphertextOnly := ciphertext[:len(ciphertext)-tagSize]

	// Construct encrypted DEK: ephemeralPub(32) || nonce(12) || ciphertext || tag(16)
	result := make([]byte, 0, 32+12+len(ciphertextOnly)+16)
	result = append(result, ephemeralPub...)
	result = append(result, nonce...)
	result = append(result, ciphertextOnly...)
	result = append(result, tag...)

	return result, nil
}

// unwrapDEKWithX25519 decrypts a DEK using X25519 key agreement + HKDF + AES-256-GCM.
func unwrapDEKWithX25519(decrypter crypto.Decrypter, encryptedDEK []byte) ([]byte, error) {
	// Validate minimum size: ephemeralPub(32) + nonce(12) + ciphertext + tag(16)
	minSize := 32 + 12 + dekSize + 16
	if len(encryptedDEK) < minSize {
		return nil, fmt.Errorf("%w: got %d bytes, expected at least %d", ErrEncryptedDEKTooShort, len(encryptedDEK), minSize)
	}

	// Extract components
	ephemeralPub := encryptedDEK[:32]
	nonce := encryptedDEK[32:44]

	// Remaining is ciphertext + tag
	ciphertextAndTag := encryptedDEK[44:]
	if len(ciphertextAndTag) < 16 {
		return nil, ErrCiphertextTooShort
	}

	tag := ciphertextAndTag[len(ciphertextAndTag)-16:]
	ciphertextOnly := ciphertextAndTag[:len(ciphertextAndTag)-16]

	// Get our Ed25519 private key and convert to X25519
	pubKey := decrypter.Public()
	_, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w, got %T", ErrNotEd25519Key, pubKey)
	}

	// Convert Ed25519 public key to X25519 (we need the private key)
	// For PKCS#11 keys, we can't access the private key directly
	// We need to use the decrypter's Decrypt method with special handling
	// However, crypto.Decrypter is designed for RSA, not key agreement
	// This is a limitation - we need a different interface or workaround

	// For now, we'll attempt to get the private key if the decrypter exposes it
	privKeyProvider, ok := decrypter.(interface{ PrivateKey() crypto.PrivateKey })
	if !ok {
		return nil, ErrDecrypterNoPrivateKey
	}

	edPrivKey, ok := privKeyProvider.PrivateKey().(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w, got %T", ErrNotEd25519Key, privKeyProvider.PrivateKey())
	}

	// Convert Ed25519 private key to X25519
	x25519PrivKey, err := ed25519PrivateKeyToX25519(edPrivKey)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to convert Ed25519 private key to X25519: %w", err)
	}
	defer func() {
		for i := range x25519PrivKey {
			x25519PrivKey[i] = 0
		}
	}()

	// Perform X25519 key agreement
	sharedSecret, err := curve25519.X25519(x25519PrivKey, ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("canokey: X25519 key agreement failed: %w", err)
	}

	// Derive decryption key using HKDF-SHA256
	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte(hkdfInfoX25519))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, derivedKey); err != nil {
		return nil, fmt.Errorf("canokey: HKDF failed: %w", err)
	}
	defer func() {
		for i := range derivedKey {
			derivedKey[i] = 0
		}
	}()

	// Decrypt DEK with AES-256-GCM
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to create GCM: %w", err)
	}

	// Reconstruct full ciphertext with tag
	fullCiphertext := append(ciphertextOnly, tag...)

	// Decrypt and verify
	dek, err := gcm.Open(nil, nonce, fullCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("canokey: GCM decryption failed: %w", err)
	}

	return dek, nil
}

// ed25519PublicKeyToX25519 converts an Ed25519 public key to an X25519 public key.
// This uses the filippo.io/edwards25519 library for the conversion.
func ed25519PublicKeyToX25519(edPub ed25519.PublicKey) ([]byte, error) {
	if len(edPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: got %d, expected %d", ErrInvalidEd25519KeySize, len(edPub), ed25519.PublicKeySize)
	}

	// Parse Ed25519 public key
	var edPoint edwards25519.Point
	if _, err := edPoint.SetBytes(edPub); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidEd25519PublicKey, err)
	}

	// Convert to X25519 using the montgomery curve isomorphism
	// This is the standard conversion defined in RFC 7748
	x25519Pub := edPoint.BytesMontgomery()

	return x25519Pub, nil
}

// ed25519PrivateKeyToX25519 converts an Ed25519 private key to an X25519 private key.
func ed25519PrivateKeyToX25519(edPriv ed25519.PrivateKey) ([]byte, error) {
	if len(edPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: got %d, expected %d", ErrInvalidEd25519KeySize, len(edPriv), ed25519.PrivateKeySize)
	}

	// Ed25519 private key format is 64 bytes: 32-byte seed || 32-byte public key
	// The X25519 private key is derived from the seed using SHA512 per RFC 8032
	seed := edPriv[:32]

	// Hash the seed with SHA512 and use the first 32 bytes (per RFC 8032)
	h := sha512.Sum512(seed)
	x25519Priv := make([]byte, curve25519.ScalarSize)
	copy(x25519Priv, h[:32])

	// Clamp the scalar (RFC 7748)
	x25519Priv[0] &= 248
	x25519Priv[31] &= 127
	x25519Priv[31] |= 64

	return x25519Priv, nil
}

// generateX25519KeyPair generates a new X25519 key pair.
func generateX25519KeyPair() (publicKey, privateKey []byte, err error) {
	privateKey = make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, fmt.Errorf("canokey: failed to generate random scalar: %w", err)
	}

	// Clamp the scalar (RFC 7748)
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// Compute public key
	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("canokey: failed to compute public key: %w", err)
	}

	return publicKey, privateKey, nil
}

// GenerateSymmetricKey generates a new symmetric key using envelope encryption.
// The symmetric key is bound to a key in the specified PIV slot (wrapping key).
// The actual DEKs are generated during each encryption operation.
func (b *Backend) GenerateSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.initialized {
		return nil, ErrNotInitialized
	}

	if err := attrs.Validate(); err != nil {
		return nil, fmt.Errorf("canokey: invalid attributes: %w", err)
	}

	if !attrs.IsSymmetric() {
		return nil, fmt.Errorf("%w: attributes specify asymmetric algorithm %s", backend.ErrInvalidAlgorithm, attrs.KeyAlgorithm)
	}

	// Validate that wrapping key attributes are provided
	if attrs.WrapAttributes == nil {
		return nil, fmt.Errorf("%w (must reference PIV slot key)", ErrWrapAttributesRequired)
	}

	// Verify wrapping key exists
	wrapKey, err := b.pkcs11.GetKey(attrs.WrapAttributes)
	if err != nil {
		return nil, fmt.Errorf("canokey: wrapping key not found: %w", err)
	}

	// Verify it's a supported key type (RSA, ECDSA, or Ed25519)
	pubKey := wrapKey.(crypto.Signer).Public()
	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		// RSA is always supported
	case *ecdsa.PublicKey:
		// Validate curve
		curveName := pub.Curve.Params().Name
		if curveName != "P-256" && curveName != "P-384" {
			return nil, fmt.Errorf("%w: %s (must be P-256 or P-384)", ErrUnsupportedCurve, curveName)
		}
	case ed25519.PublicKey:
		// Check firmware version
		if !b.SupportsX25519() {
			return nil, fmt.Errorf("%w: Ed25519 wrapping keys require firmware 3.0.0+, have %d.%d.%d", ErrFirmwareRequired, b.firmwareVer.Major, b.firmwareVer.Minor, b.firmwareVer.Patch)
		}
	default:
		return nil, fmt.Errorf("%w: wrapping key must be RSA, ECDSA, or Ed25519, got %T", backend.ErrInvalidAlgorithm, pubKey)
	}

	// Get key size from attributes
	keySize := attrs.AESAttributes.KeySize
	if keySize != 128 && keySize != 192 && keySize != 256 {
		return nil, fmt.Errorf("%w: %d bits (only 128, 192, and 256 are supported)", ErrInvalidAESKeySize, keySize)
	}

	return &canokeySymmetricKey{
		algorithm:        string(attrs.SymmetricAlgorithm),
		keySize:          keySize,
		wrappingKeyAttrs: attrs.WrapAttributes,
		backend:          b,
	}, nil
}

// GetSymmetricKey retrieves an existing symmetric key configuration.
// This validates that the wrapping key exists and returns the key configuration.
func (b *Backend) GetSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if !b.initialized {
		return nil, ErrNotInitialized
	}

	if err := attrs.Validate(); err != nil {
		return nil, fmt.Errorf("canokey: invalid attributes: %w", err)
	}

	if !attrs.IsSymmetric() {
		return nil, fmt.Errorf("%w: attributes specify asymmetric algorithm %s", backend.ErrInvalidAlgorithm, attrs.KeyAlgorithm)
	}

	// Validate that wrapping key attributes are provided
	if attrs.WrapAttributes == nil {
		return nil, ErrWrapAttributesRequired
	}

	// Verify wrapping key exists
	_, err := b.pkcs11.GetKey(attrs.WrapAttributes)
	if err != nil {
		return nil, fmt.Errorf("canokey: wrapping key not found: %w", err)
	}

	keySize := attrs.AESAttributes.KeySize
	if keySize == 0 {
		// Try to infer from algorithm
		switch attrs.SymmetricAlgorithm {
		case types.SymmetricAES128GCM:
			keySize = 128
		case types.SymmetricAES192GCM:
			keySize = 192
		case types.SymmetricAES256GCM:
			keySize = 256
		default:
			return nil, fmt.Errorf("%w: cannot determine key size for algorithm %s", backend.ErrInvalidAlgorithm, attrs.SymmetricAlgorithm)
		}
	}

	return &canokeySymmetricKey{
		algorithm:        string(attrs.SymmetricAlgorithm),
		keySize:          keySize,
		wrappingKeyAttrs: attrs.WrapAttributes,
		backend:          b,
	}, nil
}

// SymmetricEncrypter returns a SymmetricEncrypter for the specified key.
// This allows encryption/decryption operations using envelope encryption.
func (b *Backend) SymmetricEncrypter(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	// Get the symmetric key to ensure it exists and validate configuration
	key, err := b.GetSymmetricKey(attrs)
	if err != nil {
		return nil, err
	}

	// Type assert to get the CanoKey-specific key
	canokeyKey, ok := key.(*canokeySymmetricKey)
	if !ok {
		return nil, fmt.Errorf("canokey: unexpected key type: %T", key)
	}

	return &canokeySymmetricEncrypter{
		backend:          b,
		attrs:            attrs,
		wrappingKeyAttrs: canokeyKey.wrappingKeyAttrs,
	}, nil
}
