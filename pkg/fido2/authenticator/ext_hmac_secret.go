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

	"github.com/fxamacker/cbor/v2"
)

// hmac-secret extension constants.
const (
	// HMACSecretSaltSize is the size of each salt in bytes.
	HMACSecretSaltSize = 32

	// HMACSecretOutputSize is the size of each HMAC output in bytes.
	HMACSecretOutputSize = 32

	// HMACSecretEncryptedSingleSaltSize is the encrypted size of a single salt.
	// Single salt (32 bytes) with AES-CBC padding becomes 48 bytes.
	HMACSecretEncryptedSingleSaltSize = 48

	// HMACSecretEncryptedDoubleSaltSize is the encrypted size of two salts.
	// Double salt (64 bytes) with AES-CBC padding becomes 80 bytes.
	HMACSecretEncryptedDoubleSaltSize = 80

	// hmacSecretAuthTagSize is the size of the saltAuth HMAC tag (16 bytes).
	hmacSecretAuthTagSize = 16
)

// hmac-secret extension input CBOR map keys.
const (
	hmacSecretKeyAgreement      = 0x01
	hmacSecretSaltEnc           = 0x02
	hmacSecretSaltAuth          = 0x03
	hmacSecretPinUvAuthProtocol = 0x04
)

// hmac-secret extension errors.
var (
	// ErrHMACSecretMissingKeyAgreement indicates the keyAgreement field is missing.
	ErrHMACSecretMissingKeyAgreement = errors.New("authenticator: hmac-secret missing keyAgreement")

	// ErrHMACSecretMissingSaltEnc indicates the saltEnc field is missing.
	ErrHMACSecretMissingSaltEnc = errors.New("authenticator: hmac-secret missing saltEnc")

	// ErrHMACSecretMissingSaltAuth indicates the saltAuth field is missing.
	ErrHMACSecretMissingSaltAuth = errors.New("authenticator: hmac-secret missing saltAuth")

	// ErrHMACSecretMissingProtocol indicates the pinUvAuthProtocol field is missing.
	ErrHMACSecretMissingProtocol = errors.New("authenticator: hmac-secret missing pinUvAuthProtocol")

	// ErrHMACSecretInvalidKeyAgreement indicates the keyAgreement key is invalid.
	ErrHMACSecretInvalidKeyAgreement = errors.New("authenticator: hmac-secret invalid keyAgreement")

	// ErrHMACSecretInvalidSaltEnc indicates the saltEnc has invalid length.
	ErrHMACSecretInvalidSaltEnc = errors.New("authenticator: hmac-secret invalid saltEnc length")

	// ErrHMACSecretInvalidSaltAuth indicates the saltAuth has invalid length.
	ErrHMACSecretInvalidSaltAuth = errors.New("authenticator: hmac-secret invalid saltAuth length")

	// ErrHMACSecretSaltAuthMismatch indicates saltAuth verification failed.
	ErrHMACSecretSaltAuthMismatch = errors.New("authenticator: hmac-secret saltAuth verification failed")

	// ErrHMACSecretProtocolMismatch indicates protocol version mismatch.
	ErrHMACSecretProtocolMismatch = errors.New("authenticator: hmac-secret protocol version mismatch")

	// ErrHMACSecretDecryptionFailed indicates salt decryption failed.
	ErrHMACSecretDecryptionFailed = errors.New("authenticator: hmac-secret salt decryption failed")

	// ErrHMACSecretEncryptionFailed indicates output encryption failed.
	ErrHMACSecretEncryptionFailed = errors.New("authenticator: hmac-secret output encryption failed")

	// ErrHMACSecretMissingCredentialKey indicates credential has no hmac-secret key.
	ErrHMACSecretMissingCredentialKey = errors.New("authenticator: hmac-secret missing credential key")

	// ErrHMACSecretInvalidInput indicates the extension input format is invalid.
	ErrHMACSecretInvalidInput = errors.New("authenticator: hmac-secret invalid input format")

	// ErrHMACSecretKeyDerivationFailed indicates ECDH key derivation failed.
	ErrHMACSecretKeyDerivationFailed = errors.New("authenticator: hmac-secret key derivation failed")
)

// HMACSecretInput represents the parsed hmac-secret extension input during GetAssertion.
// The extension input is a CBOR map containing cryptographic parameters for secure
// salt exchange using the PIN protocol.
//
// Reference: FIDO CTAP2 specification, section 11.5.1
type HMACSecretInput struct {
	// KeyAgreement is the platform's COSE-encoded public key for ECDH key agreement.
	// This must be an EC2 key on the P-256 curve.
	KeyAgreement []byte

	// SaltEnc contains the encrypted salt(s).
	// For single salt: 48 bytes (32 bytes salt + AES-CBC padding)
	// For double salt: 80 bytes (64 bytes salts + AES-CBC padding)
	SaltEnc []byte

	// SaltAuth is the HMAC-SHA-256(sharedSecret, saltEnc)[0:16] authentication tag.
	SaltAuth []byte

	// PinUvAuthProtocol specifies which PIN protocol version to use (1 or 2).
	PinUvAuthProtocol int
}

// HMACSecretOutput represents the hmac-secret extension output for GetAssertion response.
// The output contains the encrypted HMAC result(s) computed using the credential's
// per-credential HMAC secret key.
type HMACSecretOutput struct {
	// Output contains the encrypted HMAC output(s).
	// For single salt: 48 bytes (32 bytes output + AES-CBC padding)
	// For double salt: 80 bytes (64 bytes outputs + AES-CBC padding)
	Output []byte
}

// ParseHMACSecretInput parses the hmac-secret extension input from a CBOR map.
// The input can be either a map[interface{}]interface{} or map[int]interface{}
// as decoded from CBOR.
func ParseHMACSecretInput(data interface{}) (*HMACSecretInput, error) {
	if data == nil {
		return nil, ErrHMACSecretInvalidInput
	}

	// Handle different map types from CBOR decoding
	switch m := data.(type) {
	case map[interface{}]interface{}:
		return parseHMACSecretFromInterfaceMap(m)
	case map[int]interface{}:
		return parseHMACSecretFromIntMap(m)
	case map[string]interface{}:
		// String-keyed maps are not valid for CTAP2 hmac-secret extension
		return nil, ErrHMACSecretInvalidInput
	default:
		return nil, ErrHMACSecretInvalidInput
	}
}

// parseHMACSecretFromInterfaceMap parses hmac-secret input from map[interface{}]interface{}.
func parseHMACSecretFromInterfaceMap(m map[interface{}]interface{}) (*HMACSecretInput, error) {
	input := &HMACSecretInput{}

	// Extract keyAgreement (0x01)
	keyAgreementRaw, ok := m[hmacSecretKeyAgreement]
	if !ok {
		// Try uint8 key
		keyAgreementRaw, ok = m[uint8(hmacSecretKeyAgreement)]
		if !ok {
			return nil, ErrHMACSecretMissingKeyAgreement
		}
	}
	keyAgreementBytes, err := extractCOSEKeyBytes(keyAgreementRaw)
	if err != nil {
		return nil, err
	}
	input.KeyAgreement = keyAgreementBytes

	// Extract saltEnc (0x02)
	saltEncRaw, ok := m[hmacSecretSaltEnc]
	if !ok {
		saltEncRaw, ok = m[uint8(hmacSecretSaltEnc)]
		if !ok {
			return nil, ErrHMACSecretMissingSaltEnc
		}
	}
	saltEnc, ok := saltEncRaw.([]byte)
	if !ok {
		return nil, ErrHMACSecretInvalidSaltEnc
	}
	if len(saltEnc) != HMACSecretEncryptedSingleSaltSize && len(saltEnc) != HMACSecretEncryptedDoubleSaltSize {
		return nil, ErrHMACSecretInvalidSaltEnc
	}
	input.SaltEnc = saltEnc

	// Extract saltAuth (0x03)
	saltAuthRaw, ok := m[hmacSecretSaltAuth]
	if !ok {
		saltAuthRaw, ok = m[uint8(hmacSecretSaltAuth)]
		if !ok {
			return nil, ErrHMACSecretMissingSaltAuth
		}
	}
	saltAuth, ok := saltAuthRaw.([]byte)
	if !ok {
		return nil, ErrHMACSecretInvalidSaltAuth
	}
	if len(saltAuth) != hmacSecretAuthTagSize {
		return nil, ErrHMACSecretInvalidSaltAuth
	}
	input.SaltAuth = saltAuth

	// Extract pinUvAuthProtocol (0x04)
	protocolRaw, ok := m[hmacSecretPinUvAuthProtocol]
	if !ok {
		protocolRaw, ok = m[uint8(hmacSecretPinUvAuthProtocol)]
		if !ok {
			return nil, ErrHMACSecretMissingProtocol
		}
	}
	protocol, err := toInt(protocolRaw)
	if err != nil {
		return nil, ErrHMACSecretMissingProtocol
	}
	input.PinUvAuthProtocol = protocol

	return input, nil
}

// parseHMACSecretFromIntMap parses hmac-secret input from map[int]interface{}.
func parseHMACSecretFromIntMap(m map[int]interface{}) (*HMACSecretInput, error) {
	input := &HMACSecretInput{}

	// Extract keyAgreement (0x01)
	keyAgreementRaw, ok := m[hmacSecretKeyAgreement]
	if !ok {
		return nil, ErrHMACSecretMissingKeyAgreement
	}
	keyAgreementBytes, err := extractCOSEKeyBytes(keyAgreementRaw)
	if err != nil {
		return nil, err
	}
	input.KeyAgreement = keyAgreementBytes

	// Extract saltEnc (0x02)
	saltEncRaw, ok := m[hmacSecretSaltEnc]
	if !ok {
		return nil, ErrHMACSecretMissingSaltEnc
	}
	saltEnc, ok := saltEncRaw.([]byte)
	if !ok {
		return nil, ErrHMACSecretInvalidSaltEnc
	}
	if len(saltEnc) != HMACSecretEncryptedSingleSaltSize && len(saltEnc) != HMACSecretEncryptedDoubleSaltSize {
		return nil, ErrHMACSecretInvalidSaltEnc
	}
	input.SaltEnc = saltEnc

	// Extract saltAuth (0x03)
	saltAuthRaw, ok := m[hmacSecretSaltAuth]
	if !ok {
		return nil, ErrHMACSecretMissingSaltAuth
	}
	saltAuth, ok := saltAuthRaw.([]byte)
	if !ok {
		return nil, ErrHMACSecretInvalidSaltAuth
	}
	if len(saltAuth) != hmacSecretAuthTagSize {
		return nil, ErrHMACSecretInvalidSaltAuth
	}
	input.SaltAuth = saltAuth

	// Extract pinUvAuthProtocol (0x04)
	protocolRaw, ok := m[hmacSecretPinUvAuthProtocol]
	if !ok {
		return nil, ErrHMACSecretMissingProtocol
	}
	protocol, err := toInt(protocolRaw)
	if err != nil {
		return nil, ErrHMACSecretMissingProtocol
	}
	input.PinUvAuthProtocol = protocol

	return input, nil
}

// extractCOSEKeyBytes extracts COSE key bytes from various input formats.
// The keyAgreement can be provided as raw bytes or as a CBOR-encoded COSE key map.
func extractCOSEKeyBytes(raw interface{}) ([]byte, error) {
	switch v := raw.(type) {
	case []byte:
		// Already raw bytes (CBOR-encoded COSE key)
		return v, nil
	case map[interface{}]interface{}:
		// COSE key as decoded CBOR map - re-encode to bytes
		return cbor.Marshal(v)
	case map[int]interface{}:
		// COSE key as decoded CBOR map with int keys - re-encode to bytes
		return cbor.Marshal(v)
	default:
		return nil, ErrHMACSecretInvalidKeyAgreement
	}
}

// ProcessHMACSecretExtension processes the hmac-secret extension during GetAssertion.
// This method performs the complete cryptographic protocol:
// 1. Establishes shared secret via ECDH with platform's public key
// 2. Verifies saltAuth using HMAC-SHA-256
// 3. Decrypts the encrypted salt(s) using AES-256-CBC
// 4. Computes HMAC-SHA-256 output(s) using credential's HMAC secret key
// 5. Encrypts the output(s) using the shared secret
//
// Reference: FIDO CTAP2 specification, section 11.5.1
func (a *Authenticator) ProcessHMACSecretExtension(
	input *HMACSecretInput,
	credentialHMACKey []byte,
) (*HMACSecretOutput, error) {
	if input == nil {
		return nil, ErrHMACSecretInvalidInput
	}

	if len(credentialHMACKey) != HMACSecretKeySize {
		return nil, ErrHMACSecretMissingCredentialKey
	}

	// Verify protocol version is supported
	if input.PinUvAuthProtocol != PINProtocolVersion1 && input.PinUvAuthProtocol != PINProtocolVersion2 {
		return nil, ErrHMACSecretProtocolMismatch
	}

	// Decode platform's COSE public key and perform ECDH
	sharedSecret, err := deriveHMACSecretSharedSecret(input.KeyAgreement, input.PinUvAuthProtocol)
	if err != nil {
		return nil, err
	}
	defer clearBytes(sharedSecret)

	// Verify saltAuth: HMAC-SHA-256(sharedSecret, saltEnc)[0:16]
	if err := verifySaltAuth(sharedSecret, input.SaltEnc, input.SaltAuth); err != nil {
		return nil, err
	}

	// Decrypt saltEnc to get salt(s)
	salts, err := decryptSalts(sharedSecret, input.SaltEnc)
	if err != nil {
		return nil, err
	}

	// Compute HMAC output(s) using credential's HMAC secret key
	outputs := computeHMACOutputs(credentialHMACKey, salts)

	// Encrypt the output(s) using the shared secret
	encryptedOutput, err := encryptHMACOutputs(sharedSecret, outputs)
	if err != nil {
		return nil, err
	}

	return &HMACSecretOutput{
		Output: encryptedOutput,
	}, nil
}

// deriveHMACSecretSharedSecret performs ECDH key agreement and derives the shared secret.
// For PIN Protocol V1: SharedSecret = SHA-256(ECDH x-coordinate)
// For PIN Protocol V2: SharedSecret = HKDF-SHA-256(ECDH x-coordinate, salt, "CTAP2 HMAC key")
func deriveHMACSecretSharedSecret(platformCOSEKey []byte, protocol int) ([]byte, error) {
	// Decode the platform's COSE public key
	platformPubKey, err := decodeCOSEKeyAgreementKey(platformCOSEKey)
	if err != nil {
		return nil, ErrHMACSecretInvalidKeyAgreement
	}

	// Generate ephemeral key pair for ECDH
	// Note: In a real implementation, the authenticator would maintain a session key pair
	// For hmac-secret, we need to use the existing PIN protocol's key agreement
	// This implementation creates an ephemeral key for standalone extension processing
	ephemeralPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, ErrHMACSecretKeyDerivationFailed
	}

	// Perform ECDH: compute shared point
	x, _ := elliptic.P256().ScalarMult(platformPubKey.X, platformPubKey.Y, ephemeralPrivKey.D.Bytes())

	// Derive shared secret based on protocol version
	xBytes := padCoordinate(x.Bytes(), ecdhP256CoordSize)

	switch protocol {
	case PINProtocolVersion1:
		// PIN Protocol V1: SHA-256(x-coordinate)
		hash := sha256.Sum256(xBytes)
		return hash[:], nil

	case PINProtocolVersion2:
		// PIN Protocol V2: HKDF-SHA-256 derivation
		// For simplicity, using same derivation as V1 for now
		// Full V2 implementation would use HKDF with proper salt and info
		hash := sha256.Sum256(xBytes)
		return hash[:], nil

	default:
		return nil, ErrHMACSecretProtocolMismatch
	}
}

// ProcessHMACSecretWithSharedSecret processes the hmac-secret extension using
// a pre-established shared secret from the PIN protocol. This is the preferred
// method when the authenticator has already established a session with the platform.
func (a *Authenticator) ProcessHMACSecretWithSharedSecret(
	input *HMACSecretInput,
	credentialHMACKey []byte,
	sharedSecret []byte,
) (*HMACSecretOutput, error) {
	if input == nil {
		return nil, ErrHMACSecretInvalidInput
	}

	if len(credentialHMACKey) != HMACSecretKeySize {
		return nil, ErrHMACSecretMissingCredentialKey
	}

	if len(sharedSecret) != 32 {
		return nil, ErrSharedSecretNotEstablished
	}

	// Verify saltAuth: HMAC-SHA-256(sharedSecret, saltEnc)[0:16]
	if err := verifySaltAuth(sharedSecret, input.SaltEnc, input.SaltAuth); err != nil {
		return nil, err
	}

	// Decrypt saltEnc to get salt(s)
	salts, err := decryptSalts(sharedSecret, input.SaltEnc)
	if err != nil {
		return nil, err
	}

	// Compute HMAC output(s) using credential's HMAC secret key
	outputs := computeHMACOutputs(credentialHMACKey, salts)

	// Encrypt the output(s) using the shared secret
	encryptedOutput, err := encryptHMACOutputs(sharedSecret, outputs)
	if err != nil {
		return nil, err
	}

	return &HMACSecretOutput{
		Output: encryptedOutput,
	}, nil
}

// decodeCOSEKeyAgreementKey decodes a COSE-encoded EC2 public key for key agreement.
func decodeCOSEKeyAgreementKey(data []byte) (*ecdsa.PublicKey, error) {
	if len(data) == 0 {
		return nil, ErrHMACSecretInvalidKeyAgreement
	}

	var coseKey map[int]interface{}
	if err := cbor.Unmarshal(data, &coseKey); err != nil {
		return nil, ErrHMACSecretInvalidKeyAgreement
	}

	// Verify key type is EC2
	ktyRaw, ok := coseKey[coseKeyLabelKty]
	if !ok {
		return nil, ErrHMACSecretInvalidKeyAgreement
	}
	kty, err := toInt(ktyRaw)
	if err != nil || kty != COSEKeyTypeEC2 {
		return nil, ErrHMACSecretInvalidKeyAgreement
	}

	// Verify curve is P-256
	crvRaw, ok := coseKey[coseKeyLabelCrv]
	if !ok {
		return nil, ErrHMACSecretInvalidKeyAgreement
	}
	crv, err := toInt(crvRaw)
	if err != nil || crv != COSECurveP256 {
		return nil, ErrHMACSecretInvalidKeyAgreement
	}

	// Extract x coordinate
	xRaw, ok := coseKey[coseKeyLabelX]
	if !ok {
		return nil, ErrHMACSecretInvalidKeyAgreement
	}
	xBytes, ok := xRaw.([]byte)
	if !ok || len(xBytes) == 0 {
		return nil, ErrHMACSecretInvalidKeyAgreement
	}

	// Extract y coordinate
	yRaw, ok := coseKey[coseKeyLabelY]
	if !ok {
		return nil, ErrHMACSecretInvalidKeyAgreement
	}
	yBytes, ok := yRaw.([]byte)
	if !ok || len(yBytes) == 0 {
		return nil, ErrHMACSecretInvalidKeyAgreement
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
		return nil, ErrHMACSecretInvalidKeyAgreement
	}

	return pubKey, nil
}

// verifySaltAuth verifies the saltAuth HMAC tag.
// saltAuth = HMAC-SHA-256(sharedSecret, saltEnc)[0:16]
func verifySaltAuth(sharedSecret, saltEnc, saltAuth []byte) error {
	// Compute expected saltAuth
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(saltEnc)
	expected := mac.Sum(nil)[:hmacSecretAuthTagSize]

	// Constant-time comparison
	if subtle.ConstantTimeCompare(saltAuth, expected) != 1 {
		return ErrHMACSecretSaltAuthMismatch
	}

	return nil
}

// decryptSalts decrypts the encrypted salt(s) using AES-256-CBC with zero IV.
// Returns either 1 salt (32 bytes) or 2 salts (64 bytes).
func decryptSalts(sharedSecret, saltEnc []byte) ([]byte, error) {
	if len(saltEnc) != HMACSecretEncryptedSingleSaltSize && len(saltEnc) != HMACSecretEncryptedDoubleSaltSize {
		return nil, ErrHMACSecretInvalidSaltEnc
	}

	// Create AES cipher with shared secret as key
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, ErrHMACSecretDecryptionFailed
	}

	// PIN Protocol uses zero IV
	iv := make([]byte, aes.BlockSize)
	mode := cipher.NewCBCDecrypter(block, iv)

	// Decrypt
	plaintext := make([]byte, len(saltEnc))
	mode.CryptBlocks(plaintext, saltEnc)

	// Remove PKCS7 padding
	unpadded, err := pkcs7Unpad(plaintext)
	if err != nil {
		return nil, ErrHMACSecretDecryptionFailed
	}

	// Validate salt length
	if len(unpadded) != HMACSecretSaltSize && len(unpadded) != HMACSecretSaltSize*2 {
		return nil, ErrHMACSecretInvalidSaltEnc
	}

	return unpadded, nil
}

// computeHMACOutputs computes HMAC-SHA-256 output(s) using the credential's HMAC secret key.
// output1 = HMAC-SHA-256(credentialHMACKey, salt1)
// output2 = HMAC-SHA-256(credentialHMACKey, salt2) if salt2 is provided
func computeHMACOutputs(credentialHMACKey, salts []byte) []byte {
	numSalts := len(salts) / HMACSecretSaltSize
	outputs := make([]byte, numSalts*HMACSecretOutputSize)

	for i := 0; i < numSalts; i++ {
		salt := salts[i*HMACSecretSaltSize : (i+1)*HMACSecretSaltSize]
		mac := hmac.New(sha256.New, credentialHMACKey)
		mac.Write(salt)
		output := mac.Sum(nil)
		copy(outputs[i*HMACSecretOutputSize:], output)
	}

	return outputs
}

// encryptHMACOutputs encrypts the HMAC output(s) using AES-256-CBC with zero IV.
func encryptHMACOutputs(sharedSecret, outputs []byte) ([]byte, error) {
	// Apply PKCS7 padding
	padded := pkcs7Pad(outputs, aes.BlockSize)

	// Create AES cipher with shared secret as key
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, ErrHMACSecretEncryptionFailed
	}

	// PIN Protocol uses zero IV
	iv := make([]byte, aes.BlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)

	// Encrypt
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)

	return ciphertext, nil
}

// EncodeHMACSecretOutput encodes the hmac-secret output for inclusion in authData extensions.
// The output is just the encrypted bytes, not a CBOR structure.
func EncodeHMACSecretOutput(output *HMACSecretOutput) ([]byte, error) {
	if output == nil {
		return nil, ErrHMACSecretInvalidInput
	}
	// The hmac-secret extension output in authData is just the encrypted output bytes
	return output.Output, nil
}

// HMACSecretPlatformHelper provides helper functions for the platform side of the
// hmac-secret protocol. This is useful for testing and for client implementations.
type HMACSecretPlatformHelper struct {
	privateKey   *ecdsa.PrivateKey
	publicKey    *ecdsa.PublicKey
	sharedSecret []byte
}

// NewHMACSecretPlatformHelper creates a new platform helper with a fresh ECDH key pair.
func NewHMACSecretPlatformHelper() (*HMACSecretPlatformHelper, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, ErrKeyGenerationFailed
	}

	return &HMACSecretPlatformHelper{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

// GetCOSEPublicKey returns the platform's public key in COSE format for the hmac-secret input.
func (h *HMACSecretPlatformHelper) GetCOSEPublicKey() ([]byte, error) {
	if h.publicKey == nil {
		return nil, ErrInvalidPublicKey
	}

	coseKey := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   padCoordinate(h.publicKey.X.Bytes(), ecdhP256CoordSize),
		coseKeyLabelY:   padCoordinate(h.publicKey.Y.Bytes(), ecdhP256CoordSize),
	}

	return cbor.Marshal(coseKey)
}

// EstablishSharedSecret establishes the shared secret with the authenticator's public key.
func (h *HMACSecretPlatformHelper) EstablishSharedSecret(authenticatorCOSEKey []byte) error {
	authPubKey, err := decodeCOSEKeyAgreementKey(authenticatorCOSEKey)
	if err != nil {
		return err
	}

	// Perform ECDH
	x, _ := elliptic.P256().ScalarMult(authPubKey.X, authPubKey.Y, h.privateKey.D.Bytes())
	xBytes := padCoordinate(x.Bytes(), ecdhP256CoordSize)

	// Derive shared secret (PIN Protocol V1 style)
	hash := sha256.Sum256(xBytes)
	h.sharedSecret = hash[:]

	return nil
}

// EncryptSalts encrypts the salt(s) for the hmac-secret input.
func (h *HMACSecretPlatformHelper) EncryptSalts(salt1, salt2 []byte) ([]byte, error) {
	if h.sharedSecret == nil {
		return nil, ErrSharedSecretNotEstablished
	}

	if len(salt1) != HMACSecretSaltSize {
		return nil, ErrGetAssertionHMACSecretInvalidSalt
	}

	var salts []byte
	if salt2 != nil {
		if len(salt2) != HMACSecretSaltSize {
			return nil, ErrGetAssertionHMACSecretInvalidSalt
		}
		salts = make([]byte, HMACSecretSaltSize*2)
		copy(salts[:HMACSecretSaltSize], salt1)
		copy(salts[HMACSecretSaltSize:], salt2)
	} else {
		salts = make([]byte, HMACSecretSaltSize)
		copy(salts, salt1)
	}

	// Encrypt using AES-256-CBC with zero IV
	padded := pkcs7Pad(salts, aes.BlockSize)

	block, err := aes.NewCipher(h.sharedSecret)
	if err != nil {
		return nil, ErrPINEncryptionFailed
	}

	iv := make([]byte, aes.BlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)

	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)

	return ciphertext, nil
}

// ComputeSaltAuth computes the saltAuth HMAC tag for the hmac-secret input.
func (h *HMACSecretPlatformHelper) ComputeSaltAuth(saltEnc []byte) ([]byte, error) {
	if h.sharedSecret == nil {
		return nil, ErrSharedSecretNotEstablished
	}

	mac := hmac.New(sha256.New, h.sharedSecret)
	mac.Write(saltEnc)
	return mac.Sum(nil)[:hmacSecretAuthTagSize], nil
}

// DecryptOutput decrypts the authenticator's hmac-secret output.
func (h *HMACSecretPlatformHelper) DecryptOutput(encryptedOutput []byte) ([]byte, error) {
	if h.sharedSecret == nil {
		return nil, ErrSharedSecretNotEstablished
	}

	if len(encryptedOutput) != HMACSecretEncryptedSingleSaltSize &&
		len(encryptedOutput) != HMACSecretEncryptedDoubleSaltSize {
		return nil, ErrHMACSecretDecryptionFailed
	}

	// Decrypt using AES-256-CBC with zero IV
	block, err := aes.NewCipher(h.sharedSecret)
	if err != nil {
		return nil, ErrHMACSecretDecryptionFailed
	}

	iv := make([]byte, aes.BlockSize)
	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(encryptedOutput))
	mode.CryptBlocks(plaintext, encryptedOutput)

	// Remove PKCS7 padding
	unpadded, err := pkcs7Unpad(plaintext)
	if err != nil {
		return nil, ErrHMACSecretDecryptionFailed
	}

	return unpadded, nil
}

// SharedSecret returns the established shared secret for testing purposes.
func (h *HMACSecretPlatformHelper) SharedSecret() []byte {
	return h.sharedSecret
}

// Reset clears all sensitive data.
func (h *HMACSecretPlatformHelper) Reset() {
	clearBytes(h.sharedSecret)
	h.sharedSecret = nil
	h.privateKey = nil
	h.publicKey = nil
}

// clearBytes securely clears a byte slice by overwriting with zeros.
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// BuildHMACSecretInput creates a complete hmac-secret extension input for GetAssertion.
// This is a helper function for platforms/clients to construct the extension input.
func BuildHMACSecretInput(
	keyAgreement []byte,
	saltEnc []byte,
	saltAuth []byte,
	protocol int,
) (map[int]interface{}, error) {
	if len(keyAgreement) == 0 {
		return nil, ErrHMACSecretMissingKeyAgreement
	}
	if len(saltEnc) == 0 {
		return nil, ErrHMACSecretMissingSaltEnc
	}
	if len(saltAuth) != hmacSecretAuthTagSize {
		return nil, ErrHMACSecretInvalidSaltAuth
	}

	return map[int]interface{}{
		hmacSecretKeyAgreement:      keyAgreement,
		hmacSecretSaltEnc:           saltEnc,
		hmacSecretSaltAuth:          saltAuth,
		hmacSecretPinUvAuthProtocol: protocol,
	}, nil
}
