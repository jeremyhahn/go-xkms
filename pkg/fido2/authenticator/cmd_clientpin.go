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
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

// CTAP2 ClientPIN request parameter keys (CBOR map indices).
const (
	clientPINKeyPinUvAuthProtocol = 0x01
	clientPINKeySubCommand        = 0x02
	clientPINKeyKeyAgreement      = 0x03
	clientPINKeyPinUvAuthParam    = 0x04
	clientPINKeyNewPinEnc         = 0x05
	clientPINKeyPinHashEnc        = 0x06
	clientPINKeyPermissions       = 0x09
	clientPINKeyPermissionsRPID   = 0x0A
)

// CTAP2 ClientPIN response parameter keys (CBOR map indices).
const (
	clientPINResponseKeyKeyAgreement    = 0x01
	clientPINResponseKeyPinUvAuthToken  = 0x02
	clientPINResponseKeyPinRetries      = 0x03
	clientPINResponseKeyPowerCycleState = 0x04
	clientPINResponseKeyUvRetries       = 0x05
)

// ClientPIN subcommand codes as defined in CTAP2 specification.
const (
	ClientPINSubCmdGetRetries                               = 0x01
	ClientPINSubCmdGetKeyAgreement                          = 0x02
	ClientPINSubCmdSetPIN                                   = 0x03
	ClientPINSubCmdChangePIN                                = 0x04
	ClientPINSubCmdGetPINToken                              = 0x05
	ClientPINSubCmdGetPinUvAuthTokenUsingUvWithPermissions  = 0x06
	ClientPINSubCmdGetUvRetries                             = 0x07
	ClientPINSubCmdGetPinUvAuthTokenUsingPinWithPermissions = 0x09
)

// PIN/UV auth token permission flags (CTAP2.1).
const (
	PINPermissionMakeCredential   = 0x01
	PINPermissionGetAssertion     = 0x02
	PINPermissionCredentialMgmt   = 0x04
	PINPermissionBioEnrollment    = 0x08
	PINPermissionLargeBlobWrite   = 0x10
	PINPermissionAuthenticatorCfg = 0x20
)

// PIN protocol constants.
const (
	PINProtocol1          = 1
	PINMinLength          = 4
	PINHashSize           = 16
	PINTokenSize          = 32
	AESBlockSize          = 16
	EncryptedPINMinLength = 64
)

// ClientPIN errors.
var (
	// ErrPINNotSet indicates a PIN is required but has not been configured.
	ErrPINNotSet = errors.New("authenticator: PIN not set")

	// ErrInvalidSubcommand indicates an invalid or unsupported ClientPIN subcommand.
	ErrInvalidSubcommand = errors.New("authenticator: invalid subcommand")

	// ErrMissingKeyAgreement indicates the platform key agreement is missing.
	ErrMissingKeyAgreement = errors.New("authenticator: missing key agreement")

	// ErrKeyAgreementFailed indicates ECDH key agreement failed.
	ErrKeyAgreementFailed = errors.New("authenticator: key agreement failed")

	// ErrDecryptionFailed indicates PIN decryption failed.
	ErrDecryptionFailed = errors.New("authenticator: decryption failed")

	// ErrUnsupportedPINProtocol indicates the PIN protocol is not supported.
	ErrUnsupportedPINProtocol = errors.New("authenticator: unsupported PIN protocol")
)

// ClientPINRequest represents a CTAP2 authenticatorClientPIN request.
type ClientPINRequest struct {
	// PinUvAuthProtocol specifies the PIN/UV protocol version (1 or 2).
	PinUvAuthProtocol uint8

	// SubCommand specifies the ClientPIN subcommand to execute.
	SubCommand uint8

	// KeyAgreement is the platform's COSE public key for ECDH key agreement.
	KeyAgreement []byte

	// PinUvAuthParam is the authentication parameter for PIN operations.
	PinUvAuthParam []byte

	// NewPinEnc is the encrypted new PIN for SetPIN/ChangePIN operations.
	NewPinEnc []byte

	// PinHashEnc is the encrypted PIN hash for ChangePIN/GetPINToken operations.
	PinHashEnc []byte

	// Permissions specifies the requested PIN/UV auth token permissions.
	Permissions uint8

	// RPID is the relying party ID for permission scoping.
	RPID string
}

// ClientPINResponse represents a CTAP2 authenticatorClientPIN response.
type ClientPINResponse struct {
	// KeyAgreement is the authenticator's COSE public key for ECDH key agreement.
	KeyAgreement []byte

	// PinUvAuthToken is the encrypted PIN/UV auth token.
	PinUvAuthToken []byte

	// PinRetries is the number of remaining PIN attempts.
	PinRetries uint8

	// PowerCycleState indicates if a power cycle is needed before PIN retry.
	PowerCycleState bool

	// UvRetries is the number of remaining user verification attempts.
	UvRetries uint8
}

// pinProtocolState holds the state for PIN protocol operations.
type pinProtocolState struct {
	// privateKey is the authenticator's ECDH private key.
	privateKey *ecdh.PrivateKey

	// publicKeyCOSE is the COSE-encoded authenticator public key.
	publicKeyCOSE []byte

	// sharedSecret is the derived shared secret from ECDH.
	sharedSecret []byte

	// pinUvAuthToken is the current PIN/UV auth token.
	pinUvAuthToken []byte

	// tokenPermissions holds the permissions granted to the current token.
	tokenPermissions uint8

	// tokenRPID is the RP ID the token is scoped to (empty for unscoped).
	tokenRPID string
}

// authenticatorPINState holds PIN-related state within the authenticator.
// This is embedded in Authenticator and protected by the same mutex.
type authenticatorPINState struct {
	protocol *pinProtocolState
}

// handleClientPIN implements the CTAP2 authenticatorClientPIN command (0x06).
// It dispatches to the appropriate subcommand handler based on the request.
func (a *Authenticator) handleClientPIN(data []byte) ([]byte, error) {
	if !a.config.EnablePIN {
		return nil, ErrNotImplemented
	}

	req, err := decodeClientPINRequest(data)
	if err != nil {
		return nil, err
	}

	// Validate PIN protocol version (only protocol 1 supported).
	if req.SubCommand != ClientPINSubCmdGetRetries && req.SubCommand != ClientPINSubCmdGetKeyAgreement &&
		req.SubCommand != ClientPINSubCmdGetUvRetries {
		if req.PinUvAuthProtocol != PINProtocol1 {
			return nil, ErrUnsupportedPINProtocol
		}
	}

	switch req.SubCommand {
	case ClientPINSubCmdGetRetries:
		return a.handleGetRetries()

	case ClientPINSubCmdGetKeyAgreement:
		return a.handleGetKeyAgreement()

	case ClientPINSubCmdSetPIN:
		return a.handleSetPIN(req)

	case ClientPINSubCmdChangePIN:
		return a.handleChangePIN(req)

	case ClientPINSubCmdGetPINToken:
		return a.handleGetPINToken(req)

	case ClientPINSubCmdGetPinUvAuthTokenUsingPinWithPermissions:
		return a.handleGetPinUvAuthTokenUsingPinWithPermissions(req)

	case ClientPINSubCmdGetUvRetries:
		return a.handleGetUvRetries()

	default:
		return nil, ErrInvalidSubcommand
	}
}

// handleGetRetries returns the current PIN retry count.
func (a *Authenticator) handleGetRetries() ([]byte, error) {
	a.mu.RLock()
	retries := a.state.PINRetries()
	a.mu.RUnlock()

	response := map[int]interface{}{
		clientPINResponseKeyPinRetries: uint8(retries),
	}

	data, err := encodeCBOR(response)
	if err != nil {
		return nil, err
	}

	return a.successResponse(data), nil
}

// handleGetUvRetries returns the current user verification retry count.
func (a *Authenticator) handleGetUvRetries() ([]byte, error) {
	a.mu.RLock()
	retries := a.state.UVRetries()
	a.mu.RUnlock()

	response := map[int]interface{}{
		clientPINResponseKeyUvRetries: uint8(retries),
	}

	data, err := encodeCBOR(response)
	if err != nil {
		return nil, err
	}

	return a.successResponse(data), nil
}

// handleGetKeyAgreement returns the authenticator's public key for ECDH.
func (a *Authenticator) handleGetKeyAgreement() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Initialize PIN protocol state if needed.
	if err := a.initPINProtocol(); err != nil {
		return nil, err
	}

	response := map[int]interface{}{
		clientPINResponseKeyKeyAgreement: a.pinState.protocol.publicKeyCOSE,
	}

	data, err := encodeCBOR(response)
	if err != nil {
		return nil, err
	}

	return a.successResponse(data), nil
}

// handleSetPIN sets a new PIN on the authenticator.
func (a *Authenticator) handleSetPIN(req *ClientPINRequest) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if PIN is already set.
	if a.state.PINSet {
		return nil, ErrPINInvalid
	}

	// Initialize PIN protocol if needed.
	if err := a.initPINProtocol(); err != nil {
		return nil, err
	}

	// Verify platform key agreement is provided.
	if len(req.KeyAgreement) == 0 {
		return nil, ErrMissingKeyAgreement
	}

	// Derive shared secret.
	sharedSecret, err := a.deriveSharedSecret(req.KeyAgreement)
	if err != nil {
		return nil, err
	}
	a.pinState.protocol.sharedSecret = sharedSecret

	// Verify pinUvAuthParam.
	if len(req.PinUvAuthParam) == 0 || len(req.NewPinEnc) == 0 {
		return nil, ErrInvalidParameter
	}

	// Verify the authentication parameter.
	if !a.verifyPinAuth(sharedSecret, req.NewPinEnc, req.PinUvAuthParam) {
		return nil, ErrPINAuthInvalid
	}

	// Decrypt the new PIN.
	newPIN, err := a.decryptPIN(sharedSecret, req.NewPinEnc)
	if err != nil {
		return nil, err
	}

	// Validate PIN length.
	if len(newPIN) < a.config.PINMinLength {
		return nil, ErrPINPolicyViolation
	}

	// Hash and store the PIN (SHA-256, left 16 bytes).
	pinHash := sha256.Sum256(newPIN)
	a.state.PINHash = pinHash[:PINHashSize]
	a.state.PINSet = true
	a.state.SetPINRetries(a.config.PINMaxRetries)

	// Save state.
	if err := a.storage.SaveState(a.state); err != nil {
		return nil, ErrStorageError
	}

	return a.successResponse(nil), nil
}

// handleChangePIN changes an existing PIN.
func (a *Authenticator) handleChangePIN(req *ClientPINRequest) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if PIN is set.
	if !a.state.PINSet {
		return nil, ErrPINNotSet
	}

	// Check if PIN is blocked.
	if a.state.PINRetries() <= 0 {
		return nil, ErrPINBlocked
	}

	// Initialize PIN protocol if needed.
	if err := a.initPINProtocol(); err != nil {
		return nil, err
	}

	// Verify platform key agreement is provided.
	if len(req.KeyAgreement) == 0 {
		return nil, ErrMissingKeyAgreement
	}

	// Derive shared secret.
	sharedSecret, err := a.deriveSharedSecret(req.KeyAgreement)
	if err != nil {
		return nil, err
	}
	a.pinState.protocol.sharedSecret = sharedSecret

	// Verify pinUvAuthParam.
	if len(req.PinUvAuthParam) == 0 || len(req.NewPinEnc) == 0 || len(req.PinHashEnc) == 0 {
		return nil, ErrInvalidParameter
	}

	// Verify the authentication parameter over newPinEnc || pinHashEnc.
	authData := append(req.NewPinEnc, req.PinHashEnc...)
	if !a.verifyPinAuth(sharedSecret, authData, req.PinUvAuthParam) {
		return nil, ErrPINAuthInvalid
	}

	// Decrypt and verify current PIN hash.
	currentPinHash, err := a.decryptBlock(sharedSecret, req.PinHashEnc)
	if err != nil {
		a.state.DecrementPINRetries()
		_ = a.storage.SaveState(a.state)
		if a.state.PINRetries() <= 0 {
			return nil, ErrPINBlocked
		}
		return nil, ErrPINInvalid
	}

	if !hmac.Equal(currentPinHash, a.state.PINHash) {
		a.state.DecrementPINRetries()
		_ = a.storage.SaveState(a.state)
		if a.state.PINRetries() <= 0 {
			return nil, ErrPINBlocked
		}
		return nil, ErrPINInvalid
	}

	// Decrypt the new PIN.
	newPIN, err := a.decryptPIN(sharedSecret, req.NewPinEnc)
	if err != nil {
		return nil, err
	}

	// Validate PIN length.
	if len(newPIN) < a.config.PINMinLength {
		return nil, ErrPINPolicyViolation
	}

	// Hash and store the new PIN.
	pinHash := sha256.Sum256(newPIN)
	a.state.PINHash = pinHash[:PINHashSize]
	a.state.SetPINRetries(a.config.PINMaxRetries)

	// Regenerate PIN protocol keys for security.
	if err := a.regeneratePINProtocolKeys(); err != nil {
		return nil, err
	}

	// Save state.
	if err := a.storage.SaveState(a.state); err != nil {
		return nil, ErrStorageError
	}

	return a.successResponse(nil), nil
}

// handleGetPINToken generates and returns an encrypted PIN token.
func (a *Authenticator) handleGetPINToken(req *ClientPINRequest) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if PIN is set.
	if !a.state.PINSet {
		return nil, ErrPINNotSet
	}

	// Check if PIN is blocked.
	if a.state.PINRetries() <= 0 {
		return nil, ErrPINBlocked
	}

	// Initialize PIN protocol if needed.
	if err := a.initPINProtocol(); err != nil {
		return nil, err
	}

	// Verify platform key agreement is provided.
	if len(req.KeyAgreement) == 0 {
		return nil, ErrMissingKeyAgreement
	}

	// Derive shared secret.
	sharedSecret, err := a.deriveSharedSecret(req.KeyAgreement)
	if err != nil {
		return nil, err
	}
	a.pinState.protocol.sharedSecret = sharedSecret

	// Verify pinHashEnc is provided.
	if len(req.PinHashEnc) == 0 {
		return nil, ErrInvalidParameter
	}

	// Decrypt and verify current PIN hash.
	currentPinHash, err := a.decryptBlock(sharedSecret, req.PinHashEnc)
	if err != nil {
		a.state.DecrementPINRetries()
		_ = a.storage.SaveState(a.state)
		if a.state.PINRetries() <= 0 {
			return nil, ErrPINBlocked
		}
		return nil, ErrPINInvalid
	}

	if !hmac.Equal(currentPinHash, a.state.PINHash) {
		a.state.DecrementPINRetries()
		_ = a.storage.SaveState(a.state)
		if a.state.PINRetries() <= 0 {
			return nil, ErrPINBlocked
		}
		return nil, ErrPINInvalid
	}

	// Reset retry counter on successful PIN verification.
	a.state.SetPINRetries(a.config.PINMaxRetries)

	// Generate a new PIN token.
	pinToken := make([]byte, PINTokenSize)
	if _, err := rand.Read(pinToken); err != nil {
		return nil, ErrCryptoError
	}
	a.pinState.protocol.pinUvAuthToken = pinToken

	// Encrypt the PIN token.
	encryptedToken, err := a.encryptData(sharedSecret, pinToken)
	if err != nil {
		return nil, err
	}

	// Save state.
	if err := a.storage.SaveState(a.state); err != nil {
		return nil, ErrStorageError
	}

	response := map[int]interface{}{
		clientPINResponseKeyPinUvAuthToken: encryptedToken,
	}

	data, err := encodeCBOR(response)
	if err != nil {
		return nil, err
	}

	return a.successResponse(data), nil
}

// handleGetPinUvAuthTokenUsingPinWithPermissions generates a PIN token with permissions.
func (a *Authenticator) handleGetPinUvAuthTokenUsingPinWithPermissions(req *ClientPINRequest) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if PIN is set.
	if !a.state.PINSet {
		return nil, ErrPINNotSet
	}

	// Check if PIN is blocked.
	if a.state.PINRetries() <= 0 {
		return nil, ErrPINBlocked
	}

	// Validate permissions.
	if req.Permissions == 0 {
		return nil, ErrInvalidParameter
	}

	// Initialize PIN protocol if needed.
	if err := a.initPINProtocol(); err != nil {
		return nil, err
	}

	// Verify platform key agreement is provided.
	if len(req.KeyAgreement) == 0 {
		return nil, ErrMissingKeyAgreement
	}

	// Derive shared secret.
	sharedSecret, err := a.deriveSharedSecret(req.KeyAgreement)
	if err != nil {
		return nil, err
	}
	a.pinState.protocol.sharedSecret = sharedSecret

	// Verify pinHashEnc is provided.
	if len(req.PinHashEnc) == 0 {
		return nil, ErrInvalidParameter
	}

	// Decrypt and verify current PIN hash.
	currentPinHash, err := a.decryptBlock(sharedSecret, req.PinHashEnc)
	if err != nil {
		a.state.DecrementPINRetries()
		_ = a.storage.SaveState(a.state)
		if a.state.PINRetries() <= 0 {
			return nil, ErrPINBlocked
		}
		return nil, ErrPINInvalid
	}

	if !hmac.Equal(currentPinHash, a.state.PINHash) {
		a.state.DecrementPINRetries()
		_ = a.storage.SaveState(a.state)
		if a.state.PINRetries() <= 0 {
			return nil, ErrPINBlocked
		}
		return nil, ErrPINInvalid
	}

	// Reset retry counter on successful PIN verification.
	a.state.SetPINRetries(a.config.PINMaxRetries)

	// Generate a new PIN token with permissions.
	pinToken := make([]byte, PINTokenSize)
	if _, err := rand.Read(pinToken); err != nil {
		return nil, ErrCryptoError
	}
	a.pinState.protocol.pinUvAuthToken = pinToken
	a.pinState.protocol.tokenPermissions = req.Permissions
	a.pinState.protocol.tokenRPID = req.RPID

	// Encrypt the PIN token.
	encryptedToken, err := a.encryptData(sharedSecret, pinToken)
	if err != nil {
		return nil, err
	}

	// Save state.
	if err := a.storage.SaveState(a.state); err != nil {
		return nil, ErrStorageError
	}

	response := map[int]interface{}{
		clientPINResponseKeyPinUvAuthToken: encryptedToken,
	}

	data, err := encodeCBOR(response)
	if err != nil {
		return nil, err
	}

	return a.successResponse(data), nil
}

// initPINProtocol initializes the PIN protocol state with a new ECDH key pair.
func (a *Authenticator) initPINProtocol() error {
	if a.pinState.protocol != nil && a.pinState.protocol.privateKey != nil {
		return nil
	}

	// Generate ECDH key pair using P-256.
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return ErrKeyGenerationFailed
	}

	// Encode public key in COSE format.
	publicKey := privateKey.PublicKey()
	publicKeyBytes := publicKey.Bytes()

	// P-256 uncompressed point format: 04 || X || Y.
	if len(publicKeyBytes) != 65 || publicKeyBytes[0] != 0x04 {
		return ErrKeyGenerationFailed
	}

	xBytes := publicKeyBytes[1:33]
	yBytes := publicKeyBytes[33:65]

	coseKey := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgES256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   xBytes,
		coseKeyLabelY:   yBytes,
	}

	coseKeyBytes, err := cbor.Marshal(coseKey)
	if err != nil {
		return ErrCBOREncodingFailed
	}

	a.pinState.protocol = &pinProtocolState{
		privateKey:    privateKey,
		publicKeyCOSE: coseKeyBytes,
	}

	return nil
}

// regeneratePINProtocolKeys regenerates the ECDH key pair for enhanced security.
func (a *Authenticator) regeneratePINProtocolKeys() error {
	a.pinState.protocol = nil
	return a.initPINProtocol()
}

// deriveSharedSecret derives the shared secret using ECDH with the platform's public key.
func (a *Authenticator) deriveSharedSecret(platformKeyAgreement []byte) ([]byte, error) {
	if a.pinState.protocol == nil || a.pinState.protocol.privateKey == nil {
		return nil, ErrMissingKeyAgreement
	}

	// Decode platform's COSE public key.
	var coseKey map[int]interface{}
	if err := cbor.Unmarshal(platformKeyAgreement, &coseKey); err != nil {
		return nil, ErrInvalidParameter
	}

	// Extract X and Y coordinates.
	xRaw, ok := coseKey[coseKeyLabelX]
	if !ok {
		return nil, ErrInvalidParameter
	}
	xBytes, ok := xRaw.([]byte)
	if !ok {
		return nil, ErrInvalidParameter
	}

	yRaw, ok := coseKey[coseKeyLabelY]
	if !ok {
		return nil, ErrInvalidParameter
	}
	yBytes, ok := yRaw.([]byte)
	if !ok {
		return nil, ErrInvalidParameter
	}

	// Reconstruct uncompressed point format: 04 || X || Y.
	platformPublicKeyBytes := make([]byte, 65)
	platformPublicKeyBytes[0] = 0x04
	copy(platformPublicKeyBytes[1:33], padCoordinate(xBytes, 32))
	copy(platformPublicKeyBytes[33:65], padCoordinate(yBytes, 32))

	// Parse as ECDH public key.
	platformPublicKey, err := ecdh.P256().NewPublicKey(platformPublicKeyBytes)
	if err != nil {
		return nil, ErrKeyAgreementFailed
	}

	// Perform ECDH.
	sharedSecret, err := a.pinState.protocol.privateKey.ECDH(platformPublicKey)
	if err != nil {
		return nil, ErrKeyAgreementFailed
	}

	// Derive the actual shared secret using SHA-256.
	hash := sha256.Sum256(sharedSecret)
	return hash[:], nil
}

// verifyPinAuth verifies the pinUvAuthParam using HMAC-SHA-256.
func (a *Authenticator) verifyPinAuth(sharedSecret, data, authParam []byte) bool {
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(data)
	expected := mac.Sum(nil)[:16]
	return hmac.Equal(expected, authParam)
}

// decryptPIN decrypts an encrypted PIN using AES-256-CBC.
func (a *Authenticator) decryptPIN(sharedSecret, encryptedPIN []byte) ([]byte, error) {
	if len(encryptedPIN) < EncryptedPINMinLength {
		return nil, ErrDecryptionFailed
	}

	// AES-256-CBC decryption with zero IV.
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	iv := make([]byte, AESBlockSize)
	mode := cipher.NewCBCDecrypter(block, iv)

	decrypted := make([]byte, len(encryptedPIN))
	mode.CryptBlocks(decrypted, encryptedPIN)

	// Remove padding (null-terminated PIN).
	pinLen := 0
	for i, b := range decrypted {
		if b == 0 {
			pinLen = i
			break
		}
	}
	if pinLen == 0 {
		// No null terminator found, use entire decrypted data.
		pinLen = len(decrypted)
	}

	return decrypted[:pinLen], nil
}

// decryptBlock decrypts a single AES block using AES-256-CBC.
func (a *Authenticator) decryptBlock(sharedSecret, encrypted []byte) ([]byte, error) {
	if len(encrypted) != PINHashSize {
		return nil, ErrDecryptionFailed
	}

	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	iv := make([]byte, AESBlockSize)
	mode := cipher.NewCBCDecrypter(block, iv)

	decrypted := make([]byte, len(encrypted))
	mode.CryptBlocks(decrypted, encrypted)

	return decrypted, nil
}

// encryptData encrypts data using AES-256-CBC.
func (a *Authenticator) encryptData(sharedSecret, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, ErrCryptoError
	}

	// Pad plaintext to AES block size.
	padding := AESBlockSize - (len(plaintext) % AESBlockSize)
	if padding == 0 {
		padding = AESBlockSize
	}
	paddedPlaintext := make([]byte, len(plaintext)+padding)
	copy(paddedPlaintext, plaintext)

	iv := make([]byte, AESBlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)

	ciphertext := make([]byte, len(paddedPlaintext))
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	return ciphertext, nil
}

// decodeClientPINRequest decodes a CBOR-encoded ClientPIN request.
func decodeClientPINRequest(data []byte) (*ClientPINRequest, error) {
	if len(data) == 0 {
		return nil, ErrInvalidParameter
	}

	var rawMap map[int]interface{}
	if err := cbor.Unmarshal(data, &rawMap); err != nil {
		return nil, ErrCBORDecodingFailed
	}

	req := &ClientPINRequest{}

	// Parse pinUvAuthProtocol (0x01).
	if val, ok := rawMap[clientPINKeyPinUvAuthProtocol]; ok {
		if protocol, err := clientPINToUint8(val); err == nil {
			req.PinUvAuthProtocol = protocol
		}
	}

	// Parse subCommand (0x02, required).
	if val, ok := rawMap[clientPINKeySubCommand]; ok {
		if subCmd, err := clientPINToUint8(val); err == nil {
			req.SubCommand = subCmd
		} else {
			return nil, ErrInvalidParameter
		}
	} else {
		return nil, ErrInvalidParameter
	}

	// Parse keyAgreement (0x03).
	if val, ok := rawMap[clientPINKeyKeyAgreement]; ok {
		// keyAgreement is a COSE key, which arrives as a map.
		keyBytes, err := cbor.Marshal(val)
		if err != nil {
			return nil, ErrInvalidParameter
		}
		req.KeyAgreement = keyBytes
	}

	// Parse pinUvAuthParam (0x04).
	if val, ok := rawMap[clientPINKeyPinUvAuthParam]; ok {
		if param, ok := val.([]byte); ok {
			req.PinUvAuthParam = param
		}
	}

	// Parse newPinEnc (0x05).
	if val, ok := rawMap[clientPINKeyNewPinEnc]; ok {
		if newPin, ok := val.([]byte); ok {
			req.NewPinEnc = newPin
		}
	}

	// Parse pinHashEnc (0x06).
	if val, ok := rawMap[clientPINKeyPinHashEnc]; ok {
		if pinHash, ok := val.([]byte); ok {
			req.PinHashEnc = pinHash
		}
	}

	// Parse permissions (0x09).
	if val, ok := rawMap[clientPINKeyPermissions]; ok {
		if perms, err := clientPINToUint8(val); err == nil {
			req.Permissions = perms
		}
	}

	// Parse permissionsRPID (0x0A).
	if val, ok := rawMap[clientPINKeyPermissionsRPID]; ok {
		if rpID, ok := val.(string); ok {
			req.RPID = rpID
		}
	}

	return req, nil
}

// clientPINToUint8 converts various integer types to uint8.
func clientPINToUint8(v interface{}) (uint8, error) {
	switch n := v.(type) {
	case int:
		return uint8(n), nil
	case int8:
		return uint8(n), nil
	case int16:
		return uint8(n), nil
	case int32:
		return uint8(n), nil
	case int64:
		return uint8(n), nil
	case uint:
		return uint8(n), nil
	case uint8:
		return n, nil
	case uint16:
		return uint8(n), nil
	case uint32:
		return uint8(n), nil
	case uint64:
		return uint8(n), nil
	default:
		return 0, ErrInvalidParameter
	}
}

// GetPinUvAuthToken returns the current PIN/UV auth token for testing purposes.
func (a *Authenticator) GetPinUvAuthToken() []byte {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.pinState.protocol == nil {
		return nil
	}
	return a.pinState.protocol.pinUvAuthToken
}

// VerifyPinUvAuthToken verifies a PIN/UV auth token against stored token.
func (a *Authenticator) VerifyPinUvAuthToken(clientDataHash, authParam []byte) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.pinState.protocol == nil || a.pinState.protocol.pinUvAuthToken == nil {
		return false
	}

	mac := hmac.New(sha256.New, a.pinState.protocol.pinUvAuthToken)
	mac.Write(clientDataHash)
	expected := mac.Sum(nil)[:16]
	return hmac.Equal(expected, authParam)
}

// SetPINForTesting sets the PIN directly for testing purposes.
func (a *Authenticator) SetPINForTesting(pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(pin) < a.config.PINMinLength {
		return ErrPINPolicyViolation
	}

	pinHash := sha256.Sum256([]byte(pin))
	a.state.PINHash = pinHash[:PINHashSize]
	a.state.PINSet = true
	a.state.SetPINRetries(a.config.PINMaxRetries)

	return a.storage.SaveState(a.state)
}

// generatePlatformKeyAgreement generates a platform ECDH key pair and returns
// the COSE public key and the derived shared secret with the authenticator.
func (a *Authenticator) generatePlatformKeyAgreement() (platformCOSE []byte, sharedSecret []byte, err error) {
	// Generate platform ECDH key pair.
	platformPrivKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Encode platform public key as COSE.
	pubBytes := platformPrivKey.PublicKey().Bytes()
	xBytes := pubBytes[1:33]
	yBytes := pubBytes[33:65]

	coseKey := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgES256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   xBytes,
		coseKeyLabelY:   yBytes,
	}

	platformCOSE, err = cbor.Marshal(coseKey)
	if err != nil {
		return nil, nil, err
	}

	// Get authenticator's public key for ECDH.
	if a.pinState.protocol == nil {
		return nil, nil, ErrMissingKeyAgreement
	}

	var authCOSE map[int]interface{}
	if err := cbor.Unmarshal(a.pinState.protocol.publicKeyCOSE, &authCOSE); err != nil {
		return nil, nil, err
	}

	authXBytes := authCOSE[coseKeyLabelX].([]byte)
	authYBytes := authCOSE[coseKeyLabelY].([]byte)

	authPubBytes := make([]byte, 65)
	authPubBytes[0] = 0x04
	copy(authPubBytes[1:33], padCoordinate(authXBytes, 32))
	copy(authPubBytes[33:65], padCoordinate(authYBytes, 32))

	authPubKey, err := ecdh.P256().NewPublicKey(authPubBytes)
	if err != nil {
		return nil, nil, err
	}

	// Derive shared secret.
	rawSecret, err := platformPrivKey.ECDH(authPubKey)
	if err != nil {
		return nil, nil, err
	}

	hash := sha256.Sum256(rawSecret)
	return platformCOSE, hash[:], nil
}

// encryptNewPIN encrypts a new PIN using the shared secret.
// This simulates what a client would send for SetPIN/ChangePIN.
func encryptNewPIN(sharedSecret []byte, pin string) ([]byte, []byte, error) {
	// Pad PIN to 64 bytes.
	paddedPIN := make([]byte, EncryptedPINMinLength)
	copy(paddedPIN, []byte(pin))

	// Encrypt with AES-256-CBC, zero IV.
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, nil, err
	}

	iv := make([]byte, AESBlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)

	encryptedPIN := make([]byte, len(paddedPIN))
	mode.CryptBlocks(encryptedPIN, paddedPIN)

	// Generate pinUvAuthParam: HMAC-SHA-256(sharedSecret, newPinEnc)[:16].
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(encryptedPIN)
	authParam := mac.Sum(nil)[:16]

	return encryptedPIN, authParam, nil
}

// encryptPINHash encrypts a PIN hash using the shared secret.
// This simulates what a client would send for ChangePIN/GetPINToken.
func encryptPINHash(sharedSecret []byte, pin string) ([]byte, error) {
	pinHash := sha256.Sum256([]byte(pin))

	// Encrypt first 16 bytes of PIN hash with AES-256-CBC, zero IV.
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, AESBlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)

	encrypted := make([]byte, PINHashSize)
	mode.CryptBlocks(encrypted, pinHash[:PINHashSize])

	return encrypted, nil
}

// Helper to convert ECDSA public key to COSE format for test helpers.
func ecdsaPublicKeyToCOSE(pub *ecdsa.PublicKey, algorithm int) ([]byte, error) {
	curve := COSECurveP256
	coordSize := 32

	switch pub.Curve {
	case elliptic.P256():
		curve = COSECurveP256
		coordSize = 32
	case elliptic.P384():
		curve = COSECurveP384
		coordSize = 48
	case elliptic.P521():
		curve = COSECurveP521
		coordSize = 66
	}

	xBytes := padCoordinate(pub.X.Bytes(), coordSize)
	yBytes := padCoordinate(pub.Y.Bytes(), coordSize)

	coseKey := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: algorithm,
		coseKeyLabelCrv: curve,
		coseKeyLabelX:   xBytes,
		coseKeyLabelY:   yBytes,
	}

	return cbor.Marshal(coseKey)
}
