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
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/hkdf"
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
	PINProtocol2          = 2
	PINMinLength          = 4
	PINHashSize           = 16
	PINAuthSizeV1         = 16
	PINAuthSizeV2         = 32
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

	// publicKeyCOSE is the authenticator's ECDH public key as a COSE_Key map.
	// Stored as a map so it can be embedded directly in CBOR responses
	// (Chrome expects a COSE_Key map, not a wrapped byte string).
	publicKeyCOSE map[int]interface{}

	// sharedSecret is the derived shared secret from ECDH.
	sharedSecret []byte

	// pinUvAuthToken is the current PIN/UV auth token.
	pinUvAuthToken []byte

	// tokenPermissions holds the permissions granted to the current token.
	tokenPermissions uint8

	// tokenRPID is the RP ID the token is scoped to (empty for unscoped).
	tokenRPID string

	// activeProtocol tracks which PIN protocol version is in use (1 or 2).
	activeProtocol uint8

	// hmacKey is the HKDF-derived HMAC key for V2 authentication.
	hmacKey []byte

	// aesKey is the HKDF-derived AES key for V2 encryption/decryption.
	aesKey []byte
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
		debugLog("[CLIENTPIN] decode error: %v", err)
		return nil, err
	}
	debugLog("[CLIENTPIN] subCommand=0x%02x, pinUvAuthProtocol=%d, permissions=0x%02x",
		req.SubCommand, req.PinUvAuthProtocol, req.Permissions)
	slog.Info("[CTAP2] ClientPIN command",
		"subCommand", req.SubCommand,
		"protocol", req.PinUvAuthProtocol,
		"permissions", req.Permissions,
	)

	// Validate PIN protocol version (protocols 1 and 2 supported).
	if req.SubCommand != ClientPINSubCmdGetRetries && req.SubCommand != ClientPINSubCmdGetKeyAgreement &&
		req.SubCommand != ClientPINSubCmdGetUvRetries {
		if req.PinUvAuthProtocol != PINProtocol1 && req.PinUvAuthProtocol != PINProtocol2 {
			debugLog("[CLIENTPIN] unsupported protocol version %d", req.PinUvAuthProtocol)
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

	case ClientPINSubCmdGetPinUvAuthTokenUsingUvWithPermissions:
		return a.handleGetPinUvAuthTokenUsingUvWithPermissions(req)

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
	if a.isPINSetLocked() {
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
	sharedSecret, err := a.deriveSharedSecret(req.KeyAgreement, req.PinUvAuthProtocol)
	if err != nil {
		return nil, err
	}
	a.pinState.protocol.sharedSecret = sharedSecret

	// Verify pinUvAuthParam.
	if len(req.PinUvAuthParam) == 0 || len(req.NewPinEnc) == 0 {
		return nil, ErrInvalidParameter
	}

	// Determine auth and encryption keys based on protocol version.
	authKey := sharedSecret
	encKey := sharedSecret
	if req.PinUvAuthProtocol == PINProtocol2 {
		authKey = a.pinState.protocol.hmacKey
		encKey = a.pinState.protocol.aesKey
	}

	// Verify the authentication parameter.
	if !a.verifyPinAuth(authKey, req.PinUvAuthProtocol, req.NewPinEnc, req.PinUvAuthParam) {
		return nil, ErrPINAuthInvalid
	}

	// Decrypt the new PIN.
	newPIN, err := a.decryptPIN(encKey, req.PinUvAuthProtocol, req.NewPinEnc)
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
	if !a.isPINSetLocked() {
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
	sharedSecret, err := a.deriveSharedSecret(req.KeyAgreement, req.PinUvAuthProtocol)
	if err != nil {
		return nil, err
	}
	a.pinState.protocol.sharedSecret = sharedSecret

	// Verify pinUvAuthParam.
	if len(req.PinUvAuthParam) == 0 || len(req.NewPinEnc) == 0 || len(req.PinHashEnc) == 0 {
		return nil, ErrInvalidParameter
	}

	// Determine auth and encryption keys based on protocol version.
	authKey := sharedSecret
	encKey := sharedSecret
	if req.PinUvAuthProtocol == PINProtocol2 {
		authKey = a.pinState.protocol.hmacKey
		encKey = a.pinState.protocol.aesKey
	}

	// Verify the authentication parameter over newPinEnc || pinHashEnc.
	authData := append(req.NewPinEnc, req.PinHashEnc...)
	if !a.verifyPinAuth(authKey, req.PinUvAuthProtocol, authData, req.PinUvAuthParam) {
		return nil, ErrPINAuthInvalid
	}

	// Decrypt and verify current PIN hash.
	currentPinHash, err := a.decryptBlock(encKey, req.PinUvAuthProtocol, req.PinHashEnc)
	if err != nil {
		a.state.DecrementPINRetries()
		_ = a.storage.SaveState(a.state)
		if a.state.PINRetries() <= 0 {
			return nil, ErrPINBlocked
		}
		return nil, ErrPINInvalid
	}

	if !a.verifyPINHashLocked(currentPinHash) {
		a.state.DecrementPINRetries()
		_ = a.storage.SaveState(a.state)
		if a.state.PINRetries() <= 0 {
			return nil, ErrPINBlocked
		}
		return nil, ErrPINInvalid
	}

	// Decrypt the new PIN.
	newPIN, err := a.decryptPIN(encKey, req.PinUvAuthProtocol, req.NewPinEnc)
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
	if !a.isPINSetLocked() {
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
	sharedSecret, err := a.deriveSharedSecret(req.KeyAgreement, req.PinUvAuthProtocol)
	if err != nil {
		return nil, err
	}
	a.pinState.protocol.sharedSecret = sharedSecret

	// Determine encryption key based on protocol version.
	encKey := sharedSecret
	if req.PinUvAuthProtocol == PINProtocol2 {
		encKey = a.pinState.protocol.aesKey
	}

	// Verify pinHashEnc is provided.
	if len(req.PinHashEnc) == 0 {
		return nil, ErrInvalidParameter
	}

	// Decrypt and verify current PIN hash.
	currentPinHash, err := a.decryptBlock(encKey, req.PinUvAuthProtocol, req.PinHashEnc)
	if err != nil {
		a.state.DecrementPINRetries()
		_ = a.storage.SaveState(a.state)
		if a.state.PINRetries() <= 0 {
			return nil, ErrPINBlocked
		}
		return nil, ErrPINInvalid
	}

	if !a.verifyPINHashLocked(currentPinHash) {
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
	encryptedToken, err := a.encryptData(encKey, req.PinUvAuthProtocol, pinToken)
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

// handleGetPinUvAuthTokenUsingUvWithPermissions generates a pinUvAuthToken using
// built-in user verification (UV) instead of PIN verification. This is used when
// the authenticator reports uv=true in GetInfo and the platform sends subCommand 0x06.
// The flow is identical to the PIN-with-permissions variant except PIN hash
// verification is skipped entirely -- the key backend's built-in UV (e.g.,
// biometric on a phone) is considered sufficient.
func (a *Authenticator) handleGetPinUvAuthTokenUsingUvWithPermissions(req *ClientPINRequest) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// The backend must support built-in user verification.
	if a.keyBackend == nil || !a.keyBackend.Capabilities().HandlesUserVerification {
		return nil, ErrInvalidSubcommand
	}

	// Validate permissions are non-zero.
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
	sharedSecret, err := a.deriveSharedSecret(req.KeyAgreement, req.PinUvAuthProtocol)
	if err != nil {
		return nil, err
	}
	a.pinState.protocol.sharedSecret = sharedSecret

	// Determine encryption key based on protocol version.
	encKey := sharedSecret
	if req.PinUvAuthProtocol == PINProtocol2 {
		encKey = a.pinState.protocol.aesKey
	}

	// Check UV retries.
	if a.state.UVRetries() <= 0 {
		return nil, ErrUVBlocked
	}

	slog.Debug("[CTAP2] getPinUvAuthTokenUsingUvWithPermissions",
		"protocol", req.PinUvAuthProtocol,
		"permissions", req.Permissions,
		"rpID", req.RPID,
	)

	// Built-in UV is handled by the key backend; when HandlesUserVerification
	// is true the backend performs UV as part of its operations (e.g., biometric
	// prompt on a phone). We treat the capability as implicit success.
	// Reset UV retries on success.
	a.state.SetUVRetries(DefaultUVRetries)

	// Generate a new PIN/UV auth token with permissions.
	pinToken := make([]byte, PINTokenSize)
	if _, err := rand.Read(pinToken); err != nil {
		return nil, ErrCryptoError
	}
	a.pinState.protocol.pinUvAuthToken = pinToken
	a.pinState.protocol.tokenPermissions = req.Permissions
	a.pinState.protocol.tokenRPID = req.RPID

	// Encrypt the token.
	encryptedToken, err := a.encryptData(encKey, req.PinUvAuthProtocol, pinToken)
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
	if !a.isPINSetLocked() {
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
	sharedSecret, err := a.deriveSharedSecret(req.KeyAgreement, req.PinUvAuthProtocol)
	if err != nil {
		return nil, err
	}
	a.pinState.protocol.sharedSecret = sharedSecret

	// Determine encryption key based on protocol version.
	encKey := sharedSecret
	if req.PinUvAuthProtocol == PINProtocol2 {
		encKey = a.pinState.protocol.aesKey
	}

	// Verify pinHashEnc is provided.
	if len(req.PinHashEnc) == 0 {
		return nil, ErrInvalidParameter
	}

	slog.Debug("[CTAP2] getPinUvAuthTokenUsingPinWithPermissions",
		"protocol", req.PinUvAuthProtocol,
		"pinHashEnc_len", len(req.PinHashEnc),
		"permissions", req.Permissions,
	)

	// Decrypt and verify current PIN hash.
	currentPinHash, err := a.decryptBlock(encKey, req.PinUvAuthProtocol, req.PinHashEnc)
	if err != nil {
		slog.Warn("[CTAP2] PIN hash decryption failed",
			"error", err.Error(),
			"protocol", req.PinUvAuthProtocol,
			"pinHashEnc_len", len(req.PinHashEnc),
		)
		a.state.DecrementPINRetries()
		_ = a.storage.SaveState(a.state)
		if a.state.PINRetries() <= 0 {
			return nil, ErrPINBlocked
		}
		return nil, ErrPINInvalid
	}

	if !a.verifyPINHashLocked(currentPinHash) {
		slog.Warn("[CTAP2] PIN hash mismatch",
			"retries_remaining", a.state.PINRetries()-1,
			"decrypted_len", len(currentPinHash),
			"stored_len", len(a.state.PINHash),
			"decrypted_prefix", fmt.Sprintf("%x", currentPinHash[:min(4, len(currentPinHash))]),
			"stored_prefix", fmt.Sprintf("%x", a.state.PINHash[:min(4, len(a.state.PINHash))]),
		)
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
	encryptedToken, err := a.encryptData(encKey, req.PinUvAuthProtocol, pinToken)
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
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   xBytes,
		coseKeyLabelY:   yBytes,
	}

	a.pinState.protocol = &pinProtocolState{
		privateKey:    privateKey,
		publicKeyCOSE: coseKey,
	}

	return nil
}

// regeneratePINProtocolKeys regenerates the ECDH key pair for enhanced security.
func (a *Authenticator) regeneratePINProtocolKeys() error {
	a.pinState.protocol = nil
	return a.initPINProtocol()
}

// hkdfDerive derives a 32-byte key from the IKM using HKDF-SHA-256 with
// a zero salt and the given info string (CTAP2.1 Section 6.5.6).
func hkdfDerive(ikm []byte, info string) ([]byte, error) {
	salt := make([]byte, 32)
	hkdfReader := hkdf.New(sha256.New, ikm, salt, []byte(info))
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, out); err != nil {
		return nil, ErrKeyAgreementFailed
	}
	return out, nil
}

// deriveSharedSecret derives the shared secret using ECDH with the platform's public key.
// For protocol 1, the raw ECDH output is hashed with SHA-256 to produce a single shared secret.
// For protocol 2, the raw ECDH output is fed into HKDF-SHA-256 to derive separate hmacKey and aesKey.
func (a *Authenticator) deriveSharedSecret(platformKeyAgreement []byte, protocol uint8) ([]byte, error) {
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

	// Perform ECDH to get raw shared point x-coordinate.
	rawSharedSecret, err := a.pinState.protocol.privateKey.ECDH(platformPublicKey)
	if err != nil {
		return nil, ErrKeyAgreementFailed
	}

	a.pinState.protocol.activeProtocol = protocol

	if protocol == PINProtocol2 {
		// V2 kdf(Z): The raw ECDH x-coordinate is used directly as IKM for
		// HKDF-SHA-256 to derive separate hmacKey and aesKey. Unlike V1,
		// SHA-256 is NOT applied before HKDF.
		// Reference: CTAP2.1 §6.5.6, python-fido2 reference implementation.
		hmacKey, err := hkdfDerive(rawSharedSecret, "CTAP2 HMAC key")
		if err != nil {
			return nil, err
		}
		aesKey, err := hkdfDerive(rawSharedSecret, "CTAP2 AES key")
		if err != nil {
			return nil, err
		}
		a.pinState.protocol.hmacKey = hmacKey
		a.pinState.protocol.aesKey = aesKey
		// Return hmacKey as the "sharedSecret" for backward compatibility with
		// callers that use it for authentication verification.
		return hmacKey, nil
	}

	// V1 kdf(Z): SHA-256 of the raw ECDH x-coordinate.
	hash := sha256.Sum256(rawSharedSecret)
	return hash[:], nil
}

// verifyPinAuth verifies the pinUvAuthParam using HMAC-SHA-256.
// For V1, the expected MAC is truncated to 16 bytes.
// For V2, the full 32-byte MAC is compared.
func (a *Authenticator) verifyPinAuth(key []byte, protocol uint8, data, authParam []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	expected := mac.Sum(nil)

	if protocol == PINProtocol2 {
		return hmac.Equal(expected, authParam)
	}

	// V1: truncate to 16 bytes.
	return hmac.Equal(expected[:PINAuthSizeV1], authParam)
}

// decryptPIN decrypts an encrypted PIN using AES-256-CBC.
// For V1, a zero IV is used. For V2, the IV is extracted from the first 16 bytes of the ciphertext.
func (a *Authenticator) decryptPIN(key []byte, protocol uint8, encryptedPIN []byte) ([]byte, error) {
	var iv []byte
	var ciphertext []byte

	if protocol == PINProtocol2 {
		// V2: first 16 bytes are IV, remainder is ciphertext.
		if len(encryptedPIN) < AESBlockSize+EncryptedPINMinLength {
			return nil, ErrDecryptionFailed
		}
		iv = encryptedPIN[:AESBlockSize]
		ciphertext = encryptedPIN[AESBlockSize:]
	} else {
		// V1: zero IV, entire input is ciphertext.
		if len(encryptedPIN) < EncryptedPINMinLength {
			return nil, ErrDecryptionFailed
		}
		iv = make([]byte, AESBlockSize)
		ciphertext = encryptedPIN
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

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
// For V1, expects exactly 16 bytes with a zero IV.
// For V2, expects 32 bytes: 16-byte IV followed by 16-byte ciphertext.
func (a *Authenticator) decryptBlock(key []byte, protocol uint8, encrypted []byte) ([]byte, error) {
	var iv []byte
	var ciphertext []byte

	if protocol == PINProtocol2 {
		// V2: 16-byte IV + 16-byte ciphertext = 32 bytes minimum.
		if len(encrypted) < AESBlockSize+PINHashSize {
			return nil, ErrDecryptionFailed
		}
		iv = encrypted[:AESBlockSize]
		ciphertext = encrypted[AESBlockSize : AESBlockSize+PINHashSize]
	} else {
		// V1: exactly 16 bytes, zero IV.
		if len(encrypted) != PINHashSize {
			return nil, ErrDecryptionFailed
		}
		iv = make([]byte, AESBlockSize)
		ciphertext = encrypted
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	return decrypted, nil
}

// encryptData encrypts data using AES-256-CBC per CTAP2 §6.5.5/§6.5.6.
// The plaintext MUST be a multiple of AESBlockSize (no padding is applied).
// For V1, a zero IV is used. For V2, a random 16-byte IV is generated and prepended to the ciphertext.
func (a *Authenticator) encryptData(key []byte, protocol uint8, plaintext []byte) ([]byte, error) {
	// CTAP2 encrypt() requires plaintext to be block-aligned.
	if len(plaintext) == 0 || len(plaintext)%AESBlockSize != 0 {
		return nil, ErrInvalidParameter
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrCryptoError
	}

	var iv []byte
	if protocol == PINProtocol2 {
		// V2: generate random IV.
		iv = make([]byte, AESBlockSize)
		if _, err := rand.Read(iv); err != nil {
			return nil, ErrCryptoError
		}
	} else {
		// V1: zero IV.
		iv = make([]byte, AESBlockSize)
	}

	mode := cipher.NewCBCEncrypter(block, iv)

	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)

	if protocol == PINProtocol2 {
		// V2: prepend IV to ciphertext.
		return append(iv, ciphertext...), nil
	}

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
	expected := mac.Sum(nil)

	if a.pinState.protocol.activeProtocol == PINProtocol2 {
		// V2: compare full 32-byte HMAC.
		return hmac.Equal(expected, authParam)
	}

	// V1: truncate to 16 bytes.
	return hmac.Equal(expected[:PINAuthSizeV1], authParam)
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
// the COSE public key and the derived shared secret with the authenticator
// using PIN protocol 1 (SHA-256 key derivation).
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
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
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

	authCOSE := a.pinState.protocol.publicKeyCOSE

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

	// Derive shared secret (V1: SHA-256 of raw ECDH output).
	rawSecret, err := platformPrivKey.ECDH(authPubKey)
	if err != nil {
		return nil, nil, err
	}

	hash := sha256.Sum256(rawSecret)
	return platformCOSE, hash[:], nil
}

// generatePlatformKeyAgreementV2 generates a platform ECDH key pair and returns
// the COSE public key and the HKDF-derived hmacKey and aesKey using PIN protocol 2.
func (a *Authenticator) generatePlatformKeyAgreementV2() (platformCOSE []byte, hmacKey []byte, aesKey []byte, err error) {
	// Generate platform ECDH key pair.
	platformPrivKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	// Encode platform public key as COSE.
	pubBytes := platformPrivKey.PublicKey().Bytes()
	xBytes := pubBytes[1:33]
	yBytes := pubBytes[33:65]

	coseKey := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   xBytes,
		coseKeyLabelY:   yBytes,
	}

	platformCOSE, err = cbor.Marshal(coseKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// Get authenticator's public key for ECDH.
	if a.pinState.protocol == nil {
		return nil, nil, nil, ErrMissingKeyAgreement
	}

	authCOSE := a.pinState.protocol.publicKeyCOSE

	authXBytes := authCOSE[coseKeyLabelX].([]byte)
	authYBytes := authCOSE[coseKeyLabelY].([]byte)

	authPubBytes := make([]byte, 65)
	authPubBytes[0] = 0x04
	copy(authPubBytes[1:33], padCoordinate(authXBytes, 32))
	copy(authPubBytes[33:65], padCoordinate(authYBytes, 32))

	authPubKey, err := ecdh.P256().NewPublicKey(authPubBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	// Derive raw ECDH shared secret.
	rawSecret, err := platformPrivKey.ECDH(authPubKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// V2 kdf: raw ECDH x-coordinate directly into HKDF-SHA-256 (no SHA-256 pre-hash).
	// Reference: CTAP2.1 §6.5.6, python-fido2 reference implementation.
	hmacKey, err = hkdfDerive(rawSecret, "CTAP2 HMAC key")
	if err != nil {
		return nil, nil, nil, err
	}

	aesKey, err = hkdfDerive(rawSecret, "CTAP2 AES key")
	if err != nil {
		return nil, nil, nil, err
	}

	return platformCOSE, hmacKey, aesKey, nil
}

// encryptNewPIN encrypts a new PIN using the shared secret (V1).
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
	authParam := mac.Sum(nil)[:PINAuthSizeV1]

	return encryptedPIN, authParam, nil
}

// encryptNewPINV2 encrypts a new PIN using V2 protocol (random IV, full 32-byte HMAC).
// This simulates what a client would send for SetPIN/ChangePIN with protocol 2.
func encryptNewPINV2(hmacKey, aesKey []byte, pin string) ([]byte, []byte, error) {
	// Pad PIN to 64 bytes.
	paddedPIN := make([]byte, EncryptedPINMinLength)
	copy(paddedPIN, []byte(pin))

	// Generate random IV.
	iv := make([]byte, AESBlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, ErrCryptoError
	}

	// Encrypt with AES-256-CBC using random IV.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, ErrCryptoError
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(paddedPIN))
	mode.CryptBlocks(ciphertext, paddedPIN)

	// Prepend IV to ciphertext.
	encryptedPIN := append(iv, ciphertext...)

	// Full 32-byte HMAC.
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(encryptedPIN)
	authParam := mac.Sum(nil)

	return encryptedPIN, authParam, nil
}

// encryptPINHash encrypts a PIN hash using the shared secret (V1).
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

// encryptPINHashV2 encrypts a PIN hash using V2 protocol (random IV).
// This simulates what a client would send for ChangePIN/GetPINToken with protocol 2.
func encryptPINHashV2(aesKey []byte, pin string) ([]byte, error) {
	pinHash := sha256.Sum256([]byte(pin))

	// Generate random IV.
	iv := make([]byte, AESBlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, ErrCryptoError
	}

	// Encrypt first 16 bytes of PIN hash with AES-256-CBC using random IV.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, ErrCryptoError
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, PINHashSize)
	mode.CryptBlocks(encrypted, pinHash[:PINHashSize])

	// Prepend IV to ciphertext.
	return append(iv, encrypted...), nil
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
