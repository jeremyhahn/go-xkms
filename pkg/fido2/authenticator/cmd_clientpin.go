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
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"time"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/crypto/hkdf"

	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator/keybackend"
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
	PINProtocol1  = 1
	PINProtocol2  = 2
	PINMinLength  = 4
	PINHashSize   = 16
	PINAuthSizeV1 = 16
	PINAuthSizeV2 = 32
	PINTokenSize  = 32
	AESBlockSize  = 16

	// EncryptedPINMinLength is the size, in bytes, of the zero-padded PIN
	// plaintext that decryptPIN produces and that encryptNewPIN/encryptNewPINV2
	// build: CTAP 2.1 §6.5.6 pads newPin to exactly one AES block count (64
	// bytes) regardless of protocol, so it is also the exact V1 newPinEnc
	// length and the ciphertext length within a V2 newPinEnc.
	EncryptedPINMinLength = 64

	// PINMaxLength is the largest PIN, in bytes, CTAP 2.1 §6.5.5.5 step 5
	// permits. A PIN filling all 64 padded bytes has no room for the 0x00
	// terminator decryptPIN requires, so this is also the largest PIN that
	// can round-trip through the padding scheme.
	PINMaxLength = 63
)

// pinUvAuthToken lifetime limits from CTAP 2.1 §6.5.2.1. A token is minted by
// beginUsingPinUvAuthToken and stops being usable once either limit elapses,
// so a single PIN entry cannot authorize commands indefinitely.
const (
	// pinUvAuthTokenInactivityLimit is the initial usage time limit: a token
	// that has gone unused for this long is no longer accepted.
	pinUvAuthTokenInactivityLimit = 30 * time.Second

	// pinUvAuthTokenMaxUsagePeriod is the hard cap on a token's lifetime,
	// measured from issuance regardless of how often it is used.
	pinUvAuthTokenMaxUsagePeriod = 10 * time.Minute
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

	// tokenRPID is the permissions RP ID the token is scoped to. It is empty
	// until the token is first used with makeCredential or getAssertion, at
	// which point that request's RP ID is bound to the token per CTAP 2.1
	// §6.1.2 / §6.2.2.
	tokenRPID string

	// tokenIssuedAt is when the token was minted. It starts the usage timer
	// for pinUvAuthTokenMaxUsagePeriod. A zero value means no token has been
	// minted through beginUsingPinUvAuthTokenLocked and the token is unusable.
	tokenIssuedAt time.Time

	// tokenLastUsed is when the token last authorized a command. It starts the
	// usage timer for pinUvAuthTokenInactivityLimit.
	tokenLastUsed time.Time

	// tokenUserVerified is the token's userVerified flag (CTAP 2.1 §6.5.2.1).
	// beginUsingPinUvAuthTokenLocked sets it, and the credential operation that
	// sets the "up" bit clears it along with the token's permissions, so a
	// consumed token can no longer assert that a human was verified.
	tokenUserVerified bool

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

	// mismatches counts consecutive user PIN mismatches since the last
	// correct PIN or power-up (CTAP 2.1 §6.5.5.5). It lives here rather than
	// in protocol so regenerating the key agreement does not clear it, and
	// clearPINState (authenticatorReset) does.
	mismatches pinMismatchGuard
}

// userPINRefusals are the user PIN's failed-attempt errors.
var userPINRefusals = pinRefusals{
	blocked:     ErrPINBlocked,
	authBlocked: ErrPINAuthBlocked,
	invalid:     ErrPINInvalid,
}

// handleClientPIN implements the CTAP2 authenticatorClientPIN command (0x06).
// It dispatches to the appropriate subcommand handler based on the request.
func (a *Authenticator) handleClientPIN(data []byte) ([]byte, error) {
	// authenticatorClientPIN is required only if the authenticator supports
	// PIN or a UV mechanism that mints pinUvAuthTokens (CTAP 2.1 §6.5).
	// Config.SetDefaults forces EnablePIN whenever credential management is
	// enabled, which is the only feature here that needs a minted token, so
	// EnablePIN=false means neither applies and getInfo advertises neither
	// clientPin nor pinUvAuthProtocols; declining is spec-correct.
	if !a.config.EnablePIN {
		return nil, ErrCommandNotSupported
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
//
// powerCycleState (CTAP 2.1 §6.5.5.2) reports whether the consecutive-mismatch
// block is in force, so a platform can tell "power-cycle the authenticator"
// from "attempts remain".
func (a *Authenticator) handleGetRetries() ([]byte, error) {
	a.mu.RLock()
	retries := a.state.PINRetries()
	powerCycle := a.pinState.mismatches.authBlocked()
	a.mu.RUnlock()

	response := map[int]interface{}{
		clientPINResponseKeyPinRetries:      uint8(retries),
		clientPINResponseKeyPowerCycleState: powerCycle,
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

	// The wire ceremony has proven the platform holds the shared secret; the
	// PIN policy, retry reset, token invalidation and persistence are the
	// same for every way a first PIN comes into existence.
	if err := a.establishPINLocked(newPIN); err != nil {
		return nil, err
	}
	return a.successResponse(nil), nil
}

// establishPINLocked is the single path by which an authenticator without a
// PIN acquires one. Both the CTAP setPIN subcommand (after its wire-level
// pinUvAuthParam proof) and SetInitialPIN end here, so the PIN policy, the
// retry-counter reset, the pinUvAuthToken invalidation and the persistence
// ordering cannot drift between them.
//
// The caller must hold a.mu for writing.
func (a *Authenticator) establishPINLocked(newPIN []byte) error {
	if a.isPINSetLocked() {
		return ErrPINAlreadySet
	}

	// Validate PIN length.
	if len(newPIN) < a.config.PINMinLength {
		return ErrPINPolicyViolation
	}

	// Hash and store the PIN (SHA-256, left 16 bytes).
	pinHash := sha256.Sum256(newPIN)
	a.state.PINHash = pinHash[:PINHashSize]
	a.state.PINSet = true
	a.state.SetPINRetries(a.config.PINMaxRetries)

	// CTAP 2.1 §6.5.2.1: a pinUvAuthToken must not outlive the PIN state it
	// was minted under. This path runs only when no PIN was set, yet a token
	// can be outstanding: getPinUvAuthTokenUsingUvWithPermissions mints one
	// from the key backend's built-in user verification without a PIN
	// (ruling 167). Establishing a PIN must never leave a token minted
	// without one usable.
	//
	// Placed after the new PIN is accepted into a.state and before it is
	// persisted, so a storage failure cannot leave a live token behind a PIN
	// the authenticator already considers set. Every refusal returned above,
	// so a failed establishment never discards the token.
	a.stopUsingPinUvAuthTokenLocked()

	// The audit record is written before the new PIN state is persisted, so
	// a failed write refuses the establishment rather than leave an unaudited
	// PIN in storage.
	if a.auditLog != nil {
		if err := a.auditLog.LogPINSeeded(); err != nil {
			return err
		}
	}

	// Save state.
	if err := a.storage.SaveState(a.state); err != nil {
		return errors.Join(ErrStorageError, err)
	}
	return nil
}

// SetInitialPIN establishes the authenticator's PIN when none is set. It is
// the in-process counterpart of the CTAP ClientPIN setPIN subcommand for a
// caller that already holds the operator's authority — the xkey daemon
// seeding the PIN it was started with, or a first-run wizard — and it is a
// production API, not a test hook.
//
// It runs the same establishment path as setPIN: the configured minimum
// length is enforced, the retry counter is reset, any outstanding
// pinUvAuthToken is invalidated (CTAP 2.1 §6.5.2.1) before the new state is
// persisted, and a storage failure is reported as ErrStorageError. The one
// thing it does not do is the wire-level ceremony — ECDH key agreement and
// the pinUvAuthParam proof over the encrypted PIN — because that ceremony
// exists to authenticate a remote platform to the authenticator, and an
// in-process caller is already on the authenticator's side of that boundary.
//
// An authenticator that already has a PIN refuses with ErrPINAlreadySet: an
// existing PIN is replaced only through changePIN, which proves the current
// one. A PIN shorter than the configured minimum is refused with
// ErrPINPolicyViolation.
//
// pin is not retained beyond the call: establishPINLocked only hashes it.
// Callers holding the PIN in protected memory should borrow it (e.g. via
// secure.Secret.Open/Buffer.WithBytes) rather than materializing a string.
func (a *Authenticator) SetInitialPIN(pin []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.establishPINLocked(pin)
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
	//
	// Built into its own buffer rather than append(req.NewPinEnc, ...): that
	// appends into NewPinEnc's backing array whenever it has spare capacity,
	// and these fields are decoded from one CBOR message, so the write past
	// its length can land on an adjacent decoded field -- PinHashEnc itself
	// being the obvious candidate. NewPinEnc is read again below.
	authData := make([]byte, 0, len(req.NewPinEnc)+len(req.PinHashEnc))
	authData = append(authData, req.NewPinEnc...)
	authData = append(authData, req.PinHashEnc...)
	if !a.verifyPinAuth(authKey, req.PinUvAuthProtocol, authData, req.PinUvAuthParam) {
		return nil, ErrPINAuthInvalid
	}

	// Decrypt current PIN hash. A decryption failure is not returned
	// directly: it is fed to verifyPinHashAndConsumeRetryLocked as a nil
	// candidate, which CTAP 2.1 treats as an ordinary wrong-PIN guess that
	// still spends a retry, not a protocol error the platform gets to retry
	// for free.
	currentPinHash, err := a.decryptBlock(encKey, req.PinUvAuthProtocol, req.PinHashEnc)
	if err != nil {
		currentPinHash = nil
	}

	if err := a.verifyPinHashAndConsumeRetryLocked(currentPinHash); err != nil {
		return nil, err
	}

	// Decrypt the new PIN. decryptPIN already enforces the CTAP 2.1 §6.5.5.5
	// step 5 length policy (non-empty, <= 63 bytes, >= a.config.PINMinLength
	// Unicode code points) as part of extracting it from its padded form, so
	// there is no separate length check to repeat here.
	newPIN, err := a.decryptPIN(encKey, req.PinUvAuthProtocol, req.NewPinEnc)
	if err != nil {
		return nil, err
	}

	// Hash and store the new PIN. The retry budget was already reset and
	// persisted by verifyPinHashAndConsumeRetryLocked above when the current
	// PIN verified; setting it again here would only be redundant.
	pinHash := sha256.Sum256(newPIN)
	a.state.PINHash = pinHash[:PINHashSize]

	// CTAP 2.1 §6.5.2.1: the token minted under the old PIN stops being usable
	// here. regeneratePINProtocolKeys below already achieves that as a side
	// effect — it discards the whole pinProtocolState — but only incidentally,
	// from a function named for the keys rather than the token, and it drops
	// the token bytes without wiping them. Stating the invalidation makes the
	// guarantee survive any future change that keeps the negotiated keys
	// across a PIN change, and it zeroes the token rather than leaving the
	// key material for the collector.
	//
	// Every wrong-PIN path returned above, so a failed change cannot reach
	// this and clear a token the caller could not authenticate against.
	a.stopUsingPinUvAuthTokenLocked()

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

	// CTAP 2.1 §6.5.5.7.1: the permissions and rpId parameters MUST NOT be
	// present in getPinToken. The token this subcommand issues always carries
	// the default permissions, so accepting either parameter would let a
	// platform believe it had requested a scope the authenticator ignored.
	if req.Permissions != 0 || req.RPID != "" {
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

	// Decrypt current PIN hash. A decryption failure is not returned
	// directly: it is fed to verifyPinHashAndConsumeRetryLocked as a nil
	// candidate, which CTAP 2.1 treats as an ordinary wrong-PIN guess that
	// still spends a retry, not a protocol error the platform gets to retry
	// for free.
	currentPinHash, err := a.decryptBlock(encKey, req.PinUvAuthProtocol, req.PinHashEnc)
	if err != nil {
		currentPinHash = nil
	}

	if err := a.verifyPinHashAndConsumeRetryLocked(currentPinHash); err != nil {
		return nil, err
	}

	// Generate a new PIN token.
	pinToken := make([]byte, PINTokenSize)
	if _, err := rand.Read(pinToken); err != nil {
		return nil, ErrCryptoError
	}
	// The superseded getPinToken subcommand carries no permissions parameter.
	// CTAP 2.1 §6.5.5.7.1 grants the resulting token the mc and ga permissions
	// and no permissions RP ID; the first makeCredential or getAssertion binds
	// its RP ID. Granting them explicitly also clears any permissions left over
	// from a previous token, which must not carry across a new PIN entry.
	a.beginUsingPinUvAuthTokenLocked(pinToken, PINPermissionMakeCredential|PINPermissionGetAssertion, "")

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
		"permissions", req.Permissions,
	)

	// Decrypt current PIN hash. A decryption failure is not returned
	// directly: it is fed to verifyPinHashAndConsumeRetryLocked as a nil
	// candidate, which CTAP 2.1 treats as an ordinary wrong-PIN guess that
	// still spends a retry, not a protocol error the platform gets to retry
	// for free.
	currentPinHash, err := a.decryptBlock(encKey, req.PinUvAuthProtocol, req.PinHashEnc)
	if err != nil {
		slog.Warn("[CTAP2] PIN hash decryption failed",
			"error", err.Error(),
			"protocol", req.PinUvAuthProtocol,
		)
		currentPinHash = nil
	}

	if err := a.verifyPinHashAndConsumeRetryLocked(currentPinHash); err != nil {
		if errors.Is(err, ErrPINInvalid) || errors.Is(err, ErrPINBlocked) {
			slog.Warn("[CTAP2] PIN hash mismatch",
				"error", err,
				"retries_remaining", a.state.PINRetries(),
			)
		}
		return nil, err
	}

	// Generate a new PIN token with permissions.
	pinToken := make([]byte, PINTokenSize)
	if _, err := rand.Read(pinToken); err != nil {
		return nil, ErrCryptoError
	}
	a.beginUsingPinUvAuthTokenLocked(pinToken, req.Permissions, req.RPID)

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

// rpIDIgnoredPermissions are the permissions CTAP 2.1 §6.5.5.7 marks
// "RP ID: Ignored": bioEnrollment, largeBlobWrite and authenticatorConfig act
// on the whole authenticator, and the rpId parameter does not narrow them.
const rpIDIgnoredPermissions = PINPermissionBioEnrollment | PINPermissionLargeBlobWrite | PINPermissionAuthenticatorCfg

// uvConsentRPID names the RP the user is asked to consent for in the built-in
// user verification of getPinUvAuthTokenUsingUvWithPermissions. The prompt
// must not claim a narrower scope than the token carries. mc and ga are bound
// to the rpId (CTAP 2.1 §6.5.5.7), and so is cm: a credentialMgmt token with
// a permissions RP ID manages that RP's credentials only (§6.8.3-§6.8.6). A
// permission whose rpId is ignored is authenticator-wide whatever rpId the
// request names, so a request carrying one asks for authenticator-wide
// consent: the empty RP ID, which the verifier presents as the authenticator
// itself (keybackend.UserVerifier).
func uvConsentRPID(req *ClientPINRequest) string {
	if req.Permissions&rpIDIgnoredPermissions != 0 {
		return ""
	}
	return req.RPID
}

// handleGetPinUvAuthTokenUsingUvWithPermissions mints a pinUvAuthToken on the
// strength of the key backend's built-in user verification (CTAP 2.1
// §6.5.5.7.3, ruling 167). The token is minted only after the backend's
// VerifyUser returned nil for this request; a key backend without a
// keybackend.UserVerifier has no built-in method, and the subcommand is
// refused as it always was.
//
// The ceremony runs without mu: it waits on a device and a human, and mu
// guards state every other caller reads. cmdMu (ProcessCBORWithContext) still
// serializes it against every other CTAP command.
func (a *Authenticator) handleGetPinUvAuthTokenUsingUvWithPermissions(req *ClientPINRequest) ([]byte, error) {
	verifier := a.userVerifier()
	if verifier == nil {
		return nil, ErrInvalidSubcommand
	}

	a.mu.Lock()
	encKey, err := a.prepareUvTokenLocked(req)
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}

	verifyErr := verifier.VerifyUser(a.commandContext(), uvConsentRPID(req))

	a.mu.Lock()
	defer a.mu.Unlock()

	if verifyErr != nil {
		return nil, a.failUserVerificationLocked(verifyErr)
	}
	a.state.ResetUVRetries()

	pinToken := make([]byte, PINTokenSize)
	if _, err := rand.Read(pinToken); err != nil {
		return nil, ErrCryptoError
	}
	a.beginUsingPinUvAuthTokenLocked(pinToken, req.Permissions, req.RPID)

	encryptedToken, err := a.encryptData(encKey, req.PinUvAuthProtocol, pinToken)
	if err != nil {
		return nil, err
	}

	if err := a.storage.SaveState(a.state); err != nil {
		return nil, ErrStorageError
	}

	data, err := encodeCBOR(map[int]interface{}{
		clientPINResponseKeyPinUvAuthToken: encryptedToken,
	})
	if err != nil {
		return nil, err
	}
	return a.successResponse(data), nil
}

// prepareUvTokenLocked runs the checks of CTAP 2.1 §6.5.5.7.3 that precede the
// user verification ceremony, so a malformed request never prompts the user,
// and returns the key the minted token is encrypted under.
func (a *Authenticator) prepareUvTokenLocked(req *ClientPINRequest) ([]byte, error) {
	if req.Permissions == 0 {
		return nil, ErrInvalidParameter
	}
	// The rpId parameter is optional in CTAP 2.1 §6.5.5.7.3, and a token
	// minted without one binds to the RP of its first makeCredential or
	// getAssertion (§6.1.2, §6.2.2). This authenticator's
	// built-in verification asks the user on behalf of the named RP, so an
	// RP-scoped token without one would be consented to for no RP and then
	// bound to whichever RP used it first. It answers
	// CTAP2_ERR_MISSING_PARAMETER (§8.2) before the user is asked instead.
	if req.Permissions&(PINPermissionMakeCredential|PINPermissionGetAssertion) != 0 && req.RPID == "" {
		return nil, ErrMissingRPID
	}
	if a.state.UVRetries() <= 0 {
		return nil, ErrUVBlocked
	}
	if err := a.initPINProtocol(); err != nil {
		return nil, err
	}
	if len(req.KeyAgreement) == 0 {
		return nil, ErrMissingKeyAgreement
	}

	sharedSecret, err := a.deriveSharedSecret(req.KeyAgreement, req.PinUvAuthProtocol)
	if err != nil {
		return nil, err
	}
	a.pinState.protocol.sharedSecret = sharedSecret

	if req.PinUvAuthProtocol == PINProtocol2 {
		return a.pinState.protocol.aesKey, nil
	}
	return sharedSecret, nil
}

// failUserVerificationLocked records a failed built-in user verification and
// returns the status for it: CTAP2_ERR_UV_INVALID, or CTAP2_ERR_UV_BLOCKED
// once the uvRetries counter is spent (CTAP 2.1 §6.5.5.7.3). uvRetries counts
// failed attempts to verify the user, so only those spend one. A platform
// that cancelled the request did not fail a verification. Nor did a verifier
// that could not reach a decision (keybackend.ErrUserVerificationUnavailable:
// the phone disconnected, the exchange timed out, the revocation list could
// not be read); it answers CTAP1_ERR_OTHER (§8.2), and the retries are left
// as they were, so an outage cannot block built-in user verification.
func (a *Authenticator) failUserVerificationLocked(verifyErr error) error {
	if errors.Is(verifyErr, context.Canceled) {
		return verifyErr
	}
	if errors.Is(verifyErr, keybackend.ErrUserVerificationUnavailable) {
		slog.Warn("[CTAP2] built-in user verification unavailable", "error", verifyErr)
		return verifyErr
	}

	remaining := a.state.DecrementUVRetries()
	if err := a.storage.SaveState(a.state); err != nil {
		return ErrStorageError
	}
	slog.Warn("[CTAP2] built-in user verification failed",
		"error", verifyErr,
		"uv_retries_remaining", remaining,
	)
	if remaining <= 0 {
		return &SentinelCauseError{Sentinel: ErrUVBlocked, Cause: verifyErr}
	}
	return &SentinelCauseError{Sentinel: ErrUVInvalid, Cause: verifyErr}
}

// verifyPinHashAndConsumeRetryLocked implements the CTAP 2.1 §6.5.5.5
// pinRetries procedure: a retry is spent and persisted durably BEFORE
// candidateHash is ever compared against the stored PIN, and a successful
// match resets the retry budget to its configured maximum and persists that
// too before returning. changePIN, getPinToken, and
// getPinUvAuthTokenUsingPinWithPermissions are the only three ClientPIN
// subcommands that check a pinHashEnc, and all three funnel through here so
// the decrement-before-compare ordering and its persistence cannot drift
// between them (go-xkms#686).
//
// candidateHash may be nil. verifyPINHashLocked treats a nil or empty hash as
// an automatic mismatch, which is what CTAP 2.1 requires when pinHashEnc
// itself fails to decrypt: that is an ordinary wrong-PIN attempt, not a
// protocol error the platform gets to retry for free, so it must still spend
// a retry.
//
// A storage failure while persisting the spent retry fails the whole
// operation closed: since the persist happens before the comparison, a
// caller can never learn whether an untested guess was right by racing a
// flaky store. The failure is reported as ErrStorageError with the backend's
// cause attached, the same as every other persistence failure in this
// package. It is deliberately not reported as CTAP2_ERR_PIN_AUTH_BLOCKED:
// that status promises the platform that a power cycle will resume attempts,
// and a storage fault is not fixed by one.
//
// A mismatch also regenerates the authenticator's keyAgreement key, so the
// platform must run key agreement again before its next attempt, and counts
// toward the consecutive-mismatch block: after PINMaxConsecutiveFailures
// mismatches in a row every further attempt is refused with ErrPINAuthBlocked,
// without spending a retry, until the authenticator restarts (its power
// cycle). A correct PIN clears the count. The Security Officer PIN applies the
// same rule through the same pinMismatchGuard.
//
// Returns ErrStorageError if the decremented (or, on success, reset) retry
// counter could not be persisted, ErrPINBlocked if the retry budget is now
// exhausted, ErrPINAuthBlocked if the consecutive-mismatch limit is reached,
// and ErrPINInvalid if candidateHash does not match.
//
// The caller must hold a.mu for writing.
func (a *Authenticator) verifyPinHashAndConsumeRetryLocked(candidateHash []byte) error {
	if a.pinState.mismatches.authBlocked() {
		return ErrPINAuthBlocked
	}

	a.state.DecrementPINRetries()
	if err := a.storage.SaveState(a.state); err != nil {
		return errors.Join(ErrStorageError, err)
	}

	if !a.verifyPINHashLocked(candidateHash) {
		if err := a.regenerateKeyAgreementLocked(); err != nil {
			return err
		}
		return a.pinState.mismatches.recordMismatch(a.state.PINRetries() <= 0, userPINRefusals)
	}

	a.pinState.mismatches.reset()
	a.state.SetPINRetries(a.config.PINMaxRetries)
	if err := a.storage.SaveState(a.state); err != nil {
		return errors.Join(ErrStorageError, err)
	}
	return nil
}

// initPINProtocol initializes the PIN protocol state with a new ECDH key pair.
func (a *Authenticator) initPINProtocol() error {
	if a.pinState.protocol != nil && a.pinState.protocol.privateKey != nil {
		return nil
	}

	privateKey, coseKey, err := newKeyAgreementKey()
	if err != nil {
		return err
	}

	a.pinState.protocol = &pinProtocolState{
		privateKey:    privateKey,
		publicKeyCOSE: coseKey,
	}

	return nil
}

// newKeyAgreementKey generates a P-256 ECDH key pair for the PIN/UV auth
// protocol and returns it with its public key encoded as a COSE_Key map.
func newKeyAgreementKey() (*ecdh.PrivateKey, map[int]interface{}, error) {
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, ErrKeyGenerationFailed
	}

	// P-256 uncompressed point format: 04 || X || Y.
	publicKeyBytes := privateKey.PublicKey().Bytes()
	if len(publicKeyBytes) != 65 || publicKeyBytes[0] != 0x04 {
		return nil, nil, ErrKeyGenerationFailed
	}

	coseKey := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   publicKeyBytes[1:33],
		coseKeyLabelY:   publicKeyBytes[33:65],
	}
	return privateKey, coseKey, nil
}

// regenerateKeyAgreementLocked replaces the authenticator's keyAgreement key
// pair after a PIN mismatch, the PIN/UV auth protocol's regenerate() that
// CTAP 2.1 §6.5.5.5 requires, and discards every secret derived from the old
// key. The pinUvAuthToken is not derived from the key agreement and is left
// alone: a wrong guess must not revoke the token a legitimate holder already
// minted.
//
// The caller must hold a.mu for writing.
func (a *Authenticator) regenerateKeyAgreementLocked() error {
	privateKey, coseKey, err := newKeyAgreementKey()
	if err != nil {
		return err
	}

	p := a.pinState.protocol
	if p == nil {
		a.pinState.protocol = &pinProtocolState{privateKey: privateKey, publicKeyCOSE: coseKey}
		return nil
	}
	p.privateKey = privateKey
	p.publicKeyCOSE = coseKey
	p.sharedSecret = nil
	p.hmacKey = nil
	p.aesKey = nil
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

// pinSharedSecret is the output of a PIN/UV auth protocol's kdf(Z) (CTAP 2.1
// §6.5.6 protocol one, §6.5.7 protocol two): the key authenticate()/verify()
// use and the key encrypt()/decrypt() use. Protocol one derives a single key
// and uses it for both roles; protocol two derives two independent keys.
type pinSharedSecret struct {
	// protocol is the PIN/UV auth protocol the keys were derived for.
	protocol uint8

	// hmacKey keys authenticate() and verify().
	hmacKey []byte

	// aesKey keys encrypt() and decrypt().
	aesKey []byte
}

// wipe zeroes both keys.
func (s *pinSharedSecret) wipe() {
	enclave.Wipe(s.hmacKey)
	enclave.Wipe(s.aesKey)
}

// agreeSharedSecret is the authenticator side of a PIN/UV auth protocol's
// decapsulate(): ECDH between the authenticator's current key agreement key
// (the one getKeyAgreement handed out) and the platform's COSE_Key, followed by
// the protocol's kdf(Z). Protocol one's kdf is SHA-256(Z); protocol two's is
// HKDF-SHA-256 over Z with the "CTAP2 HMAC key" and "CTAP2 AES key" infos.
//
// It reads pinState but never modifies it, so a caller that only needs a
// request-scoped secret -- the hmac-secret extension -- cannot disturb the
// clientPin session. The caller must hold a.mu.
func (a *Authenticator) agreeSharedSecret(platformKeyAgreement []byte, protocol uint8) (*pinSharedSecret, error) {
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
	defer enclave.Wipe(rawSharedSecret)

	if protocol == PINProtocol2 {
		// V2 kdf(Z): The raw ECDH x-coordinate is used directly as IKM for
		// HKDF-SHA-256 to derive separate hmacKey and aesKey. Unlike V1,
		// SHA-256 is NOT applied before HKDF.
		// Reference: CTAP2.1 §6.5.7, python-fido2 reference implementation.
		hmacKey, err := hkdfDerive(rawSharedSecret, "CTAP2 HMAC key")
		if err != nil {
			return nil, err
		}
		aesKey, err := hkdfDerive(rawSharedSecret, "CTAP2 AES key")
		if err != nil {
			return nil, err
		}
		return &pinSharedSecret{protocol: PINProtocol2, hmacKey: hmacKey, aesKey: aesKey}, nil
	}

	// V1 kdf(Z): SHA-256 of the raw ECDH x-coordinate, one key for both roles.
	hash := sha256.Sum256(rawSharedSecret)
	return &pinSharedSecret{protocol: PINProtocol1, hmacKey: hash[:], aesKey: hash[:]}, nil
}

// deriveSharedSecret establishes the clientPin session's shared secret with
// the platform's public key and records it in pinState: the active protocol
// and, for protocol 2, the separate hmacKey and aesKey. It returns the key
// authenticate()/verify() use -- SHA-256(Z) for protocol 1, the HKDF hmacKey
// for protocol 2.
func (a *Authenticator) deriveSharedSecret(platformKeyAgreement []byte, protocol uint8) ([]byte, error) {
	secret, err := a.agreeSharedSecret(platformKeyAgreement, protocol)
	if err != nil {
		return nil, err
	}

	a.pinState.protocol.activeProtocol = protocol
	if protocol == PINProtocol2 {
		a.pinState.protocol.hmacKey = secret.hmacKey
		a.pinState.protocol.aesKey = secret.aesKey
	}
	return secret.hmacKey, nil
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

// decryptPIN decrypts an encrypted PIN using AES-256-CBC and validates it
// per CTAP 2.1 §6.5.5.5 (setPIN) / §6.5.5.6 (changePIN).
//
// encryptedPIN must be exactly EncryptedPINMinLength (64) bytes for
// protocol 1, or exactly AESBlockSize+EncryptedPINMinLength (80: a 16-byte
// IV followed by 64 bytes of ciphertext) for protocol 2. Any other length is
// rejected with ErrInvalidParameter (CTAP1_ERR_INVALID_PARAMETER) before
// CryptBlocks runs: CryptBlocks panics when its input is not a whole number
// of AES blocks, and nothing on the CTAP/uhid path recovered from that
// panic before dispatchCommand's recover boundary was added (go-xkms#1149).
//
// The decrypted buffer is then handed to extractPaddedPIN, which applies
// the padding and length policy from CTAP 2.1 §6.5.5.5 step 5.
func (a *Authenticator) decryptPIN(key []byte, protocol uint8, encryptedPIN []byte) ([]byte, error) {
	want := EncryptedPINMinLength // V1: zero IV, exactly the 64-byte padded PIN.
	if protocol == PINProtocol2 {
		want = AESBlockSize + EncryptedPINMinLength // V2: 16-byte IV + 64 bytes.
	}
	if len(encryptedPIN) != want {
		return nil, ErrInvalidParameter
	}

	decrypted, err := decryptData(key, protocol, encryptedPIN)
	if err != nil {
		return nil, err
	}

	return extractPaddedPIN(decrypted, a.config.PINMinLength)
}

// extractPaddedPIN validates and extracts a PIN from the zero-padded,
// block-decrypted plaintext newPinEnc decrypts to, per CTAP 2.1 §6.5.5.5
// step 5: the PIN is every byte before the first 0x00 terminator byte, and
// every byte from the terminator onward must also be 0x00 -- a stray
// non-zero byte after the terminator means the plaintext is not a validly
// padded PIN (whether from a corrupted ceremony or an attempt to smuggle
// data past the terminator), so it is rejected rather than silently
// dropped. A buffer with no terminator at all is rejected too: it has no
// room left for one, so the PIN it would represent is 64 bytes long,
// exceeding the 63-byte maximum by construction.
//
// The extracted PIN is then checked against minLength (CTAP 2.1 §6.5.5.5
// step 5's minPINLength, counted in Unicode code points since a PIN is
// UTF-8 text) and the 63-byte maximum. Every violation -- no terminator, an
// empty PIN, one under minLength, or one over 63 bytes -- reports the same
// ErrPINPolicyViolation (CTAP2_ERR_PIN_POLICY_VIOLATION), so a platform
// cannot use the error to distinguish a malformed ceremony from an
// out-of-policy PIN.
func extractPaddedPIN(padded []byte, minLength int) ([]byte, error) {
	terminator := -1
	for i, b := range padded {
		if b == 0x00 {
			terminator = i
			break
		}
	}
	if terminator == -1 {
		return nil, ErrPINPolicyViolation
	}
	for _, b := range padded[terminator:] {
		if b != 0x00 {
			return nil, ErrPINPolicyViolation
		}
	}

	pin := padded[:terminator]
	if err := validatePINLength(pin, minLength); err != nil {
		return nil, err
	}
	return pin, nil
}

// validatePINLength enforces the CTAP 2.1 PIN length policy: non-empty, no
// more than PINMaxLength (63) bytes, and at least minLength Unicode code
// points (CTAP 2.1 §6.5.5.5 step 5, §6.4 minPINLength). A code-point count
// rather than a byte count matters once a PIN contains multi-byte UTF-8
// characters, where byte length overstates how many characters a user
// actually entered.
func validatePINLength(pin []byte, minLength int) error {
	if len(pin) == 0 || len(pin) > PINMaxLength {
		return ErrPINPolicyViolation
	}
	if utf8.RuneCount(pin) < minLength {
		return ErrPINPolicyViolation
	}
	return nil
}

// decryptBlock decrypts a single AES block using AES-256-CBC.
// For V1, expects exactly 16 bytes with a zero IV.
// For V2, expects exactly 32 bytes: 16-byte IV followed by 16-byte ciphertext.
//
// Both branches already sliced a fixed AESBlockSize/PINHashSize-sized window
// out of encrypted rather than passing its full length to CryptBlocks, so
// neither could panic on an oversized pinHashEnc even before this length
// check existed. The V2 branch's bound is tightened from a minimum to an
// exact match anyway, matching decryptPIN: CTAP 2.1 fixes pinHashEnc's
// length per protocol, so trailing bytes past that length are malformed
// input, not a length this authenticator should silently accept.
func (a *Authenticator) decryptBlock(key []byte, protocol uint8, encrypted []byte) ([]byte, error) {
	want := PINHashSize // V1: exactly 16 bytes, zero IV.
	if protocol == PINProtocol2 {
		want = AESBlockSize + PINHashSize // V2: 16-byte IV + 16-byte ciphertext.
	}
	if len(encrypted) != want {
		return nil, ErrDecryptionFailed
	}

	return decryptData(key, protocol, encrypted)
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

// decryptData is a PIN/UV auth protocol's decrypt(key, demCiphertext)
// (CTAP 2.1 §6.5.6, §6.5.7): AES-256-CBC with no padding. Protocol 1 uses an
// all-zero IV; protocol 2 reads the IV from the first 16 bytes of ciphertext.
//
// The ciphertext body must be a non-empty whole number of AES blocks, checked
// before CryptBlocks runs because CryptBlocks panics on any other length. A
// caller whose field has a fixed size per protocol checks that exact size
// first; this check is the floor that keeps every caller panic-free.
func decryptData(key []byte, protocol uint8, ciphertext []byte) ([]byte, error) {
	iv := make([]byte, AESBlockSize)
	body := ciphertext
	if protocol == PINProtocol2 {
		if len(ciphertext) < AESBlockSize {
			return nil, ErrDecryptionFailed
		}
		copy(iv, ciphertext[:AESBlockSize])
		body = ciphertext[AESBlockSize:]
	}
	if len(body) == 0 || len(body)%AESBlockSize != 0 {
		return nil, ErrDecryptionFailed
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	plaintext := make([]byte, len(body))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, body)
	return plaintext, nil
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

// beginUsingPinUvAuthTokenLocked records a freshly minted pinUvAuthToken and
// the permissions granted to it, starting the CTAP 2.1 §6.5.2.1 usage timers.
// It is the only way a token becomes usable: a token installed without going
// through here has a zero tokenIssuedAt and is rejected as expired.
//
// rpID is the permissions RP ID requested by the platform. An empty rpID
// leaves the token unbound until its first makeCredential or getAssertion,
// which binds that request's RP ID.
//
// The caller must hold a.mu for writing.
func (a *Authenticator) beginUsingPinUvAuthTokenLocked(token []byte, permissions uint8, rpID string) {
	// CTAP 2.1 §6.8 and §6.5.5.7: a credential management enumeration is
	// bound to the token that began it, so issuing a new token by any path
	// (PIN or built-in UV) discards the enumeration in progress.
	a.credMgmtState = nil

	now := time.Now()
	a.pinState.protocol.pinUvAuthToken = token
	a.pinState.protocol.tokenPermissions = permissions
	a.pinState.protocol.tokenRPID = rpID
	a.pinState.protocol.tokenIssuedAt = now
	a.pinState.protocol.tokenLastUsed = now
	a.pinState.protocol.tokenUserVerified = true
}

// stopUsingPinUvAuthTokenLocked discards the current pinUvAuthToken along with
// the permissions and permissions RP ID granted to it, per CTAP 2.1 §6.5.2.1.
//
// The caller must hold a.mu for writing.
func (a *Authenticator) stopUsingPinUvAuthTokenLocked() {
	if a.pinState.protocol == nil {
		return
	}
	// Wipe the token bytes rather than only dropping the reference, so expired
	// key material does not linger in memory until the next collection.
	enclave.Wipe(a.pinState.protocol.pinUvAuthToken)
	a.pinState.protocol.pinUvAuthToken = nil
	a.pinState.protocol.tokenPermissions = 0
	a.pinState.protocol.tokenRPID = ""
	a.pinState.protocol.tokenIssuedAt = time.Time{}
	a.pinState.protocol.tokenLastUsed = time.Time{}
	a.pinState.protocol.tokenUserVerified = false
}

// pinUvAuthTokenUsableLocked reports whether a pinUvAuthToken has been minted
// and both CTAP 2.1 §6.5.2.1 usage timers are still within their limits.
//
// The caller must hold a.mu for reading or writing.
func (a *Authenticator) pinUvAuthTokenUsableLocked(now time.Time) bool {
	p := a.pinState.protocol
	if p == nil || p.pinUvAuthToken == nil {
		return false
	}
	if p.tokenIssuedAt.IsZero() {
		return false
	}
	if now.Sub(p.tokenIssuedAt) > pinUvAuthTokenMaxUsagePeriod {
		return false
	}
	return now.Sub(p.tokenLastUsed) <= pinUvAuthTokenInactivityLimit
}

// verifyPinUvAuthTokenHMACLocked compares authParam against the HMAC of
// clientDataHash under the current pinUvAuthToken, truncating to the width
// required by the active PIN protocol version.
//
// The caller must hold a.mu for reading or writing.
func (a *Authenticator) verifyPinUvAuthTokenHMACLocked(clientDataHash, authParam []byte) bool {
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

// VerifyPinUvAuthToken verifies a PIN/UV auth token against the stored token
// and confirms the token has not outlived its CTAP 2.1 §6.5.2.1 usage timers.
//
// It deliberately says nothing about permissions or the permissions RP ID.
// Commands that a token must hold a permission for — makeCredential and
// getAssertion — must call AuthorizePinUvAuthToken instead.
func (a *Authenticator) VerifyPinUvAuthToken(clientDataHash, authParam []byte) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if !a.pinUvAuthTokenUsableLocked(time.Now()) {
		return false
	}

	return a.verifyPinUvAuthTokenHMACLocked(clientDataHash, authParam)
}

// AuthorizePinUvAuthToken authorizes one makeCredential or getAssertion
// request against the current pinUvAuthToken. It enforces, in order, the
// checks CTAP 2.1 §6.1.2 and §6.2.2 require:
//
//  1. a token exists and both usage timers are still within their limits,
//  2. authParam is a valid HMAC of clientDataHash under that token,
//  3. the token carries the permission the command needs (mc or ga),
//  4. the token's permissions RP ID, if bound, matches rpID.
//
// On success the request's RP ID is bound to the token if it was still
// unbound, and the inactivity timer is refreshed.
//
// Every failure returns ErrPINAuthInvalid — CTAP2_ERR_PIN_AUTH_INVALID — so a
// caller cannot tell a wrong HMAC from a missing permission or an RP ID
// mismatch. An expired token is discarded rather than left in place.
func (a *Authenticator) AuthorizePinUvAuthToken(clientDataHash, authParam []byte, permission uint8, rpID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	if err := a.checkPinUvAuthTokenLocked(clientDataHash, authParam, permission, rpID, now); err != nil {
		// An expired token is discarded rather than left in place. Only this
		// committing path may do so — CanAuthorizePinUvAuthToken must not have
		// side effects.
		if !a.pinUvAuthTokenUsableLocked(now) {
			a.stopUsingPinUvAuthTokenLocked()
		}
		return err
	}

	// Bind the token to this RP on first use, per CTAP 2.1 §6.1.2 / §6.2.2.
	if a.pinState.protocol.tokenRPID == "" {
		a.pinState.protocol.tokenRPID = rpID
	}
	a.pinState.protocol.tokenLastUsed = now

	return nil
}

// CanAuthorizePinUvAuthToken reports whether AuthorizePinUvAuthToken would
// succeed for this request, without consuming the token: it binds no
// permissions RP ID, refreshes no timer and discards no expired token.
//
// getAssertion needs to know whether the request counts as user-verified
// *before* it selects credentials, because CTAP 2.1 §12.1 credProtect
// filtering depends on it and §6.2.2 verifies pinUvAuthParam ahead of locating
// credentials. Asking this question must not spend the single use that the
// authoritative call later commits.
func (a *Authenticator) CanAuthorizePinUvAuthToken(clientDataHash, authParam []byte, permission uint8, rpID string) error {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.checkPinUvAuthTokenLocked(clientDataHash, authParam, permission, rpID, time.Now())
}

// checkPinUvAuthTokenLocked runs the five CTAP 2.1 checks without mutating any
// state. The caller must hold a.mu for reading or writing.
func (a *Authenticator) checkPinUvAuthTokenLocked(
	clientDataHash, authParam []byte, permission uint8, rpID string, now time.Time) error {
	if !a.pinUvAuthTokenUsableLocked(now) {
		return ErrPINAuthInvalid
	}

	if !a.verifyPinUvAuthTokenHMACLocked(clientDataHash, authParam) {
		return ErrPINAuthInvalid
	}

	if a.pinState.protocol.tokenPermissions&permission == 0 {
		if a.logger != nil {
			a.logger.Warn("pinUvAuthToken lacks the permission this command requires",
				slog.Int("required", int(permission)),
				slog.Int("granted", int(a.pinState.protocol.tokenPermissions)),
			)
		}
		return ErrPINAuthInvalid
	}

	if a.pinState.protocol.tokenRPID != "" && a.pinState.protocol.tokenRPID != rpID {
		if a.logger != nil {
			a.logger.Warn("pinUvAuthToken is bound to a different RP",
				slog.String("token_rp", a.pinState.protocol.tokenRPID),
				slog.String("request_rp", rpID),
			)
		}
		return ErrPINAuthInvalid
	}

	// getUserVerifiedFlagValue() must be true, per CTAP 2.1 §6.1.2 step 11;
	// §6.2.2 requires the same of getAssertion. It is false once a credential
	// operation has cleared the flag, which is what stops a cleared token
	// authorizing a second one.
	if !a.pinState.protocol.tokenUserVerified {
		return ErrPINAuthInvalid
	}

	return nil
}

// consumePinUvAuthToken performs the pinUvAuthToken bookkeeping CTAP 2.1
// requires once a credential operation has set the "up" bit in its response:
// clearUserVerifiedFlag() and clearPinUvAuthTokenPermissionsExceptLbw().
// §6.1.2 step 14 states it for makeCredential; §6.2.2 states the same for
// getAssertion.
//
// The effect is that one user verification authorizes one makeCredential or
// getAssertion. The platform must obtain a fresh token for the next one, which
// is what §6.5.5.7 means by "when a pinUvAuthToken is used with an operation
// that tests user presence, it is updated to remove all permissions except
// lbw". A silent (up=false) assertion sets no "up" bit and so consumes nothing.
//
// clearUserPresentFlag() has no counterpart here because this authenticator
// never caches user presence in the token: every token is minted with
// beginUsingPinUvAuthToken(userIsPresent: false), which §6.5.2.1 permits by
// allowing a user present time limit of zero.
//
// It is a no-op when no usable token exists.
func (a *Authenticator) consumePinUvAuthToken() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.pinUvAuthTokenUsableLocked(time.Now()) {
		return
	}

	a.pinState.protocol.tokenUserVerified = false
	a.pinState.protocol.tokenPermissions &= PINPermissionLargeBlobWrite
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
	copy(paddedPIN, pin)

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
	copy(paddedPIN, pin)

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

	// Prepend IV to ciphertext. Explicit buffer rather than append(iv, ...):
	// iv is currently make()d at exactly AESBlockSize so append would
	// reallocate anyway, but that is a property of this function's allocation
	// rather than of the operation, and it stops being true the moment iv is
	// sliced from a larger buffer.
	encryptedPIN := make([]byte, 0, len(iv)+len(ciphertext))
	encryptedPIN = append(encryptedPIN, iv...)
	encryptedPIN = append(encryptedPIN, ciphertext...)

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

	xBytes := padCoordinate(pub.X.Bytes(), coordSize) //nolint:staticcheck // CTAP2/COSE/ECDH protocol uses crypto/elliptic raw EC coords + ScalarMult; ecdsa big.Int access is deprecated but functional. Migrating to crypto/ecdh is a separate behavior-sensitive change.
	yBytes := padCoordinate(pub.Y.Bytes(), coordSize) //nolint:staticcheck // CTAP2/COSE/ECDH protocol uses crypto/elliptic raw EC coords + ScalarMult; ecdsa big.Int access is deprecated but functional. Migrating to crypto/ecdh is a separate behavior-sensitive change.

	coseKey := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: algorithm,
		coseKeyLabelCrv: curve,
		coseKeyLabelX:   xBytes,
		coseKeyLabelY:   yBytes,
	}

	return cbor.Marshal(coseKey)
}
