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
	"io"
	"log/slog"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
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
	// was minted under. This path runs only when no PIN was set, but a token
	// can still be outstanding: getPinUvAuthTokenUsingUvWithPermissions mints
	// one against the authenticator's built-in user verification and never
	// asks whether a PIN exists. Establishing a PIN must not leave that token
	// usable.
	//
	// Placed after the new PIN is accepted into a.state and before it is
	// persisted, so a storage failure cannot leave a live token behind a PIN
	// the authenticator already considers set. Every refusal returned above,
	// so a failed establishment never discards the token.
	a.stopUsingPinUvAuthTokenLocked()

	// OpPINSeeded is SeveritySecurity (xkey/pkg/audit/severity.go): the
	// audit record is written before the new PIN state is persisted, so a
	// failed write refuses the establishment rather than leave an unaudited
	// PIN in storage. LogPINOperation already applies the write-failure
	// policy (informational operations log-and-continue and return nil;
	// SeveritySecurity operations, which this is, return
	// *audit.ErrAuditWriteFailed on a failed write) — the same call
	// pkg/gui/services/pin_service.go makes for OpPINChanged/OpSOPINChanged.
	if a.auditLog != nil {
		if err := a.auditLog.LogPINOperation(audit.OpPINSeeded, "fido2", true, nil, nil); err != nil {
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

	// Decrypt the new PIN.
	newPIN, err := a.decryptPIN(encKey, req.PinUvAuthProtocol, req.NewPinEnc)
	if err != nil {
		return nil, err
	}

	// Validate PIN length.
	if len(newPIN) < a.config.PINMinLength {
		return nil, ErrPINPolicyViolation
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
	a.beginUsingPinUvAuthTokenLocked(pinToken, req.Permissions, req.RPID)

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
			"pinHashEnc_len", len(req.PinHashEnc),
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
// Returns ErrStorageError if the decremented (or, on success, reset) retry
// counter could not be persisted, ErrPINBlocked if the retry budget is now
// exhausted, and ErrPINInvalid if candidateHash does not match.
//
// The caller must hold a.mu for writing.
func (a *Authenticator) verifyPinHashAndConsumeRetryLocked(candidateHash []byte) error {
	a.state.DecrementPINRetries()
	if err := a.storage.SaveState(a.state); err != nil {
		return errors.Join(ErrStorageError, err)
	}

	if !a.verifyPINHashLocked(candidateHash) {
		if a.state.PINRetries() <= 0 {
			return ErrPINBlocked
		}
		return ErrPINInvalid
	}

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
