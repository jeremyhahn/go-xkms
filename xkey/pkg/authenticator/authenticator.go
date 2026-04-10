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
	"crypto/hmac"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
)

// CTAP2 command codes as defined in the FIDO2 specification.
const (
	CmdMakeCredential       = 0x01
	CmdGetAssertion         = 0x02
	CmdGetInfo              = 0x04
	CmdClientPIN            = 0x06
	CmdReset                = 0x07
	CmdGetNextAssertion     = 0x08
	CmdBioEnrollment        = 0x09
	CmdCredentialManagement = 0x0A
	CmdSelection            = 0x0B
	CmdLargeBlobs           = 0x0C
	CmdConfig               = 0x0D
)

// CTAP2 status codes as defined in the FIDO2 specification.
const (
	StatusOK                   = 0x00
	StatusInvalidCommand       = 0x01
	StatusInvalidParameter     = 0x02
	StatusInvalidLength        = 0x03
	StatusInvalidSeq           = 0x04
	StatusTimeout              = 0x05
	StatusChannelBusy          = 0x06
	StatusLockRequired         = 0x0A
	StatusInvalidChannel       = 0x0B
	StatusCBORUnexpectedType   = 0x11
	StatusInvalidCBOR          = 0x12
	StatusMissingParameter     = 0x14
	StatusLimitExceeded        = 0x15
	StatusUnsupportedExtension = 0x16
	StatusFPDatabaseFull       = 0x17
	StatusLargeBlobStorageFull = 0x18
	StatusCredentialExcluded   = 0x19
	StatusProcessing           = 0x21
	StatusInvalidCredential    = 0x22
	StatusUserActionPending    = 0x23
	StatusOperationPending     = 0x24
	StatusNoOperations         = 0x25
	StatusUnsupportedAlgorithm = 0x26
	StatusOperationDenied      = 0x27
	StatusKeyStoreFull         = 0x28
	StatusNotBusy              = 0x29
	StatusNoOperationPending   = 0x2A
	StatusUnsupportedOption    = 0x2B
	StatusInvalidOption        = 0x2C
	StatusKeepaliveCancel      = 0x2D
	StatusNoCredentials        = 0x2E
	StatusUserActionTimeout    = 0x2F
	StatusNotAllowed           = 0x30
	StatusPINInvalid           = 0x31
	StatusPINBlocked           = 0x32
	StatusPINAuthInvalid       = 0x33
	StatusPINAuthBlocked       = 0x34
	StatusPINNotSet            = 0x35
	StatusPINRequired          = 0x36
	StatusPINPolicyViolation   = 0x37
	StatusPINTokenExpired      = 0x38
	StatusRequestTooLarge      = 0x39
	StatusActionTimeout        = 0x3A
	StatusUPRequired           = 0x3B
	StatusUVBlocked            = 0x3C
	StatusIntegrityFailure     = 0x3D
	StatusInvalidSubcommand    = 0x3E
	StatusUVInvalid            = 0x3F
	StatusOtherError           = 0x7F
)

// Authenticator errors
var (
	// ErrAuthenticatorClosed indicates the authenticator has been closed.
	ErrAuthenticatorClosed = errors.New("authenticator: authenticator closed")

	// ErrCBOREncodingFailed indicates CBOR encoding of the response failed.
	ErrCBOREncodingFailed = errors.New("authenticator: CBOR encoding failed")

	// ErrCBORDecodingFailed indicates CBOR decoding of the request failed.
	ErrCBORDecodingFailed = errors.New("authenticator: CBOR decoding failed")

	// ErrNotImplemented indicates the command is not yet implemented.
	ErrNotImplemented = errors.New("authenticator: command not implemented")

	// ErrLimitExceeded indicates a storage or operation limit has been exceeded.
	ErrLimitExceeded = errors.New("authenticator: limit exceeded")
)

// cmdCtxHolder wraps a context.Context for use with atomic.Pointer.
type cmdCtxHolder struct {
	ctx context.Context
}

// Authenticator is the main FIDO2/CTAP2 authenticator implementation.
// It processes CTAP2 commands and manages credential storage.
// All public methods are safe for concurrent use.
type Authenticator struct {
	config  *Config
	storage StatefulCredentialStorage
	state   *AuthenticatorState

	// keyBackend is the pluggable key backend for credential key operations.
	// If nil, the legacy crypto.go path is used.
	keyBackend keybackend.FIDO2KeyBackend

	// upHandler handles user presence and verification requests.
	upHandler UserPresenceHandler

	// pinState holds PIN protocol state for ClientPIN operations.
	pinState authenticatorPINState

	// credMgmtState holds enumeration state for CredentialManagement operations.
	credMgmtState *credMgmtEnumerationState

	// keyManager handles key wrapping/unwrapping for SO PIN protection.
	// May be nil if SO PIN is not configured.
	keyManager *KeyManager

	// policyManager handles policy HMAC integrity verification and signing.
	// May be nil if PolicyIntegrityProvider is not configured.
	policyManager *PolicyManager

	// rpPolicyStore provides per-RP SO-configurable policy overrides.
	// When non-nil, MakeCredential and GetAssertion check per-RP policies.
	// May be nil if no per-RP policy overrides are configured.
	rpPolicyStore RPPolicyStore

	// pinVerifier provides external PIN state queries from the PINService.
	// When non-nil, GetInfo and PIN verification delegate to this verifier.
	// When nil, the authenticator falls back to internal state.PINSet.
	pinVerifier PINVerifier

	// onCredentialCreated is an optional callback invoked after a new
	// credential is successfully stored during MakeCredential.
	onCredentialCreated func(cred *StoredCredential)

	// onAssertionCompleted is an optional callback invoked after a
	// successful GetAssertion, with the RP ID of the assertion.
	onAssertionCompleted func(rpID string)

	// logger is the structured logger for CTAP2 command diagnostics.
	logger *slog.Logger

	// TamperDetected indicates that policy HMAC verification failed on startup.
	// When true, user-mode operations should be locked until SO re-signs the policy.
	TamperDetected atomic.Bool

	// closed indicates whether the authenticator has been closed.
	// Uses atomic for lock-free reads.
	closed atomic.Bool

	// cmdCtx stores the command context for the currently-executing CBOR
	// command. ProcessCBORWithContext sets it before dispatching and clears it
	// after the handler returns. Internal methods that need cancellation
	// (e.g., requestUserPresence) use commandContext() to obtain it.
	cmdCtx atomic.Pointer[cmdCtxHolder]

	// mu protects state modifications.
	mu sync.RWMutex

	// Assertion state for GetNextAssertion command.
	matchingCredentials    []*StoredCredential
	currentCredentialIndex int
	lastClientDataHash     []byte
}

// NewAuthenticator creates a new FIDO2 authenticator with the given configuration.
// The configuration must have a valid storage backend set.
// Returns an error if the configuration is invalid.
func NewAuthenticator(config *Config) (*Authenticator, error) {
	if config == nil {
		return nil, ErrNilConfig
	}

	// Apply defaults for any unset values
	config.SetDefaults()

	// Validate the complete configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Wrap the storage if it doesn't already implement StatefulCredentialStorage
	storage, ok := config.Storage.(StatefulCredentialStorage)
	if !ok {
		return nil, ErrNilStorage
	}

	// Try to load existing state or create new state
	state, err := storage.LoadState()
	if err != nil {
		if !errors.Is(err, ErrStateNotFound) {
			return nil, err
		}
		// No existing state, create new
		state = NewAuthenticatorState()
		state.SetPINRetries(config.PINMaxRetries)
	}

	// AAGUID is a device identity property from config, not a persisted value.
	// Always apply config AAGUID so configuration changes take effect without
	// requiring state deletion.
	state.AAGUID = config.AAGUID

	a := &Authenticator{
		config:               config,
		storage:              storage,
		state:                state,
		keyBackend:           config.KeyBackend,
		onCredentialCreated:  config.OnCredentialCreated,
		onAssertionCompleted: config.OnAssertionCompleted,
		logger:               config.Logger,
	}

	// Set RP policy store if configured
	if config.RPPolicyStore != nil {
		a.rpPolicyStore = config.RPPolicyStore
	}

	// Initialize KeyManager for SO PIN protection
	a.keyManager = NewKeyManager(state, config)

	// Initialize PolicyManager if a provider is configured
	if config.PolicyIntegrityProvider != nil {
		a.policyManager = NewPolicyManager(config, config.PolicyIntegrityProvider)

		// Verify policy integrity if state has an HMAC tag
		if len(state.PolicyHMACTag) > 0 {
			diag, verifyErr := a.policyManager.Verify(state)
			if verifyErr != nil {
				if errors.Is(verifyErr, ErrPolicyTampered) {
					a.TamperDetected.Store(true)
					if a.logger != nil {
						a.logger.Error("policy integrity check failed - tamper detected",
							slog.Bool("tamper_detected", true),
							slog.Any("diagnostics", diag),
						)
					}
				} else {
					return nil, verifyErr
				}
			}
		}
	}

	// Set up user presence handler (default to auto-grant)
	if config.UserPresenceHandler != nil {
		a.upHandler = config.UserPresenceHandler
	} else {
		a.upHandler = NewAutoGrantHandler()
	}

	return a, nil
}

// SetPINVerifier sets the external PIN verifier for the authenticator.
// When set, IsPINSet() and PIN verification commands delegate to this verifier.
// When nil, the authenticator falls back to internal state.PINSet.
func (a *Authenticator) SetPINVerifier(v PINVerifier) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pinVerifier = v
}

// SetFIDO2PINHash sets the authenticator's FIDO2 PIN hash directly.
// This is called by PINService when a user PIN is set or changed.
// The hash must be SHA-256(PIN)[:16] as required by CTAP2.
func (a *Authenticator) SetFIDO2PINHash(hash []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.state.PINHash = make([]byte, len(hash))
	copy(a.state.PINHash, hash)
	a.state.PINSet = true
	a.state.ResetPINRetries()

	if err := a.storage.SaveState(a.state); err != nil {
		if a.logger != nil {
			a.logger.Warn("SetFIDO2PINHash: failed to persist state",
				"error", err)
		}
	}
}

// GetState returns the authenticator's internal state.
func (a *Authenticator) GetState() *AuthenticatorState {
	return a.state
}

// SyncPINHash sets the authenticator's PIN hash directly, bypassing the
// CTAP2 clientPin flow. This is used for PIN propagation from sealed storage
// at startup.
// The pinHash must be the first 16 bytes of SHA-256(rawPIN).
func (a *Authenticator) SyncPINHash(pinHash []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.state.PINHash = make([]byte, len(pinHash))
	copy(a.state.PINHash, pinHash)
	a.state.PINSet = true
	a.state.ResetPINRetries()

	if err := a.storage.SaveState(a.state); err != nil {
		if a.logger != nil {
			a.logger.Warn("SyncPINHash: failed to persist state",
				"error", err)
		}
	}
}

// GetKeyManager returns the authenticator's key manager.
// May return nil if SO PIN is not configured.
func (a *Authenticator) GetKeyManager() *KeyManager {
	return a.keyManager
}

// PolicyManager returns the authenticator's policy manager.
// May return nil if policy integrity checking is not configured.
func (a *Authenticator) PolicyManager() *PolicyManager {
	return a.policyManager
}

// RPPolicyStore returns the authenticator's per-RP policy store.
// May return nil if per-RP policy overrides are not configured.
func (a *Authenticator) RPPolicyStore() RPPolicyStore {
	return a.rpPolicyStore
}

// requestUserPresence requests user presence confirmation via the configured handler.
func (a *Authenticator) requestUserPresence(ctx context.Context, rpID, rpName, userName, operation string) error {
	if a.logger != nil {
		a.logger.Info("requestUserPresence called",
			slog.String("operation", operation),
			slog.String("handler_type", fmt.Sprintf("%T", a.upHandler)),
		)
	}

	req := &UserPresenceRequest{
		RPID:      rpID,
		RPName:    rpName,
		UserName:  userName,
		Operation: operation,
		Timeout:   a.config.UserPresenceTimeout,
	}

	if a.logger != nil {
		a.logger.Info("calling upHandler.RequestUserPresence")
	}
	result, err := a.upHandler.RequestUserPresence(ctx, req)
	if a.logger != nil {
		a.logger.Info("upHandler.RequestUserPresence returned",
			slog.Bool("has_result", result != nil),
			slog.Bool("has_error", err != nil),
		)
	}
	if err != nil {
		if a.logger != nil {
			a.logger.Error("RequestUserPresence error", slog.String("error", err.Error()))
		}
		return err
	}
	if !result.Approved {
		return ErrUserPresenceRequired
	}
	return nil
}

// ProcessCBOR handles a CTAP2 command and returns the response.
// cmd is the CTAP command byte, data is the CBOR-encoded request payload.
// Returns the response with status byte prepended: [status][cbor_response].
// For errors, returns [status_code] with no additional data.
func (a *Authenticator) ProcessCBOR(cmd byte, data []byte) ([]byte, error) {
	return a.ProcessCBORWithContext(context.Background(), cmd, data)
}

// ProcessCBORWithContext handles a CTAP2 command with a cancellable context.
// The context is propagated to user presence requests, allowing external
// cancellation (e.g., via CTAPHID_CANCEL) to abort blocking operations.
func (a *Authenticator) ProcessCBORWithContext(ctx context.Context, cmd byte, data []byte) ([]byte, error) {
	if a.closed.Load() {
		return a.errorResponse(StatusOtherError), ErrAuthenticatorClosed
	}

	// Store the command context so internal handlers can access it via
	// commandContext(). Cleared after the handler returns.
	a.cmdCtx.Store(&cmdCtxHolder{ctx: ctx})
	defer a.cmdCtx.Store(nil)

	var response []byte
	var err error

	switch cmd {
	case CmdGetInfo:
		response, err = a.handleGetInfo()

	case CmdMakeCredential:
		response, err = a.HandleMakeCredential(data)

	case CmdGetAssertion:
		response, err = a.handleGetAssertion(data)

	case CmdGetNextAssertion:
		response, err = a.handleGetNextAssertion()

	case CmdClientPIN:
		response, err = a.handleClientPIN(data)

	case CmdReset:
		response, err = a.handleReset()

	case CmdCredentialManagement:
		response, err = a.handleCredentialManagement(data)

	case CmdSelection:
		response, err = a.handleSelection()

	case CmdBioEnrollment:
		response, err = a.handleBioEnrollment(data)

	case CmdLargeBlobs:
		response, err = a.handleLargeBlobs(data)

	case CmdConfig:
		response, err = a.handleConfig(data)

	default:
		return a.errorResponse(StatusInvalidCommand), ErrInvalidCommand
	}

	if err != nil {
		return a.errorResponseFromError(err), err
	}

	return response, nil
}

// commandContext returns the context for the currently-executing CBOR command.
// If no command context is set, returns context.Background().
func (a *Authenticator) commandContext() context.Context {
	if h := a.cmdCtx.Load(); h != nil && h.ctx != nil {
		return h.ctx
	}
	return context.Background()
}

// backendID returns the current key backend identifier string.
// Returns empty string when no key backend is configured (legacy path),
// which means software for backward compatibility.
func (a *Authenticator) backendID() types.BackendType {
	if a.keyBackend != nil {
		return a.keyBackend.Type()
	}
	return ""
}

// Close releases authenticator resources and saves final state.
// After Close is called, all ProcessCBOR calls will return ErrAuthenticatorClosed.
// Note: Close does NOT close the underlying storage, since the storage lifecycle
// is owned by the caller (e.g., the App). The caller is responsible for closing
// the storage when it is no longer needed.
func (a *Authenticator) Close() error {
	if a.closed.Swap(true) {
		return nil // Already closed
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Save final state before closing
	if err := a.storage.SaveState(a.state); err != nil {
		// Log but don't fail close
		_ = err
	}

	// Close the key backend if present
	if a.keyBackend != nil {
		if err := a.keyBackend.Close(); err != nil {
			return err
		}
	}

	return nil
}

// SetOnCredentialCreated sets a callback that is invoked after a credential
// is successfully stored during MakeCredential. This allows external
// components (e.g., GUI services) to react to credential creation events.
func (a *Authenticator) SetOnCredentialCreated(fn func(cred *StoredCredential)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onCredentialCreated = fn
}

// SetOnAssertionCompleted sets a callback that is invoked after a successful
// GetAssertion. The callback receives the RP ID of the completed assertion.
// This allows external components (e.g., AutoFillService) to suppress
// autofill during post-ceremony page navigations.
func (a *Authenticator) SetOnAssertionCompleted(fn func(rpID string)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onAssertionCompleted = fn
}

// Config returns the authenticator configuration.
func (a *Authenticator) Config() *Config {
	return a.config
}

// SetEnableUserIntentCheck enables or disables the user intent check for
// GetAssertion. When enabled, the authenticator shows a user presence dialog
// before returning StatusPINRequired, allowing the user to decline and use
// a different security key in multi-authenticator setups.
func (a *Authenticator) SetEnableUserIntentCheck(enabled bool) {
	a.config.EnableUserIntentCheck = enabled
}

// SetRequireUserPresence enables or disables the requirement for user presence
// even when PIN authentication succeeds. When false, valid PIN authentication
// implicitly satisfies the user presence requirement per CTAP2 spec.
func (a *Authenticator) SetRequireUserPresence(required bool) {
	a.config.RequireUserPresence = required
}

// SetUserPresenceHandler replaces the user presence handler on the
// authenticator. This is used to wire the SocketHandler after the
// authenticator is created so that USB HID touch prompts are routed
// to the GUI instead of being auto-approved.
func (a *Authenticator) SetUserPresenceHandler(handler UserPresenceHandler) {
	a.upHandler = handler
}

// HasMatchingCredentials performs a read-only credential lookup against
// storage to determine whether this authenticator has any credentials
// matching the given GetAssertion CBOR payload. This is used by the HID
// adapter to decide whether to defer the response (no-credentials deferral
// for multi-authenticator coexistence).
//
// Returns (hasMatch, parseable, hasPINAuth, rpID):
//   - (true, true, _, rpID):      credentials found — skip deferral, process normally
//   - (false, true, false, rpID):  no credentials, no PIN auth — enter deferral path
//   - (false, true, true, rpID):   no credentials, but PIN auth present — skip deferral
//     (Chrome already exchanged PINs, committed to this authenticator)
//   - (false, false, false, ""):   parse/storage error — skip deferral, let normal
//     processing return the appropriate error code
func (a *Authenticator) HasMatchingCredentials(data []byte) (hasMatch bool, parseable bool, hasPINAuth bool, rpID string) {
	if a.closed.Load() {
		return false, false, false, ""
	}

	request, err := decodeGetAssertionRequest(data)
	if err != nil {
		return false, false, false, ""
	}

	pinAuth := len(request.PINUVAuthParam) > 0

	// Fast path: use the CredentialIndexer for O(1) existence checks
	// when the storage backend maintains a ready in-memory metadata index.
	if indexer, ok := a.storage.(CredentialIndexer); ok && indexer.IndexReady() {
		if len(request.AllowList) > 0 {
			// Check each allowList ID against storage
			for _, desc := range request.AllowList {
				if desc.Type != "public-key" {
					continue
				}
				cred, loadErr := a.storage.Load(desc.ID)
				if loadErr != nil {
					continue
				}
				if cred.RPID == request.RPID {
					return true, true, pinAuth, request.RPID
				}
			}
			return false, true, pinAuth, request.RPID
		}
		// Discoverable credential flow: O(1) index check, zero storage I/O
		return indexer.HasDiscoverableForRP(request.RPID), true, pinAuth, request.RPID
	}

	// Fallback: full scan for non-indexed storage or index not yet ready
	creds, err := a.findMatchingCredentialsForAssertion(request)
	if err != nil {
		return false, false, false, ""
	}

	return len(creds) > 0, true, pinAuth, request.RPID
}

// NeedsPINBeforeTouch reports whether the given CBOR command will require
// PIN verification before user presence.  When true, the HID layer should
// send KeepaliveStatusProcessing (not UpNeeded) so the browser does not
// prematurely display a "Touch your security key" prompt.
//
// The check is lightweight: it only peeks at the CBOR map for the
// presence of pinUvAuthParam (key 0x06 for GetAssertion, key 0x08 for
// MakeCredential).  If PIN is enabled, set, and the request does NOT
// carry pinUvAuthParam, the authenticator will return ErrPINRequired —
// no touch is needed at that stage.
func (a *Authenticator) NeedsPINBeforeTouch(cmd byte, data []byte) bool {
	if !a.config.EnablePIN || !a.IsPINSet() {
		return false
	}

	var pinAuthKey int
	switch cmd {
	case CmdGetAssertion:
		pinAuthKey = getAssertionParamPINUVAuthParam // 0x06
	case CmdMakeCredential:
		pinAuthKey = makeCredentialKeyPINUVAuthParam // 0x08
	default:
		return false
	}

	// Quick CBOR decode into a raw map to check for the pinUvAuthParam key.
	var params map[int]cbor.RawMessage
	if err := cbor.Unmarshal(data, &params); err != nil {
		return false
	}

	_, hasPINAuth := params[pinAuthKey]
	return !hasPINAuth
}

// State returns the current authenticator state.
// Note: Modifications to the returned state may affect the authenticator.
func (a *Authenticator) State() *AuthenticatorState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.state
}

// AAGUID returns the authenticator's Attestation GUID.
func (a *Authenticator) AAGUID() [16]byte {
	return a.state.AAGUID
}

// IsPINSet returns true if a PIN has been configured.
// When a PINVerifier is set, it is the source of truth.
// Falls back to internal state.PINSet when no verifier is available.
func (a *Authenticator) IsPINSet() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.isPINSetLocked()
}

// isPINSetLocked returns whether a PIN is configured.
// Delegates to PINVerifier when available, falls back to a.state.PINSet.
// Must be called with a.mu already held (Lock or RLock).
func (a *Authenticator) isPINSetLocked() bool {
	if a.pinVerifier != nil {
		return a.pinVerifier.IsPINSet()
	}
	return a.state.PINSet
}

// verifyPINHashLocked verifies a FIDO2 PIN hash against the stored PIN.
// Delegates to PINVerifier.VerifyFIDO2Hash when available, falls back to
// constant-time comparison against a.state.PINHash for standalone mode
// or lazy-init scenarios where the verifier may not have the hash yet.
// Must be called with a.mu already held (Lock or RLock).
func (a *Authenticator) verifyPINHashLocked(hash []byte) bool {
	if a.pinVerifier != nil {
		if a.pinVerifier.VerifyFIDO2Hash(hash) {
			return true
		}
		// Verifier failed — fall through to local hash comparison for
		// backward compatibility during lazy-init or sync race scenarios.
	}
	if len(a.state.PINHash) == 0 || len(hash) == 0 {
		return false
	}
	return hmac.Equal(hash, a.state.PINHash)
}

// PINRetries returns the current number of remaining PIN attempts.
func (a *Authenticator) PINRetries() int {
	return a.state.PINRetries()
}

// Storage returns the underlying credential storage.
// This provides access to the storage for direct operations.
func (a *Authenticator) Storage() CredentialStorage {
	return a.storage
}

// errorResponse creates a response with just the status code.
func (a *Authenticator) errorResponse(status byte) []byte {
	return []byte{status}
}

// successResponse creates a response with status OK and CBOR-encoded data.
func (a *Authenticator) successResponse(data []byte) []byte {
	response := make([]byte, 1+len(data))
	response[0] = StatusOK
	copy(response[1:], data)
	return response
}

// errorResponseFromError maps an error to the appropriate CTAP status code.
func (a *Authenticator) errorResponseFromError(err error) []byte {
	status := errorToStatus(err)
	return []byte{status}
}

// errorToStatus maps an error to a CTAP2 status code.
func errorToStatus(err error) byte {
	if err == nil {
		return StatusOK
	}

	switch {
	case errors.Is(err, ErrInvalidCommand):
		return StatusInvalidCommand
	case errors.Is(err, ErrInvalidParameter):
		return StatusInvalidParameter
	case errors.Is(err, ErrCBORDecodingFailed):
		return StatusInvalidCBOR
	case errors.Is(err, ErrCredentialNotFound):
		return StatusNoCredentials
	case errors.Is(err, ErrNoCredentials):
		return StatusNoCredentials
	case errors.Is(err, ErrOperationDenied):
		return StatusOperationDenied
	case errors.Is(err, ErrRPBlocked):
		return StatusOperationDenied
	case errors.Is(err, ErrPINRequired):
		return StatusPINRequired
	case errors.Is(err, ErrPINInvalid):
		return StatusPINInvalid
	case errors.Is(err, ErrPINBlocked):
		return StatusPINBlocked
	case errors.Is(err, ErrPINAuthInvalid):
		return StatusPINAuthInvalid
	case errors.Is(err, ErrPINNotSet):
		return StatusPINNotSet
	case errors.Is(err, ErrPINPolicyViolation):
		return StatusPINPolicyViolation
	case errors.Is(err, ErrInvalidSubcommand):
		return StatusInvalidSubcommand
	case errors.Is(err, ErrUnsupportedPINProtocol):
		return StatusInvalidParameter
	case errors.Is(err, ErrUserPresenceDenied):
		return StatusOperationDenied
	case errors.Is(err, context.Canceled):
		return StatusKeepaliveCancel
	case errors.Is(err, ErrUserPresenceTimeout):
		return StatusUserActionTimeout
	case errors.Is(err, ErrUserPresenceRequired):
		return StatusUPRequired
	case errors.Is(err, ErrUserVerificationRequired):
		return StatusUVBlocked
	case errors.Is(err, ErrCredentialExcluded):
		return StatusCredentialExcluded
	case errors.Is(err, ErrUnsupportedExtension):
		return StatusUnsupportedExtension
	case errors.Is(err, ErrPolicyTampered):
		return StatusIntegrityFailure
	case errors.Is(err, ErrStorageClosed):
		return StatusOtherError
	case errors.Is(err, ErrStorageError):
		return StatusOtherError
	case errors.Is(err, ErrNotImplemented):
		return StatusInvalidCommand
	case errors.Is(err, ErrCredMgmtNotEnabled):
		return StatusInvalidCommand
	case errors.Is(err, ErrLimitExceeded):
		return StatusLimitExceeded
	case errors.Is(err, ErrUnsupportedCryptoAlgorithm):
		return StatusUnsupportedAlgorithm
	case errors.Is(err, ErrNoSupportedAlgorithm):
		return StatusUnsupportedAlgorithm
	case errors.Is(err, ErrMissingClientDataHash):
		return StatusMissingParameter
	case errors.Is(err, ErrMissingRP):
		return StatusMissingParameter
	case errors.Is(err, ErrMissingRPID):
		return StatusMissingParameter
	case errors.Is(err, ErrMissingUser):
		return StatusMissingParameter
	case errors.Is(err, ErrMissingUserID):
		return StatusMissingParameter
	case errors.Is(err, ErrMissingPubKeyCredParams):
		return StatusMissingParameter
	case errors.Is(err, ErrMissingCredentialID):
		return StatusMissingParameter
	case errors.Is(err, ErrMissingRPIDHash):
		return StatusMissingParameter
	case errors.Is(err, ErrMissingUserInfo):
		return StatusMissingParameter
	case errors.Is(err, ErrResidentKeyLimitReached):
		return StatusKeyStoreFull
	case errors.Is(err, ErrCredentialLimitReached):
		return StatusKeyStoreFull
	case errors.Is(err, ErrNoEnumerationInProgress):
		return StatusNoCredentials
	case errors.Is(err, ErrUVBlocked):
		return StatusUVBlocked
	default:
		return StatusOtherError
	}
}

// Placeholder handlers for unimplemented commands.
// These will be implemented in separate files.

func (a *Authenticator) handleSelection() ([]byte, error) {
	// CTAP2.1 authenticatorSelection: indicates the authenticator is present
	// and ready. For a virtual authenticator, always auto-approve — the user
	// selected xkey by having it running. Requiring touch here would create a
	// redundant interaction before the PIN dialog, causing the user to
	// experience touch→PIN→touch instead of just PIN→touch.
	//
	// The user intent check feature (EnableUserIntentCheck) is implemented in
	// MakeCredential/GetAssertion where it shows a touch dialog BEFORE
	// returning ErrPINRequired, giving multi-authenticator users a chance to
	// decline without an extra Selection-level prompt.
	return a.successResponse(nil), nil
}

func (a *Authenticator) handleBioEnrollment(data []byte) ([]byte, error) {
	// Biometric enrollment is not supported in software authenticator
	return nil, ErrNotImplemented
}

func (a *Authenticator) handleLargeBlobs(data []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

// ctap2EncMode is the CBOR encoder configured for CTAP2 compliance.
// CTAP2 requires canonical CBOR encoding with keys sorted in ascending order.
var ctap2EncMode cbor.EncMode

func init() {
	// Initialize CTAP2-compliant CBOR encoder.
	// SortCanonical sorts integer keys in ascending order as required by CTAP2.
	em, err := cbor.EncOptions{
		Sort: cbor.SortCanonical,
	}.EncMode()
	if err != nil {
		panic("failed to create CTAP2 CBOR encoder: " + err.Error())
	}
	ctap2EncMode = em
}

// encodeCBOR encodes a value to CBOR using CTAP2-compliant canonical encoding.
// Keys are sorted in ascending order as required by the CTAP2 specification.
func encodeCBOR(v interface{}) ([]byte, error) {
	data, err := ctap2EncMode.Marshal(v)
	if err != nil {
		return nil, ErrCBOREncodingFailed
	}
	return data, nil
}

// decodeCBOR decodes CBOR data into a value.
func decodeCBOR(data []byte, v interface{}) error {
	if err := cbor.Unmarshal(data, v); err != nil {
		return ErrCBORDecodingFailed
	}
	return nil
}
