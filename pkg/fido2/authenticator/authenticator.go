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
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator/keybackend"
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

	// ErrCommandNotSupported indicates the command is a CTAP 2.1 command
	// this authenticator does not implement or has not enabled (e.g.
	// authenticatorBioEnrollment, or authenticatorClientPIN /
	// authenticatorLargeBlobs when disabled by configuration). Each of
	// these is optional per CTAP 2.1 and, per the spec, is correctly
	// declined with CTAP1_ERR_INVALID_COMMAND when the corresponding
	// capability is absent from authenticatorGetInfo.
	ErrCommandNotSupported = errors.New("authenticator: command not supported")

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

	// largeBlobPending holds an in-progress authenticatorLargeBlobs Set
	// operation assembled across possibly several CTAP2 messages. It is
	// intentionally never persisted: an interrupted multi-fragment write is
	// discarded rather than resumed, so a partial array can never be mistaken
	// for a complete, checksum-valid one. Guarded by mu.
	largeBlobPending *largeBlobPendingWrite

	// attestation is the device attestation identity: the Security
	// Officer-provisioned key and certificate chain that sign packed
	// attestation statements.
	attestation *deviceAttestationSource

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

	// auditLog records security-relevant CTAP2 events (credential creation,
	// PIN seeding). May be nil, which disables audit logging for the
	// authenticator; set post-construction via SetAuditLogger like
	// pinVerifier, since the embedding application's audit store is
	// typically wired after the Authenticator is constructed. Guarded by mu.
	auditLog AuditLogger

	// TamperDetected indicates that policy HMAC verification failed on startup.
	//
	// It is set by NewAuthenticator when Config.PolicyIntegrityProvider is
	// configured, the stored state carries a policy HMAC tag, and that tag does
	// not verify over the current PolicyFields (ErrPolicyTampered). A policy
	// signed under an older field-set schema (ErrPolicySchemaChanged) does NOT
	// set it, so a routine upgrade never locks a device.
	//
	// While set, requirePolicyIntegrity refuses every user-mode operation with
	// ErrPolicyTamperLocked (CTAP2_ERR_INTEGRITY_FAILURE); getInfo stays
	// reachable and reports the state under the policyTamperLocked option.
	//
	// The cost of a false positive is a device that serves no user until the
	// Security Officer recovers it. The flag is never cleared at runtime; the
	// SO re-signs the policy over the configuration the device actually has
	// (PolicyManager().Sign on the current state, then persist the state) and
	// re-opens the authenticator, at which point startup verification passes
	// and the lock is gone. No reflash or reset is needed, and credentials are
	// untouched.
	TamperDetected atomic.Bool

	// closed indicates whether the authenticator has been closed.
	// Uses atomic for lock-free reads.
	closed atomic.Bool

	// cmdCtx stores the command context for the currently-executing CBOR
	// command. ProcessCBORWithContext sets it before dispatching and clears it
	// after the handler returns. Internal methods that need cancellation
	// (e.g., requestUserPresence) use commandContext() to obtain it.
	cmdCtx atomic.Pointer[cmdCtxHolder]

	// cmdMu serializes ProcessCBORWithContext end to end; see the doc comment
	// there for why. It is a dedicated field rather than mu: mu is taken and
	// released repeatedly inside a single command (e.g. AuthorizePinUvAuthToken,
	// consumePinUvAuthToken), and cmdMu must stay held across all of those
	// acquisitions for the whole command, including any user-presence wait.
	cmdMu sync.Mutex

	// poweredUpAt is when this authenticator instance came up. It bounds the
	// trust-on-first-use window for token initialization (CTAP 2.1 §6.9); for a
	// software authenticator a power cycle is a process restart.
	// Guarded by mu.
	poweredUpAt time.Time

	// mu protects state modifications.
	mu sync.RWMutex

	// Assertion state for GetNextAssertion command.
	matchingCredentials    []*StoredCredential
	currentCredentialIndex int
	lastClientDataHash     []byte

	// assertionFlags holds the UP/UV authorization flags established by the
	// preceding getAssertion. Per CTAP 2.1 §6.3, getNextAssertion MUST NOT
	// collect user presence or user verification again; it replays these
	// flags for each subsequent credential in the batch.
	assertionFlags AuthDataFlags

	// assertionExtensions holds the extension inputs from the preceding
	// getAssertion so they can be recomputed per credential during
	// getNextAssertion.
	assertionExtensions map[string]interface{}
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
		poweredUpAt:          time.Now(),
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

	// Give the key backend the device attestation identity. Attestation is a
	// property of the device, not of whichever backend holds a given credential
	// key, so a single decorator in front of the configured backend keeps one
	// provenance for software, TPM2, PKCS#11 and cloud KMS credentials alike.
	// A backend that already attests — one holding its own attestation key in
	// hardware — is left alone so it keeps precedence.
	a.attestation = &deviceAttestationSource{auth: a}
	if a.keyBackend != nil {
		if _, alreadyAttests := a.keyBackend.(keybackend.FIDO2AttestingKeyBackend); !alreadyAttests {
			a.keyBackend = keybackend.NewAttestingBackend(a.keyBackend, a.attestation)
		}
	}

	// Initialize PolicyManager if a provider is configured
	if config.PolicyIntegrityProvider != nil {
		a.policyManager = NewPolicyManager(config, config.PolicyIntegrityProvider)

		// Verify policy integrity if state has an HMAC tag
		if len(state.PolicyHMACTag) > 0 {
			diag, verifyErr := a.policyManager.Verify(state)
			if verifyErr != nil {
				switch {
				case errors.Is(verifyErr, ErrPolicyTampered):
					a.TamperDetected.Store(true)
					if a.logger != nil {
						a.logger.Error("policy integrity check failed - tamper detected",
							slog.Bool("tamper_detected", true),
							slog.Any("diagnostics", diag),
						)
					}
				case errors.Is(verifyErr, ErrPolicySchemaChanged):
					// Not tampering, and not a reason to refuse to start: the
					// policy was signed over an older field set. Integrity is
					// unverified until the SO re-signs, which is what the
					// operator needs told — TamperDetected stays false so a
					// routine upgrade is never reported as an attack.
					if a.logger != nil {
						a.logger.Warn("policy was signed under a different field-set schema - integrity unverified until the SO re-signs",
							slog.Bool("tamper_detected", false),
							slog.Any("diagnostics", diag),
						)
					}
				default:
					return nil, verifyErr
				}
			}
		}
	}

	// User presence/verification policy is required, never defaulted.
	//
	// This previously installed NewAutoGrantHandler() when the field was nil.
	// That is not "no check" -- it is a check that always answers yes, so a
	// caller who simply did not know the field existed got an authenticator
	// that approved every ceremony, with nothing in its construction, logs or
	// behaviour saying so. A control either enforces or is absent; it must
	// never fabricate a pass. Callers that genuinely want unattended approval
	// say so with an explicit NewAutoGrantHandler().
	// config.Validate() above already refused a nil handler with
	// ErrUserPresenceHandlerRequired; this assignment cannot see one.
	a.upHandler = config.UserPresenceHandler

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

// AuditLogger records the authenticator's security-relevant state changes.
// The authenticator refuses the operation when a call returns an error, so
// a credential or PIN never exists without its audit record.
type AuditLogger interface {
	// LogCredentialCreated records a new credential, identified by its
	// hex-encoded credential ID, before the credential is persisted.
	LogCredentialCreated(credentialID string) error

	// LogPINSeeded records the initial PIN being established, before the
	// PIN state is persisted.
	LogPINSeeded() error
}

// SetAuditLogger sets the audit logger used to record security-relevant
// CTAP2 events (FIDO2 credential creation, PIN seeding). A nil logger
// disables audit logging for the authenticator.
func (a *Authenticator) SetAuditLogger(logger AuditLogger) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.auditLog = logger
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
	// Read the handler once, under the lock. SetUserPresenceHandler runs on the
	// UI goroutine while a CTAP command may be in flight on the transport
	// goroutine, and an interface value is two words — an unsynchronized read
	// can tear.
	handler := a.UserPresenceHandler()

	if a.logger != nil {
		a.logger.Info("requestUserPresence called",
			slog.String("operation", operation),
			slog.String("handler_type", fmt.Sprintf("%T", handler)),
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
	result, err := handler.RequestUserPresence(ctx, req)
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
//
// Commands are serialized end to end by cmdMu, including any user-presence
// wait a command performs: CTAP authenticators are single-command devices
// (the spec's transport model has one outstanding command at a time), so
// this matches the wire protocol rather than fighting it. Without it, two
// concurrent commands presenting the same pinUvAuthToken could both pass
// checkPinUvAuthTokenLocked (cmd_clientpin.go) before either reached
// consumePinUvAuthToken — authorization and consumption are separate
// critical sections under mu, so the gap between them was a TOCTOU window,
// not a data race the race detector could see (#323). Serializing every
// command closes that window by construction and also makes the
// cmdCtx.Store/defer Store(nil) single-command assumption true.
//
// The accepted trade: a command blocked on user presence (a human touching
// the key) blocks every other queued command for the whole wait, not just
// its own critical section. That is deliberate under option 1 — every
// requestUserPresence call site already releases mu before it blocks, so
// cmdMu is the only lock held across the wait, and a real CTAP authenticator
// would not be processing a second command while waiting on the first's
// touch either.
func (a *Authenticator) ProcessCBORWithContext(ctx context.Context, cmd byte, data []byte) ([]byte, error) {
	a.cmdMu.Lock()
	defer a.cmdMu.Unlock()

	if a.closed.Load() {
		return a.errorResponse(StatusOtherError), ErrAuthenticatorClosed
	}

	// A tampered policy locks every user-mode command. Discovery stays open
	// so a platform can still see the device and read its status.
	if !tamperExemptCommands[cmd] {
		if err := a.requirePolicyIntegrity(); err != nil {
			return a.errorResponseFromError(err), err
		}
	}

	// Store the command context so internal handlers can access it via
	// commandContext(). Cleared after the handler returns.
	a.cmdCtx.Store(&cmdCtxHolder{ctx: ctx})
	defer a.cmdCtx.Store(nil)

	response, err := a.dispatchCommand(cmd, data)
	if err != nil {
		return a.errorResponseFromError(err), err
	}

	return response, nil
}

// dispatchCommand routes a decoded CTAP2 command to its handler. The actual
// recover boundary is factored into recoverCommandPanic so it can be
// exercised directly by tests without relying on a handler happening to have
// a live bug to panic on.
func (a *Authenticator) dispatchCommand(cmd byte, data []byte) ([]byte, error) {
	return a.recoverCommandPanic(cmd, func() ([]byte, error) {
		switch cmd {
		case CmdGetInfo:
			return a.handleGetInfo()

		case CmdMakeCredential:
			return a.HandleMakeCredential(data)

		case CmdGetAssertion:
			return a.handleGetAssertion(data)

		case CmdGetNextAssertion:
			return a.handleGetNextAssertion()

		case CmdClientPIN:
			return a.handleClientPIN(data)

		case CmdReset:
			return a.handleReset()

		case CmdCredentialManagement:
			return a.handleCredentialManagement(data)

		case CmdSelection:
			return a.handleSelection()

		case CmdBioEnrollment:
			return a.handleBioEnrollment(data)

		case CmdLargeBlobs:
			return a.handleLargeBlobs(data)

		case CmdConfig:
			return a.handleConfig(data)

		default:
			return nil, ErrInvalidCommand
		}
	})
}

// recoverCommandPanic is the single recover boundary for the whole CTAP/uhid
// path: every handler dispatchCommand can reach runs on external, adversarial
// input (CBOR built by a platform, forwarded over a USB/BLE/NFC transport)
// with no other recover between this call and the transport's read loop, so
// a handler bug that panics -- a slice bounds panic like the one decryptPIN
// hit on a truncated newPinEnc before it validated the length (go-xkms#1149)
// -- would otherwise crash the whole daemon rather than fail the one
// command. A recovered panic is reported as ErrCommandPanicked, which
// errorToStatus's default case maps to CTAP2_ERR_OTHER, and logged with the
// command byte and a stack trace so the fault is diagnosable without a core
// dump.
//
// fn is called synchronously and its result returned unchanged when it does
// not panic; factoring the recover out of dispatchCommand's switch lets it be
// exercised with an arbitrary fn, including one that panics on purpose, from
// a test.
func (a *Authenticator) recoverCommandPanic(cmd byte, fn func() ([]byte, error)) (response []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("[CTAP2] recovered panic in command dispatch",
				"command", fmt.Sprintf("0x%02x", cmd),
				"panic", r,
				"stack", string(debug.Stack()),
			)
			response = nil
			err = ErrCommandPanicked
		}
	}()

	return fn()
}

// tamperExemptCommands are the CTAP commands that remain answerable while the
// policy is tamper-locked. Both are read-only discovery: neither touches
// credentials, PINs, or the policy, and refusing them would make a locked
// device indistinguishable from a dead one.
var tamperExemptCommands = map[byte]bool{
	CmdGetInfo:   true,
	CmdSelection: true,
}

// requirePolicyIntegrity returns ErrPolicyTamperLocked when the SO-signed
// policy failed integrity verification at startup. It is the single gate that
// makes TamperDetected enforce what its doc comment promises: user-mode
// operations are refused until the Security Officer re-signs the policy and
// the authenticator is re-opened against the re-signed state. Nothing reset
// the flag in-process before this gate existed, and nothing does now — a
// re-sign is a startup-time verification, not a runtime toggle.
func (a *Authenticator) requirePolicyIntegrity() error {
	if a.TamperDetected.Load() {
		return ErrPolicyTamperLocked
	}
	return nil
}

// commandContext returns the context for the currently-executing CBOR command.
// If no command context is set, returns context.Background().
func (a *Authenticator) commandContext() context.Context {
	if h := a.cmdCtx.Load(); h != nil && h.ctx != nil {
		return h.ctx
	}
	return context.Background()
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
		if a.logger != nil {
			a.logger.Warn("authenticator: failed to save final state on close", slog.String("error", err.Error()))
		}
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

// SetAlwaysUV enables or disables mandatory user verification for every
// operation (MakeCredential, GetAssertion, and the getInfo "alwaysUv" option
// advertised to the platform), even when the request did not ask for it.
func (a *Authenticator) SetAlwaysUV(enabled bool) {
	a.config.AlwaysUV = enabled
}

// SetUserPresenceHandler replaces the user presence handler on the
// authenticator and returns the handler it replaced, so a caller that installs
// a handler for the lifetime of a service can put the previous one back rather
// than guessing what it should be.
//
// This is used to wire an application's presence handler (xkey's IPC socket
// handler) after the authenticator is created so that USB HID touch prompts
// are routed to the GUI instead of being auto-approved.
func (a *Authenticator) SetUserPresenceHandler(handler UserPresenceHandler) UserPresenceHandler {
	a.mu.Lock()
	defer a.mu.Unlock()
	previous := a.upHandler
	a.upHandler = handler
	return previous
}

// UserPresenceHandler returns the handler currently collecting user presence.
func (a *Authenticator) UserPresenceHandler() UserPresenceHandler {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.upHandler
}

// HasMatchingCredentials performs a read-only credential lookup against
// storage to determine whether this authenticator has any credentials the
// given GetAssertion CBOR payload may use. This is used by the HID adapter to
// decide whether to defer the response (no-credentials deferral for
// multi-authenticator coexistence).
//
// The answer applies the CTAP 2.1 §12.1 credProtect rules exactly as
// getAssertion does — a level-3 credential is invisible without user
// verification, a level-2 credential is invisible to an RP enumeration
// without it — because the answer is observable on the transport: it decides
// whether the request is answered at once or deferred, and any process that
// can reach the HID interface can read that difference. Reporting a protected
// credential here would recreate the existence oracle the assertion and
// excludeList paths already close. User verification is established without
// consuming the pinUvAuthToken, so the getAssertion that follows a "match"
// still authorizes normally.
//
// The consequence for multi-authenticator deployments is that a request this
// authenticator cannot answer without user verification is deferred exactly
// as if it held nothing: a platform that wants the protected credential
// obtains a pinUvAuthToken first, which is also what commits it to this
// authenticator (see hasPINAuth). This is the intended behaviour, not a
// heuristic gap.
//
// When the storage backend is a CredentialIndexer with a ready index, the
// discoverable-credential case is answered from the index with zero storage
// I/O: the index carries each credential's protection level, so the filter
// needs no credential load. An allowList names specific credentials that are
// loaded either way; a storage backend without a ready index is scanned.
//
// Returns (hasMatch, parseable, hasPINAuth, rpID):
//   - (true, true, _, rpID):      usable credentials found — skip deferral, process normally
//   - (false, true, false, rpID):  no usable credentials, no PIN auth — enter deferral path
//   - (false, true, true, rpID):   no usable credentials, but PIN auth present — skip deferral
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

	// Establish the request's user-verification state first, as getAssertion
	// does (CTAP 2.1 §6.2.2), because §12.1 visibility depends on it.
	uvPerformed := a.assertionUserVerified(request)

	// Fast path: the discoverable-credential flow is an O(k) index check
	// with zero storage I/O when the backend maintains a ready index.
	if len(request.AllowList) == 0 {
		if indexer, ok := a.storage.(CredentialIndexer); ok && indexer.IndexReady() {
			return indexer.HasDiscoverableForRP(request.RPID, uvPerformed), true, pinAuth, request.RPID
		}
	}

	// allowList lookups and non-indexed storage load the candidates and apply
	// the same filter the assertion path applies.
	usable, err := a.usableCredentialsForAssertion(request, uvPerformed)
	if err != nil {
		return false, false, false, ""
	}

	return len(usable) > 0, true, pinAuth, request.RPID
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

// verifyPINHashLocked verifies a FIDO2 PIN hash against the stored PIN. When
// a PINVerifier is configured its result is authoritative and final — a
// negative result is never re-checked against a.state.PINHash, which could
// be stale relative to the PIN system's own source of truth. The local
// constant-time comparison against a.state.PINHash is the verification
// mechanism only for standalone mode (no PINVerifier configured, e.g. tests
// and offline authenticators), not a fallback for a verifier's failure.
// Must be called with a.mu already held (Lock or RLock).
func (a *Authenticator) verifyPINHashLocked(hash []byte) bool {
	if a.pinVerifier != nil {
		return a.pinVerifier.VerifyFIDO2Hash(hash)
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
	// An SO policy demanded attestation the authenticator cannot produce. The
	// registration is refused rather than completed with fmt=none, so the RP
	// never receives a credential asserting that no attestation was available.
	case errors.Is(err, ErrAttestationOverrideUnsupported):
		return StatusUnsupportedOption
	case errors.Is(err, ErrAttestationUnavailable):
		return StatusOperationDenied
	// An SO policy mandated enterprise attestation for an RP that is not
	// entitled to it. Refused for the same reason: a credential carrying the
	// ordinary statement under an enterprise mandate misrepresents the policy.
	case errors.Is(err, ErrEnterpriseAttestationNotEntitled):
		return StatusOperationDenied
	// The SO-signed policy failed integrity verification. CTAP2 has a status
	// for exactly this event.
	case errors.Is(err, ErrPolicyTamperLocked):
		return StatusIntegrityFailure
	case errors.Is(err, ErrPINRequired):
		return StatusPINRequired
	case errors.Is(err, ErrPINInvalid):
		return StatusPINInvalid
	case errors.Is(err, ErrPINBlocked):
		return StatusPINBlocked
	case errors.Is(err, ErrPINAuthBlocked):
		return StatusPINAuthBlocked
	case errors.Is(err, ErrPINAuthInvalid):
		return StatusPINAuthInvalid
	case errors.Is(err, ErrPINNotSet):
		return StatusPINNotSet
	case errors.Is(err, ErrPINPolicyViolation):
		return StatusPINPolicyViolation
	// Security Officer credential states. Without these every SO refusal
	// collapsed to CTAP2_ERR_OTHER (0x7F), which tells a client nothing about
	// whether to retry, to prompt, or to stop.
	case errors.Is(err, ErrSOPINRequired):
		return StatusPINRequired
	case errors.Is(err, ErrSOPINInvalid):
		return StatusPINInvalid
	case errors.Is(err, ErrSOPINBlocked):
		return StatusPINBlocked
	case errors.Is(err, ErrSOPINAuthBlocked):
		return StatusPINAuthBlocked
	case errors.Is(err, ErrSOPINNotSet):
		return StatusPINNotSet
	case errors.Is(err, ErrSOPINPolicyViolation):
		return StatusPINPolicyViolation
	case errors.Is(err, ErrSOPINAlreadySet):
		return StatusNotAllowed
	case errors.Is(err, ErrKeyManagerAlreadyInitialized):
		return StatusNotAllowed
	// PKCS#11 CKR_TOKEN_NOT_INITIALIZED has no CTAP equivalent; CTAP 2.1 uses
	// CTAP2_ERR_NOT_ALLOWED for an operation the authenticator's current state
	// forbids, which is also what §6.9 returns outside the power-up window.
	case errors.Is(err, ErrTokenUninitialized):
		return StatusNotAllowed
	case errors.Is(err, ErrTokenInitWindowClosed):
		return StatusNotAllowed
	// A Security Officer exists but has not authenticated. Distinct on the wire
	// from ErrTokenUninitialized above, where there is no credential to
	// present, because the two demand different responses from a client.
	case errors.Is(err, ErrKeyManagerLocked):
		return StatusPINRequired
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
	case errors.Is(err, ErrUnsupportedOption):
		return StatusUnsupportedOption
	case errors.Is(err, ErrPolicyTampered):
		return StatusIntegrityFailure
	case errors.Is(err, ErrStorageClosed):
		return StatusOtherError
	case errors.Is(err, ErrStorageError):
		return StatusOtherError
	case errors.Is(err, ErrCommandNotSupported):
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
	case errors.Is(err, ErrUVInvalid):
		return StatusUVInvalid
	case errors.Is(err, ErrLargeBlobsGetSetConflict):
		return StatusInvalidParameter
	// CTAP 2.1 §6.10.2 maps a missing offset or a missing length to
	// CTAP1_ERR_INVALID_PARAMETER, not CTAP2_ERR_MISSING_PARAMETER.
	case errors.Is(err, ErrLargeBlobsMissingOffset):
		return StatusInvalidParameter
	case errors.Is(err, ErrLargeBlobsMissingLength):
		return StatusInvalidParameter
	case errors.Is(err, ErrLargeBlobsInvalidLength):
		return StatusInvalidLength
	case errors.Is(err, ErrLargeBlobsSetExceedsLength):
		return StatusInvalidParameter
	case errors.Is(err, ErrLargeBlobsMissingPinUvAuthProtocol):
		return StatusMissingParameter
	case errors.Is(err, ErrLargeBlobsInvalidOffset):
		return StatusInvalidParameter
	case errors.Is(err, ErrLargeBlobsInvalidSeq):
		return StatusInvalidSeq
	case errors.Is(err, ErrLargeBlobsStorageFull):
		return StatusLargeBlobStorageFull
	case errors.Is(err, ErrLargeBlobsChecksumInvalid):
		return StatusIntegrityFailure
	default:
		return StatusOtherError
	}
}

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
	// authenticatorBioEnrollment (CTAP 2.1 §6.7) is optional and gated by the
	// "bioEnroll" option in authenticatorGetInfo, which this authenticator
	// never advertises since it has no fingerprint sensor to enroll against.
	// A conforming platform never sends it; a compliant response to one that
	// does anyway is CTAP1_ERR_INVALID_COMMAND.
	return nil, ErrCommandNotSupported
}

// handleLargeBlobs is implemented in cmd_largeblobs.go.

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
