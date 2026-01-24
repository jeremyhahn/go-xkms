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
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-keychain/pkg/fido2/authenticator/keybackend"
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

	// closed indicates whether the authenticator has been closed.
	// Uses atomic for lock-free reads.
	closed atomic.Bool

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
		state.AAGUID = config.AAGUID
		state.SetPINRetries(config.PINMaxRetries)
	}

	a := &Authenticator{
		config:     config,
		storage:    storage,
		state:      state,
		keyBackend: config.KeyBackend,
	}

	// Set up user presence handler (default to auto-grant)
	if config.UserPresenceHandler != nil {
		a.upHandler = config.UserPresenceHandler
	} else {
		a.upHandler = NewAutoGrantHandler()
	}

	return a, nil
}

// requestUserPresence requests user presence confirmation via the configured handler.
func (a *Authenticator) requestUserPresence(ctx context.Context, rpID, rpName, userName, operation string) error {
	req := &UserPresenceRequest{
		RPID:      rpID,
		RPName:    rpName,
		UserName:  userName,
		Operation: operation,
		Timeout:   a.config.UserPresenceTimeout,
	}

	result, err := a.upHandler.RequestUserPresence(ctx, req)
	if err != nil {
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
	if a.closed.Load() {
		return a.errorResponse(StatusOtherError), ErrAuthenticatorClosed
	}

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

// Close releases authenticator resources and closes the underlying storage.
// After Close is called, all ProcessCBOR calls will return ErrAuthenticatorClosed.
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

	var errs []error

	// Close the key backend if present
	if a.keyBackend != nil {
		if err := a.keyBackend.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// Close storage
	if err := a.storage.Close(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// Config returns the authenticator configuration.
func (a *Authenticator) Config() *Config {
	return a.config
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
func (a *Authenticator) IsPINSet() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.state.PINSet
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
	case errors.Is(err, ErrUserPresenceRequired):
		return StatusUPRequired
	case errors.Is(err, ErrUserVerificationRequired):
		return StatusUVBlocked
	case errors.Is(err, ErrCredentialExcluded):
		return StatusCredentialExcluded
	case errors.Is(err, ErrUnsupportedExtension):
		return StatusUnsupportedExtension
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
	default:
		return StatusOtherError
	}
}

// Placeholder handlers for unimplemented commands.
// These will be implemented in separate files.

func (a *Authenticator) handleSelection() ([]byte, error) {
	// Selection command requires user presence.
	// For now, we assume user presence is always granted in software authenticator.
	return a.successResponse(nil), nil
}

func (a *Authenticator) handleBioEnrollment(data []byte) ([]byte, error) {
	// Biometric enrollment is not supported in software authenticator
	return nil, ErrNotImplemented
}

func (a *Authenticator) handleLargeBlobs(data []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

func (a *Authenticator) handleConfig(data []byte) ([]byte, error) {
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
