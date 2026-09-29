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

package rest

import (
	"encoding/json"
	"errors"
	"net/http"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/api/rest/secureio"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The system-barrier and PIN handlers delegate to the XKMSService and never
// to the barrier or PIN backend directly: both are platform-global, and the
// service's requirePlatformScope is what refuses a tenant-scoped caller
// (go-xkms#1227). The routes' seal:*, barrier:* and pin:* grants cannot,
// because a tenant-local Admin's self-scoped grants resolve against its own
// tenant. The refusal is xkms.TenantBindingError, which unwraps to
// qrdbsdk.ErrTenantMissing and answers 404 exactly as a genuine miss.

// Barrier/PIN handler typed errors.
var (
	ErrBarrierNotConfigured    = errors.New("rest: barrier not configured")
	ErrPasswordTooLarge        = errors.New("rest: password exceeds maximum length")
	ErrPINManagerNotConfigured = errors.New("rest: PIN manager not configured")
	ErrMissingSecret           = errors.New("rest: missing secret")
	ErrMissingPIN              = errors.New("rest: missing pin")
	ErrMissingSOPIN            = errors.New("rest: missing so_pin")
	ErrMissingNewPIN           = errors.New("rest: missing new_pin")
	ErrMissingNewSOPIN         = errors.New("rest: missing new_so_pin")
	ErrMissingCurrentPIN       = errors.New("rest: missing current_pin")
	ErrMissingCurrentSOPIN     = errors.New("rest: missing current_so_pin")
)

// --- Barrier request/response types ---

// BarrierInitializeRequest represents the request to initialize the
// barrier. Password carries the secret inside a memguard enclave.
//
// Wire format note: the secret MUST be submitted in the password_b64 field
// (standard base64, no padding stripped). The server destroys the Buffer via
// defer as soon as the barrier call returns.
type BarrierInitializeRequest struct {
	Password secureio.PasswordField `json:"password_b64,omitempty"`
}

// BarrierUnsealRequest represents the request to unseal the barrier. See
// BarrierInitializeRequest for wire-format notes.
type BarrierUnsealRequest struct {
	Password secureio.PasswordField `json:"password_b64,omitempty"`
}

// --- PIN request/response types ---

// SetSOPINRequest represents the request to set the SO PIN.
type SetSOPINRequest struct {
	CurrentSOPIN string `json:"current_so_pin"`
	NewSOPIN     string `json:"new_so_pin"`
}

// SetUserPINRequest represents the request to set the user PIN.
type SetUserPINRequest struct {
	SOPIN      string `json:"so_pin"`
	NewUserPIN string `json:"new_user_pin"`
}

// ChangeSOPINRequest represents the request to change the SO PIN.
type ChangeSOPINRequest struct {
	CurrentSOPIN string `json:"current_so_pin"`
	NewSOPIN     string `json:"new_so_pin"`
}

// ChangeUserPINRequest represents the request to change the user PIN.
type ChangeUserPINRequest struct {
	CurrentUserPIN string `json:"current_user_pin"`
	NewUserPIN     string `json:"new_user_pin"`
}

// VerifyPINRequest represents the request to verify a PIN.
type VerifyPINRequest struct {
	PIN string `json:"pin"`
}

// ResetLockoutRequest represents the request to reset the lockout counter.
type ResetLockoutRequest struct {
	SOPIN string `json:"so_pin"`
}

// --- Barrier handlers ---

// BarrierInitializeHandler handles POST /v1/barrier/initialize requests.
// Initializes the barrier with a new root key sealed using the best available strategy.
func (h *HandlerContext) BarrierInitializeHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrBarrierNotConfigured, http.StatusServiceUnavailable)
		return
	}

	var req BarrierInitializeRequest
	// Install cleanup BEFORE Decode: a duplicate-member body can allocate a
	// protected buffer during UnmarshalJSON and then fail, and the decode-error
	// return path would otherwise skip Destroy (defense in depth for #121;
	// UnmarshalJSON already destroys prior buffers on every early return).
	defer req.Password.Destroy()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if errors.Is(err, secureio.ErrPasswordTooLarge) {
			writeError(w, ErrPasswordTooLarge, http.StatusRequestEntityTooLarge)
			return
		}
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	creds, ok, err := barrierCredentialsFromRequest(req.Password)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	if !ok {
		writeError(w, ErrMissingSecret, http.StatusBadRequest)
		return
	}
	defer creds.Secret.Destroy()
	if err := h.xkmsService.BarrierInitializeWithCredentials(r.Context(), creds); err != nil {
		handleBarrierError(w, err)
		return
	}

	writeJSON(w, &SuccessResponse{
		Success: true,
		Message: "barrier initialized",
	}, http.StatusOK)
}

// BarrierUnsealHandler handles POST /v1/barrier/unseal requests.
// Unseals the barrier using the provided credentials.
func (h *HandlerContext) BarrierUnsealHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrBarrierNotConfigured, http.StatusServiceUnavailable)
		return
	}

	var req BarrierUnsealRequest
	// Install cleanup BEFORE Decode: a duplicate-member body can allocate a
	// protected buffer during UnmarshalJSON and then fail, and the decode-error
	// return path would otherwise skip Destroy (defense in depth for #121;
	// UnmarshalJSON already destroys prior buffers on every early return).
	defer req.Password.Destroy()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if errors.Is(err, secureio.ErrPasswordTooLarge) {
			writeError(w, ErrPasswordTooLarge, http.StatusRequestEntityTooLarge)
			return
		}
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	creds, ok, err := barrierCredentialsFromRequest(req.Password)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	if !ok {
		writeError(w, ErrMissingSecret, http.StatusBadRequest)
		return
	}
	defer creds.Secret.Destroy()
	if err := h.xkmsService.BarrierUnsealWithCredentials(r.Context(), creds); err != nil {
		handleBarrierError(w, err)
		return
	}

	writeJSON(w, &SuccessResponse{
		Success: true,
		Message: "barrier unsealed",
	}, http.StatusOK)
}

// BarrierSealHandler handles POST /v1/barrier/seal requests.
// Seals the barrier, zeroing the DEK and blocking further operations.
func (h *HandlerContext) BarrierSealHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrBarrierNotConfigured, http.StatusServiceUnavailable)
		return
	}

	if err := h.xkmsService.BarrierSeal(r.Context()); err != nil {
		handleBarrierError(w, err)
		return
	}

	writeJSON(w, &SuccessResponse{
		Success: true,
		Message: "barrier sealed",
	}, http.StatusOK)
}

// BarrierStatusHandler handles GET /v1/barrier/status requests.
// Returns the current barrier status including seal state and active strategy.
func (h *HandlerContext) BarrierStatusHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrBarrierNotConfigured, http.StatusServiceUnavailable)
		return
	}

	status, err := h.xkmsService.BarrierStatus(r.Context())
	if err != nil {
		handleBarrierError(w, err)
		return
	}
	writeJSON(w, status, http.StatusOK)
}

// --- PIN handlers ---

// SetSOPINHandler handles POST /v1/pin/so-pin requests.
// Sets the Security Officer PIN.
func (h *HandlerContext) SetSOPINHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrPINManagerNotConfigured, http.StatusServiceUnavailable)
		return
	}

	var req SetSOPINRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.NewSOPIN == "" {
		writeError(w, ErrMissingNewSOPIN, http.StatusBadRequest)
		return
	}

	if err := h.xkmsService.SetSOPIN(r.Context(), &transport.SetSOPINRequest{CurrentSOPIN: req.CurrentSOPIN, NewSOPIN: req.NewSOPIN}); err != nil {
		handlePINError(w, err)
		return
	}

	writeJSON(w, &SuccessResponse{
		Success: true,
		Message: "SO PIN set",
	}, http.StatusOK)
}

// SetUserPINHandler handles POST /v1/pin/user-pin requests.
// Sets the user PIN, requiring SO PIN authorization.
func (h *HandlerContext) SetUserPINHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrPINManagerNotConfigured, http.StatusServiceUnavailable)
		return
	}

	var req SetUserPINRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.SOPIN == "" {
		writeError(w, ErrMissingSOPIN, http.StatusBadRequest)
		return
	}

	if req.NewUserPIN == "" {
		writeError(w, ErrMissingNewPIN, http.StatusBadRequest)
		return
	}

	if err := h.xkmsService.SetUserPIN(r.Context(), &transport.SetUserPINRequest{SOPIN: req.SOPIN, NewUserPIN: req.NewUserPIN}); err != nil {
		handlePINError(w, err)
		return
	}

	writeJSON(w, &SuccessResponse{
		Success: true,
		Message: "user PIN set",
	}, http.StatusOK)
}

// ChangeSOPINHandler handles POST /v1/pin/so-pin/change requests.
// Changes the SO PIN from the current to a new value.
func (h *HandlerContext) ChangeSOPINHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrPINManagerNotConfigured, http.StatusServiceUnavailable)
		return
	}

	var req ChangeSOPINRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.CurrentSOPIN == "" {
		writeError(w, ErrMissingCurrentSOPIN, http.StatusBadRequest)
		return
	}

	if req.NewSOPIN == "" {
		writeError(w, ErrMissingNewSOPIN, http.StatusBadRequest)
		return
	}

	if err := h.xkmsService.ChangeSOPIN(r.Context(), &transport.ChangeSOPINRequest{CurrentSOPIN: req.CurrentSOPIN, NewSOPIN: req.NewSOPIN}); err != nil {
		handlePINError(w, err)
		return
	}

	writeJSON(w, &SuccessResponse{
		Success: true,
		Message: "SO PIN changed",
	}, http.StatusOK)
}

// ChangeUserPINHandler handles POST /v1/pin/user-pin/change requests.
// Changes the user PIN from the current to a new value.
func (h *HandlerContext) ChangeUserPINHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrPINManagerNotConfigured, http.StatusServiceUnavailable)
		return
	}

	var req ChangeUserPINRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.CurrentUserPIN == "" {
		writeError(w, ErrMissingCurrentPIN, http.StatusBadRequest)
		return
	}

	if req.NewUserPIN == "" {
		writeError(w, ErrMissingNewPIN, http.StatusBadRequest)
		return
	}

	if err := h.xkmsService.ChangeUserPIN(r.Context(), &transport.ChangeUserPINRequest{CurrentUserPIN: req.CurrentUserPIN, NewUserPIN: req.NewUserPIN}); err != nil {
		handlePINError(w, err)
		return
	}

	writeJSON(w, &SuccessResponse{
		Success: true,
		Message: "user PIN changed",
	}, http.StatusOK)
}

// VerifySOPINHandler handles POST /v1/pin/so-pin/verify requests.
// Verifies the provided SO PIN.
func (h *HandlerContext) VerifySOPINHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrPINManagerNotConfigured, http.StatusServiceUnavailable)
		return
	}

	var req VerifyPINRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.PIN == "" {
		writeError(w, ErrMissingPIN, http.StatusBadRequest)
		return
	}

	if err := h.xkmsService.VerifySOPIN(r.Context(), &transport.VerifySOPINRequest{SOPIN: req.PIN}); err != nil {
		handlePINError(w, err)
		return
	}

	writeJSON(w, &SuccessResponse{
		Success: true,
		Message: "SO PIN verified",
	}, http.StatusOK)
}

// VerifyUserPINHandler handles POST /v1/pin/user-pin/verify requests.
// Verifies the provided user PIN.
func (h *HandlerContext) VerifyUserPINHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrPINManagerNotConfigured, http.StatusServiceUnavailable)
		return
	}

	var req VerifyPINRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.PIN == "" {
		writeError(w, ErrMissingPIN, http.StatusBadRequest)
		return
	}

	if err := h.xkmsService.VerifyUserPIN(r.Context(), &transport.VerifyUserPINRequest{UserPIN: req.PIN}); err != nil {
		handlePINError(w, err)
		return
	}

	writeJSON(w, &SuccessResponse{
		Success: true,
		Message: "user PIN verified",
	}, http.StatusOK)
}

// GetLockoutStatusHandler handles GET /v1/pin/lockout requests.
// Returns the current lockout status.
func (h *HandlerContext) GetLockoutStatusHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrPINManagerNotConfigured, http.StatusServiceUnavailable)
		return
	}

	status, err := h.xkmsService.GetLockoutStatus(r.Context())
	if err != nil {
		handlePINError(w, err)
		return
	}
	writeJSON(w, status, http.StatusOK)
}

// ResetLockoutHandler handles POST /v1/pin/lockout/reset requests.
// Resets the lockout counter using SO PIN authorization.
func (h *HandlerContext) ResetLockoutHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrPINManagerNotConfigured, http.StatusServiceUnavailable)
		return
	}

	var req ResetLockoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.SOPIN == "" {
		writeError(w, ErrMissingSOPIN, http.StatusBadRequest)
		return
	}

	if err := h.xkmsService.ResetLockout(r.Context(), &transport.ResetLockoutRequest{SOPIN: req.SOPIN}); err != nil {
		handlePINError(w, err)
		return
	}

	writeJSON(w, &SuccessResponse{
		Success: true,
		Message: "lockout reset",
	}, http.StatusOK)
}

// --- Error mapping ---

// handleBarrierError maps barrier-specific errors to HTTP status codes.
func handleBarrierError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, seal.ErrAlreadyInitialized):
		writeError(w, err, http.StatusConflict)
	case errors.Is(err, seal.ErrAlreadyUnsealed):
		writeError(w, err, http.StatusConflict)
	case errors.Is(err, seal.ErrNotInitialized):
		writeError(w, err, http.StatusBadRequest)
	case errors.Is(err, seal.ErrInvalidCredentials):
		writeError(w, err, http.StatusUnauthorized)
	// A software passphrase strategy reports a wrong secret as
	// ErrDecryptionFailed; only the hardware strategies raise
	// ErrInvalidCredentials. Both mean "wrong credential" and both are 401.
	// Without this arm a wrong password reaches the default branch, which
	// answers 500 AND writes the raw error — disclosing the crypto library
	// and strategy name to an unauthenticated caller.
	case errors.Is(err, seal.ErrDecryptionFailed):
		writeError(w, err, http.StatusUnauthorized)
	case errors.Is(err, seal.ErrSealed):
		writeError(w, err, http.StatusConflict)
	case errors.Is(err, seal.ErrNoAvailableStrategy):
		writeError(w, err, http.StatusServiceUnavailable)
	case errors.Is(err, seal.ErrStrategyNotFound):
		writeError(w, err, http.StatusBadRequest)
	case errors.Is(err, seal.ErrCorruptRootKey):
		writeError(w, err, http.StatusInternalServerError)
	// A tenant-scoped caller is refused every system-barrier operation, and
	// BarrierEnableEncryption's caller-supplied target tenant is bound to the
	// caller's own; both refusals read as not-found.
	case errors.Is(err, qrdbsdk.ErrTenantMissing):
		writeError(w, err, http.StatusNotFound)
	case errors.Is(err, xkms.ErrNotConfigured):
		writeError(w, ErrBarrierNotConfigured, http.StatusServiceUnavailable)

	// Shamir-specific errors
	case errors.Is(err, seal.ErrShamirNotConfigured):
		writeError(w, err, http.StatusBadRequest)
	case errors.Is(err, seal.ErrShamirThresholdInvalid):
		writeError(w, err, http.StatusBadRequest)
	case errors.Is(err, seal.ErrShamirQuorumIncomplete):
		writeError(w, err, http.StatusUnprocessableEntity)
	case errors.Is(err, seal.ErrShamirQuorumExpired):
		writeError(w, err, http.StatusGone)
	case errors.Is(err, seal.ErrShamirDuplicateShare):
		writeError(w, err, http.StatusConflict)
	case errors.Is(err, seal.ErrShamirCombineFailed):
		writeError(w, err, http.StatusInternalServerError)
	case errors.Is(err, seal.ErrShamirShareNotFound):
		writeError(w, err, http.StatusNotFound)
	case errors.Is(err, seal.ErrShamirNoSharesFound):
		writeError(w, err, http.StatusNotFound)
	case errors.Is(err, seal.ErrShamirVerificationFailed):
		writeError(w, err, http.StatusInternalServerError)
	case errors.Is(err, seal.ErrShamirStorageFailed):
		writeError(w, err, http.StatusInternalServerError)

	// Recovery key errors
	case errors.Is(err, seal.ErrRecoveryKeysNotFound):
		writeError(w, err, http.StatusNotFound)

	// Root token errors
	case errors.Is(err, seal.ErrRootTokenVerificationFailed):
		writeError(w, err, http.StatusUnauthorized)

	default:
		writeError(w, err, http.StatusInternalServerError)
	}
}

// handlePINError maps PIN-specific errors to HTTP status codes.
func handlePINError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, qrdbsdk.ErrPINNotSet):
		writeError(w, err, http.StatusBadRequest)
	case errors.Is(err, qrdbsdk.ErrPINLocked):
		writeError(w, err, http.StatusTooManyRequests)
	case errors.Is(err, qrdbsdk.ErrPINInvalid):
		writeError(w, err, http.StatusUnauthorized)
	case errors.Is(err, qrdbsdk.ErrSOPINRequired):
		writeError(w, err, http.StatusUnauthorized)
	case errors.Is(err, qrdbsdk.ErrPINTooShort):
		writeError(w, err, http.StatusBadRequest)
	case errors.Is(err, qrdbsdk.ErrPINAlreadySet):
		writeError(w, err, http.StatusConflict)
	case errors.Is(err, qrdbsdk.ErrInvalidCurrentPIN):
		writeError(w, err, http.StatusUnauthorized)
	case errors.Is(err, qrdbsdk.ErrPINStateCorrupted):
		writeError(w, err, http.StatusInternalServerError)
	// A tenant-scoped caller is refused every PIN operation as not-found.
	case errors.Is(err, qrdbsdk.ErrTenantMissing):
		writeError(w, err, http.StatusNotFound)
	case errors.Is(err, xkms.ErrNotConfigured):
		writeError(w, ErrPINManagerNotConfigured, http.StatusServiceUnavailable)
	default:
		writeError(w, err, http.StatusInternalServerError)
	}
}

// barrierCredentialsFromRequest builds Credentials from the enclaved password
// buffer. Returns ok=false when the buffer is absent or empty — callers
// respond with ErrMissingSecret in that case.
//
// The secret is copied into protected memory with seal.CredentialsFor:
// pw.Buffer().Bytes() is borrowed from the decoded request, which the caller
// (req.Password.Destroy()) remains responsible for. The returned Credentials
// is owned by the caller of this function, which must destroy it once the
// barrier call it was built for returns.
func barrierCredentialsFromRequest(pw secureio.PasswordField) (seal.Credentials, bool, error) {
	buf := pw.Buffer()
	if buf == nil || buf.Size() == 0 {
		return seal.Credentials{}, false, nil
	}
	creds, err := seal.CredentialsFor(buf.Bytes())
	if err != nil {
		return seal.Credentials{}, false, err
	}
	return creds, true, nil
}
