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
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/api/rest/secureio"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

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
// barrier. Password carries the secret inside a memguard enclave and
// is preferred when non-empty; Secret is retained for backward
// compatibility with clients that cannot yet produce a base64
// field.
//
// Wire format note: clients using the enclaved path MUST submit the
// secret in the password_b64 field (standard base64, no padding
// stripped). The server destroys the Buffer via defer as soon as the
// barrier call returns.
type BarrierInitializeRequest struct {
	Secret   string                 `json:"secret,omitempty"`
	Password secureio.PasswordField `json:"password_b64,omitempty"`
}

// BarrierUnsealRequest represents the request to unseal the barrier.
// Password is preferred when non-empty; Secret remains for backward
// compatibility. See BarrierInitializeRequest for wire-format notes.
type BarrierUnsealRequest struct {
	Secret   string                 `json:"secret,omitempty"`
	Password secureio.PasswordField `json:"password_b64,omitempty"`
}

// BarrierStatusResponse represents the barrier status response.
type BarrierStatusResponse struct {
	Sealed         bool      `json:"sealed"`
	Strategy       string    `json:"strategy"`
	HardwareBacked bool      `json:"hardware_backed"`
	InitializedAt  time.Time `json:"initialized_at"`
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

// LockoutStatusResponse represents the lockout status response.
type LockoutStatusResponse struct {
	FailedAttempts  int       `json:"failed_attempts"`
	MaxAttempts     int       `json:"max_attempts"`
	IsLocked        bool      `json:"is_locked"`
	LockoutUntil    time.Time `json:"lockout_until,omitempty"`
	RecoverySeconds int       `json:"recovery_seconds"`
}

// --- Barrier handlers ---

// BarrierInitializeHandler handles POST /v1/barrier/initialize requests.
// Initializes the barrier with a new root key sealed using the best available strategy.
func (h *HandlerContext) BarrierInitializeHandler(w http.ResponseWriter, r *http.Request) {
	if h.Barrier == nil {
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

	creds, ok, err := barrierCredentialsFromRequest(req.Password, req.Secret)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	if !ok {
		writeError(w, ErrMissingSecret, http.StatusBadRequest)
		return
	}
	defer creds.Secret.Destroy()
	if err := h.Barrier.Initialize(r.Context(), creds); err != nil {
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
	if h.Barrier == nil {
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

	creds, ok, err := barrierCredentialsFromRequest(req.Password, req.Secret)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	if !ok {
		writeError(w, ErrMissingSecret, http.StatusBadRequest)
		return
	}
	defer creds.Secret.Destroy()
	if err := h.Barrier.Unseal(r.Context(), creds); err != nil {
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
	if h.Barrier == nil {
		writeError(w, ErrBarrierNotConfigured, http.StatusServiceUnavailable)
		return
	}

	if err := h.Barrier.Seal(); err != nil {
		writeError(w, err, http.StatusInternalServerError)
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
	if h.Barrier == nil {
		writeError(w, ErrBarrierNotConfigured, http.StatusServiceUnavailable)
		return
	}

	status := h.Barrier.Status()
	writeJSON(w, &BarrierStatusResponse{
		Sealed:         status.Sealed,
		Strategy:       string(status.Strategy),
		HardwareBacked: status.HardwareBacked,
		InitializedAt:  status.InitializedAt,
	}, http.StatusOK)
}

// --- PIN handlers ---

// SetSOPINHandler handles POST /v1/pin/so-pin requests.
// Sets the Security Officer PIN.
func (h *HandlerContext) SetSOPINHandler(w http.ResponseWriter, r *http.Request) {
	if h.PINManager == nil {
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

	if err := h.PINManager.SetSOPIN(req.CurrentSOPIN, req.NewSOPIN); err != nil {
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
	if h.PINManager == nil {
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

	if err := h.PINManager.SetUserPIN(req.SOPIN, req.NewUserPIN); err != nil {
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
	if h.PINManager == nil {
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

	if err := h.PINManager.ChangeSOPIN(req.CurrentSOPIN, req.NewSOPIN); err != nil {
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
	if h.PINManager == nil {
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

	if err := h.PINManager.ChangeUserPIN(req.CurrentUserPIN, req.NewUserPIN); err != nil {
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
	if h.PINManager == nil {
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

	if err := h.PINManager.VerifySOPIN(req.PIN); err != nil {
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
	if h.PINManager == nil {
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

	if err := h.PINManager.VerifyUserPIN(req.PIN); err != nil {
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
	if h.PINManager == nil {
		writeError(w, ErrPINManagerNotConfigured, http.StatusServiceUnavailable)
		return
	}

	status := h.PINManager.GetLockoutStatus()
	writeJSON(w, &LockoutStatusResponse{
		FailedAttempts:  status.FailedAttempts,
		MaxAttempts:     status.MaxAttempts,
		IsLocked:        status.IsLocked,
		LockoutUntil:    status.LockoutUntil,
		RecoverySeconds: status.RecoverySeconds,
	}, http.StatusOK)
}

// ResetLockoutHandler handles POST /v1/pin/lockout/reset requests.
// Resets the lockout counter using SO PIN authorization.
func (h *HandlerContext) ResetLockoutHandler(w http.ResponseWriter, r *http.Request) {
	if h.PINManager == nil {
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

	if err := h.PINManager.ResetLockout(req.SOPIN); err != nil {
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
	default:
		writeError(w, err, http.StatusInternalServerError)
	}
}

// barrierCredentialsFromRequest prefers the enclaved password buffer
// when present and non-empty; otherwise it falls back to the legacy
// plaintext Secret string. Returns ok=false only when both sources
// are empty — callers respond with ErrMissingSecret in that case.
//
// The secret is copied into protected memory with seal.CredentialsFor:
// both pw.Buffer().Bytes() and fallback are borrowed from the decoded
// request, which the caller (req.Password.Destroy(), the JSON decoder's
// string) remains responsible for. The returned Credentials is owned by
// the caller of this function, which must destroy it once the barrier
// call it was built for returns.
func barrierCredentialsFromRequest(pw secureio.PasswordField, fallback string) (seal.Credentials, bool, error) {
	if buf := pw.Buffer(); buf != nil && buf.Size() > 0 {
		creds, err := seal.CredentialsFor(buf.Bytes())
		if err != nil {
			return seal.Credentials{}, false, err
		}
		return creds, true, nil
	}
	if fallback == "" {
		return seal.Credentials{}, false, nil
	}
	creds, err := seal.CredentialsFor([]byte(fallback))
	if err != nil {
		return seal.Credentials{}, false, err
	}
	return creds, true, nil
}
