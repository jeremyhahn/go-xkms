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

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// Barrier/PIN handler typed errors.
var (
	ErrBarrierNotConfigured    = errors.New("rest: barrier not configured")
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

// BarrierInitializeRequest represents the request to initialize the barrier.
type BarrierInitializeRequest struct {
	Secret string `json:"secret"`
}

// BarrierUnsealRequest represents the request to unseal the barrier.
type BarrierUnsealRequest struct {
	Secret string `json:"secret"`
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Secret == "" {
		writeError(w, ErrMissingSecret, http.StatusBadRequest)
		return
	}

	creds := seal.Credentials{Secret: req.Secret}
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Secret == "" {
		writeError(w, ErrMissingSecret, http.StatusBadRequest)
		return
	}

	creds := seal.Credentials{Secret: req.Secret}
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
	case errors.Is(err, pin.ErrPINNotSet):
		writeError(w, err, http.StatusBadRequest)
	case errors.Is(err, pin.ErrPINLocked):
		writeError(w, err, http.StatusTooManyRequests)
	case errors.Is(err, pin.ErrPINInvalid):
		writeError(w, err, http.StatusUnauthorized)
	case errors.Is(err, pin.ErrSOPINRequired):
		writeError(w, err, http.StatusUnauthorized)
	case errors.Is(err, pin.ErrPINTooShort):
		writeError(w, err, http.StatusBadRequest)
	case errors.Is(err, pin.ErrPINAlreadySet):
		writeError(w, err, http.StatusConflict)
	case errors.Is(err, pin.ErrInvalidCurrentPIN):
		writeError(w, err, http.StatusUnauthorized)
	case errors.Is(err, pin.ErrStateCorrupted):
		writeError(w, err, http.StatusInternalServerError)
	default:
		writeError(w, err, http.StatusInternalServerError)
	}
}
