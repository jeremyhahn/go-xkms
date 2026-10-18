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
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The system-barrier and PIN handlers delegate to the XKMSService and never
// to the barrier or PIN backend directly: both are platform-global, and the
// service's system-tenant check is what refuses a tenant-scoped caller
// (go-xkms#1227). The routes' seal:*, barrier:* and pin:* grants cannot,
// because a tenant-local Admin's self-scoped grants resolve against its own
// tenant. The refusal is xkms.TenantBindingError, which unwraps to
// qrdbsdk.ErrTenantMissing and answers 404 exactly as a genuine miss.

// Barrier/PIN handler typed errors.
var (
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
