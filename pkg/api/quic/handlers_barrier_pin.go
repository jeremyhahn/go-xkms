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

package quic

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// Typed errors for barrier/PIN handler operations.
var (
	ErrBarrierNotConfigured    = errors.New("quic: barrier not configured")
	ErrPINManagerNotConfigured = errors.New("quic: PIN manager not configured")
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

// setupBarrierPINRoutes registers barrier and PIN HTTP routes on the given ServeMux.
func (s *Server) setupBarrierPINRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/barrier/", s.handleBarrierOperations)
	mux.HandleFunc("/api/v1/pin/", s.handlePINOperations)
}

// handleBarrierOperations dispatches barrier requests based on the URL path.
func (s *Server) handleBarrierOperations(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/barrier/")
	path = strings.TrimSuffix(path, "/")

	// Handle prefix-matched paths first (variable path segments).
	if strings.HasPrefix(path, "shamir/shares/") {
		s.handleBarrierShamirDeleteShare(w, r, path)
		return
	}

	// Map-based dispatch for O(1) constant-time lookup.
	type barrierHandler func(w http.ResponseWriter, r *http.Request)
	handlers := map[string]barrierHandler{
		// Existing barrier operations
		"initialize": s.handleBarrierInitialize,
		"unseal":     s.handleBarrierUnseal,
		"seal":       s.handleBarrierSeal,
		"status":     s.handleBarrierStatus,

		// Shamir barrier operations
		"initialize-shamir": s.handleBarrierInitializeShamir,
		"unseal-share":      s.handleBarrierUnsealShare,
		"unseal-shares":     s.handleBarrierUnsealShares,
		"rekey":             s.handleBarrierRekey,
		"root-token":        s.handleBarrierGenerateRootToken,

		// Shamir share management
		"shamir/shares": s.handleBarrierShamirShares,
		"shamir/verify": s.handleBarrierShamirVerify,

		// Recovery key operations
		"recovery-keys/generate": s.handleBarrierGenerateRecoveryKeys,
		"recovery-keys/recover":  s.handleBarrierRecoverWithKeys,
		"recovery-keys":          s.handleBarrierRecoveryKeysDispatch,
	}

	handler, ok := handlers[path]
	if !ok {
		s.sendError(w, http.StatusNotFound, "unknown barrier operation: "+path)
		return
	}

	handler(w, r)
}

// handlePINOperations dispatches PIN requests based on the URL path.
func (s *Server) handlePINOperations(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/pin/")
	path = strings.TrimSuffix(path, "/")

	// Map-based dispatch for O(1) constant-time lookup
	type pinHandler func(w http.ResponseWriter, r *http.Request)
	handlers := map[string]pinHandler{
		"so-pin":          s.handleSetSOPIN,
		"user-pin":        s.handleSetUserPIN,
		"so-pin/change":   s.handleChangeSOPIN,
		"user-pin/change": s.handleChangeUserPIN,
		"so-pin/verify":   s.handleVerifySOPIN,
		"user-pin/verify": s.handleVerifyUserPIN,
		"lockout":         s.handleGetLockoutStatus,
		"lockout/reset":   s.handleResetLockout,
	}

	handler, ok := handlers[path]
	if !ok {
		s.sendError(w, http.StatusNotFound, "unknown PIN operation: "+path)
		return
	}

	handler(w, r)
}

// --- Barrier handlers ---

// handleBarrierInitialize handles POST /api/v1/barrier/initialize requests.
func (s *Server) handleBarrierInitialize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.barrier == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrBarrierNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "barrier", "use") {
		return
	}

	var req BarrierInitializeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Secret == "" {
		s.sendError(w, http.StatusBadRequest, "secret is required")
		return
	}

	creds := seal.Credentials{Secret: req.Secret}
	if err := s.barrier.Initialize(r.Context(), creds); err != nil {
		sendBarrierError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "barrier initialized",
	})
}

// handleBarrierUnseal handles POST /api/v1/barrier/unseal requests.
func (s *Server) handleBarrierUnseal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.barrier == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrBarrierNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "barrier", "use") {
		return
	}

	var req BarrierUnsealRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Secret == "" {
		s.sendError(w, http.StatusBadRequest, "secret is required")
		return
	}

	creds := seal.Credentials{Secret: req.Secret}
	if err := s.barrier.Unseal(r.Context(), creds); err != nil {
		sendBarrierError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "barrier unsealed",
	})
}

// handleBarrierSeal handles POST /api/v1/barrier/seal requests.
func (s *Server) handleBarrierSeal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.barrier == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrBarrierNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "barrier", "use") {
		return
	}

	if err := s.barrier.Seal(); err != nil {
		s.sendError(w, http.StatusInternalServerError, "failed to seal barrier: "+err.Error())
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "barrier sealed",
	})
}

// handleBarrierStatus handles GET /api/v1/barrier/status requests.
func (s *Server) handleBarrierStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.barrier == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrBarrierNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "barrier", "read") {
		return
	}

	status := s.barrier.Status()
	s.sendJSON(w, http.StatusOK, BarrierStatusResponse{
		Sealed:         status.Sealed,
		Strategy:       string(status.Strategy),
		HardwareBacked: status.HardwareBacked,
		InitializedAt:  status.InitializedAt,
	})
}

// --- PIN handlers ---

// handleSetSOPIN handles POST /api/v1/pin/so-pin requests.
func (s *Server) handleSetSOPIN(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.pinManager == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrPINManagerNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "pin", "use") {
		return
	}

	var req SetSOPINRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.NewSOPIN == "" {
		s.sendError(w, http.StatusBadRequest, "new_so_pin is required")
		return
	}

	if err := s.pinManager.SetSOPIN(req.CurrentSOPIN, req.NewSOPIN); err != nil {
		sendPINError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "SO PIN set",
	})
}

// handleSetUserPIN handles POST /api/v1/pin/user-pin requests.
func (s *Server) handleSetUserPIN(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.pinManager == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrPINManagerNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "pin", "use") {
		return
	}

	var req SetUserPINRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.SOPIN == "" {
		s.sendError(w, http.StatusBadRequest, "so_pin is required")
		return
	}

	if req.NewUserPIN == "" {
		s.sendError(w, http.StatusBadRequest, "new_user_pin is required")
		return
	}

	if err := s.pinManager.SetUserPIN(req.SOPIN, req.NewUserPIN); err != nil {
		sendPINError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "user PIN set",
	})
}

// handleChangeSOPIN handles POST /api/v1/pin/so-pin/change requests.
func (s *Server) handleChangeSOPIN(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.pinManager == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrPINManagerNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "pin", "use") {
		return
	}

	var req ChangeSOPINRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.CurrentSOPIN == "" {
		s.sendError(w, http.StatusBadRequest, "current_so_pin is required")
		return
	}

	if req.NewSOPIN == "" {
		s.sendError(w, http.StatusBadRequest, "new_so_pin is required")
		return
	}

	if err := s.pinManager.ChangeSOPIN(req.CurrentSOPIN, req.NewSOPIN); err != nil {
		sendPINError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "SO PIN changed",
	})
}

// handleChangeUserPIN handles POST /api/v1/pin/user-pin/change requests.
func (s *Server) handleChangeUserPIN(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.pinManager == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrPINManagerNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "pin", "use") {
		return
	}

	var req ChangeUserPINRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.CurrentUserPIN == "" {
		s.sendError(w, http.StatusBadRequest, "current_user_pin is required")
		return
	}

	if req.NewUserPIN == "" {
		s.sendError(w, http.StatusBadRequest, "new_user_pin is required")
		return
	}

	if err := s.pinManager.ChangeUserPIN(req.CurrentUserPIN, req.NewUserPIN); err != nil {
		sendPINError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "user PIN changed",
	})
}

// handleVerifySOPIN handles POST /api/v1/pin/so-pin/verify requests.
func (s *Server) handleVerifySOPIN(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.pinManager == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrPINManagerNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "pin", "use") {
		return
	}

	var req VerifyPINRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.PIN == "" {
		s.sendError(w, http.StatusBadRequest, "pin is required")
		return
	}

	if err := s.pinManager.VerifySOPIN(req.PIN); err != nil {
		sendPINError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "SO PIN verified",
	})
}

// handleVerifyUserPIN handles POST /api/v1/pin/user-pin/verify requests.
func (s *Server) handleVerifyUserPIN(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.pinManager == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrPINManagerNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "pin", "use") {
		return
	}

	var req VerifyPINRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.PIN == "" {
		s.sendError(w, http.StatusBadRequest, "pin is required")
		return
	}

	if err := s.pinManager.VerifyUserPIN(req.PIN); err != nil {
		sendPINError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "user PIN verified",
	})
}

// handleGetLockoutStatus handles GET /api/v1/pin/lockout requests.
func (s *Server) handleGetLockoutStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.pinManager == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrPINManagerNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "pin", "read") {
		return
	}

	status := s.pinManager.GetLockoutStatus()
	s.sendJSON(w, http.StatusOK, LockoutStatusResponse{
		FailedAttempts:  status.FailedAttempts,
		MaxAttempts:     status.MaxAttempts,
		IsLocked:        status.IsLocked,
		LockoutUntil:    status.LockoutUntil,
		RecoverySeconds: status.RecoverySeconds,
	})
}

// handleResetLockout handles POST /api/v1/pin/lockout/reset requests.
func (s *Server) handleResetLockout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.pinManager == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrPINManagerNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "pin", "use") {
		return
	}

	var req ResetLockoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.SOPIN == "" {
		s.sendError(w, http.StatusBadRequest, "so_pin is required")
		return
	}

	if err := s.pinManager.ResetLockout(req.SOPIN); err != nil {
		sendPINError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "lockout reset",
	})
}

// --- Error mapping ---

// sendBarrierError maps barrier-specific errors to HTTP status codes.
func sendBarrierError(s *Server, w http.ResponseWriter, err error) {
	switch {
	// Existing barrier errors
	case errors.Is(err, seal.ErrAlreadyInitialized):
		s.sendError(w, http.StatusConflict, err.Error())
	case errors.Is(err, seal.ErrAlreadyUnsealed):
		s.sendError(w, http.StatusConflict, err.Error())
	case errors.Is(err, seal.ErrNotInitialized):
		s.sendError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, seal.ErrInvalidCredentials):
		s.sendError(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, seal.ErrSealed):
		s.sendError(w, http.StatusConflict, err.Error())
	case errors.Is(err, seal.ErrNoAvailableStrategy):
		s.sendError(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, seal.ErrStrategyNotFound):
		s.sendError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, seal.ErrCorruptRootKey):
		s.sendError(w, http.StatusInternalServerError, err.Error())

	// Shamir errors
	case errors.Is(err, seal.ErrShamirNotConfigured):
		s.sendError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, seal.ErrShamirThresholdInvalid):
		s.sendError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, seal.ErrShamirQuorumIncomplete):
		s.sendError(w, http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, seal.ErrShamirQuorumExpired):
		s.sendError(w, http.StatusGone, err.Error())
	case errors.Is(err, seal.ErrShamirDuplicateShare):
		s.sendError(w, http.StatusConflict, err.Error())
	case errors.Is(err, seal.ErrShamirCombineFailed):
		s.sendError(w, http.StatusInternalServerError, err.Error())
	case errors.Is(err, seal.ErrShamirShareNotFound):
		s.sendError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, seal.ErrShamirNoSharesFound):
		s.sendError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, seal.ErrShamirVerificationFailed):
		s.sendError(w, http.StatusInternalServerError, err.Error())

	// Recovery key errors
	case errors.Is(err, seal.ErrRecoveryKeysNotFound):
		s.sendError(w, http.StatusNotFound, err.Error())

	// Root token errors
	case errors.Is(err, seal.ErrRootTokenVerificationFailed):
		s.sendError(w, http.StatusUnauthorized, err.Error())

	default:
		s.sendError(w, http.StatusInternalServerError, err.Error())
	}
}

// sendPINError maps PIN-specific errors to HTTP status codes.
func sendPINError(s *Server, w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, pin.ErrPINNotSet):
		s.sendError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, pin.ErrPINLocked):
		s.sendError(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, pin.ErrPINInvalid):
		s.sendError(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, pin.ErrSOPINRequired):
		s.sendError(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, pin.ErrPINTooShort):
		s.sendError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, pin.ErrPINAlreadySet):
		s.sendError(w, http.StatusConflict, err.Error())
	case errors.Is(err, pin.ErrInvalidCurrentPIN):
		s.sendError(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, pin.ErrStateCorrupted):
		s.sendError(w, http.StatusInternalServerError, err.Error())
	default:
		s.sendError(w, http.StatusInternalServerError, err.Error())
	}
}
