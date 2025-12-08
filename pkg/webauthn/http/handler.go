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

package http

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/jeremyhahn/go-keychain/pkg/webauthn"
)

// Handler provides HTTP handlers for WebAuthn operations.
// These handlers can be mounted on any HTTP router.
type Handler struct {
	service *webauthn.Service
	logger  *slog.Logger
}

// NewHandler creates a new WebAuthn HTTP handler.
func NewHandler(service *webauthn.Service) *Handler {
	return &Handler{
		service: service,
		logger:  slog.Default(),
	}
}

// WithLogger sets a custom logger for the handler.
func (h *Handler) WithLogger(logger *slog.Logger) *Handler {
	h.logger = logger
	return h
}

// BeginRegistration handles POST /registration/begin
//
// Request body:
//
//	{
//	    "email": "user@example.com",
//	    "display_name": "User Name" // optional
//	}
//
// Response: WebAuthn PublicKeyCredentialCreationOptions
// Header: X-Session-Id (session identifier for FinishRegistration)
func (h *Handler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, ErrorCodeInvalidRequest, "method not allowed")
		return
	}

	var req BeginRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, "invalid request body")
		return
	}

	if req.Email == "" {
		h.writeError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, "email is required")
		return
	}

	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Email
	}

	options, sessionID, err := h.service.BeginRegistration(r.Context(), req.Email, displayName)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set(HeaderSessionID, sessionID)
	h.writeJSON(w, http.StatusOK, options)
}

// FinishRegistration handles POST /registration/finish
//
// Header: X-Session-Id (from BeginRegistration)
// Request body: Attestation response from authenticator
// Response: AuthResponse with token and user ID
func (h *Handler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, ErrorCodeInvalidRequest, "method not allowed")
		return
	}

	sessionID := r.Header.Get(HeaderSessionID)
	if sessionID == "" {
		h.writeError(w, http.StatusBadRequest, ErrorCodeInvalidSession, "session ID header is required")
		return
	}

	// Parse the credential creation response
	response, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, "invalid attestation response")
		return
	}

	token, user, err := h.service.FinishRegistration(r.Context(), sessionID, response)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, AuthResponse{
		Token:  token,
		UserID: base64.RawURLEncoding.EncodeToString(user.WebAuthnID()),
	})
}

// BeginLogin handles POST /login/begin
//
// Request body:
//
//	{
//	    "user_id": "base64-user-id", // optional
//	    "email": "user@example.com"  // optional, alternative to user_id
//	}
//
// If neither user_id nor email is provided, uses discoverable credentials flow.
// Response: WebAuthn PublicKeyCredentialRequestOptions
// Header: X-Session-Id (session identifier for FinishLogin)
// Header: X-User-Id (if user was identified)
func (h *Handler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, ErrorCodeInvalidRequest, "method not allowed")
		return
	}

	var req BeginLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Allow empty body for discoverable credentials
		req = BeginLoginRequest{}
	}

	var userID []byte
	var err error

	// Try to resolve user ID
	if req.UserID != "" {
		userID, err = base64.RawURLEncoding.DecodeString(req.UserID)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, "invalid user ID encoding")
			return
		}
	} else if req.Email != "" {
		user, userErr := h.service.GetUserByEmail(r.Context(), req.Email)
		if userErr != nil {
			if webauthn.IsUserNotFound(userErr) {
				h.writeError(w, http.StatusNotFound, ErrorCodeUserNotFound, "user not found")
				return
			}
			h.handleServiceError(w, userErr)
			return
		}
		userID = user.WebAuthnID()
	}

	options, sessionID, err := h.service.BeginLogin(r.Context(), userID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set(HeaderSessionID, sessionID)
	if userID != nil {
		w.Header().Set(HeaderUserID, base64.RawURLEncoding.EncodeToString(userID))
	}
	h.writeJSON(w, http.StatusOK, options)
}

// FinishLogin handles POST /login/finish
//
// Header: X-Session-Id (from BeginLogin)
// Header: X-User-Id (optional, for non-discoverable flow)
// Request body: Assertion response from authenticator
// Response: AuthResponse with token and user ID
func (h *Handler) FinishLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, ErrorCodeInvalidRequest, "method not allowed")
		return
	}

	sessionID := r.Header.Get(HeaderSessionID)
	if sessionID == "" {
		h.writeError(w, http.StatusBadRequest, ErrorCodeInvalidSession, "session ID header is required")
		return
	}

	// Get optional user ID
	var userID []byte
	if userIDStr := r.Header.Get(HeaderUserID); userIDStr != "" {
		var err error
		userID, err = base64.RawURLEncoding.DecodeString(userIDStr)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, "invalid user ID encoding")
			return
		}
	}

	// Parse the assertion response
	response, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, "invalid assertion response")
		return
	}

	token, user, err := h.service.FinishLogin(r.Context(), sessionID, userID, response)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, AuthResponse{
		Token:  token,
		UserID: base64.RawURLEncoding.EncodeToString(user.WebAuthnID()),
	})
}

// RegistrationStatus handles GET /registration/status
//
// Query param or header: user_id (optional)
// Response: {"registered": true/false}
func (h *Handler) RegistrationStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, ErrorCodeInvalidRequest, "method not allowed")
		return
	}

	// Get user ID from header or query param
	userIDStr := r.Header.Get(HeaderUserID)
	if userIDStr == "" {
		userIDStr = r.URL.Query().Get("user_id")
	}

	if userIDStr == "" {
		// No user ID - check if email is provided
		email := r.URL.Query().Get("email")
		if email != "" {
			user, err := h.service.GetUserByEmail(r.Context(), email)
			if err != nil {
				if webauthn.IsUserNotFound(err) {
					h.writeJSON(w, http.StatusOK, RegistrationStatusResponse{Registered: false})
					return
				}
				h.handleServiceError(w, err)
				return
			}
			userIDStr = base64.RawURLEncoding.EncodeToString(user.WebAuthnID())
		} else {
			h.writeJSON(w, http.StatusOK, RegistrationStatusResponse{Registered: false})
			return
		}
	}

	userID, err := base64.RawURLEncoding.DecodeString(userIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, "invalid user ID encoding")
		return
	}

	registered, err := h.service.IsRegistered(r.Context(), userID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, RegistrationStatusResponse{Registered: registered})
}

// handleServiceError maps service errors to HTTP responses.
func (h *Handler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, webauthn.ErrSessionNotFound):
		h.writeError(w, http.StatusBadRequest, ErrorCodeInvalidSession, "session not found")
	case errors.Is(err, webauthn.ErrSessionExpired):
		h.writeError(w, http.StatusBadRequest, ErrorCodeSessionExpired, "session expired")
	case errors.Is(err, webauthn.ErrUserNotFound):
		h.writeError(w, http.StatusNotFound, ErrorCodeUserNotFound, "user not found")
	case errors.Is(err, webauthn.ErrNoCredentials):
		h.writeError(w, http.StatusBadRequest, ErrorCodeNoCredentials, "user has no registered credentials")
	case errors.Is(err, webauthn.ErrVerificationFailed):
		h.writeError(w, http.StatusUnauthorized, ErrorCodeVerificationFailed, "verification failed")
	case errors.Is(err, webauthn.ErrInvalidRequest):
		h.writeError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, err.Error())
	case errors.Is(err, webauthn.ErrInvalidResponse):
		h.writeError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, "invalid authenticator response")
	default:
		h.writeError(w, http.StatusInternalServerError, ErrorCodeInternalError, "internal server error")
	}
}

// writeJSON writes a JSON response.
func (h *Handler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// Response headers already written, can only log the error
		h.logger.Error("failed to encode JSON response",
			"error", err,
			"status", status)
	}
}

// writeError writes an error response.
func (h *Handler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, ErrorResponse{
		Error:   code,
		Message: message,
	})
}
