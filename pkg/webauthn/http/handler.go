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

package http

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
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
//
// This is the unauthenticated ceremony: it enrolls the FIRST passkey of an
// account. An account that already has a passkey, and (with public
// registration off) an email that names no account, are both refused with
// 403 registration_refused. Adding a passkey to an existing account is
// BeginAddCredential.
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

// BeginAddCredential handles POST /credentials/begin: it starts a
// registration ceremony that adds a passkey to the account the caller's
// authenticated session belongs to. The account comes from the session
// identity (auth.GetIdentity), never from the request, so a session can only
// add a passkey to its own account. The ceremony is completed through
// FinishRegistration with the returned X-Session-Id.
//
// This handler MUST be mounted behind authentication middleware; the public
// mount helpers (MountChi, MountMux, MountStdlib, Routes, HandlerFunc) do not
// include it. Without an authenticated identity it answers 401, and with an
// identity that does not name a WebAuthn account 403
// session_account_mismatch.
//
// Response: WebAuthn PublicKeyCredentialCreationOptions
// Header: X-Session-Id (session identifier for FinishRegistration)
func (h *Handler) BeginAddCredential(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, ErrorCodeInvalidRequest, "method not allowed")
		return
	}

	identity := auth.GetIdentity(r.Context())
	if identity == nil {
		h.writeError(w, http.StatusUnauthorized, ErrorCodeUnauthenticated, "authentication required")
		return
	}

	acct, err := webauthn.SessionAccountFromIdentity(identity)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	options, sessionID, err := h.service.BeginAddCredential(r.Context(), acct)
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

	pair, user, err := h.service.FinishRegistrationPair(r.Context(), sessionID, response)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, AuthResponse{
		Token:        pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		UserID:       base64.RawURLEncoding.EncodeToString(user.WebAuthnID()),
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
//
// The response never reveals whether the account exists: an unknown email or
// user ID, or an account without credentials, is answered with well-formed
// decoy options (webauthn.Service.BeginLoginForEmail). The user ID is
// returned only by a successful FinishLogin.
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

	var (
		options   *protocol.CredentialAssertion
		sessionID string
		err       error
	)
	switch {
	case req.UserID != "":
		userID, decodeErr := base64.RawURLEncoding.DecodeString(req.UserID)
		if decodeErr != nil {
			h.writeError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, "invalid user ID encoding")
			return
		}
		options, sessionID, err = h.service.BeginLoginForHandle(r.Context(), userID)
	case req.Email != "":
		options, sessionID, err = h.service.BeginLoginForEmail(r.Context(), req.Email)
	default:
		options, sessionID, err = h.service.BeginLogin(r.Context(), nil)
	}
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set(HeaderSessionID, sessionID)
	h.writeJSON(w, http.StatusOK, options)
}

// FinishLogin handles POST /login/finish
//
// Header: X-Session-Id (from BeginLogin)
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

	// Parse the assertion response
	response, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, "invalid assertion response")
		return
	}

	// The session records whether the ceremony is discoverable or
	// user-identified, and which account it is for; no caller-supplied user
	// ID is consulted.
	pair, user, err := h.service.FinishLoginPair(r.Context(), sessionID, nil, response)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, AuthResponse{
		Token:        pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		UserID:       base64.RawURLEncoding.EncodeToString(user.WebAuthnID()),
	})
}

// handleServiceError maps service errors to HTTP responses.
//
// Client-facing messages stay deliberately generic so a forged credential
// learns nothing, but the underlying cause is logged: without it, an
// authenticator interop failure surfaces only as "verification failed" with no
// way to tell a bad signature from a user-handle or origin mismatch.
func (h *Handler) handleServiceError(w http.ResponseWriter, err error) {
	h.logger.Debug("webauthn service error", "error", err)

	switch {
	case errors.Is(err, webauthn.ErrSessionNotFound):
		h.writeError(w, http.StatusBadRequest, ErrorCodeInvalidSession, "session not found")
	case errors.Is(err, webauthn.ErrSessionExpired):
		h.writeError(w, http.StatusBadRequest, ErrorCodeSessionExpired, "session expired")
	// A verification failure is checked before ErrUserNotFound: it may wrap
	// the account lookup that failed it (a decoy ceremony's handle names no
	// account), and the client must see the generic 401 a wrong assertion
	// gets, never 404 user_not_found (go-xkms#1296, go-xkms#1298).
	case errors.Is(err, webauthn.ErrVerificationFailed):
		h.writeError(w, http.StatusUnauthorized, ErrorCodeVerificationFailed, "verification failed")
	case errors.Is(err, webauthn.ErrUserNotFound):
		h.writeError(w, http.StatusNotFound, ErrorCodeUserNotFound, "user not found")
	case errors.Is(err, webauthn.ErrNoCredentials):
		h.writeError(w, http.StatusBadRequest, ErrorCodeNoCredentials, "user has no registered credentials")
	case errors.Is(err, webauthn.ErrInvalidRequest):
		h.writeError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, err.Error())
	case errors.Is(err, webauthn.ErrInvalidResponse):
		h.writeError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, "invalid authenticator response")
	case errors.Is(err, webauthn.ErrRegistrationRefused):
		h.writeError(w, http.StatusForbidden, ErrorCodeRegistrationRefused, webauthn.ErrRegistrationRefused.Error())
	case errors.Is(err, webauthn.ErrSessionAccountMismatch):
		h.writeError(w, http.StatusForbidden, ErrorCodeSessionAccountMismatch, "the session does not identify a webauthn account")
	case errors.Is(err, webauthn.ErrCredentialAlreadyExists):
		h.writeError(w, http.StatusConflict, ErrorCodeCredentialExists, "credential is already registered")
	case webauthn.IsSessionLimit(err):
		h.writeError(w, http.StatusServiceUnavailable, ErrorCodeSessionLimit, "too many unfinished ceremonies; retry later")
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
