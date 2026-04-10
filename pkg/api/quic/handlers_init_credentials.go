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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
	"github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Typed errors for init ceremony and credential QUIC handlers.
var (
	// ErrXKMSServiceUnavailable is returned when the xkms service singleton
	// cannot be retrieved.
	ErrXKMSServiceUnavailable = errors.New("xkms service unavailable")
)

// initErrorStatusMap maps ceremony errors to HTTP status codes for O(1) lookup.
var initErrorStatusMap = map[error]int{
	initialize.ErrNotInEnrollingState:         http.StatusConflict,
	initialize.ErrPendingCertNotFound:         http.StatusNotFound,
	initialize.ErrCertAlreadyClaimed:          http.StatusConflict,
	initialize.ErrShareNotFound:               http.StatusNotFound,
	initialize.ErrShareAlreadyClaimed:         http.StatusConflict,
	initialize.ErrChallengeVerificationFailed: http.StatusUnauthorized,
	initialize.ErrAlreadyInitialized:          http.StatusConflict,
	xkms.ErrNotConfigured:                     http.StatusServiceUnavailable,
	xkms.ErrNilRequest:                        http.StatusBadRequest,
}

// credentialErrorStatusMap maps credential errors to HTTP status codes for O(1) lookup.
var credentialErrorStatusMap = map[error]int{
	credentials.ErrEmptyCredentialName:        http.StatusBadRequest,
	credentials.ErrEmptyCredentialValue:       http.StatusBadRequest,
	credentials.ErrCredentialNotFound:         http.StatusNotFound,
	credentials.ErrCredentialAlreadySubmitted: http.StatusConflict,
	credentials.ErrInvalidStrategy:            http.StatusBadRequest,
	xkms.ErrNotConfigured:                     http.StatusServiceUnavailable,
	xkms.ErrNilRequest:                        http.StatusBadRequest,
	xkms.ErrInvalidEncoding:                   http.StatusBadRequest,
}

// handleGetInitStatus returns the current init ceremony state.
// GET /api/v1/init/status
func (s *Server) handleGetInitStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "init", "read") {
		return
	}

	svc, err := xkms.Get()
	if err != nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	resp, err := svc.GetInitStatus(r.Context())
	if err != nil {
		statusCode := mapInitErrorToStatus(err)
		s.sendError(w, statusCode, err.Error())
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleClaimCertBegin begins the certificate claim process for an officer.
// POST /api/v1/init/claim-cert/begin
func (s *Server) handleClaimCertBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "init", "write") {
		return
	}

	var req transport.ClaimCertBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	svc, err := xkms.Get()
	if err != nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	resp, err := svc.ClaimCertBegin(r.Context(), &req)
	if err != nil {
		statusCode := mapInitErrorToStatus(err)
		s.sendError(w, statusCode, err.Error())
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleClaimCertComplete completes the certificate claim by verifying the
// officer's signature over the challenge nonce.
// POST /api/v1/init/claim-cert/complete
func (s *Server) handleClaimCertComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "init", "write") {
		return
	}

	var req transport.ClaimCertCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	svc, err := xkms.Get()
	if err != nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	resp, err := svc.ClaimCertComplete(r.Context(), &req)
	if err != nil {
		statusCode := mapInitErrorToStatus(err)
		s.sendError(w, statusCode, err.Error())
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleClaimShare retrieves the Shamir share for the named officer.
// POST /api/v1/init/claim-share
func (s *Server) handleClaimShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "init", "write") {
		return
	}

	var req transport.ClaimShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	svc, err := xkms.Get()
	if err != nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	resp, err := svc.ClaimShare(r.Context(), &req)
	if err != nil {
		statusCode := mapInitErrorToStatus(err)
		s.sendError(w, statusCode, err.Error())
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleSignCSRInit signs a CSR during initialization with SO authorization.
// POST /api/v1/init/sign-csr
func (s *Server) handleSignCSRInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "init", "write") {
		return
	}

	var req transport.SignCSRInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	svc, err := xkms.Get()
	if err != nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	resp, err := svc.SignCSRInit(r.Context(), &req)
	if err != nil {
		statusCode := mapInitErrorToStatus(err)
		s.sendError(w, statusCode, err.Error())
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleCredentialSubmit handles credential submission for manual mode.
// POST /api/v1/credentials/submit
func (s *Server) handleCredentialSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "credentials", "write") {
		return
	}

	var req transport.CredentialSubmitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	svc, err := xkms.Get()
	if err != nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	resp, err := svc.SubmitCredential(r.Context(), &req)
	if err != nil {
		statusCode := mapCredentialErrorToStatus(err)
		s.sendError(w, statusCode, err.Error())
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleCredentialStrategy returns the configured credential strategy.
// GET /api/v1/credentials/strategy
func (s *Server) handleCredentialStrategy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "credentials", "read") {
		return
	}

	svc, err := xkms.Get()
	if err != nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	resp, err := svc.GetCredentialStrategy(r.Context())
	if err != nil {
		statusCode := mapCredentialErrorToStatus(err)
		s.sendError(w, statusCode, err.Error())
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// mapInitErrorToStatus maps an init ceremony error to the appropriate HTTP status code.
func mapInitErrorToStatus(err error) int {
	for sentinel, status := range initErrorStatusMap {
		if errors.Is(err, sentinel) {
			return status
		}
	}
	return http.StatusInternalServerError
}

// mapCredentialErrorToStatus maps a credential error to the appropriate HTTP status code.
func mapCredentialErrorToStatus(err error) int {
	for sentinel, status := range credentialErrorStatusMap {
		if errors.Is(err, sentinel) {
			return status
		}
	}
	return http.StatusInternalServerError
}
