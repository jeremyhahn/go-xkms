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
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
	"github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Typed errors for init ceremony and credential QUIC handlers.
var (
	// ErrXKMSServiceUnavailable is returned when the xkms service singleton
	// cannot be retrieved.
	ErrXKMSServiceUnavailable = errors.New("xkms service unavailable")

	// ErrClientCertRequired is returned when a share-claim request arrives
	// without a verified mTLS peer certificate. The officer's certificate
	// thumbprint is the authentication for these routes.
	ErrClientCertRequired = errors.New("client certificate required")
)

// initErrorStatusMap maps ceremony errors to HTTP status codes for O(1) lookup.
var initErrorStatusMap = map[error]int{
	initialize.ErrNotInEnrollingState:         http.StatusConflict,
	initialize.ErrPendingCertNotFound:         http.StatusNotFound,
	initialize.ErrCertAlreadyClaimed:          http.StatusConflict,
	initialize.ErrShareNotFound:               http.StatusNotFound,
	initialize.ErrShareAlreadyClaimed:         http.StatusConflict,
	initialize.ErrChallengeVerificationFailed: http.StatusUnauthorized,
	initialize.ErrCertThumbprintMismatch:      http.StatusUnauthorized,
	initialize.ErrOfficerNotFound:             http.StatusNotFound,
	initialize.ErrNoPendingShare:              http.StatusNotFound,
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

	if !s.authorizeCeremony(w, r, auth.ActionStatus) {
		return
	}

	svc := s.xkmsService
	if svc == nil {
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

	if !s.authorizeCeremony(w, r, auth.ActionClaimCert) {
		return
	}

	var req transport.ClaimCertBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	svc := s.xkmsService
	if svc == nil {
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

	if !s.authorizeCeremony(w, r, auth.ActionClaimCert) {
		return
	}

	var req transport.ClaimCertCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	svc := s.xkmsService
	if svc == nil {
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

// callerCertThumbprint derives the caller's certificate thumbprint from the
// verified mTLS peer certificate on the HTTP/3 request. It fails closed with
// ErrClientCertRequired when the request carries none, so the share-claim
// routes never fall back to trusting a username.
//
// The value is computed with initialize.CertThumbprint, the single canonical
// binding identifier the ceremony records for each officer at enrollment.
func callerCertThumbprint(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", ErrClientCertRequired
	}
	return initialize.CertThumbprint(r.TLS.PeerCertificates[0].Raw), nil
}

// handleClaimShareBegin starts the Shamir share claim handshake for the named
// officer. The officer has no account yet; the certificate claim-cert issued
// them is their credential, and its thumbprint is the authentication here.
// POST /api/v1/init/claim-share/begin
func (s *Server) handleClaimShareBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorizeCeremony(w, r, auth.ActionClaimShareBegin) {
		return
	}

	thumbprint, err := callerCertThumbprint(r)
	if err != nil {
		s.sendError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req transport.ClaimShareBeginRequest
	if decErr := json.NewDecoder(r.Body).Decode(&req); decErr != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Never from the wire: overwrite whatever decoding produced.
	req.CallerCertThumbprint = thumbprint

	svc := s.xkmsService
	if svc == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	resp, err := svc.ClaimShareBegin(r.Context(), &req)
	if err != nil {
		statusCode := mapInitErrorToStatus(err)
		s.sendError(w, statusCode, err.Error())
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleClaimShareComplete completes the Shamir share claim handshake,
// releasing the share exactly once after both the nonce signature and the
// caller certificate thumbprint verify.
// POST /api/v1/init/claim-share/complete
func (s *Server) handleClaimShareComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorizeCeremony(w, r, auth.ActionClaimShareComplete) {
		return
	}

	thumbprint, err := callerCertThumbprint(r)
	if err != nil {
		s.sendError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req transport.ClaimShareCompleteRequest
	if decErr := json.NewDecoder(r.Body).Decode(&req); decErr != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.CallerCertThumbprint = thumbprint

	svc := s.xkmsService
	if svc == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	resp, err := svc.ClaimShareComplete(r.Context(), &req)
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

	if !s.authorize(w, r, auth.ResourceCeremony, auth.ActionSignCSR) {
		return
	}

	var req transport.SignCSRInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	svc := s.xkmsService
	if svc == nil {
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

	if !s.authorize(w, r, auth.ResourceCredentials, auth.ActionSubmit) {
		return
	}

	var req transport.CredentialSubmitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	svc := s.xkmsService
	if svc == nil {
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

	if !s.authorize(w, r, auth.ResourceCredentials, auth.ActionStrategy) {
		return
	}

	svc := s.xkmsService
	if svc == nil {
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
