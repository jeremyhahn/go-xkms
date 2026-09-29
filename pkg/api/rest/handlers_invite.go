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

	"github.com/go-chi/chi/v5"

	xkmstransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Public enrollment-invitation redemption handlers (go-xkms#1294 part B): how
// an account CreateUser provisioned with zero credentials enrolls its first
// one. Every route here is unauthenticated by design — a brand-new account
// holds no credential to authenticate a request with — and is authorized
// instead by possession of the single-use invitation token. Every failure
// answers with the one opaque "invite link is not valid" response
// (writeInviteUnusable); absent, expired and already-redeemed tokens are
// indistinguishable to the caller, matching xkms.ErrInviteUnusable's own
// doc comment.
//
// These handlers are thin: they decode the wire request, call the
// corresponding transport.InviteServicer method on XKMSService (the same
// method every other transport's server side calls — pkg/api/grpc's
// service_invite.go, pkg/api/mcp's handlers_invite.go, the embedded
// transport's direct delegation), and translate the result. There is no
// REST-specific business logic here.

// ErrorCodeInviteUnusable is the machine-readable error code every unusable
// invitation gets on this transport, mirroring pkg/webauthn/http's
// ErrorCodeRegistrationRefused convention: one code and one message for
// every refusal, so a client branches on the documented code, not on
// message text.
const ErrorCodeInviteUnusable = "invite_unusable"

// writeInviteUnusable answers with the single opaque response every unusable
// invitation gets.
func writeInviteUnusable(w http.ResponseWriter) {
	writeJSON(w, ErrorResponse{
		Error:   ErrorCodeInviteUnusable,
		Message: xkms.ErrInviteUnusable.Error(),
		Code:    http.StatusNotFound,
	}, http.StatusNotFound)
}

// writeInviteError answers err on the invite redemption surface: the opaque
// response for xkms.ErrInviteUnusable, a scrubbed 503 for ErrNotConfigured,
// and a scrubbed 500 for anything else. It never lets an unrecognized error
// fall through to a 200.
func writeInviteError(w http.ResponseWriter, err error) {
	var certDecode *xkms.ErrPIVCertDecode
	var certRejected *xkms.ErrPIVCertRejected
	switch {
	case errors.Is(err, xkms.ErrInviteUnusable):
		writeInviteUnusable(w)
	case errors.As(err, &certDecode):
		writeError(w, err, http.StatusBadRequest)
	case errors.As(err, &certRejected):
		writeError(w, err, http.StatusUnprocessableEntity)
	case errors.Is(err, xkms.ErrNotConfigured):
		writeError(w, err, http.StatusServiceUnavailable)
	default:
		writeError(w, err, http.StatusInternalServerError)
	}
}

// handleGetInvite handles GET /api/v1/invites/{tenant_id}/{token}.
func (s *Server) handleGetInvite(w http.ResponseWriter, r *http.Request) {
	if s.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}
	resp, err := s.xkmsService.GetInvite(r.Context(), &xkmstransport.GetInviteRequest{
		TenantID: chi.URLParam(r, "tenant_id"),
		Token:    chi.URLParam(r, "token"),
	})
	if err != nil {
		writeInviteError(w, err)
		return
	}
	writeJSON(w, resp, http.StatusOK)
}

// handleInviteBeginFIDO2 handles
// POST /api/v1/invites/{tenant_id}/{token}/fido2/begin.
func (s *Server) handleInviteBeginFIDO2(w http.ResponseWriter, r *http.Request) {
	if s.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}
	resp, err := s.xkmsService.BeginInviteRegistration(r.Context(), &xkmstransport.BeginInviteRegistrationRequest{
		TenantID: chi.URLParam(r, "tenant_id"),
		Token:    chi.URLParam(r, "token"),
	})
	if err != nil {
		writeInviteError(w, err)
		return
	}
	writeJSON(w, resp, http.StatusOK)
}

// handleInviteFinishFIDO2 handles
// POST /api/v1/invites/{tenant_id}/{token}/fido2/finish.
func (s *Server) handleInviteFinishFIDO2(w http.ResponseWriter, r *http.Request) {
	if s.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}
	var body struct {
		SessionID       string `json:"session_id"`
		AttestationJSON string `json:"attestation_json"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	if body.SessionID == "" || body.AttestationJSON == "" {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	resp, err := s.xkmsService.FinishInviteRegistration(r.Context(), &xkmstransport.FinishInviteRegistrationRequest{
		TenantID:        chi.URLParam(r, "tenant_id"),
		Token:           chi.URLParam(r, "token"),
		SessionID:       body.SessionID,
		AttestationJSON: body.AttestationJSON,
	})
	if err != nil {
		writeInviteError(w, err)
		return
	}
	writeJSON(w, resp, http.StatusOK)
}

// handleInviteActivatePIV handles
// POST /api/v1/invites/{tenant_id}/{token}/piv/activate.
func (s *Server) handleInviteActivatePIV(w http.ResponseWriter, r *http.Request) {
	if s.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}
	var body struct {
		CertPEM string `json:"cert_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	if body.CertPEM == "" {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	resp, err := s.xkmsService.ActivateInvitePIV(r.Context(), &xkmstransport.ActivateInvitePIVRequest{
		TenantID: chi.URLParam(r, "tenant_id"),
		Token:    chi.URLParam(r, "token"),
		CertPEM:  body.CertPEM,
	})
	if err != nil {
		writeInviteError(w, err)
		return
	}
	writeJSON(w, resp, http.StatusOK)
}
