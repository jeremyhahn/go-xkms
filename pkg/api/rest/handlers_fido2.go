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
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// FIDO2/WebAuthn registration ceremony handlers for the SDK transport.
//
// These endpoints mirror the browser ceremony served by pkg/webauthn/http, but
// transport the full WebAuthn options and attestation as JSON so the SDK can
// drive the ceremony losslessly. They delegate to the injected XKMSService,
// which shares the same WebAuthn relying-party service as the browser handlers,
// so sessions and credentials live in one place.

// handleSDKBeginRegistration handles POST /api/v1/webauthn/sdk/registration/begin.
func (s *Server) handleSDKBeginRegistration(w http.ResponseWriter, r *http.Request) {
	if s.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}
	svc := s.xkmsService

	var req transport.BeginRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	resp, err := svc.BeginRegistration(r.Context(), &req)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// handleSDKFinishRegistration handles POST /api/v1/webauthn/sdk/registration/finish.
func (s *Server) handleSDKFinishRegistration(w http.ResponseWriter, r *http.Request) {
	if s.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}
	svc := s.xkmsService

	var req transport.FinishRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	resp, err := svc.FinishRegistration(r.Context(), &req)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// handleSDKBeginAuthentication handles POST /api/v1/webauthn/sdk/authentication/begin.
func (s *Server) handleSDKBeginAuthentication(w http.ResponseWriter, r *http.Request) {
	if s.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}
	svc := s.xkmsService

	var req transport.BeginAuthenticationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	resp, err := svc.BeginAuthentication(r.Context(), &req)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// handleSDKFinishAuthentication handles POST /api/v1/webauthn/sdk/authentication/finish.
func (s *Server) handleSDKFinishAuthentication(w http.ResponseWriter, r *http.Request) {
	if s.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}
	svc := s.xkmsService

	var req transport.FinishAuthenticationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	resp, err := svc.FinishAuthentication(r.Context(), &req)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}
