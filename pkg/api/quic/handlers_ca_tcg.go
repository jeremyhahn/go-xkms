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
	"fmt"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// handleIssueEKCertificate issues an Endorsement Key certificate for a TPM.
// POST /api/v1/ca/tcg/ek
func (s *Server) handleIssueEKCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "ca", "write") {
		return
	}

	var req transport.IssueEKCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	svc, err := xkms.Get()
	if err != nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	resp, err := svc.IssueEKCertificate(r.Context(), &req)
	if err != nil {
		statusCode := mapCAErrorToStatus(err)
		s.sendError(w, statusCode, err.Error())
		return
	}

	s.sendJSON(w, http.StatusCreated, resp)
}

// handleIssueAKCertificate issues an Attestation Key certificate for a TPM.
// POST /api/v1/ca/tcg/ak
func (s *Server) handleIssueAKCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "ca", "write") {
		return
	}

	var req transport.IssueAKCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	svc, err := xkms.Get()
	if err != nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	resp, err := svc.IssueAKCertificate(r.Context(), &req)
	if err != nil {
		statusCode := mapCAErrorToStatus(err)
		s.sendError(w, statusCode, err.Error())
		return
	}

	s.sendJSON(w, http.StatusCreated, resp)
}

// handleSignTCGCSR signs a TCG-CSR-IDEVID and returns IAK and IDevID certificates.
// POST /api/v1/ca/tcg/sign-csr
func (s *Server) handleSignTCGCSR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "ca", "write") {
		return
	}

	var req transport.SignTCGCSRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	svc, err := xkms.Get()
	if err != nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	resp, err := svc.SignTCGCSR(r.Context(), &req)
	if err != nil {
		statusCode := mapCAErrorToStatus(err)
		s.sendError(w, statusCode, err.Error())
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleEnrollDevice performs full TCG device enrollment with credential
// activation challenge.
// POST /api/v1/ca/tcg/enroll
func (s *Server) handleEnrollDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "ca", "write") {
		return
	}

	var req transport.EnrollDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	svc, err := xkms.Get()
	if err != nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	resp, err := svc.EnrollDevice(r.Context(), &req)
	if err != nil {
		statusCode := mapCAErrorToStatus(err)
		s.sendError(w, statusCode, err.Error())
		return
	}

	s.sendJSON(w, http.StatusCreated, resp)
}
