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
	"fmt"
	"net/http"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// caErrorStatusMap maps CA-related errors to HTTP status codes for O(1) lookup.
var caErrorStatusMap = map[error]int{
	xkms.ErrNotConfigured:        http.StatusServiceUnavailable,
	xkms.ErrNilRequest:           http.StatusBadRequest,
	xkms.ErrNilData:              http.StatusBadRequest,
	xkms.ErrInvalidKeyAttributes: http.StatusBadRequest,
}

// handleGetCABundle retrieves the CA certificate bundle.
// GET /api/v1/ca/bundle
func (s *Server) handleGetCABundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "ca", "read") {
		return
	}

	svc, err := xkms.Get()
	if err != nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	req := &transport.GetCABundleRequest{
		StoreType: r.URL.Query().Get("store_type"),
		Algorithm: r.URL.Query().Get("algorithm"),
	}

	resp, err := svc.GetCABundle(r.Context(), req)
	if err != nil {
		statusCode := mapCAErrorToStatus(err)
		s.sendError(w, statusCode, err.Error())
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleGetCACertificate retrieves the CA certificate.
// GET /api/v1/ca/certificate
func (s *Server) handleGetCACertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "ca", "read") {
		return
	}

	svc, err := xkms.Get()
	if err != nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	req := &transport.GetCACertificateRequest{
		Identity: r.URL.Query().Get("identity"),
	}

	resp, err := svc.GetCACertificate(r.Context(), req)
	if err != nil {
		statusCode := mapCAErrorToStatus(err)
		s.sendError(w, statusCode, err.Error())
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleSignCSR signs a certificate signing request using the CA.
// POST /api/v1/ca/sign-csr
func (s *Server) handleSignCSR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "ca", "write") {
		return
	}

	var req transport.SignCSRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	svc, err := xkms.Get()
	if err != nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	resp, err := svc.SignCSR(r.Context(), &req)
	if err != nil {
		statusCode := mapCAErrorToStatus(err)
		s.sendError(w, statusCode, err.Error())
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleIssueCertificate issues a new certificate from the CA.
// POST /api/v1/ca/issue
func (s *Server) handleIssueCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "ca", "write") {
		return
	}

	var req transport.IssueCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	svc, err := xkms.Get()
	if err != nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	resp, err := svc.IssueCertificate(r.Context(), &req)
	if err != nil {
		statusCode := mapCAErrorToStatus(err)
		s.sendError(w, statusCode, err.Error())
		return
	}

	s.sendJSON(w, http.StatusCreated, resp)
}

// handleRevokeCertificate revokes a certificate by serial number.
// POST /api/v1/ca/revoke
func (s *Server) handleRevokeCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "ca", "write") {
		return
	}

	var req transport.RevokeCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	svc, err := xkms.Get()
	if err != nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	resp, err := svc.RevokeCertificate(r.Context(), &req)
	if err != nil {
		statusCode := mapCAErrorToStatus(err)
		s.sendError(w, statusCode, err.Error())
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleGenerateCRL generates a certificate revocation list.
// POST /api/v1/ca/crl
func (s *Server) handleGenerateCRL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "ca", "write") {
		return
	}

	var req transport.GenerateCRLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	svc, err := xkms.Get()
	if err != nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	resp, err := svc.GenerateCRL(r.Context(), &req)
	if err != nil {
		statusCode := mapCAErrorToStatus(err)
		s.sendError(w, statusCode, err.Error())
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleIsRevoked checks whether a certificate has been revoked.
// GET /api/v1/ca/revoked/{serial}
func (s *Server) handleIsRevoked(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "ca", "read") {
		return
	}

	// Extract serial from path: /api/v1/ca/revoked/{serial}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/ca/revoked/")
	serial := strings.TrimSuffix(path, "/")

	if serial == "" {
		s.sendError(w, http.StatusBadRequest, "serial number is required")
		return
	}

	svc, err := xkms.Get()
	if err != nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrXKMSServiceUnavailable.Error())
		return
	}

	req := &transport.IsRevokedRequest{
		SerialNumber: serial,
	}

	resp, err := svc.IsRevoked(r.Context(), req)
	if err != nil {
		statusCode := mapCAErrorToStatus(err)
		s.sendError(w, statusCode, err.Error())
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// mapCAErrorToStatus maps a CA error to the appropriate HTTP status code.
func mapCAErrorToStatus(err error) int {
	for sentinel, status := range caErrorStatusMap {
		if errors.Is(err, sentinel) {
			return status
		}
	}
	return http.StatusInternalServerError
}
