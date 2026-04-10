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
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// setupPIVRoutes registers PIV-related HTTP routes on the given ServeMux.
func (s *Server) setupPIVRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/piv/slots", s.handlePIVSlots)
	mux.HandleFunc("/api/v1/piv/slots/", s.handlePIVSlotOperations)
}

// handlePIVSlots handles requests to /api/v1/piv/slots (no trailing path).
// GET returns the list of PIV slots for the specified backend.
func (s *Server) handlePIVSlots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "piv", "read") {
		return
	}

	backendParam := r.URL.Query().Get("backend")
	if backendParam == "" {
		s.sendError(w, http.StatusBadRequest, "backend query parameter is required")
		return
	}

	ctx := r.Context()
	resp, err := xkms.ListPIVSlots(ctx, &transport.ListPIVSlotsRequest{
		Backend: backendParam,
	})
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list PIV slots: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handlePIVSlotOperations dispatches requests to /api/v1/piv/slots/{slot}/...
// It extracts the slot identifier and the trailing operation from the URL path
// and delegates to the appropriate handler.
func (s *Server) handlePIVSlotOperations(w http.ResponseWriter, r *http.Request) {
	// Extract slot and operation from path: /api/v1/piv/slots/{slot}/{operation}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/piv/slots/")
	parts := strings.SplitN(path, "/", 2)

	if len(parts) == 0 || parts[0] == "" {
		s.sendError(w, http.StatusBadRequest, "slot is required")
		return
	}

	slot := parts[0]
	var operation string
	if len(parts) > 1 {
		operation = parts[1]
	}

	backendParam := r.URL.Query().Get("backend")

	// Map-based dispatch for O(1) constant-time lookup
	type pivHandler func(w http.ResponseWriter, r *http.Request, slot, backend string)
	handlers := map[string]pivHandler{
		"certificate": s.handlePIVCertificate,
		"generate":    s.handlePIVGenerateKey,
		"import":      s.handlePIVImportCertificate,
		"export":      s.handlePIVExportCertificate,
		"csr":         s.handlePIVGenerateCSR,
	}

	handler, ok := handlers[operation]
	if !ok {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("unknown PIV operation: %s", operation))
		return
	}

	handler(w, r, slot, backendParam)
}

// handlePIVCertificate handles GET, POST, and DELETE on
// /api/v1/piv/slots/{slot}/certificate.
func (s *Server) handlePIVCertificate(w http.ResponseWriter, r *http.Request, slot, backendParam string) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetPIVCertificate(w, r, slot, backendParam)
	case http.MethodPost:
		s.handleStorePIVCertificate(w, r, slot)
	case http.MethodDelete:
		s.handleDeletePIVCertificate(w, r, slot, backendParam)
	default:
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleGetPIVCertificate retrieves a certificate from a PIV slot.
// GET /api/v1/piv/slots/{slot}/certificate?backend={backend}&format={format}
func (s *Server) handleGetPIVCertificate(w http.ResponseWriter, r *http.Request, slot, backendParam string) {
	if !s.authorize(w, r, "piv", "read") {
		return
	}

	if backendParam == "" {
		s.sendError(w, http.StatusBadRequest, "backend query parameter is required")
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "pem"
	}

	ctx := r.Context()
	resp, err := xkms.GetPIVCertificate(ctx, &transport.GetPIVCertificateRequest{
		Backend: backendParam,
		Slot:    slot,
		Format:  format,
	})
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get PIV certificate: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleStorePIVCertificate stores a certificate in a PIV slot.
// POST /api/v1/piv/slots/{slot}/certificate
func (s *Server) handleStorePIVCertificate(w http.ResponseWriter, r *http.Request, slot string) {
	if !s.authorize(w, r, "piv", "use") {
		return
	}

	var req transport.StorePIVCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if req.Backend == "" {
		s.sendError(w, http.StatusBadRequest, "backend is required")
		return
	}

	req.Slot = slot

	ctx := r.Context()
	if err := xkms.StorePIVCertificate(ctx, &req); err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to store PIV certificate: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"slot":   slot,
	})
}

// handleDeletePIVCertificate removes a certificate from a PIV slot.
// DELETE /api/v1/piv/slots/{slot}/certificate?backend={backend}
func (s *Server) handleDeletePIVCertificate(w http.ResponseWriter, r *http.Request, slot, backendParam string) {
	if !s.authorize(w, r, "piv", "use") {
		return
	}

	if backendParam == "" {
		s.sendError(w, http.StatusBadRequest, "backend query parameter is required")
		return
	}

	ctx := r.Context()
	if err := xkms.DeletePIVCertificate(ctx, &transport.DeletePIVCertificateRequest{
		Backend: backendParam,
		Slot:    slot,
	}); err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete PIV certificate: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"slot":   slot,
	})
}

// handlePIVGenerateKey generates a new key pair in a PIV slot.
// POST /api/v1/piv/slots/{slot}/generate
func (s *Server) handlePIVGenerateKey(w http.ResponseWriter, r *http.Request, slot, _ string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "piv", "use") {
		return
	}

	var req transport.GeneratePIVKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if req.Backend == "" {
		s.sendError(w, http.StatusBadRequest, "backend is required")
		return
	}

	req.Slot = slot

	ctx := r.Context()
	resp, err := xkms.GeneratePIVKey(ctx, &req)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to generate PIV key: %v", err))
		return
	}

	s.sendJSON(w, http.StatusCreated, resp)
}

// handlePIVImportCertificate imports a certificate into a PIV slot.
// POST /api/v1/piv/slots/{slot}/import
func (s *Server) handlePIVImportCertificate(w http.ResponseWriter, r *http.Request, slot, _ string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "piv", "use") {
		return
	}

	var req transport.StorePIVCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if req.Backend == "" {
		s.sendError(w, http.StatusBadRequest, "backend is required")
		return
	}

	req.Slot = slot

	ctx := r.Context()
	if err := xkms.ImportPIVCertificate(ctx, &req); err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to import PIV certificate: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"slot":   slot,
	})
}

// handlePIVExportCertificate exports a certificate from a PIV slot.
// GET /api/v1/piv/slots/{slot}/export?backend={backend}&format={format}
func (s *Server) handlePIVExportCertificate(w http.ResponseWriter, r *http.Request, slot, backendParam string) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "piv", "read") {
		return
	}

	if backendParam == "" {
		s.sendError(w, http.StatusBadRequest, "backend query parameter is required")
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "pem"
	}

	ctx := r.Context()
	resp, err := xkms.ExportPIVCertificate(ctx, &transport.GetPIVCertificateRequest{
		Backend: backendParam,
		Slot:    slot,
		Format:  format,
	})
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to export PIV certificate: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handlePIVGenerateCSR generates a certificate signing request for a PIV slot.
// POST /api/v1/piv/slots/{slot}/csr
func (s *Server) handlePIVGenerateCSR(w http.ResponseWriter, r *http.Request, slot, _ string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, "piv", "use") {
		return
	}

	var req transport.GeneratePIVCSRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if req.Backend == "" {
		s.sendError(w, http.StatusBadRequest, "backend is required")
		return
	}

	req.Slot = slot

	ctx := r.Context()
	resp, err := xkms.GeneratePIVCSR(ctx, &req)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to generate PIV CSR: %v", err))
		return
	}

	s.sendJSON(w, http.StatusCreated, resp)
}
