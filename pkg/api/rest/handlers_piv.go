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
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// PIV handler typed errors.
var (
	ErrPIVMissingSlot = errors.New("rest: missing slot parameter")
)

// ListPIVSlotsHandler handles GET /api/v1/piv/slots requests.
// Returns the status of all PIV slots for the specified backend.
//
// Query parameters:
//   - backend: backend identifier (required)
func (h *HandlerContext) ListPIVSlotsHandler(w http.ResponseWriter, r *http.Request) {
	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	req := &transport.ListPIVSlotsRequest{
		Backend: backendID,
	}

	resp, err := xkms.ListPIVSlots(r.Context(), req)
	if err != nil {
		log.Printf("Failed to list PIV slots: %v", err)
		handlePIVError(w, err)
		return
	}

	pageReq := parsePageRequest(r)
	paged, pageResp := applyPagination(resp.Slots, pageReq)
	resp.Slots = paged
	resp.PageResponse = pageResp

	writeJSON(w, resp, http.StatusOK)
}

// GetPIVCertificateHandler handles GET /api/v1/piv/slots/{slot}/certificate requests.
// Retrieves a certificate from the specified PIV slot.
//
// URL parameters:
//   - slot: PIV slot identifier (required)
//
// Query parameters:
//   - backend: backend identifier (required)
//   - format: certificate format, "pem" or "der" (required)
func (h *HandlerContext) GetPIVCertificateHandler(w http.ResponseWriter, r *http.Request) {
	slot := chi.URLParam(r, "slot")
	if slot == "" {
		writeError(w, ErrPIVMissingSlot, http.StatusBadRequest)
		return
	}

	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "pem"
	}

	req := &transport.GetPIVCertificateRequest{
		Backend: backendID,
		Slot:    slot,
		Format:  format,
	}

	resp, err := xkms.GetPIVCertificate(r.Context(), req)
	if err != nil {
		log.Printf("Failed to get PIV certificate: %v", err)
		handlePIVError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// StorePIVCertificateHandler handles POST /api/v1/piv/slots/{slot}/certificate requests.
// Stores a certificate in the specified PIV slot.
//
// URL parameters:
//   - slot: PIV slot identifier (required)
//
// Request body (JSON):
//
//	{
//	  "backend": "string",
//	  "certificate": "base64-bytes",
//	  "format": "pem|der"
//	}
func (h *HandlerContext) StorePIVCertificateHandler(w http.ResponseWriter, r *http.Request) {
	slot := chi.URLParam(r, "slot")
	if slot == "" {
		writeError(w, ErrPIVMissingSlot, http.StatusBadRequest)
		return
	}

	var req transport.StorePIVCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Override slot from URL path
	req.Slot = slot

	if req.Backend == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	if err := xkms.StorePIVCertificate(r.Context(), &req); err != nil {
		log.Printf("Failed to store PIV certificate: %v", err)
		handlePIVError(w, err)
		return
	}

	writeJSON(w, &SuccessResponse{
		Success: true,
		Message: "Certificate stored in slot " + slot,
	}, http.StatusCreated)
}

// DeletePIVCertificateHandler handles DELETE /api/v1/piv/slots/{slot}/certificate requests.
// Deletes a certificate from the specified PIV slot.
//
// URL parameters:
//   - slot: PIV slot identifier (required)
//
// Query parameters:
//   - backend: backend identifier (required)
func (h *HandlerContext) DeletePIVCertificateHandler(w http.ResponseWriter, r *http.Request) {
	slot := chi.URLParam(r, "slot")
	if slot == "" {
		writeError(w, ErrPIVMissingSlot, http.StatusBadRequest)
		return
	}

	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	req := &transport.DeletePIVCertificateRequest{
		Backend: backendID,
		Slot:    slot,
	}

	if err := xkms.DeletePIVCertificate(r.Context(), req); err != nil {
		log.Printf("Failed to delete PIV certificate: %v", err)
		handlePIVError(w, err)
		return
	}

	writeJSON(w, &SuccessResponse{
		Success: true,
		Message: "Certificate deleted from slot " + slot,
	}, http.StatusOK)
}

// GeneratePIVKeyHandler handles POST /api/v1/piv/slots/{slot}/generate requests.
// Generates a new key pair in the specified PIV slot with a self-signed certificate.
//
// URL parameters:
//   - slot: PIV slot identifier (required)
//
// Request body (JSON):
//
//	{
//	  "backend": "string",
//	  "algorithm": "string",
//	  "subject": "string"
//	}
func (h *HandlerContext) GeneratePIVKeyHandler(w http.ResponseWriter, r *http.Request) {
	slot := chi.URLParam(r, "slot")
	if slot == "" {
		writeError(w, ErrPIVMissingSlot, http.StatusBadRequest)
		return
	}

	var req transport.GeneratePIVKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Override slot from URL path
	req.Slot = slot

	if req.Backend == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	resp, err := xkms.GeneratePIVKey(r.Context(), &req)
	if err != nil {
		log.Printf("Failed to generate PIV key: %v", err)
		handlePIVError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusCreated)
}

// ImportPIVCertificateHandler handles POST /api/v1/piv/slots/{slot}/import requests.
// Imports a certificate into the specified PIV slot.
//
// URL parameters:
//   - slot: PIV slot identifier (required)
//
// Request body (JSON):
//
//	{
//	  "backend": "string",
//	  "certificate": "base64-bytes",
//	  "format": "pem|der"
//	}
func (h *HandlerContext) ImportPIVCertificateHandler(w http.ResponseWriter, r *http.Request) {
	slot := chi.URLParam(r, "slot")
	if slot == "" {
		writeError(w, ErrPIVMissingSlot, http.StatusBadRequest)
		return
	}

	var req transport.StorePIVCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Override slot from URL path
	req.Slot = slot

	if req.Backend == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	if err := xkms.ImportPIVCertificate(r.Context(), &req); err != nil {
		log.Printf("Failed to import PIV certificate: %v", err)
		handlePIVError(w, err)
		return
	}

	writeJSON(w, &SuccessResponse{
		Success: true,
		Message: "Certificate imported into slot " + slot,
	}, http.StatusCreated)
}

// ExportPIVCertificateHandler handles GET /api/v1/piv/slots/{slot}/export requests.
// Exports a certificate from the specified PIV slot.
//
// URL parameters:
//   - slot: PIV slot identifier (required)
//
// Query parameters:
//   - backend: backend identifier (required)
//   - format: certificate format, "pem" or "der" (required)
func (h *HandlerContext) ExportPIVCertificateHandler(w http.ResponseWriter, r *http.Request) {
	slot := chi.URLParam(r, "slot")
	if slot == "" {
		writeError(w, ErrPIVMissingSlot, http.StatusBadRequest)
		return
	}

	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "pem"
	}

	req := &transport.GetPIVCertificateRequest{
		Backend: backendID,
		Slot:    slot,
		Format:  format,
	}

	resp, err := xkms.ExportPIVCertificate(r.Context(), req)
	if err != nil {
		log.Printf("Failed to export PIV certificate: %v", err)
		handlePIVError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// GeneratePIVCSRHandler handles POST /api/v1/piv/slots/{slot}/csr requests.
// Generates a certificate signing request for the key in the specified PIV slot.
//
// URL parameters:
//   - slot: PIV slot identifier (required)
//
// Request body (JSON):
//
//	{
//	  "backend": "string",
//	  "subject": "string"
//	}
func (h *HandlerContext) GeneratePIVCSRHandler(w http.ResponseWriter, r *http.Request) {
	slot := chi.URLParam(r, "slot")
	if slot == "" {
		writeError(w, ErrPIVMissingSlot, http.StatusBadRequest)
		return
	}

	var req transport.GeneratePIVCSRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Override slot from URL path
	req.Slot = slot

	if req.Backend == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	resp, err := xkms.GeneratePIVCSR(r.Context(), &req)
	if err != nil {
		log.Printf("Failed to generate PIV CSR: %v", err)
		handlePIVError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusCreated)
}

// handlePIVError maps PIV-specific errors to HTTP status codes and writes the response.
func handlePIVError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, xkms.ErrPIVNotInitialized):
		writeError(w, err, http.StatusServiceUnavailable)
	case errors.Is(err, xkms.ErrPIVBackendNotFound):
		writeError(w, err, http.StatusNotFound)
	case errors.Is(err, xkms.ErrPIVInvalidSlot),
		errors.Is(err, xkms.ErrPIVInvalidFormat),
		errors.Is(err, xkms.ErrPIVInvalidAlgorithm):
		writeError(w, err, http.StatusBadRequest)
	case errors.Is(err, xkms.ErrPIVKeyNotFound):
		writeError(w, err, http.StatusNotFound)
	default:
		handleError(w, err)
	}
}
