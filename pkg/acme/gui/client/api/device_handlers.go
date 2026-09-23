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

package api

import (
	"encoding/json"
	"net/http"
	"time"
)

// deviceNameRequest is the JSON request body for spec-based device operations.
type deviceNameRequest struct {
	Name string `json:"name"`
}

// deviceEnrollResponse is the JSON response body for device enrollment.
type deviceEnrollResponse struct {
	Name              string `json:"name"`
	IAKSubject        string `json:"iakSubject"`
	IDevIDSubject     string `json:"idevidSubject"`
	IDevIDNotBefore   string `json:"idevidNotBefore"`
	IDevIDNotAfter    string `json:"idevidNotAfter"`
	IssuingChainCount int    `json:"issuingChainCount"`
}

// deviceEnroll handles POST /api/v1/device/enroll.
func (h *handlers) deviceEnroll(w http.ResponseWriter, r *http.Request) {
	var req deviceNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, (&ErrInvalidRequestBody{Detail: err.Error()}).Error())
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, (&ErrMissingField{Field: "name"}).Error())
		return
	}

	result, err := h.service.Devices().Enroll(r.Context(), req.Name)
	if err != nil {
		h.logger.Error("device enrollment failed", "error", err.Error(), "name", req.Name)
		writeError(w, http.StatusInternalServerError, (&ErrServiceCall{Operation: "enroll device", Detail: err.Error()}).Error())
		return
	}

	writeJSON(w, http.StatusOK, &deviceEnrollResponse{
		Name:              req.Name,
		IAKSubject:        result.IAKCertificate.Subject.CommonName,
		IDevIDSubject:     result.IDevIDCertificate.Subject.CommonName,
		IDevIDNotBefore:   result.IDevIDCertificate.NotBefore.UTC().Format(time.RFC3339),
		IDevIDNotAfter:    result.IDevIDCertificate.NotAfter.UTC().Format(time.RFC3339),
		IssuingChainCount: len(result.Chain),
	})
}

// deviceAttestResponse is the JSON response body for device attestation.
type deviceAttestResponse struct {
	Name      string `json:"name"`
	Subject   string `json:"subject"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

// deviceAttest handles POST /api/v1/device/attest.
func (h *handlers) deviceAttest(w http.ResponseWriter, r *http.Request) {
	var req deviceNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, (&ErrInvalidRequestBody{Detail: err.Error()}).Error())
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, (&ErrMissingField{Field: "name"}).Error())
		return
	}

	result, err := h.service.Devices().Attest(r.Context(), req.Name)
	if err != nil {
		h.logger.Error("device attestation failed", "error", err.Error(), "name", req.Name)
		writeError(w, http.StatusInternalServerError, (&ErrServiceCall{Operation: "attest device", Detail: err.Error()}).Error())
		return
	}

	writeJSON(w, http.StatusOK, &deviceAttestResponse{
		Name:      req.Name,
		Subject:   result.Certificate.Subject.CommonName,
		NotBefore: result.Certificate.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  result.Certificate.NotAfter.UTC().Format(time.RFC3339),
	})
}
