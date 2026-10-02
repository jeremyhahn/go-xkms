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
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// tcgCAServicer defines the TCG-specific CA operations required by the TCG
// CA handlers. This interface decouples the REST layer from the concrete CA
// implementation, allowing any type that satisfies these methods to be used.
type tcgCAServicer interface {
	// IssueEKCertificate issues an Endorsement Key certificate for a TPM.
	IssueEKCertificate(ctx context.Context, req *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error)

	// IssueAKCertificate issues an Attestation Key certificate for a TPM.
	IssueAKCertificate(ctx context.Context, req *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error)

	// SignTCGCSR signs a TCG-CSR-IDEVID and returns IAK and IDevID certificates.
	SignTCGCSR(ctx context.Context, req *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error)

	// EnrollDevice performs full TCG device enrollment with credential activation challenge.
	EnrollDevice(ctx context.Context, req *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error)

	// IssueLAKCertificate issues a Local Attestation Key certificate in the
	// WebAuthn Level 2 §8.3.1 profile (go-xkms#715).
	IssueLAKCertificate(ctx context.Context, req *transport.IssueLAKCertificateRequest) (*transport.IssueLAKCertificateResponse, error)
}

// Typed errors for TCG CA handlers.
var (
	ErrMissingEKPublicKey    = &tcgCAError{"missing EK public key"}
	ErrMissingPublicKey      = &tcgCAError{"missing public key"}
	ErrMissingTCGCSR         = &tcgCAError{"missing TCG CSR data"}
	ErrMissingPackedCSR      = &tcgCAError{"missing packed CSR data"}
	ErrTCGCANotSupported     = &tcgCAError{"CA does not support TCG operations"}
	ErrMissingIAKCertificate = &tcgCAError{"missing IAK certificate"}
	ErrMissingCertifyInfo    = &tcgCAError{"missing TPM2_Certify evidence (certify info and signature)"}
	ErrMissingLAKPublicArea  = &tcgCAError{"missing LAK public area"}
	ErrMissingTPMDeviceInfo  = &tcgCAError{"missing TPM manufacturer, model or firmware version"}
)

// tcgCAError is a typed error for TCG CA handler validation failures.
type tcgCAError struct {
	msg string
}

// Error implements the error interface.
func (e *tcgCAError) Error() string {
	return e.msg
}

// HandleIssueEKCertificate issues an Endorsement Key certificate for a TPM.
// POST /api/v1/ca/tcg/ek
func (h *CAHandlers) HandleIssueEKCertificate(w http.ResponseWriter, r *http.Request) {
	tcg, ok := h.ca.(tcgCAServicer)
	if !ok {
		writeError(w, ErrTCGCANotSupported, http.StatusNotImplemented)
		return
	}

	var req transport.IssueEKCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.CommonName == "" {
		writeError(w, ErrMissingCommonName, http.StatusBadRequest)
		return
	}

	if len(req.EKPublicKey) == 0 {
		writeError(w, ErrMissingEKPublicKey, http.StatusBadRequest)
		return
	}

	resp, err := tcg.IssueEKCertificate(r.Context(), &req)
	if err != nil {
		h.logger.Warn("ca: issue EK certificate failed",
			slog.String("common_name", req.CommonName),
			slog.String("error", err.Error()))
		writeError(w, err, mapCAError(err))
		return
	}

	h.logger.Info("ca: EK certificate issued",
		slog.String("common_name", req.CommonName),
		slog.String("serial", resp.SerialNumber))

	writeJSON(w, resp, http.StatusCreated)
}

// HandleIssueAKCertificate issues an Attestation Key certificate for a TPM.
// POST /api/v1/ca/tcg/ak
func (h *CAHandlers) HandleIssueAKCertificate(w http.ResponseWriter, r *http.Request) {
	tcg, ok := h.ca.(tcgCAServicer)
	if !ok {
		writeError(w, ErrTCGCANotSupported, http.StatusNotImplemented)
		return
	}

	var req transport.IssueAKCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.CommonName == "" {
		writeError(w, ErrMissingCommonName, http.StatusBadRequest)
		return
	}

	if len(req.PublicKey) == 0 {
		writeError(w, ErrMissingPublicKey, http.StatusBadRequest)
		return
	}

	resp, err := tcg.IssueAKCertificate(r.Context(), &req)
	if err != nil {
		h.logger.Warn("ca: issue AK certificate failed",
			slog.String("common_name", req.CommonName),
			slog.String("error", err.Error()))
		writeError(w, err, mapCAError(err))
		return
	}

	h.logger.Info("ca: AK certificate issued",
		slog.String("common_name", req.CommonName),
		slog.String("serial", resp.SerialNumber))

	writeJSON(w, resp, http.StatusCreated)
}

// HandleSignTCGCSR signs a TCG-CSR-IDEVID and returns IAK and IDevID certificates.
// POST /api/v1/ca/tcg/sign-csr
func (h *CAHandlers) HandleSignTCGCSR(w http.ResponseWriter, r *http.Request) {
	tcg, ok := h.ca.(tcgCAServicer)
	if !ok {
		writeError(w, ErrTCGCANotSupported, http.StatusNotImplemented)
		return
	}

	var req transport.SignTCGCSRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.CommonName == "" {
		writeError(w, ErrMissingCommonName, http.StatusBadRequest)
		return
	}

	if len(req.TCGCSR) == 0 {
		writeError(w, ErrMissingTCGCSR, http.StatusBadRequest)
		return
	}

	resp, err := tcg.SignTCGCSR(r.Context(), &req)
	if err != nil {
		h.logger.Warn("ca: sign TCG CSR failed",
			slog.String("common_name", req.CommonName),
			slog.String("error", err.Error()))
		writeError(w, err, mapCAError(err))
		return
	}

	h.logger.Info("ca: TCG CSR signed",
		slog.String("common_name", req.CommonName))

	writeJSON(w, resp, http.StatusOK)
}

// HandleEnrollDevice performs full TCG device enrollment with credential
// activation challenge.
// POST /api/v1/ca/tcg/enroll
func (h *CAHandlers) HandleEnrollDevice(w http.ResponseWriter, r *http.Request) {
	tcg, ok := h.ca.(tcgCAServicer)
	if !ok {
		writeError(w, ErrTCGCANotSupported, http.StatusNotImplemented)
		return
	}

	var req transport.EnrollDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.CommonName == "" {
		writeError(w, ErrMissingCommonName, http.StatusBadRequest)
		return
	}

	if len(req.PackedCSR) == 0 {
		writeError(w, ErrMissingPackedCSR, http.StatusBadRequest)
		return
	}

	resp, err := tcg.EnrollDevice(r.Context(), &req)
	if err != nil {
		h.logger.Warn("ca: enroll device failed",
			slog.String("common_name", req.CommonName),
			slog.String("error", err.Error()))
		writeError(w, err, mapCAError(err))
		return
	}

	h.logger.Info("ca: device enrolled",
		slog.String("common_name", req.CommonName))

	writeJSON(w, resp, http.StatusCreated)
}

// HandleIssueLAKCertificate issues a Local Attestation Key certificate in
// the WebAuthn Level 2 §8.3.1 profile (go-xkms#715).
// POST /api/v1/ca/tcg/lak
func (h *CAHandlers) HandleIssueLAKCertificate(w http.ResponseWriter, r *http.Request) {
	tcg, ok := h.ca.(tcgCAServicer)
	if !ok {
		writeError(w, ErrTCGCANotSupported, http.StatusNotImplemented)
		return
	}

	var req transport.IssueLAKCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.TPMManufacturer == "" || req.TPMModel == "" || req.TPMFirmwareVersion == "" {
		writeError(w, ErrMissingTPMDeviceInfo, http.StatusBadRequest)
		return
	}

	if len(req.IAKCertificateDER) == 0 {
		writeError(w, ErrMissingIAKCertificate, http.StatusBadRequest)
		return
	}

	if len(req.CertifyInfo) == 0 || len(req.Signature) == 0 {
		writeError(w, ErrMissingCertifyInfo, http.StatusBadRequest)
		return
	}

	if len(req.LAKPublicArea) == 0 {
		writeError(w, ErrMissingLAKPublicArea, http.StatusBadRequest)
		return
	}

	resp, err := tcg.IssueLAKCertificate(r.Context(), &req)
	if err != nil {
		h.logger.Warn("ca: issue LAK certificate failed",
			slog.String("error", err.Error()))
		writeError(w, err, mapCAError(err))
		return
	}

	h.logger.Info("ca: LAK certificate issued",
		slog.String("serial", resp.SerialNumber))

	writeJSON(w, resp, http.StatusCreated)
}
