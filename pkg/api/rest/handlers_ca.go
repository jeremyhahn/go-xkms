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
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	transport "github.com/jeremyhahn/go-xkms/pkg/api/transport"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// caServicer defines the CA operations required by the CA handlers.
// This interface decouples the REST layer from the concrete CA implementation,
// allowing any type that satisfies these methods (including XKMSService) to
// be used.
type caServicer interface {
	// GetCABundle returns the CA certificate bundle.
	GetCABundle(ctx context.Context, req *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error)

	// GetCACertificate returns the CA certificate.
	GetCACertificate(ctx context.Context, req *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error)

	// SignCSR signs a certificate signing request.
	SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error)

	// IssueCertificate issues a new certificate with the given parameters.
	IssueCertificate(ctx context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error)

	// RevokeCertificate revokes a certificate by serial number.
	RevokeCertificate(ctx context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error)

	// GenerateCRL generates a certificate revocation list.
	GenerateCRL(ctx context.Context, req *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error)

	// IsRevoked checks whether a certificate is revoked.
	IsRevoked(ctx context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error)
}

// Typed errors for CA handlers.
var (
	ErrMissingSerialNumber = errors.New("missing serial number")
	ErrMissingCSRData      = errors.New("missing CSR data")
	ErrMissingCommonName   = errors.New("missing common name")
	ErrMissingProfile      = errors.New("missing certificate profile")
)

// caErrorStatusMap maps CA errors to HTTP status codes for O(1) lookup.
var caErrorStatusMap = map[error]int{
	xkms.ErrNotConfigured:        http.StatusServiceUnavailable,
	xkms.ErrNilRequest:           http.StatusBadRequest,
	xkms.ErrNilData:              http.StatusBadRequest,
	xkms.ErrInvalidKeyAttributes: http.StatusBadRequest,
	xkms.ErrCertNotFound:         http.StatusNotFound,
	xkms.ErrInvalidEncodingPEM:   http.StatusBadRequest,
}

// CAHandlers provides HTTP handlers for the CA operations API.
type CAHandlers struct {
	ca     caServicer
	logger *slog.Logger
}

// NewCAHandlers creates a new CAHandlers instance. The ca parameter accepts
// any type satisfying the caServicer interface, including *xkms.XKMSService.
func NewCAHandlers(ca caServicer, logger *slog.Logger) *CAHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &CAHandlers{
		ca:     ca,
		logger: logger,
	}
}

// HandleGetCABundle returns the CA certificate bundle.
// GET /api/v1/ca/bundle
func (h *CAHandlers) HandleGetCABundle(w http.ResponseWriter, r *http.Request) {
	req := &transport.GetCABundleRequest{
		StoreType: r.URL.Query().Get("store_type"),
		Algorithm: r.URL.Query().Get("algorithm"),
	}

	resp, err := h.ca.GetCABundle(r.Context(), req)
	if err != nil {
		h.logger.Warn("ca: get bundle failed",
			slog.String("error", err.Error()))
		writeError(w, err, mapCAError(err))
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// HandleGetCACertificate returns the CA certificate.
// GET /api/v1/ca/certificate
func (h *CAHandlers) HandleGetCACertificate(w http.ResponseWriter, r *http.Request) {
	req := &transport.GetCACertificateRequest{
		Identity: r.URL.Query().Get("identity"),
	}

	resp, err := h.ca.GetCACertificate(r.Context(), req)
	if err != nil {
		h.logger.Warn("ca: get certificate failed",
			slog.String("error", err.Error()))
		writeError(w, err, mapCAError(err))
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// HandleSignCSR signs a certificate signing request.
// POST /api/v1/ca/sign-csr
func (h *CAHandlers) HandleSignCSR(w http.ResponseWriter, r *http.Request) {
	var req transport.SignCSRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if len(req.CSRPEM) == 0 {
		writeError(w, ErrMissingCSRData, http.StatusBadRequest)
		return
	}

	resp, err := h.ca.SignCSR(r.Context(), &req)
	if err != nil {
		h.logger.Warn("ca: sign CSR failed",
			slog.String("error", err.Error()))
		writeError(w, err, mapCAError(err))
		return
	}

	h.logger.Info("ca: CSR signed",
		slog.String("serial", resp.SerialNumber))

	writeJSON(w, resp, http.StatusOK)
}

// HandleIssueCertificate issues a new certificate.
// POST /api/v1/ca/issue
func (h *CAHandlers) HandleIssueCertificate(w http.ResponseWriter, r *http.Request) {
	var req transport.IssueCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.CommonName == "" {
		writeError(w, ErrMissingCommonName, http.StatusBadRequest)
		return
	}

	if req.Profile == "" {
		writeError(w, ErrMissingProfile, http.StatusBadRequest)
		return
	}

	resp, err := h.ca.IssueCertificate(r.Context(), &req)
	if err != nil {
		h.logger.Warn("ca: issue certificate failed",
			slog.String("common_name", req.CommonName),
			slog.String("error", err.Error()))
		writeError(w, err, mapCAError(err))
		return
	}

	h.logger.Info("ca: certificate issued",
		slog.String("common_name", req.CommonName),
		slog.String("serial", resp.SerialNumber))

	writeJSON(w, resp, http.StatusCreated)
}

// HandleRevokeCertificate revokes a certificate by serial number.
// POST /api/v1/ca/revoke
func (h *CAHandlers) HandleRevokeCertificate(w http.ResponseWriter, r *http.Request) {
	var req transport.RevokeCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.SerialNumber == "" {
		writeError(w, ErrMissingSerialNumber, http.StatusBadRequest)
		return
	}

	resp, err := h.ca.RevokeCertificate(r.Context(), &req)
	if err != nil {
		h.logger.Warn("ca: revoke certificate failed",
			slog.String("serial", req.SerialNumber),
			slog.String("error", err.Error()))
		writeError(w, err, mapCAError(err))
		return
	}

	h.logger.Info("ca: certificate revoked",
		slog.String("serial", req.SerialNumber))

	writeJSON(w, resp, http.StatusOK)
}

// HandleGenerateCRL generates a certificate revocation list.
// POST /api/v1/ca/crl
func (h *CAHandlers) HandleGenerateCRL(w http.ResponseWriter, r *http.Request) {
	var req transport.GenerateCRLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Allow empty body for CRL generation (no required fields)
		req = transport.GenerateCRLRequest{}
	}

	resp, err := h.ca.GenerateCRL(r.Context(), &req)
	if err != nil {
		h.logger.Warn("ca: generate CRL failed",
			slog.String("error", err.Error()))
		writeError(w, err, mapCAError(err))
		return
	}

	h.logger.Info("ca: CRL generated")

	writeJSON(w, resp, http.StatusOK)
}

// HandleIsRevoked checks whether a certificate is revoked by serial number.
// GET /api/v1/ca/revoked/{serial}
func (h *CAHandlers) HandleIsRevoked(w http.ResponseWriter, r *http.Request) {
	serial := chi.URLParam(r, "serial")
	if serial == "" {
		writeError(w, ErrMissingSerialNumber, http.StatusBadRequest)
		return
	}

	req := &transport.IsRevokedRequest{
		SerialNumber: serial,
	}

	resp, err := h.ca.IsRevoked(r.Context(), req)
	if err != nil {
		h.logger.Warn("ca: is-revoked check failed",
			slog.String("serial", serial),
			slog.String("error", err.Error()))
		writeError(w, err, mapCAError(err))
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// mapCAError maps a CA error to the appropriate HTTP status code.
func mapCAError(err error) int {
	for sentinelErr, status := range caErrorStatusMap {
		if errors.Is(err, sentinelErr) {
			return status
		}
	}
	return http.StatusInternalServerError
}
