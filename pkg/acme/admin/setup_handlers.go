// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package admin

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// SetupHandlers provides HTTP handlers for first-run setup API endpoints.
type SetupHandlers struct {
	service SetupService
	logger  *slog.Logger
}

// NewSetupHandlers creates a new setup handlers instance.
func NewSetupHandlers(svc SetupService, logger *slog.Logger) *SetupHandlers {
	return &SetupHandlers{
		service: svc,
		logger:  logger,
	}
}

// RegisterRoutes registers all setup API routes with the router.
// Setup endpoints have no auth middleware because no users exist during first-run.
func (h *SetupHandlers) RegisterRoutes(router *mux.Router) {
	setupRouter := router.PathPrefix("/admin/setup").Subrouter()

	setupRouter.HandleFunc("/status", h.handleSetupStatus).Methods("GET")
	setupRouter.HandleFunc("/barrier", h.handleSetupBarrier).Methods("POST")
	setupRouter.HandleFunc("/ca", h.handleSetupCA).Methods("POST")
	setupRouter.HandleFunc("/complete", h.handleSetupComplete).Methods("POST")
	setupRouter.HandleFunc("/defaults", h.handleSetupDefaults).Methods("GET")
}

// handleSetupStatus handles GET /admin/setup/status.
func (h *SetupHandlers) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	status, err := h.service.Status(r.Context())
	if err != nil {
		h.logger.Error("failed to get setup status", slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to get setup status")
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// handleSetupBarrier handles POST /admin/setup/barrier.
func (h *SetupHandlers) handleSetupBarrier(w http.ResponseWriter, r *http.Request) {
	var req SetupBarrierRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}

	resp, err := h.service.ConfigureBarrier(r.Context(), &req)
	if err != nil {
		h.writeSetupError(w, "barrier", err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleSetupCA handles POST /admin/setup/ca.
func (h *SetupHandlers) handleSetupCA(w http.ResponseWriter, r *http.Request) {
	var req SetupCARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}
	if req.RootCAName == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Root CA name is required")
		return
	}
	if req.IntermediateCAName == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Intermediate CA name is required")
		return
	}
	if req.KeyAlgorithm == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Key algorithm is required")
		return
	}
	if req.ValidityYears < 1 {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Validity years must be at least 1")
		return
	}

	if err := h.service.ConfigureCA(r.Context(), &req); err != nil {
		h.writeSetupError(w, "ca", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "CA configuration stored successfully"})
}

// handleSetupComplete handles POST /admin/setup/complete.
func (h *SetupHandlers) handleSetupComplete(w http.ResponseWriter, r *http.Request) {
	if err := h.service.Complete(r.Context()); err != nil {
		h.writeSetupError(w, "complete", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Setup completed successfully"})
}

// SetupDefaultsResponse contains default CA subject field values.
type SetupDefaultsResponse struct {
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizational_unit"`
	Country            string `json:"country"`
	State              string `json:"state"`
	Locality           string `json:"locality"`
}

// handleSetupDefaults handles GET /admin/setup/defaults.
// Delegates to go-qrdb's xkmssdk.QRDBLoadOpenSSLConfig which searches standard
// OpenSSL configuration paths (OPENSSL_CONF env, /etc/ssl/openssl.cnf,
// /etc/pki/tls/openssl.cnf, etc.) and parses the [req_distinguished_name]
// section to extract default subject field values.
func (h *SetupHandlers) handleSetupDefaults(w http.ResponseWriter, r *http.Request) {
	cfg, err := xkmssdk.QRDBLoadOpenSSLConfig()
	if err != nil || cfg == nil {
		writeJSON(w, http.StatusOK, &SetupDefaultsResponse{})
		return
	}
	writeJSON(w, http.StatusOK, &SetupDefaultsResponse{
		Organization:       cfg.Organization,
		OrganizationalUnit: cfg.OrganizationalUnit,
		Country:            cfg.Country,
		State:              cfg.Province,
		Locality:           cfg.Locality,
	})
}

// writeSetupError maps setup error types to appropriate HTTP responses.
func (h *SetupHandlers) writeSetupError(w http.ResponseWriter, operation string, err error) {
	var alreadyCompleteErr *SetupAlreadyCompleteError
	if errors.As(err, &alreadyCompleteErr) {
		writeProblem(w, http.StatusConflict, "urn:trusted-ca:error:setup-already-complete", alreadyCompleteErr.Error())
		return
	}

	var remoteModeErr *BarrierRemoteModeError
	if errors.As(err, &remoteModeErr) {
		writeProblem(w, http.StatusConflict, "urn:trusted-ca:error:barrier-remote-mode", remoteModeErr.Error())
		return
	}

	var unsupportedStrategyErr *UnsupportedBarrierStrategyError
	if errors.As(err, &unsupportedStrategyErr) {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:setup-invalid", unsupportedStrategyErr.Error())
		return
	}

	var setupErr *SetupError
	if errors.As(err, &setupErr) {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:setup-invalid", setupErr.Error())
		return
	}

	var barrierErr *SetupBarrierError
	if errors.As(err, &barrierErr) {
		h.logger.Error("setup barrier operation failed",
			slog.String("operation", operation),
			slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Setup barrier operation failed")
		return
	}

	h.logger.Error("setup operation failed",
		slog.String("operation", operation),
		slog.String("error", err.Error()))
	writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Setup operation failed")
}
