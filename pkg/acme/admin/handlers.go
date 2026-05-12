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
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

// AlgorithmInfo describes a supported signing or key encapsulation algorithm.
type AlgorithmInfo struct {
	Algorithm string   `json:"algorithm"`
	Curves    []string `json:"curves,omitempty"`
	KeySizes  []int    `json:"key_sizes,omitempty"`
	Backends  []string `json:"backends"`
}

// AlgorithmsResponse lists the available cryptographic algorithms.
type AlgorithmsResponse struct {
	Signing          []AlgorithmInfo `json:"signing"`
	KeyEncapsulation []AlgorithmInfo `json:"key_encapsulation"`
}

// softwareSigningAlgorithms is the static set of signing algorithms supported
// by the software backend. This will be replaced by a dynamic query to go-xkms
// once the SDK provides the canonical version.
var softwareSigningAlgorithms = []AlgorithmInfo{
	{
		Algorithm: "ECDSA",
		Curves:    []string{"P-224", "P-256", "P-384", "P-521"},
		Backends:  []string{"software"},
	},
	{
		Algorithm: "RSA",
		KeySizes:  []int{2048, 3072, 4096},
		Backends:  []string{"software"},
	},
	{
		Algorithm: "Ed25519",
		Backends:  []string{"software"},
	},
}

// Handlers provides HTTP handlers for admin API endpoints
type Handlers struct {
	service Service
	logger  *slog.Logger
}

// NewHandlers creates a new handlers instance
func NewHandlers(service Service, logger *slog.Logger) *Handlers {
	return &Handlers{
		service: service,
		logger:  logger,
	}
}

// RegisterRoutes registers all admin API routes with the router
func (h *Handlers) RegisterRoutes(router *mux.Router, authMiddleware AuthHandler) {
	// Apply auth middleware to all routes
	adminRouter := router.PathPrefix("/admin").Subrouter()
	if authMiddleware != nil {
		adminRouter.Use(authMiddleware.Authenticate)
	}

	// Certificate Management (viewer access required)
	// Note: /certificates/expiring must be registered BEFORE /certificates/{serial}
	// to avoid gorilla/mux matching "expiring" as a serial number
	adminRouter.HandleFunc("/certificates", h.ListCertificates).Methods("GET")
	adminRouter.HandleFunc("/certificates/expiring", h.ListExpiringCertificates).Methods("GET")
	adminRouter.HandleFunc("/certificates/{serial}", h.GetCertificate).Methods("GET")

	// Certificate revocation (admin access required)
	revokeRouter := adminRouter.PathPrefix("/certificates/{serial}/revoke").Subrouter()
	revokeRouter.Use(RequireRole(RoleAdmin))
	revokeRouter.HandleFunc("", h.RevokeCertificate).Methods("POST")

	// Account Management (viewer access required for GET, admin for DELETE)
	adminRouter.HandleFunc("/accounts", h.ListAccounts).Methods("GET")
	adminRouter.HandleFunc("/accounts/{id}", h.GetAccount).Methods("GET")

	// Account deletion (admin access required)
	deleteRouter := adminRouter.PathPrefix("/accounts/{id}").Subrouter()
	deleteRouter.Use(RequireRole(RoleAdmin))
	deleteRouter.HandleFunc("", h.DisableAccount).Methods("DELETE")

	// Order Management (viewer access required)
	adminRouter.HandleFunc("/orders", h.ListOrders).Methods("GET")
	adminRouter.HandleFunc("/orders/{id}", h.GetOrder).Methods("GET")

	// Audit Log (viewer access required)
	adminRouter.HandleFunc("/audit", h.ListAuditLogs).Methods("GET")

	// CA Status and Stats (viewer access required)
	adminRouter.HandleFunc("/status", h.GetStatus).Methods("GET")
	adminRouter.HandleFunc("/stats", h.GetStats).Methods("GET")

	// Algorithms (no special role required)
	adminRouter.HandleFunc("/algorithms", h.GetAlgorithms).Methods("GET")
}

// ListCertificates handles GET /admin/certificates
func (h *Handlers) ListCertificates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	query := r.URL.Query()
	req := ListCertificatesRequest{
		Page:    parseInt(query.Get("page"), 1),
		PerPage: parseInt(query.Get("per_page"), 20),
		Status:  query.Get("status"),
		Subject: query.Get("subject"),
	}

	certs, pagination, err := h.service.ListCertificates(ctx, req)
	if err != nil {
		h.logger.Error("failed to list certificates", slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to list certificates")
		return
	}
	if certs == nil {
		certs = []*CertificateInfo{}
	}

	writeJSON(w, http.StatusOK, ListResponse{Items: certs, Total: pagination.Total, Page: pagination.Page, PerPage: pagination.PerPage})
}

// GetCertificate handles GET /admin/certificates/:serial
func (h *Handlers) GetCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	serial := vars["serial"]

	cert, err := h.service.GetCertificate(ctx, serial)
	if err != nil {
		if err == ErrCertificateNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Certificate not found")
			return
		}
		h.logger.Error("failed to get certificate", slog.String("serial", serial), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to get certificate")
		return
	}

	writeJSON(w, http.StatusOK, cert)
}

// RevokeCertificate handles POST /admin/certificates/:serial/revoke
func (h *Handlers) RevokeCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	serial := vars["serial"]

	var req RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}

	if err := h.service.RevokeCertificate(ctx, serial, req.Reason); err != nil {
		if err == ErrCertificateNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Certificate not found")
			return
		}
		h.logger.Error("failed to revoke certificate", slog.String("serial", serial), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to revoke certificate")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Certificate revoked successfully"})
}

// ListExpiringCertificates handles GET /admin/certificates/expiring
func (h *Handlers) ListExpiringCertificates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	query := r.URL.Query()
	days := parseInt(query.Get("days"), 30)
	page := parseInt(query.Get("page"), 1)
	perPage := parseInt(query.Get("per_page"), 20)

	certs, pagination, err := h.service.ListExpiringCertificates(ctx, days, page, perPage)
	if err != nil {
		h.logger.Error("failed to list expiring certificates", slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to list expiring certificates")
		return
	}
	if certs == nil {
		certs = []*CertificateInfo{}
	}

	writeJSON(w, http.StatusOK, ListResponse{Items: certs, Total: pagination.Total, Page: pagination.Page, PerPage: pagination.PerPage})
}

// ListAccounts handles GET /admin/accounts
func (h *Handlers) ListAccounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	query := r.URL.Query()
	req := ListAccountsRequest{
		Page:    parseInt(query.Get("page"), 1),
		PerPage: parseInt(query.Get("per_page"), 20),
		Status:  query.Get("status"),
	}

	accounts, pagination, err := h.service.ListAccounts(ctx, req)
	if err != nil {
		h.logger.Error("failed to list accounts", slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to list accounts")
		return
	}
	if accounts == nil {
		accounts = []*AccountInfo{}
	}

	writeJSON(w, http.StatusOK, ListResponse{Items: accounts, Total: pagination.Total, Page: pagination.Page, PerPage: pagination.PerPage})
}

// GetAccount handles GET /admin/accounts/:id
func (h *Handlers) GetAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	accountID, err := strconv.ParseUint(vars["id"], 10, 64)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid account ID")
		return
	}

	account, err := h.service.GetAccount(ctx, accountID)
	if err != nil {
		if err == ErrAccountNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Account not found")
			return
		}
		h.logger.Error("failed to get account", slog.Uint64("id", accountID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to get account")
		return
	}

	writeJSON(w, http.StatusOK, account)
}

// DisableAccount handles DELETE /admin/accounts/:id
func (h *Handlers) DisableAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	accountID, err := strconv.ParseUint(vars["id"], 10, 64)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid account ID")
		return
	}

	if err := h.service.DisableAccount(ctx, accountID); err != nil {
		if err == ErrAccountNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Account not found")
			return
		}
		h.logger.Error("failed to disable account", slog.Uint64("id", accountID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to disable account")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Account disabled successfully"})
}

// ListOrders handles GET /admin/orders
func (h *Handlers) ListOrders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	query := r.URL.Query()
	req := ListOrdersRequest{
		Page:    parseInt(query.Get("page"), 1),
		PerPage: parseInt(query.Get("per_page"), 20),
		Status:  query.Get("status"),
	}

	if accountIDStr := query.Get("account_id"); accountIDStr != "" {
		if accountID, err := strconv.ParseUint(accountIDStr, 10, 64); err == nil {
			req.AccountID = accountID
		}
	}

	orders, pagination, err := h.service.ListOrders(ctx, req)
	if err != nil {
		h.logger.Error("failed to list orders", slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to list orders")
		return
	}
	if orders == nil {
		orders = []*OrderInfo{}
	}

	writeJSON(w, http.StatusOK, ListResponse{Items: orders, Total: pagination.Total, Page: pagination.Page, PerPage: pagination.PerPage})
}

// GetOrder handles GET /admin/orders/:id
func (h *Handlers) GetOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orderID, err := strconv.ParseUint(vars["id"], 10, 64)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid order ID")
		return
	}

	// Get account ID from query parameter
	query := r.URL.Query()
	accountID, err := strconv.ParseUint(query.Get("account_id"), 10, 64)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Account ID is required")
		return
	}

	order, err := h.service.GetOrder(ctx, orderID, accountID)
	if err != nil {
		if err == ErrOrderNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Order not found")
			return
		}
		h.logger.Error("failed to get order", slog.Uint64("id", orderID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to get order")
		return
	}

	writeJSON(w, http.StatusOK, order)
}

// GetStatus handles GET /admin/status
func (h *Handlers) GetStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	status, err := h.service.GetStatus(ctx)
	if err != nil {
		h.logger.Error("failed to get status", slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to get status")
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// GetStats handles GET /admin/stats
func (h *Handlers) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := h.service.GetStats(ctx)
	if err != nil {
		h.logger.Error("failed to get stats", slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to get stats")
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

// ListAuditLogs handles GET /admin/audit.
func (h *Handlers) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	page := parseInt(query.Get("page"), 1)
	perPage := parseInt(query.Get("per_page"), 25)

	writeJSON(w, http.StatusOK, ListResponse{
		Items:   []interface{}{},
		Total:   0,
		Page:    page,
		PerPage: perPage,
	})
}

// GetAlgorithms handles GET /admin/algorithms.
// Returns the available cryptographic algorithms for CA key generation.
//
// TODO: Replace with go-xkms SDK call when available via embedded transport.
// The go-xkms server exposes GET /api/v1/algorithms with dynamic algorithm
// discovery based on configured backends. The static list here matches what
// go-xkms returns for software-only backends. Once go-xkms's embedded
// transport supports algorithm discovery, this handler should delegate to it.
func (h *Handlers) GetAlgorithms(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, &AlgorithmsResponse{
		Signing:          softwareSigningAlgorithms,
		KeyEncapsulation: []AlgorithmInfo{},
	})
}

// Helper functions

// writeJSON writes a direct JSON response with the given status code.
func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

// writeProblem writes an RFC 7807 Problem Details error response.
func writeProblem(w http.ResponseWriter, statusCode int, problemType, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(ProblemDetail{
		Type:   problemType,
		Title:  http.StatusText(statusCode),
		Detail: detail,
		Status: statusCode,
	})
}

func parseInt(s string, defaultValue int) int {
	if s == "" {
		return defaultValue
	}

	val, err := strconv.Atoi(s)
	if err != nil {
		return defaultValue
	}

	return val
}
