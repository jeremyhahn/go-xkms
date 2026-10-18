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

package admin

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// AlgorithmInfo and AlgorithmsResponse are the canonical xkms algorithm
// discovery types, re-exported so the admin API reports exactly what the
// key management service reports.
type (
	AlgorithmInfo      = xkmssdk.AlgorithmInfo
	AlgorithmsResponse = xkmssdk.AlgorithmsResponse
)

// AlgorithmDiscoverer reports the cryptographic algorithms this deployment can
// actually perform. The default implementation inspects the backends
// configured on the xkms service, so a software-only deployment never
// advertises hardware or post-quantum algorithms it cannot execute.
type AlgorithmDiscoverer func() *AlgorithmsResponse

// Handlers provides HTTP handlers for admin API endpoints
type Handlers struct {
	service            Service
	logger             *slog.Logger
	auditQuerier       audit.Querier
	discoverAlgorithms AlgorithmDiscoverer
}

// HandlerOption configures optional Handlers dependencies.
type HandlerOption func(*Handlers)

// WithAuditQuerier wires the audit trail read path into GET /admin/audit.
// Without it the endpoint reports that no audit trail is configured rather
// than claiming the trail is empty.
func WithAuditQuerier(querier audit.Querier) HandlerOption {
	return func(h *Handlers) {
		h.auditQuerier = querier
	}
}

// WithAlgorithmDiscoverer overrides the capability source behind
// GET /admin/algorithms.
func WithAlgorithmDiscoverer(discoverer AlgorithmDiscoverer) HandlerOption {
	return func(h *Handlers) {
		if discoverer != nil {
			h.discoverAlgorithms = discoverer
		}
	}
}

// NewHandlers creates a new handlers instance
func NewHandlers(service Service, logger *slog.Logger, opts ...HandlerOption) *Handlers {
	h := &Handlers{
		service:            service,
		logger:             logger,
		discoverAlgorithms: xkmssdk.ServiceDiscoverAlgorithms,
	}

	for _, opt := range opts {
		opt(h)
	}

	return h
}

// RegisterRoutes registers the /admin routes (see Routes) on router for a
// standalone host.
//
// Every route is gated on its own go-qrdb permission, which gate resolves
// through the hosted qrdb node's RBAC service (see PermissionGate).
// Registration is fail-closed by construction: every route comes from the
// one route table, each entry carries its permission, and a nil gate denies
// every request.
func (h *Handlers) RegisterRoutes(router *mux.Router, authMiddleware AuthHandler, gate *PermissionGate) {
	mountRoutes(router, adminPathPrefix, authMiddleware, h, adminRoutes(), gate.guardRoute)
}

// RegisterAuthorizedRoutes registers the /admin routes on router for a host
// that has already authorized every request against the route's permission
// before dispatching to router: the unified server, whose admin module
// mounts each entry of Routes through qrdb's HTTPRegistrar.Handle. Only a
// route the host mounts identity-gated (Route.SelfPermission) is authorized
// here, by gate. Mounted anywhere else, the other routes are served
// unauthorized; a standalone host uses RegisterRoutes.
func (h *Handlers) RegisterAuthorizedRoutes(router *mux.Router, authMiddleware AuthHandler, gate *PermissionGate) {
	mountRoutes(router, adminPathPrefix, authMiddleware, h, adminRoutes(), gate.guardReachRoute)
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
		if writeUnavailableIfNotConfigured(w, err) {
			return
		}
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
		if writeUnavailableIfNotConfigured(w, err) {
			return
		}
		if errors.Is(err, ErrCertificateNotFound) {
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
		if writeUnavailableIfNotConfigured(w, err) {
			return
		}
		if errors.Is(err, ErrCertificateNotFound) {
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
		if writeUnavailableIfNotConfigured(w, err) {
			return
		}
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
		if writeUnavailableIfNotConfigured(w, err) {
			return
		}
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
		if writeUnavailableIfNotConfigured(w, err) {
			return
		}
		if errors.Is(err, ErrAccountNotFound) {
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
		if writeUnavailableIfNotConfigured(w, err) {
			return
		}
		if errors.Is(err, ErrAccountNotFound) {
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
		if writeUnavailableIfNotConfigured(w, err) {
			return
		}
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
		if writeUnavailableIfNotConfigured(w, err) {
			return
		}
		if errors.Is(err, ErrOrderNotFound) {
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
		if writeUnavailableIfNotConfigured(w, err) {
			return
		}
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
		if writeUnavailableIfNotConfigured(w, err) {
			return
		}
		h.logger.Error("failed to get stats", slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to get stats")
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

// ListAuditLogs handles GET /admin/audit.
//
// The audit trail is a compliance control, so this endpoint never invents an
// answer: it either reports the events the configured trail holds, or it
// reports that no trail is configured. It never returns "no events" for a
// server whose audit trail it cannot read.
//
// The trail records no tenant for its events, so it cannot be confined to one:
// reading it is a platform operation, and a caller outside the system tenant
// (qrdbsdk.IdentityIsSystemTenant) is answered exactly as a caller lacking
// audit:read is.
func (h *Handlers) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	if !qrdbsdk.IdentityIsSystemTenant(auth.GetIdentity(r.Context())) {
		writePermissionDenied(w)
		return
	}

	if h.auditQuerier == nil {
		h.logger.Warn("audit log query rejected: no audit trail is configured")
		writeProblem(w, http.StatusNotImplemented, "urn:trusted-ca:error:not-implemented",
			"Audit log querying is unavailable: this server has no audit trail configured")
		return
	}

	req, err := parseListAuditLogsRequest(r.URL.Query())
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", err.Error())
		return
	}

	result, err := h.auditQuerier.Query(r.Context(), req.auditQuery())
	if err != nil {
		if errors.Is(err, audit.ErrQueryWindowExceeded) || errors.Is(err, audit.ErrInvalidTimeRange) {
			writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", err.Error())
			return
		}

		h.logger.Error("failed to list audit logs", slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to list audit logs")
		return
	}

	if result.Malformed > 0 {
		h.logger.Warn("audit trail contains records that could not be decoded",
			slog.Int("malformed", result.Malformed))
	}

	writeJSON(w, http.StatusOK, ListResponse{
		Items:   result.Events,
		Total:   result.Total,
		Page:    result.Page,
		PerPage: result.PerPage,
	})
}

// parseListAuditLogsRequest builds an audit log request from query parameters.
func parseListAuditLogsRequest(query map[string][]string) (ListAuditLogsRequest, error) {
	get := func(key string) string {
		if values, ok := query[key]; ok && len(values) > 0 {
			return values[0]
		}
		return ""
	}

	req := ListAuditLogsRequest{
		Page:      parseInt(get("page"), 1),
		PerPage:   parseInt(get("per_page"), audit.DefaultQueryPageSize),
		EventType: get("event_type"),
		Actor:     get("actor"),
		Action:    get("action"),
		Resource:  get("resource"),
		Result:    get("result"),
		RequestID: get("request_id"),
	}

	startTime, err := parseTimestamp(get("start_time"))
	if err != nil {
		return ListAuditLogsRequest{}, err
	}
	req.StartTime = startTime

	endTime, err := parseTimestamp(get("end_time"))
	if err != nil {
		return ListAuditLogsRequest{}, err
	}
	req.EndTime = endTime

	return req, nil
}

// parseTimestamp parses an optional RFC 3339 query parameter.
func parseTimestamp(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}

	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, caerrors.MalformedError("timestamp %q must be RFC 3339", value)
	}

	return parsed, nil
}

// GetAlgorithms handles GET /admin/algorithms.
//
// The response is derived from the backends this deployment has configured,
// so it lists only algorithms the server can actually execute: hardware
// algorithms appear when a hardware backend is loaded, and key encapsulation
// algorithms appear when a backend supports them.
func (h *Handlers) GetAlgorithms(w http.ResponseWriter, r *http.Request) {
	response := h.discoverAlgorithms()
	if response == nil {
		response = &AlgorithmsResponse{
			Signing:          []AlgorithmInfo{},
			KeyEncapsulation: []AlgorithmInfo{},
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// Helper functions

// writeJSON writes a direct JSON response with the given status code.
func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// Headers and status are already written; there is no way to
		// report this to the client, so it's only logged.
		slog.Error("failed to write JSON response", slog.String("error", err.Error()))
	}
}

// writeUnavailableIfNotConfigured answers ErrCANotConfigured and
// ErrStorageNotConfigured with the same "not implemented" shape
// ListAuditLogs already uses for a missing audit trail: the admin surface
// is mounted (ACME may be disabled entirely), but this route has no backing
// CA or storage to administer. It reports whether it wrote a response so
// the caller can fall through to its ordinary error handling otherwise.
func writeUnavailableIfNotConfigured(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, ErrCANotConfigured):
		writeProblem(w, http.StatusNotImplemented, "urn:trusted-ca:error:not-implemented",
			"Certificate administration is unavailable: this server has no ACME certificate authority configured")
		return true
	case errors.Is(err, ErrStorageNotConfigured):
		writeProblem(w, http.StatusNotImplemented, "urn:trusted-ca:error:not-implemented",
			"Certificate administration is unavailable: this server has no ACME storage configured")
		return true
	}
	return false
}

// writeProblem writes an RFC 7807 Problem Details error response.
func writeProblem(w http.ResponseWriter, statusCode int, problemType, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(statusCode)
	err := json.NewEncoder(w).Encode(ProblemDetail{
		Type:   problemType,
		Title:  http.StatusText(statusCode),
		Detail: detail,
		Status: statusCode,
	})
	if err != nil {
		slog.Error("failed to write problem detail response", slog.String("error", err.Error()))
	}
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
