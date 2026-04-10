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
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// Typed errors for tenant handlers.
var (
	ErrTenantNotConfigured = errors.New("tenant service not configured")
	ErrMissingTenantID     = errors.New("missing tenant_id")
	ErrMissingTenantName   = errors.New("missing tenant name")
)

// createTenantRequest represents a request to register a new tenant.
type createTenantRequest struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// tenantInfoResponse represents tenant information.
type tenantInfoResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	Sealed    bool   `json:"sealed"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// wrappedTenantResponse wraps a single tenant for SDK compatibility.
type wrappedTenantResponse struct {
	Tenant tenantInfoResponse `json:"tenant"`
}

// listTenantsResponse represents the response for listing tenants.
type listTenantsResponse struct {
	Tenants    []tenantInfoResponse   `json:"tenants"`
	Pagination transport.PageResponse `json:"pagination"`
}

// tenantBarrierStatusResponse represents the barrier status for a tenant.
type tenantBarrierStatusResponse struct {
	TenantID       string          `json:"tenant_id"`
	Sealed         bool            `json:"sealed"`
	Strategy       seal.StrategyID `json:"strategy,omitempty"`
	HardwareBacked bool            `json:"hardware_backed"`
}

// tenantBarrierInitRequest represents a request to initialize a tenant barrier.
type tenantBarrierInitRequest struct {
	Threshold int `json:"threshold,omitempty"`
	Shares    int `json:"shares,omitempty"`
}

// tenantBarrierUnsealRequest represents a request to unseal a tenant barrier.
type tenantBarrierUnsealRequest struct {
	Share []byte `json:"share,omitempty"`
	Key   []byte `json:"key,omitempty"`
}

// TenantHandlers provides REST handlers for tenant management and
// per-tenant barrier operations. Tenants are registered in the
// BarrierRegistry and each receives an isolated TenantBarrier that
// scopes all storage operations to the tenant's namespace.
type TenantHandlers struct {
	registry *seal.BarrierRegistry
}

// NewTenantHandlers creates a new TenantHandlers instance.
// The registry must not be nil.
func NewTenantHandlers(registry *seal.BarrierRegistry) *TenantHandlers {
	return &TenantHandlers{registry: registry}
}

// CreateTenantHandler handles POST /tenants requests.
// It registers a new tenant in the barrier registry, creating an isolated
// TenantBarrier that scopes all storage operations to the tenant's namespace.
func (h *TenantHandlers) CreateTenantHandler(w http.ResponseWriter, r *http.Request) {
	if h.registry == nil {
		writeError(w, ErrTenantNotConfigured, http.StatusServiceUnavailable)
		return
	}

	var req createTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.ID == "" {
		writeError(w, ErrMissingTenantID, http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		writeError(w, ErrMissingTenantName, http.StatusBadRequest)
		return
	}

	tb, err := h.registry.RegisterTenant(req.ID)
	if err != nil {
		handleTenantError(w, err)
		return
	}

	resp := wrappedTenantResponse{
		Tenant: tenantInfoResponse{
			ID:     req.ID,
			Name:   req.Name,
			Sealed: tb.IsSealed(),
		},
	}
	writeJSON(w, resp, http.StatusCreated)
}

// ListTenantsHandler handles GET /tenants requests.
// It returns all registered tenant IDs with their barrier status.
// Tenant-scoped identities see only their own tenant; system-level
// identities (SO) see all tenants.
func (h *TenantHandlers) ListTenantsHandler(w http.ResponseWriter, r *http.Request) {
	if h.registry == nil {
		writeError(w, ErrTenantNotConfigured, http.StatusServiceUnavailable)
		return
	}

	identity := auth.GetIdentity(r.Context())

	ids := h.registry.ListTenants()
	sort.Strings(ids)

	tenants := make([]tenantInfoResponse, 0, len(ids))
	for _, id := range ids {
		// If identity is tenant-scoped, only include the caller's own tenant
		if identity != nil && !identity.IsCrossTenant() && id != identity.TenantID {
			continue
		}

		tb, err := h.registry.Tenant(id)
		if err != nil {
			continue
		}
		tenants = append(tenants, tenantInfoResponse{
			ID:     id,
			Sealed: tb.IsSealed(),
		})
	}

	pageReq := parsePageRequest(r)
	paged, pageResp := applyPagination(tenants, pageReq)

	resp := listTenantsResponse{
		Tenants:    paged,
		Pagination: pageResp,
	}
	writeJSON(w, resp, http.StatusOK)
}

// GetTenantHandler handles GET /tenants/{id} requests.
// It returns information about a specific registered tenant.
// Tenant-scoped identities can only access their own tenant; cross-tenant
// access returns 404 to prevent tenant enumeration.
func (h *TenantHandlers) GetTenantHandler(w http.ResponseWriter, r *http.Request) {
	if h.registry == nil {
		writeError(w, ErrTenantNotConfigured, http.StatusServiceUnavailable)
		return
	}

	tenantID := chi.URLParam(r, "tenantID")
	if tenantID == "" {
		writeError(w, ErrMissingTenantID, http.StatusBadRequest)
		return
	}

	// Tenant access check: return 404 to prevent enumeration
	identity := auth.GetIdentity(r.Context())
	if isCrossTenantAccess(identity, tenantID) {
		writeError(w, seal.ErrTenantNotFound, http.StatusNotFound)
		return
	}

	tb, err := h.registry.Tenant(tenantID)
	if err != nil {
		handleTenantError(w, err)
		return
	}

	resp := wrappedTenantResponse{
		Tenant: tenantInfoResponse{
			ID:     tb.TenantID(),
			Sealed: tb.IsSealed(),
		},
	}
	writeJSON(w, resp, http.StatusOK)
}

// DeleteTenantHandler handles DELETE /tenants/{id} requests.
// It unregisters a tenant from the barrier registry.
// Tenant-scoped identities can only delete their own tenant; cross-tenant
// access returns 404 to prevent tenant enumeration.
func (h *TenantHandlers) DeleteTenantHandler(w http.ResponseWriter, r *http.Request) {
	if h.registry == nil {
		writeError(w, ErrTenantNotConfigured, http.StatusServiceUnavailable)
		return
	}

	tenantID := chi.URLParam(r, "tenantID")
	if tenantID == "" {
		writeError(w, ErrMissingTenantID, http.StatusBadRequest)
		return
	}

	// Tenant access check: return 404 to prevent enumeration
	identity := auth.GetIdentity(r.Context())
	if isCrossTenantAccess(identity, tenantID) {
		writeError(w, seal.ErrTenantNotFound, http.StatusNotFound)
		return
	}

	if err := h.registry.UnregisterTenant(tenantID); err != nil {
		handleTenantError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// TenantBarrierStatusHandler handles GET /tenants/{id}/barrier/status requests.
// It returns the barrier status for a specific tenant. Each tenant has an
// independent barrier with its own DEK, so the status reflects the tenant's
// own seal state, strategy, and hardware-backed flag.
// Tenant-scoped identities can only view their own tenant's barrier status.
func (h *TenantHandlers) TenantBarrierStatusHandler(w http.ResponseWriter, r *http.Request) {
	if h.registry == nil {
		writeError(w, ErrTenantNotConfigured, http.StatusServiceUnavailable)
		return
	}

	tenantID := chi.URLParam(r, "tenantID")
	if tenantID == "" {
		writeError(w, ErrMissingTenantID, http.StatusBadRequest)
		return
	}

	// Tenant access check: return 404 to prevent enumeration
	identity := auth.GetIdentity(r.Context())
	if isCrossTenantAccess(identity, tenantID) {
		writeError(w, seal.ErrTenantNotFound, http.StatusNotFound)
		return
	}

	status, err := h.registry.TenantStatus(tenantID)
	if err != nil {
		handleTenantError(w, err)
		return
	}

	resp := tenantBarrierStatusResponse{
		TenantID:       tenantID,
		Sealed:         status.Sealed,
		Strategy:       status.Strategy,
		HardwareBacked: status.HardwareBacked,
	}
	writeJSON(w, resp, http.StatusOK)
}

// TenantBarrierInitHandler handles POST /tenants/{id}/barrier/init requests.
// Each tenant has an independent barrier with its own DEK. This endpoint
// initializes the tenant's barrier by generating a root key and sealing it
// with the tenant's configured strategy. The tenant barrier transitions to
// unsealed state after initialization.
// Tenant-scoped identities can only initialize their own tenant's barrier.
func (h *TenantHandlers) TenantBarrierInitHandler(w http.ResponseWriter, r *http.Request) {
	if h.registry == nil {
		writeError(w, ErrTenantNotConfigured, http.StatusServiceUnavailable)
		return
	}

	tenantID := chi.URLParam(r, "tenantID")
	if tenantID == "" {
		writeError(w, ErrMissingTenantID, http.StatusBadRequest)
		return
	}

	// Tenant access check: return 404 to prevent enumeration
	identity := auth.GetIdentity(r.Context())
	if isCrossTenantAccess(identity, tenantID) {
		writeError(w, seal.ErrTenantNotFound, http.StatusNotFound)
		return
	}

	var req tenantBarrierInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	creds := seal.Credentials{Secret: "tenant-init"}
	if err := h.registry.InitializeTenant(r.Context(), tenantID, creds); err != nil {
		handleTenantError(w, err)
		return
	}

	status, err := h.registry.TenantStatus(tenantID)
	if err != nil {
		handleTenantError(w, err)
		return
	}

	resp := tenantBarrierStatusResponse{
		TenantID:       tenantID,
		Sealed:         status.Sealed,
		Strategy:       status.Strategy,
		HardwareBacked: status.HardwareBacked,
	}
	writeJSON(w, resp, http.StatusOK)
}

// TenantBarrierUnsealHandler handles POST /tenants/{id}/barrier/unseal requests.
// Each tenant has an independent barrier with its own DEK. This endpoint
// unseals the tenant's barrier using the provided credentials. The tenant
// barrier must have been previously initialized.
// Tenant-scoped identities can only unseal their own tenant's barrier.
func (h *TenantHandlers) TenantBarrierUnsealHandler(w http.ResponseWriter, r *http.Request) {
	if h.registry == nil {
		writeError(w, ErrTenantNotConfigured, http.StatusServiceUnavailable)
		return
	}

	tenantID := chi.URLParam(r, "tenantID")
	if tenantID == "" {
		writeError(w, ErrMissingTenantID, http.StatusBadRequest)
		return
	}

	// Tenant access check: return 404 to prevent enumeration
	identity := auth.GetIdentity(r.Context())
	if isCrossTenantAccess(identity, tenantID) {
		writeError(w, seal.ErrTenantNotFound, http.StatusNotFound)
		return
	}

	var req tenantBarrierUnsealRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	creds := seal.Credentials{Secret: string(req.Key)}
	if err := h.registry.UnsealTenant(r.Context(), tenantID, creds); err != nil {
		handleTenantError(w, err)
		return
	}

	status, err := h.registry.TenantStatus(tenantID)
	if err != nil {
		handleTenantError(w, err)
		return
	}

	resp := tenantBarrierStatusResponse{
		TenantID:       tenantID,
		Sealed:         status.Sealed,
		Strategy:       status.Strategy,
		HardwareBacked: status.HardwareBacked,
	}
	writeJSON(w, resp, http.StatusOK)
}

// handleTenantError maps seal package errors to HTTP status codes and writes
// the appropriate error response.
func handleTenantError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, seal.ErrTenantNotFound):
		writeError(w, err, http.StatusNotFound)
	case errors.Is(err, seal.ErrTenantAlreadyExists):
		writeError(w, err, http.StatusConflict)
	case errors.Is(err, seal.ErrEmptyTenantID):
		writeError(w, err, http.StatusBadRequest)
	case errors.Is(err, seal.ErrSealed):
		writeError(w, err, http.StatusServiceUnavailable)
	case errors.Is(err, seal.ErrTenantSealed):
		writeError(w, err, http.StatusServiceUnavailable)
	case errors.Is(err, seal.ErrNotInitialized):
		writeError(w, err, http.StatusPreconditionFailed)
	case errors.Is(err, seal.ErrTenantNotInitialized):
		writeError(w, err, http.StatusPreconditionFailed)
	case errors.Is(err, seal.ErrAlreadyInitialized):
		writeError(w, err, http.StatusConflict)
	case errors.Is(err, seal.ErrTenantAlreadyInitialized):
		writeError(w, err, http.StatusConflict)
	case errors.Is(err, seal.ErrAlreadyUnsealed):
		writeError(w, err, http.StatusConflict)
	case errors.Is(err, seal.ErrTenantAlreadyUnsealed):
		writeError(w, err, http.StatusConflict)
	case errors.Is(err, seal.ErrInvalidCredentials):
		writeError(w, err, http.StatusUnauthorized)
	case errors.Is(err, seal.ErrNilSystemBarrier):
		writeError(w, err, http.StatusServiceUnavailable)
	default:
		writeError(w, ErrInternalError, http.StatusInternalServerError)
	}
}
