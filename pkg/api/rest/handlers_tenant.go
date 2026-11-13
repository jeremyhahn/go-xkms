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
	"log/slog"
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Typed errors for tenant handlers.
var (
	ErrTenantNotConfigured = errors.New("tenant service not configured")
	ErrMissingTenantID     = errors.New("missing tenant_id")
	ErrMissingTenantName   = errors.New("missing tenant name")
)

// createTenantRequest represents a request to register a new tenant. The
// optional IsolationType selects the tenant's isolation mode (prefix / barrier
// / volume / raft; default prefix) and BarrierAutoUnseal opts a dedicated-
// isolation tenant into system-managed auto-unseal (entitlement-gated).
type createTenantRequest struct {
	// ID is optional; the service generates one when it is empty.
	ID                string                        `json:"id,omitempty"`
	Name              string                        `json:"name"`
	IsolationType     string                        `json:"isolation_type,omitempty"`
	BarrierAutoUnseal bool                          `json:"barrier_auto_unseal,omitempty"`
	Settings          *transport.TenantSettingsInfo `json:"settings,omitempty"`
}

// tenantInfoResponse represents tenant information.
type tenantInfoResponse struct {
	ID            string `json:"id"`
	Name          string `json:"name,omitempty"`
	Sealed        bool   `json:"sealed"`
	IsolationType string `json:"isolation_type,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`

	// The CA record kept beside the tenant (status, CA hierarchy, issuance
	// settings), inlined; absent when no record is kept.
	*transport.TenantRecord
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

// TenantHandlers provides REST handlers for tenant management and
// per-tenant barrier operations. All tenant CRUD and barrier operations route
// through xkmsService (which requires go-qrdb's composed TenantService);
// registry is used only for the supplementary live-sealed-state read
// tenantSealed needs. Tenants are registered in the BarrierRegistry and each
// receives an isolated TenantBarrier that scopes all storage operations to
// the tenant's namespace.
type TenantHandlers struct {
	registry    *seal.BarrierRegistry
	xkmsService *xkms.XKMSService
}

// NewTenantHandlers creates a new TenantHandlers instance. registry and svc
// are both required, and svc must already have a TenantService composed
// (xkms.XKMSService.SetTenantService) — ErrTenantNotConfigured otherwise.
// There is no fallback to direct barrier-registry tenant operations.
func NewTenantHandlers(registry *seal.BarrierRegistry, svc *xkms.XKMSService) (*TenantHandlers, error) {
	if registry == nil || svc == nil || svc.TenantService() == nil {
		return nil, ErrTenantNotConfigured
	}
	return &TenantHandlers{registry: registry, xkmsService: svc}, nil
}

// CreateTenantHandler handles POST /tenants requests.
// It registers a new tenant in the barrier registry, creating an isolated
// TenantBarrier that scopes all storage operations to the tenant's namespace.
func (h *TenantHandlers) CreateTenantHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
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

	// Delegate to the XKMS service, which routes through go-qrdb's
	// TenantService so the requested isolation mode and the system-managed
	// auto-unseal key-management mode are entitlement-gated and the per-tenant
	// barrier is sealed by the composed hardware strategies.
	detail, err := h.xkmsService.CreateTenantDetail(r.Context(), &transport.CreateTenantRequest{
		ID:                req.ID,
		Name:              req.Name,
		IsolationType:     transport.TenantIsolationType(req.IsolationType),
		BarrierAutoUnseal: req.BarrierAutoUnseal,
	}, req.Settings)
	if err != nil {
		handleTenantError(w, err)
		return
	}
	writeJSON(w, wrappedTenantResponse{Tenant: h.tenantResponse(detail)}, http.StatusCreated)
}

// tenantResponse renders a tenant and its CA record.
func (h *TenantHandlers) tenantResponse(detail *transport.TenantDetail) tenantInfoResponse {
	return tenantInfoResponse{
		ID:            detail.Tenant.ID,
		Name:          detail.Tenant.Name,
		Sealed:        h.tenantSealed(detail.Tenant.ID),
		IsolationType: string(detail.Tenant.IsolationType),
		TenantRecord:  detail.Record,
	}
}

// tenantSealed reports the live sealed state of a tenant's barrier. Prefix-
// isolated tenants have no dedicated barrier and are reported unsealed; a
// dedicated-isolation tenant reports its barrier's current sealed state.
func (h *TenantHandlers) tenantSealed(tenantID string) bool {
	if h.registry == nil {
		return false
	}
	tb, err := h.registry.Tenant(tenantID)
	if err != nil {
		return false
	}
	return tb.IsSealed()
}

// ListTenantsHandler handles GET /tenants requests.
// It returns all registered tenant IDs with their barrier status.
// Tenant-scoped identities see only their own tenant; system-level
// identities (SO) see all tenants. XKMSService.ListTenants applies that
// filter.
func (h *TenantHandlers) ListTenantsHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrTenantNotConfigured, http.StatusServiceUnavailable)
		return
	}

	pageReq, err := transport.PageRequestFromQuery(r)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	// List through the XKMS tenant service so prefix-isolated (default)
	// tenants — which are not in the barrier registry — are included,
	// consistent with the create/get paths. The service already confines a
	// tenant-scoped caller to its own tenant and refuses a status filter
	// (go-qrdb carries no tenant status yet), which answers 400.
	details, err := h.xkmsService.ListTenantDetails(r.Context(), r.URL.Query().Get("status"))
	if err != nil {
		handleTenantError(w, err)
		return
	}
	tenants := make([]tenantInfoResponse, 0, len(details))
	for i := range details {
		tenants = append(tenants, h.tenantResponse(&details[i]))
	}
	sort.Slice(tenants, func(i, j int) bool { return tenants[i].ID < tenants[j].ID })

	paged, pageResp := transport.ApplyPagination(tenants, pageReq)
	writeJSON(w, listTenantsResponse{Tenants: paged, Pagination: pageResp}, http.StatusOK)
}

// GetTenantHandler handles GET /tenants/{id} requests.
// It returns information about a specific registered tenant.
// Tenant-scoped identities can only access their own tenant: XKMSService
// refuses any other tenant with an error that maps to 404, so a probe cannot
// enumerate tenants.
func (h *TenantHandlers) GetTenantHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrTenantNotConfigured, http.StatusServiceUnavailable)
		return
	}

	tenantID := chi.URLParam(r, "tenantID")
	if tenantID == "" {
		writeError(w, ErrMissingTenantID, http.StatusBadRequest)
		return
	}

	// The XKMS tenant service is the source of truth for ALL tenants.
	// Prefix-isolated (default) tenants share the system store and are NOT
	// registered in the barrier registry, so a registry-only lookup would
	// 404 them even though CreateTenant persisted their metadata.
	detail, err := h.xkmsService.GetTenantDetail(r.Context(), tenantID)
	if err != nil {
		handleTenantError(w, err)
		return
	}
	writeJSON(w, wrappedTenantResponse{Tenant: h.tenantResponse(detail)}, http.StatusOK)
}

// DeleteTenantHandler handles DELETE /tenants/{id} requests.
// It unregisters a tenant from the barrier registry.
// Tenant-scoped identities can only delete their own tenant: XKMSService
// refuses any other tenant with an error that maps to 404.
func (h *TenantHandlers) DeleteTenantHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrTenantNotConfigured, http.StatusServiceUnavailable)
		return
	}

	tenantID := chi.URLParam(r, "tenantID")
	if tenantID == "" {
		writeError(w, ErrMissingTenantID, http.StatusBadRequest)
		return
	}

	// Delete through the XKMS tenant service so prefix-isolated tenants
	// (absent from the barrier registry) are removed, consistent with the
	// create/get/list paths.
	if err := h.xkmsService.DeleteTenant(r.Context(), tenantID); err != nil {
		handleTenantError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// UpdateTenantEntitlementsHandler handles PUT /tenants/{tenantID}/entitlements.
// It updates which isolation tiers and dedicated-storage features the tenant's
// plan permits. The route requires tenants:set_entitlements and XKMSService
// admits only a cross-tenant identity (a tenant-scoped caller gets 404).
// Requires the composed TenantService.
func (h *TenantHandlers) UpdateTenantEntitlementsHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrTenantNotConfigured, http.StatusServiceUnavailable)
		return
	}
	tenantID := chi.URLParam(r, "tenantID")
	if tenantID == "" {
		writeError(w, ErrMissingTenantID, http.StatusBadRequest)
		return
	}

	var req transport.UpdateTenantEntitlementsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	req.TenantID = tenantID

	resp, err := h.xkmsService.UpdateTenantEntitlements(r.Context(), &req)
	if err != nil {
		handleTenantError(w, err)
		return
	}
	writeJSON(w, resp, http.StatusOK)
}

// UpdateTenantQuotasHandler handles PUT /tenants/{tenantID}/quotas. It updates
// the tenant's resource quotas. The route requires tenants:set_quotas and
// XKMSService admits only a cross-tenant identity (a tenant-scoped caller gets
// 404). Requires the composed TenantService.
func (h *TenantHandlers) UpdateTenantQuotasHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrTenantNotConfigured, http.StatusServiceUnavailable)
		return
	}
	tenantID := chi.URLParam(r, "tenantID")
	if tenantID == "" {
		writeError(w, ErrMissingTenantID, http.StatusBadRequest)
		return
	}

	var req transport.UpdateTenantQuotasRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	req.TenantID = tenantID

	resp, err := h.xkmsService.UpdateTenantQuotas(r.Context(), &req)
	if err != nil {
		handleTenantError(w, err)
		return
	}
	writeJSON(w, resp, http.StatusOK)
}

// handleTenantError maps seal package errors to HTTP status codes and writes
// the appropriate error response.
func handleTenantError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, xkms.ErrTenantStatusUnsupported):
		writeError(w, err, http.StatusBadRequest)
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
	// Software strategies report a wrong passphrase as ErrDecryptionFailed;
	// hardware ones raise ErrInvalidCredentials. Both are 401.
	case errors.Is(err, seal.ErrDecryptionFailed):
		writeError(w, err, http.StatusUnauthorized)
	case errors.Is(err, seal.ErrNilSystemBarrier):
		writeError(w, err, http.StatusServiceUnavailable)
	default:
		// Delegate to the central mapper, which classifies go-qrdb tenant
		// entitlement / barrier-mode / quota denials (EntitlementError → 403,
		// ErrSharedBarrierImmutable → 409, quota-exceeded → 429). Only a genuinely
		// unrecognized error falls through to a generic 500 with details hidden.
		if status := mapErrorToStatusCode(err); status != http.StatusInternalServerError {
			writeError(w, err, status)
			return
		}
		slog.Default().Error("tenant operation failed", "error", err)
		writeError(w, ErrInternalError, http.StatusInternalServerError)
	}
}
