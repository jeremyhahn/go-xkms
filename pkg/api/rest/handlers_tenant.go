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
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Typed errors for tenant handlers.
var (
	ErrTenantNotConfigured = errors.New("tenant service not configured")
	ErrMissingTenantID     = errors.New("missing tenant_id")
	ErrMissingTenantName   = errors.New("missing tenant name")
)

// isCrossTenantAccess reports whether the given identity is attempting to act
// on a tenant other than its own. A cross-tenant-scoped identity per
// auth.IsCrossTenant (nil, empty TenantID, or the reserved system tenant), a
// request scoped to no tenant, and same-tenant access all return false; only
// a tenant-scoped identity targeting a different tenant is cross-tenant.
func isCrossTenantAccess(identity *auth.Identity, tenantID string) bool {
	if auth.IsCrossTenant(identity) || tenantID == "" {
		return false
	}
	return identity.TenantID != tenantID
}

// createTenantRequest represents a request to register a new tenant. The
// optional IsolationType selects the tenant's isolation mode (prefix / barrier
// / volume / raft; default prefix) and BarrierAutoUnseal opts a dedicated-
// isolation tenant into system-managed auto-unseal (entitlement-gated).
type createTenantRequest struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	IsolationType     string `json:"isolation_type,omitempty"`
	BarrierAutoUnseal bool   `json:"barrier_auto_unseal,omitempty"`
}

// tenantInfoResponse represents tenant information.
type tenantInfoResponse struct {
	ID            string `json:"id"`
	Name          string `json:"name,omitempty"`
	Sealed        bool   `json:"sealed"`
	IsolationType string `json:"isolation_type,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
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
// Passphrase carries the tenant admin's caller-supplied secret; the server
// never generates it (§3.6). Strategy selects the seal strategy (empty means
// the passphrase strategy).
type tenantBarrierInitRequest struct {
	Passphrase string `json:"passphrase,omitempty"`
	Strategy   string `json:"strategy,omitempty"`
	Threshold  int    `json:"threshold,omitempty"`
	Shares     int    `json:"shares,omitempty"`
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
	registry    *seal.BarrierRegistry
	xkmsService *xkms.XKMSService
}

// NewTenantHandlers creates a new TenantHandlers instance.
// The registry must not be nil. svc is the injected XKMS service used by
// barrier-init and barrier-unseal operations.
func NewTenantHandlers(registry *seal.BarrierRegistry, svc *xkms.XKMSService) *TenantHandlers {
	return &TenantHandlers{registry: registry, xkmsService: svc}
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

	// Preferred path: delegate to the XKMS service, which routes through
	// go-qrdb's TenantService so the requested isolation mode and the
	// system-managed auto-unseal key-management mode are entitlement-gated and
	// the per-tenant barrier is sealed by the composed hardware strategies. The
	// registry fallback below preserves the legacy sealed-shell behavior when no
	// service is wired.
	if h.xkmsService != nil {
		createResp, err := h.xkmsService.CreateTenant(r.Context(), &transport.CreateTenantRequest{
			ID:                req.ID,
			Name:              req.Name,
			IsolationType:     transport.TenantIsolationType(req.IsolationType),
			BarrierAutoUnseal: req.BarrierAutoUnseal,
		})
		if err != nil {
			handleTenantError(w, err)
			return
		}
		writeJSON(w, wrappedTenantResponse{
			Tenant: tenantInfoResponse{
				ID:            createResp.Tenant.ID,
				Name:          createResp.Tenant.Name,
				Sealed:        h.tenantSealed(req.ID),
				IsolationType: string(createResp.Tenant.IsolationType),
			},
		}, http.StatusCreated)
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
// identities (SO) see all tenants.
func (h *TenantHandlers) ListTenantsHandler(w http.ResponseWriter, r *http.Request) {
	if h.registry == nil {
		writeError(w, ErrTenantNotConfigured, http.StatusServiceUnavailable)
		return
	}

	identity := auth.GetIdentity(r.Context())

	tenants := make([]tenantInfoResponse, 0)

	// Preferred path: list through the XKMS tenant service so prefix-isolated
	// (default) tenants — which are not in the barrier registry — are included,
	// consistent with the create/get paths.
	if h.xkmsService != nil {
		listResp, err := h.xkmsService.ListTenants(r.Context())
		if err != nil {
			handleTenantError(w, err)
			return
		}
		for _, ti := range listResp.Tenants {
			if identity != nil && !auth.IsCrossTenant(identity) && ti.ID != identity.TenantID {
				continue
			}
			tenants = append(tenants, tenantInfoResponse{
				ID:            ti.ID,
				Name:          ti.Name,
				Sealed:        h.tenantSealed(ti.ID),
				IsolationType: string(ti.IsolationType),
			})
		}
		sort.Slice(tenants, func(i, j int) bool { return tenants[i].ID < tenants[j].ID })
	} else {
		ids := h.registry.ListTenants()
		sort.Strings(ids)
		for _, id := range ids {
			// If identity is tenant-scoped, only include the caller's own tenant
			if identity != nil && !auth.IsCrossTenant(identity) && id != identity.TenantID {
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

	// Preferred path: the XKMS tenant service is the source of truth for ALL
	// tenants. Prefix-isolated (default) tenants share the system store and are
	// NOT registered in the barrier registry, so the registry-only lookup below
	// would 404 them even though CreateTenant persisted their metadata. Read
	// through the same service the write path uses to keep create→get
	// consistent.
	if h.xkmsService != nil {
		getResp, err := h.xkmsService.GetTenant(r.Context(), tenantID)
		if err != nil {
			handleTenantError(w, err)
			return
		}
		writeJSON(w, wrappedTenantResponse{
			Tenant: tenantInfoResponse{
				ID:            getResp.Tenant.ID,
				Name:          getResp.Tenant.Name,
				Sealed:        h.tenantSealed(tenantID),
				IsolationType: string(getResp.Tenant.IsolationType),
			},
		}, http.StatusOK)
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

	// Preferred path: delete through the XKMS tenant service so prefix-isolated
	// tenants (absent from the barrier registry) are removed, consistent with
	// the create/get/list paths.
	if h.xkmsService != nil {
		if err := h.xkmsService.DeleteTenant(r.Context(), tenantID); err != nil {
			handleTenantError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
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

	// Preferred path: the servicer surfaces the full per-tenant status
	// (initialized flag, active strategy, hardware-backing, Shamir quorum).
	if h.xkmsService != nil {
		resp, err := h.xkmsService.TenantBarrierStatus(r.Context(), tenantID)
		if err != nil {
			handleTenantError(w, err)
			return
		}
		writeJSON(w, resp, http.StatusOK)
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

// UpdateTenantEntitlementsHandler handles PUT /tenants/{tenantID}/entitlements.
// It updates which isolation tiers and dedicated-storage features the tenant's
// plan permits. Requires the composed TenantService.
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
// the tenant's resource quotas. Requires the composed TenantService.
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

	// Route through the service layer so the §3.6 invariant (the server never
	// generates a tenant secret) is enforced in exactly one place. The
	// passphrase is taken verbatim from the caller's request.
	if h.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}
	if err := h.xkmsService.TenantBarrierInit(r.Context(), &transport.TenantBarrierInitRequest{
		TenantID:   tenantID,
		Passphrase: req.Passphrase,
		Strategy:   req.Strategy,
		Threshold:  req.Threshold,
		Shares:     req.Shares,
	}); err != nil {
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

	// Route through the service layer; the unseal credentials are taken
	// verbatim from the caller's request (Key for passphrase strategies, Share
	// for shamir). The server holds no tenant secret of its own.
	if h.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}
	if err := h.xkmsService.TenantBarrierUnseal(r.Context(), &transport.TenantBarrierUnsealRequest{
		TenantID: tenantID,
		Key:      req.Key,
		Share:    req.Share,
	}); err != nil {
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
