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

	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// TenantHandlers provides HTTP handlers for tenant management API endpoints
type TenantHandlers struct {
	service TenantService
	logger  *slog.Logger
}

// NewTenantHandlers creates a new tenant handlers instance
func NewTenantHandlers(service TenantService, logger *slog.Logger) *TenantHandlers {
	return &TenantHandlers{
		service: service,
		logger:  logger,
	}
}

// RegisterRoutes registers the /api/v1/tenants routes (see Routes) on router
// for a standalone host, each gated on its own go-qrdb permission, which
// gate resolves through the hosted qrdb node's RBAC service. The role and
// user sub-trees are gated on qrdb's canonical roles:* and users:*
// permissions — the same grants the main REST/gRPC/QUIC/MCP transports
// require for identity administration. The tenant lifecycle routes are gated
// by the tenant they reach (PermissionGate.WrapTenant).
func (h *TenantHandlers) RegisterRoutes(router *mux.Router, authMiddleware AuthHandler, gate *PermissionGate) {
	mountRoutes(router, tenantsPathPrefix, authMiddleware, h, tenantRoutes(), gate.guardRoute)
}

// RegisterAuthorizedRoutes registers the /api/v1/tenants routes on router
// for a host that has already authorized every request against the route's
// permission; see Handlers.RegisterAuthorizedRoutes. The tenant lifecycle
// routes, which such a host mounts identity-gated (Route.SelfPermission),
// are still authorized here, by gate.
func (h *TenantHandlers) RegisterAuthorizedRoutes(router *mux.Router, authMiddleware AuthHandler, gate *PermissionGate) {
	mountRoutes(router, tenantsPathPrefix, authMiddleware, h, tenantRoutes(), gate.guardReachRoute)
}

// checkTenantAccess enforces the tenant binding for a request addressing
// tenantID, before its body is read. It answers 401 when no caller is
// authenticated, and a caller that may not address tenantID gets exactly the
// response a missing tenant gets (writeTenantNotFound, the go-xkms#1112
// convention). It reports whether the handler may proceed.
//
// The service applies the same binding (admitTenant) for every
// transport. Checking here as well answers a refused request before body
// parsing and validation run, whose answers would otherwise set a foreign
// tenant apart from a missing one.
func (h *TenantHandlers) checkTenantAccess(w http.ResponseWriter, r *http.Request, op, tenantID string) bool {
	user := GetUserFromContext(r.Context())
	if user == nil {
		writeProblem(w, http.StatusUnauthorized, problemUnauthorized, "Authentication required")
		return false
	}
	if err := admitTenant(r.Context(), op, tenantID); err != nil {
		h.logger.Warn("cross-tenant access refused",
			slog.String("op", op),
			slog.String("user_id", user.UserID),
			slog.String("user_tenant", user.TenantID),
			slog.String("target_tenant", tenantID))
		writeTenantNotFound(w)
		return false
	}
	return true
}

// writeTenantNotFound writes the single response for a tenant the caller
// cannot reach, whether it does not exist or belongs to someone else.
func writeTenantNotFound(w http.ResponseWriter) {
	writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Tenant not found")
}

// writeIdentityError answers a failed role or user operation. A refused or
// missing tenant, role or user is not-found; an operation qrdb's authorizer
// refuses the caller (strict tenant isolation keeps even a platform caller out
// of another tenant's users and roles) is permission-denied; anything else is
// an internal failure described by failure.
func writeIdentityError(w http.ResponseWriter, err error, failure string) {
	var denied *qrdbsdk.PermissionDeniedError
	switch {
	case errors.As(err, &denied):
		writePermissionDenied(w)
	case errors.Is(err, ErrTenantNotFound):
		writeTenantNotFound(w)
	case errors.Is(err, ErrRoleNotFound):
		writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Role not found")
	case errors.Is(err, ErrUserNotFound):
		writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "User not found")
	default:
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", failure)
	}
}

// UpdateTenant handles PUT /api/v1/tenants/{id}
func (h *TenantHandlers) UpdateTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	tenantID := vars["id"]

	if !h.checkTenantAccess(w, r, "update tenant", tenantID) {
		return
	}

	var req UpdateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}

	tenant, err := h.service.UpdateTenant(ctx, tenantID, req)
	if err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			writeTenantNotFound(w)
			return
		}
		h.logger.Error("failed to update tenant", slog.String("id", tenantID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to update tenant")
		return
	}

	writeJSON(w, http.StatusOK, tenant)
}

// UpdateTenantStatus handles PUT /api/v1/tenants/{id}/status
func (h *TenantHandlers) UpdateTenantStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	tenantID := vars["id"]

	if !h.checkTenantAccess(w, r, "update tenant status", tenantID) {
		return
	}

	var req UpdateTenantStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}

	if req.Status == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Status is required")
		return
	}

	// Validate status value
	validStatuses := map[string]bool{"active": true, "suspended": true, "deleted": true}
	if !validStatuses[req.Status] {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Status must be one of: active, suspended, deleted")
		return
	}

	if err := h.service.UpdateTenantStatus(ctx, tenantID, req.Status); err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			writeTenantNotFound(w)
			return
		}
		h.logger.Error("failed to update tenant status", slog.String("id", tenantID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to update tenant status")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Tenant status updated successfully"})
}

// CreateTenantRootCA handles POST /api/v1/tenants/{id}/root-ca
func (h *TenantHandlers) CreateTenantRootCA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	tenantID := vars["id"]

	if !h.checkTenantAccess(w, r, "create tenant root CA", tenantID) {
		return
	}

	var req CreateTenantRootCARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}

	if req.CommonName == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Common name is required")
		return
	}

	if req.KeyAlgorithm == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Key algorithm is required")
		return
	}

	if req.ValidityYears <= 0 {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Validity years must be positive")
		return
	}

	rootCA, err := h.service.CreateTenantRootCA(ctx, tenantID, req)
	if err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			writeTenantNotFound(w)
			return
		}
		if errors.Is(err, ErrTenantRootCAExists) {
			writeProblem(w, http.StatusConflict, "urn:trusted-ca:error:conflict", "Tenant root CA already exists")
			return
		}
		h.logger.Error("failed to create tenant root CA", slog.String("tenant", tenantID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to create tenant root CA")
		return
	}

	writeJSON(w, http.StatusCreated, rootCA)
}

// CreateTenantIntermediateCA handles POST /api/v1/tenants/{id}/intermediate-ca
func (h *TenantHandlers) CreateTenantIntermediateCA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	tenantID := vars["id"]

	if !h.checkTenantAccess(w, r, "create tenant intermediate CA", tenantID) {
		return
	}

	var req CreateTenantIntermediateCARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}

	if req.CommonName == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Common name is required")
		return
	}

	if req.KeyAlgorithm == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Key algorithm is required")
		return
	}

	if req.ParentType == "" {
		req.ParentType = "global" // Default to global root CA
	}

	validParentTypes := map[string]bool{"global": true, "tenant": true}
	if !validParentTypes[req.ParentType] {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Parent type must be 'global' or 'tenant'")
		return
	}

	if req.ValidityYears <= 0 {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Validity years must be positive")
		return
	}

	intCA, err := h.service.CreateTenantIntermediateCA(ctx, tenantID, req)
	if err != nil {
		if writeUnavailableIfNotConfigured(w, err) {
			return
		}
		if errors.Is(err, ErrTenantNotFound) {
			writeTenantNotFound(w)
			return
		}
		h.logger.Error("failed to create tenant intermediate CA", slog.String("tenant", tenantID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to create tenant intermediate CA")
		return
	}

	writeJSON(w, http.StatusCreated, intCA)
}

// GetTenantCAStatus handles GET /api/v1/tenants/{id}/ca-status
func (h *TenantHandlers) GetTenantCAStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	tenantID := vars["id"]

	if !h.checkTenantAccess(w, r, "get tenant CA status", tenantID) {
		return
	}

	status, err := h.service.GetTenantCAStatus(ctx, tenantID)
	if err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			writeTenantNotFound(w)
			return
		}
		h.logger.Error("failed to get tenant CA status", slog.String("tenant", tenantID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to get tenant CA status")
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// ListTenantIntermediateCAs handles GET /api/v1/tenants/{id}/intermediate-cas
func (h *TenantHandlers) ListTenantIntermediateCAs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	tenantID := vars["id"]

	if !h.checkTenantAccess(w, r, "list tenant intermediate CAs", tenantID) {
		return
	}

	cas, err := h.service.ListTenantIntermediateCAs(ctx, tenantID)
	if err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			writeTenantNotFound(w)
			return
		}
		h.logger.Error("failed to list tenant intermediate CAs", slog.String("tenant", tenantID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to list intermediate CAs")
		return
	}
	if cas == nil {
		cas = []*TenantIntCAInfo{}
	}

	writeJSON(w, http.StatusOK, cas)
}

// GetTenantIntermediateCA handles GET /api/v1/tenants/{id}/intermediate-cas/{caid}
func (h *TenantHandlers) GetTenantIntermediateCA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	tenantID := vars["id"]
	caID := vars["caid"]

	if !h.checkTenantAccess(w, r, "get tenant intermediate CA", tenantID) {
		return
	}

	ca, err := h.service.GetTenantIntermediateCA(ctx, tenantID, caID)
	if err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			writeTenantNotFound(w)
			return
		}
		if errors.Is(err, ErrTenantCANotConfigured) {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Intermediate CA not found")
			return
		}
		h.logger.Error("failed to get tenant intermediate CA", slog.String("tenant", tenantID), slog.String("ca_id", caID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to get intermediate CA")
		return
	}

	writeJSON(w, http.StatusOK, ca)
}

// UpdateTenantIntermediateCAStatus handles PUT /api/v1/tenants/{id}/intermediate-cas/{caid}/status
func (h *TenantHandlers) UpdateTenantIntermediateCAStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	tenantID := vars["id"]
	caID := vars["caid"]

	if !h.checkTenantAccess(w, r, "update tenant intermediate CA status", tenantID) {
		return
	}

	var req UpdateIntermediateCAStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}

	if req.Status == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Status is required")
		return
	}

	// Validate status value
	validStatuses := map[string]bool{"active": true, "pending-rotation": true, "revoked": true}
	if !validStatuses[req.Status] {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Status must be one of: active, pending-rotation, revoked")
		return
	}

	if err := h.service.UpdateTenantIntermediateCAStatus(ctx, tenantID, caID, req.Status); err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			writeTenantNotFound(w)
			return
		}
		if errors.Is(err, ErrTenantCANotConfigured) {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Intermediate CA not found")
			return
		}
		h.logger.Error("failed to update tenant intermediate CA status", slog.String("tenant", tenantID), slog.String("ca_id", caID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to update intermediate CA status")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Intermediate CA status updated successfully"})
}

// SetTenantDefaultIntermediateCA handles PUT /api/v1/tenants/{id}/default-intermediate-ca
func (h *TenantHandlers) SetTenantDefaultIntermediateCA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	tenantID := vars["id"]

	if !h.checkTenantAccess(w, r, "set tenant default intermediate CA", tenantID) {
		return
	}

	var req UpdateTenantDefaultCARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}

	if req.IntermediateCAID == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Intermediate CA ID is required")
		return
	}

	if err := h.service.SetTenantDefaultIntermediateCA(ctx, tenantID, req.IntermediateCAID); err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			writeTenantNotFound(w)
			return
		}
		if errors.Is(err, ErrTenantCANotConfigured) {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Intermediate CA not found")
			return
		}
		h.logger.Error("failed to set tenant default intermediate CA", slog.String("tenant", tenantID), slog.String("ca_id", req.IntermediateCAID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to set default intermediate CA")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Default intermediate CA updated successfully"})
}

// CreateTenantEAB handles POST /api/v1/tenants/{id}/eab
func (h *TenantHandlers) CreateTenantEAB(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	tenantID := vars["id"]

	if !h.checkTenantAccess(w, r, "create tenant EAB", tenantID) {
		return
	}

	var req CreateEABRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}

	// Default purpose to account-binding if not specified
	if req.Purpose == "" {
		req.Purpose = "account-binding"
	}

	// Validate purpose
	validPurposes := map[string]bool{"account-binding": true, "endorse-01": true, "enroll-01": true}
	if !validPurposes[req.Purpose] {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Purpose must be one of: account-binding, endorse-01, enroll-01")
		return
	}

	// For endorse-01, device info is recommended but not required
	if req.Purpose == "endorse-01" && req.DeviceInfo == nil {
		h.logger.Warn("creating endorse-01 EAB without device info", slog.String("tenant", tenantID))
	}

	eabResp, err := h.service.CreateTenantEAB(ctx, tenantID, req)
	if err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			writeTenantNotFound(w)
			return
		}
		if errors.Is(err, ErrInvalidEABPurpose) {
			writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid EAB purpose")
			return
		}
		h.logger.Error("failed to create tenant EAB", slog.String("tenant", tenantID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to create EAB")
		return
	}

	writeJSON(w, http.StatusCreated, eabResp)
}

// GetTenantEAB handles GET /api/v1/tenants/{id}/eab/{kid}
func (h *TenantHandlers) GetTenantEAB(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	tenantID := vars["id"]
	kid := vars["kid"]

	if !h.checkTenantAccess(w, r, "get tenant EAB", tenantID) {
		return
	}

	eab, err := h.service.GetTenantEAB(ctx, tenantID, kid)
	if err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			writeTenantNotFound(w)
			return
		}
		if errors.Is(err, ErrEABNotFound) {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "External account binding not found")
			return
		}
		h.logger.Error("failed to get tenant EAB", slog.String("tenant", tenantID), slog.String("kid", kid), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to get EAB")
		return
	}

	writeJSON(w, http.StatusOK, eab)
}

// DeleteTenantEAB handles DELETE /api/v1/tenants/{id}/eab/{kid}
func (h *TenantHandlers) DeleteTenantEAB(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	tenantID := vars["id"]
	kid := vars["kid"]

	if !h.checkTenantAccess(w, r, "delete tenant EAB", tenantID) {
		return
	}

	if err := h.service.DeleteTenantEAB(ctx, tenantID, kid); err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			writeTenantNotFound(w)
			return
		}
		if errors.Is(err, ErrEABNotFound) {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "External account binding not found")
			return
		}
		h.logger.Error("failed to delete tenant EAB", slog.String("tenant", tenantID), slog.String("kid", kid), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to delete EAB")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "EAB deleted successfully"})
}

// ListTenantEABs handles GET /api/v1/tenants/{id}/eab
func (h *TenantHandlers) ListTenantEABs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	tenantID := vars["id"]

	if !h.checkTenantAccess(w, r, "list tenant EABs", tenantID) {
		return
	}

	query := r.URL.Query()
	req := ListEABRequest{
		Page:    parseInt(query.Get("page"), 1),
		PerPage: parseInt(query.Get("per_page"), 20),
		Status:  query.Get("status"),
		Purpose: query.Get("purpose"),
	}

	eabs, pagination, err := h.service.ListTenantEABs(ctx, tenantID, req)
	if err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			writeTenantNotFound(w)
			return
		}
		h.logger.Error("failed to list tenant EABs", slog.String("tenant", tenantID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to list EABs")
		return
	}
	if eabs == nil {
		eabs = []*EABInfo{}
	}

	writeJSON(w, http.StatusOK, ListResponse{Items: eabs, Total: pagination.Total, Page: pagination.Page, PerPage: pagination.PerPage})
}

// CreateTenantRole handles POST /api/v1/tenants/{id}/roles
func (h *TenantHandlers) CreateTenantRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Tenant ID is required")
		return
	}
	if !h.checkTenantAccess(w, r, "create tenant role", tenantID) {
		return
	}

	var req db.CreateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body: "+err.Error())
		return
	}
	req.TenantID = tenantID

	role, err := h.service.CreateTenantRole(r.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error("failed to create role", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		writeIdentityError(w, err, "Failed to create role")
		return
	}

	writeJSON(w, http.StatusCreated, role)
}

// GetTenantRole handles GET /api/v1/tenants/{id}/roles/{roleID}
func (h *TenantHandlers) GetTenantRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	roleID := vars["roleID"]
	if tenantID == "" || roleID == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Tenant ID and role ID are required")
		return
	}
	if !h.checkTenantAccess(w, r, "get tenant role", tenantID) {
		return
	}

	role, err := h.service.GetTenantRole(r.Context(), tenantID, roleID)
	if err != nil {
		h.logger.Error("failed to get role", slog.String("tenant_id", tenantID), slog.String("role_id", roleID), slog.String("error", err.Error()))
		writeIdentityError(w, err, "Failed to get role")
		return
	}

	writeJSON(w, http.StatusOK, role)
}

// UpdateTenantRole handles PUT /api/v1/tenants/{id}/roles/{roleID}
func (h *TenantHandlers) UpdateTenantRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	roleID := vars["roleID"]
	if tenantID == "" || roleID == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Tenant ID and role ID are required")
		return
	}
	if !h.checkTenantAccess(w, r, "update tenant role", tenantID) {
		return
	}

	var req db.UpdateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body: "+err.Error())
		return
	}
	req.ID = roleID

	role, err := h.service.UpdateTenantRole(r.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error("failed to update role", slog.String("tenant_id", tenantID), slog.String("role_id", roleID), slog.String("error", err.Error()))
		writeIdentityError(w, err, "Failed to update role")
		return
	}

	writeJSON(w, http.StatusOK, role)
}

// DeleteTenantRole handles DELETE /api/v1/tenants/{id}/roles/{roleID}
func (h *TenantHandlers) DeleteTenantRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	roleID := vars["roleID"]
	if tenantID == "" || roleID == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Tenant ID and role ID are required")
		return
	}
	if !h.checkTenantAccess(w, r, "delete tenant role", tenantID) {
		return
	}

	if err := h.service.DeleteTenantRole(r.Context(), tenantID, roleID); err != nil {
		h.logger.Error("failed to delete role", slog.String("tenant_id", tenantID), slog.String("role_id", roleID), slog.String("error", err.Error()))
		writeIdentityError(w, err, "Failed to delete role")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Role deleted successfully"})
}

// ListTenantRoles handles GET /api/v1/tenants/{id}/roles
func (h *TenantHandlers) ListTenantRoles(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Tenant ID is required")
		return
	}
	if !h.checkTenantAccess(w, r, "list tenant roles", tenantID) {
		return
	}

	page, pageSize := parsePagination(r)
	req := &db.ListRolesRequest{
		TenantID: tenantID,
		Page:     page,
		PageSize: pageSize,
	}

	resp, err := h.service.ListTenantRoles(r.Context(), tenantID, req)
	if err != nil {
		h.logger.Error("failed to list roles", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		writeIdentityError(w, err, "Failed to list roles")
		return
	}
	if resp.Roles == nil {
		resp.Roles = []*db.Role{}
	}

	writeJSON(w, http.StatusOK, resp)
}

// CreateTenantUser handles POST /api/v1/tenants/{id}/users
func (h *TenantHandlers) CreateTenantUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Tenant ID is required")
		return
	}
	if !h.checkTenantAccess(w, r, "create tenant user", tenantID) {
		return
	}

	var req db.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body: "+err.Error())
		return
	}
	req.TenantID = tenantID

	user, err := h.service.CreateTenantUser(r.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error("failed to create user", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		writeIdentityError(w, err, "Failed to create user")
		return
	}

	writeJSON(w, http.StatusCreated, user)
}

// GetTenantUser handles GET /api/v1/tenants/{id}/users/{userID}
func (h *TenantHandlers) GetTenantUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	userID := vars["userID"]
	if tenantID == "" || userID == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Tenant ID and user ID are required")
		return
	}
	if !h.checkTenantAccess(w, r, "get tenant user", tenantID) {
		return
	}
	if _, err := strconv.ParseUint(userID, 10, 64); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid user ID: "+err.Error())
		return
	}

	user, err := h.service.GetTenantUser(r.Context(), tenantID, userID)
	if err != nil {
		h.logger.Error("failed to get user", slog.String("tenant_id", tenantID), slog.String("user_id", userID), slog.String("error", err.Error()))
		writeIdentityError(w, err, "Failed to get user")
		return
	}

	writeJSON(w, http.StatusOK, user)
}

// UpdateTenantUser handles PUT /api/v1/tenants/{id}/users/{userID}
func (h *TenantHandlers) UpdateTenantUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	userID := vars["userID"]
	if tenantID == "" || userID == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Tenant ID and user ID are required")
		return
	}
	if !h.checkTenantAccess(w, r, "update tenant user", tenantID) {
		return
	}

	var req db.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body: "+err.Error())
		return
	}
	parsedID, err := strconv.ParseUint(userID, 10, 64)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid user ID: "+err.Error())
		return
	}
	req.ID = parsedID

	user, err := h.service.UpdateTenantUser(r.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error("failed to update user", slog.String("tenant_id", tenantID), slog.String("user_id", userID), slog.String("error", err.Error()))
		writeIdentityError(w, err, "Failed to update user")
		return
	}

	writeJSON(w, http.StatusOK, user)
}

// DeleteTenantUser handles DELETE /api/v1/tenants/{id}/users/{userID}
func (h *TenantHandlers) DeleteTenantUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	userID := vars["userID"]
	if tenantID == "" || userID == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Tenant ID and user ID are required")
		return
	}
	if !h.checkTenantAccess(w, r, "delete tenant user", tenantID) {
		return
	}
	if _, err := strconv.ParseUint(userID, 10, 64); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid user ID: "+err.Error())
		return
	}

	if err := h.service.DeleteTenantUser(r.Context(), tenantID, userID); err != nil {
		h.logger.Error("failed to delete user", slog.String("tenant_id", tenantID), slog.String("user_id", userID), slog.String("error", err.Error()))
		writeIdentityError(w, err, "Failed to delete user")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "User deleted successfully"})
}

// ListTenantUsers handles GET /api/v1/tenants/{id}/users
func (h *TenantHandlers) ListTenantUsers(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Tenant ID is required")
		return
	}
	if !h.checkTenantAccess(w, r, "list tenant users", tenantID) {
		return
	}

	page, pageSize := parsePagination(r)
	req := &db.ListUsersRequest{
		TenantID: tenantID,
		Page:     page,
		PageSize: pageSize,
	}

	resp, err := h.service.ListTenantUsers(r.Context(), tenantID, req)
	if err != nil {
		h.logger.Error("failed to list users", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		writeIdentityError(w, err, "Failed to list users")
		return
	}
	if resp.Users == nil {
		resp.Users = []*db.User{}
	}

	writeJSON(w, http.StatusOK, resp)
}

// parsePagination extracts page and pageSize from query parameters.
func parsePagination(r *http.Request) (int, int) {
	page := 1
	pageSize := 20
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 {
			pageSize = v
		}
	}
	return page, pageSize
}
