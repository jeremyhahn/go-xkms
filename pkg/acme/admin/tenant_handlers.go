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
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
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

// RegisterRoutes registers all tenant API routes with the router
func (h *TenantHandlers) RegisterRoutes(router *mux.Router, authMiddleware AuthHandler) {
	// Apply auth middleware to all routes
	tenantsRouter := router.PathPrefix("/api/v1/tenants").Subrouter()
	if authMiddleware != nil {
		tenantsRouter.Use(authMiddleware.Authenticate)
	}

	// Tenant list (super-admin only)
	listRouter := tenantsRouter.NewRoute().Subrouter()
	listRouter.Use(RequireRole(RoleSuperAdmin))
	listRouter.HandleFunc("", h.ListTenants).Methods("GET")

	// Tenant creation (super-admin only)
	createRouter := tenantsRouter.NewRoute().Subrouter()
	createRouter.Use(RequireRole(RoleSuperAdmin))
	createRouter.HandleFunc("", h.CreateTenant).Methods("POST")

	// Tenant get/update/delete (admin can view own tenant, super-admin all)
	// Note: Role checks for tenant access are handled in the handlers
	tenantsRouter.HandleFunc("/{id}", h.GetTenant).Methods("GET")

	updateRouter := tenantsRouter.PathPrefix("/{id}").Subrouter()
	updateRouter.Use(RequireRole(RoleAdmin))
	updateRouter.HandleFunc("", h.UpdateTenant).Methods("PUT")

	// Tenant deletion (super-admin only)
	deleteRouter := tenantsRouter.PathPrefix("/{id}").Subrouter()
	deleteRouter.Use(RequireRole(RoleSuperAdmin))
	deleteRouter.HandleFunc("", h.DeleteTenant).Methods("DELETE")

	// Tenant status update (super-admin only)
	statusRouter := tenantsRouter.PathPrefix("/{id}/status").Subrouter()
	statusRouter.Use(RequireRole(RoleSuperAdmin))
	statusRouter.HandleFunc("", h.UpdateTenantStatus).Methods("PUT")

	// Tenant CA endpoints (admin access required)
	caRouter := tenantsRouter.PathPrefix("/{id}").Subrouter()
	caRouter.Use(RequireRole(RoleAdmin))
	caRouter.HandleFunc("/root-ca", h.CreateTenantRootCA).Methods("POST")
	caRouter.HandleFunc("/intermediate-cas", h.ListTenantIntermediateCAs).Methods("GET")
	caRouter.HandleFunc("/intermediate-cas", h.CreateTenantIntermediateCA).Methods("POST")
	caRouter.HandleFunc("/intermediate-cas/{caid}", h.GetTenantIntermediateCA).Methods("GET")
	caRouter.HandleFunc("/intermediate-cas/{caid}/status", h.UpdateTenantIntermediateCAStatus).Methods("PUT")
	caRouter.HandleFunc("/default-intermediate-ca", h.SetTenantDefaultIntermediateCA).Methods("PUT")
	caRouter.HandleFunc("/ca-status", h.GetTenantCAStatus).Methods("GET")

	// Tenant EAB endpoints (endorser can create, admin can manage)
	eabRouter := tenantsRouter.PathPrefix("/{id}/eab").Subrouter()
	eabRouter.Use(RequireRole(RoleEndorser))
	eabRouter.HandleFunc("", h.ListTenantEABs).Methods("GET")
	eabRouter.HandleFunc("", h.CreateTenantEAB).Methods("POST")
	eabRouter.HandleFunc("/{kid}", h.GetTenantEAB).Methods("GET")

	// EAB deletion requires admin role
	eabDeleteRouter := tenantsRouter.PathPrefix("/{id}/eab/{kid}").Subrouter()
	eabDeleteRouter.Use(RequireRole(RoleAdmin))
	eabDeleteRouter.HandleFunc("", h.DeleteTenantEAB).Methods("DELETE")

	// Role management routes
	roleRouter := tenantsRouter.PathPrefix("/{id}/roles").Subrouter()
	roleRouter.HandleFunc("", h.ListTenantRoles).Methods("GET")
	roleRouter.HandleFunc("", h.CreateTenantRole).Methods("POST")
	roleRouter.HandleFunc("/{roleID}", h.GetTenantRole).Methods("GET")
	roleRouter.HandleFunc("/{roleID}", h.UpdateTenantRole).Methods("PUT")
	roleRouter.HandleFunc("/{roleID}", h.DeleteTenantRole).Methods("DELETE")

	// User management routes
	userRouter := tenantsRouter.PathPrefix("/{id}/users").Subrouter()
	userRouter.HandleFunc("", h.ListTenantUsers).Methods("GET")
	userRouter.HandleFunc("", h.CreateTenantUser).Methods("POST")
	userRouter.HandleFunc("/{userID}", h.GetTenantUser).Methods("GET")
	userRouter.HandleFunc("/{userID}", h.UpdateTenantUser).Methods("PUT")
	userRouter.HandleFunc("/{userID}", h.DeleteTenantUser).Methods("DELETE")
}

// checkTenantAccess verifies that the caller has permission to access the specified tenant.
// It performs RBAC role checks to determine access.
//
// Access rules:
// - Super-admins can access any tenant
// - Users can access their own tenant (tenant ID matches)
// - Cross-tenant access is denied by default
//
// Returns nil if access is allowed, or an error describing the denial reason.
func (h *TenantHandlers) checkTenantAccess(_ context.Context, _ *http.Request, user *AuthenticatedUser, targetTenantID, _ string) error {
	// Super-admins have unrestricted access to all tenants
	if user.Role == RoleSuperAdmin {
		return nil
	}

	// Users can access their own tenant
	if user.TenantID == targetTenantID {
		return nil
	}

	// Default deny for cross-tenant access
	h.logger.Warn("cross-tenant access denied",
		slog.String("user_id", user.UserID),
		slog.String("user_tenant", user.TenantID),
		slog.String("target_tenant", targetTenantID))
	return ErrForbidden
}

// CreateTenant handles POST /api/v1/tenants
func (h *TenantHandlers) CreateTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}

	// Auto-generate ID if not provided
	if req.ID == "" {
		req.ID = fmt.Sprintf("tenant-%d", time.Now().UnixNano())
	}

	if req.Name == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Tenant name is required")
		return
	}

	tenant, err := h.service.CreateTenant(ctx, req)
	if err != nil {
		if err == ErrTenantAlreadyExists {
			writeProblem(w, http.StatusConflict, "urn:trusted-ca:error:conflict", "Tenant already exists")
			return
		}
		h.logger.Error("failed to create tenant", slog.String("id", req.ID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to create tenant")
		return
	}

	writeJSON(w, http.StatusCreated, tenant)
}

// GetTenant handles GET /api/v1/tenants/{id}
func (h *TenantHandlers) GetTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	tenantID := vars["id"]

	// Extract caller identity from request context
	user := GetUserFromContext(ctx)
	if user == nil {
		writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Authentication required")
		return
	}

	// Check if caller has permission to access this tenant
	if err := h.checkTenantAccess(ctx, r, user, tenantID, ActionRead); err != nil {
		writeProblem(w, http.StatusForbidden, "urn:trusted-ca:error:forbidden", "Access denied to tenant")
		return
	}

	tenant, err := h.service.GetTenant(ctx, tenantID)
	if err != nil {
		if err == ErrTenantNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Tenant not found")
			return
		}
		h.logger.Error("failed to get tenant", slog.String("id", tenantID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to get tenant")
		return
	}

	writeJSON(w, http.StatusOK, tenant)
}

// UpdateTenant handles PUT /api/v1/tenants/{id}
func (h *TenantHandlers) UpdateTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	tenantID := vars["id"]

	// Extract caller identity and check tenant access
	user := GetUserFromContext(ctx)
	if user == nil {
		writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Authentication required")
		return
	}

	if err := h.checkTenantAccess(ctx, r, user, tenantID, ActionUpdate); err != nil {
		writeProblem(w, http.StatusForbidden, "urn:trusted-ca:error:forbidden", "Access denied to tenant")
		return
	}

	var req UpdateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}

	tenant, err := h.service.UpdateTenant(ctx, tenantID, req)
	if err != nil {
		if err == ErrTenantNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Tenant not found")
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
		if err == ErrTenantNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Tenant not found")
			return
		}
		h.logger.Error("failed to update tenant status", slog.String("id", tenantID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to update tenant status")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Tenant status updated successfully"})
}

// DeleteTenant handles DELETE /api/v1/tenants/{id}
func (h *TenantHandlers) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	tenantID := vars["id"]

	if err := h.service.DeleteTenant(ctx, tenantID); err != nil {
		if err == ErrTenantNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Tenant not found")
			return
		}
		h.logger.Error("failed to delete tenant", slog.String("id", tenantID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to delete tenant")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Tenant deleted successfully"})
}

// ListTenants handles GET /api/v1/tenants
func (h *TenantHandlers) ListTenants(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	query := r.URL.Query()
	req := ListTenantsRequest{
		Page:    parseInt(query.Get("page"), 1),
		PerPage: parseInt(query.Get("per_page"), 20),
		Status:  query.Get("status"),
	}

	tenants, pagination, err := h.service.ListTenants(ctx, req)
	if err != nil {
		h.logger.Error("failed to list tenants", slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to list tenants")
		return
	}
	if tenants == nil {
		tenants = []*TenantInfo{}
	}

	writeJSON(w, http.StatusOK, ListResponse{Items: tenants, Total: pagination.Total, Page: pagination.Page, PerPage: pagination.PerPage})
}

// CreateTenantRootCA handles POST /api/v1/tenants/{id}/root-ca
func (h *TenantHandlers) CreateTenantRootCA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	tenantID := vars["id"]

	// Check tenant access for CA management
	user := GetUserFromContext(ctx)
	if user == nil {
		writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Authentication required")
		return
	}

	if err := h.checkTenantAccess(ctx, r, user, tenantID, ActionAdmin); err != nil {
		writeProblem(w, http.StatusForbidden, "urn:trusted-ca:error:forbidden", "Access denied to tenant")
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
		if err == ErrTenantNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Tenant not found")
			return
		}
		if err == ErrTenantRootCAExists {
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

	// Check tenant access for CA management
	user := GetUserFromContext(ctx)
	if user == nil {
		writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Authentication required")
		return
	}

	if err := h.checkTenantAccess(ctx, r, user, tenantID, ActionAdmin); err != nil {
		writeProblem(w, http.StatusForbidden, "urn:trusted-ca:error:forbidden", "Access denied to tenant")
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
		if err == ErrTenantNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Tenant not found")
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

	// Check tenant access
	user := GetUserFromContext(ctx)
	if user == nil {
		writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Authentication required")
		return
	}

	if err := h.checkTenantAccess(ctx, r, user, tenantID, ActionRead); err != nil {
		writeProblem(w, http.StatusForbidden, "urn:trusted-ca:error:forbidden", "Access denied to tenant")
		return
	}

	status, err := h.service.GetTenantCAStatus(ctx, tenantID)
	if err != nil {
		if err == ErrTenantNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Tenant not found")
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

	// Check tenant access
	user := GetUserFromContext(ctx)
	if user == nil {
		writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Authentication required")
		return
	}

	if err := h.checkTenantAccess(ctx, r, user, tenantID, ActionRead); err != nil {
		writeProblem(w, http.StatusForbidden, "urn:trusted-ca:error:forbidden", "Access denied to tenant")
		return
	}

	cas, err := h.service.ListTenantIntermediateCAs(ctx, tenantID)
	if err != nil {
		if err == ErrTenantNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Tenant not found")
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

	// Check tenant access
	user := GetUserFromContext(ctx)
	if user == nil {
		writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Authentication required")
		return
	}

	if err := h.checkTenantAccess(ctx, r, user, tenantID, ActionRead); err != nil {
		writeProblem(w, http.StatusForbidden, "urn:trusted-ca:error:forbidden", "Access denied to tenant")
		return
	}

	ca, err := h.service.GetTenantIntermediateCA(ctx, tenantID, caID)
	if err != nil {
		if err == ErrTenantNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Tenant not found")
			return
		}
		if err == ErrTenantCANotConfigured {
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

	// Check tenant access for CA management
	user := GetUserFromContext(ctx)
	if user == nil {
		writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Authentication required")
		return
	}

	if err := h.checkTenantAccess(ctx, r, user, tenantID, ActionAdmin); err != nil {
		writeProblem(w, http.StatusForbidden, "urn:trusted-ca:error:forbidden", "Access denied to tenant")
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
		if err == ErrTenantNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Tenant not found")
			return
		}
		if err == ErrTenantCANotConfigured {
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

	// Check tenant access for CA management
	user := GetUserFromContext(ctx)
	if user == nil {
		writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Authentication required")
		return
	}

	if err := h.checkTenantAccess(ctx, r, user, tenantID, ActionAdmin); err != nil {
		writeProblem(w, http.StatusForbidden, "urn:trusted-ca:error:forbidden", "Access denied to tenant")
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
		if err == ErrTenantNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Tenant not found")
			return
		}
		if err == ErrTenantCANotConfigured {
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

	// Check tenant access for EAB creation
	user := GetUserFromContext(ctx)
	if user == nil {
		writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Authentication required")
		return
	}

	if err := h.checkTenantAccess(ctx, r, user, tenantID, ActionCreate); err != nil {
		writeProblem(w, http.StatusForbidden, "urn:trusted-ca:error:forbidden", "Access denied to tenant")
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
		if err == ErrTenantNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Tenant not found")
			return
		}
		if err == ErrInvalidEABPurpose {
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

	// Check tenant access
	user := GetUserFromContext(ctx)
	if user == nil {
		writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Authentication required")
		return
	}

	if err := h.checkTenantAccess(ctx, r, user, tenantID, ActionRead); err != nil {
		writeProblem(w, http.StatusForbidden, "urn:trusted-ca:error:forbidden", "Access denied to tenant")
		return
	}

	eab, err := h.service.GetTenantEAB(ctx, tenantID, kid)
	if err != nil {
		if err == ErrTenantNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Tenant not found")
			return
		}
		if err == ErrEABNotFound {
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

	// Check tenant access for EAB deletion
	user := GetUserFromContext(ctx)
	if user == nil {
		writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Authentication required")
		return
	}

	if err := h.checkTenantAccess(ctx, r, user, tenantID, ActionDelete); err != nil {
		writeProblem(w, http.StatusForbidden, "urn:trusted-ca:error:forbidden", "Access denied to tenant")
		return
	}

	if err := h.service.DeleteTenantEAB(ctx, tenantID, kid); err != nil {
		if err == ErrTenantNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Tenant not found")
			return
		}
		if err == ErrEABNotFound {
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

	// Check tenant access
	user := GetUserFromContext(ctx)
	if user == nil {
		writeProblem(w, http.StatusUnauthorized, "urn:trusted-ca:error:unauthorized", "Authentication required")
		return
	}

	if err := h.checkTenantAccess(ctx, r, user, tenantID, ActionList); err != nil {
		writeProblem(w, http.StatusForbidden, "urn:trusted-ca:error:forbidden", "Access denied to tenant")
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
		if err == ErrTenantNotFound {
			writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Tenant not found")
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

	var req db.CreateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body: "+err.Error())
		return
	}
	req.TenantID = tenantID

	role, err := h.service.CreateTenantRole(r.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error("failed to create role", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to create role")
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

	role, err := h.service.GetTenantRole(r.Context(), tenantID, roleID)
	if err != nil {
		h.logger.Error("failed to get role", slog.String("tenant_id", tenantID), slog.String("role_id", roleID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "Role not found")
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

	var req db.UpdateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body: "+err.Error())
		return
	}
	req.ID = roleID

	role, err := h.service.UpdateTenantRole(r.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error("failed to update role", slog.String("tenant_id", tenantID), slog.String("role_id", roleID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to update role")
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

	if err := h.service.DeleteTenantRole(r.Context(), tenantID, roleID); err != nil {
		h.logger.Error("failed to delete role", slog.String("tenant_id", tenantID), slog.String("role_id", roleID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to delete role")
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

	page, pageSize := parsePagination(r)
	req := &db.ListRolesRequest{
		TenantID: tenantID,
		Page:     page,
		PageSize: pageSize,
	}

	resp, err := h.service.ListTenantRoles(r.Context(), tenantID, req)
	if err != nil {
		h.logger.Error("failed to list roles", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to list roles")
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

	var req db.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body: "+err.Error())
		return
	}
	req.TenantID = tenantID

	user, err := h.service.CreateTenantUser(r.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error("failed to create user", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to create user")
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

	user, err := h.service.GetTenantUser(r.Context(), tenantID, userID)
	if err != nil {
		h.logger.Error("failed to get user", slog.String("tenant_id", tenantID), slog.String("user_id", userID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusNotFound, "urn:trusted-ca:error:not-found", "User not found")
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
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to update user")
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

	if err := h.service.DeleteTenantUser(r.Context(), tenantID, userID); err != nil {
		h.logger.Error("failed to delete user", slog.String("tenant_id", tenantID), slog.String("user_id", userID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to delete user")
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

	page, pageSize := parsePagination(r)
	req := &db.ListUsersRequest{
		TenantID: tenantID,
		Page:     page,
		PageSize: pageSize,
	}

	resp, err := h.service.ListTenantUsers(r.Context(), tenantID, req)
	if err != nil {
		h.logger.Error("failed to list users", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to list users")
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
