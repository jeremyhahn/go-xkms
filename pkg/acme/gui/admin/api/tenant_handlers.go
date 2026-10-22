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

package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"

	adminsdk "github.com/jeremyhahn/go-xkms/sdk/go/acme/client/admin"
	sdkerrors "github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

// Tenant CRUD

// listTenants handles GET /api/v1/tenants.
func (h *handlers) listTenants(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	req := &adminsdk.ListTenantsRequest{
		Page:    parseInt(query.Get("page"), 1),
		PerPage: parseInt(query.Get("per_page"), 20),
	}

	resp, err := h.client.Admin().Tenant().List(r.Context(), req)
	if err != nil {
		h.logger.Error("failed to list tenants", slog.String("error", err.Error()))
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list tenants")
		return
	}

	writeJSON(w, http.StatusOK, resp.Tenants, resp.Pagination)
}

// createTenant handles POST /api/v1/tenants.
func (h *handlers) createTenant(w http.ResponseWriter, r *http.Request) {
	var req adminsdk.CreateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}

	tenant, err := h.client.Admin().Tenant().Create(r.Context(), &req)
	if err != nil {
		if sdkerrors.IsAlreadyExists(err) {
			writeErrorResponse(w, http.StatusConflict, "ALREADY_EXISTS", "tenant already exists")
			return
		}
		if sdkerrors.IsInvalidInput(err) {
			writeErrorResponse(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
			return
		}
		h.logger.Error("failed to create tenant", slog.String("error", err.Error()))
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create tenant")
		return
	}

	writeJSON(w, http.StatusCreated, tenant, nil)
}

// getTenant handles GET /api/v1/tenants/{id}.
func (h *handlers) getTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]

	tenant, err := h.client.Admin().Tenant().Get(r.Context(), tenantID)
	if err != nil {
		if sdkerrors.IsNotFound(err) {
			writeErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "tenant not found")
			return
		}
		h.logger.Error("failed to get tenant",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get tenant")
		return
	}

	writeJSON(w, http.StatusOK, tenant, nil)
}

// updateTenant handles PUT /api/v1/tenants/{id}.
func (h *handlers) updateTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]

	var req adminsdk.UpdateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}

	tenant, err := h.client.Admin().Tenant().Update(r.Context(), tenantID, &req)
	if err != nil {
		if sdkerrors.IsNotFound(err) {
			writeErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "tenant not found")
			return
		}
		if sdkerrors.IsInvalidInput(err) {
			writeErrorResponse(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
			return
		}
		h.logger.Error("failed to update tenant",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update tenant")
		return
	}

	writeJSON(w, http.StatusOK, tenant, nil)
}

// deleteTenant handles DELETE /api/v1/tenants/{id}.
func (h *handlers) deleteTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]

	if err := h.client.Admin().Tenant().Delete(r.Context(), tenantID); err != nil {
		if sdkerrors.IsNotFound(err) {
			writeErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "tenant not found")
			return
		}
		h.logger.Error("failed to delete tenant",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete tenant")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "tenant deleted successfully"}, nil)
}

// EAB Operations

// listEABs handles GET /api/v1/tenants/{id}/eab.
func (h *handlers) listEABs(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]
	query := r.URL.Query()
	req := &adminsdk.ListEABRequest{
		Page:    parseInt(query.Get("page"), 1),
		PerPage: parseInt(query.Get("per_page"), 20),
		Status:  query.Get("status"),
		Purpose: query.Get("purpose"),
	}

	resp, err := h.client.Admin().EAB().List(r.Context(), tenantID, req)
	if err != nil {
		h.logger.Error("failed to list EABs",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list EABs")
		return
	}

	writeJSON(w, http.StatusOK, resp.EABs, resp.Pagination)
}

// createEAB handles POST /api/v1/tenants/{id}/eab.
func (h *handlers) createEAB(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]

	var req adminsdk.CreateEABRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}

	eab, err := h.client.Admin().EAB().Create(r.Context(), tenantID, &req)
	if err != nil {
		if sdkerrors.IsInvalidInput(err) {
			writeErrorResponse(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
			return
		}
		h.logger.Error("failed to create EAB",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create EAB")
		return
	}

	writeJSON(w, http.StatusCreated, eab, nil)
}

// deleteEAB handles DELETE /api/v1/tenants/{id}/eab/{eabId}.
func (h *handlers) deleteEAB(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	eabID := vars["eabId"]

	if err := h.client.Admin().EAB().Delete(r.Context(), tenantID, eabID); err != nil {
		if sdkerrors.IsNotFound(err) {
			writeErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "EAB not found")
			return
		}
		h.logger.Error("failed to delete EAB",
			slog.String("tenant_id", tenantID),
			slog.String("eab_id", eabID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete EAB")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "EAB deleted successfully"}, nil)
}

// Role Operations

// listRoles handles GET /api/v1/tenants/{id}/roles.
func (h *handlers) listRoles(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]
	query := r.URL.Query()
	req := &adminsdk.ListRolesRequest{
		Page:     parseInt(query.Get("page"), 1),
		PageSize: parseInt(query.Get("per_page"), 20),
	}

	resp, err := h.client.Admin().Role().List(r.Context(), tenantID, req)
	if err != nil {
		h.logger.Error("failed to list roles",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list roles")
		return
	}

	writeJSON(w, http.StatusOK, resp.Roles, nil)
}

// createRole handles POST /api/v1/tenants/{id}/roles.
func (h *handlers) createRole(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]

	var req adminsdk.CreateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}

	role, err := h.client.Admin().Role().Create(r.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error("failed to create role",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create role")
		return
	}

	writeJSON(w, http.StatusCreated, role, nil)
}

// getRole handles GET /api/v1/tenants/{id}/roles/{roleId}.
func (h *handlers) getRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	roleID := vars["roleId"]

	role, err := h.client.Admin().Role().Get(r.Context(), tenantID, roleID)
	if err != nil {
		h.logger.Error("failed to get role",
			slog.String("tenant_id", tenantID),
			slog.String("role_id", roleID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get role")
		return
	}

	writeJSON(w, http.StatusOK, role, nil)
}

// updateRole handles PUT /api/v1/tenants/{id}/roles/{roleId}.
func (h *handlers) updateRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	roleID := vars["roleId"]

	var req adminsdk.UpdateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}
	req.ID = roleID

	role, err := h.client.Admin().Role().Update(r.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error("failed to update role",
			slog.String("tenant_id", tenantID),
			slog.String("role_id", roleID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update role")
		return
	}

	writeJSON(w, http.StatusOK, role, nil)
}

// deleteRole handles DELETE /api/v1/tenants/{id}/roles/{roleId}.
func (h *handlers) deleteRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	roleID := vars["roleId"]

	if err := h.client.Admin().Role().Delete(r.Context(), tenantID, roleID); err != nil {
		h.logger.Error("failed to delete role",
			slog.String("tenant_id", tenantID),
			slog.String("role_id", roleID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete role")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "role deleted successfully"}, nil)
}

// User Operations

// listUsers handles GET /api/v1/tenants/{id}/users.
func (h *handlers) listUsers(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]
	query := r.URL.Query()
	req := &adminsdk.ListUsersRequest{
		Page:     parseInt(query.Get("page"), 1),
		PageSize: parseInt(query.Get("per_page"), 20),
	}

	resp, err := h.client.Admin().User().List(r.Context(), tenantID, req)
	if err != nil {
		h.logger.Error("failed to list users",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list users")
		return
	}

	writeJSON(w, http.StatusOK, resp.Users, nil)
}

// createUser handles POST /api/v1/tenants/{id}/users.
func (h *handlers) createUser(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]

	var req adminsdk.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}

	user, err := h.client.Admin().User().Create(r.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error("failed to create user",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create user")
		return
	}

	writeJSON(w, http.StatusCreated, user, nil)
}

// getUser handles GET /api/v1/tenants/{id}/users/{userId}.
func (h *handlers) getUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	userID := vars["userId"]

	user, err := h.client.Admin().User().Get(r.Context(), tenantID, userID)
	if err != nil {
		h.logger.Error("failed to get user",
			slog.String("tenant_id", tenantID),
			slog.String("user_id", userID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get user")
		return
	}

	writeJSON(w, http.StatusOK, user, nil)
}

// updateUser handles PUT /api/v1/tenants/{id}/users/{userId}.
func (h *handlers) updateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	userID := vars["userId"]

	var req adminsdk.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}
	req.ID = userID

	user, err := h.client.Admin().User().Update(r.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error("failed to update user",
			slog.String("tenant_id", tenantID),
			slog.String("user_id", userID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update user")
		return
	}

	writeJSON(w, http.StatusOK, user, nil)
}

// deleteUser handles DELETE /api/v1/tenants/{id}/users/{userId}.
func (h *handlers) deleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	userID := vars["userId"]

	if err := h.client.Admin().User().Delete(r.Context(), tenantID, userID); err != nil {
		h.logger.Error("failed to delete user",
			slog.String("tenant_id", tenantID),
			slog.String("user_id", userID),
			slog.String("error", err.Error()),
		)
		writeErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete user")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "user deleted successfully"}, nil)
}
