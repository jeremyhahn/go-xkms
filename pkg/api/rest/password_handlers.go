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

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
)

// PasswordHandlers provides HTTP handlers for password store operations.
// When a TenantPasswordStoreManager is provided, operations are routed
// to per-tenant encrypted stores based on the authenticated identity.
type PasswordHandlers struct {
	store   staticpw.Store
	manager *staticpw.TenantPasswordStoreManager
}

// NewPasswordHandlers creates a new PasswordHandlers instance. The manager
// parameter may be nil for single-tenant (backward compatible) mode.
func NewPasswordHandlers(store staticpw.Store, manager *staticpw.TenantPasswordStoreManager) *PasswordHandlers {
	return &PasswordHandlers{
		store:   store,
		manager: manager,
	}
}

// resolveStore returns the appropriate store for the request. When a manager
// is configured and the identity has a TenantID, a scoped store (with
// personal/shared separation) is returned. Otherwise, the system store is used.
func (h *PasswordHandlers) resolveStore(r *http.Request) (staticpw.Store, error) {
	if h.manager != nil {
		identity := auth.GetIdentity(r.Context())
		if identity != nil && identity.TenantID != "" {
			return h.manager.ResolveScopedStore(identity.TenantID, identity.Subject)
		}
	}
	if h.store != nil {
		return h.store, nil
	}
	return nil, staticpw.ErrNotConfigured
}

// --- Request types ---

// PasswordAddRequest is the request body for adding a new password entry.
type PasswordAddRequest struct {
	Name       string `json:"name"`
	Title      string `json:"title,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password"`
	URL        string `json:"url,omitempty"`
	Notes      string `json:"notes,omitempty"`
	FolderPath string `json:"folder_path,omitempty"`
	Shared     bool   `json:"shared,omitempty"`
}

// PasswordUpdateRequest is the request body for updating an existing password entry.
type PasswordUpdateRequest struct {
	Name       *string `json:"name,omitempty"`
	Title      *string `json:"title,omitempty"`
	Username   *string `json:"username,omitempty"`
	Password   *string `json:"password,omitempty"`
	URL        *string `json:"url,omitempty"`
	Notes      *string `json:"notes,omitempty"`
	FolderPath *string `json:"folder_path,omitempty"`
}

// PasswordGenerateRequest is the request body for generating a random password.
type PasswordGenerateRequest struct {
	Length  int    `json:"length,omitempty"`
	Charset string `json:"charset,omitempty"`
}

// PasswordStoreUnlockRequest is the request body for unlocking the password store.
type PasswordStoreUnlockRequest struct {
	PIN string `json:"pin"`
}

// --- Response types ---

// PasswordAddResponse is the response after adding a password entry.
type PasswordAddResponse struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Message string `json:"message"`
}

// PasswordInfo is a summary of a password entry returned in list responses.
type PasswordInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Title      string `json:"title,omitempty"`
	Username   string `json:"username,omitempty"`
	URL        string `json:"url,omitempty"`
	FolderPath string `json:"folder_path,omitempty"`
	OwnerID    string `json:"owner_id,omitempty"`
	Shared     bool   `json:"shared,omitempty"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// PasswordListResponse is the response for listing password entries.
type PasswordListResponse struct {
	Passwords []PasswordInfo `json:"passwords"`
	Total     int            `json:"total"`
}

// PasswordDetailResponse is the detailed response for a single password entry.
type PasswordDetailResponse struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Title      string `json:"title,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password"`
	URL        string `json:"url,omitempty"`
	Notes      string `json:"notes,omitempty"`
	FolderPath string `json:"folder_path,omitempty"`
	OwnerID    string `json:"owner_id,omitempty"`
	Shared     bool   `json:"shared,omitempty"`
	ReadOnly   bool   `json:"read_only,omitempty"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// PasswordUpdateResponse is the response after updating a password entry.
type PasswordUpdateResponse struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Message string `json:"message"`
}

// PasswordDeleteResponse is the response after deleting a password entry.
type PasswordDeleteResponse struct {
	Message string `json:"message"`
}

// PasswordGenerateResponse is the response for generating a random password.
type PasswordGenerateResponse struct {
	Password string `json:"password"`
	Length   int    `json:"length"`
}

// PasswordStoreStatusResponse is the response for the password store status endpoint.
type PasswordStoreStatusResponse struct {
	Available     bool   `json:"available"`
	IsLocked      bool   `json:"is_locked"`
	BarrierSealed bool   `json:"barrier_sealed"`
	PasswordCount int    `json:"password_count"`
	Message       string `json:"message"`
}

// --- Handlers ---

// AddPasswordHandler handles POST /api/v1/passwords requests.
// It decodes the request body, validates the input, and stores the new password entry.
func (h *PasswordHandlers) AddPasswordHandler(w http.ResponseWriter, r *http.Request) {
	store, err := h.resolveStore(r)
	if err != nil {
		passwordHandleStoreError(w, err)
		return
	}

	var req PasswordAddRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		passwordWriteJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	pw := &staticpw.StaticPassword{
		Name:       req.Name,
		Title:      req.Title,
		Username:   req.Username,
		Password:   req.Password,
		URL:        req.URL,
		Notes:      req.Notes,
		FolderPath: req.FolderPath,
		Shared:     req.Shared,
	}

	if err := store.Add(pw); err != nil {
		switch {
		case errors.Is(err, staticpw.ErrInvalidName):
			passwordWriteJSONError(w, "Name is required", http.StatusBadRequest)
		case errors.Is(err, staticpw.ErrEmptyPassword):
			passwordWriteJSONError(w, "Password is required", http.StatusBadRequest)
		case errors.Is(err, staticpw.ErrPasswordExists):
			passwordWriteJSONError(w, "Password with this name already exists", http.StatusConflict)
		case errors.Is(err, staticpw.ErrStoreClosed):
			passwordWriteJSONError(w, "Password store is closed", http.StatusServiceUnavailable)
		default:
			passwordWriteJSONError(w, "Failed to add password", http.StatusInternalServerError)
		}
		return
	}

	resp := PasswordAddResponse{
		ID:      pw.ID,
		Name:    pw.Name,
		Message: "Password added successfully",
	}

	writeJSON(w, resp, http.StatusCreated)
}

// ListPasswordsHandler handles GET /api/v1/passwords requests.
// It returns all password entries, optionally filtered by folder query parameter.
func (h *PasswordHandlers) ListPasswordsHandler(w http.ResponseWriter, r *http.Request) {
	store, err := h.resolveStore(r)
	if err != nil {
		passwordHandleStoreError(w, err)
		return
	}

	folder := r.URL.Query().Get("folder")
	scope := r.URL.Query().Get("scope")

	var entries []*staticpw.StaticPassword

	// Scope-aware listing.
	if scope != "" {
		ps := staticpw.PasswordScope(scope)
		if !ps.IsValid() {
			passwordWriteJSONError(w, "Invalid scope (use personal, shared, or all)", http.StatusBadRequest)
			return
		}
		if scopedStore, ok := store.(*staticpw.ScopedStore); ok {
			entries, err = scopedStore.ListByScope(ps)
		} else {
			entries, err = store.List()
		}
	} else if folder != "" {
		entries, err = store.ListByFolder(folder)
	} else {
		entries, err = store.List()
	}

	if err != nil {
		if errors.Is(err, staticpw.ErrStoreClosed) {
			passwordWriteJSONError(w, "Password store is closed", http.StatusServiceUnavailable)
			return
		}
		passwordWriteJSONError(w, "Failed to list passwords", http.StatusInternalServerError)
		return
	}

	infos := make([]PasswordInfo, len(entries))
	for i, pw := range entries {
		infos[i] = PasswordInfo{
			ID:         pw.ID,
			Name:       pw.Name,
			Title:      pw.Title,
			Username:   pw.Username,
			URL:        pw.URL,
			FolderPath: pw.FolderPath,
			OwnerID:    pw.OwnerID,
			Shared:     pw.Shared,
			CreatedAt:  pw.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:  pw.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		}
	}

	resp := PasswordListResponse{
		Passwords: infos,
		Total:     len(infos),
	}

	writeJSON(w, resp, http.StatusOK)
}

// GetPasswordHandler handles GET /api/v1/passwords/{id} requests.
// It retrieves a password entry by ID or name.
func (h *PasswordHandlers) GetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	store, err := h.resolveStore(r)
	if err != nil {
		passwordHandleStoreError(w, err)
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		passwordWriteJSONError(w, "Password ID is required", http.StatusBadRequest)
		return
	}

	pw, err := store.Get(id)
	if err != nil {
		if errors.Is(err, staticpw.ErrPasswordNotFound) {
			passwordWriteJSONError(w, "Password not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, staticpw.ErrStoreClosed) {
			passwordWriteJSONError(w, "Password store is closed", http.StatusServiceUnavailable)
			return
		}
		passwordWriteJSONError(w, "Failed to get password", http.StatusInternalServerError)
		return
	}

	resp := PasswordDetailResponse{
		ID:         pw.ID,
		Name:       pw.Name,
		Title:      pw.Title,
		Username:   pw.Username,
		Password:   pw.Password,
		URL:        pw.URL,
		Notes:      pw.Notes,
		FolderPath: pw.FolderPath,
		OwnerID:    pw.OwnerID,
		Shared:     pw.Shared,
		ReadOnly:   pw.ReadOnly,
		CreatedAt:  pw.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:  pw.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}

	writeJSON(w, resp, http.StatusOK)
}

// UpdatePasswordHandler handles PUT /api/v1/passwords/{id} requests.
// It updates an existing password entry, applying only non-nil fields from the request.
func (h *PasswordHandlers) UpdatePasswordHandler(w http.ResponseWriter, r *http.Request) {
	store, err := h.resolveStore(r)
	if err != nil {
		passwordHandleStoreError(w, err)
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		passwordWriteJSONError(w, "Password ID is required", http.StatusBadRequest)
		return
	}

	var req PasswordUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		passwordWriteJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get existing entry
	existing, err := store.Get(id)
	if err != nil {
		if errors.Is(err, staticpw.ErrPasswordNotFound) {
			passwordWriteJSONError(w, "Password not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, staticpw.ErrStoreClosed) {
			passwordWriteJSONError(w, "Password store is closed", http.StatusServiceUnavailable)
			return
		}
		passwordWriteJSONError(w, "Failed to get password", http.StatusInternalServerError)
		return
	}

	// Apply updates from request (only non-nil pointer fields)
	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Title != nil {
		existing.Title = *req.Title
	}
	if req.Username != nil {
		existing.Username = *req.Username
	}
	if req.Password != nil {
		existing.Password = *req.Password
	}
	if req.URL != nil {
		existing.URL = *req.URL
	}
	if req.Notes != nil {
		existing.Notes = *req.Notes
	}
	if req.FolderPath != nil {
		existing.FolderPath = *req.FolderPath
	}

	if err := store.Update(existing); err != nil {
		switch {
		case errors.Is(err, staticpw.ErrInvalidName):
			passwordWriteJSONError(w, "Name is required", http.StatusBadRequest)
		case errors.Is(err, staticpw.ErrEmptyPassword):
			passwordWriteJSONError(w, "Password is required", http.StatusBadRequest)
		case errors.Is(err, staticpw.ErrPasswordNotFound):
			passwordWriteJSONError(w, "Password not found", http.StatusNotFound)
		case errors.Is(err, staticpw.ErrPasswordReadOnly):
			passwordWriteJSONError(w, "Password is read-only", http.StatusForbidden)
		case errors.Is(err, staticpw.ErrStoreClosed):
			passwordWriteJSONError(w, "Password store is closed", http.StatusServiceUnavailable)
		default:
			passwordWriteJSONError(w, "Failed to update password", http.StatusInternalServerError)
		}
		return
	}

	resp := PasswordUpdateResponse{
		ID:      existing.ID,
		Name:    existing.Name,
		Message: "Password updated successfully",
	}

	writeJSON(w, resp, http.StatusOK)
}

// DeletePasswordHandler handles DELETE /api/v1/passwords/{id} requests.
// It removes a password entry by ID or name.
func (h *PasswordHandlers) DeletePasswordHandler(w http.ResponseWriter, r *http.Request) {
	store, err := h.resolveStore(r)
	if err != nil {
		passwordHandleStoreError(w, err)
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		passwordWriteJSONError(w, "Password ID is required", http.StatusBadRequest)
		return
	}

	if err := store.Delete(id); err != nil {
		switch {
		case errors.Is(err, staticpw.ErrPasswordNotFound):
			passwordWriteJSONError(w, "Password not found", http.StatusNotFound)
		case errors.Is(err, staticpw.ErrPasswordReadOnly):
			passwordWriteJSONError(w, "Password is read-only", http.StatusForbidden)
		case errors.Is(err, staticpw.ErrStoreClosed):
			passwordWriteJSONError(w, "Password store is closed", http.StatusServiceUnavailable)
		default:
			passwordWriteJSONError(w, "Failed to delete password", http.StatusInternalServerError)
		}
		return
	}

	resp := PasswordDeleteResponse{
		Message: "Password deleted successfully",
	}

	writeJSON(w, resp, http.StatusOK)
}

// UnlockHandler handles POST /api/v1/passwords/unlock requests.
// When a TenantPasswordStoreManager is configured, it unlocks the
// tenant's session allowing password store access.
func (h *PasswordHandlers) UnlockHandler(w http.ResponseWriter, r *http.Request) {
	if h.manager == nil {
		passwordWriteJSONError(w, "Password store unlock requires server integration", http.StatusNotImplemented)
		return
	}

	identity := auth.GetIdentity(r.Context())
	if identity == nil || identity.TenantID == "" {
		passwordWriteJSONError(w, "Tenant identity required", http.StatusUnauthorized)
		return
	}

	if err := h.manager.UnlockTenant(identity.TenantID); err != nil {
		switch {
		case errors.Is(err, staticpw.ErrStoreNotLocked):
			passwordWriteJSONError(w, "Store is already unlocked", http.StatusConflict)
		case errors.Is(err, seal.ErrTenantSealed):
			passwordWriteJSONError(w, "Tenant barrier is sealed", http.StatusServiceUnavailable)
		case errors.Is(err, seal.ErrTenantNotFound):
			passwordWriteJSONError(w, "Tenant not found", http.StatusNotFound)
		default:
			passwordWriteJSONError(w, "Failed to unlock store", http.StatusInternalServerError)
		}
		return
	}

	status, err := h.manager.TenantStoreStatus(identity.TenantID)
	if err != nil {
		passwordWriteJSONError(w, "Store unlocked but failed to get status", http.StatusInternalServerError)
		return
	}

	resp := PasswordStoreStatusResponse{
		Available:     true,
		IsLocked:      status.IsLocked,
		BarrierSealed: status.BarrierSealed,
		PasswordCount: status.PasswordCount,
		Message:       "Store unlocked successfully",
	}

	writeJSON(w, resp, http.StatusOK)
}

// LockHandler handles POST /api/v1/passwords/lock requests.
// When a TenantPasswordStoreManager is configured, it locks the
// tenant's session preventing password store access.
func (h *PasswordHandlers) LockHandler(w http.ResponseWriter, r *http.Request) {
	if h.manager == nil {
		passwordWriteJSONError(w, "Password store lock requires server integration", http.StatusNotImplemented)
		return
	}

	identity := auth.GetIdentity(r.Context())
	if identity == nil || identity.TenantID == "" {
		passwordWriteJSONError(w, "Tenant identity required", http.StatusUnauthorized)
		return
	}

	if err := h.manager.LockTenant(identity.TenantID); err != nil {
		switch {
		case errors.Is(err, staticpw.ErrStoreAlreadyLocked):
			passwordWriteJSONError(w, "Store is already locked", http.StatusConflict)
		case errors.Is(err, seal.ErrTenantNotFound):
			passwordWriteJSONError(w, "Tenant not found", http.StatusNotFound)
		default:
			passwordWriteJSONError(w, "Failed to lock store", http.StatusInternalServerError)
		}
		return
	}

	status, err := h.manager.TenantStoreStatus(identity.TenantID)
	if err != nil {
		passwordWriteJSONError(w, "Store locked but failed to get status", http.StatusInternalServerError)
		return
	}

	resp := PasswordStoreStatusResponse{
		Available:     true,
		IsLocked:      status.IsLocked,
		BarrierSealed: status.BarrierSealed,
		PasswordCount: status.PasswordCount,
		Message:       "Store locked successfully",
	}

	writeJSON(w, resp, http.StatusOK)
}

// StatusHandler handles GET /api/v1/passwords/status requests.
// It returns the availability and lock status of the password store.
func (h *PasswordHandlers) StatusHandler(w http.ResponseWriter, r *http.Request) {
	if h.manager != nil {
		identity := auth.GetIdentity(r.Context())
		if identity != nil && identity.TenantID != "" {
			status, err := h.manager.TenantStoreStatus(identity.TenantID)
			if err != nil {
				if errors.Is(err, seal.ErrTenantNotFound) {
					passwordWriteJSONError(w, "Tenant not found", http.StatusNotFound)
					return
				}
				passwordWriteJSONError(w, "Failed to get store status", http.StatusInternalServerError)
				return
			}

			resp := PasswordStoreStatusResponse{
				Available:     true,
				IsLocked:      status.IsLocked,
				BarrierSealed: status.BarrierSealed,
				PasswordCount: status.PasswordCount,
				Message:       "Password store status retrieved",
			}
			writeJSON(w, resp, http.StatusOK)
			return
		}
	}

	// System-level fallback.
	resp := PasswordStoreStatusResponse{
		Available: true,
		Message:   "Password store is available",
	}

	writeJSON(w, resp, http.StatusOK)
}

// SetAccessModeHandler handles PUT /api/v1/passwords/access-mode requests.
// This endpoint is a stub that returns 501 Not Implemented. Access mode
// management requires server-level integration with the access control layer.
func (h *PasswordHandlers) SetAccessModeHandler(w http.ResponseWriter, r *http.Request) {
	passwordWriteJSONError(w, "Access mode management requires server integration", http.StatusNotImplemented)
}

// GeneratePasswordHandler handles POST /api/v1/passwords/generate requests.
// It generates a cryptographically random password using the specified parameters.
func (h *PasswordHandlers) GeneratePasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req PasswordGenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		passwordWriteJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Apply defaults
	length := req.Length
	if length == 0 {
		length = staticpw.DefaultLength
	}

	charset := req.Charset
	if charset == "" {
		charset = staticpw.CharsetAll
	}

	password, err := staticpw.GeneratePassword(length, charset)
	if err != nil {
		if errors.Is(err, staticpw.ErrInvalidLength) {
			passwordWriteJSONError(w, "Invalid password length (min 8, max 128)", http.StatusBadRequest)
			return
		}
		passwordWriteJSONError(w, "Failed to generate password", http.StatusInternalServerError)
		return
	}

	resp := PasswordGenerateResponse{
		Password: password,
		Length:   length,
	}

	writeJSON(w, resp, http.StatusOK)
}

// passwordHandleStoreError maps store resolution errors to HTTP status codes.
func passwordHandleStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, staticpw.ErrStoreLocked):
		passwordWriteJSONError(w, "Password store is locked", http.StatusLocked)
	case errors.Is(err, seal.ErrTenantSealed):
		passwordWriteJSONError(w, "Tenant barrier is sealed", http.StatusServiceUnavailable)
	case errors.Is(err, seal.ErrTenantNotFound):
		passwordWriteJSONError(w, "Tenant not found", http.StatusNotFound)
	case errors.Is(err, staticpw.ErrNotConfigured):
		passwordWriteJSONError(w, "Password store not configured", http.StatusServiceUnavailable)
	case errors.Is(err, staticpw.ErrInvalidUserID):
		passwordWriteJSONError(w, "Invalid user identity", http.StatusBadRequest)
	case errors.Is(err, staticpw.ErrNotOwner):
		passwordWriteJSONError(w, "Not the owner of this password", http.StatusForbidden)
	case errors.Is(err, staticpw.ErrInvalidScope):
		passwordWriteJSONError(w, "Invalid scope", http.StatusBadRequest)
	default:
		passwordWriteJSONError(w, "Failed to access password store", http.StatusInternalServerError)
	}
}

// passwordWriteJSONError writes an error response in the standard JSON format.
func passwordWriteJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := map[string]string{"error": message}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		return
	}
}
