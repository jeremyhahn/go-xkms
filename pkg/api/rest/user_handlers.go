// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package rest

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-keychain/pkg/user"
)

// UserHandlers provides HTTP handlers for user management.
type UserHandlers struct {
	userStore user.Store
}

// NewUserHandlers creates a new UserHandlers instance.
func NewUserHandlers(userStore user.Store) *UserHandlers {
	return &UserHandlers{
		userStore: userStore,
	}
}

// BootstrapStatusResponse is the response for the bootstrap status endpoint.
type BootstrapStatusResponse struct {
	RequiresSetup bool   `json:"requires_setup"`
	UserCount     int    `json:"user_count"`
	Message       string `json:"message"`
}

// BootstrapStatusHandler returns whether the system requires initial setup.
// This endpoint is unauthenticated and is used by clients to determine if
// they should show the initial user registration flow.
func (h *UserHandlers) BootstrapStatusHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hasUsers, err := h.userStore.HasAnyUsers(ctx)
	if err != nil {
		userWriteJSONError(w, "Failed to check user status", http.StatusInternalServerError)
		return
	}

	count, err := h.userStore.Count(ctx)
	if err != nil {
		userWriteJSONError(w, "Failed to count users", http.StatusInternalServerError)
		return
	}

	resp := BootstrapStatusResponse{
		RequiresSetup: !hasUsers,
		UserCount:     count,
	}

	if !hasUsers {
		resp.Message = "No users configured. Please register the first administrator."
	} else {
		resp.Message = "System is configured and ready."
	}

	writeJSON(w, resp, http.StatusOK)
}

// UserListResponse is the response for listing users.
type UserListResponse struct {
	Users []UserInfo `json:"users"`
	Total int        `json:"total"`
}

// UserInfo is a summary of a user.
type UserInfo struct {
	ID              string `json:"id"`
	Username        string `json:"username"`
	DisplayName     string `json:"display_name"`
	Role            string `json:"role"`
	Enabled         bool   `json:"enabled"`
	CredentialCount int    `json:"credential_count"`
	CreatedAt       string `json:"created_at"`
	LastLoginAt     string `json:"last_login_at,omitempty"`
}

// ListUsersHandler returns a list of all users.
// This endpoint requires authentication.
func (h *UserHandlers) ListUsersHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	users, err := h.userStore.List(ctx)
	if err != nil {
		userWriteJSONError(w, "Failed to list users", http.StatusInternalServerError)
		return
	}

	userInfos := make([]UserInfo, len(users))
	for i, u := range users {
		userInfos[i] = UserInfo{
			ID:              encodeUserID(u.ID),
			Username:        u.Username,
			DisplayName:     u.DisplayName,
			Role:            string(u.Role),
			Enabled:         u.Enabled,
			CredentialCount: len(u.Credentials),
			CreatedAt:       u.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
		if u.LastLoginAt != nil {
			userInfos[i].LastLoginAt = u.LastLoginAt.Format("2006-01-02T15:04:05Z")
		}
	}

	resp := UserListResponse{
		Users: userInfos,
		Total: len(userInfos),
	}

	writeJSON(w, resp, http.StatusOK)
}

// UserDetailResponse is the detailed response for a single user.
type UserDetailResponse struct {
	ID          string           `json:"id"`
	Username    string           `json:"username"`
	DisplayName string           `json:"display_name"`
	Role        string           `json:"role"`
	Enabled     bool             `json:"enabled"`
	Credentials []CredentialInfo `json:"credentials"`
	CreatedAt   string           `json:"created_at"`
	LastLoginAt string           `json:"last_login_at,omitempty"`
}

// CredentialInfo is a summary of a WebAuthn credential.
type CredentialInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
}

// GetUserHandler returns details for a specific user.
// This endpoint requires authentication.
func (h *UserHandlers) GetUserHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user ID from URL path
	idParam := chi.URLParam(r, "id")
	if idParam == "" {
		userWriteJSONError(w, "User ID is required", http.StatusBadRequest)
		return
	}

	// Decode the base64url-encoded ID
	userID, err := decodeUserID(idParam)
	if err != nil {
		userWriteJSONError(w, "Invalid user ID format", http.StatusBadRequest)
		return
	}

	// Get user from store
	u, err := h.userStore.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			userWriteJSONError(w, "User not found", http.StatusNotFound)
			return
		}
		userWriteJSONError(w, "Failed to get user", http.StatusInternalServerError)
		return
	}

	// Build credential info list
	credentials := make([]CredentialInfo, len(u.Credentials))
	for i, cred := range u.Credentials {
		credentials[i] = CredentialInfo{
			ID:        encodeBase64URL(cred.ID),
			Name:      cred.Name,
			CreatedAt: cred.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
		if cred.LastUsedAt != nil {
			credentials[i].LastUsedAt = cred.LastUsedAt.Format("2006-01-02T15:04:05Z")
		}
	}

	resp := UserDetailResponse{
		ID:          encodeUserID(u.ID),
		Username:    u.Username,
		DisplayName: u.DisplayName,
		Role:        string(u.Role),
		Enabled:     u.Enabled,
		Credentials: credentials,
		CreatedAt:   u.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}
	if u.LastLoginAt != nil {
		resp.LastLoginAt = u.LastLoginAt.Format("2006-01-02T15:04:05Z")
	}

	writeJSON(w, resp, http.StatusOK)
}

// UpdateUserRequest is the request body for updating a user.
type UpdateUserRequest struct {
	DisplayName string `json:"display_name,omitempty"`
	Role        string `json:"role,omitempty"`
	Enabled     *bool  `json:"enabled,omitempty"`
}

// UpdateUserResponse is the response after updating a user.
type UpdateUserResponse struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	Enabled     bool   `json:"enabled"`
	Message     string `json:"message"`
}

// UpdateUserHandler updates a user's details.
// This endpoint requires authentication and admin role.
func (h *UserHandlers) UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user ID from URL path
	idParam := chi.URLParam(r, "id")
	if idParam == "" {
		userWriteJSONError(w, "User ID is required", http.StatusBadRequest)
		return
	}

	// Decode the base64url-encoded ID
	userID, err := decodeUserID(idParam)
	if err != nil {
		userWriteJSONError(w, "Invalid user ID format", http.StatusBadRequest)
		return
	}

	// Parse request body
	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		userWriteJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get existing user
	u, err := h.userStore.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			userWriteJSONError(w, "User not found", http.StatusNotFound)
			return
		}
		userWriteJSONError(w, "Failed to get user", http.StatusInternalServerError)
		return
	}

	// Apply updates
	if req.DisplayName != "" {
		u.DisplayName = req.DisplayName
	}
	if req.Role != "" {
		role := user.Role(req.Role)
		if !user.IsValidRole(role) {
			userWriteJSONError(w, "Invalid role. Must be one of: admin, operator, auditor, user, readonly, guest", http.StatusBadRequest)
			return
		}
		u.Role = role
	}
	if req.Enabled != nil {
		u.Enabled = *req.Enabled
	}

	// Save changes
	if err := h.userStore.Update(ctx, u); err != nil {
		userWriteJSONError(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	resp := UpdateUserResponse{
		ID:          encodeUserID(u.ID),
		Username:    u.Username,
		DisplayName: u.DisplayName,
		Role:        string(u.Role),
		Enabled:     u.Enabled,
		Message:     "User updated successfully",
	}

	writeJSON(w, resp, http.StatusOK)
}

// DeleteUserResponse is the response after deleting a user.
type DeleteUserResponse struct {
	Message string `json:"message"`
}

// DeleteUserHandler deletes a user.
// This endpoint requires authentication and admin role.
// Prevents deletion of the last admin to avoid lockout.
func (h *UserHandlers) DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user ID from URL path
	idParam := chi.URLParam(r, "id")
	if idParam == "" {
		userWriteJSONError(w, "User ID is required", http.StatusBadRequest)
		return
	}

	// Decode the base64url-encoded ID
	userID, err := decodeUserID(idParam)
	if err != nil {
		userWriteJSONError(w, "Invalid user ID format", http.StatusBadRequest)
		return
	}

	// Get the user to check their role
	u, err := h.userStore.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			userWriteJSONError(w, "User not found", http.StatusNotFound)
			return
		}
		userWriteJSONError(w, "Failed to get user", http.StatusInternalServerError)
		return
	}

	// If deleting an admin, check if this is the last admin
	if u.Role == user.RoleAdmin {
		adminCount, err := h.userStore.CountAdmins(ctx)
		if err != nil {
			userWriteJSONError(w, "Failed to count admins", http.StatusInternalServerError)
			return
		}
		if adminCount <= 1 {
			userWriteJSONError(w, "Cannot delete the last administrator", http.StatusForbidden)
			return
		}
	}

	// Delete the user
	if err := h.userStore.Delete(ctx, userID); err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			userWriteJSONError(w, "User not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, user.ErrLastAdmin) {
			userWriteJSONError(w, "Cannot delete the last administrator", http.StatusForbidden)
			return
		}
		userWriteJSONError(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	resp := DeleteUserResponse{
		Message: "User deleted successfully",
	}

	writeJSON(w, resp, http.StatusOK)
}

// Helper functions

func encodeUserID(id []byte) string {
	return encodeBase64URL(id)
}

func decodeUserID(encoded string) ([]byte, error) {
	// Add padding if necessary for standard base64 decoding
	// Our encodeBase64URL doesn't include padding, so we need to handle both cases
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		// Try with standard URL encoding (with padding)
		decoded, err = base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, err
		}
	}
	return decoded, nil
}

func userWriteJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := map[string]string{"error": message}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		return
	}
}

func encodeBase64URL(data []byte) string {
	// Use URL-safe base64 encoding without padding
	const base64URLChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	result := make([]byte, 0, (len(data)*8+5)/6)
	var val uint32
	var bits int
	for _, b := range data {
		val = (val << 8) | uint32(b)
		bits += 8
		for bits >= 6 {
			bits -= 6
			result = append(result, base64URLChars[(val>>bits)&0x3f])
		}
	}
	if bits > 0 {
		result = append(result, base64URLChars[(val<<(6-bits))&0x3f])
	}
	return string(result)
}
