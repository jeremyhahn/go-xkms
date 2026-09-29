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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// User management HTTP handlers. xkms presents its own user model; the backing
// store is the embedded qrdb node, reached through the injected XKMSService.
// The CLI (xkmsctl) and webui (xkey) drive these endpoints via the xkms SDK.

// createUserBody is the request payload for creating a user.
type createUserBody struct {
	Username             string `json:"username"`
	Email                string `json:"email"`
	WithoutEmailLoginKey bool   `json:"without_email_login_key"`
	DisplayName          string `json:"display_name"`
	Role                 string `json:"role"`
	TenantID             string `json:"tenant_id"`
}

// handleCreateUser handles POST /api/v1/users/.
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if s.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}
	svc := s.xkmsService
	var body createUserBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	resp, err := svc.CreateUser(r.Context(), &transport.CreateUserRequest{
		Username:             body.Username,
		Email:                body.Email,
		WithoutEmailLoginKey: body.WithoutEmailLoginKey,
		DisplayName:          body.DisplayName,
		Role:                 body.Role,
		TenantID:             body.TenantID,
	})
	if err != nil {
		// A missing login key is malformed CLIENT input, not a server fault.
		// Forwarding it as 500 tells the caller to retry something that can
		// never succeed and buries a fixable mistake in the server's error rate.
		if errors.Is(err, xkms.ErrEmailRequired) {
			writeError(w, err, http.StatusBadRequest)
			return
		}
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, resp.User, http.StatusCreated)
}

// handleListUsers handles GET /api/v1/users/.
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if s.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}
	svc := s.xkmsService
	resp, err := svc.ListUsers(r.Context())
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, resp, http.StatusOK)
}

// handleGetUser handles GET /api/v1/users/{username}.
func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	if s.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}
	svc := s.xkmsService
	username := chi.URLParam(r, "username")
	resp, err := svc.GetUser(r.Context(), username)
	if err != nil {
		writeError(w, err, http.StatusNotFound)
		return
	}
	writeJSON(w, resp.User, http.StatusOK)
}

// handleEnableUser handles POST /api/v1/users/{username}/enable. It
// requires users:enable (go-qrdb permission.UsersEnable) rather than the
// coarser users:update, matching gRPC's EnableUser RPC and MCP's
// user.enable method (go-xkms#1249).
func (s *Server) handleEnableUser(w http.ResponseWriter, r *http.Request) {
	s.setUserEnabled(w, r, true)
}

// handleDisableUser handles POST /api/v1/users/{username}/disable. It
// requires users:disable (go-qrdb permission.UsersDisable) for the same
// reason handleEnableUser requires users:enable (go-xkms#1249).
func (s *Server) handleDisableUser(w http.ResponseWriter, r *http.Request) {
	s.setUserEnabled(w, r, false)
}

// setUserEnabled performs the toggle and returns the updated user. The
// permission gate (users:enable or users:disable) is the caller's route
// decorator, not this helper, so this helper itself must never hold an
// authorization decision.
func (s *Server) setUserEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	if s.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}
	svc := s.xkmsService
	username := chi.URLParam(r, "username")
	var err error
	if enabled {
		err = svc.EnableUser(r.Context(), username)
	} else {
		err = svc.DisableUser(r.Context(), username)
	}
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	resp, err := svc.GetUser(r.Context(), username)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, resp.User, http.StatusOK)
}

// handleDeleteUser handles DELETE /api/v1/users/{username}.
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if s.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}
	svc := s.xkmsService
	username := chi.URLParam(r, "username")
	if err := svc.DeleteUser(r.Context(), username); err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"username": username, "status": "deleted"}, http.StatusOK)
}

// bindUserCertBody is the request payload for binding an mTLS certificate to a user.
type bindUserCertBody struct {
	Thumbprint   string `json:"thumbprint"`
	NotAfterUnix int64  `json:"not_after_unix"`
}

// handleBindUserCert handles POST /api/v1/users/{username}/cert-bindings.
func (s *Server) handleBindUserCert(w http.ResponseWriter, r *http.Request) {
	if s.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}
	svc := s.xkmsService
	username := chi.URLParam(r, "username")
	var body bindUserCertBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	if err := svc.BindUserCert(r.Context(), username, body.Thumbprint, body.NotAfterUnix); err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"username": username, "status": "bound"}, http.StatusOK)
}

// userCredentialItem mirrors the wire shape the SDK client expects for a
// user credential.
type userCredentialItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// handleListUserCredentials handles GET /api/v1/users/{username}/credentials.
func (s *Server) handleListUserCredentials(w http.ResponseWriter, r *http.Request) {
	if s.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}
	svc := s.xkmsService
	username := chi.URLParam(r, "username")
	resp, err := svc.ListUserCredentials(r.Context(), username)
	if err != nil {
		writeError(w, err, http.StatusNotFound)
		return
	}
	items := make([]userCredentialItem, 0, len(resp.Credentials))
	for _, c := range resp.Credentials {
		items = append(items, userCredentialItem{ID: c.ID, Name: c.DisplayName})
	}
	writeJSON(w, map[string]any{"credentials": items}, http.StatusOK)
}
