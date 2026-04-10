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
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
)

// Typed errors for team handlers.
var (
	ErrTeamStoreNotConfigured = errors.New("team store not configured")
	ErrMissingTeamName        = errors.New("missing team name")
	ErrMissingMemberID        = errors.New("missing member_id")
)

// TeamHandlers provides REST handlers for team-based password sharing.
type TeamHandlers struct {
	teamStore staticpw.TeamStore
}

// NewTeamHandlers creates a new TeamHandlers instance. The teamStore
// must not be nil.
func NewTeamHandlers(teamStore staticpw.TeamStore) *TeamHandlers {
	return &TeamHandlers{teamStore: teamStore}
}

// CreateTeamHandler handles POST /api/v1/teams requests.
// It creates a new team with the authenticated user as the owner.
func (h *TeamHandlers) CreateTeamHandler(w http.ResponseWriter, r *http.Request) {
	if h.teamStore == nil {
		writeError(w, ErrTeamStoreNotConfigured, http.StatusServiceUnavailable)
		return
	}

	var req transport.CreateTeamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		writeError(w, ErrMissingTeamName, http.StatusBadRequest)
		return
	}

	// Determine owner from authenticated identity.
	ownerID := authenticatedUserID(r)

	team := &staticpw.TeamEntity{
		Name:     req.Name,
		TenantID: req.TenantID,
		OwnerID:  ownerID,
		Members:  req.Members,
	}

	if err := h.teamStore.Create(r.Context(), team); err != nil {
		if errors.Is(err, staticpw.ErrTeamExists) {
			writeError(w, err, http.StatusConflict)
			return
		}
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	resp := transport.CreateTeamResponse{
		Team: teamEntityToInfo(team),
	}
	writeJSON(w, resp, http.StatusCreated)
}

// ListTeamsHandler handles GET /api/v1/teams requests.
// It returns all teams with optional pagination and tenant filtering.
func (h *TeamHandlers) ListTeamsHandler(w http.ResponseWriter, r *http.Request) {
	if h.teamStore == nil {
		writeError(w, ErrTeamStoreNotConfigured, http.StatusServiceUnavailable)
		return
	}

	pr := transport.PageRequestFromQuery(r)
	tenantID := r.URL.Query().Get("tenant_id")

	var teams []*staticpw.TeamEntity
	var err error

	if tenantID != "" {
		teams, err = h.teamStore.ListByTenant(r.Context(), tenantID)
	} else {
		teams, err = h.teamStore.List(r.Context())
	}

	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	infos := make([]transport.TeamInfo, 0, len(teams))
	for _, t := range teams {
		infos = append(infos, teamEntityToInfo(t))
	}

	page, pagination := transport.ApplyPagination(infos, pr)

	resp := transport.ListTeamsResponse{
		Teams:      page,
		Pagination: pagination,
	}
	writeJSON(w, resp, http.StatusOK)
}

// GetTeamHandler handles GET /api/v1/teams/{name} requests.
func (h *TeamHandlers) GetTeamHandler(w http.ResponseWriter, r *http.Request) {
	if h.teamStore == nil {
		writeError(w, ErrTeamStoreNotConfigured, http.StatusServiceUnavailable)
		return
	}

	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, ErrMissingTeamName, http.StatusBadRequest)
		return
	}

	team, err := h.teamStore.Get(r.Context(), name)
	if err != nil {
		if errors.Is(err, staticpw.ErrTeamNotFound) {
			writeError(w, err, http.StatusNotFound)
			return
		}
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	resp := transport.GetTeamResponse{
		Team: teamEntityToInfo(team),
	}
	writeJSON(w, resp, http.StatusOK)
}

// DeleteTeamHandler handles DELETE /api/v1/teams/{name} requests.
func (h *TeamHandlers) DeleteTeamHandler(w http.ResponseWriter, r *http.Request) {
	if h.teamStore == nil {
		writeError(w, ErrTeamStoreNotConfigured, http.StatusServiceUnavailable)
		return
	}

	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, ErrMissingTeamName, http.StatusBadRequest)
		return
	}

	if err := h.teamStore.Delete(r.Context(), name); err != nil {
		if errors.Is(err, staticpw.ErrTeamNotFound) {
			writeError(w, err, http.StatusNotFound)
			return
		}
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// AddMemberHandler handles POST /api/v1/teams/{name}/members requests.
func (h *TeamHandlers) AddMemberHandler(w http.ResponseWriter, r *http.Request) {
	if h.teamStore == nil {
		writeError(w, ErrTeamStoreNotConfigured, http.StatusServiceUnavailable)
		return
	}

	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, ErrMissingTeamName, http.StatusBadRequest)
		return
	}

	var req transport.AddTeamMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.MemberID == "" {
		writeError(w, ErrMissingMemberID, http.StatusBadRequest)
		return
	}

	if err := h.teamStore.AddMember(r.Context(), name, req.MemberID); err != nil {
		if errors.Is(err, staticpw.ErrTeamNotFound) {
			writeError(w, err, http.StatusNotFound)
			return
		}
		if errors.Is(err, staticpw.ErrInvalidUserID) {
			writeError(w, err, http.StatusBadRequest)
			return
		}
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	// Return updated team.
	team, err := h.teamStore.Get(r.Context(), name)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	resp := transport.GetTeamResponse{
		Team: teamEntityToInfo(team),
	}
	writeJSON(w, resp, http.StatusOK)
}

// RemoveMemberHandler handles DELETE /api/v1/teams/{name}/members/{memberID} requests.
func (h *TeamHandlers) RemoveMemberHandler(w http.ResponseWriter, r *http.Request) {
	if h.teamStore == nil {
		writeError(w, ErrTeamStoreNotConfigured, http.StatusServiceUnavailable)
		return
	}

	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, ErrMissingTeamName, http.StatusBadRequest)
		return
	}

	memberID := chi.URLParam(r, "memberID")
	if memberID == "" {
		writeError(w, ErrMissingMemberID, http.StatusBadRequest)
		return
	}

	if err := h.teamStore.RemoveMember(r.Context(), name, memberID); err != nil {
		if errors.Is(err, staticpw.ErrTeamNotFound) {
			writeError(w, err, http.StatusNotFound)
			return
		}
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	// Return updated team.
	team, err := h.teamStore.Get(r.Context(), name)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	resp := transport.GetTeamResponse{
		Team: teamEntityToInfo(team),
	}
	writeJSON(w, resp, http.StatusOK)
}

// teamEntityToInfo converts a TeamEntity to a transport TeamInfo.
func teamEntityToInfo(t *staticpw.TeamEntity) transport.TeamInfo {
	members := t.Members
	if members == nil {
		members = []string{}
	}
	return transport.TeamInfo{
		Name:      t.Name,
		TenantID:  t.TenantID,
		OwnerID:   t.OwnerID,
		Members:   members,
		CreatedAt: t.CreatedAt,
		UpdatedAt: t.UpdatedAt,
	}
}

// authenticatedUserID extracts the user ID from the request context.
// Falls back to an empty string if no identity is present.
func authenticatedUserID(r *http.Request) string {
	// Check for identity in context (set by auth middleware).
	if id := r.Header.Get("X-User-ID"); id != "" {
		return id
	}
	return ""
}
