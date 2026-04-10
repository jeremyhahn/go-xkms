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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestTeamHandlers creates a TeamHandlers backed by in-memory storage.
func newTestTeamHandlers(t *testing.T) (*TeamHandlers, staticpw.TeamStore) {
	t.Helper()
	backend := storage.NewMemory()
	t.Cleanup(func() { require.NoError(t, backend.Close()) })

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	teamStore, err := staticpw.NewDAOTeamStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, teamStore.Close()) })

	return NewTeamHandlers(teamStore), teamStore
}

// chiContext creates a chi routing context with URL params.
func chiContext(r *http.Request, params map[string]string) *http.Request {
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestTeamHandlers_CreateTeam(t *testing.T) {
	handlers, _ := newTestTeamHandlers(t)

	body, _ := json.Marshal(transport.CreateTeamRequest{
		Name:     "engineering",
		TenantID: "t1",
		Members:  []string{"bob"},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "alice")
	w := httptest.NewRecorder()

	handlers.CreateTeamHandler(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp transport.CreateTeamResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "engineering", resp.Team.Name)
	assert.Equal(t, "alice", resp.Team.OwnerID)
	assert.Equal(t, "t1", resp.Team.TenantID)
	assert.Equal(t, []string{"bob"}, resp.Team.Members)
}

func TestTeamHandlers_CreateTeam_MissingName(t *testing.T) {
	handlers, _ := newTestTeamHandlers(t)

	body, _ := json.Marshal(transport.CreateTeamRequest{Name: ""})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handlers.CreateTeamHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTeamHandlers_CreateTeam_Duplicate(t *testing.T) {
	handlers, teamStore := newTestTeamHandlers(t)
	ctx := context.Background()

	require.NoError(t, teamStore.Create(ctx, &staticpw.TeamEntity{
		Name:    "ops",
		OwnerID: "alice",
	}))

	body, _ := json.Marshal(transport.CreateTeamRequest{Name: "ops"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "bob")
	w := httptest.NewRecorder()

	handlers.CreateTeamHandler(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestTeamHandlers_CreateTeam_InvalidJSON(t *testing.T) {
	handlers, _ := newTestTeamHandlers(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams", bytes.NewReader([]byte("{")))
	w := httptest.NewRecorder()

	handlers.CreateTeamHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTeamHandlers_CreateTeam_NilStore(t *testing.T) {
	handlers := NewTeamHandlers(nil)

	body, _ := json.Marshal(transport.CreateTeamRequest{Name: "test"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handlers.CreateTeamHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestTeamHandlers_ListTeams(t *testing.T) {
	handlers, teamStore := newTestTeamHandlers(t)
	ctx := context.Background()

	require.NoError(t, teamStore.Create(ctx, &staticpw.TeamEntity{
		Name: "alpha", OwnerID: "alice",
	}))
	require.NoError(t, teamStore.Create(ctx, &staticpw.TeamEntity{
		Name: "bravo", OwnerID: "bob",
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams", nil)
	w := httptest.NewRecorder()

	handlers.ListTeamsHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp transport.ListTeamsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Teams, 2)
}

func TestTeamHandlers_ListTeams_WithTenantFilter(t *testing.T) {
	handlers, teamStore := newTestTeamHandlers(t)
	ctx := context.Background()

	require.NoError(t, teamStore.Create(ctx, &staticpw.TeamEntity{
		Name: "team-a", TenantID: "t1", OwnerID: "alice",
	}))
	require.NoError(t, teamStore.Create(ctx, &staticpw.TeamEntity{
		Name: "team-b", TenantID: "t2", OwnerID: "bob",
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams?tenant_id=t1", nil)
	w := httptest.NewRecorder()

	handlers.ListTeamsHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp transport.ListTeamsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Teams, 1)
	assert.Equal(t, "team-a", resp.Teams[0].Name)
}

func TestTeamHandlers_ListTeams_WithPagination(t *testing.T) {
	handlers, teamStore := newTestTeamHandlers(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		name := string(rune('a'+i)) + "-team"
		require.NoError(t, teamStore.Create(ctx, &staticpw.TeamEntity{
			Name: name, OwnerID: "alice",
		}))
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams?page=1&page_size=2", nil)
	w := httptest.NewRecorder()

	handlers.ListTeamsHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp transport.ListTeamsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Teams, 2)
	assert.True(t, resp.Pagination.HasMore)
	assert.Equal(t, 5, resp.Pagination.Total)
}

func TestTeamHandlers_ListTeams_NilStore(t *testing.T) {
	handlers := NewTeamHandlers(nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams", nil)
	w := httptest.NewRecorder()

	handlers.ListTeamsHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestTeamHandlers_GetTeam(t *testing.T) {
	handlers, teamStore := newTestTeamHandlers(t)
	ctx := context.Background()

	require.NoError(t, teamStore.Create(ctx, &staticpw.TeamEntity{
		Name: "ops", OwnerID: "alice", Members: []string{"bob"},
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams/ops", nil)
	req = chiContext(req, map[string]string{"name": "ops"})
	w := httptest.NewRecorder()

	handlers.GetTeamHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp transport.GetTeamResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "ops", resp.Team.Name)
	assert.Equal(t, "alice", resp.Team.OwnerID)
}

func TestTeamHandlers_GetTeam_NotFound(t *testing.T) {
	handlers, _ := newTestTeamHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams/ghost", nil)
	req = chiContext(req, map[string]string{"name": "ghost"})
	w := httptest.NewRecorder()

	handlers.GetTeamHandler(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestTeamHandlers_GetTeam_MissingName(t *testing.T) {
	handlers, _ := newTestTeamHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams/", nil)
	req = chiContext(req, map[string]string{"name": ""})
	w := httptest.NewRecorder()

	handlers.GetTeamHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTeamHandlers_GetTeam_NilStore(t *testing.T) {
	handlers := NewTeamHandlers(nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams/ops", nil)
	req = chiContext(req, map[string]string{"name": "ops"})
	w := httptest.NewRecorder()

	handlers.GetTeamHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestTeamHandlers_DeleteTeam(t *testing.T) {
	handlers, teamStore := newTestTeamHandlers(t)
	ctx := context.Background()

	require.NoError(t, teamStore.Create(ctx, &staticpw.TeamEntity{
		Name: "temp", OwnerID: "alice",
	}))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/teams/temp", nil)
	req = chiContext(req, map[string]string{"name": "temp"})
	w := httptest.NewRecorder()

	handlers.DeleteTeamHandler(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)

	// Verify deletion.
	_, err := teamStore.Get(ctx, "temp")
	assert.ErrorIs(t, err, staticpw.ErrTeamNotFound)
}

func TestTeamHandlers_DeleteTeam_NotFound(t *testing.T) {
	handlers, _ := newTestTeamHandlers(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/teams/ghost", nil)
	req = chiContext(req, map[string]string{"name": "ghost"})
	w := httptest.NewRecorder()

	handlers.DeleteTeamHandler(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestTeamHandlers_DeleteTeam_MissingName(t *testing.T) {
	handlers, _ := newTestTeamHandlers(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/teams/", nil)
	req = chiContext(req, map[string]string{"name": ""})
	w := httptest.NewRecorder()

	handlers.DeleteTeamHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTeamHandlers_DeleteTeam_NilStore(t *testing.T) {
	handlers := NewTeamHandlers(nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/teams/ops", nil)
	req = chiContext(req, map[string]string{"name": "ops"})
	w := httptest.NewRecorder()

	handlers.DeleteTeamHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestTeamHandlers_AddMember(t *testing.T) {
	handlers, teamStore := newTestTeamHandlers(t)
	ctx := context.Background()

	require.NoError(t, teamStore.Create(ctx, &staticpw.TeamEntity{
		Name: "dev", OwnerID: "alice",
	}))

	body, _ := json.Marshal(transport.AddTeamMemberRequest{MemberID: "bob"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams/dev/members", bytes.NewReader(body))
	req = chiContext(req, map[string]string{"name": "dev"})
	w := httptest.NewRecorder()

	handlers.AddMemberHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp transport.GetTeamResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, resp.Team.Members, "bob")
}

func TestTeamHandlers_AddMember_MissingMemberID(t *testing.T) {
	handlers, teamStore := newTestTeamHandlers(t)
	ctx := context.Background()

	require.NoError(t, teamStore.Create(ctx, &staticpw.TeamEntity{
		Name: "dev", OwnerID: "alice",
	}))

	body, _ := json.Marshal(transport.AddTeamMemberRequest{MemberID: ""})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams/dev/members", bytes.NewReader(body))
	req = chiContext(req, map[string]string{"name": "dev"})
	w := httptest.NewRecorder()

	handlers.AddMemberHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTeamHandlers_AddMember_TeamNotFound(t *testing.T) {
	handlers, _ := newTestTeamHandlers(t)

	body, _ := json.Marshal(transport.AddTeamMemberRequest{MemberID: "bob"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams/ghost/members", bytes.NewReader(body))
	req = chiContext(req, map[string]string{"name": "ghost"})
	w := httptest.NewRecorder()

	handlers.AddMemberHandler(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestTeamHandlers_AddMember_InvalidJSON(t *testing.T) {
	handlers, teamStore := newTestTeamHandlers(t)
	ctx := context.Background()

	require.NoError(t, teamStore.Create(ctx, &staticpw.TeamEntity{
		Name: "dev", OwnerID: "alice",
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams/dev/members", bytes.NewReader([]byte("{")))
	req = chiContext(req, map[string]string{"name": "dev"})
	w := httptest.NewRecorder()

	handlers.AddMemberHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTeamHandlers_AddMember_NilStore(t *testing.T) {
	handlers := NewTeamHandlers(nil)

	body, _ := json.Marshal(transport.AddTeamMemberRequest{MemberID: "bob"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams/dev/members", bytes.NewReader(body))
	req = chiContext(req, map[string]string{"name": "dev"})
	w := httptest.NewRecorder()

	handlers.AddMemberHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestTeamHandlers_RemoveMember(t *testing.T) {
	handlers, teamStore := newTestTeamHandlers(t)
	ctx := context.Background()

	require.NoError(t, teamStore.Create(ctx, &staticpw.TeamEntity{
		Name: "dev", OwnerID: "alice", Members: []string{"bob", "charlie"},
	}))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/teams/dev/members/bob", nil)
	req = chiContext(req, map[string]string{"name": "dev", "memberID": "bob"})
	w := httptest.NewRecorder()

	handlers.RemoveMemberHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp transport.GetTeamResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotContains(t, resp.Team.Members, "bob")
	assert.Contains(t, resp.Team.Members, "charlie")
}

func TestTeamHandlers_RemoveMember_TeamNotFound(t *testing.T) {
	handlers, _ := newTestTeamHandlers(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/teams/ghost/members/bob", nil)
	req = chiContext(req, map[string]string{"name": "ghost", "memberID": "bob"})
	w := httptest.NewRecorder()

	handlers.RemoveMemberHandler(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestTeamHandlers_RemoveMember_MissingMemberID(t *testing.T) {
	handlers, teamStore := newTestTeamHandlers(t)
	ctx := context.Background()

	require.NoError(t, teamStore.Create(ctx, &staticpw.TeamEntity{
		Name: "dev", OwnerID: "alice",
	}))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/teams/dev/members/", nil)
	req = chiContext(req, map[string]string{"name": "dev", "memberID": ""})
	w := httptest.NewRecorder()

	handlers.RemoveMemberHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTeamHandlers_RemoveMember_NilStore(t *testing.T) {
	handlers := NewTeamHandlers(nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/teams/dev/members/bob", nil)
	req = chiContext(req, map[string]string{"name": "dev", "memberID": "bob"})
	w := httptest.NewRecorder()

	handlers.RemoveMemberHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}
