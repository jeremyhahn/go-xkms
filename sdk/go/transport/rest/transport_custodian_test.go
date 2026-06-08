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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// custodianFakeServer is a compact, in-memory implementation of the custodian
// group HTTP API exercised by the SDK REST CustodianGroupService client. It
// stands in for the former pkg/custodian-backed handlers (now hosted in the
// go-qrdb node) so these tests can validate the client's request
// serialization and response/error mapping against a real HTTP server without
// depending on any production custodian backend.
type custodianFakeServer struct {
	groups map[string]*transport.CustodianGroupInfo
}

func newCustodianFakeServer() *custodianFakeServer {
	return &custodianFakeServer{groups: make(map[string]*transport.CustodianGroupInfo)}
}

// writeJSON writes a JSON body with the given status code.
func writeJSON(t *testing.T, w http.ResponseWriter, status int, v interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Logf("failed to encode response: %v", err)
	}
}

// writeErr writes a JSON error body matching the {"error": ...} shape the SDK
// client extracts for non-2xx responses.
func writeErr(t *testing.T, w http.ResponseWriter, status int, msg string) {
	t.Helper()
	writeJSON(t, w, status, map[string]string{"error": msg})
}

func (s *custodianFakeServer) createGroup(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req transport.CreateCustodianGroupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(t, w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.Name == "" {
			writeErr(t, w, http.StatusBadRequest, "name is required")
			return
		}
		if req.Threshold < 1 {
			writeErr(t, w, http.StatusBadRequest, "threshold must be at least 1")
			return
		}
		if req.Total < req.Threshold {
			writeErr(t, w, http.StatusBadRequest, "total must be greater than or equal to threshold")
			return
		}

		now := time.Now().UTC()
		group := &transport.CustodianGroupInfo{
			ID:        req.ID,
			TenantID:  req.TenantID,
			Name:      req.Name,
			Purpose:   req.Purpose,
			Threshold: req.Threshold,
			Total:     req.Total,
			Members:   []transport.CustodianMemberInfo{},
			CreatedAt: now,
			UpdatedAt: now,
		}
		s.groups[req.ID] = group

		writeJSON(t, w, http.StatusCreated, transport.CreateCustodianGroupResponse{Group: *group})
	}
}

func (s *custodianFakeServer) getGroup(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		group, ok := s.groups[chi.URLParam(r, "id")]
		if !ok {
			writeErr(t, w, http.StatusNotFound, "group not found")
			return
		}
		writeJSON(t, w, http.StatusOK, transport.GetCustodianGroupResponse{Group: *group})
	}
}

func (s *custodianFakeServer) listGroups(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		groups := make([]transport.CustodianGroupInfo, 0, len(s.groups))
		for _, g := range s.groups {
			groups = append(groups, *g)
		}
		writeJSON(t, w, http.StatusOK, transport.ListCustodianGroupsResponse{Groups: groups})
	}
}

func (s *custodianFakeServer) deleteGroup(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if _, ok := s.groups[id]; !ok {
			writeErr(t, w, http.StatusNotFound, "group not found")
			return
		}
		delete(s.groups, id)
		writeJSON(t, w, http.StatusNoContent, nil)
	}
}

func (s *custodianFakeServer) addMember(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		group, ok := s.groups[chi.URLParam(r, "id")]
		if !ok {
			writeErr(t, w, http.StatusNotFound, "group not found")
			return
		}

		var req transport.AddCustodianMemberRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(t, w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.UserID == "" {
			writeErr(t, w, http.StatusBadRequest, "user_id is required")
			return
		}
		for _, m := range group.Members {
			if m.UserID == req.UserID {
				writeErr(t, w, http.StatusConflict, "member already exists")
				return
			}
		}

		member := transport.CustodianMemberInfo{
			ShareIndex: len(group.Members) + 1,
			UserID:     req.UserID,
			Username:   req.Username,
			AssignedAt: time.Now().UTC(),
			Method:     req.Method,
		}
		group.Members = append(group.Members, member)
		group.UpdatedAt = time.Now().UTC()

		writeJSON(t, w, http.StatusCreated, transport.AddCustodianMemberResponse{Member: member})
	}
}

func (s *custodianFakeServer) removeMember(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		group, ok := s.groups[chi.URLParam(r, "id")]
		if !ok {
			writeErr(t, w, http.StatusNotFound, "group not found")
			return
		}

		userID := chi.URLParam(r, "userID")
		idx := -1
		for i, m := range group.Members {
			if m.UserID == userID {
				idx = i
				break
			}
		}
		if idx < 0 {
			writeErr(t, w, http.StatusNotFound, "member not found")
			return
		}

		group.Members = append(group.Members[:idx], group.Members[idx+1:]...)
		group.UpdatedAt = time.Now().UTC()
		writeJSON(t, w, http.StatusNoContent, nil)
	}
}

func (s *custodianFakeServer) distributeShares(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		group, ok := s.groups[chi.URLParam(r, "id")]
		if !ok {
			writeErr(t, w, http.StatusNotFound, "group not found")
			return
		}
		if len(group.Members) == 0 {
			writeErr(t, w, http.StatusBadRequest, "group has no members")
			return
		}
		writeJSON(t, w, http.StatusOK, transport.DistributeSharesResponse{Distributed: len(group.Members)})
	}
}

// router builds the chi router exposing the custodian-group HTTP API plus the
// /health endpoint required by Transport.Connect().
func (s *custodianFakeServer) router(t *testing.T) http.Handler {
	r := chi.NewRouter()

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Route("/api/v1/custodian/groups", func(r chi.Router) {
		r.Post("/", s.createGroup(t))
		r.Get("/", s.listGroups(t))
		r.Get("/{id}", s.getGroup(t))
		r.Delete("/{id}", s.deleteGroup(t))
		r.Post("/{id}/members", s.addMember(t))
		r.Delete("/{id}/members/{userID}", s.removeMember(t))
		r.Post("/{id}/distribute", s.distributeShares(t))
	})

	return r
}

// newCustodianTestTransport creates a REST transport connected to an httptest
// server backed by an in-memory fake implementing the custodian-group HTTP API.
func newCustodianTestTransport(t *testing.T) (*Transport, *httptest.Server) {
	t.Helper()

	server := httptest.NewServer(newCustodianFakeServer().router(t))
	t.Cleanup(server.Close)

	tr, err := NewWithConfig(&transport.Config{
		Address:    server.URL,
		TLSEnabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := tr.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}

	return tr, server
}

func TestTransport_CreateCustodianGroup_Success(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)

	resp, err := tr.CreateCustodianGroup(context.Background(), &transport.CreateCustodianGroupRequest{
		ID:        "grp-001",
		Name:      "Test Group",
		Purpose:   "barrier",
		Threshold: 2,
		Total:     3,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestTransport_CreateCustodianGroup_MissingName(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)

	_, err := tr.CreateCustodianGroup(context.Background(), &transport.CreateCustodianGroupRequest{
		ID:        "grp-no-name",
		Purpose:   "barrier",
		Threshold: 2,
		Total:     3,
	})
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestTransport_CreateCustodianGroup_InvalidThreshold(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)

	_, err := tr.CreateCustodianGroup(context.Background(), &transport.CreateCustodianGroupRequest{
		ID:        "grp-bad-threshold",
		Name:      "Bad Threshold",
		Purpose:   "barrier",
		Threshold: 0,
		Total:     3,
	})
	if err == nil {
		t.Fatal("expected error for invalid threshold")
	}
}

func TestTransport_CreateCustodianGroup_TotalLessThanThreshold(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)

	_, err := tr.CreateCustodianGroup(context.Background(), &transport.CreateCustodianGroupRequest{
		ID:        "grp-bad-total",
		Name:      "Bad Total",
		Purpose:   "barrier",
		Threshold: 3,
		Total:     2,
	})
	if err == nil {
		t.Fatal("expected error for total < threshold")
	}
}

func TestTransport_GetCustodianGroup_Success(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)
	ctx := context.Background()

	_, err := tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID:        "grp-get",
		Name:      "Get Group",
		Purpose:   "barrier",
		Threshold: 2,
		Total:     3,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := tr.GetCustodianGroup(ctx, "grp-get")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestTransport_GetCustodianGroup_NotFound(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)

	_, err := tr.GetCustodianGroup(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent group")
	}
}

func TestTransport_ListCustodianGroups_Empty(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)

	resp, err := tr.ListCustodianGroups(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestTransport_ListCustodianGroups_WithGroups(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)
	ctx := context.Background()

	_, err := tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID:        "grp-list-1",
		Name:      "Group One",
		Purpose:   "barrier",
		Threshold: 2,
		Total:     3,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID:        "grp-list-2",
		Name:      "Group Two",
		Purpose:   "backup",
		Threshold: 3,
		Total:     5,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := tr.ListCustodianGroups(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestTransport_DeleteCustodianGroup_Success(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)
	ctx := context.Background()

	_, err := tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID:        "grp-del",
		Name:      "Delete Group",
		Purpose:   "barrier",
		Threshold: 2,
		Total:     3,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = tr.DeleteCustodianGroup(ctx, "grp-del")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it was deleted.
	_, err = tr.GetCustodianGroup(ctx, "grp-del")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestTransport_DeleteCustodianGroup_NotFound(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)

	err := tr.DeleteCustodianGroup(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent group")
	}
}

func TestTransport_AddCustodianMember_Success(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)
	ctx := context.Background()

	_, err := tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID:        "grp-member",
		Name:      "Member Group",
		Purpose:   "barrier",
		Threshold: 2,
		Total:     3,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := tr.AddCustodianMember(ctx, &transport.AddCustodianMemberRequest{
		GroupID:  "grp-member",
		UserID:   "user-001",
		Username: "alice",
		Method:   "fido2",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestTransport_AddCustodianMember_GroupNotFound(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)

	_, err := tr.AddCustodianMember(context.Background(), &transport.AddCustodianMemberRequest{
		GroupID:  "nonexistent",
		UserID:   "user-001",
		Username: "alice",
		Method:   "fido2",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent group")
	}
}

func TestTransport_AddCustodianMember_MissingUserID(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)
	ctx := context.Background()

	_, err := tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID:        "grp-member-noid",
		Name:      "Member No ID Group",
		Purpose:   "barrier",
		Threshold: 2,
		Total:     3,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = tr.AddCustodianMember(ctx, &transport.AddCustodianMemberRequest{
		GroupID:  "grp-member-noid",
		Username: "alice",
		Method:   "fido2",
	})
	if err == nil {
		t.Fatal("expected error for missing user_id")
	}
}

func TestTransport_AddCustodianMember_Duplicate(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)
	ctx := context.Background()

	_, err := tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID:        "grp-member-dup",
		Name:      "Dup Member Group",
		Purpose:   "barrier",
		Threshold: 2,
		Total:     3,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = tr.AddCustodianMember(ctx, &transport.AddCustodianMemberRequest{
		GroupID:  "grp-member-dup",
		UserID:   "user-dup",
		Username: "alice",
		Method:   "fido2",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = tr.AddCustodianMember(ctx, &transport.AddCustodianMemberRequest{
		GroupID:  "grp-member-dup",
		UserID:   "user-dup",
		Username: "alice",
		Method:   "fido2",
	})
	if err == nil {
		t.Fatal("expected error for duplicate member")
	}
}

func TestTransport_RemoveCustodianMember_Success(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)
	ctx := context.Background()

	_, err := tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID:        "grp-rm-member",
		Name:      "Remove Member Group",
		Purpose:   "barrier",
		Threshold: 2,
		Total:     3,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = tr.AddCustodianMember(ctx, &transport.AddCustodianMemberRequest{
		GroupID:  "grp-rm-member",
		UserID:   "user-rm",
		Username: "removable",
		Method:   "manual",
	})
	if err != nil {
		t.Fatal(err)
	}

	err = tr.RemoveCustodianMember(ctx, &transport.RemoveCustodianMemberRequest{
		GroupID: "grp-rm-member",
		UserID:  "user-rm",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTransport_RemoveCustodianMember_NotFound(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)
	ctx := context.Background()

	_, err := tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID:        "grp-rm-nf",
		Name:      "Remove NF Group",
		Purpose:   "barrier",
		Threshold: 2,
		Total:     3,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = tr.RemoveCustodianMember(ctx, &transport.RemoveCustodianMemberRequest{
		GroupID: "grp-rm-nf",
		UserID:  "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent member")
	}
}

func TestTransport_RemoveCustodianMember_GroupNotFound(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)

	err := tr.RemoveCustodianMember(context.Background(), &transport.RemoveCustodianMemberRequest{
		GroupID: "nonexistent-group",
		UserID:  "user-001",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent group")
	}
}

func TestTransport_DistributeShares_Success(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)
	ctx := context.Background()

	_, err := tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID:        "grp-dist",
		Name:      "Distribute Group",
		Purpose:   "barrier",
		Threshold: 2,
		Total:     3,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = tr.AddCustodianMember(ctx, &transport.AddCustodianMemberRequest{
		GroupID:  "grp-dist",
		UserID:   "user-a",
		Username: "alice",
		Method:   "fido2",
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := tr.DistributeShares(ctx, &transport.DistributeSharesRequest{
		GroupID: "grp-dist",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Distributed != 1 {
		t.Errorf("expected distributed 1, got %d", resp.Distributed)
	}
}

func TestTransport_DistributeShares_GroupNotFound(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)

	_, err := tr.DistributeShares(context.Background(), &transport.DistributeSharesRequest{
		GroupID: "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent group")
	}
}

func TestTransport_DistributeShares_EmptyGroup(t *testing.T) {
	tr, _ := newCustodianTestTransport(t)
	ctx := context.Background()

	_, err := tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID:        "grp-dist-empty",
		Name:      "Empty Distribute Group",
		Purpose:   "barrier",
		Threshold: 2,
		Total:     3,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = tr.DistributeShares(ctx, &transport.DistributeSharesRequest{
		GroupID: "grp-dist-empty",
	})
	if err == nil {
		t.Fatal("expected error for empty group")
	}
}
