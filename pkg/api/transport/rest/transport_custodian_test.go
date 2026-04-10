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

	"github.com/go-chi/chi/v5"
	restapi "github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/custodian"
)

// newCustodianTestTransport creates a REST transport connected to an httptest
// server backed by real custodian handlers with an in-memory store.
func newCustodianTestTransport(t *testing.T) (*Transport, *httptest.Server) {
	t.Helper()

	store := custodian.NewMemoryStore()
	svc, err := custodian.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	handlers := restapi.NewCustodianHandlers(svc)

	r := chi.NewRouter()

	// Health endpoint required by Connect().
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
			t.Logf("failed to encode health response: %v", err)
		}
	})

	r.Route("/api/v1/custodian/groups", func(r chi.Router) {
		r.Post("/", handlers.CreateGroupHandler)
		r.Get("/", handlers.ListGroupsHandler)
		r.Get("/{id}", handlers.GetGroupHandler)
		r.Delete("/{id}", handlers.DeleteGroupHandler)
		r.Post("/{id}/members", handlers.AddMemberHandler)
		r.Delete("/{id}/members/{userID}", handlers.RemoveMemberHandler)
		r.Post("/{id}/distribute", handlers.DistributeSharesHandler)
	})

	server := httptest.NewServer(r)
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
