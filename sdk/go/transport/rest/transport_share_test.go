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
	"github.com/jeremyhahn/go-xkms/pkg/sharestore"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// newShareTestTransport creates a REST transport connected to an httptest
// server backed by real share handlers with an in-memory store.
func newShareTestTransport(t *testing.T) (*Transport, *httptest.Server) {
	t.Helper()

	store := sharestore.NewMemoryShareStore()
	handlers := restapi.NewShareHandlers(store)

	r := chi.NewRouter()

	// Health endpoint required by Connect().
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
			t.Logf("failed to encode health response: %v", err)
		}
	})

	r.Route("/api/v1/shares", func(r chi.Router) {
		r.Post("/submit", handlers.SubmitShareHandler)
		r.Get("/", handlers.ListSharesHandler)
		r.Get("/status/{groupID}", handlers.GetShareCollectionStatusHandler)
		r.Get("/{serverURL}/{groupID}", handlers.GetShareHandler)
		r.Delete("/{serverURL}/{groupID}", handlers.DeleteShareHandler)
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

func TestTransport_SubmitShare_Success(t *testing.T) {
	tr, _ := newShareTestTransport(t)

	resp, err := tr.SubmitShare(context.Background(), &transport.SubmitShareRequest{
		ServerURL:  "https://kms.example.com",
		GroupID:    "grp-001",
		GroupName:  "Test Group",
		ShareIndex: 1,
		ShareData:  []byte("secret-share-data"),
		Purpose:    "barrier",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestTransport_SubmitShare_MissingServerURL(t *testing.T) {
	tr, _ := newShareTestTransport(t)

	_, err := tr.SubmitShare(context.Background(), &transport.SubmitShareRequest{
		GroupID:   "grp-001",
		ShareData: []byte("data"),
	})
	if err == nil {
		t.Fatal("expected error for missing server_url")
	}
}

func TestTransport_SubmitShare_MissingGroupID(t *testing.T) {
	tr, _ := newShareTestTransport(t)

	_, err := tr.SubmitShare(context.Background(), &transport.SubmitShareRequest{
		ServerURL: "https://kms.example.com",
		ShareData: []byte("data"),
	})
	if err == nil {
		t.Fatal("expected error for missing group_id")
	}
}

func TestTransport_SubmitShare_MissingShareData(t *testing.T) {
	tr, _ := newShareTestTransport(t)

	_, err := tr.SubmitShare(context.Background(), &transport.SubmitShareRequest{
		ServerURL: "https://kms.example.com",
		GroupID:   "grp-001",
	})
	if err == nil {
		t.Fatal("expected error for missing share_data")
	}
}

func TestTransport_SubmitShare_Duplicate(t *testing.T) {
	tr, _ := newShareTestTransport(t)
	ctx := context.Background()

	req := &transport.SubmitShareRequest{
		ServerURL: "https://kms.example.com",
		GroupID:   "grp-dup",
		ShareData: []byte("share-data"),
	}

	_, err := tr.SubmitShare(ctx, req)
	if err != nil {
		t.Fatal(err)
	}

	_, err = tr.SubmitShare(ctx, req)
	if err == nil {
		t.Fatal("expected error for duplicate share")
	}
}

func TestTransport_ListShares_Empty(t *testing.T) {
	tr, _ := newShareTestTransport(t)

	resp, err := tr.ListShares(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if len(resp.Shares) != 0 {
		t.Errorf("expected 0 shares, got %d", len(resp.Shares))
	}
}

func TestTransport_ListShares_WithShares(t *testing.T) {
	tr, _ := newShareTestTransport(t)
	ctx := context.Background()

	_, err := tr.SubmitShare(ctx, &transport.SubmitShareRequest{
		ServerURL: "https://kms1.example.com",
		GroupID:   "grp-a",
		ShareData: []byte("share-a"),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = tr.SubmitShare(ctx, &transport.SubmitShareRequest{
		ServerURL: "https://kms2.example.com",
		GroupID:   "grp-b",
		ShareData: []byte("share-b"),
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := tr.ListShares(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if len(resp.Shares) != 2 {
		t.Errorf("expected 2 shares, got %d", len(resp.Shares))
	}
}

func TestTransport_GetShareCollectionStatus_Empty(t *testing.T) {
	tr, _ := newShareTestTransport(t)

	resp, err := tr.GetShareCollectionStatus(context.Background(), "grp-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.GroupID != "grp-001" {
		t.Errorf("expected group_id %q, got %q", "grp-001", resp.GroupID)
	}
	if resp.Collected != 0 {
		t.Errorf("expected collected 0, got %d", resp.Collected)
	}
}

func TestTransport_GetShareCollectionStatus_WithShares(t *testing.T) {
	tr, _ := newShareTestTransport(t)
	ctx := context.Background()

	_, err := tr.SubmitShare(ctx, &transport.SubmitShareRequest{
		ServerURL: "https://kms1.example.com",
		GroupID:   "grp-status",
		ShareData: []byte("share-1"),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = tr.SubmitShare(ctx, &transport.SubmitShareRequest{
		ServerURL: "https://kms2.example.com",
		GroupID:   "grp-status",
		ShareData: []byte("share-2"),
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := tr.GetShareCollectionStatus(ctx, "grp-status")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Collected != 2 {
		t.Errorf("expected collected 2, got %d", resp.Collected)
	}
}

func TestTransport_GetShareCollectionStatus_DifferentGroups(t *testing.T) {
	tr, _ := newShareTestTransport(t)
	ctx := context.Background()

	_, err := tr.SubmitShare(ctx, &transport.SubmitShareRequest{
		ServerURL: "https://kms1.example.com",
		GroupID:   "grp-mixed-a",
		ShareData: []byte("share-a"),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = tr.SubmitShare(ctx, &transport.SubmitShareRequest{
		ServerURL: "https://kms2.example.com",
		GroupID:   "grp-mixed-b",
		ShareData: []byte("share-b"),
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := tr.GetShareCollectionStatus(ctx, "grp-mixed-a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Collected != 1 {
		t.Errorf("expected collected 1 for grp-mixed-a, got %d", resp.Collected)
	}
}
