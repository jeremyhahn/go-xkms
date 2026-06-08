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

// shareFakeServer is a compact, in-memory implementation of the share-store
// HTTP API exercised by the SDK REST ShareService client. It stands in for the
// former pkg/sharestore-backed handlers (now hosted in the go-qrdb node) so
// these tests can validate the client's request serialization and
// response/error mapping against a real HTTP server without depending on any
// production share backend. Shares are keyed by server URL + group ID, matching
// the uniqueness contract enforced by the production store.
type shareFakeServer struct {
	shares map[string]*transport.ShareInfo
}

func newShareFakeServer() *shareFakeServer {
	return &shareFakeServer{shares: make(map[string]*transport.ShareInfo)}
}

// shareKey builds the composite uniqueness key for a stored share.
func shareKey(serverURL, groupID string) string {
	return serverURL + "\x00" + groupID
}

func (s *shareFakeServer) submitShare(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req transport.SubmitShareRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(t, w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.ServerURL == "" {
			writeErr(t, w, http.StatusBadRequest, "server_url is required")
			return
		}
		if req.GroupID == "" {
			writeErr(t, w, http.StatusBadRequest, "group_id is required")
			return
		}
		if len(req.ShareData) == 0 {
			writeErr(t, w, http.StatusBadRequest, "share_data is required")
			return
		}

		key := shareKey(req.ServerURL, req.GroupID)
		if _, ok := s.shares[key]; ok {
			writeErr(t, w, http.StatusConflict, "share already exists")
			return
		}

		s.shares[key] = &transport.ShareInfo{
			ServerURL:  req.ServerURL,
			GroupID:    req.GroupID,
			GroupName:  req.GroupName,
			ShareIndex: req.ShareIndex,
			ShareData:  req.ShareData,
			Purpose:    req.Purpose,
			ReceivedAt: time.Now().UTC(),
			TenantID:   req.TenantID,
		}

		writeJSON(t, w, http.StatusCreated, transport.SubmitShareResponse{Accepted: true})
	}
}

func (s *shareFakeServer) listShares(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		shares := make([]transport.ShareInfo, 0, len(s.shares))
		for _, sh := range s.shares {
			shares = append(shares, *sh)
		}
		writeJSON(t, w, http.StatusOK, transport.ListSharesResponse{Shares: shares})
	}
}

func (s *shareFakeServer) collectionStatus(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		groupID := chi.URLParam(r, "groupID")
		collected := 0
		for _, sh := range s.shares {
			if sh.GroupID == groupID {
				collected++
			}
		}
		writeJSON(t, w, http.StatusOK, transport.ShareCollectionStatus{
			GroupID:   groupID,
			Collected: collected,
			Ready:     false,
		})
	}
}

// router builds the chi router exposing the share-store HTTP API plus the
// /health endpoint required by Transport.Connect().
func (s *shareFakeServer) router(t *testing.T) http.Handler {
	r := chi.NewRouter()

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Route("/api/v1/shares", func(r chi.Router) {
		r.Post("/submit", s.submitShare(t))
		r.Get("/", s.listShares(t))
		r.Get("/status/{groupID}", s.collectionStatus(t))
	})

	return r
}

// newShareTestTransport creates a REST transport connected to an httptest
// server backed by an in-memory fake implementing the share-store HTTP API.
func newShareTestTransport(t *testing.T) (*Transport, *httptest.Server) {
	t.Helper()

	server := httptest.NewServer(newShareFakeServer().router(t))
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
