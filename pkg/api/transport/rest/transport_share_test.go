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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	restapi "github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/require"
)

// errDuplicateShare mirrors the embedded go-qrdb node's rejection of a share
// already submitted for the same server URL, group, and index.
var errDuplicateShare = errors.New("share already submitted")

// shareTestClient is an in-memory qrdbtransport.ShareClient mirroring the
// embedded go-qrdb node's share semantics, used to drive the REST share
// handlers through the SDK transport without a real node.
type shareTestClient struct {
	shares []qrdbtransport.ShareInfo
}

func (c *shareTestClient) SubmitShare(_ context.Context, req *qrdbtransport.SubmitShareRequest) (*qrdbtransport.SubmitShareResponse, error) {
	for _, s := range c.shares {
		if s.ServerURL == req.ServerURL && s.GroupID == req.GroupID && s.ShareIndex == req.ShareIndex {
			return nil, errDuplicateShare
		}
	}
	c.shares = append(c.shares, qrdbtransport.ShareInfo{
		ServerURL:  req.ServerURL,
		GroupID:    req.GroupID,
		GroupName:  req.GroupName,
		ShareIndex: req.ShareIndex,
		ShareData:  req.ShareData,
		Purpose:    req.Purpose,
		ReceivedAt: time.Now().UTC(),
		TenantID:   req.TenantID,
	})
	return &qrdbtransport.SubmitShareResponse{Accepted: true}, nil
}

func (c *shareTestClient) ListShares(_ context.Context) (*qrdbtransport.ListSharesResponse, error) {
	return &qrdbtransport.ListSharesResponse{Shares: c.shares}, nil
}

func (c *shareTestClient) GetShare(_ context.Context, serverURL, groupID string, shareIndex int) (*qrdbtransport.ShareInfo, error) {
	for i := range c.shares {
		s := c.shares[i]
		if s.ServerURL == serverURL && s.GroupID == groupID && s.ShareIndex == shareIndex {
			return &s, nil
		}
	}
	return nil, qrdbsdk.ErrCeremonyShareNotFound
}

func (c *shareTestClient) DeleteShare(_ context.Context, serverURL, groupID string, shareIndex int) error {
	for i := range c.shares {
		s := c.shares[i]
		if s.ServerURL == serverURL && s.GroupID == groupID && s.ShareIndex == shareIndex {
			c.shares = append(c.shares[:i], c.shares[i+1:]...)
			return nil
		}
	}
	return qrdbsdk.ErrCeremonyShareNotFound
}

func (c *shareTestClient) GetShareCollectionStatus(_ context.Context, groupID string) (*qrdbtransport.ShareCollectionStatus, error) {
	collected := 0
	for i := range c.shares {
		if c.shares[i].GroupID == groupID {
			collected++
		}
	}
	return &qrdbtransport.ShareCollectionStatus{
		GroupID:   groupID,
		Collected: collected,
	}, nil
}

// newShareTestTransport creates a REST transport connected to an httptest server
// backed by real share handlers wired to an in-memory share client through the
// XKMSService singleton, mirroring production wiring in pkg/server/server.go.
func newShareTestTransport(t *testing.T) (*Transport, *httptest.Server) {
	t.Helper()

	xkms.Reset()
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "mem",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	svc.SetShareClient(&shareTestClient{})
	t.Cleanup(func() { xkms.Reset() })

	handlers := restapi.NewShareHandlers(svc)

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
		// The share index is part of a share's identity, so these routes
		// must match pkg/api/rest/server.go exactly — a fixture missing
		// {shareIndex} would leave the handlers permanently unreachable.
		r.Get("/{serverURL}/{groupID}/{shareIndex}", handlers.GetShareHandler)
		r.Delete("/{serverURL}/{groupID}/{shareIndex}", handlers.DeleteShareHandler)
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

// TestTransport_GetShare_RoundTrip drives a share through submit and back out
// through GetShare. The server URL carries a scheme, "//", and a port, so the
// path escaping the client applies — and the unescaping the handler applies —
// are both exercised end to end.
func TestTransport_GetShare_RoundTrip(t *testing.T) {
	tr, _ := newShareTestTransport(t)
	ctx := context.Background()

	const serverURL = "https://kms1.example.com:8443"
	_, err := tr.SubmitShare(ctx, &transport.SubmitShareRequest{
		ServerURL:  serverURL,
		GroupID:    "grp-get",
		GroupName:  "ops",
		ShareIndex: 3,
		ShareData:  []byte("share-material"),
		Purpose:    "barrier",
	})
	require.NoError(t, err)

	info, err := tr.GetShare(ctx, serverURL, "grp-get", 3)
	require.NoError(t, err)
	require.NotNil(t, info)

	require.Equal(t, serverURL, info.ServerURL, "the escaped server URL must survive the round trip")
	require.Equal(t, "grp-get", info.GroupID)
	require.Equal(t, "ops", info.GroupName)
	require.Equal(t, 3, info.ShareIndex)
	require.Equal(t, "barrier", info.Purpose)
	require.False(t, info.ReceivedAt.IsZero(), "received_at must decode into a real time")
}

// TestTransport_GetShare_NeverReturnsShareData pins the security property:
// share material is write-only over the API. A share that was submitted with
// bytes must come back without them.
func TestTransport_GetShare_NeverReturnsShareData(t *testing.T) {
	tr, _ := newShareTestTransport(t)
	ctx := context.Background()

	const serverURL = "https://kms1.example.com:8443"
	_, err := tr.SubmitShare(ctx, &transport.SubmitShareRequest{
		ServerURL:  serverURL,
		GroupID:    "grp-secret",
		ShareIndex: 1,
		ShareData:  []byte("top-secret-share"),
	})
	require.NoError(t, err)

	info, err := tr.GetShare(ctx, serverURL, "grp-secret", 1)
	require.NoError(t, err)
	require.Nil(t, info.ShareData, "share material must never cross the wire on read")
}

func TestTransport_GetShare_NotFound(t *testing.T) {
	tr, _ := newShareTestTransport(t)

	_, err := tr.GetShare(context.Background(), "https://kms1.example.com:8443", "absent", 1)
	require.Error(t, err, "an unknown share must surface an error, not a zero value")
}

// TestTransport_DeleteShare_RoundTrip proves a deleted share stops resolving
// and drops out of the group's collected count.
func TestTransport_DeleteShare_RoundTrip(t *testing.T) {
	tr, _ := newShareTestTransport(t)
	ctx := context.Background()

	const serverURL = "https://kms1.example.com:8443"
	_, err := tr.SubmitShare(ctx, &transport.SubmitShareRequest{
		ServerURL:  serverURL,
		GroupID:    "grp-del",
		ShareIndex: 2,
		ShareData:  []byte("share-material"),
	})
	require.NoError(t, err)

	status, err := tr.GetShareCollectionStatus(ctx, "grp-del")
	require.NoError(t, err)
	require.Equal(t, 1, status.Collected)

	require.NoError(t, tr.DeleteShare(ctx, serverURL, "grp-del", 2))

	_, err = tr.GetShare(ctx, serverURL, "grp-del", 2)
	require.Error(t, err, "a deleted share must no longer resolve")

	status, err = tr.GetShareCollectionStatus(ctx, "grp-del")
	require.NoError(t, err)
	require.Equal(t, 0, status.Collected, "deleting a share must lower the collected count")
}

func TestTransport_DeleteShare_NotFound(t *testing.T) {
	tr, _ := newShareTestTransport(t)

	err := tr.DeleteShare(context.Background(), "https://kms1.example.com:8443", "absent", 1)
	require.Error(t, err, "deleting an unknown share must surface an error")
}

// TestTransport_ShareIndexDistinguishesShares proves the index is part of a
// share's identity: two shares differing only by index are addressed
// independently.
func TestTransport_ShareIndexDistinguishesShares(t *testing.T) {
	tr, _ := newShareTestTransport(t)
	ctx := context.Background()

	const serverURL = "https://kms1.example.com:8443"
	for _, idx := range []int{1, 2} {
		_, err := tr.SubmitShare(ctx, &transport.SubmitShareRequest{
			ServerURL:  serverURL,
			GroupID:    "grp-idx",
			ShareIndex: idx,
			ShareData:  []byte("share-material"),
		})
		require.NoError(t, err)
	}

	require.NoError(t, tr.DeleteShare(ctx, serverURL, "grp-idx", 1))

	_, err := tr.GetShare(ctx, serverURL, "grp-idx", 1)
	require.Error(t, err, "the deleted index must be gone")

	surviving, err := tr.GetShare(ctx, serverURL, "grp-idx", 2)
	require.NoError(t, err, "the other index must be untouched")
	require.Equal(t, 2, surviving.ShareIndex)
}
