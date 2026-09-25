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
	"net/url"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/require"
)

// fakeShareClient is an in-memory implementation of qrdbtransport.ShareClient
// used to exercise the REST share handlers without an embedded go-qrdb node.
type fakeShareClient struct {
	shares    []qrdbtransport.ShareInfo
	threshold int
	total     int
}

func newFakeShareClient() *fakeShareClient {
	return &fakeShareClient{}
}

func (f *fakeShareClient) SubmitShare(_ context.Context, req *qrdbtransport.SubmitShareRequest) (*qrdbtransport.SubmitShareResponse, error) {
	f.shares = append(f.shares, qrdbtransport.ShareInfo{
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

func (f *fakeShareClient) ListShares(_ context.Context) (*qrdbtransport.ListSharesResponse, error) {
	return &qrdbtransport.ListSharesResponse{Shares: f.shares}, nil
}

func (f *fakeShareClient) GetShare(_ context.Context, serverURL, groupID string, shareIndex int) (*qrdbtransport.ShareInfo, error) {
	for i := range f.shares {
		s := f.shares[i]
		if s.ServerURL == serverURL && s.GroupID == groupID && s.ShareIndex == shareIndex {
			return &s, nil
		}
	}
	return nil, qrdbsdk.ErrCeremonyShareNotFound
}

func (f *fakeShareClient) DeleteShare(_ context.Context, serverURL, groupID string, shareIndex int) error {
	for i := range f.shares {
		s := f.shares[i]
		if s.ServerURL == serverURL && s.GroupID == groupID && s.ShareIndex == shareIndex {
			f.shares = append(f.shares[:i], f.shares[i+1:]...)
			return nil
		}
	}
	return qrdbsdk.ErrCeremonyShareNotFound
}

func (f *fakeShareClient) GetShareCollectionStatus(_ context.Context, groupID string) (*qrdbtransport.ShareCollectionStatus, error) {
	collected := 0
	for i := range f.shares {
		if f.shares[i].GroupID == groupID {
			collected++
		}
	}
	return &qrdbtransport.ShareCollectionStatus{
		GroupID:   groupID,
		Threshold: f.threshold,
		Total:     f.total,
		Collected: collected,
		Ready:     f.threshold > 0 && collected >= f.threshold,
	}, nil
}

// initShareServiceSingleton initializes the XKMSService singleton with a backend
// and (optionally) wires the given share client. Share state is owned by the
// embedded go-qrdb node; the handlers delegate to the injected service.
// Returns the initialized service so callers can pass it to NewShareHandlers.
func initShareServiceSingleton(t *testing.T, client qrdbtransport.ShareClient) *xkms.XKMSService {
	t.Helper()
	xkms.Reset()
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "mem",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	if client != nil {
		svc.SetShareClient(client)
	}
	t.Cleanup(func() { xkms.Reset() })
	return svc
}

// shareRouter mounts the share routes on a chi router.
func shareRouter(handlers *ShareHandlers) *chi.Mux {
	r := chi.NewRouter()
	r.Route("/shares", func(r chi.Router) {
		r.Post("/submit", handlers.SubmitShareHandler)
		r.Get("/", handlers.ListSharesHandler)
		r.Get("/status/{groupID}", handlers.GetShareCollectionStatusHandler)
		r.Get("/{serverURL}/{groupID}/{shareIndex}", handlers.GetShareHandler)
		r.Delete("/{serverURL}/{groupID}/{shareIndex}", handlers.DeleteShareHandler)
	})
	return r
}

// setupShareTestHandlers wires the XKMSService singleton with an in-memory share
// client and mounts the share routes on a chi router.
func setupShareTestHandlers(t *testing.T) (*fakeShareClient, *chi.Mux) {
	t.Helper()
	client := newFakeShareClient()
	svc := initShareServiceSingleton(t, client)
	return client, shareRouter(NewShareHandlers(svc))
}

// submitTestShare is a helper that submits a share through the router and
// returns the decoded shareStatusResponse.
func submitTestShare(t *testing.T, router *chi.Mux, serverURL, groupID, groupName string, shareIndex int, shareData []byte, purpose string) *shareStatusResponse {
	t.Helper()
	body := submitShareRequest{
		ServerURL:  serverURL,
		GroupID:    groupID,
		GroupName:  groupName,
		ShareIndex: shareIndex,
		ShareData:  shareData,
		Purpose:    purpose,
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/shares/submit", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("submitTestShare: expected status %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}
	var resp shareStatusResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	return &resp
}

func TestSubmitShareHandler_Success(t *testing.T) {
	client, router := setupShareTestHandlers(t)

	body := submitShareRequest{
		ServerURL:  "https://kms.example.com",
		GroupID:    "grp-001",
		GroupName:  "Barrier Custodians",
		ShareIndex: 1,
		ShareData:  []byte("secret-share-data"),
		Purpose:    "barrier",
		TenantID:   "tenant-a",
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/shares/submit", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}

	var resp shareStatusResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	if resp.ServerURL != "https://kms.example.com" {
		t.Errorf("expected server_url %q, got %q", "https://kms.example.com", resp.ServerURL)
	}
	if resp.GroupID != "grp-001" {
		t.Errorf("expected group_id %q, got %q", "grp-001", resp.GroupID)
	}
	if resp.GroupName != "Barrier Custodians" {
		t.Errorf("expected group_name %q, got %q", "Barrier Custodians", resp.GroupName)
	}
	if resp.ShareIndex != 1 {
		t.Errorf("expected share_index 1, got %d", resp.ShareIndex)
	}
	if resp.TenantID != "tenant-a" {
		t.Errorf("expected tenant_id %q, got %q", "tenant-a", resp.TenantID)
	}
	if resp.ReceivedAt == "" {
		t.Error("expected non-empty received_at")
	}
	if len(client.shares) != 1 {
		t.Fatalf("expected 1 share submitted to client, got %d", len(client.shares))
	}
}

func TestSubmitShareHandler_MissingServerURL(t *testing.T) {
	_, router := setupShareTestHandlers(t)
	expectShareError(t, router, http.MethodPost, "/shares/submit", submitShareRequest{
		GroupID:    "grp-001",
		ShareIndex: 1,
		ShareData:  []byte("data"),
	}, http.StatusBadRequest, ErrMissingShareServerURL.Error())
}

func TestSubmitShareHandler_MissingGroupID(t *testing.T) {
	_, router := setupShareTestHandlers(t)
	expectShareError(t, router, http.MethodPost, "/shares/submit", submitShareRequest{
		ServerURL:  "https://kms.example.com",
		ShareIndex: 1,
		ShareData:  []byte("data"),
	}, http.StatusBadRequest, ErrMissingShareGroupID.Error())
}

func TestSubmitShareHandler_MissingShareData(t *testing.T) {
	_, router := setupShareTestHandlers(t)
	expectShareError(t, router, http.MethodPost, "/shares/submit", submitShareRequest{
		ServerURL:  "https://kms.example.com",
		GroupID:    "grp-001",
		ShareIndex: 1,
	}, http.StatusBadRequest, ErrMissingShareData.Error())
}

func TestSubmitShareHandler_InvalidBody(t *testing.T) {
	_, router := setupShareTestHandlers(t)

	req := httptest.NewRequest(http.MethodPost, "/shares/submit", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	if errResp.Error != ErrInvalidRequest.Error() {
		t.Errorf("expected error %q, got %q", ErrInvalidRequest.Error(), errResp.Error)
	}
}

func TestSubmitShareHandler_NotConfigured(t *testing.T) {
	svc := initShareServiceSingleton(t, nil) // xkms initialized, share client not wired
	router := shareRouter(NewShareHandlers(svc))

	body := submitShareRequest{
		ServerURL:  "https://kms.example.com",
		GroupID:    "grp-001",
		ShareIndex: 1,
		ShareData:  []byte("data"),
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/shares/submit", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d: %s", http.StatusServiceUnavailable, rr.Code, rr.Body.String())
	}
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	if errResp.Error != ErrShareNotConfigured.Error() {
		t.Errorf("expected error %q, got %q", ErrShareNotConfigured.Error(), errResp.Error)
	}
}

func TestListSharesHandler_Empty(t *testing.T) {
	_, router := setupShareTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/shares/", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
	var resp listSharesResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	if len(resp.Shares) != 0 {
		t.Errorf("expected 0 shares, got %d", len(resp.Shares))
	}
}

func TestListSharesHandler_WithShares(t *testing.T) {
	_, router := setupShareTestHandlers(t)

	submitTestShare(t, router, "https://kms1.example.com", "grp-a", "Group A", 1, []byte("share-a"), "barrier")
	submitTestShare(t, router, "https://kms2.example.com", "grp-b", "Group B", 2, []byte("share-b"), "backup")

	req := httptest.NewRequest(http.MethodGet, "/shares/", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
	var resp listSharesResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	if len(resp.Shares) != 2 {
		t.Errorf("expected 2 shares, got %d", len(resp.Shares))
	}

	// Verify share data is not included in the response.
	if bytes.Contains(rr.Body.Bytes(), []byte("share_data")) {
		t.Error("response should not contain share_data field")
	}
}

func TestListSharesHandler_InvalidPageParam(t *testing.T) {
	_, router := setupShareTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/shares/?page=notanumber", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

func TestListSharesHandler_NotConfigured(t *testing.T) {
	svc := initShareServiceSingleton(t, nil)
	router := shareRouter(NewShareHandlers(svc))

	req := httptest.NewRequest(http.MethodGet, "/shares/", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d: %s", http.StatusServiceUnavailable, rr.Code, rr.Body.String())
	}
}

func TestGetShareHandler_Success(t *testing.T) {
	_, router := setupShareTestHandlers(t)

	submitTestShare(t, router, "https://kms.example.com", "grp-get", "Get Group", 3, []byte("share-data"), "signing-key")

	encodedURL := url.PathEscape("https://kms.example.com")
	req := httptest.NewRequest(http.MethodGet, "/shares/"+encodedURL+"/grp-get/3", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
	var resp shareStatusResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	if resp.ServerURL != "https://kms.example.com" {
		t.Errorf("expected server_url %q, got %q", "https://kms.example.com", resp.ServerURL)
	}
	if resp.GroupID != "grp-get" {
		t.Errorf("expected group_id %q, got %q", "grp-get", resp.GroupID)
	}
	if resp.ShareIndex != 3 {
		t.Errorf("expected share_index 3, got %d", resp.ShareIndex)
	}

	// Verify share_data is NOT in the response JSON.
	if bytes.Contains(rr.Body.Bytes(), []byte("share_data")) {
		t.Error("response should not contain share_data field")
	}
}

func TestGetShareHandler_NotFound(t *testing.T) {
	_, router := setupShareTestHandlers(t)

	encodedURL := url.PathEscape("https://kms.example.com")
	req := httptest.NewRequest(http.MethodGet, "/shares/"+encodedURL+"/nonexistent/1", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d: %s", http.StatusNotFound, rr.Code, rr.Body.String())
	}
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	if errResp.Error != qrdbsdk.ErrCeremonyShareNotFound.Error() {
		t.Errorf("expected error %q, got %q", qrdbsdk.ErrCeremonyShareNotFound.Error(), errResp.Error)
	}
}

func TestGetShareHandler_InvalidShareIndex(t *testing.T) {
	_, router := setupShareTestHandlers(t)

	encodedURL := url.PathEscape("https://kms.example.com")
	req := httptest.NewRequest(http.MethodGet, "/shares/"+encodedURL+"/grp-001/notanumber", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	if errResp.Error != ErrMissingShareIndex.Error() {
		t.Errorf("expected error %q, got %q", ErrMissingShareIndex.Error(), errResp.Error)
	}
}

func TestGetShareHandler_NotConfigured(t *testing.T) {
	svc := initShareServiceSingleton(t, nil)
	router := shareRouter(NewShareHandlers(svc))

	encodedURL := url.PathEscape("https://kms.example.com")
	req := httptest.NewRequest(http.MethodGet, "/shares/"+encodedURL+"/grp-001/1", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d: %s", http.StatusServiceUnavailable, rr.Code, rr.Body.String())
	}
}

func TestDeleteShareHandler_Success(t *testing.T) {
	client, router := setupShareTestHandlers(t)

	submitTestShare(t, router, "https://kms.example.com", "grp-del", "Del Group", 1, []byte("share"), "barrier")

	encodedURL := url.PathEscape("https://kms.example.com")
	req := httptest.NewRequest(http.MethodDelete, "/shares/"+encodedURL+"/grp-del/1", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d: %s", http.StatusNoContent, rr.Code, rr.Body.String())
	}
	if len(client.shares) != 0 {
		t.Errorf("expected share removed, got %d remaining", len(client.shares))
	}
}

func TestDeleteShareHandler_NotFound(t *testing.T) {
	_, router := setupShareTestHandlers(t)

	encodedURL := url.PathEscape("https://kms.example.com")
	req := httptest.NewRequest(http.MethodDelete, "/shares/"+encodedURL+"/missing/9", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d: %s", http.StatusNotFound, rr.Code, rr.Body.String())
	}
}

func TestDeleteShareHandler_NotConfigured(t *testing.T) {
	svc := initShareServiceSingleton(t, nil)
	router := shareRouter(NewShareHandlers(svc))

	encodedURL := url.PathEscape("https://kms.example.com")
	req := httptest.NewRequest(http.MethodDelete, "/shares/"+encodedURL+"/grp-001/1", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d: %s", http.StatusServiceUnavailable, rr.Code, rr.Body.String())
	}
}

func TestGetShareCollectionStatusHandler_Success(t *testing.T) {
	client, router := setupShareTestHandlers(t)
	client.threshold = 2
	client.total = 3

	submitTestShare(t, router, "https://kms.example.com", "grp-status", "Status Group", 1, []byte("s1"), "barrier")
	submitTestShare(t, router, "https://kms.example.com", "grp-status", "Status Group", 2, []byte("s2"), "barrier")

	req := httptest.NewRequest(http.MethodGet, "/shares/status/grp-status", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
	var resp shareCollectionStatusResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	if resp.GroupID != "grp-status" {
		t.Errorf("expected group_id %q, got %q", "grp-status", resp.GroupID)
	}
	if resp.Collected != 2 {
		t.Errorf("expected collected 2, got %d", resp.Collected)
	}
}

func TestGetShareCollectionStatusHandler_NotConfigured(t *testing.T) {
	svc := initShareServiceSingleton(t, nil)
	router := shareRouter(NewShareHandlers(svc))

	req := httptest.NewRequest(http.MethodGet, "/shares/status/grp-001", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d: %s", http.StatusServiceUnavailable, rr.Code, rr.Body.String())
	}
}

// expectShareError submits the given body and asserts the response status and
// error message.
func expectShareError(t *testing.T, router *chi.Mux, method, path string, body submitShareRequest, wantStatus int, wantErr string) {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != wantStatus {
		t.Fatalf("expected status %d, got %d: %s", wantStatus, rr.Code, rr.Body.String())
	}
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	if errResp.Error != wantErr {
		t.Errorf("expected error %q, got %q", wantErr, errResp.Error)
	}
}
