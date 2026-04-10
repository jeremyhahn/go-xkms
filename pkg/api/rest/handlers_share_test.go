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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/sharestore"
)

// setupShareTestHandlers creates ShareHandlers backed by an in-memory
// store and mounts the routes on a chi router for testing.
func setupShareTestHandlers(t *testing.T) (*ShareHandlers, *chi.Mux) {
	t.Helper()
	store := sharestore.NewMemoryShareStore()
	handlers := NewShareHandlers(store)
	r := chi.NewRouter()
	r.Route("/shares", func(r chi.Router) {
		r.Post("/submit", handlers.SubmitShareHandler)
		r.Get("/", handlers.ListSharesHandler)
		r.Get("/status/{groupID}", handlers.GetShareCollectionStatusHandler)
		r.Get("/{serverURL}/{groupID}/{shareIndex}", handlers.GetShareHandler)
		r.Delete("/{serverURL}/{groupID}/{shareIndex}", handlers.DeleteShareHandler)
	})
	return handlers, r
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
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/shares/submit", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("submitTestShare: expected status %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}
	var resp shareStatusResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return &resp
}

func TestSubmitShareHandler_Success(t *testing.T) {
	_, router := setupShareTestHandlers(t)

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
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/shares/submit", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}

	var resp shareStatusResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
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
	if resp.Purpose != "barrier" {
		t.Errorf("expected purpose %q, got %q", "barrier", resp.Purpose)
	}
	if resp.TenantID != "tenant-a" {
		t.Errorf("expected tenant_id %q, got %q", "tenant-a", resp.TenantID)
	}
	if resp.ReceivedAt == "" {
		t.Error("expected non-empty received_at")
	}
}

func TestSubmitShareHandler_MissingServerURL(t *testing.T) {
	_, router := setupShareTestHandlers(t)

	body := submitShareRequest{
		GroupID:    "grp-001",
		ShareIndex: 1,
		ShareData:  []byte("data"),
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/shares/submit", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error != ErrMissingShareServerURL.Error() {
		t.Errorf("expected error %q, got %q", ErrMissingShareServerURL.Error(), errResp.Error)
	}
}

func TestSubmitShareHandler_MissingGroupID(t *testing.T) {
	_, router := setupShareTestHandlers(t)

	body := submitShareRequest{
		ServerURL:  "https://kms.example.com",
		ShareIndex: 1,
		ShareData:  []byte("data"),
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/shares/submit", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error != ErrMissingShareGroupID.Error() {
		t.Errorf("expected error %q, got %q", ErrMissingShareGroupID.Error(), errResp.Error)
	}
}

func TestSubmitShareHandler_MissingShareData(t *testing.T) {
	_, router := setupShareTestHandlers(t)

	body := submitShareRequest{
		ServerURL:  "https://kms.example.com",
		GroupID:    "grp-001",
		ShareIndex: 1,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/shares/submit", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error != ErrMissingShareData.Error() {
		t.Errorf("expected error %q, got %q", ErrMissingShareData.Error(), errResp.Error)
	}
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
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error != ErrInvalidRequest.Error() {
		t.Errorf("expected error %q, got %q", ErrInvalidRequest.Error(), errResp.Error)
	}
}

func TestSubmitShareHandler_DuplicateShare(t *testing.T) {
	_, router := setupShareTestHandlers(t)

	// Submit share with index 1.
	submitTestShare(t, router, "https://kms.example.com", "grp-dup", "Group", 1, []byte("share-1"), "barrier")

	// Submit same server+group+index again -- must conflict.
	body := submitShareRequest{
		ServerURL:  "https://kms.example.com",
		GroupID:    "grp-dup",
		ShareIndex: 1,
		ShareData:  []byte("share-1-again"),
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/shares/submit", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected status %d, got %d: %s", http.StatusConflict, rr.Code, rr.Body.String())
	}
}

func TestSubmitShareHandler_DifferentShareIndex_NoConflict(t *testing.T) {
	_, router := setupShareTestHandlers(t)

	// Submit share with index 1.
	submitTestShare(t, router, "https://kms.example.com", "grp-multi", "Group", 1, []byte("share-1"), "barrier")

	// Submit same server+group but different index (2) -- must succeed.
	body := submitShareRequest{
		ServerURL:  "https://kms.example.com",
		GroupID:    "grp-multi",
		ShareIndex: 2,
		ShareData:  []byte("share-2"),
		Purpose:    "barrier",
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/shares/submit", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}

	var resp shareStatusResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.ShareIndex != 2 {
		t.Errorf("expected share_index 2, got %d", resp.ShareIndex)
	}
}

func TestSubmitShareHandler_NotConfigured(t *testing.T) {
	handlers := NewShareHandlers(nil)
	r := chi.NewRouter()
	r.Post("/shares/submit", handlers.SubmitShareHandler)

	body := submitShareRequest{
		ServerURL:  "https://kms.example.com",
		GroupID:    "grp-001",
		ShareIndex: 1,
		ShareData:  []byte("data"),
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/shares/submit", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d: %s", http.StatusServiceUnavailable, rr.Code, rr.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
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
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
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
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Shares) != 2 {
		t.Errorf("expected 2 shares, got %d", len(resp.Shares))
	}

	// Verify share data is not included in the response.
	raw := rr.Body.String()
	if bytes.Contains([]byte(raw), []byte("share_data")) {
		t.Error("response should not contain share_data field")
	}
}

func TestListSharesHandler_NotConfigured(t *testing.T) {
	handlers := NewShareHandlers(nil)
	r := chi.NewRouter()
	r.Get("/shares/", handlers.ListSharesHandler)

	req := httptest.NewRequest(http.MethodGet, "/shares/", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

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
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.ServerURL != "https://kms.example.com" {
		t.Errorf("expected server_url %q, got %q", "https://kms.example.com", resp.ServerURL)
	}
	if resp.GroupID != "grp-get" {
		t.Errorf("expected group_id %q, got %q", "grp-get", resp.GroupID)
	}
	if resp.GroupName != "Get Group" {
		t.Errorf("expected group_name %q, got %q", "Get Group", resp.GroupName)
	}
	if resp.ShareIndex != 3 {
		t.Errorf("expected share_index 3, got %d", resp.ShareIndex)
	}
	if resp.Purpose != "signing-key" {
		t.Errorf("expected purpose %q, got %q", "signing-key", resp.Purpose)
	}

	// Verify share_data is NOT in the response JSON.
	raw := rr.Body.String()
	if bytes.Contains([]byte(raw), []byte("share_data")) {
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
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error != sharestore.ErrShareNotFound.Error() {
		t.Errorf("expected error %q, got %q", sharestore.ErrShareNotFound.Error(), errResp.Error)
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
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error != ErrMissingShareIndex.Error() {
		t.Errorf("expected error %q, got %q", ErrMissingShareIndex.Error(), errResp.Error)
	}
}

func TestGetShareHandler_NotConfigured(t *testing.T) {
	handlers := NewShareHandlers(nil)
	r := chi.NewRouter()
	r.Get("/shares/{serverURL}/{groupID}/{shareIndex}", handlers.GetShareHandler)

	encodedURL := url.PathEscape("https://kms.example.com")
	req := httptest.NewRequest(http.MethodGet, "/shares/"+encodedURL+"/grp-001/1", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d: %s", http.StatusServiceUnavailable, rr.Code, rr.Body.String())
	}
}

func TestDeleteShareHandler_Success(t *testing.T) {
	_, router := setupShareTestHandlers(t)

	submitTestShare(t, router, "https://kms.example.com", "grp-del", "Del Group", 1, []byte("share"), "barrier")

	encodedURL := url.PathEscape("https://kms.example.com")
	req := httptest.NewRequest(http.MethodDelete, "/shares/"+encodedURL+"/grp-del/1", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d: %s", http.StatusNoContent, rr.Code, rr.Body.String())
	}

	// Verify the share is no longer retrievable.
	getReq := httptest.NewRequest(http.MethodGet, "/shares/"+encodedURL+"/grp-del/1", nil)
	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)

	if getRR.Code != http.StatusNotFound {
		t.Fatalf("expected GET after delete to return %d, got %d", http.StatusNotFound, getRR.Code)
	}
}

func TestDeleteShareHandler_NotFound(t *testing.T) {
	_, router := setupShareTestHandlers(t)

	encodedURL := url.PathEscape("https://kms.example.com")
	req := httptest.NewRequest(http.MethodDelete, "/shares/"+encodedURL+"/nonexistent/1", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d: %s", http.StatusNotFound, rr.Code, rr.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error != sharestore.ErrShareNotFound.Error() {
		t.Errorf("expected error %q, got %q", sharestore.ErrShareNotFound.Error(), errResp.Error)
	}
}

func TestDeleteShareHandler_InvalidShareIndex(t *testing.T) {
	_, router := setupShareTestHandlers(t)

	encodedURL := url.PathEscape("https://kms.example.com")
	req := httptest.NewRequest(http.MethodDelete, "/shares/"+encodedURL+"/grp-001/abc", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error != ErrMissingShareIndex.Error() {
		t.Errorf("expected error %q, got %q", ErrMissingShareIndex.Error(), errResp.Error)
	}
}

func TestDeleteShareHandler_NotConfigured(t *testing.T) {
	handlers := NewShareHandlers(nil)
	r := chi.NewRouter()
	r.Delete("/shares/{serverURL}/{groupID}/{shareIndex}", handlers.DeleteShareHandler)

	encodedURL := url.PathEscape("https://kms.example.com")
	req := httptest.NewRequest(http.MethodDelete, "/shares/"+encodedURL+"/grp-001/1", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d: %s", http.StatusServiceUnavailable, rr.Code, rr.Body.String())
	}
}

func TestShareHandlers_NilStore(t *testing.T) {
	handlers := NewShareHandlers(nil)
	r := chi.NewRouter()
	r.Route("/shares", func(r chi.Router) {
		r.Post("/submit", handlers.SubmitShareHandler)
		r.Get("/", handlers.ListSharesHandler)
		r.Get("/status/{groupID}", handlers.GetShareCollectionStatusHandler)
		r.Get("/{serverURL}/{groupID}/{shareIndex}", handlers.GetShareHandler)
		r.Delete("/{serverURL}/{groupID}/{shareIndex}", handlers.DeleteShareHandler)
	})

	encodedURL := url.PathEscape("https://kms.example.com")

	tests := []struct {
		name   string
		method string
		path   string
		body   []byte
	}{
		{
			name:   "SubmitShare",
			method: http.MethodPost,
			path:   "/shares/submit",
			body:   []byte(`{"server_url":"https://x","group_id":"g","share_data":"ZGF0YQ=="}`),
		},
		{
			name:   "ListShares",
			method: http.MethodGet,
			path:   "/shares/",
		},
		{
			name:   "GetShareCollectionStatus",
			method: http.MethodGet,
			path:   "/shares/status/grp-001",
		},
		{
			name:   "GetShare",
			method: http.MethodGet,
			path:   "/shares/" + encodedURL + "/grp-001/1",
		},
		{
			name:   "DeleteShare",
			method: http.MethodDelete,
			path:   "/shares/" + encodedURL + "/grp-001/1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.body != nil {
				req = httptest.NewRequest(tt.method, tt.path, bytes.NewReader(tt.body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(tt.method, tt.path, nil)
			}
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			if rr.Code != http.StatusServiceUnavailable {
				t.Errorf("expected status %d, got %d: %s", http.StatusServiceUnavailable, rr.Code, rr.Body.String())
			}

			var errResp ErrorResponse
			if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
				t.Fatal(err)
			}
			if errResp.Error != ErrShareNotConfigured.Error() {
				t.Errorf("expected error %q, got %q", ErrShareNotConfigured.Error(), errResp.Error)
			}
		})
	}
}

func TestGetShareCollectionStatusHandler_Empty(t *testing.T) {
	_, router := setupShareTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/shares/status/grp-001", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp shareCollectionStatusResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.GroupID != "grp-001" {
		t.Errorf("expected group_id %q, got %q", "grp-001", resp.GroupID)
	}
	if resp.Collected != 0 {
		t.Errorf("expected collected 0, got %d", resp.Collected)
	}
}

func TestGetShareCollectionStatusHandler_WithShares(t *testing.T) {
	_, router := setupShareTestHandlers(t)

	// Submit shares for the same group from different servers.
	submitTestShare(t, router, "https://kms1.example.com", "grp-status", "Group", 1, []byte("share-1"), "barrier")
	submitTestShare(t, router, "https://kms2.example.com", "grp-status", "Group", 2, []byte("share-2"), "barrier")
	// Submit a share for a different group (should not count).
	submitTestShare(t, router, "https://kms3.example.com", "other-grp", "Other", 1, []byte("share-3"), "backup")

	req := httptest.NewRequest(http.MethodGet, "/shares/status/grp-status", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp shareCollectionStatusResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.GroupID != "grp-status" {
		t.Errorf("expected group_id %q, got %q", "grp-status", resp.GroupID)
	}
	if resp.Collected != 2 {
		t.Errorf("expected collected 2, got %d", resp.Collected)
	}
}

func TestGetShareCollectionStatusHandler_NotConfigured(t *testing.T) {
	handlers := NewShareHandlers(nil)
	r := chi.NewRouter()
	r.Get("/shares/status/{groupID}", handlers.GetShareCollectionStatusHandler)

	req := httptest.NewRequest(http.MethodGet, "/shares/status/grp-001", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d: %s", http.StatusServiceUnavailable, rr.Code, rr.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error != ErrShareNotConfigured.Error() {
		t.Errorf("expected error %q, got %q", ErrShareNotConfigured.Error(), errResp.Error)
	}
}

func TestHandleShareError_MapsAllErrorTypes(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{
			name:           "ShareNotFound",
			err:            sharestore.ErrShareNotFound,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "ShareExists",
			err:            sharestore.ErrShareExists,
			expectedStatus: http.StatusConflict,
		},
		{
			name:           "InvalidServerURL",
			err:            sharestore.ErrInvalidServerURL,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "InvalidGroupID",
			err:            sharestore.ErrInvalidGroupID,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "EmptyShare",
			err:            sharestore.ErrEmptyShare,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "NilEntry",
			err:            sharestore.ErrNilEntry,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "StoreClosed",
			err:            sharestore.ErrStoreClosed,
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name:           "UnknownError",
			err:            errors.New("something unexpected"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			handleShareError(rr, tt.err)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

// Ensure the unused import is used.
var _ = fmt.Sprintf
