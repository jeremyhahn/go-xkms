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

// handlers_share_test.go covers the QUIC Shamir share endpoints: request
// routing (including the escaped server-URL segment), method and parameter
// validation, and the not-configured path taken when no go-qrdb node backs
// the service.
package quic

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// testShareServerURL is a server URL that must survive path escaping: it
// carries a scheme, "//", and a port, all of which would fragment a naive
// path split.
const testShareServerURL = "https://xkms.example.com:8443"

// sharePathFor builds the per-share request path the transport client emits.
func sharePathFor(serverURL, groupID string, shareIndex int) string {
	return "/api/v1/shares/" + url.PathEscape(serverURL) + "/" + url.PathEscape(groupID) + "/" +
		strconv.Itoa(shareIndex)
}

// TestShareRoutes_Registered proves the share endpoints are mounted at all.
// They were absent from the QUIC server entirely while the transport client
// already dialed them, so a missing mount is the exact regression to catch.
func TestShareRoutes_Registered(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	for _, path := range []string{
		"/api/v1/shares",
		"/api/v1/shares/submit",
		"/api/v1/shares/status/g1",
		sharePathFor(testShareServerURL, "g1", 2),
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.NotEqual(t, http.StatusNotFound, w.Code,
			"share route %q must be mounted", path)
	}
}

// TestHandleShareOperations_EscapedServerURLSurvivesRouting is the routing
// regression that matters: the server URL is escaped into a single path
// segment, and splitting the decoded path would tear its scheme and host
// apart into extra segments.
func TestHandleShareOperations_EscapedServerURLSurvivesRouting(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, sharePathFor(testShareServerURL, "group-1", 3), nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	// The share client is not configured in this harness, so a correctly
	// routed request reaches the service and reports that — a mis-split
	// path would have produced 404 "not found" instead.
	assert.Equal(t, http.StatusServiceUnavailable, w.Code,
		"a correctly parsed share path must reach the service layer")
}

func TestHandleShares_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPut, "/api/v1/shares", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleSubmitShare_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/shares/submit", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleSubmitShare_InvalidBody(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/shares/submit", strings.NewReader("{"))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleSubmitShare_RequiresGroupIDAndData(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	tests := []struct {
		name string
		req  transport.SubmitShareRequest
	}{
		{"missing group_id", transport.SubmitShareRequest{ShareData: []byte("s")}},
		{"missing share_data", transport.SubmitShareRequest{GroupID: "g1"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.req)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/shares/submit", bytes.NewReader(body))
			w := httptest.NewRecorder()
			server.handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestHandleShareOperations_InvalidShareIndex(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	path := "/api/v1/shares/" + url.PathEscape(testShareServerURL) + "/g1/not-a-number"
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleShareOperations_UnknownShapes(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	tests := []struct {
		name string
		path string
	}{
		{"too few segments", "/api/v1/shares/only-one"},
		{"too many segments", "/api/v1/shares/a/b/1/extra"},
		{"status without group", "/api/v1/shares/status"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			w := httptest.NewRecorder()
			server.handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusNotFound, w.Code)
		})
	}
}

func TestHandleShareOperations_MethodNotAllowedOnShare(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, sharePathFor(testShareServerURL, "g1", 1), nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleShareCollectionStatus_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/shares/status/g1", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// TestShareEndpoints_NotConfigured proves every share endpoint degrades to a
// 503 rather than a panic when no go-qrdb node backs the service.
func TestShareEndpoints_NotConfigured(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, err := json.Marshal(transport.SubmitShareRequest{GroupID: "g1", ShareData: []byte("s")})
	require.NoError(t, err)

	tests := []struct {
		name   string
		method string
		path   string
		body   []byte
	}{
		{"submit", http.MethodPost, "/api/v1/shares/submit", body},
		{"list", http.MethodGet, "/api/v1/shares", nil},
		{"get", http.MethodGet, sharePathFor(testShareServerURL, "g1", 1), nil},
		{"delete", http.MethodDelete, sharePathFor(testShareServerURL, "g1", 1), nil},
		{"status", http.MethodGet, "/api/v1/shares/status/g1", nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var req *http.Request
			if tc.body != nil {
				req = httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
			} else {
				req = httptest.NewRequest(tc.method, tc.path, nil)
			}
			w := httptest.NewRecorder()
			server.handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		})
	}
}

// TestWithoutShareData proves the response scrubber clears share material
// while preserving every metadata field. Share bytes are write-only over the
// API: leaking them here would hand a reader quorum material directly.
func TestWithoutShareData(t *testing.T) {
	received := time.Now().UTC()
	info := transport.ShareInfo{
		ServerURL:  testShareServerURL,
		GroupID:    "g1",
		GroupName:  "ops",
		ShareIndex: 4,
		ShareData:  []byte("secret-share-material"),
		Purpose:    "barrier",
		ReceivedAt: received,
		TenantID:   "t1",
	}

	got := withoutShareData(info)

	assert.Nil(t, got.ShareData, "share material must be cleared")
	assert.Equal(t, testShareServerURL, got.ServerURL)
	assert.Equal(t, "g1", got.GroupID)
	assert.Equal(t, "ops", got.GroupName)
	assert.Equal(t, 4, got.ShareIndex)
	assert.Equal(t, "barrier", got.Purpose)
	assert.Equal(t, received, got.ReceivedAt)
	assert.Equal(t, "t1", got.TenantID)

	assert.Equal(t, []byte("secret-share-material"), info.ShareData,
		"the caller's own value must not be mutated")
}

// TestRawRequestPath proves the path accessor prefers the escaped form, which
// is what keeps a server URL in one path segment.
func TestRawRequestPath(t *testing.T) {
	escaped := httptest.NewRequest(http.MethodGet, sharePathFor(testShareServerURL, "g1", 1), nil)
	assert.Contains(t, rawRequestPath(escaped), "%2F",
		"an escaped path must be reported in its escaped form")

	plain := httptest.NewRequest(http.MethodGet, "/api/v1/shares", nil)
	assert.Equal(t, "/api/v1/shares", rawRequestPath(plain),
		"a path with nothing to escape falls back to URL.Path")
}
