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

package services

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
)

// newTestExplorerConfig creates a valid ExplorerConfig with in-memory dependencies.
func newTestExplorerConfig() *ExplorerConfig {
	return &ExplorerConfig{
		Logger:       slog.Default(),
		TokenStore:   tokenstore.NewMemoryTokenStore(),
		Registry:     serverregistry.NewMemoryServerRegistry(),
		TrustStore:   storage.NewMemory(),
		HistoryStore: storage.NewMemory(),
	}
}

// newTestExplorerService creates an APIExplorerService with the given config,
// failing the test on error. It also sets a background context on the service.
func newTestExplorerService(t *testing.T, cfg *ExplorerConfig) *APIExplorerService {
	t.Helper()
	svc, err := NewAPIExplorerService(cfg)
	require.NoError(t, err)
	require.NotNil(t, svc)
	svc.SetContext(context.Background())
	return svc
}

// newTestServer creates an httptest.Server that echoes the Authorization header
// and request body back, along with a custom response header.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"method":        r.Method,
			"path":          r.URL.Path,
			"authorization": r.Header.Get("Authorization"),
			"content_type":  r.Header.Get("Content-Type"),
		}

		// Echo back body for non-GET requests.
		if r.Method != http.MethodGet && r.Body != nil {
			body, err := io.ReadAll(r.Body)
			if err == nil {
				resp["body"] = string(body)
			}
		}

		// Echo back custom header if present.
		if custom := r.Header.Get("X-Custom"); custom != "" {
			resp["x_custom"] = custom
		}

		w.Header().Set("X-Test-Header", "test-value")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		data, _ := json.Marshal(resp)
		w.Write(data)
	}))
}

// --- Constructor tests ---

func TestNewAPIExplorerService_Success(t *testing.T) {
	cfg := newTestExplorerConfig()
	svc, err := NewAPIExplorerService(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, svc)
	assert.NotNil(t, svc.log)
	assert.NotNil(t, svc.httpClient)
	assert.Equal(t, defaultHTTPTimeout, svc.httpClient.Timeout)
}

func TestNewAPIExplorerService_NilConfig(t *testing.T) {
	svc, err := NewAPIExplorerService(nil)
	assert.Nil(t, svc)
	assert.ErrorIs(t, err, ErrExplorerNilConfig)
}

func TestNewAPIExplorerService_NilTokenStore(t *testing.T) {
	cfg := newTestExplorerConfig()
	cfg.TokenStore = nil
	svc, err := NewAPIExplorerService(cfg)
	assert.Nil(t, svc)
	assert.ErrorIs(t, err, ErrExplorerNilTokenStore)
}

func TestNewAPIExplorerService_NilRegistry(t *testing.T) {
	cfg := newTestExplorerConfig()
	cfg.Registry = nil
	svc, err := NewAPIExplorerService(cfg)
	assert.Nil(t, svc)
	assert.ErrorIs(t, err, ErrExplorerNilRegistry)
}

func TestNewAPIExplorerService_NilTrustStore(t *testing.T) {
	cfg := newTestExplorerConfig()
	cfg.TrustStore = nil
	svc, err := NewAPIExplorerService(cfg)
	assert.Nil(t, svc)
	assert.ErrorIs(t, err, ErrExplorerNilTrustStore)
}

func TestNewAPIExplorerService_NilHistoryStore(t *testing.T) {
	cfg := newTestExplorerConfig()
	cfg.HistoryStore = nil
	svc, err := NewAPIExplorerService(cfg)
	assert.Nil(t, svc)
	assert.ErrorIs(t, err, ErrExplorerNilHistoryStore)
}

func TestNewAPIExplorerService_NilLogger(t *testing.T) {
	cfg := newTestExplorerConfig()
	cfg.Logger = nil
	svc, err := NewAPIExplorerService(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, svc)
	assert.NotNil(t, svc.log)
}

// --- Execute tests ---

func TestAPIExplorerService_Execute_GET_Success(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	cfg := newTestExplorerConfig()

	// Store a token for the test server.
	ctx := context.Background()
	err := cfg.TokenStore.Save(ctx, &tokenstore.TokenEntry{
		ServerURL: ts.URL,
		Token:     "test-jwt-token-123",
		TokenType: tokenstore.TypeBearer,
		Source:    tokenstore.SourceOIDC,
	})
	require.NoError(t, err)

	svc := newTestExplorerService(t, cfg)

	resp, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    ts.URL + "/api/v1/keys",
	})

	assert.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Status, "200")
	assert.NotEmpty(t, resp.Body)

	// Verify JWT was injected.
	var body map[string]interface{}
	err = json.Unmarshal([]byte(resp.Body), &body)
	require.NoError(t, err)
	assert.Equal(t, "Bearer test-jwt-token-123", body["authorization"])
	assert.Equal(t, "GET", body["method"])
	assert.Equal(t, "/api/v1/keys", body["path"])
}

func TestAPIExplorerService_Execute_POST_WithBody(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	reqBody := `{"algorithm":"EC","curve":"P-256"}`
	resp, err := svc.Execute(&ExplorerRequest{
		Method: "POST",
		URL:    ts.URL + "/api/v1/keys",
		Body:   reqBody,
	})

	assert.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]interface{}
	err = json.Unmarshal([]byte(resp.Body), &body)
	require.NoError(t, err)
	assert.Equal(t, "POST", body["method"])
	assert.Equal(t, reqBody, body["body"])
	assert.Equal(t, "application/json", body["content_type"])
}

func TestAPIExplorerService_Execute_CustomHeaders(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	resp, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    ts.URL + "/api/v1/status",
		Headers: map[string]string{
			"X-Custom": "custom-value",
		},
	})

	assert.NoError(t, err)
	require.NotNil(t, resp)

	var body map[string]interface{}
	err = json.Unmarshal([]byte(resp.Body), &body)
	require.NoError(t, err)
	assert.Equal(t, "custom-value", body["x_custom"])
}

func TestAPIExplorerService_Execute_NoToken(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	resp, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    ts.URL + "/api/v1/health",
	})

	assert.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify no Authorization header was sent.
	var body map[string]interface{}
	err = json.Unmarshal([]byte(resp.Body), &body)
	require.NoError(t, err)
	assert.Equal(t, "", body["authorization"])
}

func TestAPIExplorerService_Execute_InvalidMethod(t *testing.T) {
	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	resp, err := svc.Execute(&ExplorerRequest{
		Method: "INVALID",
		URL:    "https://example.com/api",
	})

	assert.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Error)
	assert.Contains(t, resp.Error, "invalid HTTP method")
}

func TestAPIExplorerService_Execute_EmptyURL(t *testing.T) {
	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	resp, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    "",
	})

	assert.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Error)
	assert.Contains(t, resp.Error, "invalid URL")
}

func TestAPIExplorerService_Execute_InvalidURL(t *testing.T) {
	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	resp, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    "not-a-valid-url",
	})

	assert.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Error)
	assert.Contains(t, resp.Error, "invalid URL")
}

func TestAPIExplorerService_Execute_NilRequest(t *testing.T) {
	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	resp, err := svc.Execute(nil)

	assert.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Error)
	assert.Contains(t, resp.Error, "request is required")
}

func TestAPIExplorerService_Execute_Closed(t *testing.T) {
	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	err := svc.Close()
	require.NoError(t, err)

	resp, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    "https://example.com/api",
	})

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrExplorerClosed)
}

func TestAPIExplorerService_Execute_RecordsHistory(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	_, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    ts.URL + "/api/v1/keys",
	})
	require.NoError(t, err)

	history, err := svc.GetHistory()
	require.NoError(t, err)
	require.Len(t, history, 1)

	entry := history[0]
	assert.NotEmpty(t, entry.ID)
	assert.False(t, entry.Timestamp.IsZero())
	assert.Equal(t, "GET", entry.Request.Method)
	assert.Contains(t, entry.Request.URL, "/api/v1/keys")
	assert.Equal(t, http.StatusOK, entry.Response.StatusCode)
}

func TestAPIExplorerService_Execute_ServerError(t *testing.T) {
	// Create a server that always returns 500.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer ts.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	resp, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    ts.URL + "/api/v1/keys",
	})

	// A 500 is a valid HTTP response, not an error.
	assert.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Contains(t, resp.Body, "internal server error")
}

func TestAPIExplorerService_Execute_DurationTracked(t *testing.T) {
	// Create a server with a small delay.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	resp, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    ts.URL + "/api/v1/health",
	})

	assert.NoError(t, err)
	require.NotNil(t, resp)
	// Duration should be at least 10ms (our sleep) but account for scheduling variance.
	assert.GreaterOrEqual(t, resp.DurationMs, int64(5))
}

func TestAPIExplorerService_Execute_ConnectionRefused(t *testing.T) {
	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	// Use a port that is not listening.
	resp, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    "http://127.0.0.1:1/api",
	})

	// Connection errors are now returned in the response, not as Go errors.
	assert.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Error)
	assert.Greater(t, resp.DurationMs, int64(-1))
}

func TestAPIExplorerService_Execute_ResponseHeaders(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	resp, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    ts.URL + "/api/v1/keys",
	})

	assert.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotNil(t, resp.Headers)
	assert.Equal(t, "test-value", resp.Headers["X-Test-Header"])
}

// --- ExplorerRequest.Validate tests ---

func TestExplorerRequest_Validate_Valid(t *testing.T) {
	tests := []struct {
		name   string
		method string
		url    string
	}{
		{"GET", "GET", "https://example.com/api"},
		{"POST", "POST", "https://example.com/api"},
		{"PUT", "PUT", "https://example.com/api"},
		{"DELETE", "DELETE", "https://example.com/api"},
		{"PATCH", "PATCH", "https://example.com/api"},
		{"HEAD", "HEAD", "https://example.com/api"},
		{"OPTIONS", "OPTIONS", "https://example.com/api"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &ExplorerRequest{Method: tc.method, URL: tc.url}
			assert.NoError(t, req.Validate())
		})
	}
}

func TestExplorerRequest_Validate_EmptyMethod(t *testing.T) {
	req := &ExplorerRequest{Method: "", URL: "https://example.com/api"}
	err := req.Validate()
	assert.ErrorIs(t, err, ErrExplorerInvalidMethod)
}

func TestExplorerRequest_Validate_InvalidMethod(t *testing.T) {
	req := &ExplorerRequest{Method: "TRACE", URL: "https://example.com/api"}
	err := req.Validate()
	assert.ErrorIs(t, err, ErrExplorerInvalidMethod)
}

func TestExplorerRequest_Validate_EmptyURL(t *testing.T) {
	req := &ExplorerRequest{Method: "GET", URL: ""}
	err := req.Validate()
	assert.ErrorIs(t, err, ErrExplorerInvalidURL)
}

func TestExplorerRequest_Validate_InvalidURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"no scheme", "example.com/api"},
		{"no host", "https:///path"},
		{"relative path", "/api/v1/keys"},
		{"just text", "not-a-url"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &ExplorerRequest{Method: "GET", URL: tc.url}
			err := req.Validate()
			assert.ErrorIs(t, err, ErrExplorerInvalidURL)
		})
	}
}

// --- History tests ---

func TestAPIExplorerService_GetHistory_Empty(t *testing.T) {
	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	history, err := svc.GetHistory()
	assert.NoError(t, err)
	assert.Empty(t, history)
}

func TestAPIExplorerService_GetHistory_Multiple(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	// Execute multiple requests with a small delay to ensure different timestamps.
	for i := 0; i < 3; i++ {
		_, err := svc.Execute(&ExplorerRequest{
			Method: "GET",
			URL:    ts.URL + "/api/v1/keys",
		})
		require.NoError(t, err)
		time.Sleep(2 * time.Millisecond)
	}

	history, err := svc.GetHistory()
	require.NoError(t, err)
	require.Len(t, history, 3)

	// Verify sorted by timestamp descending (most recent first).
	for i := 0; i < len(history)-1; i++ {
		assert.True(t, history[i].Timestamp.After(history[i+1].Timestamp) ||
			history[i].Timestamp.Equal(history[i+1].Timestamp),
			"history entries should be sorted by timestamp descending")
	}
}

func TestAPIExplorerService_GetHistory_Closed(t *testing.T) {
	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	err := svc.Close()
	require.NoError(t, err)

	history, err := svc.GetHistory()
	assert.Nil(t, history)
	assert.ErrorIs(t, err, ErrExplorerClosed)
}

func TestAPIExplorerService_ClearHistory(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	// Execute a few requests to populate history.
	for i := 0; i < 3; i++ {
		_, err := svc.Execute(&ExplorerRequest{
			Method: "GET",
			URL:    ts.URL + "/api/v1/keys",
		})
		require.NoError(t, err)
	}

	// Verify history has entries.
	history, err := svc.GetHistory()
	require.NoError(t, err)
	require.Len(t, history, 3)

	// Clear history.
	err = svc.ClearHistory()
	assert.NoError(t, err)

	// Verify history is empty.
	history, err = svc.GetHistory()
	assert.NoError(t, err)
	assert.Empty(t, history)
}

func TestAPIExplorerService_ClearHistory_Closed(t *testing.T) {
	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	err := svc.Close()
	require.NoError(t, err)

	err = svc.ClearHistory()
	assert.ErrorIs(t, err, ErrExplorerClosed)
}

func TestAPIExplorerService_DeleteHistoryEntry_Success(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	// Execute a request.
	_, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    ts.URL + "/api/v1/keys",
	})
	require.NoError(t, err)

	// Get history and grab the entry ID.
	history, err := svc.GetHistory()
	require.NoError(t, err)
	require.Len(t, history, 1)

	entryID := history[0].ID
	assert.NotEmpty(t, entryID)

	// Delete the entry.
	err = svc.DeleteHistoryEntry(entryID)
	assert.NoError(t, err)

	// Verify it was deleted.
	history, err = svc.GetHistory()
	assert.NoError(t, err)
	assert.Empty(t, history)
}

func TestAPIExplorerService_DeleteHistoryEntry_NotFound(t *testing.T) {
	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	err := svc.DeleteHistoryEntry("nonexistent-id")
	assert.ErrorIs(t, err, ErrExplorerHistoryNotFound)
}

func TestAPIExplorerService_DeleteHistoryEntry_Closed(t *testing.T) {
	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	err := svc.Close()
	require.NoError(t, err)

	err = svc.DeleteHistoryEntry("some-id")
	assert.ErrorIs(t, err, ErrExplorerClosed)
}

// --- Close tests ---

func TestAPIExplorerService_Close_Idempotent(t *testing.T) {
	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	err := svc.Close()
	assert.NoError(t, err)

	err = svc.Close()
	assert.NoError(t, err)

	// Verify all operations return ErrExplorerClosed after close.
	_, execErr := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    "https://example.com/api",
	})
	assert.ErrorIs(t, execErr, ErrExplorerClosed)

	_, histErr := svc.GetHistory()
	assert.ErrorIs(t, histErr, ErrExplorerClosed)

	clearErr := svc.ClearHistory()
	assert.ErrorIs(t, clearErr, ErrExplorerClosed)

	delErr := svc.DeleteHistoryEntry("id")
	assert.ErrorIs(t, delErr, ErrExplorerClosed)
}

// --- Concurrent access tests ---

func TestAPIExplorerService_ConcurrentAccess(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()

			// Execute a request.
			resp, err := svc.Execute(&ExplorerRequest{
				Method: "GET",
				URL:    ts.URL + "/api/v1/keys",
			})
			if err != nil {
				errs <- err
				return
			}
			if resp.StatusCode != http.StatusOK {
				errs <- errors.New("unexpected status code")
				return
			}

			// Read history concurrently.
			_, err = svc.GetHistory()
			if err != nil {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent access error: %v", err)
	}

	// Verify all requests were recorded.
	history, err := svc.GetHistory()
	require.NoError(t, err)
	assert.Len(t, history, goroutines)
}

// --- extractServerURL tests ---

func TestExtractServerURL_Valid(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"https with port", "https://xkms.example.com:8443/api/v1/keys", "https://xkms.example.com:8443"},
		{"https without port", "https://example.com/api", "https://example.com"},
		{"http localhost", "http://localhost:8080/health", "http://localhost:8080"},
		{"uppercase normalized", "HTTPS://EXAMPLE.COM/API", "https://example.com"},
		{"with path and query", "https://api.example.com:443/v1/keys?limit=10", "https://api.example.com:443"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := extractServerURL(tc.input)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractServerURL_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"no scheme", "example.com/api"},
		{"empty string", ""},
		{"just path", "/api/v1/keys"},
		{"relative", "api/v1/keys"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := extractServerURL(tc.input)
			assert.ErrorIs(t, err, ErrExplorerInvalidURL)
			assert.Empty(t, result)
		})
	}
}

// --- Error distinctness test ---

func TestAPIExplorerErrors_AreDistinct(t *testing.T) {
	allErrors := []error{
		ErrExplorerNilConfig,
		ErrExplorerClosed,
		ErrExplorerInvalidURL,
		ErrExplorerInvalidMethod,
		ErrExplorerRequestFailed,
		ErrExplorerNilTokenStore,
		ErrExplorerNilRegistry,
		ErrExplorerNilTrustStore,
		ErrExplorerNilHistoryStore,
		ErrExplorerInvalidRequest,
		ErrExplorerBodyTooLarge,
		ErrExplorerHistoryNotFound,
		ErrExplorerTokenListFailed,
	}

	// Verify all errors are distinct from each other.
	seen := make(map[string]bool, len(allErrors))
	for _, err := range allErrors {
		msg := err.Error()
		assert.False(t, seen[msg], "duplicate error message: %s", msg)
		seen[msg] = true
	}

	// Verify all errors have the api_explorer prefix.
	for _, err := range allErrors {
		assert.True(t, strings.HasPrefix(err.Error(), "api_explorer:"),
			"error should have api_explorer prefix: %s", err.Error())
	}
}

// --- Additional edge case tests ---

func TestAPIExplorerService_Execute_AllHTTPMethods(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		data, _ := json.Marshal(map[string]string{"method": r.Method})
		w.Write(data)
	}))
	defer ts.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			resp, err := svc.Execute(&ExplorerRequest{
				Method: method,
				URL:    ts.URL + "/api",
			})
			assert.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

func TestAPIExplorerService_Execute_EmptyResponseBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	resp, err := svc.Execute(&ExplorerRequest{
		Method: "DELETE",
		URL:    ts.URL + "/api/v1/keys/abc",
	})

	assert.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Empty(t, resp.Body)
}

func TestAPIExplorerService_Execute_HeadersOverrideDefault(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		data, _ := json.Marshal(map[string]string{
			"content_type": r.Header.Get("Content-Type"),
		})
		w.Write(data)
	}))
	defer ts.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	// Custom headers should override the default Content-Type.
	resp, err := svc.Execute(&ExplorerRequest{
		Method: "POST",
		URL:    ts.URL + "/api/v1/keys",
		Body:   `{"test": true}`,
		Headers: map[string]string{
			"Content-Type": "text/plain",
		},
	})

	assert.NoError(t, err)
	require.NotNil(t, resp)

	var body map[string]string
	err = json.Unmarshal([]byte(resp.Body), &body)
	require.NoError(t, err)
	assert.Equal(t, "text/plain", body["content_type"])
}

func TestAPIExplorerService_Execute_CancelledContext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	// Set a cancelled context on the service so the HTTP request fails.
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.
	svc.SetContext(cancelledCtx)

	resp, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    ts.URL + "/api",
	})

	// Cancelled context errors are now returned in the response, not as Go errors.
	assert.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Error)
}

func TestAPIExplorerService_Execute_WithServerRegistry(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	cfg := newTestExplorerConfig()

	// Register the test server in the registry.
	ctx := context.Background()
	err := cfg.Registry.Register(ctx, &serverregistry.ServerEntry{
		URL:           ts.URL,
		Name:          "test-server",
		Protocol:      serverregistry.ProtocolREST,
		CAFingerprint: "abc123",
	})
	require.NoError(t, err)

	svc := newTestExplorerService(t, cfg)

	resp, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    ts.URL + "/api/v1/keys",
	})

	assert.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAPIExplorerService_ClearHistory_Empty(t *testing.T) {
	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	// Clearing empty history should succeed.
	err := svc.ClearHistory()
	assert.NoError(t, err)
}

func TestAPIExplorerService_Execute_MultipleHistoryEntries(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	// Execute GET.
	_, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    ts.URL + "/api/v1/keys",
	})
	require.NoError(t, err)

	// Execute POST.
	_, err = svc.Execute(&ExplorerRequest{
		Method: "POST",
		URL:    ts.URL + "/api/v1/keys",
		Body:   `{"algorithm":"RSA"}`,
	})
	require.NoError(t, err)

	history, err := svc.GetHistory()
	require.NoError(t, err)
	assert.Len(t, history, 2)

	// Both entries should have unique IDs.
	assert.NotEqual(t, history[0].ID, history[1].ID)
}

func TestAPIExplorerService_Execute_FailedRequestRecordsHistory(t *testing.T) {
	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	// Request to unreachable server.
	resp, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    "http://127.0.0.1:1/api",
	})

	// Connection errors are now returned in the response, not as Go errors.
	assert.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Error)

	// The failed request should still be recorded in history.
	history, err := svc.GetHistory()
	require.NoError(t, err)
	require.Len(t, history, 1)

	entry := history[0]
	assert.NotEmpty(t, entry.Response.Error)
	assert.Equal(t, "GET", entry.Request.Method)
}

// --- ListAvailableTokens tests ---

func TestAPIExplorerListAvailableTokens_Empty(t *testing.T) {
	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	tokens := svc.ListAvailableTokens()
	assert.Empty(t, tokens)
}

func TestAPIExplorerListAvailableTokens_FromTokenStore(t *testing.T) {
	cfg := newTestExplorerConfig()

	ctx := context.Background()

	// Save a FIDO2 token.
	err := cfg.TokenStore.Save(ctx, &tokenstore.TokenEntry{
		ServerURL: "https://server-a.example.com:8443",
		Token:     "fido2-jwt-abc",
		TokenType: tokenstore.TypeBearer,
		Source:    tokenstore.SourceFIDO2,
		Subject:   "user@example.com",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)

	// Save a bootstrap token.
	err = cfg.TokenStore.Save(ctx, &tokenstore.TokenEntry{
		ServerURL: "https://server-b.example.com:8443",
		Token:     "bootstrap-jwt-xyz",
		TokenType: tokenstore.TypeBearer,
		Source:    tokenstore.SourceBootstrap,
	})
	require.NoError(t, err)

	svc := newTestExplorerService(t, cfg)

	tokens := svc.ListAvailableTokens()
	require.Len(t, tokens, 2)

	// Tokens should be sorted by source then label.
	// "bootstrap" < "fido2" alphabetically.
	assert.Equal(t, "bootstrap", tokens[0].Source)
	assert.Equal(t, "fido2", tokens[1].Source)

	// Verify the bootstrap token fields.
	assert.Equal(t, "ts:https://server-b.example.com:8443", tokens[0].ID)
	assert.Equal(t, "bootstrap-jwt-xyz", tokens[0].Token)
	assert.Contains(t, tokens[0].Label, "bootstrap")
	assert.Contains(t, tokens[0].Label, "server-b.example.com")
	assert.Empty(t, tokens[0].ExpiresAt)
	assert.False(t, tokens[0].IsExpired)

	// Verify the FIDO2 token fields.
	assert.Equal(t, "ts:https://server-a.example.com:8443", tokens[1].ID)
	assert.Equal(t, "fido2-jwt-abc", tokens[1].Token)
	assert.Contains(t, tokens[1].Label, "fido2")
	assert.Contains(t, tokens[1].Label, "user@example.com")
	assert.NotEmpty(t, tokens[1].ExpiresAt)
	assert.False(t, tokens[1].IsExpired)
}

func TestAPIExplorerListAvailableTokens_Closed(t *testing.T) {
	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	err := svc.Close()
	require.NoError(t, err)

	tokens := svc.ListAvailableTokens()
	assert.Nil(t, tokens)
}

func TestAPIExplorerListAvailableTokens_NilOIDCService(t *testing.T) {
	cfg := newTestExplorerConfig()
	// OIDCService is nil by default in newTestExplorerConfig.
	assert.Nil(t, cfg.OIDCService)

	ctx := context.Background()

	// Save a token so the list is not empty.
	err := cfg.TokenStore.Save(ctx, &tokenstore.TokenEntry{
		ServerURL: "https://xkms.local:8443",
		Token:     "some-jwt",
		TokenType: tokenstore.TypeBearer,
		Source:    tokenstore.SourceFIDO2,
	})
	require.NoError(t, err)

	svc := newTestExplorerService(t, cfg)

	// Should work without panicking even though OIDCService is nil.
	tokens := svc.ListAvailableTokens()
	require.Len(t, tokens, 1)
	assert.Equal(t, "fido2", tokens[0].Source)
	assert.Equal(t, "some-jwt", tokens[0].Token)
	assert.Nil(t, svc.oidcService)
}
