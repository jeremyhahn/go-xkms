// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Constructor tests ---

func TestNew_DefaultConfig(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	require.NotNil(t, tr)
}

func TestNew_WithAddress(t *testing.T) {
	tr, err := New(transport.WithAddress("localhost:8080"))
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8080", tr.baseURL)
}

func TestNew_InvalidOption(t *testing.T) {
	_, err := New(transport.WithAddress(""))
	require.Error(t, err)
}

func TestNewWithConfig_NilConfig(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	require.NotNil(t, tr)
}

func TestNewWithConfig_HTTPSPrefix(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "https://secure:443"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "https://secure:443", tr.baseURL)
}

func TestNewWithConfig_HTTPPrefix(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "http://plain:8080"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "http://plain:8080", tr.baseURL)
}

func TestNewWithConfig_TLSEnabled(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "host:443"
	cfg.TLSEnabled = true
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "https://host:443", tr.baseURL)
}

func TestNewWithConfig_TrailingSlash(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "http://host:8080/"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "http://host:8080", tr.baseURL)
}

// --- Close ---

func TestClose_NilClient(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.NoError(t, tr.Close())
	assert.False(t, tr.connected)
}

// --- Conn ---

func TestConn_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.Nil(t, tr.Conn())
}

// --- Config ---

func TestConfig(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "test:8080"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test:8080", tr.Config().Address)
}

// --- BaseURL ---

func TestBaseURL(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "myhost:8080"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "http://myhost:8080", tr.BaseURL())
}

// --- IsConnected ---

func TestIsConnected_Default(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.False(t, tr.IsConnected())
}

// --- Healthy ---

func TestHealthy_NilClient(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.False(t, tr.Healthy(context.Background()))
}

// --- RequestStream ---

func TestRequestStream_NotSupported(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.RequestStream(context.Background(), "test", nil)
	assert.ErrorIs(t, err, transport.ErrStreamNotSupported)
}

// --- NotConnected error paths ---

func TestHealth_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.Health(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestListBackends_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.ListBackends(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGenerateKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GenerateKey(context.Background(), &transport.GenerateKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestSign_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.Sign(context.Background(), &transport.SignRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestSeal_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.Seal(context.Background(), &transport.SealRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierStatus_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.BarrierStatus(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDoRequest_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.DoRequest(context.Background(), "GET", "/health", nil, nil)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDoRawRequest_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.DoRawRequest(context.Background(), "GET", "/health", nil)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestRequest_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.Request(context.Background(), "/health", nil, nil)
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- Connect with httptest server ---

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
	})
	mux.HandleFunc("/api/v1/backends", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"backends": []map[string]interface{}{
				{"id": "software", "type": "software"},
			},
		})
	})
	return httptest.NewServer(mux)
}

func TestConnect_Success(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.NoError(t, err)
	assert.True(t, tr.IsConnected())
	assert.NotNil(t, tr.HTTPClient())
	assert.NoError(t, tr.Close())
}

func TestConnect_FailedHealthCheck(t *testing.T) {
	// Server that returns error for health
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	assert.Error(t, err)
}

func TestHealth_Connected(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.Health(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ok", resp.Status)
}

func TestListBackends_Connected(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.ListBackends(context.Background())
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.Backends, 1)
	assert.Equal(t, "software", resp.Backends[0].ID)
}

func TestHealthy_Connected(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	assert.True(t, tr.Healthy(context.Background()))
}

func TestDoRequest_InvalidResponseJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	var result map[string]string
	err = tr.DoRequest(context.Background(), "GET", "/invalid", nil, &result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestDoRequest_WithBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	var result map[string]string
	err = tr.DoRequest(context.Background(), "POST", "/api/v1/keys", map[string]string{"key_id": "test"}, &result)
	require.NoError(t, err)
	assert.Equal(t, "ok", result["result"])
}

func TestDoRawRequest_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	_, err = tr.DoRawRequest(context.Background(), "GET", "/error", nil)
	assert.Error(t, err)
}

func TestConnect_WithJWTToken(t *testing.T) {
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	tr, err := New(
		transport.WithAddress(srv.URL),
		transport.WithJWTToken("my-test-token"),
	)
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	// The health check during Connect should have sent the JWT
	assert.Equal(t, "Bearer my-test-token", receivedAuth)
}

func TestConnect_WithCustomHeaders(t *testing.T) {
	var receivedHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Custom")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	tr, err := New(
		transport.WithAddress(srv.URL),
		transport.WithHeader("X-Custom", "test-value"),
	)
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	assert.Equal(t, "test-value", receivedHeader)
}

// --- DoHeadRequest ---

func TestDoHeadRequest_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.DoHeadRequest(context.Background(), "/test")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDoHeadRequest_Exists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	exists, err := tr.DoHeadRequest(context.Background(), "/api/v1/certs/sw/key1")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestDoHeadRequest_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	exists, err := tr.DoHeadRequest(context.Background(), "/api/v1/certs/sw/missing")
	require.NoError(t, err)
	assert.False(t, exists)
}

// --- DoRequestWithHeaders ---

func TestDoRequestWithHeaders_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, _, err = tr.DoRequestWithHeaders(context.Background(), "GET", "/test", nil, nil)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDoRequestWithHeaders_Success(t *testing.T) {
	var receivedHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		receivedHeader = r.Header.Get("X-Req-Custom")
		w.Header().Set("X-Response", "test-resp")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	body, headers, err := tr.DoRequestWithHeaders(
		context.Background(), "POST", "/api/v1/keys",
		map[string]string{"key_id": "test"},
		map[string]string{"X-Req-Custom": "custom-val"},
	)
	require.NoError(t, err)
	assert.NotEmpty(t, body)
	assert.Equal(t, "custom-val", receivedHeader)
	assert.Equal(t, "test-resp", headers.Get("X-Response"))
}

func TestDoRequestWithHeaders_ServerErrorWithMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "bad param"})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	_, _, err = tr.DoRequestWithHeaders(context.Background(), "POST", "/api/v1/keys", nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bad param")
}

func TestDoRequestWithHeaders_ServerErrorRawBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("raw error text"))
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	_, _, err = tr.DoRequestWithHeaders(context.Background(), "GET", "/api/v1/err", nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// --- More method coverage ---

func newRESTMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/health":
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
		case r.URL.Path == "/api/v1/backends":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"backends": []map[string]interface{}{{"id": "software"}},
			})
		case r.URL.Path == "/api/v1/keys" && r.Method == "POST":
			json.NewEncoder(w).Encode(transport.GenerateKeyResponse{KeyID: "new-key", KeyType: "ECDSA"})
		case r.URL.Path == "/api/v1/keys" && r.Method == "GET":
			json.NewEncoder(w).Encode(transport.ListKeysResponse{})
		case r.URL.Path == "/api/v1/seal":
			json.NewEncoder(w).Encode(transport.SealResponse{Ciphertext: []byte("sealed")})
		case r.URL.Path == "/api/v1/unseal":
			json.NewEncoder(w).Encode(transport.UnsealResponse{Plaintext: []byte("data")})
		case r.URL.Path == "/v1/barrier/status":
			json.NewEncoder(w).Encode(transport.BarrierStatusResponse{})
		default:
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		}
	}))
}

func connectToMockREST(t *testing.T, srv *httptest.Server) *Transport {
	t.Helper()
	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	return tr
}

func TestGetBackend_Connected(t *testing.T) {
	srv := newRESTMockServer(t)
	defer srv.Close()
	tr := connectToMockREST(t, srv)
	defer tr.Close()

	resp, err := tr.GetBackend(context.Background(), "software")
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGenerateKey_Connected(t *testing.T) {
	srv := newRESTMockServer(t)
	defer srv.Close()
	tr := connectToMockREST(t, srv)
	defer tr.Close()

	resp, err := tr.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:   "new-key",
		Backend: "software",
		KeyType: "ECDSA",
	})
	require.NoError(t, err)
	assert.Equal(t, "new-key", resp.KeyID)
}

func TestSign_Connected(t *testing.T) {
	srv := newRESTMockServer(t)
	defer srv.Close()
	tr := connectToMockREST(t, srv)
	defer tr.Close()

	resp, err := tr.Sign(context.Background(), &transport.SignRequest{
		Backend: "software",
		KeyID:   "test-key",
		Data:    []byte("hello"),
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSeal_Connected(t *testing.T) {
	srv := newRESTMockServer(t)
	defer srv.Close()
	tr := connectToMockREST(t, srv)
	defer tr.Close()

	resp, err := tr.Seal(context.Background(), &transport.SealRequest{
		Backend: "software",
		Data:    []byte("secret"),
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestUnseal_Connected(t *testing.T) {
	srv := newRESTMockServer(t)
	defer srv.Close()
	tr := connectToMockREST(t, srv)
	defer tr.Close()

	resp, err := tr.Unseal(context.Background(), &transport.UnsealRequest{
		Backend:    "software",
		Ciphertext: []byte("sealed"),
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestBarrierStatus_Connected(t *testing.T) {
	srv := newRESTMockServer(t)
	defer srv.Close()
	tr := connectToMockREST(t, srv)
	defer tr.Close()

	resp, err := tr.BarrierStatus(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestDoRawRequest_ServerErrorWithErrorField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid param"})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	_, err = tr.DoRawRequest(context.Background(), "POST", "/bad", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid param")
}

func TestDoRawRequest_ServerErrorWithMessageField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"message": "forbidden"})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	_, err = tr.DoRawRequest(context.Background(), "POST", "/forbidden", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestDoRawRequest_ServerErrorPlainText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("bad gateway"))
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	_, err = tr.DoRawRequest(context.Background(), "GET", "/bad-gw", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "502")
}

func TestClose_WithClient(t *testing.T) {
	srv := newRESTMockServer(t)
	defer srv.Close()
	tr := connectToMockREST(t, srv)

	assert.True(t, tr.IsConnected())
	assert.NoError(t, tr.Close())
	assert.False(t, tr.IsConnected())
}
