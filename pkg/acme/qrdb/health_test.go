// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package qrdb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthHandlerHealth(t *testing.T) {
	t.Run("healthy service returns 200", func(t *testing.T) {
		svc := &mockHealthService{healthy: true}
		handler := NewHealthHandler(svc, DefaultConfig())

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		handler.Health(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var status healthStatus
		err := json.Unmarshal(w.Body.Bytes(), &status)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.Equal(t, "healthy", status.Status)
	})

	t.Run("unhealthy service returns 503", func(t *testing.T) {
		svc := &mockHealthService{healthy: false}
		handler := NewHealthHandler(svc, DefaultConfig())

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		handler.Health(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)

		var status healthStatus
		err := json.Unmarshal(w.Body.Bytes(), &status)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Equal(t, "unhealthy", status.Status)
	})
}

func TestHealthHandlerReady(t *testing.T) {
	t.Run("ready service returns 200", func(t *testing.T) {
		svc := &mockHealthService{
			healthy: true,
			adminHealthResp: &db.HealthResponse{
				Status: "ready",
			},
		}
		handler := NewHealthHandler(svc, DefaultConfig())

		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		w := httptest.NewRecorder()

		handler.Ready(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var status healthStatus
		err := json.Unmarshal(w.Body.Bytes(), &status)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.Equal(t, "ready", status.Status)
	})

	t.Run("not healthy returns 503", func(t *testing.T) {
		svc := &mockHealthService{healthy: false}
		handler := NewHealthHandler(svc, DefaultConfig())

		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		w := httptest.NewRecorder()

		handler.Ready(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)

		var status healthStatus
		err := json.Unmarshal(w.Body.Bytes(), &status)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
	})

	t.Run("admin health error returns 503", func(t *testing.T) {
		svc := &mockHealthService{
			healthy:        true,
			adminHealthErr: NewError(ErrorCodeConnection, "admin unreachable"),
		}
		handler := NewHealthHandler(svc, DefaultConfig())

		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		w := httptest.NewRecorder()

		handler.Ready(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestRegisterHealthEndpoints(t *testing.T) {
	t.Run("registers health and ready endpoints", func(t *testing.T) {
		svc := &mockHealthService{
			healthy: true,
			adminHealthResp: &db.HealthResponse{
				Status: "healthy",
			},
		}
		handler := NewHealthHandler(svc, DefaultConfig())
		mux := http.NewServeMux()

		RegisterHealthEndpoints(mux, handler)

		// Test /health
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Test /ready
		req = httptest.NewRequest(http.MethodGet, "/ready", nil)
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestNewHealthHandler(t *testing.T) {
	t.Run("creates handler with service and config", func(t *testing.T) {
		svc := &mockHealthService{}
		cfg := DefaultConfig()
		h := NewHealthHandler(svc, cfg)
		require.NotNil(t, h)
	})
}

// mockHealthService implements Service for health testing.
type mockHealthService struct {
	healthy         bool
	adminHealthResp *db.HealthResponse
	adminHealthErr  error
}

func (m *mockHealthService) KV() db.KVClient       { return nil }
func (m *mockHealthService) Watch() db.WatchClient { return nil }
func (m *mockHealthService) Lease() db.LeaseClient { return nil }
func (m *mockHealthService) Batch() db.BatchClient { return nil }
func (m *mockHealthService) Transaction() db.TransactionClient {
	return nil
}
func (m *mockHealthService) Index() db.IndexClient            { return nil }
func (m *mockHealthService) Users() db.UserClient             { return nil }
func (m *mockHealthService) Roles() db.RoleClient             { return nil }
func (m *mockHealthService) Certs() db.CertClient             { return nil }
func (m *mockHealthService) Barrier() db.BarrierClient        { return nil }
func (m *mockHealthService) Ceremony() db.CeremonyClient      { return nil }
func (m *mockHealthService) Credentials() db.CredentialClient { return nil }
func (m *mockHealthService) Config() *Config                  { return DefaultConfig() }
func (m *mockHealthService) Healthy(_ context.Context) bool {
	return m.healthy
}
func (m *mockHealthService) Close() error { return nil }
func (m *mockHealthService) Admin() db.AdminClient {
	return &mockHealthAdmin{
		healthResp: m.adminHealthResp,
		healthErr:  m.adminHealthErr,
	}
}

// mockHealthAdmin implements AdminClient for health testing.
type mockHealthAdmin struct {
	healthResp *db.HealthResponse
	healthErr  error
}

func (a *mockHealthAdmin) Health(_ context.Context) (*db.HealthResponse, error) {
	return a.healthResp, a.healthErr
}
func (a *mockHealthAdmin) Status(_ context.Context) (*db.StatusResponse, error) {
	return nil, nil
}
func (a *mockHealthAdmin) Peers(_ context.Context) (*db.PeersResponse, error) {
	return nil, nil
}
func (a *mockHealthAdmin) AddMember(_ context.Context, _, _ uint64, _ string) error {
	return nil
}
func (a *mockHealthAdmin) RemoveMember(_ context.Context, _, _ uint64) error { return nil }
func (a *mockHealthAdmin) RequestSnapshot(_ context.Context, _ uint64) error { return nil }
func (a *mockHealthAdmin) Drain(_ context.Context) error                     { return nil }
func (a *mockHealthAdmin) Capabilities(_ context.Context) (*db.CapabilitiesResponse, error) {
	return nil, nil
}
func (a *mockHealthAdmin) StartShard(_ context.Context, _ *db.StartShardRequest) error {
	return nil
}
func (a *mockHealthAdmin) StopShard(_ context.Context, _ uint64) error { return nil }
func (a *mockHealthAdmin) GetShardState(_ context.Context, _ uint64) (*db.ShardStateResponse, error) {
	return nil, nil
}
func (a *mockHealthAdmin) GetTopology(_ context.Context) (*db.TopologyResponse, error) {
	return nil, nil
}
