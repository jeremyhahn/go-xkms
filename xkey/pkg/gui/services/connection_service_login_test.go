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
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
)

// authRecordingRESTServer answers /health and records every Authorization
// header it receives.
func authRecordingRESTServer(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if v := r.Header.Get("Authorization"); v != "" {
			auth = append(auth, v)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","version":"v"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), auth...)
	}
}

func TestConnectionServiceConnect_PresentsStoredLogin(t *testing.T) {
	srv, seen := authRecordingRESTServer(t)
	addr := srv.Listener.Addr().String()
	store := tokenstore.NewMemoryTokenStore()
	require.NoError(t, store.Save(context.Background(), &tokenstore.TokenEntry{
		ServerURL: "http://" + addr, Token: "login.jwt", ExpiresAt: time.Now().Add(time.Hour),
	}))

	svc := NewConnectionService()
	svc.SetContext(context.Background())
	svc.SetTokenStore(store)

	_, err := svc.Connect("rest", addr, false, "", "")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, svc.Disconnect()) })

	_, err = svc.GetClient().Health(context.Background())
	require.NoError(t, err)
	assert.Contains(t, seen(), "Bearer login.jwt")
}

func TestConnectionServiceConnect_NoLoginNoAuthorization(t *testing.T) {
	srv, seen := authRecordingRESTServer(t)

	svc := NewConnectionService()
	svc.SetContext(context.Background())
	svc.SetTokenStore(tokenstore.NewMemoryTokenStore())

	_, err := svc.Connect("rest", srv.Listener.Addr().String(), false, "", "")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, svc.Disconnect()) })
	assert.Empty(t, seen())
}

func TestConnectionServiceConnect_ExpiredLoginRefused(t *testing.T) {
	srv, seen := authRecordingRESTServer(t)
	addr := srv.Listener.Addr().String()
	store := tokenstore.NewMemoryTokenStore()
	require.NoError(t, store.Save(context.Background(), &tokenstore.TokenEntry{
		ServerURL: "http://" + addr, Token: "old.jwt", ExpiresAt: time.Now().Add(-time.Minute),
	}))

	svc := NewConnectionService()
	svc.SetContext(context.Background())
	svc.SetTokenStore(store)

	info, err := svc.Connect("rest", addr, false, "", "")
	assert.ErrorIs(t, err, tokenstore.ErrTokenExpired)
	require.NotNil(t, info)
	assert.Equal(t, "error", info.State)
	assert.False(t, svc.IsConnected())
	assert.Empty(t, seen(), "an expired login never reaches the server")
}

func TestConnectionURL(t *testing.T) {
	for _, tc := range []struct {
		protocol, address string
		tls               bool
		want              string
	}{
		{"rest", "xkms.example:8443", true, "https://xkms.example:8443"},
		{"rest", "xkms.example:8080", false, "http://xkms.example:8080"},
		{"rest", "https://xkms.example:8443", true, "https://xkms.example:8443"},
		{"grpc", "xkms.example:9443", true, "grpcs://xkms.example:9443"},
		{"grpc", "xkms.example:9090", false, "grpc://xkms.example:9090"},
		{"quic", "xkms.example:8443", true, "quic://xkms.example:8443"},
		{"mcp", "xkms.example:9444", true, "mcps://xkms.example:9444"},
		{"mcp", "xkms.example:9444", false, "mcp://xkms.example:9444"},
		{"unix", "/run/xkms.sock", false, "unix:///run/xkms.sock"},
	} {
		assert.Equal(t, tc.want, connectionURL(tc.protocol, tc.address, tc.tls), "%s %s", tc.protocol, tc.address)
	}
}
