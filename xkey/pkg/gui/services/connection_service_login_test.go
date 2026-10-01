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

	sshclient "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverid"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverid/serveridtest"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
)

// authRecordingRESTServer answers every request with a health body over
// HTTPS and records each Authorization header. It returns the server, a CA
// file trusting it, and the recorded headers.
func authRecordingRESTServer(t *testing.T) (*httptest.Server, string, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var auth []string
	srv, caFile := serveridtest.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if v := r.Header.Get("Authorization"); v != "" {
			auth = append(auth, v)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","version":"v"}`))
	}))
	return srv, caFile, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), auth...)
	}
}

// saveLogin stores a login to srv's identity, made through another URL.
func saveLogin(t *testing.T, store tokenstore.TokenStore, srv *httptest.Server, token string, expires time.Time) {
	t.Helper()
	require.NoError(t, store.Save(context.Background(), &tokenstore.TokenEntry{
		ServerURL: "https://login.example:1", ServerID: serverid.Of(srv.Certificate()), ServerName: "login.example",
		Token: token, IssuedAt: time.Now(), ExpiresAt: expires,
	}))
}

func TestConnectionServiceConnect_PresentsStoredLoginOfTheServerIdentity(t *testing.T) {
	srv, caFile, seen := authRecordingRESTServer(t)
	store := tokenstore.NewMemoryTokenStore()
	saveLogin(t, store, srv, "login.jwt", time.Now().Add(time.Hour))

	svc := NewConnectionService()
	svc.SetContext(context.Background())
	svc.SetTokenStore(store)

	_, err := svc.Connect("rest", srv.Listener.Addr().String(), true, caFile, "")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, svc.Disconnect()) })

	_, err = svc.GetClient().Health(context.Background())
	require.NoError(t, err)
	assert.Contains(t, seen(), "Bearer login.jwt")
}

func TestConnectionServiceConnect_OtherCertificateGetsNoLogin(t *testing.T) {
	loggedIn, _, _ := authRecordingRESTServer(t)
	other, otherCA, seen := authRecordingRESTServer(t)
	store := tokenstore.NewMemoryTokenStore()
	saveLogin(t, store, loggedIn, "login.jwt", time.Now().Add(time.Hour))

	svc := NewConnectionService()
	svc.SetContext(context.Background())
	svc.SetTokenStore(store)

	_, err := svc.Connect("rest", other.Listener.Addr().String(), true, otherCA, "")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, svc.Disconnect()) })
	assert.Empty(t, seen(), "a different certificate on the same host is a different server")
}

func TestConnectionServiceConnect_ExpiredLoginRefused(t *testing.T) {
	srv, caFile, seen := authRecordingRESTServer(t)
	store := tokenstore.NewMemoryTokenStore()
	saveLogin(t, store, srv, "old.jwt", time.Now().Add(-time.Minute))

	svc := NewConnectionService()
	svc.SetContext(context.Background())
	svc.SetTokenStore(store)

	info, err := svc.Connect("rest", srv.Listener.Addr().String(), true, caFile, "")
	assert.ErrorIs(t, err, tokenstore.ErrTokenExpired)
	require.NotNil(t, info)
	assert.Equal(t, "error", info.State)
	assert.False(t, svc.IsConnected())
	assert.Empty(t, seen(), "an expired login never reaches the server")
}

func TestConnectionServiceConnect_PlainConnectionUsesServerName(t *testing.T) {
	srv := newHealthyRESTServer(t, "v")
	store := tokenstore.NewMemoryTokenStore()
	require.NoError(t, store.Save(context.Background(), &tokenstore.TokenEntry{
		ServerURL: "https://named:1", ServerID: "id", ServerName: "named", Token: "old", ExpiresAt: time.Now().Add(-time.Minute),
	}))

	svc := NewConnectionService()
	svc.SetContext(context.Background())
	svc.SetTokenStore(store)
	svc.SetServerName("named")

	_, err := svc.Connect("rest", srv.Listener.Addr().String(), false, "", "")
	assert.ErrorIs(t, err, tokenstore.ErrTokenExpired, "without TLS the configured server name selects the login")
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

func TestConnectionServiceSSHClient_NotConnected(t *testing.T) {
	svc := NewConnectionService()
	_, err := svc.SSHClient()
	assert.ErrorIs(t, err, ErrServerNotConnected)
}

// TestConnectionServiceSSHClient_UsesConnectionAndLogin proves the SSH
// client dials the connected server with the connection's stored login.
func TestConnectionServiceSSHClient_UsesConnectionAndLogin(t *testing.T) {
	srv, caFile, seen := authRecordingRESTServer(t)
	store := tokenstore.NewMemoryTokenStore()
	saveLogin(t, store, srv, "login.jwt", time.Now().Add(time.Hour))

	svc := NewConnectionService()
	svc.SetContext(context.Background())
	svc.SetTokenStore(store)
	_, err := svc.Connect("rest", srv.Listener.Addr().String(), true, caFile, "")
	require.NoError(t, err)

	client, err := svc.SSHClient()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })
	// The recording server answers every path with a health body; the call
	// only has to reach it.
	_, _ = client.Keys().List(context.Background(), sshclient.ListKeysRequest{Scope: "user", Owner: "me"})
	assert.Contains(t, seen(), "Bearer login.jwt")

	require.NoError(t, svc.Disconnect())
	_, err = svc.SSHClient()
	assert.ErrorIs(t, err, ErrServerNotConnected, "a disconnected service dials nothing")
}
