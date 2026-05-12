//go:build local

package client

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCoverageBoost_WithAuthClient verifies that WithAuthClient sets the authClient field.
func TestCoverageBoost_WithAuthClient(t *testing.T) {
	t.Run("sets authClient on TrustedCA", func(t *testing.T) {
		client := auth.NewMemoryClient()
		tca := &TrustedCA{}
		opt := WithAuthClient(client)
		err := opt(tca)
		require.NoError(t, err)
		assert.Equal(t, client, tca.authClient)
	})

	t.Run("sets nil authClient", func(t *testing.T) {
		tca := &TrustedCA{}
		opt := WithAuthClient(nil)
		err := opt(tca)
		require.NoError(t, err)
		assert.Nil(t, tca.authClient)
	})
}

// startHTTPServerWithActiveConn starts an HTTP server on a random port and
// establishes an active connection that keeps the server busy, so that
// Shutdown with an expired context will return an error. Returns the server
// and a cleanup function.
func startHTTPServerWithActiveConn(t *testing.T) (*http.Server, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &http.Server{
		Addr:    listener.Addr().String(),
		Handler: http.NewServeMux(),
	}

	go func() {
		_ = srv.Serve(listener)
	}()

	// Wait briefly for the server to start
	time.Sleep(20 * time.Millisecond)

	// Establish an active connection with a partial HTTP request
	// to keep it alive during Shutdown
	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n"))
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	cleanup := func() {
		_ = conn.Close()
		_ = srv.Close()
	}

	return srv, cleanup
}

// TestCoverageBoost_Shutdown_ACMEServerError tests Shutdown when acmeServer.Shutdown
// returns an error due to an already-expired context and active connections.
func TestCoverageBoost_Shutdown_ACMEServerError(t *testing.T) {
	tca := &TrustedCA{}
	srv, cleanup := startHTTPServerWithActiveConn(t)
	defer cleanup()
	tca.acmeServer = srv

	pastCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	err := tca.Shutdown(pastCtx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ACME server shutdown")
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

// TestCoverageBoost_Shutdown_AdminServerError tests Shutdown when only the
// adminServer.Shutdown returns an error.
func TestCoverageBoost_Shutdown_AdminServerError(t *testing.T) {
	tca := &TrustedCA{}
	srv, cleanup := startHTTPServerWithActiveConn(t)
	defer cleanup()
	tca.adminServer = srv

	pastCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	err := tca.Shutdown(pastCtx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "admin server shutdown")
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

// TestCoverageBoost_Shutdown_BothServersError tests that errors from both
// ACME and admin servers are joined when both fail during shutdown.
func TestCoverageBoost_Shutdown_BothServersError(t *testing.T) {
	tca := &TrustedCA{}
	acmeSrv, acmeCleanup := startHTTPServerWithActiveConn(t)
	defer acmeCleanup()
	adminSrv, adminCleanup := startHTTPServerWithActiveConn(t)
	defer adminCleanup()

	tca.acmeServer = acmeSrv
	tca.adminServer = adminSrv

	pastCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	err := tca.Shutdown(pastCtx)
	require.Error(t, err)

	errStr := err.Error()
	assert.Contains(t, errStr, "ACME server shutdown")
	assert.Contains(t, errStr, "admin server shutdown")
}

// TestCoverageBoost_Shutdown_NoServers tests Shutdown when no servers are set
// produces no error and resets the started flag.
func TestCoverageBoost_Shutdown_NoServers(t *testing.T) {
	tca := &TrustedCA{started: true}
	err := tca.Shutdown(context.Background())
	require.NoError(t, err)
	assert.False(t, tca.started)
}
