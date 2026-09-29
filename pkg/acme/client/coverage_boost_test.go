//go:build codec_json

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
// drives one connection into the handler, then blocks the handler there
// until the returned cleanup runs. net/http only marks a connection
// http.StateActive once its handler has been dispatched; a partial request
// with no trailing "\r\n\r\n" never reaches that point; readRequest just
// blocks with the connection still in http.StateNew, which Shutdown treats
// as idle and closes immediately, so Shutdown with an expired context
// returns nil instead of an error. Sending a complete request and waiting
// for the handler to signal that it is running proves the connection is
// active before Shutdown is invoked, so Shutdown must poll until the
// context deadline and return an error. Returns the server and a cleanup
// function that releases the handler and waits for the server goroutine to
// exit.
func startHTTPServerWithActiveConn(t *testing.T) (*http.Server, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	inFlight := make(chan struct{})
	release := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		close(inFlight)
		<-release
	})

	srv := &http.Server{
		Addr:    listener.Addr().String(),
		Handler: mux,
	}

	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = srv.Serve(listener)
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	require.NoError(t, err)

	// Block until the handler is actually running, which guarantees the
	// connection is in http.StateActive before Shutdown is called.
	select {
	case <-inFlight:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for handler to receive request")
	}

	cleanup := func() {
		close(release)
		_ = conn.Close()
		_ = srv.Close()
		<-serveDone
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
