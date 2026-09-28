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

package enroll01

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// testServerState holds server state for testing purposes
type testServerState struct {
	server       *http.Server
	shutdownOnce sync.Once
	listener     net.Listener
}

// Port returns the port the server actually bound, read back from the
// listener rather than named by the caller. Only valid once startTestServer
// has returned.
func (s *testServerState) Port() string {
	_, port, err := net.SplitHostPort(s.listener.Addr().String())
	if err != nil {
		// listener.Addr() always returns a valid "host:port" pair for a
		// bound TCP listener, so SplitHostPort cannot fail here.
		panic(fmt.Sprintf("testServerState.Port: %v", err))
	}
	return port
}

// startTestServer starts a server on an OS-assigned loopback port and
// returns state that tests can use to manage it and to read that port back
// via Port(). This is the test-friendly version of startServer that allows
// proper cleanup.
//
// The listener is bound synchronously, before this function returns, so
// Port() is safe to call immediately: only accepting the connections that
// follow (http.Server.Serve) happens in the background goroutine. This also
// replaces the fixed ports the tests previously named (go-xkms#1142): a
// literal port can already be bound by another package's test running in
// parallel in the same CI job.
func startTestServer(t *testing.T, tpm TrustedPlatformModule, packedCSR []byte) *testServerState {
	t.Helper()
	state := &testServerState{}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on an ephemeral loopback port: %v", err)
	}
	state.listener = listener

	// Create server first so handlers can reference it
	state.server = &http.Server{
		Addr:         listener.Addr().String(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Set up HTTP server to handle challenges with closures capturing local state
	mux := http.NewServeMux()
	mux.HandleFunc(challengePath, challengeHandlerHTTPx(packedCSR))
	mux.HandleFunc(secretPath, activateCredentialHandlerWithShutdown(tpm, state.server, &state.shutdownOnce))
	state.server.Handler = mux

	// Serve on the already-bound listener in a separate goroutine.
	go func() {
		log.Printf("Starting test HTTP server on %s for enroll-01 challenge", state.server.Addr)
		if err := state.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("Test HTTP server error: %v", err)
		}
	}()

	return state
}

// Shutdown gracefully shuts down the test server
func (s *testServerState) Shutdown() error {
	if s.server == nil {
		return nil
	}

	var shutdownErr error
	s.shutdownOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
		defer cancel()
		shutdownErr = s.server.Shutdown(ctx)
	})
	return shutdownErr
}

// Close forcefully closes the test server
func (s *testServerState) Close() error {
	if s.server == nil {
		return nil
	}
	return s.server.Close()
}

// Server returns the underlying HTTP server
func (s *testServerState) Server() *http.Server {
	return s.server
}
