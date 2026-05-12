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

package enroll01

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// testServerState holds server state for testing purposes
type testServerState struct {
	server       *http.Server
	shutdownOnce sync.Once
	listener     net.Listener
}

// startTestServer starts a server and returns state that tests can use to manage it.
// This is the test-friendly version of startServer that allows proper cleanup.
func startTestServer(port string, tpm TrustedPlatformModule, packedCSR []byte) *testServerState {
	state := &testServerState{}

	addr := fmt.Sprintf(":%s", port)

	// Create server first so handlers can reference it
	state.server = &http.Server{
		Addr:         addr,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Set up HTTP server to handle challenges with closures capturing local state
	mux := http.NewServeMux()
	mux.HandleFunc(challengePath, challengeHandlerHTTPx(packedCSR))
	mux.HandleFunc(secretPath, activateCredentialHandlerWithShutdown(tpm, state.server, &state.shutdownOnce))
	state.server.Handler = mux

	// Start the HTTP server in a separate goroutine
	go func() {
		log.Printf("Starting test HTTP server on %s for enroll-01 challenge", addr)
		// Listen on all interfaces
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("Failed to listen on %s: %v", addr, err)
			return
		}
		state.listener = listener
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
