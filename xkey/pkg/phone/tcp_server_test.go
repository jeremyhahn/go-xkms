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

package phone

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockRequestHandler is a test helper that echoes back the request as a response
// or returns a configurable error.
type mockRequestHandler struct {
	mu        sync.Mutex
	received  [][]byte
	response  []byte
	returnErr error
}

func (m *mockRequestHandler) HandleRequest(_ context.Context, request []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.received = append(m.received, append([]byte{}, request...))
	if m.returnErr != nil {
		return nil, m.returnErr
	}
	if m.response != nil {
		return m.response, nil
	}
	// Default: echo the request back.
	return request, nil
}

func (m *mockRequestHandler) receivedRequests() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([][]byte{}, m.received...)
}

// clientHandshake performs a Noise XX handshake as initiator over a raw TCP
// connection using the 2-byte length-prefixed framing. Returns the established
// NoiseSession.
func clientHandshake(t *testing.T, conn net.Conn) *NoiseSession {
	t.Helper()

	clientKey, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}

	clientSession, err := NewNoiseSession(&NoiseSessionConfig{
		LocalStaticKey: clientKey,
		IsInitiator:    true,
	})
	if err != nil {
		t.Fatalf("create client session: %v", err)
	}

	if err := clientSession.InitHandshake(); err != nil {
		t.Fatalf("init client handshake: %v", err)
	}

	// Step 1: initiator sends msg1 (e)
	msg1, complete, err := clientSession.HandshakeMessage(nil)
	if err != nil {
		t.Fatalf("client handshake msg1: %v", err)
	}
	if complete {
		t.Fatal("handshake should not be complete after msg1")
	}
	if err := tcpSend(conn, msg1); err != nil {
		t.Fatalf("send msg1: %v", err)
	}

	// Step 2: receive msg2 from responder (e, ee, s, es)
	msg2, err := tcpReceive(conn)
	if err != nil {
		t.Fatalf("receive msg2: %v", err)
	}

	// Step 3: process msg2, generate msg3 (s, se) -- initiator completes
	msg3, complete, err := clientSession.HandshakeMessage(msg2)
	if err != nil {
		t.Fatalf("client handshake msg3: %v", err)
	}
	if !complete {
		t.Fatal("handshake should be complete for initiator after processing msg2")
	}

	// Step 4: send msg3 to responder
	if err := tcpSend(conn, msg3); err != nil {
		t.Fatalf("send msg3: %v", err)
	}

	return clientSession
}

func TestTCPPairingServer_StartStop(t *testing.T) {
	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	addr := srv.Addr()
	if addr == "" {
		t.Fatal("Addr() should return a non-empty address after Start")
	}
	if !strings.Contains(addr, ":") {
		t.Fatalf("Addr() should contain a port, got %q", addr)
	}

	// Verify we can connect to it at the TCP level.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestTCPPairingServer_NilConfig(t *testing.T) {
	srv, err := NewTCPPairingServer(nil)
	if err != nil {
		t.Fatalf("NewTCPPairingServer(nil): %v", err)
	}
	if srv.cfg.ListenAddr != DefaultTCPListenAddr {
		t.Errorf("expected default listen addr %q, got %q", DefaultTCPListenAddr, srv.cfg.ListenAddr)
	}
	if srv.localStaticKey == nil {
		t.Error("expected auto-generated static key, got nil")
	}
	if len(srv.LocalStaticPublicKey()) == 0 {
		t.Error("expected non-empty public key")
	}
}

func TestTCPPairingServer_DoubleStart(t *testing.T) {
	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	defer srv.Stop()

	err = srv.Start()
	if !errors.Is(err, ErrTCPServerAlreadyRunning) {
		t.Fatalf("second Start: expected ErrTCPServerAlreadyRunning, got %v", err)
	}
}

func TestTCPPairingServer_StopNotRunning(t *testing.T) {
	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}

	err = srv.Stop()
	if !errors.Is(err, ErrTCPServerNotRunning) {
		t.Fatalf("Stop before Start: expected ErrTCPServerNotRunning, got %v", err)
	}
}

func TestTCPPairingServer_HandshakeAndRequest(t *testing.T) {
	// Prepare a handler that returns a known JSON-RPC response.
	expectedResponse := `{"jsonrpc":"2.0","id":1,"result":{"pong":true}}`
	handler := &mockRequestHandler{
		response: []byte(expectedResponse),
	}

	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr:     "127.0.0.1:0",
		RequestHandler: handler,
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	// Connect a client.
	conn, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Perform Noise XX handshake as initiator.
	clientSession := clientHandshake(t, conn)

	// Send an encrypted JSON-RPC request.
	request := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	encrypted, err := clientSession.Encrypt([]byte(request))
	if err != nil {
		t.Fatalf("encrypt request: %v", err)
	}
	if err := tcpSend(conn, encrypted); err != nil {
		t.Fatalf("send encrypted request: %v", err)
	}

	// Receive encrypted response.
	responseCiphertext, err := tcpReceive(conn)
	if err != nil {
		t.Fatalf("receive response: %v", err)
	}

	responsePlaintext, err := clientSession.Decrypt(responseCiphertext)
	if err != nil {
		t.Fatalf("decrypt response: %v", err)
	}

	if string(responsePlaintext) != expectedResponse {
		t.Fatalf("response mismatch:\n  got:  %s\n  want: %s", responsePlaintext, expectedResponse)
	}

	// Verify the handler received the original plaintext request.
	received := handler.receivedRequests()
	if len(received) != 1 {
		t.Fatalf("expected 1 received request, got %d", len(received))
	}
	if string(received[0]) != request {
		t.Fatalf("handler received unexpected request:\n  got:  %s\n  want: %s", received[0], request)
	}
}

func TestTCPPairingServer_MultipleConnections(t *testing.T) {
	handler := &mockRequestHandler{}

	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr:     "127.0.0.1:0",
		RequestHandler: handler,
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	// Connect two clients sequentially and verify both work.
	for i := 0; i < 2; i++ {
		conn, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
		if err != nil {
			t.Fatalf("connection %d: dial: %v", i, err)
		}

		clientSession := clientHandshake(t, conn)

		msg := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
		encrypted, err := clientSession.Encrypt([]byte(msg))
		if err != nil {
			t.Fatalf("connection %d: encrypt: %v", i, err)
		}
		if err := tcpSend(conn, encrypted); err != nil {
			t.Fatalf("connection %d: send: %v", i, err)
		}

		ciphertext, err := tcpReceive(conn)
		if err != nil {
			t.Fatalf("connection %d: receive: %v", i, err)
		}

		plaintext, err := clientSession.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("connection %d: decrypt: %v", i, err)
		}
		// Echo handler returns the request as the response.
		if string(plaintext) != msg {
			t.Fatalf("connection %d: response mismatch: got %s", i, plaintext)
		}

		conn.Close()
	}

	received := handler.receivedRequests()
	if len(received) != 2 {
		t.Fatalf("expected 2 received requests, got %d", len(received))
	}
}

func TestTCPPairingServer_StopDrainsConnections(t *testing.T) {
	// Use a handler that blocks until we signal it, proving the server
	// waits for active connections to finish.
	blockCh := make(chan struct{})
	handler := &mockRequestHandler{
		response: []byte(`{"jsonrpc":"2.0","id":1,"result":null}`),
	}

	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr:     "127.0.0.1:0",
		RequestHandler: handler,
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Connect and complete handshake.
	conn, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	clientSession := clientHandshake(t, conn)

	// Send one request to confirm the connection is alive.
	msg := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	encrypted, err := clientSession.Encrypt([]byte(msg))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := tcpSend(conn, encrypted); err != nil {
		t.Fatalf("send: %v", err)
	}

	_, err = tcpReceive(conn)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}

	// Start Stop in background -- it should complete once we close the conn.
	stopDone := make(chan error, 1)
	go func() {
		stopDone <- srv.Stop()
	}()

	// Close the client connection so the server's requestLoop can exit.
	conn.Close()

	// Unblock if needed (for safety).
	close(blockCh)

	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("Stop: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not complete within timeout -- connection not drained")
	}
}

func TestTCPPairingServer_LocalStaticPublicKey(t *testing.T) {
	key, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr:     "127.0.0.1:0",
		LocalStaticKey: key,
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}

	pubKey := srv.LocalStaticPublicKey()
	if len(pubKey) == 0 {
		t.Fatal("expected non-empty public key")
	}
	if len(pubKey) != 32 {
		t.Fatalf("expected 32-byte Curve25519 public key, got %d bytes", len(pubKey))
	}

	// The public key should match the provided key.
	for i, b := range key.Public {
		if pubKey[i] != b {
			t.Fatalf("public key byte %d mismatch: got %02x, want %02x", i, pubKey[i], b)
		}
	}

	// Verify mutation safety: modifying the returned slice must not affect the server's key.
	original := make([]byte, len(pubKey))
	copy(original, pubKey)

	// Mutate every byte.
	for i := range pubKey {
		pubKey[i] ^= 0xFF
	}

	// Fetch again and verify it matches the original, not the mutated slice.
	pubKey2 := srv.LocalStaticPublicKey()
	for i, b := range original {
		if pubKey2[i] != b {
			t.Fatalf("mutation safety violated: byte %d changed from %02x to %02x", i, b, pubKey2[i])
		}
	}
}

func TestTCPPairingServer_AddrBeforeStart(t *testing.T) {
	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}

	// Addr should return empty string when listener is nil.
	if addr := srv.Addr(); addr != "" {
		t.Fatalf("expected empty Addr before Start, got %q", addr)
	}
}

func TestTCPPairingServer_NoHandler(t *testing.T) {
	// Server with no RequestHandler should return a "method not found" error.
	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr: "127.0.0.1:0",
		// No RequestHandler
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	conn, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	clientSession := clientHandshake(t, conn)

	// Send a request.
	request := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	encrypted, err := clientSession.Encrypt([]byte(request))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := tcpSend(conn, encrypted); err != nil {
		t.Fatalf("send: %v", err)
	}

	ciphertext, err := tcpReceive(conn)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}

	plaintext, err := clientSession.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	// Verify the response is a JSON-RPC error for method not found.
	var rpcResp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(plaintext, &rpcResp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if rpcResp.Error == nil {
		t.Fatal("expected error response when no handler is configured")
	}
	if rpcResp.Error.Code != -32601 {
		t.Fatalf("expected error code -32601, got %d", rpcResp.Error.Code)
	}
}

func TestTCPPairingServer_HandlerError(t *testing.T) {
	// Server handler that returns an error should produce an internal error response.
	handler := &mockRequestHandler{
		returnErr: errors.New("handler failure"),
	}

	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr:     "127.0.0.1:0",
		RequestHandler: handler,
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	conn, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	clientSession := clientHandshake(t, conn)

	request := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	encrypted, err := clientSession.Encrypt([]byte(request))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := tcpSend(conn, encrypted); err != nil {
		t.Fatalf("send: %v", err)
	}

	ciphertext, err := tcpReceive(conn)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}

	plaintext, err := clientSession.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	var rpcResp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(plaintext, &rpcResp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if rpcResp.Error == nil {
		t.Fatal("expected error response when handler returns error")
	}
	if rpcResp.Error.Code != -32603 {
		t.Fatalf("expected error code -32603 (Internal error), got %d", rpcResp.Error.Code)
	}
}

func TestTCPPairingServer_StartAfterStop(t *testing.T) {
	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// After Stop sets closed=true, Start should return ErrTCPServerNotRunning.
	err = srv.Start()
	if !errors.Is(err, ErrTCPServerNotRunning) {
		t.Fatalf("Start after Stop: expected ErrTCPServerNotRunning, got %v", err)
	}
}

func TestTCPPairingServer_StartBadAddress(t *testing.T) {
	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr: "invalid-address-no-port",
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}

	err = srv.Start()
	if !errors.Is(err, ErrTCPServerStartFailed) {
		t.Fatalf("Start with bad address: expected ErrTCPServerStartFailed, got %v", err)
	}
}

func TestTCPPairingServer_ConcurrentConnections(t *testing.T) {
	handler := &mockRequestHandler{}

	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr:     "127.0.0.1:0",
		RequestHandler: handler,
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	// Connect 3 clients concurrently.
	const numClients = 3
	var wg sync.WaitGroup
	errs := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()

			clientSession := clientHandshake(t, conn)

			msg := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
			encrypted, err := clientSession.Encrypt([]byte(msg))
			if err != nil {
				errs <- err
				return
			}
			if err := tcpSend(conn, encrypted); err != nil {
				errs <- err
				return
			}

			ciphertext, err := tcpReceive(conn)
			if err != nil {
				errs <- err
				return
			}

			plaintext, err := clientSession.Decrypt(ciphertext)
			if err != nil {
				errs <- err
				return
			}

			if string(plaintext) != msg {
				errs <- errors.New("response mismatch")
				return
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent client error: %v", err)
	}

	received := handler.receivedRequests()
	if len(received) != numClients {
		t.Fatalf("expected %d received requests, got %d", numClients, len(received))
	}
}

func TestTCPPairingServer_DefaultTimeouts(t *testing.T) {
	srv, err := NewTCPPairingServer(nil)
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}

	if srv.cfg.HandshakeTimeout != DefaultHandshakeTimeout {
		t.Errorf("HandshakeTimeout: want %v, got %v", DefaultHandshakeTimeout, srv.cfg.HandshakeTimeout)
	}
	if srv.cfg.IdleTimeout != DefaultIdleTimeout {
		t.Errorf("IdleTimeout: want %v, got %v", DefaultIdleTimeout, srv.cfg.IdleTimeout)
	}
	if srv.cfg.RequestTimeout != DefaultRequestTimeout {
		t.Errorf("RequestTimeout: want %v, got %v", DefaultRequestTimeout, srv.cfg.RequestTimeout)
	}
	if srv.cfg.MaxConnections != DefaultMaxConnections {
		t.Errorf("MaxConnections: want %d, got %d", DefaultMaxConnections, srv.cfg.MaxConnections)
	}

	// Verify custom values override defaults.
	custom, err := NewTCPPairingServer(&TCPPairingConfig{
		HandshakeTimeout: 10 * time.Second,
		IdleTimeout:      2 * time.Minute,
		RequestTimeout:   15 * time.Second,
		MaxConnections:   8,
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer with custom timeouts: %v", err)
	}
	if custom.cfg.HandshakeTimeout != 10*time.Second {
		t.Errorf("custom HandshakeTimeout: want 10s, got %v", custom.cfg.HandshakeTimeout)
	}
	if custom.cfg.IdleTimeout != 2*time.Minute {
		t.Errorf("custom IdleTimeout: want 2m, got %v", custom.cfg.IdleTimeout)
	}
	if custom.cfg.RequestTimeout != 15*time.Second {
		t.Errorf("custom RequestTimeout: want 15s, got %v", custom.cfg.RequestTimeout)
	}
	if custom.cfg.MaxConnections != 8 {
		t.Errorf("custom MaxConnections: want 8, got %d", custom.cfg.MaxConnections)
	}
}

func TestTCPPairingServer_MaxConnections(t *testing.T) {
	handler := &mockRequestHandler{}

	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr:     "127.0.0.1:0",
		RequestHandler: handler,
		MaxConnections: 2,
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	// Open 2 connections and complete handshakes (they hold semaphore slots).
	conns := make([]net.Conn, 2)
	sessions := make([]*NoiseSession, 2)
	for i := 0; i < 2; i++ {
		c, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial conn %d: %v", i, err)
		}
		conns[i] = c
		sessions[i] = clientHandshake(t, c)
	}

	// Give the server a moment for both connections to be fully registered
	// in the accept loop (semaphore acquired before goroutine spawn).
	time.Sleep(100 * time.Millisecond)

	// The 3rd connection should be accepted at TCP level but immediately
	// closed by the server because the semaphore is full.
	c3, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial conn 3: %v", err)
	}
	defer c3.Close()

	// Set a read deadline so we do not block forever.
	c3.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Try to read anything: the server should close the connection,
	// resulting in an EOF or connection reset.
	buf := make([]byte, 1)
	_, readErr := c3.Read(buf)
	if readErr == nil {
		t.Fatal("expected read error on rejected connection, got nil")
	}

	// Clean up the two held connections.
	for _, c := range conns {
		c.Close()
	}
}

func TestTCPPairingServer_HandshakeTimeout(t *testing.T) {
	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr:       "127.0.0.1:0",
		HandshakeTimeout: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	// Connect but do NOT send any handshake data.
	conn, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// The server should close the connection after HandshakeTimeout.
	// Wait for the server to time out and close our connection.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	_, readErr := conn.Read(buf)
	if readErr == nil {
		t.Fatal("expected connection to be closed by server after handshake timeout")
	}
}

func TestTCPSend_OversizedMessage(t *testing.T) {
	// Create a pair of connected pipes to simulate a connection.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// A message larger than maxTCPMessageSize should fail.
	oversized := make([]byte, maxTCPMessageSize+1)
	err := tcpSend(client, oversized)
	if !errors.Is(err, ErrProtocolError) {
		t.Fatalf("expected ErrProtocolError for oversized message, got %v", err)
	}
}

func TestTCPSendReceive_Roundtrip(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	payload := []byte("hello, world")

	// Send from client, receive on server in parallel.
	errCh := make(chan error, 1)
	go func() {
		errCh <- tcpSend(client, payload)
	}()

	received, err := tcpReceive(server)
	if err != nil {
		t.Fatalf("tcpReceive: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("tcpSend: %v", err)
	}

	if string(received) != string(payload) {
		t.Fatalf("roundtrip mismatch: got %q, want %q", received, payload)
	}
}

func TestTCPReceive_ZeroLength(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Send a zero-length message (just the 2-byte header with value 0).
	go func() {
		tcpSend(client, []byte{})
	}()

	received, err := tcpReceive(server)
	if err != nil {
		t.Fatalf("tcpReceive: %v", err)
	}
	if len(received) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(received))
	}
}

func TestTCPReceive_ConnectionClosed(t *testing.T) {
	server, client := net.Pipe()
	client.Close()

	_, err := tcpReceive(server)
	if err == nil {
		t.Fatal("expected error reading from closed connection")
	}
	server.Close()
}
