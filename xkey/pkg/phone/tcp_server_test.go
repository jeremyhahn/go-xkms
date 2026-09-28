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
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
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
func clientHandshake(t *testing.T, conn net.Conn) *pairing.NoiseSession {
	t.Helper()

	clientKey, err := pairing.GenerateStaticKey()
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}

	clientSession, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{
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
	key, err := pairing.GenerateStaticKey()
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
	sessions := make([]*pairing.NoiseSession, 2)
	for i := 0; i < 2; i++ {
		c, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial conn %d: %v", i, err)
		}
		conns[i] = c
		sessions[i] = clientHandshake(t, c)
	}

	// No wait needed: the accept loop is single-threaded and acquires the
	// semaphore slot before spawning each connection's handler goroutine, so
	// a completed handshake already proves that connection's slot was taken.
	//
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

// failingDeadlineConn wraps a net.Conn and lets tests force SetDeadline /
// SetReadDeadline / SetWriteDeadline to fail regardless of the underlying
// connection's real state. A real net.Conn essentially only fails these
// calls once already closed, at which point the following Read/Write would
// fail too and mask the deadline-specific code path; this decorator
// reproduces the failure deterministically on an otherwise healthy pipe.
type failingDeadlineConn struct {
	net.Conn
	failSetDeadline      bool
	failSetReadDeadline  bool
	failSetWriteDeadline bool
}

var errInjectedDeadlineFailure = errors.New("injected deadline failure")

func (c *failingDeadlineConn) SetDeadline(t time.Time) error {
	if c.failSetDeadline {
		return errInjectedDeadlineFailure
	}
	return c.Conn.SetDeadline(t)
}

func (c *failingDeadlineConn) SetReadDeadline(t time.Time) error {
	if c.failSetReadDeadline {
		return errInjectedDeadlineFailure
	}
	return c.Conn.SetReadDeadline(t)
}

func (c *failingDeadlineConn) SetWriteDeadline(t time.Time) error {
	if c.failSetWriteDeadline {
		return errInjectedDeadlineFailure
	}
	return c.Conn.SetWriteDeadline(t)
}

// TestTCPPairingServer_HandshakeDeadlineFailureReturnsPromptly verifies that
// handleConnection treats a SetDeadline failure as fatal. Before this was
// handled, the error from SetDeadline was discarded and the handshake read
// that follows had no deadline at all: on a healthy but non-deadline-capable
// connection, that read blocks forever instead of ever timing out. Here nothing
// is ever written to the pipe, so the old behavior would hang this test.
func TestTCPPairingServer_HandshakeDeadlineFailureReturnsPromptly(t *testing.T) {
	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		HandshakeTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}

	client, server := net.Pipe()
	defer client.Close()
	wrapped := &failingDeadlineConn{Conn: server, failSetDeadline: true}

	// handleConnection expects to be entered the same way acceptLoop enters
	// it: a semaphore slot already acquired and the WaitGroup already counting
	// this connection.
	srv.connSem <- struct{}{}
	srv.wg.Add(1)

	done := make(chan struct{})
	go func() {
		srv.handleConnection(wrapped)
		close(done)
	}()

	select {
	case <-done:
		// handleConnection returned promptly after the deadline failure,
		// as expected.
	case <-time.After(2 * time.Second):
		t.Fatal("handleConnection did not return after SetDeadline failure; " +
			"it is blocked reading with no deadline set")
	}
}

// TestTCPPairingServer_RequestLoopReadDeadlineFailureReturnsPromptly verifies
// that requestLoop treats a SetReadDeadline failure as fatal for the same
// reason: silently reading with no idle-timeout deadline set would hang this
// test forever since nothing is ever written to the pipe.
func TestTCPPairingServer_RequestLoopReadDeadlineFailureReturnsPromptly(t *testing.T) {
	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		IdleTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}

	client, server := net.Pipe()
	defer client.Close()
	wrapped := &failingDeadlineConn{Conn: server, failSetReadDeadline: true}

	// requestLoop returns before ever touching session on this failure path,
	// so a nil session is safe here.
	done := make(chan struct{})
	go func() {
		srv.requestLoop(wrapped, nil, "test")
		close(done)
	}()

	select {
	case <-done:
		// requestLoop returned promptly after the deadline failure, as
		// expected.
	case <-time.After(2 * time.Second):
		t.Fatal("requestLoop did not return after SetReadDeadline failure; " +
			"it is blocked reading with no deadline set")
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

// TestTCPPairingServer_StopKeepsSuppliedKey checks the ownership half of the
// protected-memory contract: a key handed in through the config belongs to the
// caller, so Stop must leave it usable. Destroying a borrowed key would free
// pages another session is still reading.
func TestTCPPairingServer_StopKeepsSuppliedKey(t *testing.T) {
	key, err := pairing.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	defer key.Destroy()

	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr:     "127.0.0.1:0",
		LocalStaticKey: key,
		RequestHandler: &mockRequestHandler{},
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

	// Still intact: Destroy zeroes the key pair, so a live private half is
	// what distinguishes "left alone" from "freed".
	if len(key.Private) != pairing.NoiseKeySize {
		t.Fatalf("supplied key was destroyed by Stop: private half is %d bytes, want %d",
			len(key.Private), pairing.NoiseKeySize)
	}
	if _, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{LocalStaticKey: key, IsInitiator: true}); err != nil {
		t.Fatalf("supplied key unusable after Stop: %v", err)
	}
}

// TestTCPPairingServer_StopReleasesGeneratedKey is the other half: a key the
// server generated itself has no other owner, so Stop must release it rather
// than leave a locked page resident.
func TestTCPPairingServer_StopReleasesGeneratedKey(t *testing.T) {
	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr:     "127.0.0.1:0",
		RequestHandler: &mockRequestHandler{},
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}
	if !srv.ownsStaticKey {
		t.Fatal("server generated its own key but did not claim ownership")
	}

	// Hold a reference to the key itself, not just to the field. Asserting
	// srv.localStaticKey == nil after Stop only proves the POINTER was
	// cleared, which a Stop that dropped the reference without destroying the
	// key would satisfy while leaking a locked page for the life of the
	// process. The observable property is the wipe, and it is only observable
	// through a reference taken beforehand.
	generated := srv.localStaticKey
	if generated == nil {
		t.Fatal("server claimed ownership of a nil key")
	}
	if len(generated.Private) != pairing.NoiseKeySize {
		t.Fatalf("generated key private half is %d bytes, want %d",
			len(generated.Private), pairing.NoiseKeySize)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if len(generated.Private) != 0 {
		t.Fatalf("Stop left the generated key resident: private half is %d bytes",
			len(generated.Private))
	}
	if len(generated.Public) != 0 {
		t.Fatalf("Stop left the generated key pair populated: public half is %d bytes",
			len(generated.Public))
	}
	if srv.localStaticKey != nil {
		t.Fatal("Stop left the generated key in place")
	}
	if got := srv.LocalStaticPublicKey(); got != nil {
		t.Fatalf("public key still readable after Stop: %x", got)
	}
}

// TestTCPPairingServer_StopReleasesKeyAfterFailedStart covers the gap between
// construction and a successful bind. NewTCPPairingServer generates and owns
// the key, so a Start that cannot bind would otherwise strand a locked page
// with no cleanup path — Stop reported "not running" and returned early.
func TestTCPPairingServer_StopReleasesKeyAfterFailedStart(t *testing.T) {
	// Occupy an address so the server's bind is guaranteed to fail.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = occupied.Close() }()

	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr:     occupied.Addr().String(),
		RequestHandler: &mockRequestHandler{},
	})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}
	if !srv.ownsStaticKey {
		t.Fatal("server generated its own key but did not claim ownership")
	}

	if err := srv.Start(); !errors.Is(err, ErrTCPServerStartFailed) {
		t.Fatalf("Start on an occupied address: expected ErrTCPServerStartFailed, got %v", err)
	}

	// Stop still reports that nothing was listening, and still cleans up.
	if err := srv.Stop(); !errors.Is(err, ErrTCPServerNotRunning) {
		t.Fatalf("Stop after failed Start: expected ErrTCPServerNotRunning, got %v", err)
	}
	if srv.localStaticKey != nil {
		t.Fatal("Stop left the generated key in place after a failed Start")
	}

	// Repeatable: a second Stop must not double-destroy or panic.
	if err := srv.Stop(); !errors.Is(err, ErrTCPServerNotRunning) {
		t.Fatalf("second Stop: expected ErrTCPServerNotRunning, got %v", err)
	}
}

// hangingHandler ignores its context entirely, which is what a
// caller-supplied handler is free to do and what closing the socket cannot
// fix.
type hangingHandler struct{ released chan struct{} }

func (h *hangingHandler) HandleRequest(context.Context, []byte) ([]byte, error) {
	<-h.released
	return nil, nil
}

// TestStopBoundsTheHandlerJoin covers the last unbounded drain in this
// package, and the deadlock hiding behind it.
//
// Stop waited on the connection WaitGroup without a bound, holding
// lifecycleMu the whole time. Connection workers call a caller-supplied
// RequestHandler synchronously, so a handler that ignores cancellation is not
// interrupted by closing the socket — Stop simply never returns. Worse, any
// handler that called LocalStaticPublicKey would take the read side of
// lifecycleMu and deadlock against the Stop waiting for it.
func TestStopBoundsTheHandlerJoin(t *testing.T) {
	original := serverShutdownTimeout
	serverShutdownTimeout = 150 * time.Millisecond
	t.Cleanup(func() { serverShutdownTimeout = original })

	handler := &hangingHandler{released: make(chan struct{})}
	defer close(handler.released)

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

	// Occupy a handler slot the way a stuck connection does.
	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		<-handler.released
	}()

	stopped := make(chan error, 1)
	go func() { stopped <- srv.Stop() }()

	select {
	case err := <-stopped:
		if !errors.Is(err, ErrShutdownIncomplete) {
			t.Fatalf("Stop returned %v, want ErrShutdownIncomplete", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop never returned: the handler join is still unbounded")
	}

	// The key must survive: a handler still running may be reading it.
	if srv.ownsStaticKey && srv.localStaticKey == nil {
		t.Fatal("Stop released the static key while a handler was still running")
	}
}

// TestSecondStopDoesNotDestroyARetainedKey covers the way an incomplete
// shutdown could be undone by a second caller.
//
// The first Stop times out, reports ErrShutdownIncomplete and deliberately
// retains the static key because a handler may still be reading it. A second
// Stop then found running already false, skipped the join entirely, kept its
// local joined=true, and destroyed that key — reintroducing precisely the
// use-after-free the bounded join exists to prevent. Both callers now observe
// the same latched outcome.
func TestSecondStopDoesNotDestroyARetainedKey(t *testing.T) {
	original := serverShutdownTimeout
	serverShutdownTimeout = 100 * time.Millisecond
	t.Cleanup(func() { serverShutdownTimeout = original })

	handler := &hangingHandler{released: make(chan struct{})}
	defer close(handler.released)

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

	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		<-handler.released
	}()

	if err := srv.Stop(); !errors.Is(err, ErrShutdownIncomplete) {
		t.Fatalf("first Stop returned %v, want ErrShutdownIncomplete", err)
	}
	if srv.localStaticKey == nil {
		t.Fatal("the first Stop released the key it reported retaining")
	}

	// The second call must report the same thing and change nothing.
	if err := srv.Stop(); !errors.Is(err, ErrShutdownIncomplete) {
		t.Fatalf("second Stop returned %v, want the first outcome", err)
	}
	if srv.localStaticKey == nil {
		t.Fatal("the second Stop destroyed a key the first had retained")
	}
	if len(srv.localStaticKey.Private) == 0 {
		t.Fatal("the retained key's protected pages were wiped by the second Stop")
	}
}

// TestTCPPairingServer_OwnsSuppliedKey covers the OwnsStaticKey branch of
// NewTCPPairingServer: when the caller transfers a key it generated (rather
// than leaving LocalStaticKey nil for the server to generate one), the
// server must claim ownership, consume the key out of the config so a reused
// config cannot hand the same protected pages to a second owner, and destroy
// it on Stop exactly like a key it generated itself.
func TestTCPPairingServer_OwnsSuppliedKey(t *testing.T) {
	key, err := pairing.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	cfg := &TCPPairingConfig{
		ListenAddr:     "127.0.0.1:0",
		LocalStaticKey: key,
		OwnsStaticKey:  true,
		RequestHandler: &mockRequestHandler{},
	}
	srv, err := NewTCPPairingServer(cfg)
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}
	if !srv.ownsStaticKey {
		t.Fatal("server did not claim ownership of the transferred key")
	}
	if cfg.LocalStaticKey != nil {
		t.Fatal("config still holds the key after ownership transferred; a " +
			"reused config would hand it to a second owner")
	}
	if srv.localStaticKey != key {
		t.Fatal("server did not retain the exact key instance the caller supplied")
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if len(key.Private) != 0 {
		t.Fatalf("Stop left the owned key resident: private half is %d bytes, want 0",
			len(key.Private))
	}
}

// TestTCPPairingServer_TrackConnInitializesNilMap covers trackConn's lazy
// initialization of the connection set. registerConn always goes through
// NewTCPPairingServer, which pre-populates conns, so this exercises the
// defensive path directly: a server value that never went through the
// constructor must still register connections correctly rather than panic
// on a nil map write.
func TestTCPPairingServer_TrackConnInitializesNilMap(t *testing.T) {
	s := &TCPPairingServer{}
	if s.conns != nil {
		t.Fatal("test setup: expected a nil conns map")
	}

	conn, remote := net.Pipe()
	defer conn.Close()
	defer remote.Close()

	s.trackConn(conn)

	if _, ok := s.conns[conn]; !ok {
		t.Fatal("trackConn did not register the connection in the lazily-initialized map")
	}
}

// errInjectedTransientAccept is a stand-in for a transient Accept() failure
// that is not the listener-closed-during-shutdown case acceptLoop already
// special-cases.
var errInjectedTransientAccept = errors.New("injected transient accept error")

// flakyOnceListener fails its first Accept call with errInjectedTransientAccept,
// then delegates every later call to the wrapped listener.
type flakyOnceListener struct {
	net.Listener
	failed atomic.Bool
}

func (l *flakyOnceListener) Accept() (net.Conn, error) {
	if !l.failed.Swap(true) {
		return nil, errInjectedTransientAccept
	}
	return l.Listener.Accept()
}

// TestAcceptLoop_TransientErrorContinuesAccepting proves acceptLoop logs and
// retries a transient (non-shutdown) Accept error instead of exiting the
// loop: a listener that errors once, then a real client that completes a
// full handshake afterward, shows the loop kept serving.
func TestAcceptLoop_TransientErrorContinuesAccepting(t *testing.T) {
	real, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer real.Close()

	srv, err := NewTCPPairingServer(&TCPPairingConfig{Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatalf("NewTCPPairingServer: %v", err)
	}
	srv.listener = &flakyOnceListener{Listener: real}

	srv.wg.Add(1)
	go srv.acceptLoop()
	defer func() {
		srv.closed.Store(true)
		real.Close()
		srv.wg.Wait()
	}()

	conn, err := net.DialTimeout("tcp", real.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial after injected transient accept error: %v", err)
	}
	defer conn.Close()

	// Completing a full Noise handshake proves handleConnection actually ran
	// for this connection, not just that the TCP-level accept succeeded.
	clientHandshake(t, conn)
}
