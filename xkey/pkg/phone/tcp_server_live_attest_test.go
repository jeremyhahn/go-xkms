// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
)

// TestTCPPairingServer_LiveAttestNil_RefusesConnection verifies that a
// server with no LiveAttest configured closes a connection immediately after
// the Noise handshake, before any request is served -- go-xkms#1306, closing
// the gap where a phone-initiated session served the full bridge on Noise
// static-key possession alone.
func TestTCPPairingServer_LiveAttestNil_RefusesConnection(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	handler := &mockRequestHandler{response: []byte(`{"jsonrpc":"2.0","id":1,"result":{"pong":true}}`)}
	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr:     "127.0.0.1:0",
		RequestHandler: handler,
		// LiveAttest deliberately left nil.
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

	clientHandshake(t, conn)

	// The server must close the connection rather than serve anything: the
	// next read observes EOF (or a reset), never a request/response cycle.
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := tcpReceive(conn); err == nil {
		t.Fatal("expected the connection to be closed after an unattested handshake, got a message instead")
	}
}

// TestTCPPairingServer_LiveAttest_DeniedRefusesConnection verifies that a
// configured verifier which refuses the request closes the connection before
// the request loop starts, and never runs the RequestHandler.
func TestTCPPairingServer_LiveAttest_DeniedRefusesConnection(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	handler := &mockRequestHandler{response: []byte(`{"jsonrpc":"2.0","id":1,"result":{"pong":true}}`)}
	denyErr := errors.New("test: attestation refused")
	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr:     "127.0.0.1:0",
		RequestHandler: handler,
		LiveAttest: func(context.Context, pairingproto.RPCExchange, []byte) error {
			return denyErr
		},
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

	clientHandshake(t, conn)

	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := tcpReceive(conn); err == nil {
		t.Fatal("expected the connection to be closed after a denied attestation, got a message instead")
	}

	if len(handler.receivedRequests()) != 0 {
		t.Fatal("RequestHandler must not run when live attestation is denied")
	}
}

// TestTCPPairingServer_LiveAttest_ChallengeExchange drives the verifier's
// exchange over the real wire: the server sends a request THROUGH the
// InlineExchange plumbing, a fake phone on the other end answers it, and the
// verifier's own judgment of that answer decides whether the request loop
// ever starts. This is the same shape local.attestDevice uses in production;
// the wire content here is deliberately just something InlineExchange must
// round-trip correctly, not the real attestation protocol.
func TestTCPPairingServer_LiveAttest_ChallengeExchange(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	handler := &mockRequestHandler{response: []byte(`{"jsonrpc":"2.0","id":1,"result":{"pong":true}}`)}

	var sawMethod string
	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr:     "127.0.0.1:0",
		RequestHandler: handler,
		LiveAttest: func(ctx context.Context, exchange pairingproto.RPCExchange, binding []byte) error {
			if len(binding) == 0 {
				return errors.New("test: empty channel binding")
			}
			resp, err := exchange(ctx, pairingproto.NewRequest("local.attestDevice", map[string]string{"nonce": "test"}))
			if err != nil {
				return err
			}
			if resp.Error != nil {
				return errors.New("test: phone refused the challenge")
			}
			return nil
		},
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

	// The fake phone: read the server's challenge, decrypt it, and answer
	// with a successful JSON-RPC response carrying the same request ID.
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	challengeCiphertext, err := tcpReceive(conn)
	if err != nil {
		t.Fatalf("receive challenge: %v", err)
	}
	challengePlaintext, err := clientSession.Decrypt(challengeCiphertext)
	if err != nil {
		t.Fatalf("decrypt challenge: %v", err)
	}
	req, err := pairingproto.DecodeRequest(challengePlaintext)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	sawMethod = req.Method

	respBytes, err := pairingproto.EncodeResponse(req.ID, req.Generation, map[string]bool{"ok": true})
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	respCiphertext, err := clientSession.Encrypt(respBytes)
	if err != nil {
		t.Fatalf("encrypt response: %v", err)
	}
	if err := tcpSend(conn, respCiphertext); err != nil {
		t.Fatalf("send response: %v", err)
	}

	if sawMethod != "local.attestDevice" {
		t.Fatalf("expected the server to challenge with local.attestDevice, got %q", sawMethod)
	}

	// With the gate satisfied, the ordinary request loop now serves requests.
	pingReq := `{"jsonrpc":"2.0","id":2,"method":"ping"}`
	encryptedPing, err := clientSession.Encrypt([]byte(pingReq))
	if err != nil {
		t.Fatalf("encrypt ping: %v", err)
	}
	if err := tcpSend(conn, encryptedPing); err != nil {
		t.Fatalf("send ping: %v", err)
	}
	pingRespCiphertext, err := tcpReceive(conn)
	if err != nil {
		t.Fatalf("receive ping response: %v", err)
	}
	pingRespPlaintext, err := clientSession.Decrypt(pingRespCiphertext)
	if err != nil {
		t.Fatalf("decrypt ping response: %v", err)
	}
	if string(pingRespPlaintext) != string(handler.response) {
		t.Fatalf("ping response mismatch:\n  got:  %s\n  want: %s", pingRespPlaintext, handler.response)
	}
}
