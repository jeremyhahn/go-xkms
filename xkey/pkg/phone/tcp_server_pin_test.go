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
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
)

// TestNewTCPPairingServer_RejectsInvalidPin mirrors
// TestNewBLEPeripheral_RejectsInvalidPin for the TCP responder
// (go-xkms#1306): a caller that supplies ExpectedRemoteStatic but the value
// is not a usable Noise static key -- empty, or any length other than
// NoiseKeySize -- must be refused rather than silently accepted as "nothing
// to pin". An omitted (nil) ExpectedRemoteStatic is the one value that
// legitimately means unpinned, and must still construct successfully.
func TestNewTCPPairingServer_RejectsInvalidPin(t *testing.T) {
	tests := []struct {
		name    string
		pin     []byte
		wantErr error
	}{
		{name: "nil is unpinned, not an error", pin: nil, wantErr: nil},
		{name: "empty is refused", pin: []byte{}, wantErr: ErrTCPServerInvalidPin},
		{name: "too short is refused", pin: make([]byte, bootstrap.NoiseKeySize-1), wantErr: ErrTCPServerInvalidPin},
		{name: "too long is refused", pin: make([]byte, bootstrap.NoiseKeySize+1), wantErr: ErrTCPServerInvalidPin},
		{name: "correct length is accepted", pin: make([]byte, bootstrap.NoiseKeySize), wantErr: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, err := NewTCPPairingServer(&TCPPairingConfig{ExpectedRemoteStatic: tt.pin})
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("got error %v, want %v", err, tt.wantErr)
				}
				if srv != nil {
					t.Fatal("a refused construction must not return a server")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewTCPPairingServer failed: %v", err)
			}
		})
	}
}

// TestTCPPairingServer_PinRefusesAnUnexpectedInitiator proves the pin is
// enforced on the wire, not merely accepted as configuration: a client
// holding a DIFFERENT static key than ExpectedRemoteStatic fails the Noise
// handshake, and the request loop is never reached (go-xkms#1306 closes the
// gap where the relay "pinned nothing").
func TestTCPPairingServer_PinRefusesAnUnexpectedInitiator(t *testing.T) {
	// The key the server expects -- NOT the one the test client below uses.
	expectedKey, err := bootstrap.GenerateNoiseStaticKey()
	if err != nil {
		t.Fatalf("generate expected key: %v", err)
	}
	defer expectedKey.Destroy()

	handler := &mockRequestHandler{response: []byte(`{"jsonrpc":"2.0","id":1,"result":{"pong":true}}`)}
	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr:           "127.0.0.1:0",
		RequestHandler:       handler,
		LiveAttest:           alwaysLiveAttestForTest,
		ExpectedRemoteStatic: expectedKey.PublicBytes(),
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

	// clientHandshake generates and uses its OWN static key -- unrelated to
	// expectedKey -- exactly the "wrong phone" scenario the pin exists to
	// refuse. The client completes its own (local) view of the handshake
	// and sends msg3 regardless; the pin is enforced when the SERVER
	// processes msg3 and finds the initiator's static key does not match
	// ExpectedRemoteStatic, so the observable effect from here is the
	// server closing the connection rather than serving anything.
	clientHandshake(t, conn)

	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := tcpReceive(conn); err == nil {
		t.Fatal("expected the connection to be closed for an unpinned static key, got a message instead")
	}

	if len(handler.receivedRequests()) != 0 {
		t.Fatal("RequestHandler must not run when the pin rejects the initiator")
	}
}
