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

//go:build ble

package phone

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// echoHandler returns the request wrapped in a JSON-RPC result so the test can
// prove the handler output is what reached the peer.
type echoHandler struct {
	err error
}

func (h *echoHandler) HandleRequest(_ context.Context, request []byte) ([]byte, error) {
	if h.err != nil {
		return nil, h.err
	}
	return []byte(`{"jsonrpc":"2.0","result":"` + string(request) + `"}`), nil
}

// newTestPeripheral builds a peripheral whose notify path is wired to an
// in-memory writer. Nothing here touches Bluetooth hardware: only the
// fragmentation and notify plumbing is under test.
func newTestPeripheral(t *testing.T, handler PeripheralRequestHandler, writer FragmentWriter) *BLEPeripheral {
	t.Helper()

	p, err := NewBLEPeripheral(&BLEPeripheralConfig{
		DeviceName:     "xKey-test",
		RequestHandler: handler,
	})
	if err != nil {
		t.Fatalf("NewBLEPeripheral failed: %v", err)
	}

	p.notifier = writer
	p.fragmenter = NewFragmenter(p.mtu - bleNotifyOverhead)
	p.reassembler = NewReassembler()
	p.sender = newFragmentSender(p.notifier, p.fragmenter, p.log)
	return p
}

// establishSession runs a complete Noise XX handshake in memory and returns
// the initiator session paired with the peripheral's responder session.
func establishSession(t *testing.T, p *BLEPeripheral) *NoiseSession {
	t.Helper()

	initiatorKey, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("initiator key: %v", err)
	}
	responderKey, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("responder key: %v", err)
	}

	initiator, err := NewNoiseSession(&NoiseSessionConfig{
		LocalStaticKey: initiatorKey,
		IsInitiator:    true,
	})
	if err != nil {
		t.Fatalf("initiator session: %v", err)
	}
	responder, err := NewNoiseSession(&NoiseSessionConfig{
		LocalStaticKey: responderKey,
		IsInitiator:    false,
	})
	if err != nil {
		t.Fatalf("responder session: %v", err)
	}

	if err := initiator.InitHandshake(); err != nil {
		t.Fatalf("initiator init: %v", err)
	}
	if err := responder.InitHandshake(); err != nil {
		t.Fatalf("responder init: %v", err)
	}

	msg1, _, err := initiator.HandshakeMessage(nil)
	if err != nil {
		t.Fatalf("msg1: %v", err)
	}
	msg2, _, err := responder.HandshakeMessage(msg1)
	if err != nil {
		t.Fatalf("msg2: %v", err)
	}
	msg3, _, err := initiator.HandshakeMessage(msg2)
	if err != nil {
		t.Fatalf("msg3: %v", err)
	}
	if _, complete, err := responder.HandshakeMessage(msg3); err != nil || !complete {
		t.Fatalf("responder handshake incomplete: complete=%v err=%v", complete, err)
	}
	if !initiator.IsHandshakeComplete() {
		t.Fatal("initiator handshake incomplete")
	}

	// Publish the same way AcceptConnection does, so the helper cannot drift
	// from production again: setting p.session directly skipped the
	// public-key snapshot and left LocalStaticPublicKey returning nothing.
	p.publishSession(responder)
	return initiator
}

func TestBLEPeripheral_ProcessRequestNotifiesResponse(t *testing.T) {
	writer := newCaptureWriter()
	p := newTestPeripheral(t, &echoHandler{}, writer)
	initiator := establishSession(t, p)

	request := []byte(`{"jsonrpc":"2.0","method":"ping","id":1}`)
	encrypted, err := initiator.Encrypt(request)
	if err != nil {
		t.Fatalf("encrypt request: %v", err)
	}

	if err := p.processRequest(context.Background(), encrypted); err != nil {
		t.Fatalf("processRequest failed: %v", err)
	}

	if writer.count() == 0 {
		t.Fatal("processRequest transmitted nothing: the notify path is dead")
	}

	// Reassemble exactly as the phone would, then decrypt with the peer
	// session: this proves real ciphertext reached the peer.
	ciphertext := writer.reassemble(t)
	plaintext, err := initiator.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt response: %v", err)
	}
	want := `{"jsonrpc":"2.0","result":"` + string(request) + `"}`
	if string(plaintext) != want {
		t.Fatalf("got %q, want %q", plaintext, want)
	}
}

func TestBLEPeripheral_ProcessRequestLargeResponseFragments(t *testing.T) {
	// A response larger than one fragment must arrive byte-identical.
	large := strings.Repeat("A", 4096)
	writer := newCaptureWriter()
	p := newTestPeripheral(t, &echoHandler{}, writer)
	initiator := establishSession(t, p)

	encrypted, err := initiator.Encrypt([]byte(large))
	if err != nil {
		t.Fatalf("encrypt request: %v", err)
	}
	if err := p.processRequest(context.Background(), encrypted); err != nil {
		t.Fatalf("processRequest failed: %v", err)
	}

	if writer.count() < 2 {
		t.Fatalf("expected a fragmented response, got %d fragment(s)", writer.count())
	}

	plaintext, err := initiator.Decrypt(writer.reassemble(t))
	if err != nil {
		t.Fatalf("decrypt response: %v", err)
	}
	if string(plaintext) != `{"jsonrpc":"2.0","result":"`+large+`"}` {
		t.Fatal("large response did not round trip byte-identically")
	}
}

func TestBLEPeripheral_ProcessRequestPropagatesSendFailure(t *testing.T) {
	writer := newCaptureWriter()
	writer.failAt = 0
	p := newTestPeripheral(t, &echoHandler{}, writer)
	initiator := establishSession(t, p)

	encrypted, err := initiator.Encrypt([]byte(`{"jsonrpc":"2.0","method":"ping","id":1}`))
	if err != nil {
		t.Fatalf("encrypt request: %v", err)
	}

	err = p.processRequest(context.Background(), encrypted)
	if err == nil {
		t.Fatal("processRequest reported success while the transport rejected the response")
	}
	if !errors.Is(err, errNotifyWrite) {
		t.Fatalf("expected the transport failure to propagate, got %v", err)
	}
}

func TestBLEPeripheral_ProcessRequestHandlerErrorStillNotifies(t *testing.T) {
	// A handler failure must still produce a JSON-RPC error response on the
	// wire; the phone otherwise blocks until its receive timeout.
	writer := newCaptureWriter()
	p := newTestPeripheral(t, &echoHandler{err: errors.New("handler exploded")}, writer)
	initiator := establishSession(t, p)

	encrypted, err := initiator.Encrypt([]byte(`{"jsonrpc":"2.0","method":"boom","id":2}`))
	if err != nil {
		t.Fatalf("encrypt request: %v", err)
	}
	if err := p.processRequest(context.Background(), encrypted); err != nil {
		t.Fatalf("processRequest failed: %v", err)
	}

	plaintext, err := initiator.Decrypt(writer.reassemble(t))
	if err != nil {
		t.Fatalf("decrypt response: %v", err)
	}
	if !strings.Contains(string(plaintext), `"code":-32603`) {
		t.Fatalf("expected an internal error response, got %s", plaintext)
	}
}

func TestBLEPeripheral_ProcessRequestRejectsUndecryptableData(t *testing.T) {
	writer := newCaptureWriter()
	p := newTestPeripheral(t, &echoHandler{}, writer)
	establishSession(t, p)

	err := p.processRequest(context.Background(), []byte("not a valid ciphertext"))
	if err == nil {
		t.Fatal("expected a decrypt failure")
	}
	if writer.count() != 0 {
		t.Fatalf("expected nothing to be transmitted, got %d fragments", writer.count())
	}
}

func TestBLEPeripheral_HandshakePropagatesSendFailure(t *testing.T) {
	// performHandshake must fail loudly when msg2 cannot be transmitted;
	// before the notify path existed it returned nil and the session hung.
	writer := newCaptureWriter()
	writer.failAt = 0
	p := newTestPeripheral(t, &echoHandler{}, writer)

	responderKey, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("responder key: %v", err)
	}
	p.session, err = NewNoiseSession(&NoiseSessionConfig{
		LocalStaticKey: responderKey,
		IsInitiator:    false,
	})
	if err != nil {
		t.Fatalf("responder session: %v", err)
	}

	initiatorKey, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("initiator key: %v", err)
	}
	initiator, err := NewNoiseSession(&NoiseSessionConfig{
		LocalStaticKey: initiatorKey,
		IsInitiator:    true,
	})
	if err != nil {
		t.Fatalf("initiator session: %v", err)
	}
	if err := initiator.InitHandshake(); err != nil {
		t.Fatalf("initiator init: %v", err)
	}
	msg1, _, err := initiator.HandshakeMessage(nil)
	if err != nil {
		t.Fatalf("msg1: %v", err)
	}

	// Deliver msg1 as the peripheral's receive loop would: one fragment at a
	// time on the incoming channel.
	fragments, err := p.fragmenter.Fragment(msg1)
	if err != nil {
		t.Fatalf("fragment msg1: %v", err)
	}
	for _, frag := range fragments {
		p.incomingData <- frag
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := p.performHandshake(ctx); err == nil {
		t.Fatal("performHandshake reported success while msg2 was never transmitted")
	} else if !errors.Is(err, errNotifyWrite) {
		t.Fatalf("expected the transport failure to propagate, got %v", err)
	}
}

func TestBLEPeripheral_SendMessageWithoutNotifier(t *testing.T) {
	p, err := NewBLEPeripheral(&BLEPeripheralConfig{DeviceName: "xKey-test"})
	if err != nil {
		t.Fatalf("NewBLEPeripheral failed: %v", err)
	}

	// No GATT service registered: sendMessage must refuse rather than
	// pretend the message was delivered.
	if err := p.sendMessage(context.Background(), []byte("payload")); !errors.Is(err, ErrNotifyUnavailable) {
		t.Fatalf("expected ErrNotifyUnavailable, got %v", err)
	}
}

func TestNewBLEPeripheral_MTUSelection(t *testing.T) {
	tests := []struct {
		name string
		cfg  *BLEPeripheralConfig
		want int
	}{
		{name: "nil config", cfg: nil, want: DefaultMTU},
		{name: "unset MTU", cfg: &BLEPeripheralConfig{}, want: DefaultMTU},
		{name: "below minimum", cfg: &BLEPeripheralConfig{MTU: 8}, want: DefaultMTU},
		{name: "explicit MTU", cfg: &BLEPeripheralConfig{MTU: 512}, want: 512},
		{name: "minimum MTU", cfg: &BLEPeripheralConfig{MTU: MinMTU}, want: MinMTU},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewBLEPeripheral(tt.cfg)
			if err != nil {
				t.Fatalf("NewBLEPeripheral failed: %v", err)
			}
			if p.mtu != tt.want {
				t.Fatalf("got MTU %d, want %d", p.mtu, tt.want)
			}
		})
	}
}

func TestBLEPeripheral_HandleRequestsReassemblesFragments(t *testing.T) {
	// The control point delivers BLE-sized fragments. A request larger than
	// one fragment must be reassembled before it is decrypted, otherwise the
	// session sees fragment headers instead of ciphertext.
	writer := newCaptureWriter()
	p := newTestPeripheral(t, &echoHandler{}, writer)
	initiator := establishSession(t, p)

	request := []byte(strings.Repeat("R", 2048))
	encrypted, err := initiator.Encrypt(request)
	if err != nil {
		t.Fatalf("encrypt request: %v", err)
	}
	fragments, err := p.fragmenter.Fragment(encrypted)
	if err != nil {
		t.Fatalf("fragment request: %v", err)
	}
	if len(fragments) < 2 {
		t.Fatalf("expected a fragmented request, got %d fragment(s)", len(fragments))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- p.handleRequests(ctx) }()

	for _, frag := range fragments {
		p.incomingData <- frag
	}

	// Wait for the whole response: the last fragment carries the end-of-message
	// flag, so there is no need to guess at how long the handler needs.
	waitCtx, cancelWait := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWait()
	writer.waitForCompleteMessage(waitCtx, t)

	plaintext, err := initiator.Decrypt(writer.reassemble(t))
	if err != nil {
		t.Fatalf("decrypt response: %v", err)
	}
	if string(plaintext) != `{"jsonrpc":"2.0","result":"`+string(request)+`"}` {
		t.Fatal("fragmented request did not round trip")
	}

	if err := p.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("handleRequests returned %v, want nil after Stop", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handleRequests did not return after Stop")
	}
}

func TestBLEPeripheral_ReceiveMessageTimeout(t *testing.T) {
	p := newTestPeripheral(t, &echoHandler{}, newCaptureWriter())

	_, err := p.receiveMessageTimeout(context.Background(), 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected a receive timeout")
	}
	var msgErr *MessageError
	if !errors.As(err, &msgErr) {
		t.Fatalf("expected *MessageError, got %T: %v", err, err)
	}
}

func TestBLEPeripheral_ReceiveMessageContextCancelled(t *testing.T) {
	p := newTestPeripheral(t, &echoHandler{}, newCaptureWriter())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := p.receiveMessageTimeout(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestBLEPeripheral_ReceiveMessageDiscardsMalformedFragment(t *testing.T) {
	p := newTestPeripheral(t, &echoHandler{}, newCaptureWriter())

	// A truncated fragment header must be dropped, not mistaken for a
	// message, and must not poison the fragment that follows.
	p.incomingData <- []byte{0x01, 0x02}
	fragments, err := p.fragmenter.Fragment([]byte("hello"))
	if err != nil {
		t.Fatalf("fragment: %v", err)
	}
	for _, frag := range fragments {
		p.incomingData <- frag
	}

	message, err := p.receiveMessageTimeout(context.Background(), 2*time.Second)
	if err != nil {
		t.Fatalf("receive failed: %v", err)
	}
	if string(message) != "hello" {
		t.Fatalf("got %q, want %q", message, "hello")
	}
}

func TestBLEPeripheral_IsConnected(t *testing.T) {
	p := newTestPeripheral(t, &echoHandler{}, newCaptureWriter())
	if p.IsConnected() {
		t.Fatal("a fresh peripheral must not report a connected client")
	}

	p.connected.Store(true)
	if !p.IsConnected() {
		t.Fatal("expected the peripheral to report a connected client")
	}
}

func TestBLEPeripheral_LocalStaticPublicKey(t *testing.T) {
	p := newTestPeripheral(t, &echoHandler{}, newCaptureWriter())
	if key := p.LocalStaticPublicKey(); key != nil {
		t.Fatalf("expected no key before a session exists, got %d bytes", len(key))
	}

	establishSession(t, p)
	if key := p.LocalStaticPublicKey(); len(key) != 32 {
		t.Fatalf("expected a 32 byte X25519 public key, got %d bytes", len(key))
	}
}
