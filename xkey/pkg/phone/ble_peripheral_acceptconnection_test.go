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

//go:build ble

package phone

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// This file drives BLEPeripheral.AcceptConnection end to end -- the
// production entry point every real connection goes through -- with a
// simulated phone on the other end, entirely in memory. Nothing here opens a
// Bluetooth adapter: AcceptConnection itself never touches one (only Start
// and setupGATTService do, and those need real hardware CI does not have).
// What AcceptConnection touches is the notify path (already abstracted by
// FragmentWriter) and the incoming-data channel (already fed by handleWrite,
// itself hardware-free), so the whole connection lifecycle can be exercised
// here.

// fragmentChannelWriter is a FragmentWriter that delivers each fragment onto
// a channel in order, so a test can consume the peripheral's notifications
// as SEPARATE messages -- unlike captureWriter (ble_notify_test.go), which
// is built to capture exactly one message per test.
type fragmentChannelWriter struct {
	ch chan []byte
}

func newFragmentChannelWriter() *fragmentChannelWriter {
	return &fragmentChannelWriter{ch: make(chan []byte, 64)}
}

func (w *fragmentChannelWriter) Write(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	w.ch <- cp
	return len(p), nil
}

// nextMessage reassembles fragments read from w.ch until one complete
// message is available, failing the test if ctx expires first.
func (w *fragmentChannelWriter) nextMessage(ctx context.Context, t *testing.T) []byte {
	t.Helper()

	r := pairing.NewReassembler()
	for {
		select {
		case raw := <-w.ch:
			frag, err := pairing.DecodeFragment(raw)
			if err != nil {
				t.Fatalf("fragment failed to decode: %v", err)
			}
			complete, err := r.AddFragment(frag)
			if err != nil {
				t.Fatalf("fragment failed to reassemble: %v", err)
			}
			if complete {
				msg, err := r.Assemble()
				if err != nil {
					t.Fatalf("assemble failed: %v", err)
				}
				return msg
			}
		case <-ctx.Done():
			t.Fatalf("no complete message notified before %v", ctx.Err())
			return nil
		}
	}
}

// deliverToPeripheral fragments message the way a real phone's BLE stack
// would and hands each fragment to the peripheral through handleWrite -- the
// same entry point a GATT WriteEvent callback uses in production.
func deliverToPeripheral(t *testing.T, p *BLEPeripheral, mtu int, message []byte) {
	t.Helper()

	f := pairing.NewFragmenter(mtu - bleNotifyOverhead)
	fragments, err := f.Fragment(message)
	if err != nil {
		t.Fatalf("fragment message: %v", err)
	}
	for _, frag := range fragments {
		p.handleWrite(frag)
	}
}

// TestBLEPeripheral_AcceptConnection_HandshakeThenRequest drives the whole
// AcceptConnection lifecycle: registration, static key generation, the Noise
// XX handshake as responder, and one encrypted request/response -- all
// through the same channel and notifier a real connection uses.
func TestBLEPeripheral_AcceptConnection_HandshakeThenRequest(t *testing.T) {
	handler := &echoHandler{}
	writer := newFragmentChannelWriter()
	p := newTestPeripheral(t, handler, writer)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	acceptDone := make(chan error, 1)
	go func() { acceptDone <- p.AcceptConnection(ctx) }()

	// The simulated phone: a real Noise XX initiator.
	clientKey, err := pairing.GenerateStaticKey()
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	defer clientKey.Destroy()

	client, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{
		LocalStaticKey: clientKey,
		IsInitiator:    true,
	})
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	if err := client.InitHandshake(); err != nil {
		t.Fatalf("client init: %v", err)
	}

	msg1, _, err := client.HandshakeMessage(nil)
	if err != nil {
		t.Fatalf("client msg1: %v", err)
	}
	deliverToPeripheral(t, p, p.mtu, msg1)

	msg2 := writer.nextMessage(ctx, t)
	msg3, complete, err := client.HandshakeMessage(msg2)
	if err != nil {
		t.Fatalf("client msg3: %v", err)
	}
	if !complete {
		t.Fatal("client did not complete on its third message (e, ee, s, es then s, se)")
	}
	deliverToPeripheral(t, p, p.mtu, msg3)
	if !client.IsHandshakeComplete() {
		t.Fatal("client handshake did not complete after msg3")
	}

	// AcceptConnection has moved on to handleRequests by the time it consumes
	// this fragment, because the incoming-data channel preserves order: the
	// goroutine cannot see this before it has finished processing msg3.
	plaintext := []byte("ping-from-simulated-phone")
	ciphertext, err := client.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("client encrypt: %v", err)
	}
	deliverToPeripheral(t, p, p.mtu, ciphertext)

	respCiphertext := writer.nextMessage(ctx, t)
	respPlaintext, err := client.Decrypt(respCiphertext)
	if err != nil {
		t.Fatalf("client decrypt: %v", err)
	}
	if got := string(respPlaintext); got != `{"jsonrpc":"2.0","result":"ping-from-simulated-phone"}` {
		t.Fatalf("unexpected echoed response: %q", got)
	}

	if !p.connected.Load() {
		t.Fatal("peripheral did not report connected after a completed handshake")
	}
	if !p.IsConnected() {
		t.Fatal("IsConnected() must agree with the internal connected flag")
	}

	// Cancelling ends handleRequests' blocking receive, and AcceptConnection
	// returns the context error rather than hanging forever waiting for a
	// phone that has gone away.
	cancel()
	select {
	case err := <-acceptDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("AcceptConnection error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AcceptConnection did not return after its context was cancelled")
	}
}

// TestBLEPeripheral_AcceptConnection_RefusesASecondCallerWhileOneIsActive
// pins acceptMu: a BLE peripheral serves one central at a time, and a second
// concurrent AcceptConnection must wait rather than corrupt the first
// connection's session state.
func TestBLEPeripheral_AcceptConnection_RefusesASecondCallerWhileOneIsActive(t *testing.T) {
	writer := newFragmentChannelWriter()
	p := newTestPeripheral(t, &echoHandler{}, writer)

	firstCtx, firstCancel := context.WithCancel(context.Background())
	defer firstCancel()

	firstStarted := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		close(firstStarted)
		firstDone <- p.AcceptConnection(firstCtx)
	}()
	<-firstStarted

	// Wait for the first call to actually hold acceptMu instead of sleeping
	// a fixed duration: closing firstStarted only proves the goroutine was
	// scheduled, not that it won the lock ahead of the second call below.
	// TryLock is the real signal -- it fails exactly when someone else holds
	// the mutex, and succeeding means nobody does yet, so it must be
	// released immediately rather than mistaken for the first call's hold.
	deadline := time.Now().Add(5 * time.Second)
	for p.acceptMu.TryLock() {
		p.acceptMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("the first AcceptConnection never acquired acceptMu")
		}
		runtime.Gosched()
	}

	// The second call's context is already meant to have expired by the time
	// it ever gets to check it: it must sit blocked on acceptMu the whole
	// time, never even reaching its own context or the incoming-data channel.
	secondCtx, secondCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer secondCancel()

	secondDone := make(chan error, 1)
	go func() { secondDone <- p.AcceptConnection(secondCtx) }()

	// The second call must NOT complete while the first still holds acceptMu,
	// even though its own deadline passes during this wait -- proving the
	// mutex, not the context, is what is gating it.
	select {
	case err := <-secondDone:
		t.Fatalf("second AcceptConnection returned (%v) while the first still held acceptMu", err)
	case <-time.After(400 * time.Millisecond):
	}

	firstCancel()
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first AcceptConnection did not return after cancellation")
	}

	// Only once acceptMu is released does the second call proceed -- straight
	// into its own already-expired context.
	select {
	case err := <-secondDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("second AcceptConnection error = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second AcceptConnection did not proceed after acceptMu was released")
	}
}
