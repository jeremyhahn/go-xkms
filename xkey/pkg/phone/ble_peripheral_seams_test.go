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
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
)

// TestBLEPeripheral_RegisterConnection_RefusesWhenClosed pins the refusal
// branch of registerConnection directly: once closed is set, no further
// connection may register and read the (possibly already-freed) key.
func TestBLEPeripheral_RegisterConnection_RefusesWhenClosed(t *testing.T) {
	p, err := NewBLEPeripheral(&BLEPeripheralConfig{DeviceName: "xKey-test"})
	if err != nil {
		t.Fatalf("NewBLEPeripheral failed: %v", err)
	}
	p.closed.Store(true)

	if err := p.registerConnection(); !errors.Is(err, ErrBLEPeripheralStopped) {
		t.Fatalf("registerConnection() error = %v, want %v", err, ErrBLEPeripheralStopped)
	}
}

// TestBLEPeripheral_ReceiveMessageTimeout_StopChanClosed pins that a
// peripheral shutting down unblocks a receive in progress with
// ErrPeripheralNotRunning, rather than leaving it to time out.
func TestBLEPeripheral_ReceiveMessageTimeout_StopChanClosed(t *testing.T) {
	p := newTestPeripheral(t, &echoHandler{}, newCaptureWriter())
	close(p.stopChan)

	_, err := p.receiveMessageTimeout(context.Background(), 5*time.Second)
	if !errors.Is(err, ErrPeripheralNotRunning) {
		t.Fatalf("receiveMessageTimeout() error = %v, want %v", err, ErrPeripheralNotRunning)
	}
}

// TestBLEPeripheral_ReceiveMessageTimeout_ReassemblyErrorContinues pins that
// a fragment which DECODES cleanly but fails reassembly (an invalid
// sequence number, here) is discarded and the receive loop keeps going,
// rather than returning the reassembly error to the caller.
func TestBLEPeripheral_ReceiveMessageTimeout_ReassemblyErrorContinues(t *testing.T) {
	p := newTestPeripheral(t, &echoHandler{}, newCaptureWriter())

	// A hand-built fragment: sequence 5 of a 3-fragment message. DecodeFragment
	// accepts it (the header is well-formed); Reassembler.AddFragment is what
	// refuses it, exercising the branch DecodeFragment's own error test
	// (TestBLEPeripheral_ReceiveMessageDiscardsMalformedFragment) cannot reach.
	bad := make([]byte, pairingproto.FragmentHeaderSize+5)
	bad[0] = pairingproto.FlagFirstFragment
	binary.BigEndian.PutUint16(bad[1:3], 5) // sequence
	binary.BigEndian.PutUint16(bad[3:5], 3) // total
	binary.BigEndian.PutUint16(bad[5:7], 5) // length
	copy(bad[7:], "hello")
	p.incomingData <- bad

	fragments, err := p.fragmenter.Fragment([]byte("good message"))
	if err != nil {
		t.Fatalf("fragment: %v", err)
	}
	for _, frag := range fragments {
		p.incomingData <- frag
	}

	message, err := p.receiveMessageTimeout(context.Background(), 2*time.Second)
	if err != nil {
		t.Fatalf("receiveMessageTimeout() error = %v, want nil (the bad fragment must be skipped)", err)
	}
	if string(message) != "good message" {
		t.Fatalf("got %q, want %q", message, "good message")
	}
}

// TestBLEPeripheral_Start_AlreadyRunningRefusesWithoutTouchingHardware pins
// the reservation Start takes before it enables the adapter: a peripheral
// already mid-Start must be refused at that reservation, never reaching
// adapter.Enable (which this test environment has no Bluetooth stack for).
func TestBLEPeripheral_Start_AlreadyRunningRefusesWithoutTouchingHardware(t *testing.T) {
	p, err := NewBLEPeripheral(&BLEPeripheralConfig{DeviceName: "xKey-test"})
	if err != nil {
		t.Fatalf("NewBLEPeripheral failed: %v", err)
	}

	p.lifeMu.Lock()
	p.starting = true
	p.lifeMu.Unlock()

	if err := p.Start(context.Background()); !errors.Is(err, ErrPeripheralAlreadyRunning) {
		t.Fatalf("Start() error = %v, want %v", err, ErrPeripheralAlreadyRunning)
	}
}
