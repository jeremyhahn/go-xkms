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

//go:build !usb

package phone

import (
	"context"
	"errors"
	"testing"
)

// This build (no "usb" tag) links usb_transport_stub.go, the AOA-less
// stand-in used by static release binaries and the FIPS lane (see the note
// on USBTransport). Every operation must refuse with ErrUSBUnavailable
// rather than silently no-op, so a caller cannot mistake "not built in this
// binary" for "briefly disconnected".

// TestNewUSBTransport_Stub_Unavailable pins the constructor's refusal.
func TestNewUSBTransport_Stub_Unavailable(t *testing.T) {
	transport, err := NewUSBTransport(DefaultUSBTransportConfig())

	if !errors.Is(err, ErrUSBUnavailable) {
		t.Fatalf("NewUSBTransport() error = %v, want %v", err, ErrUSBUnavailable)
	}
	if transport != nil {
		t.Fatal("NewUSBTransport() returned a non-nil transport alongside an error")
	}
}

// TestUSBTransport_Stub_EveryOperationRefuses pins that the stub's exported
// surface matches the real transport's (pairing.Transport) but every method
// reports the same unavailability rather than pretending to work.
func TestUSBTransport_Stub_EveryOperationRefuses(t *testing.T) {
	transport := &USBTransport{}
	ctx := context.Background()

	if err := transport.Connect(ctx); !errors.Is(err, ErrUSBUnavailable) {
		t.Errorf("Connect() error = %v, want %v", err, ErrUSBUnavailable)
	}
	if err := transport.Send(ctx, []byte("payload")); !errors.Is(err, ErrUSBUnavailable) {
		t.Errorf("Send() error = %v, want %v", err, ErrUSBUnavailable)
	}
	if data, err := transport.Receive(ctx); !errors.Is(err, ErrUSBUnavailable) || data != nil {
		t.Errorf("Receive() = (%v, %v), want (nil, %v)", data, err, ErrUSBUnavailable)
	}
	if data, err := transport.SendAndReceive(ctx, []byte("payload")); !errors.Is(err, ErrUSBUnavailable) || data != nil {
		t.Errorf("SendAndReceive() = (%v, %v), want (nil, %v)", data, err, ErrUSBUnavailable)
	}
	if transport.IsConnected() {
		t.Error("IsConnected() = true, want false: the stub never has a live connection")
	}
	if err := transport.Close(); err != nil {
		t.Errorf("Close() = %v, want nil: closing a transport that was never open must be a no-op", err)
	}
}
