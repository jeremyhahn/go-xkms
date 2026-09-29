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
	"testing"
	"time"
)

// handleWrite is the WriteEvent callback the GATT server invokes for every
// incoming packet on the control point characteristic (see
// setupGATTService). It never touches Bluetooth hardware itself -- it only
// queues onto incomingData -- so it is exercised directly here rather than
// through a real characteristic write.

// TestBLEPeripheral_HandleWrite_QueuesData pins the normal path: a write is
// queued verbatim for the receive loop to pick up.
func TestBLEPeripheral_HandleWrite_QueuesData(t *testing.T) {
	p, err := NewBLEPeripheral(&BLEPeripheralConfig{DeviceName: "xKey-test"})
	if err != nil {
		t.Fatalf("NewBLEPeripheral failed: %v", err)
	}

	p.handleWrite(1, []byte("fragment-1"))

	select {
	case got := <-p.incomingData:
		if string(got) != "fragment-1" {
			t.Fatalf("got %q, want %q", got, "fragment-1")
		}
	case <-time.After(time.Second):
		t.Fatal("handleWrite did not queue the data onto incomingData")
	}
}

// TestBLEPeripheral_HandleWrite_DropsWhenBufferFull pins the overflow guard:
// a write arriving while incomingData is saturated is dropped rather than
// blocking the GATT server's write callback, which would stall every other
// characteristic operation on the connection.
func TestBLEPeripheral_HandleWrite_DropsWhenBufferFull(t *testing.T) {
	p, err := NewBLEPeripheral(&BLEPeripheralConfig{DeviceName: "xKey-test"})
	if err != nil {
		t.Fatalf("NewBLEPeripheral failed: %v", err)
	}

	// Saturate the buffer exactly, without going through handleWrite, so the
	// overflow behavior under test is isolated from the fill behavior above.
	capacity := cap(p.incomingData)
	for i := 0; i < capacity; i++ {
		p.incomingData <- []byte("filler")
	}

	done := make(chan struct{})
	go func() {
		p.handleWrite(1, []byte("one-too-many"))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handleWrite blocked instead of dropping the overflow write")
	}

	if got := len(p.incomingData); got != capacity {
		t.Fatalf("incomingData holds %d entries, want exactly %d (the dropped write must not have been queued)", got, capacity)
	}
}

// TestBLEPeripheral_HandleWrite_BindsToFirstCentral pins #1307: the GATT
// control point is shared by every connected central, not scoped per
// session, so without a binding a second central's write would be spliced
// into the first central's reassembler. handleWrite must bind to whichever
// central's write arrives first and drop every write reporting a different
// one.
func TestBLEPeripheral_HandleWrite_BindsToFirstCentral(t *testing.T) {
	p, err := NewBLEPeripheral(&BLEPeripheralConfig{DeviceName: "xKey-test"})
	if err != nil {
		t.Fatalf("NewBLEPeripheral failed: %v", err)
	}

	// The first write binds the session to client 1.
	p.handleWrite(1, []byte("from-first"))
	select {
	case got := <-p.incomingData:
		if string(got) != "from-first" {
			t.Fatalf("got %q, want %q", got, "from-first")
		}
	case <-time.After(time.Second):
		t.Fatal("the first central's write was not queued")
	}

	// A different client's write must be dropped, not queued.
	p.handleWrite(2, []byte("from-second"))
	select {
	case got := <-p.incomingData:
		t.Fatalf("write from an unbound central was queued: %q", got)
	case <-time.After(100 * time.Millisecond):
	}

	// The bound central can still write.
	p.handleWrite(1, []byte("from-first-again"))
	select {
	case got := <-p.incomingData:
		if string(got) != "from-first-again" {
			t.Fatalf("got %q, want %q", got, "from-first-again")
		}
	case <-time.After(time.Second):
		t.Fatal("the bound central's follow-up write was not queued")
	}
}

// TestBLEPeripheral_ResetCentralBinding_AllowsNextCentral pins the other half
// of #1307's binding: resetCentralBinding (called by AcceptConnection when a
// session ends) must let the next session bind to whatever central writes
// first, rather than continuing to refuse the previous session's central
// forever.
func TestBLEPeripheral_ResetCentralBinding_AllowsNextCentral(t *testing.T) {
	p, err := NewBLEPeripheral(&BLEPeripheralConfig{DeviceName: "xKey-test"})
	if err != nil {
		t.Fatalf("NewBLEPeripheral failed: %v", err)
	}

	p.handleWrite(1, []byte("session-one"))
	<-p.incomingData

	p.resetCentralBinding()

	p.handleWrite(2, []byte("session-two"))
	select {
	case got := <-p.incomingData:
		if string(got) != "session-two" {
			t.Fatalf("got %q, want %q", got, "session-two")
		}
	case <-time.After(time.Second):
		t.Fatal("the new central's write was dropped after resetCentralBinding")
	}
}
