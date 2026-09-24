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

	p.handleWrite([]byte("fragment-1"))

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
		p.handleWrite([]byte("one-too-many"))
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
