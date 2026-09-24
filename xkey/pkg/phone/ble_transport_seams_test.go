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
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"tinygo.org/x/bluetooth"
)

// This file exercises the parts of BLETransport that do not require a real
// Bluetooth adapter: the guard clauses every exported method checks before
// touching hardware, the notification handlers (fed by the GATT client
// library, not by hardware directly), and the pure helper functions.
//
// NewBLETransport itself calls bluetooth.DefaultAdapter.Enable(), which
// depends on a running bluetoothd and has no injectable seam (see the
// package-level report on this). Every test here builds a *BLETransport by
// struct literal instead, exactly as the peripheral's own tests build a
// *BLEPeripheral without calling Start.

// newTestTransport builds a transport whose channels and fragmenter are
// initialized the way NewBLETransport would, without ever calling
// adapter.Enable(). adapterPresent controls whether the adapter-nil guard is
// hit; nothing here calls a method ON the adapter, so a non-nil zero-value
// pointer is safe.
func newTestTransport(adapterPresent bool) *BLETransport {
	t := &BLETransport{
		cfg:          DefaultBLETransportConfig(),
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		fragmenter:   pairing.NewFragmenter(DefaultMTU),
		reassembler:  pairing.NewReassembler(),
		responseChan: make(chan []byte, 16),
		statusChan:   make(chan []byte, 16),
	}
	if adapterPresent {
		t.adapter = &bluetooth.Adapter{}
	}
	return t
}

// --- guard clauses: adapter absent, closed, not connected ---

func TestBLETransport_Send_NoAdapter(t *testing.T) {
	tr := newTestTransport(false)

	if err := tr.Send(context.Background(), []byte("x")); !errors.Is(err, ErrBLEUnavailable) {
		t.Fatalf("Send() error = %v, want %v", err, ErrBLEUnavailable)
	}
}

func TestBLETransport_Send_Closed(t *testing.T) {
	tr := newTestTransport(true)
	tr.closed.Store(true)

	if err := tr.Send(context.Background(), []byte("x")); !errors.Is(err, ErrBackendClosed) {
		t.Fatalf("Send() error = %v, want %v", err, ErrBackendClosed)
	}
}

func TestBLETransport_Send_NotConnected(t *testing.T) {
	tr := newTestTransport(true)

	if err := tr.Send(context.Background(), []byte("x")); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("Send() error = %v, want %v", err, ErrNotConnected)
	}
}

func TestBLETransport_Receive_NoAdapter(t *testing.T) {
	tr := newTestTransport(false)

	if _, err := tr.Receive(context.Background()); !errors.Is(err, ErrBLEUnavailable) {
		t.Fatalf("Receive() error = %v, want %v", err, ErrBLEUnavailable)
	}
}

func TestBLETransport_Receive_Closed(t *testing.T) {
	tr := newTestTransport(true)
	tr.closed.Store(true)

	if _, err := tr.Receive(context.Background()); !errors.Is(err, ErrBackendClosed) {
		t.Fatalf("Receive() error = %v, want %v", err, ErrBackendClosed)
	}
}

func TestBLETransport_Receive_NotConnected(t *testing.T) {
	tr := newTestTransport(true)

	if _, err := tr.Receive(context.Background()); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("Receive() error = %v, want %v", err, ErrNotConnected)
	}
}

// TestBLETransport_Receive_DeliversQueuedMessage pins the accept path: a
// message already sitting on responseChan (as handleResponseNotification
// would have placed it) is returned without touching hardware.
func TestBLETransport_Receive_DeliversQueuedMessage(t *testing.T) {
	tr := newTestTransport(true)
	tr.connected.Store(true)
	tr.responseChan <- []byte("queued-response")

	got, err := tr.Receive(context.Background())
	if err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if string(got) != "queued-response" {
		t.Fatalf("Receive() = %q, want %q", got, "queued-response")
	}
}

// TestBLETransport_Receive_ContextDeadline pins the timeout branch: no
// message arrives before ctx expires.
func TestBLETransport_Receive_ContextDeadline(t *testing.T) {
	tr := newTestTransport(true)
	tr.connected.Store(true)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	if _, err := tr.Receive(ctx); !errors.Is(err, ErrTimeout) {
		t.Fatalf("Receive() error = %v, want %v", err, ErrTimeout)
	}
}

// TestBLETransport_SendAndReceive_PropagatesSendFailure pins that
// SendAndReceive never calls Receive when Send itself refuses.
func TestBLETransport_SendAndReceive_PropagatesSendFailure(t *testing.T) {
	tr := newTestTransport(false)

	if _, err := tr.SendAndReceive(context.Background(), []byte("x")); !errors.Is(err, ErrBLEUnavailable) {
		t.Fatalf("SendAndReceive() error = %v, want %v", err, ErrBLEUnavailable)
	}
}

func TestBLETransport_ScanWithOptions_NoAdapter(t *testing.T) {
	tr := newTestTransport(false)

	if _, err := tr.ScanWithOptions(context.Background(), true); !errors.Is(err, ErrBLEUnavailable) {
		t.Fatalf("ScanWithOptions() error = %v, want %v", err, ErrBLEUnavailable)
	}
}

func TestBLETransport_ScanWithOptions_Closed(t *testing.T) {
	tr := newTestTransport(true)
	tr.closed.Store(true)

	if _, err := tr.ScanWithOptions(context.Background(), true); !errors.Is(err, ErrBackendClosed) {
		t.Fatalf("ScanWithOptions() error = %v, want %v", err, ErrBackendClosed)
	}
}

// TestBLETransport_Scan_DelegatesStopOnFirst and TestBLETransport_ScanAll_DelegatesStopOnFirst
// pin that the two convenience wrappers reach ScanWithOptions (and therefore
// its guard clauses) rather than duplicating them.
func TestBLETransport_Scan_DelegatesStopOnFirst(t *testing.T) {
	tr := newTestTransport(false)

	if _, err := tr.Scan(context.Background()); !errors.Is(err, ErrBLEUnavailable) {
		t.Fatalf("Scan() error = %v, want %v", err, ErrBLEUnavailable)
	}
}

func TestBLETransport_ScanAll_DelegatesStopOnFirst(t *testing.T) {
	tr := newTestTransport(false)

	if _, err := tr.ScanAll(context.Background()); !errors.Is(err, ErrBLEUnavailable) {
		t.Fatalf("ScanAll() error = %v, want %v", err, ErrBLEUnavailable)
	}
}

func TestBLETransport_Connect_NoAdapter(t *testing.T) {
	tr := newTestTransport(false)

	if err := tr.Connect(context.Background(), "AA:BB:CC:DD:EE:FF"); !errors.Is(err, ErrBLEUnavailable) {
		t.Fatalf("Connect() error = %v, want %v", err, ErrBLEUnavailable)
	}
}

func TestBLETransport_ConnectWithBondedAddress_Closed(t *testing.T) {
	tr := newTestTransport(true)
	tr.closed.Store(true)

	err := tr.ConnectWithBondedAddress(context.Background(), "AA:BB:CC:DD:EE:FF", "")
	if !errors.Is(err, ErrBackendClosed) {
		t.Fatalf("ConnectWithBondedAddress() error = %v, want %v", err, ErrBackendClosed)
	}
}

// TestBLETransport_ConnectWithBondedAddress_AlreadyConnected pins the
// short-circuit: a transport that reports connected must not attempt a
// second connection.
func TestBLETransport_ConnectWithBondedAddress_AlreadyConnected(t *testing.T) {
	tr := newTestTransport(true)
	tr.connected.Store(true)

	if err := tr.ConnectWithBondedAddress(context.Background(), "AA:BB:CC:DD:EE:FF", ""); err != nil {
		t.Fatalf("ConnectWithBondedAddress() error = %v, want nil (already connected)", err)
	}
}

// --- notification handlers: fed by the GATT client library, no hardware ---

func TestBLETransport_HandleResponseNotification_ClosedDrops(t *testing.T) {
	tr := newTestTransport(true)
	tr.closed.Store(true)

	tr.handleResponseNotification([]byte("anything"))

	select {
	case msg := <-tr.responseChan:
		t.Fatalf("closed transport delivered %q, want nothing queued", msg)
	default:
	}
}

func TestBLETransport_HandleResponseNotification_MalformedFragmentDropped(t *testing.T) {
	tr := newTestTransport(true)

	tr.handleResponseNotification([]byte{0x01, 0x02}) // too short to be a fragment

	select {
	case msg := <-tr.responseChan:
		t.Fatalf("malformed fragment produced a message: %q", msg)
	default:
	}
}

// TestBLETransport_HandleResponseNotification_CompleteMessageQueued pins the
// full reassembly path: fragments delivered via the notification handler
// (the production entry point for GATT notifications) produce one complete
// message on responseChan.
func TestBLETransport_HandleResponseNotification_CompleteMessageQueued(t *testing.T) {
	tr := newTestTransport(true)

	fragments, err := pairing.NewFragmenter(DefaultMTU).Fragment([]byte("hello-response"))
	if err != nil {
		t.Fatalf("fragment: %v", err)
	}
	for _, frag := range fragments {
		tr.handleResponseNotification(frag)
	}

	select {
	case msg := <-tr.responseChan:
		if string(msg) != "hello-response" {
			t.Fatalf("got %q, want %q", msg, "hello-response")
		}
	default:
		t.Fatal("no message was queued after a complete fragment sequence")
	}
}

// TestBLETransport_HandleResponseNotification_FullChannelDropsMessage pins
// the overflow guard on the response channel.
func TestBLETransport_HandleResponseNotification_FullChannelDropsMessage(t *testing.T) {
	tr := newTestTransport(true)
	tr.responseChan = make(chan []byte, 1)
	tr.responseChan <- []byte("already queued")

	fragments, err := pairing.NewFragmenter(DefaultMTU).Fragment([]byte("dropped"))
	if err != nil {
		t.Fatalf("fragment: %v", err)
	}
	for _, frag := range fragments {
		tr.handleResponseNotification(frag)
	}

	if got := len(tr.responseChan); got != 1 {
		t.Fatalf("responseChan holds %d entries, want 1 (the overflow message must be dropped)", got)
	}
}

func TestBLETransport_HandleStatusNotification_ClosedDrops(t *testing.T) {
	tr := newTestTransport(true)
	tr.closed.Store(true)

	tr.handleStatusNotification([]byte("status"))

	select {
	case msg := <-tr.statusChan:
		t.Fatalf("closed transport delivered %q, want nothing queued", msg)
	default:
	}
}

func TestBLETransport_HandleStatusNotification_Queued(t *testing.T) {
	tr := newTestTransport(true)

	tr.handleStatusNotification([]byte("status-update"))

	select {
	case msg := <-tr.statusChan:
		if string(msg) != "status-update" {
			t.Fatalf("got %q, want %q", msg, "status-update")
		}
	default:
		t.Fatal("status update was not queued")
	}
}

func TestBLETransport_HandleStatusNotification_FullChannelDrops(t *testing.T) {
	tr := newTestTransport(true)
	tr.statusChan = make(chan []byte, 1)
	tr.statusChan <- []byte("already queued")

	tr.handleStatusNotification([]byte("overflow"))

	if got := len(tr.statusChan); got != 1 {
		t.Fatalf("statusChan holds %d entries, want 1 (the overflow status must be dropped)", got)
	}
}

// --- disconnect / close / channel bookkeeping: no hardware touched when
// there is nothing connected to disconnect from ---

// TestBLETransport_Disconnect_NotConnectedIsANoop pins that disconnecting an
// already-idle transport neither touches the adapter nor shells out.
func TestBLETransport_Disconnect_NotConnectedIsANoop(t *testing.T) {
	tr := newTestTransport(true)

	if err := tr.Disconnect(); err != nil {
		t.Fatalf("Disconnect() error = %v, want nil", err)
	}
}

// TestBLETransport_Close_IdleTransport drives the whole Close path on a
// transport that was never connected: Disconnect is a no-op, and both
// channels are closed.
func TestBLETransport_Close_IdleTransport(t *testing.T) {
	tr := newTestTransport(true)

	if err := tr.Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}

	if _, open := <-tr.responseChan; open {
		t.Fatal("responseChan was not closed")
	}
	if _, open := <-tr.statusChan; open {
		t.Fatal("statusChan was not closed")
	}
}

// TestBLETransport_Close_Idempotent pins that a second Close is a no-op
// rather than a double-close panic on the channels.
func TestBLETransport_Close_Idempotent(t *testing.T) {
	tr := newTestTransport(true)

	if err := tr.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}

	if err := tr.Close(); err != nil {
		t.Fatalf("second Close() error = %v, want nil", err)
	}
}

// TestBLETransport_DrainChannels empties both channels directly, the way
// disconnectLocked calls it between connections.
func TestBLETransport_DrainChannels(t *testing.T) {
	tr := newTestTransport(true)
	tr.responseChan <- []byte("stale-response")
	tr.statusChan <- []byte("stale-status")

	tr.drainChannels()

	if got := len(tr.responseChan); got != 0 {
		t.Fatalf("responseChan holds %d entries after drain, want 0", got)
	}
	if got := len(tr.statusChan); got != 0 {
		t.Fatalf("statusChan holds %d entries after drain, want 0", got)
	}
}

// --- trivial accessors ---

// TestBLETransport_CleanStaleBlueZEntry_EmptyAddressIsANoop guards a real
// regression: without the empty-address guard, CleanStaleBlueZEntry would
// shell out to bluetoothctl during an ordinary unit test run.
func TestBLETransport_CleanStaleBlueZEntry_EmptyAddressIsANoop(t *testing.T) {
	tr := newTestTransport(true)

	// Must return immediately without shelling out to bluetoothctl.
	tr.CleanStaleBlueZEntry("")
}

func TestBLETransport_SetMTU_AndMTU(t *testing.T) {
	tr := newTestTransport(true)

	tr.SetMTU(600)
	if got := tr.MTU(); got != 600 {
		t.Fatalf("MTU() = %d, want 600", got)
	}

	// Below the protocol minimum is refused rather than silently applied.
	tr.SetMTU(1)
	if got := tr.MTU(); got != 600 {
		t.Fatalf("MTU() = %d after a below-minimum SetMTU, want it unchanged at 600", got)
	}
}

// --- pure helpers ---

func TestDisplayName_LocalNameWins(t *testing.T) {
	sr := ScanResult{LocalName: "Pixel 8", Address: "AA:BB:CC:DD:EE:FF"}
	if got := sr.DisplayName(); got != "Pixel 8" {
		t.Fatalf("DisplayName() = %q, want %q", got, "Pixel 8")
	}
}

func TestDisplayName_FallsBackToAddressSuffix(t *testing.T) {
	sr := ScanResult{Address: "AA:BB:CC:DD:EE:FF"}
	got := sr.DisplayName()
	// The suffix is exactly the last 5 characters of the address string.
	want := "xKey (" + "AA:BB:CC:DD:EE:FF"[len("AA:BB:CC:DD:EE:FF")-5:] + ")"
	if got != want {
		t.Fatalf("DisplayName() = %q, want %q", got, want)
	}
}

func TestDisplayName_ShortAddressHasNoSuffix(t *testing.T) {
	sr := ScanResult{Address: "AB"}
	if got := sr.DisplayName(); got != "xKey" {
		t.Fatalf("DisplayName() = %q, want %q", got, "xKey")
	}
}

func TestParseMACAddress_Valid(t *testing.T) {
	addr, err := parseMACAddress("AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatalf("parseMACAddress() error = %v", err)
	}
	if addr.MAC.String() == "" {
		t.Fatal("parsed MAC address stringifies to empty")
	}
}

func TestParseMACAddress_Invalid(t *testing.T) {
	if _, err := parseMACAddress("not-a-mac-address"); err == nil {
		t.Fatal("parseMACAddress() succeeded on garbage input")
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		s, substr string
		want      bool
	}{
		{"", "", true},
		{"hello world", "world", true},
		{"hello world", "xyz", false},
		{"hello", "hello world", false}, // substr longer than s
		{"aaa", "aa", true},
	}
	for _, tt := range tests {
		if got := contains(tt.s, tt.substr); got != tt.want {
			t.Errorf("contains(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
		}
	}
}

func TestIsBlueZCacheError(t *testing.T) {
	if isBlueZCacheError(nil) {
		t.Fatal("isBlueZCacheError(nil) = true, want false")
	}

	staleErr := errors.New("org.freedesktop.DBus.Properties: object doesn't exist")
	if !isBlueZCacheError(staleErr) {
		t.Fatal("isBlueZCacheError() = false for a genuine stale-object error")
	}

	otherErr := errors.New("connection refused")
	if isBlueZCacheError(otherErr) {
		t.Fatal("isBlueZCacheError() = true for an unrelated error")
	}
}
