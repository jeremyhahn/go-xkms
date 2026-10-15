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
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
)

// This file exercises the guard clauses every exported method checks before
// touching the central, the notification handlers (fed by the GATT client
// library, not by hardware directly), and the pure helper functions. The
// paths that drive a central are in ble_transport_central_test.go.

// newTestTransport builds a transport whose channels and fragmenter are
// initialized the way newBLETransport would. adapterPresent controls whether
// the adapter-nil guard is hit; when present the adapter is a fakeCentral that
// finds nothing, and bluetoothctl reports every device as unknown.
func newTestTransport(adapterPresent bool) *BLETransport {
	t := &BLETransport{
		cfg:          DefaultBLETransportConfig(),
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		bluetoothctl: newFakeBluetoothctl().run,
		sleep:        func(time.Duration) {},
		fragmenter:   pairingproto.NewFragmenter(DefaultMTU),
		reassembler:  pairingproto.NewReassembler(),
		responseChan: make(chan []byte, 16),
		statusChan:   make(chan []byte, 16),
		done:         make(chan struct{}),
	}
	if adapterPresent {
		t.adapter = newFakeCentral()
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

// TestBLETransport_Receive_UnblocksOnClose pins that a Receive already
// blocked when Close runs is woken up via done rather than left hanging
// until its context expires.
func TestBLETransport_Receive_UnblocksOnClose(t *testing.T) {
	tr := newTestTransport(true)
	tr.connected.Store(true)

	errCh := make(chan error, 1)
	go func() {
		_, err := tr.Receive(context.Background())
		errCh <- err
	}()

	// Give Receive a moment to reach its select before closing.
	time.Sleep(20 * time.Millisecond)

	if err := tr.Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrBackendClosed) {
			t.Fatalf("Receive() error = %v, want %v", err, ErrBackendClosed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Receive() did not unblock after Close()")
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

	fragments, err := pairingproto.NewFragmenter(DefaultMTU).Fragment([]byte("hello-response"))
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

	fragments, err := pairingproto.NewFragmenter(DefaultMTU).Fragment([]byte("dropped"))
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
// transport that was never connected: Disconnect is a no-op, and done is
// closed to wake up any blocked receivers. responseChan and statusChan are
// deliberately left open (see the done field comment on BLETransport) since
// BLE notification handlers may still be in flight and must never send on a
// closed channel.
func TestBLETransport_Close_IdleTransport(t *testing.T) {
	tr := newTestTransport(true)

	if err := tr.Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}

	select {
	case <-tr.done:
	default:
		t.Fatal("done was not closed")
	}

	select {
	case _, open := <-tr.responseChan:
		if !open {
			t.Fatal("responseChan must never be closed")
		}
	default:
		// No message queued, which is expected; the point is the channel
		// must not be closed (the case above would fire with open == false).
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

// TestBLETransport_NotificationsRaceClose is a regression test for #1271:
// handleResponseNotification and handleStatusNotification run on BlueZ
// goroutines and can still be delivering notifications after Close begins
// (the connEpoch note on BLETransport explains why). The old Close closed
// responseChan/statusChan; a handler that passed its closed.Load() check
// and then lost the race to Close's swap+close would panic sending on a
// closed channel. Close no longer closes those channels (see the done field
// comment), so this must run clean under -race no matter how Close and the
// notification handlers interleave.
func TestBLETransport_NotificationsRaceClose(t *testing.T) {
	statusPayload := []byte("status-update")
	fragments, err := pairingproto.NewFragmenter(DefaultMTU).Fragment([]byte("response"))
	if err != nil {
		t.Fatalf("fragment: %v", err)
	}

	for i := 0; i < 200; i++ {
		tr := newTestTransport(true)

		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				for _, frag := range fragments {
					tr.handleResponseNotification(frag)
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				tr.handleStatusNotification(statusPayload)
			}
		}()
		go func() {
			defer wg.Done()
			_ = tr.Close()
		}()
		wg.Wait()
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
	if addr.String() == "" {
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
