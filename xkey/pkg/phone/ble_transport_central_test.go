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
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"tinygo.org/x/bluetooth"
)

// This file drives BLETransport against the in-memory central in
// ble_transport_fakes_test.go: scanning, connecting with BlueZ recovery,
// service and characteristic discovery, notifications, writes and teardown.

const (
	phoneAddr  = "AA:BB:CC:DD:EE:01"
	bondedAddr = "AA:BB:CC:DD:EE:02"
)

var errDBusStale = errors.New("org.freedesktop.DBus.Properties: object path doesn't exist")

// newCentralTransport builds a transport over central the way NewBLETransport
// would, with sleeps elided.
func newCentralTransport(t *testing.T, central *fakeCentral, ctl *fakeBluetoothctl) *BLETransport {
	t.Helper()
	cfg := DefaultBLETransportConfig()
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	tr, err := newBLETransport(cfg, central, ctl.run)
	if err != nil {
		t.Fatalf("newBLETransport() error = %v", err)
	}
	tr.sleep = func(time.Duration) {}
	t.Cleanup(func() {
		if err := tr.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return tr
}

// connectedTransport returns a transport connected to a fake phone.
func connectedTransport(t *testing.T) (*BLETransport, *fakePhone, *fakeBluetoothctl) {
	t.Helper()
	phone := newFakePhone()
	ctl := newFakeBluetoothctl()
	tr := newCentralTransport(t, &fakeCentral{device: phone.device}, ctl)
	if err := tr.Connect(context.Background(), phoneAddr); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	return tr, phone, ctl
}

// fragments splits msg the way the phone would before notifying it.
func fragments(t *testing.T, msg []byte) [][]byte {
	t.Helper()
	frags, err := pairingproto.NewFragmenter(DefaultMTU).Fragment(msg)
	if err != nil {
		t.Fatalf("Fragment() error = %v", err)
	}
	return frags
}

func scanResult(t *testing.T, address, name string, services ...bluetooth.UUID) bluetooth.ScanResult {
	t.Helper()
	addr, err := parseMACAddress(address)
	if err != nil {
		t.Fatalf("parseMACAddress(%q) error = %v", address, err)
	}
	return bluetooth.ScanResult{
		Address:              addr,
		RSSI:                 -60,
		AdvertisementPayload: fakeAdvertisement{name: name, services: services},
	}
}

// --- construction ---

func TestNewBLETransport_DefaultsConfig(t *testing.T) {
	cfg := &BLETransportConfig{MTU: 1}
	tr, err := newBLETransport(cfg, newFakeCentral(), newFakeBluetoothctl().run)
	if err != nil {
		t.Fatalf("newBLETransport() error = %v", err)
	}
	if cfg.MTU != DefaultMTU || tr.MTU() != DefaultMTU {
		t.Fatalf("MTU = %d (transport %d), want %d", cfg.MTU, tr.MTU(), DefaultMTU)
	}
	if cfg.Logger == nil {
		t.Fatal("nil Logger was not defaulted")
	}

	tr, err = newBLETransport(nil, newFakeCentral(), newFakeBluetoothctl().run)
	if err != nil {
		t.Fatalf("newBLETransport(nil) error = %v", err)
	}
	if tr.cfg.ScanTimeout != ScanTimeout {
		t.Fatalf("nil config ScanTimeout = %v, want %v", tr.cfg.ScanTimeout, ScanTimeout)
	}
}

func TestNewBLETransport_AdapterUnavailable(t *testing.T) {
	central := &fakeCentral{enableErr: errors.New("no adapter")}
	if _, err := newBLETransport(nil, central, newFakeBluetoothctl().run); !errors.Is(err, ErrBLEUnavailable) {
		t.Fatalf("newBLETransport() error = %v, want %v", err, ErrBLEUnavailable)
	}
}

// --- scanning ---

func TestBLETransport_Scan_StopsOnFirstXKeyDevice(t *testing.T) {
	central := &fakeCentral{results: []bluetooth.ScanResult{
		scanResult(t, "11:22:33:44:55:66", "headphones"),
		scanResult(t, phoneAddr, "Pixel", XKeyServiceUUID),
		scanResult(t, phoneAddr, "Pixel", XKeyServiceUUID),
	}}
	tr := newCentralTransport(t, central, newFakeBluetoothctl())
	tr.cfg.ScanTimeout = time.Minute

	got, err := tr.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	want := []ScanResult{{Address: phoneAddr, LocalName: "Pixel", RSSI: -60}}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("Scan() = %+v, want %+v", got, want)
	}
	if _, stops := central.counts(); stops != 1 {
		t.Fatalf("StopScan calls = %d, want 1", stops)
	}
}

// A stop-on-first scan that hears several distinct xKey devices must not block
// the scan callback on its one-slot found signal. The fake's StopScan waits for
// Scan to return, so Scan returning at all proves every callback returned and
// the scan goroutine exited; a blocked callback deadlocks StopScan instead.
func TestBLETransport_Scan_StopOnFirstDoesNotBlockLaterDevices(t *testing.T) {
	central := &fakeCentral{results: []bluetooth.ScanResult{
		scanResult(t, phoneAddr, "Pixel", XKeyServiceUUID),
		scanResult(t, bondedAddr, "Tablet", XKeyServiceUUID),
		scanResult(t, "AA:BB:CC:DD:EE:03", "Watch", XKeyServiceUUID),
	}}
	tr := newCentralTransport(t, central, newFakeBluetoothctl())
	tr.cfg.ScanTimeout = time.Minute

	type scanOutcome struct {
		got []ScanResult
		err error
	}
	done := make(chan scanOutcome, 1)
	go func() {
		got, err := tr.Scan(context.Background())
		done <- scanOutcome{got: got, err: err}
	}()

	var out scanOutcome
	select {
	case out = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Scan() did not return: the scan callback is blocked on the found signal")
	}
	if out.err != nil {
		t.Fatalf("Scan() error = %v", out.err)
	}
	if len(out.got) != 3 {
		t.Fatalf("Scan() = %+v, want the 3 devices heard before the stop", out.got)
	}
	if _, stops := central.counts(); stops != 1 {
		t.Fatalf("StopScan calls = %d, want 1", stops)
	}
}

func TestBLETransport_ScanAll_CollectsUntilTimeout(t *testing.T) {
	central := &fakeCentral{
		results: []bluetooth.ScanResult{
			scanResult(t, phoneAddr, "", XKeyServiceUUID),
			scanResult(t, bondedAddr, "Tablet", XKeyServiceUUID),
			scanResult(t, phoneAddr, "", XKeyServiceUUID),
		},
		stopScanErr: errors.New("not scanning"),
	}
	tr := newCentralTransport(t, central, newFakeBluetoothctl())
	tr.cfg.ScanTimeout = 20 * time.Millisecond

	got, err := tr.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("ScanAll() error = %v", err)
	}
	if len(got) != 2 || got[0].Address != phoneAddr || got[1].Address != bondedAddr {
		t.Fatalf("ScanAll() = %+v, want %s then %s once each", got, phoneAddr, bondedAddr)
	}
}

func TestBLETransport_Scan_ParentCancellationEndsScan(t *testing.T) {
	tr := newCentralTransport(t, newFakeCentral(), newFakeBluetoothctl())
	tr.cfg.ScanTimeout = time.Minute
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := tr.Scan(ctx)
	if err != nil || len(got) != 0 {
		t.Fatalf("Scan() = %+v, %v; want no devices and no error", got, err)
	}
}

func TestBLETransport_Scan_AdapterErrorIsUnavailable(t *testing.T) {
	central := &fakeCentral{scanErr: errors.New("org.bluez.Error.NotReady")}
	tr := newCentralTransport(t, central, newFakeBluetoothctl())
	tr.cfg.ScanTimeout = time.Minute

	if _, err := tr.Scan(context.Background()); !errors.Is(err, ErrBLEUnavailable) {
		t.Fatalf("Scan() error = %v, want %v", err, ErrBLEUnavailable)
	}
}

// --- connecting ---

func TestBLETransport_Connect_EstablishesSession(t *testing.T) {
	tr, phone, ctl := connectedTransport(t)

	if !tr.IsConnected() || tr.ConnectedAddress() != phoneAddr {
		t.Fatalf("IsConnected() = %v, ConnectedAddress() = %q; want true, %q",
			tr.IsConnected(), tr.ConnectedAddress(), phoneAddr)
	}
	if ctl.called("trust", phoneAddr) != 1 {
		t.Fatalf("bluetoothctl calls = %v, want the device trusted before connecting", ctl.calls)
	}

	// The phone's response notifications reach Receive, its status
	// notifications reach StatusChannel.
	for _, frag := range fragments(t, []byte("pong")) {
		phone.response.notifier()(frag)
	}
	got, err := tr.Receive(context.Background())
	if err != nil || string(got) != "pong" {
		t.Fatalf("Receive() = %q, %v; want %q", got, err, "pong")
	}
	phone.status.notifier()([]byte{0x02})
	if status := <-tr.StatusChannel(); !bytes.Equal(status, []byte{0x02}) {
		t.Fatalf("StatusChannel() delivered %x, want 02", status)
	}
}

func TestBLETransport_Connect_AlreadyConnectedIsANoop(t *testing.T) {
	tr, _, _ := connectedTransport(t)
	central := tr.adapter.(*fakeCentral)

	if err := tr.Connect(context.Background(), bondedAddr); err != nil {
		t.Fatalf("second Connect() error = %v", err)
	}
	if connects, _ := central.counts(); connects != 1 {
		t.Fatalf("adapter Connect calls = %d, want 1", connects)
	}
	if tr.ConnectedAddress() != phoneAddr {
		t.Fatalf("ConnectedAddress() = %q, want %q", tr.ConnectedAddress(), phoneAddr)
	}
}

func TestBLETransport_Connect_InvalidAddress(t *testing.T) {
	central := &fakeCentral{device: newFakePhone().device}
	tr := newCentralTransport(t, central, newFakeBluetoothctl())

	if err := tr.Connect(context.Background(), "not-a-mac"); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("Connect() error = %v, want %v", err, ErrDeviceNotFound)
	}
	if connects, _ := central.counts(); connects != 0 {
		t.Fatalf("adapter Connect calls = %d, want 0", connects)
	}
}

// TestBLETransport_Connect_StaleNotificationsDiscarded pins the connection
// epoch: a notification handler registered by an earlier connection must not
// feed the current connection's reassembler.
func TestBLETransport_Connect_StaleNotificationsDiscarded(t *testing.T) {
	tr, first, _ := connectedTransport(t)
	staleResponse, staleStatus := first.response.notifier(), first.status.notifier()
	if err := tr.Disconnect(); err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}

	second := newFakePhone()
	tr.adapter.(*fakeCentral).device = second.device
	if err := tr.Connect(context.Background(), phoneAddr); err != nil {
		t.Fatalf("reconnect error = %v", err)
	}

	for _, frag := range fragments(t, []byte("stale")) {
		staleResponse(frag)
	}
	staleStatus([]byte{0x01})
	for _, frag := range fragments(t, []byte("fresh")) {
		second.response.notifier()(frag)
	}

	got, err := tr.Receive(context.Background())
	if err != nil || string(got) != "fresh" {
		t.Fatalf("Receive() = %q, %v; want %q", got, err, "fresh")
	}
	select {
	case status := <-tr.StatusChannel():
		t.Fatalf("stale status notification delivered: %x", status)
	default:
	}
}

func TestBLETransport_Connect_RotatedAddressRefreshesBondedEntry(t *testing.T) {
	tests := []struct {
		name       string
		info       string
		wantRemove int
		wantDisc   int
	}{
		{name: "bonded entry is disconnected, keeping the bond", info: "Paired: yes", wantDisc: 1},
		{name: "bonded via Bonded flag", info: "Bonded: yes", wantDisc: 1},
		{name: "unbonded entry is removed", info: "Paired: no", wantRemove: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := newFakeBluetoothctl().reply("info", tc.info, nil)
			tr := newCentralTransport(t, &fakeCentral{device: newFakePhone().device}, ctl)

			if err := tr.ConnectWithBondedAddress(context.Background(), phoneAddr, bondedAddr); err != nil {
				t.Fatalf("ConnectWithBondedAddress() error = %v", err)
			}
			if ctl.called("remove", bondedAddr) != tc.wantRemove || ctl.called("disconnect", bondedAddr) != tc.wantDisc {
				t.Fatalf("bluetoothctl calls = %v, want %d remove and %d disconnect of %s",
					ctl.calls, tc.wantRemove, tc.wantDisc, bondedAddr)
			}
			if ctl.called("remove", phoneAddr) != 0 {
				t.Fatalf("bluetoothctl calls = %v, the scanned address must keep its entry", ctl.calls)
			}
		})
	}
}

func TestBLETransport_Connect_TrustFailureIsNotFatal(t *testing.T) {
	ctl := newFakeBluetoothctl().reply("trust", "Device not available", errors.New("exit status 1"))
	tr := newCentralTransport(t, &fakeCentral{device: newFakePhone().device}, ctl)

	if err := tr.Connect(context.Background(), phoneAddr); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
}

// TestBLETransport_Connect_DBusStaleObject pins the recovery for a broken
// BlueZ object: both addresses are removed and the caller is told to re-scan
// instead of the connect being retried against the same object.
func TestBLETransport_Connect_DBusStaleObject(t *testing.T) {
	ctl := newFakeBluetoothctl().reply("remove", "", errors.New("exit status 1"))
	ctl.reply("info", "Paired: yes", nil)
	central := &fakeCentral{
		connectErrs: []error{errDBusStale},
		device:      newFakePhone().device,
		stopScanErr: errors.New("not scanning"),
	}
	tr := newCentralTransport(t, central, ctl)

	err := tr.ConnectWithBondedAddress(context.Background(), phoneAddr, bondedAddr)
	if !errors.Is(err, ErrDBusStaleObject) {
		t.Fatalf("ConnectWithBondedAddress() error = %v, want %v", err, ErrDBusStaleObject)
	}
	if connects, stops := central.counts(); connects != 1 || stops != 1 {
		t.Fatalf("adapter Connect/StopScan calls = %d/%d, want 1/1", connects, stops)
	}
	if ctl.called("remove", phoneAddr) != 1 || ctl.called("remove", bondedAddr) != 1 {
		t.Fatalf("bluetoothctl calls = %v, want both addresses removed", ctl.calls)
	}
	if tr.IsConnected() {
		t.Fatal("IsConnected() = true after a failed connect")
	}
}

func TestBLETransport_Connect_RetriesTransientFailure(t *testing.T) {
	ctl := newFakeBluetoothctl().reply("disconnect", "", errors.New("exit status 1"))
	ctl.reply("info", "Paired: yes", nil)
	central := &fakeCentral{
		connectErrs: []error{errors.New("le-connection-abort-by-local")},
		device:      newFakePhone().device,
	}
	tr := newCentralTransport(t, central, ctl)

	if err := tr.Connect(context.Background(), phoneAddr); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if connects, _ := central.counts(); connects != 2 {
		t.Fatalf("adapter Connect calls = %d, want 2", connects)
	}
	// Between attempts the bonded entry is refreshed, not removed, and trusted again.
	if ctl.called("disconnect", phoneAddr) != 1 || ctl.called("trust", phoneAddr) != 2 || ctl.called("remove", phoneAddr) != 0 {
		t.Fatalf("bluetoothctl calls = %v", ctl.calls)
	}
}

func TestBLETransport_Connect_GivesUpAfterThreeAttempts(t *testing.T) {
	failure := errors.New("le-connection-abort-by-local")
	ctl := newFakeBluetoothctl().reply("trust", "", errors.New("exit status 1"))
	ctl.reply("remove", "", errors.New("exit status 1"))
	central := &fakeCentral{
		connectErrs: []error{failure, failure, failure},
		device:      newFakePhone().device,
		stopScanErr: errors.New("not scanning"),
	}
	tr := newCentralTransport(t, central, ctl)

	if err := tr.Connect(context.Background(), phoneAddr); !errors.Is(err, ErrConnectionFailed) {
		t.Fatalf("Connect() error = %v, want %v", err, ErrConnectionFailed)
	}
	if connects, stops := central.counts(); connects != 3 || stops != 2 {
		t.Fatalf("adapter Connect/StopScan calls = %d/%d, want 3/2", connects, stops)
	}
	if tr.ConnectedAddress() != "" {
		t.Fatalf("ConnectedAddress() = %q after a failed connect, want empty", tr.ConnectedAddress())
	}
}

func TestBLETransport_Connect_FallsBackToFullDiscovery(t *testing.T) {
	phone := newFakePhone()
	other := &fakeService{uuid: bluetooth.New16BitUUID(0x180F)}
	phone.device.discoveries = []discoverReply{
		{err: errors.New("filtered discovery unsupported")},
		{services: []bleService{other}},
		{err: errors.New("org.bluez.Error.InProgress")},
		{services: []bleService{other, phone.service}},
	}
	tr := newCentralTransport(t, &fakeCentral{device: phone.device}, newFakeBluetoothctl())

	if err := tr.Connect(context.Background(), phoneAddr); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if phone.device.discoverCalls != 4 {
		t.Fatalf("DiscoverServices calls = %d, want 4", phone.device.discoverCalls)
	}
}

func TestBLETransport_Connect_FailuresDisconnectTheDevice(t *testing.T) {
	tests := []struct {
		name    string
		breakIt func(p *fakePhone)
		want    error
	}{
		{
			name: "service discovery keeps failing",
			breakIt: func(p *fakePhone) {
				p.device.discoveries = []discoverReply{{err: errors.New("org.bluez.Error.Failed")}}
			},
			want: ErrServiceNotFound,
		},
		{
			name: "xKey service never advertised",
			breakIt: func(p *fakePhone) {
				p.device.discoveries = []discoverReply{{services: []bleService{&fakeService{uuid: bluetooth.New16BitUUID(0x1800)}}}}
			},
			want: ErrServiceNotFound,
		},
		{
			name:    "characteristic discovery fails",
			breakIt: func(p *fakePhone) { p.service.err = errors.New("org.bluez.Error.Failed") },
			want:    ErrCharacteristicNotFound,
		},
		{
			name:    "response characteristic missing",
			breakIt: func(p *fakePhone) { p.service.chars = []bleCharacteristic{p.control, p.status} },
			want:    ErrCharacteristicNotFound,
		},
		{
			name:    "control point missing",
			breakIt: func(p *fakePhone) { p.service.chars = []bleCharacteristic{p.response} },
			want:    ErrCharacteristicNotFound,
		},
		{
			name:    "response notifications refused",
			breakIt: func(p *fakePhone) { p.response.enableErr = errors.New("org.bluez.Error.NotPermitted") },
			want:    ErrCharacteristicNotFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			phone := newFakePhone()
			tc.breakIt(phone)
			phone.device.disconnectErr = errors.New("not connected")
			tr := newCentralTransport(t, &fakeCentral{device: phone.device}, newFakeBluetoothctl())

			if err := tr.Connect(context.Background(), phoneAddr); !errors.Is(err, tc.want) {
				t.Fatalf("Connect() error = %v, want %v", err, tc.want)
			}
			if phone.device.disconnectCount() != 1 {
				t.Fatalf("device Disconnect calls = %d, want 1", phone.device.disconnectCount())
			}
			if tr.IsConnected() {
				t.Fatal("IsConnected() = true after a failed connect")
			}
		})
	}
}

// TestBLETransport_Connect_StatusIsOptional pins that the status
// characteristic is a bonus: missing, or refusing notifications, it does not
// stop the connection.
func TestBLETransport_Connect_StatusIsOptional(t *testing.T) {
	tests := []struct {
		name    string
		breakIt func(p *fakePhone)
	}{
		{name: "status characteristic missing", breakIt: func(p *fakePhone) {
			p.service.chars = []bleCharacteristic{p.control, p.response}
		}},
		{name: "status notifications refused", breakIt: func(p *fakePhone) {
			p.status.enableErr = errors.New("org.bluez.Error.NotPermitted")
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			phone := newFakePhone()
			tc.breakIt(phone)
			tr := newCentralTransport(t, &fakeCentral{device: phone.device}, newFakeBluetoothctl())

			if err := tr.Connect(context.Background(), phoneAddr); err != nil {
				t.Fatalf("Connect() error = %v", err)
			}
			if !tr.IsConnected() {
				t.Fatal("IsConnected() = false")
			}
		})
	}
}

func TestBLETransport_Connect_CancelledContextDisconnects(t *testing.T) {
	phone := newFakePhone()
	ctl := newFakeBluetoothctl()
	tr := newCentralTransport(t, &fakeCentral{device: phone.device}, ctl)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := tr.Connect(ctx, phoneAddr); !errors.Is(err, ErrTimeout) {
		t.Fatalf("Connect() error = %v, want %v", err, ErrTimeout)
	}
	if tr.IsConnected() || phone.device.disconnectCount() != 1 || ctl.called("disconnect", phoneAddr) != 1 {
		t.Fatalf("connected=%v device disconnects=%d bluetoothctl=%v; want the link torn down",
			tr.IsConnected(), phone.device.disconnectCount(), ctl.calls)
	}
}

// --- sending ---

func TestBLETransport_SendAndReceive_RoundTrip(t *testing.T) {
	tr, phone, _ := connectedTransport(t)
	tr.SetMTU(pairingproto.MinMTU)

	// The phone reassembles what the control point receives and answers on
	// the response characteristic.
	request := bytes.Repeat([]byte("request-"), 20)
	inbound := pairingproto.NewReassembler()
	phone.control.onWrite = func(data []byte) {
		frag, err := pairingproto.DecodeFragment(data)
		if err != nil {
			t.Errorf("phone received an undecodable fragment: %v", err)
			return
		}
		complete, err := inbound.AddFragment(frag)
		if err != nil || !complete {
			return
		}
		msg, err := inbound.Assemble()
		if err != nil {
			t.Errorf("phone could not assemble the request: %v", err)
			return
		}
		reply, err := pairingproto.NewFragmenter(DefaultMTU).Fragment(append([]byte("echo:"), msg...))
		if err != nil {
			t.Errorf("phone could not fragment the reply: %v", err)
			return
		}
		for _, f := range reply {
			phone.response.notifier()(f)
		}
	}

	got, err := tr.SendAndReceive(context.Background(), request)
	if err != nil {
		t.Fatalf("SendAndReceive() error = %v", err)
	}
	if want := append([]byte("echo:"), request...); !bytes.Equal(got, want) {
		t.Fatalf("SendAndReceive() = %q, want %q", got, want)
	}
	if n := len(phone.control.written()); n < 2 {
		t.Fatalf("control point writes = %d, want the request split into several fragments", n)
	}
}

func TestBLETransport_Send_WriteFailure(t *testing.T) {
	tr, phone, _ := connectedTransport(t)
	phone.control.writeErr = errors.New("org.bluez.Error.Failed")

	if err := tr.Send(context.Background(), []byte("x")); !errors.Is(err, ErrConnectionFailed) {
		t.Fatalf("Send() error = %v, want %v", err, ErrConnectionFailed)
	}
}

func TestBLETransport_Send_CancelledBeforeWriting(t *testing.T) {
	tr, phone, _ := connectedTransport(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := tr.Send(ctx, []byte("x")); !errors.Is(err, ErrTimeout) {
		t.Fatalf("Send() error = %v, want %v", err, ErrTimeout)
	}
	if n := len(phone.control.written()); n != 0 {
		t.Fatalf("control point writes = %d, want 0", n)
	}
}

// TestBLETransport_Send_CancelledDuringBlockedWrite pins that a write stuck
// in BlueZ does not hold Send past its context.
func TestBLETransport_Send_CancelledDuringBlockedWrite(t *testing.T) {
	tr, phone, _ := connectedTransport(t)
	phone.control.release = make(chan struct{})
	defer close(phone.control.release)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	if err := tr.Send(ctx, []byte("x")); !errors.Is(err, ErrTimeout) {
		t.Fatalf("Send() error = %v, want %v", err, ErrTimeout)
	}
}

func TestBLETransport_Send_MessageTooLargeToFragment(t *testing.T) {
	tr, phone, _ := connectedTransport(t)
	tr.SetMTU(pairingproto.MinMTU)
	tooLarge := make([]byte, 65536*(pairingproto.MinMTU-pairingproto.FragmentHeaderSize))

	if err := tr.Send(context.Background(), tooLarge); !errors.Is(err, pairingproto.ErrFragmentationError) {
		t.Fatalf("Send() error = %v, want %v", err, pairingproto.ErrFragmentationError)
	}
	if n := len(phone.control.written()); n != 0 {
		t.Fatalf("control point writes = %d, want 0", n)
	}
}

// --- disconnecting ---

func TestBLETransport_Disconnect_KeepsBond(t *testing.T) {
	tr, phone, ctl := connectedTransport(t)
	phone.device.disconnectErr = errors.New("already disconnected")
	ctl.reply("disconnect", "Device not connected", errors.New("exit status 1"))
	tr.responseChan <- []byte("leftover")
	tr.statusChan <- []byte{0x01}

	if err := tr.Disconnect(); err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}
	if tr.IsConnected() || phone.device.disconnectCount() != 1 {
		t.Fatalf("connected=%v device disconnects=%d; want disconnected once", tr.IsConnected(), phone.device.disconnectCount())
	}
	if ctl.called("disconnect", phoneAddr) != 1 || ctl.called("remove", phoneAddr) != 0 {
		t.Fatalf("bluetoothctl calls = %v, want a disconnect and no remove", ctl.calls)
	}
	if len(tr.responseChan) != 0 || len(tr.statusChan) != 0 {
		t.Fatal("Disconnect() left stale data for the next connection")
	}
}

func TestBLETransport_Disconnect_BlueZFailureIsNotFatal(t *testing.T) {
	tr, _, ctl := connectedTransport(t)
	ctl.reply("disconnect", "org.bluez.Error.Failed", errors.New("exit status 1"))

	if err := tr.Disconnect(); err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}
	if tr.IsConnected() {
		t.Fatal("IsConnected() = true after Disconnect")
	}
}

func TestBLETransport_DisconnectAndRemove_RemovesDevice(t *testing.T) {
	tr, phone, ctl := connectedTransport(t)
	ctl.reply("remove", "", errors.New("exit status 1"))

	if err := tr.DisconnectAndRemove(); err != nil {
		t.Fatalf("DisconnectAndRemove() error = %v", err)
	}
	if phone.device.disconnectCount() != 1 || ctl.called("remove", phoneAddr) != 1 || ctl.called("disconnect", phoneAddr) != 0 {
		t.Fatalf("device disconnects=%d bluetoothctl=%v; want one disconnect and a remove",
			phone.device.disconnectCount(), ctl.calls)
	}

	// Removing again after the link is down still clears the BlueZ entry.
	if err := tr.DisconnectAndRemove(); err != nil {
		t.Fatalf("second DisconnectAndRemove() error = %v", err)
	}
	if ctl.called("remove", phoneAddr) != 2 || phone.device.disconnectCount() != 1 {
		t.Fatalf("device disconnects=%d bluetoothctl=%v; want a second remove only",
			phone.device.disconnectCount(), ctl.calls)
	}
}

func TestBLETransport_DisconnectAndRemove_NeverConnectedIsANoop(t *testing.T) {
	ctl := newFakeBluetoothctl()
	tr := newCentralTransport(t, newFakeCentral(), ctl)

	if err := tr.DisconnectAndRemove(); err != nil {
		t.Fatalf("DisconnectAndRemove() error = %v", err)
	}
	if len(ctl.calls) != 0 {
		t.Fatalf("bluetoothctl calls = %v, want none", ctl.calls)
	}
}

// --- BlueZ cache cleanup ---

func TestBLETransport_CleanStaleBlueZEntry(t *testing.T) {
	tests := []struct {
		name       string
		info       string
		infoErr    error
		wantRemove bool
	}{
		{name: "unknown to BlueZ", infoErr: errors.New("exit status 1")},
		{name: "not available", info: "Device AA:BB:CC:DD:EE:01 not available"},
		{name: "BLE-only entry is kept", info: "Paired: yes\nUUID: Generic Access Profile"},
		{name: "connected classic entry is kept", info: "UUID: Audio Sink\nConnected: yes"},
		{name: "audio sink", info: "UUID: Audio Sink\nConnected: no", wantRemove: true},
		{name: "handsfree", info: "UUID: Handsfree\nConnected: no", wantRemove: true},
		{name: "obex", info: "UUID: OBEX Object Push", wantRemove: true},
		{name: "A2DP UUID", info: "UUID: 0000110a-0000-1000-8000-00805f9b34fb", wantRemove: true},
		{name: "HSP UUID", info: "UUID: 00001112-0000-1000-8000-00805f9b34fb", wantRemove: true},
		{name: "OPP UUID", info: "UUID: 00001105-0000-1000-8000-00805f9b34fb", wantRemove: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := newFakeBluetoothctl().reply("info", tc.info, tc.infoErr)
			ctl.reply("remove", "", errors.New("exit status 1"))
			tr := newCentralTransport(t, newFakeCentral(), ctl)

			tr.CleanStaleBlueZEntry(phoneAddr)

			if removed := ctl.called("remove", phoneAddr) == 1; removed != tc.wantRemove {
				t.Fatalf("removed = %v, want %v (bluetoothctl calls %v)", removed, tc.wantRemove, ctl.calls)
			}
		})
	}
}

// --- bluetoothctl helpers ---

func TestBLETransport_BluetoothctlFailuresAreReported(t *testing.T) {
	ctl := newFakeBluetoothctl().
		reply("trust", "Device not available", errors.New("exit status 1")).
		reply("remove", "Device not available", errors.New("exit status 1")).
		reply("disconnect", "org.bluez.Error.Failed", errors.New("exit status 1"))
	tr := newCentralTransport(t, newFakeCentral(), ctl)

	for name, err := range map[string]error{
		"trust":      tr.trustBlueZDevice(phoneAddr),
		"remove":     tr.removeBlueZDevice(phoneAddr),
		"disconnect": tr.disconnectBlueZDevice(phoneAddr),
	} {
		var msgErr *MessageError
		if !errors.As(err, &msgErr) {
			t.Errorf("%s error = %v, want a *MessageError", name, err)
		}
	}
}

func TestBLETransport_BluetoothctlSuccess(t *testing.T) {
	ctl := newFakeBluetoothctl().reply("disconnect", "Device not connected", errors.New("exit status 1"))
	tr := newCentralTransport(t, newFakeCentral(), ctl)

	if err := tr.trustBlueZDevice(phoneAddr); err != nil {
		t.Errorf("trustBlueZDevice() error = %v", err)
	}
	if err := tr.removeBlueZDevice(phoneAddr); err != nil {
		t.Errorf("removeBlueZDevice() error = %v", err)
	}
	if err := tr.disconnectBlueZDevice(phoneAddr); err != nil {
		t.Errorf("disconnectBlueZDevice() of a disconnected device error = %v, want nil", err)
	}
}

func TestBLETransport_IsDevicePaired(t *testing.T) {
	tests := []struct {
		name string
		info string
		err  error
		want bool
	}{
		{name: "paired", info: "Paired: yes", want: true},
		{name: "bonded", info: "Bonded: yes", want: true},
		{name: "neither", info: "Paired: no\nBonded: no"},
		{name: "unknown device", info: "Paired: yes", err: errors.New("exit status 1")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := newFakeBluetoothctl().reply("info", tc.info, tc.err)
			tr := newCentralTransport(t, newFakeCentral(), ctl)

			if got := tr.isDevicePaired(phoneAddr); got != tc.want {
				t.Fatalf("isDevicePaired() = %v, want %v", got, tc.want)
			}
		})
	}
}
