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

package phone

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errFakeConnect is a generic (non-D-Bus) connection failure used to exercise
// the force-remove-and-rescan retry branch of connectBLE.
var errFakeConnect = errors.New("fake: connect failed")

// connectAttempt records the arguments of one ConnectWithBondedAddress call.
type connectAttempt struct {
	address string
	bonded  string
}

// fakeBLETransport implements BLECapableTransport on top of an in-memory pipe.
// Scan results, per-attempt connect errors, and BlueZ bookkeeping calls are
// scriptable/recordable so the connectBLE retry state machine can be driven
// deterministically without a Bluetooth adapter.
type fakeBLETransport struct {
	inner *mockPipeTransport

	mu              sync.Mutex
	scanResults     []ScanResult
	scanErr         error
	scanCalls       int
	connectErrs     []error // consumed one per connect attempt; nil means success
	connectAttempts []connectAttempt
	cleanCalls      []string
	removeCalls     int
	disconnectCalls int
	connectedAddr   string
}

func (f *fakeBLETransport) Send(ctx context.Context, message []byte) error {
	return f.inner.Send(ctx, message)
}

func (f *fakeBLETransport) Receive(ctx context.Context) ([]byte, error) {
	return f.inner.Receive(ctx)
}

func (f *fakeBLETransport) SendAndReceive(ctx context.Context, message []byte) ([]byte, error) {
	return f.inner.SendAndReceive(ctx, message)
}

func (f *fakeBLETransport) IsConnected() bool { return f.inner.IsConnected() }

func (f *fakeBLETransport) Close() error { return f.inner.Close() }

func (f *fakeBLETransport) Scan(_ context.Context) ([]ScanResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scanCalls++
	if f.scanErr != nil {
		return nil, f.scanErr
	}
	return f.scanResults, nil
}

func (f *fakeBLETransport) ConnectWithBondedAddress(_ context.Context, address, bondedAddress string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connectAttempts = append(f.connectAttempts, connectAttempt{address: address, bonded: bondedAddress})
	if len(f.connectErrs) > 0 {
		err := f.connectErrs[0]
		f.connectErrs = f.connectErrs[1:]
		if err != nil {
			return err
		}
	}
	f.connectedAddr = address
	return nil
}

func (f *fakeBLETransport) Disconnect() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disconnectCalls++
	f.connectedAddr = ""
	return nil
}

func (f *fakeBLETransport) ConnectedAddress() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.connectedAddr
}

func (f *fakeBLETransport) CleanStaleBlueZEntry(address string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cleanCalls = append(f.cleanCalls, address)
}

func (f *fakeBLETransport) DisconnectAndRemove() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removeCalls++
	f.connectedAddr = ""
	return nil
}

func (f *fakeBLETransport) snapshot() (scans int, attempts []connectAttempt, cleans []string, removes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.scanCalls, append([]connectAttempt(nil), f.connectAttempts...), append([]string(nil), f.cleanCalls...), f.removeCalls
}

// recordedConnectionEvent is one captured audit connection event.
type recordedConnectionEvent struct {
	op         audit.OperationType
	deviceID   string
	deviceName string
	details    map[string]any
}

// recordingAuditLogger captures connection events. Only LogConnectionEvent is
// implemented; any other call panics through the nil embedded interface, which
// deliberately fails the test if the backend starts emitting unexpected audit
// categories from the connection path.
type recordingAuditLogger struct {
	audit.Logger

	mu     sync.Mutex
	events []recordedConnectionEvent
}

func (l *recordingAuditLogger) LogConnectionEvent(op audit.OperationType, deviceID, deviceName string, details map[string]any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, recordedConnectionEvent{op: op, deviceID: deviceID, deviceName: deviceName, details: details})
	return nil
}

func (l *recordingAuditLogger) recorded() []recordedConnectionEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]recordedConnectionEvent(nil), l.events...)
}

// runRetryResponder services successive handshake attempts on the responder
// side of the pipe. The first failFirst attempts are answered with an invalid
// identity-ack status so the initiator's handshake fails and connectBLE
// retries; later attempts complete a full Noise XX handshake.
func runRetryResponder(t *testing.T, transport *mockPipeTransport, failFirst int, stop <-chan struct{}) {
	t.Helper()

	attempt := 0
	for {
		var identityMsg []byte
		select {
		case identityMsg = <-transport.recvCh:
		case <-stop:
			return
		}

		attempt++
		if len(identityMsg) != pairingproto.IdentityMsgSize || identityMsg[0] != pairingproto.IdentityMsgVersion {
			t.Errorf("responder: malformed identity message: %v", identityMsg)
			return
		}

		if attempt <= failFirst {
			// 0xEE is neither IdentityAckKnown nor IdentityAckUnknown.
			transport.sendCh <- []byte{0xEE}
			continue
		}

		transport.sendCh <- []byte{pairingproto.IdentityAckUnknown}

		session, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{IsInitiator: false})
		if err != nil {
			t.Errorf("responder: new session: %v", err)
			return
		}
		if err := session.InitHandshake(); err != nil {
			t.Errorf("responder: init handshake: %v", err)
			return
		}

		msg1 := <-transport.recvCh
		msg2, complete, err := session.HandshakeMessage(msg1)
		if err != nil || complete {
			t.Errorf("responder: msg1 processing failed: err=%v complete=%v", err, complete)
			return
		}
		transport.sendCh <- msg2

		msg3 := <-transport.recvCh
		if _, complete, err = session.HandshakeMessage(msg3); err != nil || !complete {
			t.Errorf("responder: msg3 processing failed: err=%v complete=%v", err, complete)
			return
		}
	}
}

// newBLEConnectFixture wires a PhoneKeyBackend to a fakeBLETransport and starts
// a responder that fails the first failFirst handshakes.
func newBLEConnectFixture(t *testing.T, cfg *PhoneKeyBackendConfig, fake *fakeBLETransport, failFirst int) *PhoneKeyBackend {
	t.Helper()

	initiator, responder := newPipeTransports()
	fake.inner = initiator

	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}

	backend, err := NewPhoneKeyBackendWithTransport(cfg, fake)
	require.NoError(t, err)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		runRetryResponder(t, responder, failFirst, stop)
	}()
	t.Cleanup(func() {
		close(stop)
		_ = backend.Close()
		<-done
	})

	return backend
}

func TestPhoneKeyBackend_ConnectBLE_ScanThenHandshakeSucceeds(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	fake := &fakeBLETransport{scanResults: []ScanResult{{Address: "AA:BB:CC:DD:EE:FF", LocalName: "xKey"}}}
	auditLog := &recordingAuditLogger{}
	backend := newBLEConnectFixture(t, &PhoneKeyBackendConfig{
		TrustNewDevices: true,
		DeviceAddress:   "11:22:33:44:55:66",
		DeviceName:      "pixel",
		AuditLogger:     auditLog,
		MTU:             DefaultMTU,
	}, fake, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.NoError(t, backend.Connect(ctx))
	assert.True(t, backend.IsConnected())

	scans, attempts, cleans, removes := fake.snapshot()
	assert.Equal(t, 1, scans, "exactly one scan for a first-try success")
	assert.Equal(t, 0, removes, "no BlueZ force-remove on success")
	assert.Equal(t, []string{"11:22:33:44:55:66"}, cleans,
		"the configured (bonded) address must be pre-emptively cleaned from the BlueZ cache")
	require.Len(t, attempts, 1)
	assert.Equal(t, "AA:BB:CC:DD:EE:FF", attempts[0].address, "must connect to the scanned RPA")
	assert.Equal(t, "11:22:33:44:55:66", attempts[0].bonded, "bonded address must be passed for IRK resolution")

	// ConnectedAddress must surface the rotated address, not the configured one.
	assert.Equal(t, "AA:BB:CC:DD:EE:FF", backend.ConnectedAddress())

	events := auditLog.recorded()
	require.Len(t, events, 1)
	assert.Equal(t, audit.OpConnectionEstablished, events[0].op)
	assert.Equal(t, "AA:BB:CC:DD:EE:FF", events[0].deviceID)
	assert.Equal(t, "pixel", events[0].deviceName)
	assert.Equal(t, "ble", events[0].details["transport"])
	assert.Equal(t, DefaultMTU, events[0].details["mtu"])

	// A second Connect is a no-op and must not re-scan.
	require.NoError(t, backend.Connect(ctx))
	scans2, attempts2, _, _ := fake.snapshot()
	assert.Equal(t, scans, scans2)
	assert.Len(t, attempts2, 1)
}

func TestPhoneKeyBackend_ConnectBLE_RetriesAfterHandshakeFailure(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	fake := &fakeBLETransport{scanResults: []ScanResult{{Address: "AA:BB:CC:DD:EE:FF"}}}
	backend := newBLEConnectFixture(t, &PhoneKeyBackendConfig{
		TrustNewDevices: true,
	}, fake, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.NoError(t, backend.Connect(ctx))
	assert.True(t, backend.IsConnected())

	scans, attempts, cleans, removes := fake.snapshot()
	assert.Equal(t, 2, scans, "a failed handshake must trigger a fresh scan")
	assert.Len(t, attempts, 2)
	assert.Equal(t, 1, removes, "the device must be force-removed from BlueZ after a failed handshake")
	assert.Empty(t, cleans, "no pre-emptive clean when no bonded address is configured")
}

func TestPhoneKeyBackend_ConnectBLE_HandshakeFailsOnEveryAttempt(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	fake := &fakeBLETransport{scanResults: []ScanResult{{Address: "AA:BB:CC:DD:EE:FF"}}}
	backend := newBLEConnectFixture(t, &PhoneKeyBackendConfig{
		TrustNewDevices: true,
	}, fake, 3)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := backend.Connect(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoiseHandshakeFailed)
	assert.False(t, backend.IsConnected())

	scans, attempts, _, removes := fake.snapshot()
	assert.Equal(t, 3, scans, "connectBLE allows exactly 3 attempts")
	assert.Len(t, attempts, 3)
	assert.Equal(t, 3, removes)
}

func TestPhoneKeyBackend_ConnectBLE_StaleDBusObjectRescansAndFails(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	fake := &fakeBLETransport{
		scanResults: []ScanResult{{Address: "AA:BB:CC:DD:EE:FF"}},
		connectErrs: []error{ErrDBusStaleObject, ErrDBusStaleObject, ErrDBusStaleObject},
	}
	backend := newBLEConnectFixture(t, &PhoneKeyBackendConfig{
		TrustNewDevices: true,
	}, fake, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := backend.Connect(ctx)
	assert.ErrorIs(t, err, ErrDBusStaleObject)
	assert.False(t, backend.IsConnected())

	scans, attempts, _, removes := fake.snapshot()
	assert.Equal(t, 3, scans)
	assert.Len(t, attempts, 3)
	assert.Equal(t, 0, removes,
		"stale-object errors already removed the device; connectBLE must not force-remove again")
}

func TestPhoneKeyBackend_ConnectBLE_GenericConnectErrorForcesRemoveThenSucceeds(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	fake := &fakeBLETransport{
		scanResults: []ScanResult{{Address: "AA:BB:CC:DD:EE:FF"}},
		connectErrs: []error{errFakeConnect},
	}
	backend := newBLEConnectFixture(t, &PhoneKeyBackendConfig{
		TrustNewDevices: true,
	}, fake, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.NoError(t, backend.Connect(ctx))

	scans, attempts, _, removes := fake.snapshot()
	assert.Equal(t, 2, scans)
	assert.Len(t, attempts, 2)
	assert.Equal(t, 1, removes, "a generic connect failure must force-remove before retrying")
}

func TestPhoneKeyBackend_ConnectBLE_GenericConnectErrorOnLastAttemptReturnsError(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	fake := &fakeBLETransport{
		scanResults: []ScanResult{{Address: "AA:BB:CC:DD:EE:FF"}},
		connectErrs: []error{errFakeConnect, errFakeConnect, errFakeConnect},
	}
	backend := newBLEConnectFixture(t, &PhoneKeyBackendConfig{
		TrustNewDevices: true,
	}, fake, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := backend.Connect(ctx)
	assert.ErrorIs(t, err, errFakeConnect)

	_, _, _, removes := fake.snapshot()
	assert.Equal(t, 2, removes, "the final attempt returns without an extra force-remove")
}

func TestPhoneKeyBackend_ConnectBLE_ScanFailureFallsBackToSavedAddress(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	fake := &fakeBLETransport{scanErr: ErrAdapterDisabled}
	backend := newBLEConnectFixture(t, &PhoneKeyBackendConfig{
		TrustNewDevices: true,
		DeviceAddress:   "11:22:33:44:55:66",
	}, fake, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.NoError(t, backend.Connect(ctx))

	_, attempts, _, _ := fake.snapshot()
	require.Len(t, attempts, 1)
	assert.Equal(t, "11:22:33:44:55:66", attempts[0].address,
		"a failing scan must fall back to the saved address rather than aborting")
}

func TestPhoneKeyBackend_ConnectBLE_ScanFailureWithoutSavedAddressFails(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	fake := &fakeBLETransport{scanErr: ErrAdapterDisabled}
	backend := newBLEConnectFixture(t, &PhoneKeyBackendConfig{
		TrustNewDevices: true,
	}, fake, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := backend.Connect(ctx)
	assert.ErrorIs(t, err, ErrAdapterDisabled)

	scans, attempts, _, _ := fake.snapshot()
	assert.Equal(t, 3, scans)
	assert.Empty(t, attempts, "no connection may be attempted when no address is known")
}

func TestPhoneKeyBackend_ConnectBLE_NoDevicesFoundWithoutSavedAddress(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	fake := &fakeBLETransport{scanResults: nil}
	backend := newBLEConnectFixture(t, &PhoneKeyBackendConfig{
		TrustNewDevices: true,
	}, fake, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := backend.Connect(ctx)
	assert.ErrorIs(t, err, ErrDeviceNotFound)

	_, attempts, _, _ := fake.snapshot()
	assert.Empty(t, attempts)
}

func TestPhoneKeyBackend_ConnectBLE_NoDevicesFoundFallsBackToSavedAddress(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	fake := &fakeBLETransport{scanResults: []ScanResult{}}
	backend := newBLEConnectFixture(t, &PhoneKeyBackendConfig{
		TrustNewDevices: true,
		DeviceAddress:   "11:22:33:44:55:66",
	}, fake, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.NoError(t, backend.Connect(ctx))

	_, attempts, _, _ := fake.snapshot()
	require.Len(t, attempts, 1)
	assert.Equal(t, "11:22:33:44:55:66", attempts[0].address)
}

func TestPhoneKeyBackend_Connect_ClosedBackend(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	fake := &fakeBLETransport{scanResults: []ScanResult{{Address: "AA:BB:CC:DD:EE:FF"}}}
	backend := newBLEConnectFixture(t, &PhoneKeyBackendConfig{
		TrustNewDevices: true,
	}, fake, 0)

	require.NoError(t, backend.Close())

	err := backend.Connect(context.Background())
	assert.ErrorIs(t, err, ErrBackendClosed)

	scans, attempts, _, _ := fake.snapshot()
	assert.Zero(t, scans, "a closed backend must not touch the radio")
	assert.Empty(t, attempts)
}
