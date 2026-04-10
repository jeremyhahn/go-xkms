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

package notify

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSystemBusBusObject implements dbus.BusObject for system bus mock calls.
type mockSystemBusBusObject struct {
	callErr    error
	lastMethod string
	lastArgs   []interface{}
}

func (m *mockSystemBusBusObject) Call(method string, flags dbus.Flags, args ...interface{}) *dbus.Call {
	m.lastMethod = method
	m.lastArgs = args
	call := &dbus.Call{}
	call.Err = m.callErr
	return call
}

func (m *mockSystemBusBusObject) CallWithContext(_ context.Context, method string, flags dbus.Flags, args ...interface{}) *dbus.Call {
	return m.Call(method, flags, args...)
}

func (m *mockSystemBusBusObject) Go(method string, flags dbus.Flags, ch chan *dbus.Call, args ...interface{}) *dbus.Call {
	return m.Call(method, flags, args...)
}

func (m *mockSystemBusBusObject) GoWithContext(_ context.Context, method string, flags dbus.Flags, ch chan *dbus.Call, args ...interface{}) *dbus.Call {
	return m.Call(method, flags, args...)
}

func (m *mockSystemBusBusObject) AddMatchSignal(iface, member string, options ...dbus.MatchOption) *dbus.Call {
	return &dbus.Call{}
}

func (m *mockSystemBusBusObject) RemoveMatchSignal(iface, member string, options ...dbus.MatchOption) *dbus.Call {
	return &dbus.Call{}
}

func (m *mockSystemBusBusObject) GetProperty(p string) (dbus.Variant, error) {
	return dbus.Variant{}, nil
}

func (m *mockSystemBusBusObject) StoreProperty(p string, value interface{}) error {
	return nil
}

func (m *mockSystemBusBusObject) SetProperty(p string, v interface{}) error {
	return nil
}

func (m *mockSystemBusBusObject) Destination() string {
	return "org.freedesktop.login1"
}

func (m *mockSystemBusBusObject) Path() dbus.ObjectPath {
	return "/org/freedesktop/login1"
}

// mockSystemBusConn implements the systemBusConnection interface for testing.
type mockSystemBusConn struct {
	busObj        *mockSystemBusBusObject
	closed        bool
	closeErr      error
	signalCalled  bool
	removedSignal bool
}

func (m *mockSystemBusConn) Signal(ch chan<- *dbus.Signal) {
	m.signalCalled = true
}

func (m *mockSystemBusConn) RemoveSignal(ch chan<- *dbus.Signal) {
	m.removedSignal = true
}

func (m *mockSystemBusConn) BusObject() dbus.BusObject {
	return m.busObj
}

func (m *mockSystemBusConn) Close() error {
	m.closed = true
	return m.closeErr
}

// waitForCallback polls the atomic counter until it reaches the expected value
// or the timeout expires. Returns true if the expected count was reached.
func waitForCallback(counter *atomic.Int32, expected int32, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if counter.Load() >= expected {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return counter.Load() >= expected
}

func TestScreenLockMonitorCallback(t *testing.T) {
	conn := &mockSystemBusConn{busObj: &mockSystemBusBusObject{}}
	signalCh := make(chan *dbus.Signal, signalChannelSize)

	var callbackCount atomic.Int32
	callback := func() {
		callbackCount.Add(1)
	}

	m := newScreenLockMonitorWithConn(conn, signalCh, callback, slog.Default())

	// Send a Lock signal.
	signalCh <- &dbus.Signal{
		Name: logindLockSignalName,
	}

	// Wait for the callback to fire.
	require.True(t, waitForCallback(&callbackCount, 1, time.Second),
		"callback should have been invoked once")
	assert.Equal(t, int32(1), callbackCount.Load())

	// Send a second Lock signal to verify repeated delivery.
	signalCh <- &dbus.Signal{
		Name: logindLockSignalName,
	}

	require.True(t, waitForCallback(&callbackCount, 2, time.Second),
		"callback should have been invoked twice")
	assert.Equal(t, int32(2), callbackCount.Load())

	// Clean up.
	require.NoError(t, m.Close())
}

func TestScreenLockMonitorIgnoresOtherSignals(t *testing.T) {
	conn := &mockSystemBusConn{busObj: &mockSystemBusBusObject{}}
	signalCh := make(chan *dbus.Signal, signalChannelSize)

	var callbackCount atomic.Int32
	callback := func() {
		callbackCount.Add(1)
	}

	m := newScreenLockMonitorWithConn(conn, signalCh, callback, slog.Default())

	// Send signals that are NOT Lock signals.
	signalCh <- &dbus.Signal{
		Name: "org.freedesktop.login1.Session.Unlock",
	}
	signalCh <- &dbus.Signal{
		Name: "org.freedesktop.DBus.NameOwnerChanged",
	}
	signalCh <- &dbus.Signal{
		Name: "org.freedesktop.login1.Manager.SessionNew",
	}

	// Send a sentinel Lock signal to confirm the goroutine processed all preceding signals.
	signalCh <- &dbus.Signal{
		Name: logindLockSignalName,
	}

	require.True(t, waitForCallback(&callbackCount, 1, time.Second),
		"callback should have fired exactly once for the Lock signal")
	assert.Equal(t, int32(1), callbackCount.Load(),
		"non-Lock signals must not trigger the callback")

	require.NoError(t, m.Close())
}

func TestScreenLockMonitorClose(t *testing.T) {
	conn := &mockSystemBusConn{busObj: &mockSystemBusBusObject{}}
	signalCh := make(chan *dbus.Signal, signalChannelSize)

	m := newScreenLockMonitorWithConn(conn, signalCh, func() {}, slog.Default())

	// First close succeeds.
	err := m.Close()
	require.NoError(t, err)
	assert.True(t, conn.closed, "connection should be closed")
	assert.True(t, conn.removedSignal, "signal registration should be removed")
	assert.True(t, m.closed.Load(), "monitor should be marked as closed")

	// Second close is idempotent and returns nil.
	err = m.Close()
	require.NoError(t, err)
}

func TestScreenLockMonitorCloseIdempotent(t *testing.T) {
	conn := &mockSystemBusConn{busObj: &mockSystemBusBusObject{}}
	signalCh := make(chan *dbus.Signal, signalChannelSize)

	m := newScreenLockMonitorWithConn(conn, signalCh, func() {}, slog.Default())

	// Call Close multiple times; all must succeed.
	for i := 0; i < 5; i++ {
		err := m.Close()
		require.NoError(t, err, "Close call %d should return nil", i+1)
	}

	assert.True(t, m.closed.Load())
}

func TestScreenLockMonitorClosedDoesNotCallback(t *testing.T) {
	conn := &mockSystemBusConn{busObj: &mockSystemBusBusObject{}}
	signalCh := make(chan *dbus.Signal, signalChannelSize)

	var callbackCount atomic.Int32
	callback := func() {
		callbackCount.Add(1)
	}

	m := newScreenLockMonitorWithConn(conn, signalCh, callback, slog.Default())

	// Close the monitor first.
	require.NoError(t, m.Close())

	// The channel is closed by Close(), so we cannot send to it. Verify the
	// callback was never invoked.
	assert.Equal(t, int32(0), callbackCount.Load(),
		"callback must not fire after Close")
}

func TestScreenLockMonitorCloseError(t *testing.T) {
	closeErr := ErrScreenLockUnavailable
	conn := &mockSystemBusConn{
		busObj:   &mockSystemBusBusObject{},
		closeErr: closeErr,
	}
	signalCh := make(chan *dbus.Signal, signalChannelSize)

	m := newScreenLockMonitorWithConn(conn, signalCh, func() {}, slog.Default())

	err := m.Close()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrScreenLockUnavailable)
}

func TestScreenLockMonitorCloseRemovesMatchRule(t *testing.T) {
	busObj := &mockSystemBusBusObject{}
	conn := &mockSystemBusConn{busObj: busObj}
	signalCh := make(chan *dbus.Signal, signalChannelSize)

	m := newScreenLockMonitorWithConn(conn, signalCh, func() {}, slog.Default())

	require.NoError(t, m.Close())

	// Verify RemoveMatch was called with the correct rule.
	assert.Equal(t, "org.freedesktop.DBus.RemoveMatch", busObj.lastMethod)
	require.Len(t, busObj.lastArgs, 1)
	assert.Equal(t, screenLockMatchRule, busObj.lastArgs[0])
}

func TestScreenLockMonitorConstants(t *testing.T) {
	assert.Equal(t, "org.freedesktop.login1.Session", logindSessionInterface)
	assert.Equal(t, "Lock", logindLockMember)
	assert.Equal(t, "org.freedesktop.login1.Session.Lock", logindLockSignalName)
	assert.Contains(t, screenLockMatchRule, "interface='org.freedesktop.login1.Session'")
	assert.Contains(t, screenLockMatchRule, "member='Lock'")
	assert.Equal(t, 16, signalChannelSize)
}

func TestNewScreenLockMonitor_Unavailable(t *testing.T) {
	// In CI / headless environments, the system bus is typically not available.
	// This test verifies that the constructor returns ErrScreenLockUnavailable
	// when the system bus cannot be reached.
	m, err := NewScreenLockMonitor(slog.Default(), func() {})
	if err != nil {
		assert.ErrorIs(t, err, ErrScreenLockUnavailable)
		assert.Nil(t, m)
	} else {
		// If a system bus happens to be available, just close cleanly.
		require.NoError(t, m.Close())
	}
}
