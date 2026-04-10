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
	"errors"
	"log/slog"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockBusObject implements dbus.BusObject for testing D-Bus notification calls.
type mockBusObject struct {
	callErr    error
	lastMethod string
	lastArgs   []interface{}
}

func (m *mockBusObject) Call(method string, flags dbus.Flags, args ...interface{}) *dbus.Call {
	m.lastMethod = method
	m.lastArgs = args
	call := &dbus.Call{}
	call.Err = m.callErr
	return call
}

func (m *mockBusObject) CallWithContext(_ context.Context, method string, flags dbus.Flags, args ...interface{}) *dbus.Call {
	return m.Call(method, flags, args...)
}

func (m *mockBusObject) Go(method string, flags dbus.Flags, ch chan *dbus.Call, args ...interface{}) *dbus.Call {
	return m.Call(method, flags, args...)
}

func (m *mockBusObject) GoWithContext(_ context.Context, method string, flags dbus.Flags, ch chan *dbus.Call, args ...interface{}) *dbus.Call {
	return m.Call(method, flags, args...)
}

func (m *mockBusObject) AddMatchSignal(iface, member string, options ...dbus.MatchOption) *dbus.Call {
	return &dbus.Call{}
}

func (m *mockBusObject) RemoveMatchSignal(iface, member string, options ...dbus.MatchOption) *dbus.Call {
	return &dbus.Call{}
}

func (m *mockBusObject) GetProperty(p string) (dbus.Variant, error) {
	return dbus.Variant{}, nil
}

func (m *mockBusObject) StoreProperty(p string, value interface{}) error {
	return nil
}

func (m *mockBusObject) SetProperty(p string, v interface{}) error {
	return nil
}

func (m *mockBusObject) Destination() string {
	return dbusNotifyDest
}

func (m *mockBusObject) Path() dbus.ObjectPath {
	return dbusNotifyPath
}

// mockDBusConn implements the dbusConnection interface for testing.
type mockDBusConn struct {
	obj        *mockBusObject
	closed     bool
	closeErr   error
	objectDest string
	objectPath dbus.ObjectPath
}

func (m *mockDBusConn) Object(dest string, path dbus.ObjectPath) dbus.BusObject {
	m.objectDest = dest
	m.objectPath = path
	return m.obj
}

func (m *mockDBusConn) Close() error {
	m.closed = true
	return m.closeErr
}

func TestNewDBusNotifier_Unavailable(t *testing.T) {
	// In CI / headless environments, the session bus is typically not available.
	// This test verifies that the constructor returns ErrDBusUnavailable
	// when the session bus cannot be opened.
	n, err := NewDBusNotifier(slog.Default())
	if err != nil {
		assert.ErrorIs(t, err, ErrDBusUnavailable)
		assert.Nil(t, n)
	} else {
		// If a session bus happens to be available, just close cleanly.
		require.NoError(t, n.Close())
	}
}

func TestDBusNotifier_NotifyTouchRequired(t *testing.T) {
	obj := &mockBusObject{}
	conn := &mockDBusConn{obj: obj}
	n := newDBusNotifierWithConn(conn, slog.Default())

	req := &TouchRequest{
		Operation: "register",
		RPID:      "example.com",
		RPName:    "Example Corp",
		UserName:  "alice",
	}

	err := n.NotifyTouchRequired(req)
	require.NoError(t, err)

	assert.Equal(t, dbusNotifyMethod, obj.lastMethod)
	assert.Equal(t, dbusNotifyDest, conn.objectDest)
	assert.Equal(t, dbus.ObjectPath(dbusNotifyPath), conn.objectPath)

	// Verify the notification arguments.
	require.GreaterOrEqual(t, len(obj.lastArgs), 8)
	assert.Equal(t, dbusAppName, obj.lastArgs[0])                         // app_name
	assert.Equal(t, uint32(0), obj.lastArgs[1])                           // replaces_id
	assert.Equal(t, "", obj.lastArgs[2])                                  // app_icon
	assert.Equal(t, "Touch Required", obj.lastArgs[3])                    // summary
	assert.Equal(t, "Approve register for Example Corp", obj.lastArgs[4]) // body
	assert.Equal(t, dbusTimeout, obj.lastArgs[7])                         // timeout
}

func TestDBusNotifier_NotifyTouchRequired_FallsBackToRPID(t *testing.T) {
	obj := &mockBusObject{}
	conn := &mockDBusConn{obj: obj}
	n := newDBusNotifierWithConn(conn, slog.Default())

	req := &TouchRequest{
		Operation: "authenticate",
		RPID:      "example.com",
		RPName:    "",
	}

	err := n.NotifyTouchRequired(req)
	require.NoError(t, err)
	assert.Equal(t, "Approve authenticate for example.com", obj.lastArgs[4])
}

func TestDBusNotifier_NotifyTouchRequired_CallFails(t *testing.T) {
	obj := &mockBusObject{callErr: errors.New("dbus: connection closed")}
	conn := &mockDBusConn{obj: obj}
	n := newDBusNotifierWithConn(conn, slog.Default())

	req := &TouchRequest{
		Operation: "register",
		RPID:      "example.com",
	}

	err := n.NotifyTouchRequired(req)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotificationFailed)
}

func TestDBusNotifier_Close(t *testing.T) {
	conn := &mockDBusConn{obj: &mockBusObject{}}
	n := newDBusNotifierWithConn(conn, slog.Default())

	err := n.Close()
	require.NoError(t, err)
	assert.True(t, conn.closed)
}

func TestDBusNotifier_CloseIdempotent(t *testing.T) {
	conn := &mockDBusConn{obj: &mockBusObject{}}
	n := newDBusNotifierWithConn(conn, slog.Default())

	require.NoError(t, n.Close())
	require.NoError(t, n.Close()) // second call is no-op

	assert.True(t, n.closed.Load())
}

func TestDBusNotifier_NotifyAfterClose(t *testing.T) {
	conn := &mockDBusConn{obj: &mockBusObject{}}
	n := newDBusNotifierWithConn(conn, slog.Default())

	require.NoError(t, n.Close())

	req := &TouchRequest{Operation: "register", RPID: "example.com"}
	err := n.NotifyTouchRequired(req)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotifierClosed)
}

func TestDBusNotifier_CloseError(t *testing.T) {
	closeErr := errors.New("dbus: close failed")
	conn := &mockDBusConn{obj: &mockBusObject{}, closeErr: closeErr}
	n := newDBusNotifierWithConn(conn, slog.Default())

	err := n.Close()
	require.Error(t, err)
	assert.Equal(t, closeErr, err)
}

func TestBuildNotificationBody(t *testing.T) {
	tests := []struct {
		name     string
		req      *TouchRequest
		expected string
	}{
		{
			name: "with RPName",
			req: &TouchRequest{
				Operation: "register",
				RPName:    "Example Corp",
			},
			expected: "Approve register for Example Corp",
		},
		{
			name: "without RPName falls back to RPID",
			req: &TouchRequest{
				Operation: "authenticate",
				RPID:      "example.com",
				RPName:    "",
			},
			expected: "Approve authenticate for example.com",
		},
		{
			name: "RPName takes precedence over RPID",
			req: &TouchRequest{
				Operation: "register",
				RPID:      "example.com",
				RPName:    "My Service",
			},
			expected: "Approve register for My Service",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := buildNotificationBody(tc.req)
			assert.Equal(t, tc.expected, body)
		})
	}
}
