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

package secretservice

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// errRequestBusNameUnavailable is injected to exercise requestBusName's
// non-ErrServiceAlreadyRunning failure branch of Start.
var errRequestBusNameUnavailable = errors.New("request bus name: unavailable")

// TestClassifyRequestNameReply covers the pure reply-classification logic
// Start relies on, directly and without any bus at all.
func TestClassifyRequestNameReply(t *testing.T) {
	t.Run("primary_owner_is_success", func(t *testing.T) {
		assert.NoError(t, classifyRequestNameReply(dbus.RequestNameReplyPrimaryOwner))
	})

	t.Run("every_other_reply_is_already_running", func(t *testing.T) {
		for _, reply := range []dbus.RequestNameReply{
			dbus.RequestNameReplyInQueue,
			dbus.RequestNameReplyExists,
			dbus.RequestNameReplyAlreadyOwner,
		} {
			assert.ErrorIs(t, classifyRequestNameReply(reply), ErrServiceAlreadyRunning)
		}
	})
}

// swapDialBus replaces the dialBus seam for the duration of the test.
func swapDialBus(t *testing.T, fn func(string) (*dbus.Conn, error)) {
	t.Helper()
	original := dialBus
	dialBus = fn
	t.Cleanup(func() { dialBus = original })
}

// swapRequestBusName replaces the requestBusName seam for the duration of
// the test.
func swapRequestBusName(t *testing.T, fn func(*dbus.Conn) error) {
	t.Helper()
	original := requestBusName
	requestBusName = fn
	t.Cleanup(func() { requestBusName = original })
}

// TestDaemon_Start_Success drives Start's entire success path -- claiming
// the bus name, exportObjects, exporting the default collection plus every
// existing folder/item, and flipping the running flag -- against a fake,
// already-connected loopback bus instead of a real D-Bus daemon. dialBus
// and requestBusName are the only two points Start touches the network;
// everything downstream of them (the object model, the store) is real.
func TestDaemon_Start_Success(t *testing.T) {
	store := newMemoryStore()
	require.NoError(t, store.CreateFolder("Work"))
	require.NoError(t, store.Add(&xkms.StaticPassword{Name: "gh", FolderPath: "Work", Password: "s3cret"}))

	d, err := NewDaemon(store, newTestBarrier(t), nil, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	conn, closePeer := newLoopbackBus(t)
	t.Cleanup(closePeer)

	dialed := false
	swapDialBus(t, func(busKind string) (*dbus.Conn, error) {
		dialed = true
		assert.Equal(t, "session", busKind)
		return conn, nil
	})
	requested := false
	swapRequestBusName(t, func(c *dbus.Conn) error {
		requested = true
		assert.Same(t, conn, c)
		return nil
	})

	require.NoError(t, d.Start())
	assert.True(t, dialed)
	assert.True(t, requested)
	assert.True(t, d.IsRunning())
	assert.Same(t, conn, d.conn)

	// Not exercising Stop() here: ReleaseName is a real blocking bus call
	// (like RequestName) that would hang against this loopback connection,
	// which nothing on the "server" side ever replies to -- see
	// TestDaemon_Stop_ReleasesConnection in service_dbus_test.go, which
	// closes the peer first specifically so that call fails fast instead.
	d.running.Store(false)
}

// TestDaemon_Start_Success_WhileSealed proves Start succeeds on a sealed
// barrier too, skipping exportExistingCollections (it cannot list a sealed
// store -- see Daemon's doc comment) without failing the whole call.
func TestDaemon_Start_Success_WhileSealed(t *testing.T) {
	barrier := newTestBarrier(t)
	require.NoError(t, barrier.Seal())

	d, err := NewDaemon(newMemoryStore(), barrier, nil, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	conn, closePeer := newLoopbackBus(t)
	t.Cleanup(closePeer)
	swapDialBus(t, func(string) (*dbus.Conn, error) { return conn, nil })
	swapRequestBusName(t, func(*dbus.Conn) error { return nil })

	require.NoError(t, d.Start())
	assert.True(t, d.IsRunning())
}

// TestDaemon_Start_AlreadyRunning proves Start refuses a second call
// without ever touching dialBus.
func TestDaemon_Start_AlreadyRunning(t *testing.T) {
	d, err := NewDaemon(newMemoryStore(), newTestBarrier(t), nil, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	d.running.Store(true)

	swapDialBus(t, func(string) (*dbus.Conn, error) {
		t.Fatal("dialBus must not be called when the daemon is already running")
		return nil, nil
	})

	assert.ErrorIs(t, d.Start(), ErrServiceAlreadyRunning)
}

// TestDaemon_Start_RequestBusNameFails proves a non-ErrServiceAlreadyRunning
// requestBusName failure surfaces as ErrDBusUnavailable and does not mark
// the daemon running.
func TestDaemon_Start_RequestBusNameFails(t *testing.T) {
	d, err := NewDaemon(newMemoryStore(), newTestBarrier(t), nil, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	conn, closePeer := newLoopbackBus(t)
	t.Cleanup(closePeer)
	swapDialBus(t, func(string) (*dbus.Conn, error) { return conn, nil })
	swapRequestBusName(t, func(*dbus.Conn) error { return errRequestBusNameUnavailable })

	assert.ErrorIs(t, d.Start(), ErrDBusUnavailable)
	assert.False(t, d.IsRunning())
}

// TestDaemon_Start_RequestBusNameAlreadyRunning proves a
// classifyRequestNameReply-style failure (another process already owns the
// name) surfaces as ErrServiceAlreadyRunning rather than the generic
// ErrDBusUnavailable.
func TestDaemon_Start_RequestBusNameAlreadyRunning(t *testing.T) {
	d, err := NewDaemon(newMemoryStore(), newTestBarrier(t), nil, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	conn, closePeer := newLoopbackBus(t)
	t.Cleanup(closePeer)
	swapDialBus(t, func(string) (*dbus.Conn, error) { return conn, nil })
	swapRequestBusName(t, func(*dbus.Conn) error { return ErrServiceAlreadyRunning })

	assert.ErrorIs(t, d.Start(), ErrServiceAlreadyRunning)
	assert.False(t, d.IsRunning())
}

// TestDaemon_Start_SystemBus proves the "system" config value reaches
// dialBus verbatim.
func TestDaemon_Start_SystemBus(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Bus = "system"
	d, err := NewDaemon(newMemoryStore(), newTestBarrier(t), cfg, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	conn, closePeer := newLoopbackBus(t)
	t.Cleanup(closePeer)
	swapDialBus(t, func(busKind string) (*dbus.Conn, error) {
		assert.Equal(t, "system", busKind)
		return conn, nil
	})
	swapRequestBusName(t, func(*dbus.Conn) error { return nil })

	require.NoError(t, d.Start())
}

// TestDialBus_DefaultsToTheRealGodbusConstructors is a narrow regression
// test proving the package-level default (before any test swaps it) is
// wired to the real dbus.Connect{Session,System}Bus functions rather than
// silently becoming a no-op if the seam is ever refactored incorrectly. It
// cannot succeed without a real bus, so it only checks the failure shape,
// mirroring TestDaemon_Start_DBusUnavailable's approach.
func TestDialBus_DefaultsToTheRealGodbusConstructors(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/xkey-test-bus")
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/nonexistent/xkey-test-bus")

	_, err := dialBus("session")
	assert.Error(t, err)

	_, err = dialBus("system")
	assert.Error(t, err)
}
