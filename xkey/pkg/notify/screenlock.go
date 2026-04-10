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
	"log/slog"
	"sync/atomic"

	"github.com/godbus/dbus/v5"
)

const (
	// logindSessionInterface is the D-Bus interface for logind session signals.
	logindSessionInterface = "org.freedesktop.login1.Session"

	// logindLockMember is the Lock signal name emitted when the screen locks.
	logindLockMember = "Lock"

	// logindLockSignalName is the fully qualified D-Bus signal name for screen lock.
	logindLockSignalName = "org.freedesktop.login1.Session.Lock"

	// screenLockMatchRule is the D-Bus match rule for subscribing to Lock signals.
	screenLockMatchRule = "type='signal',interface='org.freedesktop.login1.Session',member='Lock'"

	// signalChannelSize is the buffer size for the D-Bus signal channel.
	signalChannelSize = 16
)

// systemBusConnection abstracts the D-Bus system bus connection to enable
// testing without a real system bus.
type systemBusConnection interface {
	Signal(ch chan<- *dbus.Signal)
	RemoveSignal(ch chan<- *dbus.Signal)
	BusObject() dbus.BusObject
	Close() error
}

// ScreenLockMonitor monitors the org.freedesktop.login1.Session.Lock D-Bus
// signal on the system bus. When the OS screen locks, the registered callback
// is invoked synchronously.
type ScreenLockMonitor struct {
	conn     systemBusConnection
	signalCh chan *dbus.Signal
	callback func()
	closed   atomic.Bool
	logger   *slog.Logger
}

// NewScreenLockMonitor creates a ScreenLockMonitor that listens for screen lock
// events on the D-Bus system bus. The callback is invoked each time a Lock signal
// is received and should complete quickly (e.g., set an atomic flag).
// Returns ErrScreenLockUnavailable if the system bus cannot be reached.
func NewScreenLockMonitor(logger *slog.Logger, callback func()) (*ScreenLockMonitor, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		logger.Warn("failed to connect to D-Bus system bus for screen lock monitoring",
			slog.String("error", err.Error()))
		return nil, ErrScreenLockUnavailable
	}

	signalCh := make(chan *dbus.Signal, signalChannelSize)
	conn.Signal(signalCh)

	// Subscribe to Lock signals from logind sessions.
	call := conn.BusObject().Call("org.freedesktop.DBus.AddMatch", 0, screenLockMatchRule)
	if call.Err != nil {
		logger.Warn("failed to add D-Bus match rule for screen lock signal",
			slog.String("error", call.Err.Error()))
		conn.RemoveSignal(signalCh)
		conn.Close()
		return nil, ErrScreenLockUnavailable
	}

	m := &ScreenLockMonitor{
		conn:     conn,
		signalCh: signalCh,
		callback: callback,
		logger:   logger,
	}

	go m.listen()

	logger.Info("screen lock monitor started, listening for logind Lock signals")
	return m, nil
}

// newScreenLockMonitorWithConn creates a ScreenLockMonitor with an injected
// connection and signal channel for testing. The caller is responsible for
// providing a pre-configured connection and channel.
func newScreenLockMonitorWithConn(
	conn systemBusConnection,
	signalCh chan *dbus.Signal,
	callback func(),
	logger *slog.Logger,
) *ScreenLockMonitor {
	m := &ScreenLockMonitor{
		conn:     conn,
		signalCh: signalCh,
		callback: callback,
		logger:   logger,
	}

	go m.listen()

	return m
}

// listen processes incoming D-Bus signals on the signal channel. It invokes
// the callback for each Lock signal received and exits when the channel is
// closed or the monitor is closed.
func (m *ScreenLockMonitor) listen() {
	for sig := range m.signalCh {
		if m.closed.Load() {
			return
		}
		if sig.Name == logindLockSignalName {
			m.logger.Info("screen lock signal received")
			m.callback()
		}
	}
}

// Close stops monitoring and releases the D-Bus connection. Close is idempotent;
// subsequent calls return nil without side effects.
func (m *ScreenLockMonitor) Close() error {
	if m.closed.Swap(true) {
		return nil
	}

	// Remove the match rule (best effort).
	call := m.conn.BusObject().Call("org.freedesktop.DBus.RemoveMatch", 0, screenLockMatchRule)
	if call.Err != nil {
		m.logger.Warn("failed to remove D-Bus match rule for screen lock signal",
			slog.String("error", call.Err.Error()))
	}

	m.conn.RemoveSignal(m.signalCh)
	close(m.signalCh)

	m.logger.Info("screen lock monitor stopped")
	return m.conn.Close()
}
