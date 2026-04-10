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
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync/atomic"

	"github.com/godbus/dbus/v5"
)

const (
	// dbusNotifyDest is the D-Bus destination for the notification daemon.
	dbusNotifyDest = "org.freedesktop.Notifications"

	// dbusNotifyPath is the D-Bus object path for the notification interface.
	dbusNotifyPath = "/org/freedesktop/Notifications"

	// dbusNotifyMethod is the full method name for sending a notification.
	dbusNotifyMethod = "org.freedesktop.Notifications.Notify"

	// dbusAppName is the application name shown in desktop notifications.
	dbusAppName = "xKey"

	// dbusTimeout is the notification timeout in milliseconds.
	dbusTimeout = int32(30000)
)

// dbusConnection abstracts the D-Bus connection to enable testing without
// a real session bus.
type dbusConnection interface {
	Object(dest string, path dbus.ObjectPath) dbus.BusObject
	Close() error
}

// DBusNotifier sends desktop notifications via the org.freedesktop.Notifications
// D-Bus interface. It falls back gracefully when the session bus is unavailable
// by returning ErrDBusUnavailable from the constructor.
type DBusNotifier struct {
	conn   dbusConnection
	closed atomic.Bool
	logger *slog.Logger
}

// NewDBusNotifier creates a DBusNotifier by opening the D-Bus session bus.
// When running as root (e.g., via sudo), it attempts to connect to the
// invoking user's session bus using SUDO_UID to find the correct bus address.
// Returns ErrDBusUnavailable if the session bus cannot be reached.
func NewDBusNotifier(logger *slog.Logger) (*DBusNotifier, error) {
	conn, err := connectSessionBus(logger)
	if err != nil {
		return nil, ErrDBusUnavailable
	}

	return &DBusNotifier{
		conn:   conn,
		logger: logger,
	}, nil
}

// connectSessionBus connects to the appropriate D-Bus session bus. When running
// as root via sudo, it connects to the invoking user's session bus so that
// desktop notifications reach the user's notification daemon.
func connectSessionBus(logger *slog.Logger) (*dbus.Conn, error) {
	// If not running as root, use default session bus
	if os.Getuid() != 0 {
		logger.Info("connecting to D-Bus session bus (non-root)")
		return dbus.ConnectSessionBus()
	}

	// Running as root - try to find the original user's session bus
	sudoUID := os.Getenv("SUDO_UID")
	if sudoUID == "" {
		// No SUDO_UID, fall back to default (will likely fail)
		logger.Warn("running as root without SUDO_UID, D-Bus notifications may fail")
		return dbus.ConnectSessionBus()
	}

	uid, err := strconv.Atoi(sudoUID)
	if err != nil {
		logger.Warn("invalid SUDO_UID, using default session bus",
			slog.String("sudo_uid", sudoUID),
			slog.String("error", err.Error()))
		return dbus.ConnectSessionBus()
	}

	// Construct the user's session bus address and set it in the environment
	// so that ConnectSessionBus() uses the correct bus
	busAddress := fmt.Sprintf("unix:path=/run/user/%d/bus", uid)
	logger.Info("connecting to user's D-Bus session (running as root via sudo)",
		slog.Int("uid", uid),
		slog.String("bus_address", busAddress))

	// Set the environment variable for the D-Bus library
	oldAddr := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	if err := os.Setenv("DBUS_SESSION_BUS_ADDRESS", busAddress); err != nil {
		logger.Warn("failed to set DBUS_SESSION_BUS_ADDRESS",
			slog.String("error", err.Error()))
		return dbus.ConnectSessionBus()
	}

	// Connect using the standard method which respects the env var
	conn, err := dbus.ConnectSessionBus()

	// Restore old env var (best effort)
	if oldAddr != "" {
		_ = os.Setenv("DBUS_SESSION_BUS_ADDRESS", oldAddr)
	} else {
		_ = os.Unsetenv("DBUS_SESSION_BUS_ADDRESS")
	}

	if err != nil {
		logger.Warn("failed to connect to user's session bus",
			slog.String("bus_address", busAddress),
			slog.String("error", err.Error()))
		return nil, err
	}

	logger.Info("successfully connected to user's D-Bus session")
	return conn, nil
}

// newDBusNotifierWithConn creates a DBusNotifier with an injected connection,
// used for testing.
func newDBusNotifierWithConn(conn dbusConnection, logger *slog.Logger) *DBusNotifier {
	return &DBusNotifier{
		conn:   conn,
		logger: logger,
	}
}

// buildNotificationBody returns the human-readable notification body text
// for the given touch request.
func buildNotificationBody(req *TouchRequest) string {
	display := req.RPName
	if display == "" {
		display = req.RPID
	}
	return fmt.Sprintf("Approve %s for %s", req.Operation, display)
}

// NotifyTouchRequired sends a desktop notification via D-Bus informing the
// user that touch or user presence is required.
func (n *DBusNotifier) NotifyTouchRequired(req *TouchRequest) error {
	if n.closed.Load() {
		return ErrNotifierClosed
	}

	body := buildNotificationBody(req)

	hints := map[string]dbus.Variant{
		"urgency": dbus.MakeVariant(byte(2)), // critical
	}

	obj := n.conn.Object(dbusNotifyDest, dbusNotifyPath)
	call := obj.Call(
		dbusNotifyMethod,
		0,                // flags
		dbusAppName,      // app_name
		uint32(0),        // replaces_id
		"",               // app_icon
		"Touch Required", // summary
		body,             // body
		[]string{},       // actions
		hints,            // hints
		dbusTimeout,      // expire_timeout
	)

	if call.Err != nil {
		n.logger.Error("D-Bus notification failed",
			slog.String("error", call.Err.Error()),
			slog.String("operation", req.Operation),
			slog.String("rp_id", req.RPID),
		)
		return ErrNotificationFailed
	}
	return nil
}

// Close closes the underlying D-Bus connection. Subsequent calls to
// NotifyTouchRequired will return ErrNotifierClosed. Close is idempotent.
func (n *DBusNotifier) Close() error {
	if n.closed.Swap(true) {
		return nil
	}
	return n.conn.Close()
}
