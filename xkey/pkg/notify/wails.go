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
)

// WailsNotifier implements Notifier by emitting events through the Wails
// runtime event system. This delivers touch notifications directly to the
// frontend without relying on D-Bus desktop notifications.
type WailsNotifier struct {
	emitFunc func(eventType string, data any)
	closed   atomic.Bool
}

// NewWailsNotifier creates a WailsNotifier that delegates notification delivery
// to the provided emit function. The emit function is typically wired to the
// Wails runtime EventsEmit call.
func NewWailsNotifier(emitFunc func(eventType string, data any)) *WailsNotifier {
	return &WailsNotifier{
		emitFunc: emitFunc,
	}
}

// NotifyTouchRequired emits a "fido2:touch_required" event through the Wails
// runtime with the touch request details as a string map payload. Returns
// ErrNotifierClosed if the notifier has been closed.
func (w *WailsNotifier) NotifyTouchRequired(req *TouchRequest) error {
	if w.closed.Load() {
		return ErrNotifierClosed
	}
	slog.Debug("fido2: touch required",
		slog.String("operation", req.Operation),
		slog.String("rp_id", req.RPID),
		slog.String("user", req.UserName))
	w.emitFunc("fido2:touch_required", map[string]string{
		"operation": req.Operation,
		"rp_id":     req.RPID,
		"rp_name":   req.RPName,
		"user_name": req.UserName,
	})
	return nil
}

// Close marks the notifier as closed. Subsequent calls to NotifyTouchRequired
// will return ErrNotifierClosed. Close is safe to call multiple times.
func (w *WailsNotifier) Close() error {
	w.closed.Store(true)
	return nil
}

var _ Notifier = (*WailsNotifier)(nil)
