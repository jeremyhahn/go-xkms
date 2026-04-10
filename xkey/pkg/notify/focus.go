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

import "sync/atomic"

// FocusNotifier wraps a Notifier and calls a focus function before
// delegating the notification. This brings the application window
// to the foreground when touch is required so the user can approve
// with a single click.
type FocusNotifier struct {
	inner   Notifier
	focusFn func()
	closed  atomic.Bool
}

// NewFocusNotifier creates a FocusNotifier that calls focusFn before
// forwarding to the inner notifier.
func NewFocusNotifier(inner Notifier, focusFn func()) *FocusNotifier {
	return &FocusNotifier{
		inner:   inner,
		focusFn: focusFn,
	}
}

// NotifyTouchRequired brings the window to the foreground then delegates
// to the wrapped notifier. Returns ErrNotifierClosed if closed.
func (f *FocusNotifier) NotifyTouchRequired(req *TouchRequest) error {
	if f.closed.Load() {
		return ErrNotifierClosed
	}
	f.focusFn()
	return f.inner.NotifyTouchRequired(req)
}

// Close marks the notifier as closed and closes the inner notifier.
// Safe to call multiple times; only the first call propagates to inner.
func (f *FocusNotifier) Close() error {
	if f.closed.Swap(true) {
		return nil
	}
	return f.inner.Close()
}

var _ Notifier = (*FocusNotifier)(nil)
