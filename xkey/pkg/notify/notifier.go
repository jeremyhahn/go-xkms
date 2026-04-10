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

// Package notify provides a notification system for xKey virtual security
// key operations. It alerts users when touch or user presence confirmation is
// required for WebAuthn ceremonies such as credential registration and
// authentication.
//
// The package ships with multiple notifier backends:
//   - LogNotifier: logs via slog (always available as fallback)
//   - DBusNotifier: sends desktop notifications via org.freedesktop.Notifications
//   - CommandNotifier: executes a user-provided shell command
//   - MultiNotifier: fans out to multiple notifiers in parallel
//
// All notifier implementations are safe for concurrent use.
package notify

import (
	"errors"
	"sync/atomic"
)

// TouchRequest contains information about a pending touch request that
// triggered the notification.
type TouchRequest struct {
	// Operation is the WebAuthn ceremony type ("register" or "authenticate").
	Operation string

	// RPID is the relying party identifier (e.g. "example.com").
	RPID string

	// RPName is the human-readable relying party name (e.g. "Example Corp").
	RPName string

	// UserName is the display name of the user being prompted.
	UserName string
}

// Notifier defines the interface for sending touch-required notifications
// to the user during WebAuthn operations.
type Notifier interface {
	// NotifyTouchRequired sends a notification informing the user that
	// touch or user presence confirmation is needed.
	NotifyTouchRequired(req *TouchRequest) error

	// Close releases any resources held by the notifier. After Close
	// returns, subsequent calls to NotifyTouchRequired must return
	// ErrNotifierClosed.
	Close() error
}

// MultiNotifier wraps multiple Notifier implementations and fires all of
// them when a notification is requested. A single notifier failure does not
// prevent the remaining notifiers from being invoked.
type MultiNotifier struct {
	notifiers []Notifier
	closed    atomic.Bool
}

// NewMultiNotifier creates a MultiNotifier that dispatches to all provided
// notifiers.
func NewMultiNotifier(notifiers ...Notifier) *MultiNotifier {
	return &MultiNotifier{
		notifiers: notifiers,
	}
}

// NotifyTouchRequired dispatches the touch request to every wrapped notifier.
// Errors from individual notifiers are collected and returned as a single
// joined error. A failure in one notifier does not block the others.
func (m *MultiNotifier) NotifyTouchRequired(req *TouchRequest) error {
	if m.closed.Load() {
		return ErrNotifierClosed
	}

	var errs []error
	for _, n := range m.notifiers {
		if err := n.NotifyTouchRequired(req); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// Close closes all wrapped notifiers. Errors from individual Close calls are
// collected and returned as a single joined error.
func (m *MultiNotifier) Close() error {
	if m.closed.Swap(true) {
		return nil
	}

	var errs []error
	for _, n := range m.notifiers {
		if err := n.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
