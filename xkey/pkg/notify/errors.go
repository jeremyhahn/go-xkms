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

import "errors"

// Package-level errors for notification operations.
var (
	// ErrNotifierClosed is returned when an operation is attempted on a closed notifier.
	ErrNotifierClosed = errors.New("notify: notifier is closed")

	// ErrDBusUnavailable is returned when the D-Bus session bus cannot be opened.
	ErrDBusUnavailable = errors.New("notify: D-Bus session bus unavailable")

	// ErrCommandFailed is returned when a notification command exits with an error.
	ErrCommandFailed = errors.New("notify: notification command failed")

	// ErrInvalidCommand is returned when an empty or invalid command string is provided.
	ErrInvalidCommand = errors.New("notify: invalid notification command")

	// ErrNotificationFailed is returned when notification delivery fails.
	ErrNotificationFailed = errors.New("notify: notification delivery failed")

	// ErrScreenLockUnavailable is returned when the D-Bus system bus cannot be
	// reached for screen lock monitoring.
	ErrScreenLockUnavailable = errors.New("notify: screen lock monitoring unavailable")
)
