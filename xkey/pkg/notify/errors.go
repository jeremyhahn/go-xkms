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

	// ErrUnterminatedQuote is returned when a notification command template
	// has an opening quote with no matching close.
	ErrUnterminatedQuote = errors.New("notify: unterminated quote in notification command template")

	// ErrTemplatePlaceholder is returned when a notification command
	// template contains a %o, %r, %n, or %u placeholder. Those placeholders
	// were removed: they used to be substituted directly into argv, which
	// made request data (RP name, user name -- both caller-controlled via
	// WebAuthn) part of an argv element. Request data now reaches the
	// command only through the XKEY_OPERATION, XKEY_RP_ID, XKEY_RP_NAME,
	// and XKEY_USER_NAME environment variables, for example
	// sh -c 'notify-send "Touch required" "$XKEY_RP_ID"'.
	ErrTemplatePlaceholder = errors.New("notify: notification command template contains a %o/%r/%n/%u placeholder; " +
		"these were removed, use the XKEY_OPERATION/XKEY_RP_ID/XKEY_RP_NAME/XKEY_USER_NAME environment variables instead, " +
		`for example: sh -c 'notify-send "Touch required" "$XKEY_RP_ID"'`)
)

// MessageError is a typed error that carries a preformatted message. It
// replaces inline formatted-error constructions that do not wrap a cause.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
type SentinelCauseError struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}
