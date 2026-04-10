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

package ipc

import "errors"

var (
	// ErrServerClosed is returned when an operation is attempted on a closed server.
	ErrServerClosed = errors.New("ipc: server is closed")

	// ErrClientClosed is returned when an operation is attempted on a closed client.
	ErrClientClosed = errors.New("ipc: client is closed")

	// ErrConnectionFailed is returned when a connection to the IPC socket fails.
	ErrConnectionFailed = errors.New("ipc: connection failed")

	// ErrDaemonNotRunning is returned when the daemon socket does not exist or
	// the connection is refused.
	ErrDaemonNotRunning = errors.New("ipc: daemon is not running")

	// ErrInvalidMessage is returned when a received message fails validation.
	ErrInvalidMessage = errors.New("ipc: invalid message")

	// ErrProtocolError is returned when the wire protocol is violated (e.g.,
	// malformed JSON).
	ErrProtocolError = errors.New("ipc: protocol error")

	// ErrSocketCreateFailed is returned when socket creation fails.
	ErrSocketCreateFailed = errors.New("ipc: socket creation failed")

	// ErrSocketPermission is returned when socket permission operations fail.
	ErrSocketPermission = errors.New("ipc: socket permission error")

	// ErrHandlerFailed is returned when a handler returns an error while
	// processing a message.
	ErrHandlerFailed = errors.New("ipc: handler returned error")

	// ErrTimeout is returned when an IPC operation exceeds its deadline.
	ErrTimeout = errors.New("ipc: operation timed out")

	// ErrBarrierSealed is returned when a PKCS#11 operation is attempted
	// while the barrier is sealed.
	ErrBarrierSealed = errors.New("ipc: barrier is sealed")

	// ErrPKCS11Operation is returned when a PKCS#11 operation fails.
	ErrPKCS11Operation = errors.New("ipc: pkcs11 operation failed")

	// ErrAutofillOperation is returned when an autofill operation fails.
	ErrAutofillOperation = errors.New("ipc: autofill operation failed")

	// ErrAutofillDisabled is returned when autofill is requested but the
	// browser extension feature is disabled.
	ErrAutofillDisabled = errors.New("ipc: browser extension is disabled")
)
