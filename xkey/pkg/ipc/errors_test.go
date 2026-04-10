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

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrors_NotNilAndNonEmpty(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrServerClosed", ErrServerClosed},
		{"ErrClientClosed", ErrClientClosed},
		{"ErrConnectionFailed", ErrConnectionFailed},
		{"ErrDaemonNotRunning", ErrDaemonNotRunning},
		{"ErrInvalidMessage", ErrInvalidMessage},
		{"ErrProtocolError", ErrProtocolError},
		{"ErrSocketCreateFailed", ErrSocketCreateFailed},
		{"ErrSocketPermission", ErrSocketPermission},
		{"ErrHandlerFailed", ErrHandlerFailed},
		{"ErrTimeout", ErrTimeout},
		{"ErrBarrierSealed", ErrBarrierSealed},
		{"ErrPKCS11Operation", ErrPKCS11Operation},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotNil(t, tt.err)
			assert.NotEmpty(t, tt.err.Error())
		})
	}
}

func TestErrors_Uniqueness(t *testing.T) {
	errs := []error{
		ErrServerClosed,
		ErrClientClosed,
		ErrConnectionFailed,
		ErrDaemonNotRunning,
		ErrInvalidMessage,
		ErrProtocolError,
		ErrSocketCreateFailed,
		ErrSocketPermission,
		ErrHandlerFailed,
		ErrTimeout,
		ErrBarrierSealed,
		ErrPKCS11Operation,
	}

	seen := make(map[string]bool)
	for _, err := range errs {
		msg := err.Error()
		assert.False(t, seen[msg], "error message must be unique: %s", msg)
		seen[msg] = true
	}
}

func TestErrors_Prefix(t *testing.T) {
	errs := []error{
		ErrServerClosed,
		ErrClientClosed,
		ErrConnectionFailed,
		ErrDaemonNotRunning,
		ErrInvalidMessage,
		ErrProtocolError,
		ErrSocketCreateFailed,
		ErrSocketPermission,
		ErrHandlerFailed,
		ErrTimeout,
		ErrBarrierSealed,
		ErrPKCS11Operation,
	}

	for _, err := range errs {
		assert.Contains(t, err.Error(), "ipc:",
			"all errors must have the ipc: prefix")
	}
}

func TestErrors_Is(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
		want   bool
	}{
		{"ErrServerClosed matches itself", ErrServerClosed, ErrServerClosed, true},
		{"ErrClientClosed matches itself", ErrClientClosed, ErrClientClosed, true},
		{"ErrConnectionFailed matches itself", ErrConnectionFailed, ErrConnectionFailed, true},
		{"ErrDaemonNotRunning matches itself", ErrDaemonNotRunning, ErrDaemonNotRunning, true},
		{"ErrInvalidMessage matches itself", ErrInvalidMessage, ErrInvalidMessage, true},
		{"ErrProtocolError matches itself", ErrProtocolError, ErrProtocolError, true},
		{"ErrSocketCreateFailed matches itself", ErrSocketCreateFailed, ErrSocketCreateFailed, true},
		{"ErrSocketPermission matches itself", ErrSocketPermission, ErrSocketPermission, true},
		{"ErrHandlerFailed matches itself", ErrHandlerFailed, ErrHandlerFailed, true},
		{"ErrTimeout matches itself", ErrTimeout, ErrTimeout, true},
		{"ErrBarrierSealed matches itself", ErrBarrierSealed, ErrBarrierSealed, true},
		{"ErrPKCS11Operation matches itself", ErrPKCS11Operation, ErrPKCS11Operation, true},
		{"ErrServerClosed does not match ErrClientClosed", ErrServerClosed, ErrClientClosed, false},
		{"ErrDaemonNotRunning does not match ErrTimeout", ErrDaemonNotRunning, ErrTimeout, false},
		{"ErrBarrierSealed does not match ErrPKCS11Operation", ErrBarrierSealed, ErrPKCS11Operation, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, errors.Is(tt.err, tt.target))
		})
	}
}

func TestErrors_Wrapping(t *testing.T) {
	base := errors.New("underlying cause")

	tests := []struct {
		name string
		err  error
	}{
		{"ErrServerClosed", ErrServerClosed},
		{"ErrClientClosed", ErrClientClosed},
		{"ErrConnectionFailed", ErrConnectionFailed},
		{"ErrDaemonNotRunning", ErrDaemonNotRunning},
		{"ErrInvalidMessage", ErrInvalidMessage},
		{"ErrProtocolError", ErrProtocolError},
		{"ErrSocketCreateFailed", ErrSocketCreateFailed},
		{"ErrSocketPermission", ErrSocketPermission},
		{"ErrHandlerFailed", ErrHandlerFailed},
		{"ErrTimeout", ErrTimeout},
		{"ErrBarrierSealed", ErrBarrierSealed},
		{"ErrPKCS11Operation", ErrPKCS11Operation},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := errors.Join(tt.err, base)
			assert.True(t, errors.Is(wrapped, tt.err),
				"wrapped error must match the sentinel")
			assert.True(t, errors.Is(wrapped, base),
				"wrapped error must match the base cause")
		})
	}
}
