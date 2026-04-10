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
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrors_NonNil(t *testing.T) {
	errs := []error{
		ErrNotifierClosed,
		ErrDBusUnavailable,
		ErrCommandFailed,
		ErrInvalidCommand,
		ErrNotificationFailed,
		ErrScreenLockUnavailable,
	}
	for _, err := range errs {
		assert.NotNil(t, err, "error should not be nil")
	}
}

func TestErrors_HaveNotifyPrefix(t *testing.T) {
	errs := map[string]error{
		"ErrNotifierClosed":        ErrNotifierClosed,
		"ErrDBusUnavailable":       ErrDBusUnavailable,
		"ErrCommandFailed":         ErrCommandFailed,
		"ErrInvalidCommand":        ErrInvalidCommand,
		"ErrNotificationFailed":    ErrNotificationFailed,
		"ErrScreenLockUnavailable": ErrScreenLockUnavailable,
	}
	for name, err := range errs {
		assert.True(t, strings.HasPrefix(err.Error(), "notify:"),
			"%s should have 'notify:' prefix, got: %s", name, err.Error())
	}
}

func TestErrors_Unique(t *testing.T) {
	errs := []error{
		ErrNotifierClosed,
		ErrDBusUnavailable,
		ErrCommandFailed,
		ErrInvalidCommand,
		ErrNotificationFailed,
		ErrScreenLockUnavailable,
	}
	seen := make(map[string]bool, len(errs))
	for _, err := range errs {
		msg := err.Error()
		require.False(t, seen[msg], "duplicate error message: %s", msg)
		seen[msg] = true
	}
}

func TestErrors_Is(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
	}{
		{name: "ErrNotifierClosed", err: ErrNotifierClosed, target: ErrNotifierClosed},
		{name: "ErrDBusUnavailable", err: ErrDBusUnavailable, target: ErrDBusUnavailable},
		{name: "ErrCommandFailed", err: ErrCommandFailed, target: ErrCommandFailed},
		{name: "ErrInvalidCommand", err: ErrInvalidCommand, target: ErrInvalidCommand},
		{name: "ErrNotificationFailed", err: ErrNotificationFailed, target: ErrNotificationFailed},
		{name: "ErrScreenLockUnavailable", err: ErrScreenLockUnavailable, target: ErrScreenLockUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.True(t, errors.Is(tc.err, tc.target))
		})
	}
}

func TestErrors_IsNotCrossMatch(t *testing.T) {
	assert.False(t, errors.Is(ErrNotifierClosed, ErrDBusUnavailable))
	assert.False(t, errors.Is(ErrCommandFailed, ErrInvalidCommand))
	assert.False(t, errors.Is(ErrDBusUnavailable, ErrNotificationFailed))
	assert.False(t, errors.Is(ErrScreenLockUnavailable, ErrDBusUnavailable))
	assert.False(t, errors.Is(ErrScreenLockUnavailable, ErrNotifierClosed))
}
