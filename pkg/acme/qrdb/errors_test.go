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

package qrdb

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewError(t *testing.T) {
	t.Run("creates error with code and message", func(t *testing.T) {
		err := NewError(ErrorCodeNotFound, "resource missing")
		require.NotNil(t, err)
		assert.Equal(t, ErrorCodeNotFound, err.Code)
		assert.Equal(t, "resource missing", err.Message)
		assert.Nil(t, err.Cause)
		assert.Nil(t, err.Context)
	})

	t.Run("all error codes have names", func(t *testing.T) {
		codes := []ErrorCode{
			ErrorCodeInvalidConfig, ErrorCodeConnection, ErrorCodeNotFound,
			ErrorCodeAlreadyExists, ErrorCodeInvalidInput, ErrorCodeInternal,
			ErrorCodeSealed, ErrorCodeNotInitialized, ErrorCodePermissionDenied,
			ErrorCodeSerialization, ErrorCodeShutdown, ErrorCodeShutdownInProgress,
			ErrorCodeNoLeader, ErrorCodeNotLeader,
		}
		for _, code := range codes {
			name := code.String()
			assert.NotContains(t, name, "Unknown", "code %d should have a name", code)
		}
	})
}

func TestErrorCodeString(t *testing.T) {
	t.Run("known codes", func(t *testing.T) {
		assert.Equal(t, "NotFound", ErrorCodeNotFound.String())
		assert.Equal(t, "Internal", ErrorCodeInternal.String())
		assert.Equal(t, "ShutdownInProgress", ErrorCodeShutdownInProgress.String())
	})

	t.Run("unknown code", func(t *testing.T) {
		code := ErrorCode(255)
		assert.Contains(t, code.String(), "Unknown")
	})
}

func TestErrorError(t *testing.T) {
	t.Run("without cause", func(t *testing.T) {
		err := NewError(ErrorCodeNotFound, "key missing")
		assert.Equal(t, "qrdb: NotFound: key missing", err.Error())
	})

	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("underlying problem")
		err := NewError(ErrorCodeConnection, "connect failed").WithCause(cause)
		assert.Equal(t, "qrdb: Connection: connect failed: underlying problem", err.Error())
	})
}

func TestErrorWithCause(t *testing.T) {
	t.Run("attaches cause", func(t *testing.T) {
		cause := errors.New("disk full")
		original := NewError(ErrorCodeInternal, "write failed")
		withCause := original.WithCause(cause)

		assert.Equal(t, cause, withCause.Cause)
		assert.Equal(t, ErrorCodeInternal, withCause.Code)
		assert.Equal(t, "write failed", withCause.Message)
		// Original should be unchanged.
		assert.Nil(t, original.Cause)
	})

	t.Run("unwrap returns cause", func(t *testing.T) {
		cause := errors.New("timeout")
		err := NewError(ErrorCodeConnection, "connect").WithCause(cause)
		assert.True(t, errors.Is(err, cause))
	})
}

func TestErrorWithContext(t *testing.T) {
	t.Run("adds context entry", func(t *testing.T) {
		err := NewError(ErrorCodeInvalidInput, "bad key").
			WithContext("key", "foo").
			WithContext("length", 3)

		assert.Equal(t, "foo", err.Context["key"])
		assert.Equal(t, 3, err.Context["length"])
	})

	t.Run("does not mutate original", func(t *testing.T) {
		original := NewError(ErrorCodeInvalidInput, "bad key")
		withCtx := original.WithContext("key", "foo")

		assert.Nil(t, original.Context)
		assert.NotNil(t, withCtx.Context)
	})
}

func TestErrorIs(t *testing.T) {
	t.Run("matches same code", func(t *testing.T) {
		err1 := NewError(ErrorCodeNotFound, "a")
		err2 := NewError(ErrorCodeNotFound, "b")
		assert.True(t, err1.Is(err2))
	})

	t.Run("does not match different code", func(t *testing.T) {
		err1 := NewError(ErrorCodeNotFound, "a")
		err2 := NewError(ErrorCodeInternal, "b")
		assert.False(t, err1.Is(err2))
	})

	t.Run("does not match non-Error", func(t *testing.T) {
		err := NewError(ErrorCodeNotFound, "a")
		assert.False(t, err.Is(errors.New("other")))
	})
}

func TestIsHelpers(t *testing.T) {
	tests := []struct {
		name   string
		code   ErrorCode
		check  func(error) bool
		expect bool
	}{
		{"IsNotFound_true", ErrorCodeNotFound, IsNotFound, true},
		{"IsNotFound_false", ErrorCodeInternal, IsNotFound, false},
		{"IsAlreadyExists_true", ErrorCodeAlreadyExists, IsAlreadyExists, true},
		{"IsAlreadyExists_false", ErrorCodeNotFound, IsAlreadyExists, false},
		{"IsInvalidConfig_true", ErrorCodeInvalidConfig, IsInvalidConfig, true},
		{"IsConnection_true", ErrorCodeConnection, IsConnection, true},
		{"IsInvalidInput_true", ErrorCodeInvalidInput, IsInvalidInput, true},
		{"IsInternal_true", ErrorCodeInternal, IsInternal, true},
		{"IsSealed_true", ErrorCodeSealed, IsSealed, true},
		{"IsNotInitialized_true", ErrorCodeNotInitialized, IsNotInitialized, true},
		{"IsPermissionDenied_true", ErrorCodePermissionDenied, IsPermissionDenied, true},
		{"IsSerialization_true", ErrorCodeSerialization, IsSerialization, true},
		{"IsShutdown_true", ErrorCodeShutdown, IsShutdown, true},
		{"IsShutdownInProgress_true", ErrorCodeShutdownInProgress, IsShutdownInProgress, true},
		{"IsNoLeader_true", ErrorCodeNoLeader, IsNoLeader, true},
		{"IsNotLeader_true", ErrorCodeNotLeader, IsNotLeader, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewError(tt.code, "test")
			assert.Equal(t, tt.expect, tt.check(err))
		})
	}

	t.Run("non-Error returns false", func(t *testing.T) {
		plainErr := errors.New("plain")
		assert.False(t, IsNotFound(plainErr))
		assert.False(t, IsInternal(plainErr))
		assert.False(t, IsShutdownInProgress(plainErr))
	})
}
