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

package interceptors

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeadlineError_Error(t *testing.T) {
	err := NewDeadlineError("insufficient time", 50, 100, nil)

	assert.Equal(t, "insufficient time", err.Error())
	assert.Equal(t, int64(50), err.Remaining)
	assert.Equal(t, int64(100), err.RequiredMinimum)
	assert.Nil(t, err.Cause)
}

func TestDeadlineError_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := NewDeadlineError("deadline error", 0, 100, cause)

	assert.Equal(t, cause, err.Unwrap())
	assert.True(t, errors.Is(err, cause))
}

func TestDeadlineError_Unwrap_NilCause(t *testing.T) {
	err := NewDeadlineError("deadline error", 0, 100, nil)

	assert.Nil(t, err.Unwrap())
}

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrInsufficientTime",
			err:  ErrInsufficientTime,
			want: "interceptors: insufficient time for request processing",
		},
		{
			name: "ErrNilHandler",
			err:  ErrNilHandler,
			want: "interceptors: handler cannot be nil",
		},
		{
			name: "ErrInvalidOverhead",
			err:  ErrInvalidOverhead,
			want: "interceptors: return overhead must be >= 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.err.Error())
		})
	}
}
