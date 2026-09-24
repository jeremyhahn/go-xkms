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

package grpc

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestMapPasswordError_UserPINSentinels pins the status codes for the password
// store user-PIN sentinels. Before these mappings the sentinels fell through to
// codes.Internal, so a caller could not tell a missing credential from a server
// fault.
func TestMapPasswordError_UserPINSentinels(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want codes.Code
	}{
		{
			name: "user PIN required",
			err:  xkms.ErrPasswordStoreUserPINRequired,
			want: codes.InvalidArgument,
		},
		{
			name: "user PIN not provisioned",
			err:  xkms.ErrPasswordStoreUserPINNotProvisioned,
			want: codes.FailedPrecondition,
		},
		{
			name: "decrypt not supported",
			err:  xkms.ErrPasswordDecryptNotSupported,
			want: codes.Unimplemented,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapPasswordError(tc.err)
			require.Error(t, got)
			assert.Equal(t, tc.want, status.Code(got))
		})
	}
}

// TestMapPasswordUnlockError covers the unlock path's mapping. It differs from
// mapPasswordError only in its fallback: on the unlock path an unrecognised
// error is a failed PIN verification, which is PermissionDenied rather than
// Internal.
func TestMapPasswordUnlockError(t *testing.T) {
	t.Run("nil is nil", func(t *testing.T) {
		assert.NoError(t, mapPasswordUnlockError(nil))
	})

	t.Run("missing PIN is invalid argument", func(t *testing.T) {
		err := mapPasswordUnlockError(xkms.ErrPasswordStoreUserPINRequired)
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("unprovisioned PIN is failed precondition", func(t *testing.T) {
		err := mapPasswordUnlockError(xkms.ErrPasswordStoreUserPINNotProvisioned)
		require.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	})

	t.Run("wrong PIN is permission denied and does not leak backend detail", func(t *testing.T) {
		backendErr := errors.New("pin: verification failed, 2 attempts remaining")

		err := mapPasswordUnlockError(backendErr)
		require.Error(t, err)
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
		assert.NotContains(t, err.Error(), "attempts remaining",
			"retry counters and lockout state must not reach the caller")
		assert.Contains(t, err.Error(), "user PIN verification failed")
	})

	t.Run("genuine internal faults stay internal", func(t *testing.T) {
		// These are deliberately mapped to Internal by mapPasswordError and
		// must not be reinterpreted as a failed credential check.
		for _, sentinel := range []error{
			staticpw.ErrNilStore,
			staticpw.ErrNilBarrierRegistry,
		} {
			err := mapPasswordUnlockError(sentinel)
			require.Error(t, err)
			assert.Equal(t, codes.Internal, status.Code(err), sentinel.Error())
		}
	})

	t.Run("already unlocked is preserved", func(t *testing.T) {
		err := mapPasswordUnlockError(staticpw.ErrStoreNotLocked)
		require.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	})

	t.Run("not configured is preserved", func(t *testing.T) {
		err := mapPasswordUnlockError(xkms.ErrNotConfigured)
		require.Error(t, err)
		assert.Equal(t, codes.Unavailable, status.Code(err))
	})
}

// TestIsKnownInternalPasswordError distinguishes the sentinels mapPasswordError
// deliberately reports as Internal from an unrecognised error that merely fell
// through to its default.
func TestIsKnownInternalPasswordError(t *testing.T) {
	assert.True(t, isKnownInternalPasswordError(staticpw.ErrNilStore))
	assert.True(t, isKnownInternalPasswordError(staticpw.ErrNilBarrierRegistry))
	assert.False(t, isKnownInternalPasswordError(errors.New("pin: verification failed")))
}
