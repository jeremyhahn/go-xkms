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

package wrapping

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// failingBorrower fails the borrow, as a destroyed buffer does.
type failingBorrower struct{ err error }

func (f failingBorrower) WithBytes(func([]byte) error) error { return f.err }

func TestWindow_LendsOnlyTheRequestedRange(t *testing.T) {
	buf, err := secure.NewBufferFromBytes([]byte("0123456789"))
	require.NoError(t, err)
	defer buf.Destroy()

	got, err := copyOutKey(window{buf: buf, offset: 2, length: 5})
	require.NoError(t, err)
	assert.Equal(t, []byte("23456"), got)
}

func TestCopyOutKey_BorrowFailureIsACryptoError(t *testing.T) {
	cause := errors.New("borrow refused")
	_, err := copyOutKey(failingBorrower{err: cause})
	var ce *CryptoError
	require.ErrorAs(t, err, &ce)
	assert.ErrorIs(t, err, cause)
}

func TestCopyOutKey_DestroyedBufferIsRefused(t *testing.T) {
	buf, err := secure.NewBufferFromBytes([]byte("0123456789"))
	require.NoError(t, err)
	buf.Destroy()

	out, err := copyOutKey(window{buf: buf, offset: 0, length: 4})
	var ce *CryptoError
	require.ErrorAs(t, err, &ce)
	assert.Nil(t, out)
}

// TestRoundTrips_AfterRegisterRefactor pins that the in-place register
// helpers still invert one another across the single-block and general paths.
func TestRoundTrips_AfterRegisterRefactor(t *testing.T) {
	kek := make([]byte, 32)
	for _, size := range []int{1, 7, 8, 9, 16, 20, 32, 33} {
		key := make([]byte, size)
		for i := range key {
			key[i] = byte(i + 1)
		}
		wrapped, err := WrapAESKWP(key, kek)
		require.NoError(t, err, "size %d", size)
		got, err := UnwrapAESKWP(wrapped, kek)
		require.NoError(t, err, "size %d", size)
		assert.Equal(t, key, got, "size %d", size)
	}
}
