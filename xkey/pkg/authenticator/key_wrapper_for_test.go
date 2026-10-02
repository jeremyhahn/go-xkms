// Copyright (c) 2026 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authenticator

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// TestKeyWrapperFor_RoundTripsThroughProtectedBuffers proves a wrapper built
// from a protected key wraps and unwraps into protected memory, and that the
// key buffer is still usable afterwards (the borrow was released).
func TestKeyWrapperFor_RoundTripsThroughProtectedBuffers(t *testing.T) {
	key, err := newRandomKeyBuffer(AESGCMKeySize)
	require.NoError(t, err)
	defer key.Destroy()

	plain := make([]byte, 32)
	_, err = rand.Read(plain)
	require.NoError(t, err)
	src, err := secure.NewBufferFromBytes(append([]byte(nil), plain...))
	require.NoError(t, err)
	defer src.Destroy()

	wrapped, err := wrapFromProtected(key, src)
	require.NoError(t, err)

	dst, err := unwrapIntoProtected(key, wrapped)
	require.NoError(t, err)
	defer dst.Destroy()
	require.NoError(t, dst.WithBytes(func(b []byte) error {
		assert.Equal(t, plain, b)
		return nil
	}))
	assert.Equal(t, AESGCMKeySize, key.Size())
}

// TestKeyWrapperFor_NilKey proves an absent key is reported as locked.
func TestKeyWrapperFor_NilKey(t *testing.T) {
	wrapper, err := keyWrapperFor(nil)
	assert.ErrorIs(t, err, ErrKeyManagerLocked)
	assert.Nil(t, wrapper)

	dst, err := unwrapIntoProtected(nil, make([]byte, 64))
	assert.Error(t, err)
	assert.Nil(t, dst)
}

// TestUnwrapIntoProtected_WrongKeyLeavesNothing proves a failed
// authentication returns no buffer.
func TestUnwrapIntoProtected_WrongKeyLeavesNothing(t *testing.T) {
	right, err := newRandomKeyBuffer(AESGCMKeySize)
	require.NoError(t, err)
	defer right.Destroy()
	wrong, err := newRandomKeyBuffer(AESGCMKeySize)
	require.NoError(t, err)
	defer wrong.Destroy()
	src, err := newRandomKeyBuffer(32)
	require.NoError(t, err)
	defer src.Destroy()

	wrapped, err := wrapFromProtected(right, src)
	require.NoError(t, err)

	dst, err := unwrapIntoProtected(wrong, wrapped)
	assert.ErrorIs(t, err, ErrKeyUnwrapFailed)
	assert.Nil(t, dst)
}
