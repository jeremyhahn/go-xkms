// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package symmetric

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/importtoken"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// go-xkms#1261: the symmetric backend's import-token wrapping keys
// previously lived in a plain map that only ever grew -- never capped,
// never swept for expiry, and (unlike the software backend) never even
// cleared on Close. These tests cover the fix: single-use tokens, a
// capacity limit, and destroyed key material on eviction.

func testSymmetricAttrs(cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:                 cn,
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
}

// TestUnwrapKey_TokenSingleUse verifies a used token is gone: a second
// UnwrapKey call with the same import token fails, because the first
// call's Take removed and destroyed the wrapping key.
func TestUnwrapKey_TokenSingleUse(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	attrs := testSymmetricAttrs("single-use")
	params, err := b.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	keyMaterial := make([]byte, 32)
	_, err = rand.Read(keyMaterial)
	require.NoError(t, err)

	wrapped, err := b.WrapKey(context.Background(), keyMaterial, params)
	require.NoError(t, err)

	_, err = b.UnwrapKey(context.Background(), wrapped, params)
	require.NoError(t, err)

	_, err = b.UnwrapKey(context.Background(), wrapped, params)
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

// TestImportKey_TokenConsumedRegardlessOfOutcome verifies a successful
// ImportKey leaves its token consumed, so a second ImportKey attempt with
// the same wrapped material fails rather than silently reusing the
// wrapping key.
func TestImportKey_TokenConsumedRegardlessOfOutcome(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	attrs := testSymmetricAttrs("token-consumed")
	params, err := b.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	keyMaterial := make([]byte, 32)
	_, err = rand.Read(keyMaterial)
	require.NoError(t, err)

	wrapped, err := b.WrapKey(context.Background(), keyMaterial, params)
	require.NoError(t, err)

	require.NoError(t, b.ImportKey(context.Background(), attrs, wrapped))

	err = b.ImportKey(context.Background(), attrs, wrapped)
	require.Error(t, err, "a second ImportKey with the same token must fail once it is consumed")
}

// TestUnwrapKey_ExpiredTokenIsSwept verifies an expired token is swept:
// once its TTL passes, UnwrapKey reports it not found rather than
// unwrapping with a wrapping key that should already be gone.
func TestUnwrapKey_ExpiredTokenIsSwept(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	// Swap in a Store with a TTL so short the entry is already past
	// expiry by the time UnwrapKey looks it up, exercising the real
	// sweep-on-Take path.
	b.wrappingKeys = importtoken.New[*importtoken.SealedRSAKey](time.Nanosecond, importtoken.DefaultMaxTokens, (*importtoken.SealedRSAKey).Destroy)

	attrs := testSymmetricAttrs("expiring")
	params, err := b.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	keyMaterial := make([]byte, 32)
	_, err = rand.Read(keyMaterial)
	require.NoError(t, err)

	wrapped, err := b.WrapKey(context.Background(), keyMaterial, params)
	require.NoError(t, err)

	time.Sleep(time.Millisecond)

	_, err = b.UnwrapKey(context.Background(), wrapped, params)
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

// TestGetImportParameters_CapEnforced verifies the hard cap holds: once
// the wrapping-key store is full, GetImportParameters reports a typed
// *importtoken.LimitExceededError instead of growing past the limit. The
// store is swapped for one with a cap of 2 so the test does not need to
// generate thousands of RSA keys to observe the real DefaultMaxTokens
// limit.
func TestGetImportParameters_CapEnforced(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	b.wrappingKeys = importtoken.New[*importtoken.SealedRSAKey](time.Hour, 2, (*importtoken.SealedRSAKey).Destroy)

	attrs := testSymmetricAttrs("cap-enforced")
	for i := 0; i < 2; i++ {
		_, err := b.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		require.NoError(t, err)
	}

	_, err := b.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.Error(t, err)
	var limitErr *importtoken.LimitExceededError
	require.True(t, errors.As(err, &limitErr), "expected *importtoken.LimitExceededError, got %T: %v", err, err)
	assert.Equal(t, 2, limitErr.Limit)
	assert.Equal(t, 2, b.wrappingKeys.Len(), "the cap must hold rather than merely slow growth")
}

// TestClose_DestroysPendingWrappingKeys verifies eviction wipes the
// material on shutdown: this backend previously never cleared
// wrappingKeys at all, so a key generated by GetImportParameters and
// never consumed would outlive Close. After Close, the token is gone.
func TestClose_DestroysPendingWrappingKeys(t *testing.T) {
	b := createTestBackend(t)

	attrs := testSymmetricAttrs("close-destroys")
	params, err := b.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)
	require.Equal(t, 1, b.wrappingKeys.Len())

	require.NoError(t, b.Close())

	assert.Equal(t, 0, b.wrappingKeys.Len())
	_, err = b.wrappingKeys.Take(string(params.ImportToken))
	require.Error(t, err)
}
