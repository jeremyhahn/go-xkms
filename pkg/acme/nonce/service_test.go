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

package nonce

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceAdapter(t *testing.T) {
	t.Run("adapts Generate to Nonce", func(t *testing.T) {
		svc, err := NewService()
		require.NoError(t, err)

		adapter := NewServiceAdapter(svc)

		nonce, err := adapter.Nonce(context.Background())

		require.NoError(t, err)
		assert.NotEmpty(t, nonce)
	})

	t.Run("adapts Redeem", func(t *testing.T) {
		svc, err := NewService()
		require.NoError(t, err)

		adapter := NewServiceAdapter(svc)

		nonce, _ := adapter.Nonce(context.Background())
		err = adapter.Redeem(context.Background(), nonce)

		assert.NoError(t, err)
	})

	t.Run("implements Getter interface", func(t *testing.T) {
		svc, _ := NewService()
		adapter := NewServiceAdapter(svc)

		var getter Getter = adapter
		_, err := getter.Nonce(context.Background())
		assert.NoError(t, err)
	})

	t.Run("implements Redeemer interface", func(t *testing.T) {
		svc, _ := NewService()
		adapter := NewServiceAdapter(svc)

		nonce, _ := svc.Generate()

		var redeemer Redeemer = adapter
		err := redeemer.Redeem(context.Background(), nonce)
		assert.NoError(t, err)
	})
}

func TestMultiService(t *testing.T) {
	t.Run("creates with local service", func(t *testing.T) {
		local, _ := NewService(WithPrefix("AAAAAAAA"))
		multi := NewMultiService(local)

		assert.Equal(t, "AAAAAAAA", multi.Prefix())
	})

	t.Run("generates using local service", func(t *testing.T) {
		local, _ := NewService(WithPrefix("AAAAAAAA"))
		multi := NewMultiService(local)

		nonce, err := multi.Generate()

		require.NoError(t, err)
		assert.True(t, len(nonce) > PrefixLen)
		assert.Equal(t, "AAAAAAAA", nonce[:PrefixLen])
	})

	t.Run("redeems local nonce", func(t *testing.T) {
		local, _ := NewService(WithPrefix("AAAAAAAA"))
		multi := NewMultiService(local)

		nonce, _ := multi.Generate()
		err := multi.Redeem(nonce)

		assert.NoError(t, err)
	})

	t.Run("registers and redeems remote service", func(t *testing.T) {
		key := make([]byte, 16)
		rand.Read(key)

		local, _ := NewService(WithPrefix("AAAAAAAA"), WithKey(key))
		remote, _ := NewService(WithPrefix("BBBBBBBB"), WithKey(key))

		multi := NewMultiService(local)
		multi.Register(remote)

		// Generate nonce from remote
		remoteNonce, _ := remote.Generate()

		// Multi should route to remote service
		err := multi.Redeem(remoteNonce)
		assert.NoError(t, err)
	})

	t.Run("falls back to local for unknown prefix", func(t *testing.T) {
		local, _ := NewService(WithPrefix("AAAAAAAA"))
		multi := NewMultiService(local)

		localNonce, _ := local.Generate()
		err := multi.Redeem(localNonce)
		assert.NoError(t, err)
	})

	t.Run("unregisters service", func(t *testing.T) {
		key := make([]byte, 16)
		rand.Read(key)

		local, _ := NewService(WithPrefix("AAAAAAAA"), WithKey(key))
		remote, _ := NewService(WithPrefix("BBBBBBBB"), WithKey(key))

		multi := NewMultiService(local)
		multi.Register(remote)

		// Generate nonce before unregister
		remoteNonce, _ := remote.Generate()

		// Unregister remote
		multi.Unregister("BBBBBBBB")

		// Should now fail (routed to local which can't decrypt)
		err := multi.Redeem(remoteNonce)
		assert.Error(t, err)
	})

	t.Run("Valid routes to correct service", func(t *testing.T) {
		key := make([]byte, 16)
		rand.Read(key)

		local, _ := NewService(WithPrefix("AAAAAAAA"), WithKey(key))
		remote, _ := NewService(WithPrefix("BBBBBBBB"), WithKey(key))

		multi := NewMultiService(local)
		multi.Register(remote)

		remoteNonce, _ := remote.Generate()
		err := multi.Valid(remoteNonce)
		assert.NoError(t, err)
	})

	t.Run("Valid falls back to local for short nonce", func(t *testing.T) {
		local, _ := NewService()
		multi := NewMultiService(local)

		err := multi.Valid("short")
		assert.Error(t, err)
	})

	t.Run("Redeem falls back to local for short nonce", func(t *testing.T) {
		local, _ := NewService()
		multi := NewMultiService(local)

		err := multi.Redeem("short")
		assert.Error(t, err)
	})

	t.Run("handles nil local service prefix", func(t *testing.T) {
		local, _ := NewService() // No prefix
		multi := NewMultiService(local)

		assert.Equal(t, "", multi.Prefix())
	})

	t.Run("ignores register of empty prefix", func(t *testing.T) {
		local, _ := NewService(WithPrefix("AAAAAAAA"))
		noPrefix, _ := NewService()

		multi := NewMultiService(local)
		multi.Register(noPrefix)

		// Should only have local registered
		assert.Equal(t, 1, len(multi.services))
	})

	t.Run("Valid falls back to local for unknown prefix", func(t *testing.T) {
		key := make([]byte, 16)
		rand.Read(key)

		local, _ := NewService(WithPrefix("AAAAAAAA"), WithKey(key))
		multi := NewMultiService(local)

		// Create a nonce with unknown prefix but valid format
		unknown, _ := NewService(WithPrefix("CCCCCCCC"), WithKey(key))
		unknownNonce, _ := unknown.Generate()

		// Should fall back to local, which will fail to decrypt
		err := multi.Valid(unknownNonce)
		assert.Error(t, err)
	})

	t.Run("Redeem falls back to local for unknown prefix after lookup", func(t *testing.T) {
		key := make([]byte, 16)
		rand.Read(key)

		local, _ := NewService(WithPrefix("AAAAAAAA"), WithKey(key))
		multi := NewMultiService(local)

		// Create nonce with prefix that is not registered
		unknown, _ := NewService(WithPrefix("DDDDDDDD"), WithKey(key))
		unknownNonce, _ := unknown.Generate()

		// MultiService has prefix "DDDDDDDD" in nonce but no service registered for it
		// Should fall back to local which will fail prefix mismatch
		err := multi.Redeem(unknownNonce)
		assert.Error(t, err)
	})
}

func TestNonceServiceInterface(t *testing.T) {
	t.Run("Service implements NonceService", func(t *testing.T) {
		svc, _ := NewService()
		var _ NonceService = svc
	})

	t.Run("MultiService implements NonceService", func(t *testing.T) {
		local, _ := NewService()
		multi := NewMultiService(local)
		var _ NonceService = multi
	})
}
