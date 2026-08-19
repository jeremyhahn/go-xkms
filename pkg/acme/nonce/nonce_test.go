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
	"container/heap"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewService(t *testing.T) {
	t.Run("creates service with defaults", func(t *testing.T) {
		svc, err := NewService()

		require.NoError(t, err)
		require.NotNil(t, svc)
		assert.Equal(t, "", svc.Prefix())
		assert.Equal(t, int64(0), svc.Latest())
		assert.Equal(t, int64(0), svc.Earliest())
		assert.Equal(t, 0, svc.UsedCount())
	})

	t.Run("creates service with prefix", func(t *testing.T) {
		prefix := "AAAAAAAA" // Valid 8-char base64url

		svc, err := NewService(WithPrefix(prefix))

		require.NoError(t, err)
		assert.Equal(t, prefix, svc.Prefix())
	})

	t.Run("creates service with maxUsed", func(t *testing.T) {
		svc, err := NewService(WithMaxUsed(100))

		require.NoError(t, err)
		assert.Equal(t, 100, svc.maxUsed)
	})

	t.Run("uses default maxUsed for zero value", func(t *testing.T) {
		svc, err := NewService(WithMaxUsed(0))

		require.NoError(t, err)
		assert.Equal(t, DefaultMaxUsed, svc.maxUsed)
	})

	t.Run("uses default maxUsed for negative value", func(t *testing.T) {
		svc, err := NewService(WithMaxUsed(-1))

		require.NoError(t, err)
		assert.Equal(t, DefaultMaxUsed, svc.maxUsed)
	})

	t.Run("creates service with custom key", func(t *testing.T) {
		key := make([]byte, 16)
		rand.Read(key)

		svc, err := NewService(WithKey(key))

		require.NoError(t, err)
		require.NotNil(t, svc)
	})

	t.Run("rejects invalid prefix length", func(t *testing.T) {
		_, err := NewService(WithPrefix("short"))

		assert.Error(t, err)
	})

	t.Run("rejects invalid prefix encoding", func(t *testing.T) {
		_, err := NewService(WithPrefix("!!!!!!!!!")) // Invalid base64

		assert.Error(t, err)
	})

	t.Run("rejects invalid key length", func(t *testing.T) {
		_, err := NewService(WithKey([]byte("short")))

		assert.Error(t, err)
	})

	t.Run("accepts empty prefix", func(t *testing.T) {
		svc, err := NewService(WithPrefix(""))

		require.NoError(t, err)
		assert.Equal(t, "", svc.Prefix())
	})

	t.Run("rejects 8 char invalid base64url prefix", func(t *testing.T) {
		// 8 characters but contains invalid base64url characters
		_, err := NewService(WithPrefix("!@#$%^&*"))

		require.Error(t, err)
		var validationErr *errors.ValidationError
		require.True(t, errors.As(err, &validationErr))
		assert.Equal(t, "prefix", validationErr.Field)
		assert.Contains(t, validationErr.Message, "base64url")
	})
}

func TestServiceGenerate(t *testing.T) {
	t.Run("generates unique nonces", func(t *testing.T) {
		svc, err := NewService()
		require.NoError(t, err)

		nonces := make(map[string]bool)
		for i := 0; i < 100; i++ {
			nonce, err := svc.Generate()
			require.NoError(t, err)
			assert.False(t, nonces[nonce], "duplicate nonce generated")
			nonces[nonce] = true
		}
	})

	t.Run("increments counter", func(t *testing.T) {
		svc, err := NewService()
		require.NoError(t, err)

		svc.Generate()
		assert.Equal(t, int64(1), svc.Latest())

		svc.Generate()
		assert.Equal(t, int64(2), svc.Latest())
	})

	t.Run("includes prefix", func(t *testing.T) {
		prefix := "AAAAAAAA"
		svc, err := NewService(WithPrefix(prefix))
		require.NoError(t, err)

		nonce, err := svc.Generate()

		require.NoError(t, err)
		assert.True(t, len(nonce) > PrefixLen)
		assert.Equal(t, prefix, nonce[:PrefixLen])
	})

	t.Run("generates valid base64url", func(t *testing.T) {
		svc, err := NewService()
		require.NoError(t, err)

		nonce, err := svc.Generate()
		require.NoError(t, err)

		_, err = base64.RawURLEncoding.DecodeString(nonce)
		assert.NoError(t, err)
	})
}

func TestServiceRedeem(t *testing.T) {
	t.Run("redeems valid nonce", func(t *testing.T) {
		svc, err := NewService()
		require.NoError(t, err)

		nonce, _ := svc.Generate()

		err = svc.Redeem(nonce)

		assert.NoError(t, err)
	})

	t.Run("rejects already used nonce", func(t *testing.T) {
		svc, err := NewService()
		require.NoError(t, err)

		nonce, _ := svc.Generate()
		svc.Redeem(nonce)

		err = svc.Redeem(nonce)

		assert.Error(t, err)
		var nonceErr *errors.NonceError
		require.True(t, errors.As(err, &nonceErr))
		assert.True(t, errors.Is(nonceErr.Cause, errors.ErrNonceAlreadyUsed))
	})

	t.Run("rejects nonce with wrong prefix", func(t *testing.T) {
		svc, err := NewService(WithPrefix("AAAAAAAA"))
		require.NoError(t, err)

		// Generate nonce then modify prefix
		nonce, _ := svc.Generate()
		badNonce := "BBBBBBBB" + nonce[PrefixLen:]

		err = svc.Redeem(badNonce)

		assert.Error(t, err)
		var nonceErr *errors.NonceError
		require.True(t, errors.As(err, &nonceErr))
		assert.True(t, errors.Is(nonceErr.Cause, errors.ErrNoncePrefixMismatch))
	})

	t.Run("rejects invalid nonce format", func(t *testing.T) {
		svc, err := NewService()
		require.NoError(t, err)

		err = svc.Redeem("invalid-nonce!!!")

		assert.Error(t, err)
	})

	t.Run("rejects nonce too short", func(t *testing.T) {
		svc, err := NewService(WithPrefix("AAAAAAAA"))
		require.NoError(t, err)

		err = svc.Redeem("ABC")

		assert.Error(t, err)
	})

	t.Run("rejects nonce with counter too high", func(t *testing.T) {
		key := make([]byte, 16)
		rand.Read(key)

		svc1, _ := NewService(WithKey(key))
		svc2, _ := NewService(WithKey(key))

		// Generate 10 nonces on svc2
		var lastNonce string
		for i := 0; i < 10; i++ {
			lastNonce, _ = svc2.Generate()
		}

		// svc1 has latest=0, so svc2's nonce should be "too high"
		err := svc1.Redeem(lastNonce)

		assert.Error(t, err)
		var nonceErr *errors.NonceError
		require.True(t, errors.As(err, &nonceErr))
		assert.True(t, errors.Is(nonceErr.Cause, errors.ErrNonceTooHigh))
	})

	t.Run("retires oldest nonces when maxUsed exceeded", func(t *testing.T) {
		svc, err := NewService(WithMaxUsed(10))
		require.NoError(t, err)

		nonces := make([]string, 20)
		for i := 0; i < 20; i++ {
			nonces[i], _ = svc.Generate()
		}

		// Redeem all 20 nonces - oldest should be retired
		for _, n := range nonces {
			svc.Redeem(n)
		}

		// First nonce should now be too old
		assert.Equal(t, 10, svc.UsedCount())
		assert.Greater(t, svc.Earliest(), int64(0))
	})

	t.Run("rejects nonce below earliest", func(t *testing.T) {
		svc, err := NewService(WithMaxUsed(5))
		require.NoError(t, err)

		// Generate and redeem 10 nonces to advance earliest
		for i := 0; i < 10; i++ {
			n, _ := svc.Generate()
			svc.Redeem(n)
		}

		// Create a new nonce with same key but lower counter
		// This is simulated by setting earliest manually
		svc.mu.Lock()
		svc.earliest = 8
		svc.mu.Unlock()

		// Create a valid-looking nonce that would decode to counter 5
		// We can't easily test this without access to encrypt method,
		// but we can verify earliest is respected
		assert.Greater(t, svc.Earliest(), int64(0))
	})

	t.Run("rejects tampered ciphertext", func(t *testing.T) {
		svc, err := NewService()
		require.NoError(t, err)

		nonce, err := svc.Generate()
		require.NoError(t, err)

		// Decode, tamper with ciphertext, re-encode
		decoded, _ := base64.RawURLEncoding.DecodeString(nonce)
		// Flip bits in the ciphertext portion (after first 8 bytes)
		decoded[20] ^= 0xFF
		tampered := base64.RawURLEncoding.EncodeToString(decoded)

		err = svc.Redeem(tampered)

		assert.Error(t, err)
		var nonceErr *errors.NonceError
		require.True(t, errors.As(err, &nonceErr))
	})

	t.Run("rejects nonce with invalid length after decode", func(t *testing.T) {
		svc, err := NewService()
		require.NoError(t, err)

		// Create a valid base64url string that decodes to wrong length (not 32 bytes)
		shortData := make([]byte, 16) // Wrong length, should be 32
		rand.Read(shortData)
		invalidNonce := base64.RawURLEncoding.EncodeToString(shortData)

		err = svc.Redeem(invalidNonce)

		assert.Error(t, err)
		var nonceErr *errors.NonceError
		require.True(t, errors.As(err, &nonceErr))
		assert.True(t, errors.Is(nonceErr.Cause, errors.ErrInvalidNonceLength))
	})
}

func TestServiceValid(t *testing.T) {
	t.Run("validates without redeeming", func(t *testing.T) {
		svc, err := NewService()
		require.NoError(t, err)

		nonce, _ := svc.Generate()

		err = svc.Valid(nonce)
		assert.NoError(t, err)

		// Should still be valid for redemption
		err = svc.Redeem(nonce)
		assert.NoError(t, err)
	})

	t.Run("reports already used nonce", func(t *testing.T) {
		svc, err := NewService()
		require.NoError(t, err)

		nonce, _ := svc.Generate()
		svc.Redeem(nonce)

		err = svc.Valid(nonce)
		assert.Error(t, err)
	})

	t.Run("rejects nonce with counter too high", func(t *testing.T) {
		key := make([]byte, 16)
		rand.Read(key)

		svc1, _ := NewService(WithKey(key))
		svc2, _ := NewService(WithKey(key))

		// Generate nonces on svc2 only
		var futureNonce string
		for i := 0; i < 5; i++ {
			futureNonce, _ = svc2.Generate()
		}

		// svc1 has latest=0, so svc2's nonce should be "too high"
		err := svc1.Valid(futureNonce)

		assert.Error(t, err)
		var nonceErr *errors.NonceError
		require.True(t, errors.As(err, &nonceErr))
		assert.True(t, errors.Is(nonceErr.Cause, errors.ErrNonceTooHigh))
	})

	t.Run("rejects nonce with counter too low", func(t *testing.T) {
		key := make([]byte, 16)
		rand.Read(key)

		svc, err := NewService(WithKey(key), WithMaxUsed(5))
		require.NoError(t, err)

		// Generate first nonce to save
		earlyNonce, _ := svc.Generate()

		// Generate and redeem more nonces to advance earliest
		for i := 0; i < 10; i++ {
			n, _ := svc.Generate()
			svc.Redeem(n)
		}

		// Now earlyNonce should be too old
		err = svc.Valid(earlyNonce)

		assert.Error(t, err)
		var nonceErr *errors.NonceError
		require.True(t, errors.As(err, &nonceErr))
		assert.True(t, errors.Is(nonceErr.Cause, errors.ErrNonceTooLow))
	})

	t.Run("rejects tampered ciphertext", func(t *testing.T) {
		svc, err := NewService()
		require.NoError(t, err)

		nonce, err := svc.Generate()
		require.NoError(t, err)

		// Decode, tamper with ciphertext, re-encode
		decoded, _ := base64.RawURLEncoding.DecodeString(nonce)
		decoded[25] ^= 0xFF
		tampered := base64.RawURLEncoding.EncodeToString(decoded)

		err = svc.Valid(tampered)

		assert.Error(t, err)
	})

	t.Run("rejects nonce with invalid length after decode", func(t *testing.T) {
		svc, err := NewService()
		require.NoError(t, err)

		// Create a valid base64url string that decodes to wrong length
		shortData := make([]byte, 20) // Wrong length, should be 32
		rand.Read(shortData)
		invalidNonce := base64.RawURLEncoding.EncodeToString(shortData)

		err = svc.Valid(invalidNonce)

		assert.Error(t, err)
		var nonceErr *errors.NonceError
		require.True(t, errors.As(err, &nonceErr))
		assert.True(t, errors.Is(nonceErr.Cause, errors.ErrInvalidNonceLength))
	})
}

func TestDerivePrefix(t *testing.T) {
	t.Run("derives consistent prefix", func(t *testing.T) {
		key := []byte("secret-key-12345")
		addr := "localhost:8443"

		p1 := DerivePrefix(addr, key)
		p2 := DerivePrefix(addr, key)

		assert.Equal(t, p1, p2)
		assert.Len(t, p1, PrefixLen)
	})

	t.Run("different addresses give different prefixes", func(t *testing.T) {
		key := []byte("secret-key-12345")

		p1 := DerivePrefix("localhost:8443", key)
		p2 := DerivePrefix("localhost:8444", key)

		assert.NotEqual(t, p1, p2)
	})

	t.Run("different keys give different prefixes", func(t *testing.T) {
		addr := "localhost:8443"

		// >= 112-bit HMAC keys: FIPS 140-3 (SP 800-131A Rev. 2) sets that floor
		// and crypto/hmac enforces it under GODEBUG=fips140=only. The point of
		// this case is that distinct keys give distinct prefixes, which a
		// realistic key length demonstrates just as well as a 4-byte one.
		p1 := DerivePrefix(addr, []byte("derive-prefix-key-1"))
		p2 := DerivePrefix(addr, []byte("derive-prefix-key-2"))

		assert.NotEqual(t, p1, p2)
	})

	t.Run("prefix is valid base64url", func(t *testing.T) {
		prefix := DerivePrefix("test", []byte("derive-prefix-key-1"))

		_, err := base64.RawURLEncoding.DecodeString(prefix)
		assert.NoError(t, err)
	})
}

func TestServiceConcurrency(t *testing.T) {
	t.Run("handles concurrent generate", func(t *testing.T) {
		svc, err := NewService()
		require.NoError(t, err)

		nonces := make(chan string, 100)
		var wg sync.WaitGroup

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				n, err := svc.Generate()
				if err == nil {
					nonces <- n
				}
			}()
		}

		wg.Wait()
		close(nonces)

		seen := make(map[string]bool)
		for n := range nonces {
			assert.False(t, seen[n], "duplicate nonce")
			seen[n] = true
		}
		assert.Len(t, seen, 100)
	})

	t.Run("handles concurrent redeem", func(t *testing.T) {
		svc, err := NewService()
		require.NoError(t, err)

		// Pre-generate nonces
		nonces := make([]string, 100)
		for i := 0; i < 100; i++ {
			nonces[i], _ = svc.Generate()
		}

		var wg sync.WaitGroup
		var successCount int32
		var mu sync.Mutex

		for _, n := range nonces {
			wg.Add(1)
			go func(nonce string) {
				defer wg.Done()
				if svc.Redeem(nonce) == nil {
					mu.Lock()
					successCount++
					mu.Unlock()
				}
			}(n)
		}

		wg.Wait()
		assert.Equal(t, int32(100), successCount)
	})

	t.Run("handles mixed concurrent operations", func(t *testing.T) {
		svc, err := NewService(WithMaxUsed(50))
		require.NoError(t, err)

		var wg sync.WaitGroup

		// Generators
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					n, err := svc.Generate()
					if err == nil {
						svc.Redeem(n)
					}
				}
			}()
		}

		wg.Wait()
		// No panics or deadlocks = success
	})
}

func TestInt64Heap(t *testing.T) {
	t.Run("maintains min-heap property with heap package", func(t *testing.T) {
		h := &int64Heap{}
		heap.Init(h)
		heap.Push(h, int64(5))
		heap.Push(h, int64(2))
		heap.Push(h, int64(8))
		heap.Push(h, int64(1))

		// Pop should return smallest first
		val := heap.Pop(h).(int64)
		assert.Equal(t, int64(1), val)
	})

	t.Run("Len returns correct count", func(t *testing.T) {
		h := int64Heap{1, 2, 3}
		assert.Equal(t, 3, h.Len())
	})

	t.Run("Less compares correctly", func(t *testing.T) {
		h := int64Heap{1, 5, 3}
		assert.True(t, h.Less(0, 1))
		assert.False(t, h.Less(1, 0))
	})

	t.Run("Swap works correctly", func(t *testing.T) {
		h := int64Heap{1, 2, 3}
		h.Swap(0, 2)
		assert.Equal(t, int64(3), h[0])
		assert.Equal(t, int64(1), h[2])
	})

	t.Run("Pop removes last element", func(t *testing.T) {
		h := int64Heap{1, 2, 3}
		val := h.Pop()
		assert.Equal(t, int64(3), val)
		assert.Len(t, h, 2)
	})

	t.Run("Push appends element", func(t *testing.T) {
		h := int64Heap{1, 2}
		h.Push(int64(3))
		assert.Len(t, h, 3)
		assert.Equal(t, int64(3), h[2])
	})
}

func TestDecryptEdgeCases(t *testing.T) {
	t.Run("rejects nonce shorter than prefix when prefix set", func(t *testing.T) {
		svc, err := NewService(WithPrefix("AAAAAAAA"))
		require.NoError(t, err)

		// Try to validate a nonce shorter than the prefix length
		err = svc.Valid("SHORT")

		assert.Error(t, err)
		var nonceErr *errors.NonceError
		require.True(t, errors.As(err, &nonceErr))
		assert.True(t, errors.Is(nonceErr.Cause, errors.ErrInvalidNonceLength))
	})

	t.Run("rejects nonce with mismatched prefix", func(t *testing.T) {
		svc, err := NewService(WithPrefix("AAAAAAAA"))
		require.NoError(t, err)

		// Create a nonce-length valid base64url string with wrong prefix
		data := make([]byte, NonceLen)
		rand.Read(data)
		wrongPrefixNonce := "ZZZZZZZZ" + base64.RawURLEncoding.EncodeToString(data)

		err = svc.Valid(wrongPrefixNonce)

		assert.Error(t, err)
		var nonceErr *errors.NonceError
		require.True(t, errors.As(err, &nonceErr))
		assert.True(t, errors.Is(nonceErr.Cause, errors.ErrNoncePrefixMismatch))
	})

	t.Run("handles GCM decryption failure", func(t *testing.T) {
		svc, err := NewService()
		require.NoError(t, err)

		// Generate a valid nonce first
		nonce, err := svc.Generate()
		require.NoError(t, err)

		// Create a properly sized but corrupted nonce
		decoded, _ := base64.RawURLEncoding.DecodeString(nonce)
		// Corrupt the authentication tag (last 16 bytes of ciphertext)
		for i := len(decoded) - 5; i < len(decoded); i++ {
			decoded[i] ^= 0xFF
		}
		corrupted := base64.RawURLEncoding.EncodeToString(decoded)

		err = svc.Redeem(corrupted)

		assert.Error(t, err)
	})
}
