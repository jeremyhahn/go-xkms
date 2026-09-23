//go:build codec_json

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

package handlers

import (
	"crypto/rand"
	"testing"
	"time"

	acmenonce "github.com/jeremyhahn/go-xkms/pkg/acme/nonce"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRestService_NonceValidRedeemedOnce verifies a nonce RestService mints
// validates exactly once through redeemNonce, RFC 8555 Section 6.5's
// single-use requirement, exercised through the wiring rather than
// pkg/acme/nonce directly.
func TestRestService_NonceValidRedeemedOnce(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	n, err := service.generateNonce()
	require.NoError(t, err)

	require.NoError(t, service.redeemNonce(n))
}

// TestRestService_NonceReplayRejected verifies a redeemed nonce is rejected
// on a second redemption attempt.
func TestRestService_NonceReplayRejected(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	n, err := service.generateNonce()
	require.NoError(t, err)
	require.NoError(t, service.redeemNonce(n))

	assert.Error(t, service.redeemNonce(n))
}

// TestRestService_NonceMalformedRejected verifies a syntactically invalid
// nonce is rejected rather than causing a panic.
func TestRestService_NonceMalformedRejected(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	assert.Error(t, service.redeemNonce("not-a-real-nonce!!!"))
}

// TestRestService_NonceForeignPrefixRejected verifies a nonce minted by a
// different, unregistered node (a different prefix under the same key) is
// rejected, per pkg/acme/nonce.MultiService's fall-back-to-local routing —
// the safe, RFC-8555-compliant outcome (badNonce; the client retries with a
// fresh nonce) for a request that lands on a node that does not know the
// issuing node.
func TestRestService_NonceForeignPrefixRejected(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	foreign, err := acmenonce.NewService(
		acmenonce.WithKey(service.nonceKey),
		acmenonce.WithPrefix("FFFFFFFF"),
	)
	require.NoError(t, err)

	foreignNonce, err := foreign.Generate()
	require.NoError(t, err)

	assert.Error(t, service.redeemNonce(foreignNonce))
}

// TestRestService_NonceBoundedMemoryUnderFlood verifies the redeemed-set
// pkg/acme/nonce tracks stays capped at Params.NonceMaxUsed regardless of
// how many nonces a client mints and redeems in one epoch — the defense a
// nonce flood needs against unbounded memory growth.
func TestRestService_NonceBoundedMemoryUnderFlood(t *testing.T) {
	const maxUsed = 50

	params := &Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		Logger:         setupTestLogger(),
		StorageFactory: setupTestStorage(t),
		NonceMaxUsed:   maxUsed,
	}
	svc, err := NewRestService(params)
	require.NoError(t, err)
	service := svc.(*RestService)

	for i := 0; i < maxUsed*10; i++ {
		n, err := service.generateNonce()
		require.NoError(t, err)
		require.NoError(t, service.redeemNonce(n))
	}

	assert.LessOrEqual(t, service.nonceEpoch.Load().UsedCount(), maxUsed)
}

// TestRestService_NonceEpochRotation verifies NonceLifetime bounds a nonce's
// validity: once the configured lifetime elapses, minting rotates to a fresh
// counter window and every nonce still outstanding from the previous epoch
// is retired.
func TestRestService_NonceEpochRotation(t *testing.T) {
	params := &Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		Logger:         setupTestLogger(),
		StorageFactory: setupTestStorage(t),
		NonceLifetime:  time.Minute,
	}
	svc, err := NewRestService(params)
	require.NoError(t, err)
	service := svc.(*RestService)

	stale, err := service.generateNonce()
	require.NoError(t, err)

	firstEpoch := service.nonceEpoch.Load()

	// Advance the clock seam past the epoch's lifetime.
	base := nonceClock()
	restore := nonceClock
	nonceClock = func() time.Time { return base.Add(2 * time.Minute) }
	defer func() { nonceClock = restore }()

	fresh, err := service.generateNonce()
	require.NoError(t, err)

	assert.NotSame(t, firstEpoch, service.nonceEpoch.Load(),
		"minting after the lifetime elapsed should rotate to a new epoch")

	// The pre-rotation nonce is gone with the retired epoch.
	assert.Error(t, service.redeemNonce(stale))
	// The post-rotation nonce redeems normally.
	assert.NoError(t, service.redeemNonce(fresh))
}

// TestRestService_NonceEpochRotation_NoConcurrentDoubleRotation verifies
// concurrent callers that all observe an expired epoch converge on a single
// replacement rather than each constructing and registering their own.
func TestRestService_NonceEpochRotation_NoConcurrentDoubleRotation(t *testing.T) {
	params := &Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		Logger:         setupTestLogger(),
		StorageFactory: setupTestStorage(t),
		NonceLifetime:  time.Minute,
	}
	svc, err := NewRestService(params)
	require.NoError(t, err)
	service := svc.(*RestService)

	base := nonceClock()
	restore := nonceClock
	nonceClock = func() time.Time { return base.Add(2 * time.Minute) }
	defer func() { nonceClock = restore }()

	const goroutines = 20
	results := make(chan *acmenonce.Service, goroutines)
	done := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			results <- service.currentNonceEpoch()
			done <- struct{}{}
		}()
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}
	close(results)

	first := <-results
	for epoch := range results {
		assert.Same(t, first, epoch)
	}
}

// TestNewRestService_NoncePrefixConfigured verifies Params.NoncePrefix
// changes the derived per-epoch prefix pkg/acme/nonce.MultiService routes
// by: two services built from the same key and epoch start but distinct
// NoncePrefix values get distinct, deterministic prefixes.
func TestNewRestService_NoncePrefixConfigured(t *testing.T) {
	key := make([]byte, nonceKeyLen)
	_, err := rand.Read(key)
	require.NoError(t, err)

	base := nonceClock()
	restore := nonceClock
	nonceClock = func() time.Time { return base }
	defer func() { nonceClock = restore }()

	nodeA, err := NewRestService(&Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		Logger:         setupTestLogger(),
		StorageFactory: setupTestStorage(t),
		NonceKey:       key,
		NoncePrefix:    "NODE0001",
	})
	require.NoError(t, err)
	serviceA := nodeA.(*RestService)

	nodeB, err := NewRestService(&Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		Logger:         setupTestLogger(),
		StorageFactory: setupTestStorage(t),
		NonceKey:       key,
		NoncePrefix:    "NODE0002",
	})
	require.NoError(t, err)
	serviceB := nodeB.(*RestService)

	prefixA := serviceA.GetNonceService().Prefix()
	prefixB := serviceB.GetNonceService().Prefix()

	assert.Len(t, prefixA, acmenonce.PrefixLen)
	assert.Len(t, prefixB, acmenonce.PrefixLen)
	assert.NotEqual(t, prefixA, prefixB)

	// Deterministic: rebuilding node A at the same epoch start derives the
	// same prefix again.
	rebuiltA, err := NewRestService(&Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		Logger:         setupTestLogger(),
		StorageFactory: setupTestStorage(t),
		NonceKey:       key,
		NoncePrefix:    "NODE0001",
	})
	require.NoError(t, err)
	assert.Equal(t, prefixA, rebuiltA.(*RestService).GetNonceService().Prefix())
}

// TestNewRestService_SharedNonceKeyValidatesAcrossNodes verifies that two
// RestService instances configured with the same Params.NonceKey and
// distinct NoncePrefix values can validate each other's nonces once each
// node's service is registered with the other, the multi-node correctness
// Params.NonceKey exists for.
func TestNewRestService_SharedNonceKeyValidatesAcrossNodes(t *testing.T) {
	key := make([]byte, nonceKeyLen)
	_, err := rand.Read(key)
	require.NoError(t, err)

	nodeA, err := NewRestService(&Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		Logger:         setupTestLogger(),
		StorageFactory: setupTestStorage(t),
		NonceKey:       key,
		NoncePrefix:    "NODEAAAA",
	})
	require.NoError(t, err)
	serviceA := nodeA.(*RestService)

	nodeB, err := NewRestService(&Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		Logger:         setupTestLogger(),
		StorageFactory: setupTestStorage(t),
		NonceKey:       key,
		NoncePrefix:    "NODEBBBB",
	})
	require.NoError(t, err)
	serviceB := nodeB.(*RestService)

	// Cross-register each node's current epoch with the other, the step a
	// load-balanced deployment's peer discovery would perform.
	serviceA.GetNonceService().Register(serviceB.nonceEpoch.Load())
	serviceB.GetNonceService().Register(serviceA.nonceEpoch.Load())

	nonceFromB, err := serviceB.generateNonce()
	require.NoError(t, err)

	assert.NoError(t, serviceA.redeemNonce(nonceFromB))
}

// TestNewRestService_NonceKeyGeneratedWhenUnset verifies that two
// RestService instances built without a shared Params.NonceKey each get
// their own random key: correct for a single-node deployment, and proof
// that no fallback silently makes nonces portable across nodes without an
// explicit shared key.
func TestNewRestService_NonceKeyGeneratedWhenUnset(t *testing.T) {
	nodeA, err := NewRestService(&Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		Logger:         setupTestLogger(),
		StorageFactory: setupTestStorage(t),
	})
	require.NoError(t, err)
	serviceA := nodeA.(*RestService)

	nodeB, err := NewRestService(&Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		Logger:         setupTestLogger(),
		StorageFactory: setupTestStorage(t),
	})
	require.NoError(t, err)
	serviceB := nodeB.(*RestService)

	assert.NotEqual(t, serviceA.nonceKey, serviceB.nonceKey)
}

// TestNewRestService_NonceDefaults verifies unset NonceLifetime/NonceMaxUsed
// resolve to the documented defaults.
func TestNewRestService_NonceDefaults(t *testing.T) {
	svc, err := NewRestService(&Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		Logger:         setupTestLogger(),
		StorageFactory: setupTestStorage(t),
	})
	require.NoError(t, err)
	service := svc.(*RestService)

	assert.Equal(t, DefaultNonceLifetime, service.nonceLifetime)
	assert.Equal(t, acmenonce.DefaultMaxUsed, service.nonceMaxUsed)
}

// TestNewRestService_InvalidNonceKeyRejected verifies a malformed
// Params.NonceKey (not 16 bytes) fails construction with a typed error
// rather than silently falling back to a generated key.
func TestNewRestService_InvalidNonceKeyRejected(t *testing.T) {
	svc, err := NewRestService(&Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		Logger:         setupTestLogger(),
		StorageFactory: setupTestStorage(t),
		NonceKey:       []byte("too-short"),
	})
	require.Error(t, err)
	assert.Nil(t, svc)
	var initErr *ErrNonceServiceInit
	require.ErrorAs(t, err, &initErr)
	assert.ErrorIs(t, err, ErrNonceServiceCreate)
}
