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

package xkms

import (
	"context"
	"crypto/fips140"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/aeadnonce"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// attachPersistentStore attaches a fresh, memory-backed aeadnonce.Store to
// the process-wide AEAD nonce guard for the life of the calling test, and
// detaches it again on cleanup -- the guard is a package singleton this whole
// binary shares (aead.TestSharedAEADNonceGuardIsOneInstance proves it is one
// instance), so a test that attaches a store and never removes it would leak
// a stale reference into every test that runs after it.
func attachPersistentStore(t *testing.T) *aeadnonce.Store {
	t.Helper()
	guard, err := aead.SharedAEADNonceGuard()
	require.NoError(t, err)

	store, err := aeadnonce.NewStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)

	guard.SetPersistentStore(store)
	t.Cleanup(func() {
		guard.SetPersistentStore(nil)
	})
	return store
}

// simulateGuardRestart forgets everything the shared guard's in-memory
// tracker holds, without touching the attached PersistentNonceStore. That is
// exactly the difference between this guard and the one a fresh process
// would build: a restart draws a new salt and starts its tracker empty, but
// -- by construction, so the store can still be found after one -- neither
// the salt nor the tracker enters into what a PersistentNonceStore claim
// looks like (pkg/crypto/aead's persistentEntry). Clearing the tracker alone
// therefore reproduces a restart's effect on this test's outcome exactly.
func simulateGuardRestart(t *testing.T) {
	t.Helper()
	guard, err := aead.SharedAEADNonceGuard()
	require.NoError(t, err)
	guard.Reset()
}

// TestEncryptRefusesAReusedCallerNonceAfterAGuardRestart is the persistence
// property go-xkms#1201 asked for at the RPC boundary: a caller-supplied
// nonce claimed before a (simulated) restart of the shared guard must still
// be refused after one, because the claim lives in the attached
// PersistentNonceStore rather than only in the guard's in-memory tracker.
func TestEncryptRefusesAReusedCallerNonceAfterAGuardRestart(t *testing.T) {
	if fips140.Enforced() {
		requireCallerNonceEncryptRefusedUnderFIPS(t)
		return
	}

	attachPersistentStore(t)
	store, attrs := newUntrackedAESWrappingBackend(t, "persist-reuse-be", "persist-reuse-key")
	svc := serviceWith(t, store)
	nonce := uniqueNonce(t, aesGCMNonceSize)

	_, err := encryptWithNonce(svc, store.name, attrs.CN, []byte("before restart"), nonce)
	require.NoError(t, err, "the first use of a nonce under a key is legitimate")

	simulateGuardRestart(t)

	_, err = encryptWithNonce(svc, store.name, attrs.CN, []byte("after restart"), nonce)
	require.Error(t, err, "a nonce claimed before the guard restarted must still be refused after one")
	assert.True(t, errors.Is(err, aead.ErrNonceReuse), "got %v", err)
}

// TestEncryptGeneratedNonceRoundTripsThroughDecryptWithPersistence proves the
// happy path is untouched by attaching persistence: a provider-generated
// nonce is still unique, still returned to the caller, and the ciphertext it
// produced still decrypts with it.
func TestEncryptGeneratedNonceRoundTripsThroughDecryptWithPersistence(t *testing.T) {
	attachPersistentStore(t)
	store, attrs := newUntrackedAESWrappingBackend(t, "persist-roundtrip-be", "persist-roundtrip-key")
	svc := serviceWith(t, store)

	plaintext := []byte("round trips through decrypt")
	enc, err := encryptWithNonce(svc, store.name, attrs.CN, plaintext, nil)
	require.NoError(t, err)
	require.NotEmpty(t, enc.Nonce, "the provider must generate and return a nonce")

	dec, err := svc.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend:    store.name,
		KeyID:      attrs.CN,
		Ciphertext: enc.Ciphertext,
		Nonce:      enc.Nonce,
		Tag:        enc.Tag,
	})
	require.NoError(t, err, "decrypt must accept the nonce Encrypt returned")
	assert.Equal(t, plaintext, dec.Plaintext)
}

// TestEncryptAdmitsExactlyOneOfConcurrentSameNonceCallsWithPersistence is the
// race TestEncryptAdmitsExactlyOneOfConcurrentSameNonceCalls already covers
// for the in-memory tracker alone, repeated with a PersistentNonceStore
// attached: every claim now also round-trips through the claim DAO's\n// SaveIfAbsent, and exactly one caller must still win.
func TestEncryptAdmitsExactlyOneOfConcurrentSameNonceCallsWithPersistence(t *testing.T) {
	if fips140.Enforced() {
		requireCallerNonceEncryptRefusedUnderFIPS(t)
		return
	}

	attachPersistentStore(t)
	store, attrs := newUntrackedAESWrappingBackend(t, "persist-race-be", "persist-race-key")
	svc := serviceWith(t, store)
	nonce := uniqueNonce(t, aesGCMNonceSize)

	const callers = 32
	var succeeded, refused atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := encryptWithNonce(svc, store.name, attrs.CN, []byte("racing"), nonce)
			switch {
			case err == nil:
				succeeded.Add(1)
			case errors.Is(err, aead.ErrNonceReuse):
				refused.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	assert.Equal(t, int32(1), succeeded.Load(), "exactly one caller may consume the pair")
	assert.Equal(t, int32(callers-1), refused.Load(), "every other caller is refused as a reuse")
}
