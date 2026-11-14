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

package token

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test doubles for the qrdb KV plane.
// ---------------------------------------------------------------------------

// kvNotFoundError mimics the qrdb SDK's typed missing-key error.
type kvNotFoundError struct{ key string }

func (e *kvNotFoundError) Error() string  { return "key not found: " + e.key }
func (e *kvNotFoundError) NotFound() bool { return true }

// guardedMemoryKV is a linearizable in-memory stand-in for the qrdb KV plane.
// Every operation completes under one mutex, which is precisely the guarantee
// the real guarded verbs obtain from Raft: the condition and the write are
// evaluated as a single indivisible step in the state machine. A test double
// that did not serialize them would be testing a store weaker than production.
type guardedMemoryKV struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newGuardedMemoryKV() *guardedMemoryKV {
	return &guardedMemoryKV{data: make(map[string][]byte)}
}

var _ qrdbtransport.GuardedKVClient = (*guardedMemoryKV)(nil)

// clone copies a value so no caller shares the store's backing array.
func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp
}

func (k *guardedMemoryKV) Put(_ context.Context, key string, value []byte, _ ...qrdbtransport.WriteOption) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.data[key] = clone(value)
	return nil
}

func (k *guardedMemoryKV) Get(_ context.Context, key string, _ ...qrdbtransport.ReadOption) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.data[key]
	if !ok {
		return nil, &kvNotFoundError{key: key}
	}
	return clone(v), nil
}

func (k *guardedMemoryKV) Delete(_ context.Context, key string, _ ...qrdbtransport.WriteOption) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.data, key)
	return nil
}

func (k *guardedMemoryKV) List(_ context.Context, prefix string, _ ...qrdbtransport.ReadOption) ([]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	keys := make([]string, 0, len(k.data))
	for key := range k.data {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func (k *guardedMemoryKV) Scan(_ context.Context, prefix string, _ ...qrdbtransport.ReadOption) (map[string][]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make(map[string][]byte)
	for key, v := range k.data {
		if strings.HasPrefix(key, prefix) {
			out[key] = clone(v)
		}
	}
	return out, nil
}

func (k *guardedMemoryKV) Exists(_ context.Context, key string, _ ...qrdbtransport.ReadOption) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	_, ok := k.data[key]
	return ok, nil
}

func (k *guardedMemoryKV) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.data[key]; ok {
		return false, nil
	}
	k.data[key] = clone(value)
	return true, nil
}

func (k *guardedMemoryKV) CompareAndDelete(_ context.Context, key string, expected []byte) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	cur, ok := k.data[key]
	if !ok || string(cur) != string(expected) {
		return false, nil
	}
	delete(k.data, key)
	return true, nil
}

func (k *guardedMemoryKV) CompareAndSwap(_ context.Context, key string, expected, next []byte) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	cur, ok := k.data[key]
	if !ok || string(cur) != string(expected) {
		return false, nil
	}
	k.data[key] = clone(next)
	return true, nil
}

// plainMemoryKV exposes only the unguarded KVClient surface. It stands for a
// transport whose wire contract does not carry the conditional-write verbs.
type plainMemoryKV struct{ inner *guardedMemoryKV }

func newPlainMemoryKV() *plainMemoryKV { return &plainMemoryKV{inner: newGuardedMemoryKV()} }

var _ qrdbtransport.KVClient = (*plainMemoryKV)(nil)

func (p *plainMemoryKV) Put(ctx context.Context, key string, value []byte, opts ...qrdbtransport.WriteOption) error {
	return p.inner.Put(ctx, key, value, opts...)
}

func (p *plainMemoryKV) Get(ctx context.Context, key string, opts ...qrdbtransport.ReadOption) ([]byte, error) {
	return p.inner.Get(ctx, key, opts...)
}

func (p *plainMemoryKV) Delete(ctx context.Context, key string, opts ...qrdbtransport.WriteOption) error {
	return p.inner.Delete(ctx, key, opts...)
}

func (p *plainMemoryKV) List(ctx context.Context, prefix string, opts ...qrdbtransport.ReadOption) ([]string, error) {
	return p.inner.List(ctx, prefix, opts...)
}

func (p *plainMemoryKV) Scan(ctx context.Context, prefix string, opts ...qrdbtransport.ReadOption) (map[string][]byte, error) {
	return p.inner.Scan(ctx, prefix, opts...)
}

func (p *plainMemoryKV) Exists(ctx context.Context, key string, opts ...qrdbtransport.ReadOption) (bool, error) {
	return p.inner.Exists(ctx, key, opts...)
}

// ---------------------------------------------------------------------------
// Store matrix
// ---------------------------------------------------------------------------

// storeCase names one RefreshStore implementation. Every atomicity property
// below is asserted against both, because the issuer cannot tell them apart.
type storeCase struct {
	name     string
	newStore func(t *testing.T) RefreshStore
}

func refreshStoreCases() []storeCase {
	return []storeCase{
		{
			name: "memory",
			newStore: func(*testing.T) RefreshStore {
				return NewMemoryRefreshStore()
			},
		},
		{
			name: "qrdb",
			newStore: func(t *testing.T) RefreshStore {
				t.Helper()
				store, err := NewQRDBRefreshStore(newGuardedMemoryKV())
				require.NoError(t, err)
				return store
			},
		},
	}
}

// newIssuerWithStore builds an issuer over the given refresh store.
func newIssuerWithStore(t *testing.T, store RefreshStore) *Issuer {
	t.Helper()
	return newTestIssuer(t, func(c *Config) { c.RefreshStore = store })
}

// ---------------------------------------------------------------------------
// Construction: a store that cannot do conditional writes must not be built.
// ---------------------------------------------------------------------------

func TestNewQRDBRefreshStore_RejectsUnguardedKV(t *testing.T) {
	store, err := NewQRDBRefreshStore(newPlainMemoryKV())

	require.Nil(t, store, "an unguarded transport must not yield a store")
	var unsupported *GuardedKVUnsupportedError
	require.ErrorAs(t, err, &unsupported)
	assert.Contains(t, unsupported.ClientType, "plainMemoryKV")
}

func TestNewQRDBRefreshStore_AcceptsGuardedKV(t *testing.T) {
	store, err := NewQRDBRefreshStore(newGuardedMemoryKV())

	require.NoError(t, err)
	require.NotNil(t, store)
}

func TestNewQRDBRefreshStore_NilKV(t *testing.T) {
	store, err := NewQRDBRefreshStore(nil)

	require.Nil(t, store)
	var nilErr *NilInputError
	require.ErrorAs(t, err, &nilErr)
}

func TestNewIssuer_RejectsRefreshTTLBeyondTombstoneWindow(t *testing.T) {
	_, err := NewIssuer(&Config{
		Signer:        newTestIssuer(t).signer,
		KeyAttributes: testKeyAttrs(),
		RefreshStore:  NewMemoryRefreshStore(),
		RefreshTTL:    RevocationTombstoneTTL + time.Hour,
	})

	var ttlErr *RefreshTTLTooLongError
	require.ErrorAs(t, err, &ttlErr)
	assert.Equal(t, RevocationTombstoneTTL, ttlErr.Max)
}

// ---------------------------------------------------------------------------
// MarkRotated is a compare-and-swap.
// ---------------------------------------------------------------------------

func TestMarkRotated_MissingRecord(t *testing.T) {
	for _, tc := range refreshStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.newStore(t)

			err := store.MarkRotated(context.Background(), "no-such-family", "no-such-jti")

			var revoked *RefreshRevokedError
			require.ErrorAs(t, err, &revoked,
				"rotating a record that is not there must fail closed, not report success")
		})
	}
}

func TestMarkRotated_AlreadyRotated(t *testing.T) {
	for _, tc := range refreshStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.newStore(t)
			rec := &Record{
				JTI:       "jti-1",
				Family:    "fam-1",
				Subject:   "user-1",
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
			}
			require.NoError(t, store.Save(ctx, rec))
			require.NoError(t, store.MarkRotated(ctx, "fam-1", "jti-1"))

			err := store.MarkRotated(ctx, "fam-1", "jti-1")

			var lost *RefreshRaceLostError
			require.ErrorAs(t, err, &lost)
			assert.Equal(t, "fam-1", lost.Family)
			assert.Equal(t, "jti-1", lost.JTI)
		})
	}
}

func TestMarkRotated_ConcurrentCallersElectOneWinner(t *testing.T) {
	for _, tc := range refreshStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.newStore(t)
			require.NoError(t, store.Save(ctx, &Record{
				JTI:       "jti-1",
				Family:    "fam-1",
				Subject:   "user-1",
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
			}))

			const workers = 32
			var (
				start sync.WaitGroup
				done  sync.WaitGroup
				mu    sync.Mutex
				wins  int
			)
			start.Add(1)
			for i := 0; i < workers; i++ {
				done.Add(1)
				go func() {
					defer done.Done()
					start.Wait()
					if err := store.MarkRotated(ctx, "fam-1", "jti-1"); err == nil {
						mu.Lock()
						wins++
						mu.Unlock()
					}
				}()
			}
			start.Done()
			done.Wait()

			assert.Equal(t, 1, wins,
				"exactly one concurrent rotation may win the compare-and-swap")
		})
	}
}

// ---------------------------------------------------------------------------
// Refresh: N concurrent refreshes of one token yield exactly one successor.
// ---------------------------------------------------------------------------

// TestRefresh_ConcurrentRefreshesNeverMintTwoSuccessors is the regression test
// for the rotation race. The load-bearing invariant is that a refresh token is
// single-use: a burst of concurrent exchanges may mint AT MOST one successor.
//
// It is at most one rather than exactly one because the losers of the race
// observe an already-rotated token, which is the reuse signal, and reuse
// revokes the whole family — the pre-existing anti-theft policy, unchanged
// here. A burst therefore settles on either one successor or a revoked family,
// never on two live lineages, which is what the defect produced.
func TestRefresh_ConcurrentRefreshesNeverMintTwoSuccessors(t *testing.T) {
	for _, tc := range refreshStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			issuer := newIssuerWithStore(t, tc.newStore(t))

			original, err := issuer.Mint(ctx, testIdentity())
			require.NoError(t, err)

			const workers = 16
			var (
				start     sync.WaitGroup
				done      sync.WaitGroup
				mu        sync.Mutex
				successes []*Pair
				failures  []error
			)
			start.Add(1)
			for i := 0; i < workers; i++ {
				done.Add(1)
				go func() {
					defer done.Done()
					start.Wait()
					pair, refreshErr := issuer.Refresh(ctx, original.RefreshToken)
					mu.Lock()
					defer mu.Unlock()
					if refreshErr != nil {
						failures = append(failures, refreshErr)
						return
					}
					successes = append(successes, pair)
				}()
			}
			start.Done()
			done.Wait()

			require.LessOrEqual(t, len(successes), 1,
				"a refresh token is single-use: concurrent exchanges must never mint two successors")
			require.Len(t, failures, workers-len(successes))
			for _, failure := range failures {
				var (
					lost    *RefreshRaceLostError
					reuse   *RefreshReuseError
					revoked *RefreshRevokedError
					famDead *FamilyRevokedError
				)
				// FamilyRevokedError belongs here: a caller can win the
				// compare-and-swap and still be refused at commit time because
				// another loser's reuse detection revoked the family first.
				typed := errors.As(failure, &lost) ||
					errors.As(failure, &reuse) ||
					errors.As(failure, &revoked) ||
					errors.As(failure, &famDead)
				assert.True(t, typed,
					"losing refreshes must fail with a typed rotation error, got %T: %v", failure, failure)
			}

			// The original is spent either way: it was rotated, or its family
			// was revoked underneath it.
			_, err = issuer.Refresh(ctx, original.RefreshToken)
			require.Error(t, err, "the exchanged token must never be usable again")
		})
	}
}

// TestRefresh_SequentialRotationYieldsOneUsableSuccessor pins the happy path
// the race test cannot: one exchange at a time mints a working successor and
// spends its predecessor, and replaying the spent token is reuse, which
// revokes the family and takes the successor down with it.
func TestRefresh_SequentialRotationYieldsOneUsableSuccessor(t *testing.T) {
	for _, tc := range refreshStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			issuer := newIssuerWithStore(t, tc.newStore(t))

			original, err := issuer.Mint(ctx, testIdentity())
			require.NoError(t, err)

			successor, err := issuer.Refresh(ctx, original.RefreshToken)
			require.NoError(t, err)
			require.NotEmpty(t, successor.RefreshToken)

			// The successor is a working refresh token.
			third, err := issuer.Refresh(ctx, successor.RefreshToken)
			require.NoError(t, err)
			require.NotEmpty(t, third.RefreshToken)

			// Replaying the spent original is theft: the family dies.
			_, err = issuer.Refresh(ctx, original.RefreshToken)
			var reuse *RefreshReuseError
			require.ErrorAs(t, err, &reuse)

			_, err = issuer.Refresh(ctx, third.RefreshToken)
			require.Error(t, err,
				"reuse of an ancestor must revoke the whole lineage, including live successors")
		})
	}
}

// ---------------------------------------------------------------------------
// Refresh racing RevokeFamily must never leave a usable successor.
// ---------------------------------------------------------------------------

func TestRefresh_RacingRevokeFamilyLeavesNoUsableSuccessor(t *testing.T) {
	for _, tc := range refreshStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			// Repeated so the two goroutines interleave both ways: the revoke
			// landing before the successor is written, and after.
			const rounds = 64
			for round := 0; round < rounds; round++ {
				issuer := newIssuerWithStore(t, tc.newStore(t))

				original, err := issuer.Mint(ctx, testIdentity())
				require.NoError(t, err)

				var (
					start     sync.WaitGroup
					done      sync.WaitGroup
					successor *Pair
				)
				start.Add(1)
				done.Add(2)
				go func() {
					defer done.Done()
					start.Wait()
					successor, _ = issuer.Refresh(ctx, original.RefreshToken) // the race outcome is the assertion below
				}()
				go func() {
					defer done.Done()
					start.Wait()
					_ = issuer.Revoke(ctx, original.RefreshToken) // revoke is idempotent; the assertion is on the successor
				}()
				start.Done()
				done.Wait()

				if successor == nil {
					continue
				}
				_, err = issuer.Refresh(ctx, successor.RefreshToken)
				require.Error(t, err,
					"round %d: a successor committed into a revoked family must not be usable", round)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// A revoked family refuses new records outright.
// ---------------------------------------------------------------------------

func TestSave_IntoRevokedFamily(t *testing.T) {
	for _, tc := range refreshStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.newStore(t)
			require.NoError(t, store.RevokeFamily(ctx, "fam-1"))

			err := store.Save(ctx, &Record{
				JTI:       "jti-successor",
				Family:    "fam-1",
				Subject:   "user-1",
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
			})

			var revoked *FamilyRevokedError
			require.ErrorAs(t, err, &revoked)
			assert.Equal(t, "fam-1", revoked.Family)

			got, err := store.Get(ctx, "fam-1", "jti-successor")
			require.NoError(t, err)
			assert.Nil(t, got, "a rejected successor must leave no record behind")
		})
	}
}

func TestSave_NilRecord(t *testing.T) {
	for _, tc := range refreshStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.newStore(t).Save(context.Background(), nil)

			var nilErr *NilInputError
			require.ErrorAs(t, err, &nilErr)
		})
	}
}

func TestRevokeFamily_IsIdempotent(t *testing.T) {
	for _, tc := range refreshStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.newStore(t)

			require.NoError(t, store.RevokeFamily(ctx, "fam-1"))
			require.NoError(t, store.RevokeFamily(ctx, "fam-1"),
				"logout must stay idempotent after the tombstone exists")
		})
	}
}

// ---------------------------------------------------------------------------
// RevokeBySubject (go-xkms#1297): a user-lifecycle change ends every
// session the account holds, and no other account's.
// ---------------------------------------------------------------------------

func TestRevokeBySubject_RevokesEveryFamilyForSubjectAndNoOther(t *testing.T) {
	for _, tc := range refreshStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.newStore(t)

			// alice holds two families (e.g. two browser sessions); bob holds
			// one. Revoking alice must not touch bob's.
			require.NoError(t, store.Save(ctx, &Record{
				JTI: "jti-1", Family: "fam-alice-1", Subject: "alice",
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
			}))
			require.NoError(t, store.Save(ctx, &Record{
				JTI: "jti-2", Family: "fam-alice-2", Subject: "alice",
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
			}))
			require.NoError(t, store.Save(ctx, &Record{
				JTI: "jti-3", Family: "fam-bob-1", Subject: "bob",
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
			}))

			require.NoError(t, store.RevokeBySubject(ctx, "", "alice"))

			got1, err := store.Get(ctx, "fam-alice-1", "jti-1")
			require.NoError(t, err)
			assert.Nil(t, got1, "alice's first family must be revoked")

			got2, err := store.Get(ctx, "fam-alice-2", "jti-2")
			require.NoError(t, err)
			assert.Nil(t, got2, "alice's second family must be revoked")

			got3, err := store.Get(ctx, "fam-bob-1", "jti-3")
			require.NoError(t, err)
			require.NotNil(t, got3, "bob's family must survive alice's revocation")
			assert.Equal(t, "bob", got3.Subject)

			// A successor can no longer be minted into either of alice's
			// families -- exactly RevokeFamily's own tombstone guarantee.
			err = store.Save(ctx, &Record{
				JTI: "jti-successor", Family: "fam-alice-1", Subject: "alice",
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
			})
			var revoked *FamilyRevokedError
			assert.ErrorAs(t, err, &revoked)
		})
	}
}

func TestRevokeBySubject_NoFamiliesIsANoop(t *testing.T) {
	for _, tc := range refreshStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.newStore(t)
			require.NoError(t, store.RevokeBySubject(context.Background(), "", "nobody"))
		})
	}
}

// TestRevokeBySubject_IssuerIntegration proves the Issuer-level convenience
// method (used by pkg/xkms's DisableUser/DeleteUser) reaches the store and
// ends a session a refresh token was already minted for.
func TestRevokeBySubject_IssuerIntegration(t *testing.T) {
	for _, tc := range refreshStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			issuer := newIssuerWithStore(t, tc.newStore(t))

			pair, err := issuer.Mint(ctx, testIdentity())
			require.NoError(t, err)

			require.NoError(t, issuer.RevokeBySubject(ctx, testIdentity().TenantID, testIdentity().Subject))

			_, err = issuer.Refresh(ctx, pair.RefreshToken)
			var revokedErr *RefreshRevokedError
			assert.ErrorAs(t, err, &revokedErr)
		})
	}
}

// Every tenant's sessions share one record namespace, and account names are
// unique only within a tenant: revoking system/alice must leave acme/alice's
// sessions alone.
func TestRevokeBySubject_LeavesAnotherTenantsNamesakeSessions(t *testing.T) {
	for _, tc := range refreshStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			issuer := newIssuerWithStore(t, tc.newStore(t))

			systemAlice := testIdentity()
			systemAlice.Subject = "alice"
			systemAlice.TenantID = "default"
			acmeAlice := testIdentity()
			acmeAlice.Subject = "alice"
			acmeAlice.TenantID = "acme"

			systemPair, err := issuer.Mint(ctx, systemAlice)
			require.NoError(t, err)
			acmePair, err := issuer.Mint(ctx, acmeAlice)
			require.NoError(t, err)

			require.NoError(t, issuer.RevokeBySubject(ctx, "default", "alice"))

			_, err = issuer.Refresh(ctx, systemPair.RefreshToken)
			var revokedErr *RefreshRevokedError
			require.ErrorAs(t, err, &revokedErr, "the revoked account's session ends")
			_, err = issuer.Refresh(ctx, acmePair.RefreshToken)
			require.NoError(t, err, "acme's alice keeps her session")
		})
	}
}
