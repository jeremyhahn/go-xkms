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

package module

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// This file pins the PIN lockout to the token's shared, durable counter rather
// than to any one process's copy of it (#1144).
//
// Two Module values over one backend model two processes that opened the same
// file or remote token: each builds its own SessionManagers with their own
// in-memory counters, so anything one of them enforces against the other it
// must have read from the store at the moment of the attempt.

const (
	ledgerTestUserPIN = "user-pin-1234"
	ledgerTestSOPIN   = "so-pin-1234"
	ledgerWrongPIN    = "wrong-pin-9999"
)

// countDerivations counts every Argon2id PIN derivation that starts while the
// test runs. A derivation is exactly what the lockout exists to ration, so this
// is the direct measure of how many guesses were actually checked.
func countDerivations(t *testing.T) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	original := pinDerivationBegan
	t.Cleanup(func() { pinDerivationBegan = original })
	pinDerivationBegan = func() { n.Add(1) }
	return &n
}

// provisionedSharedToken provisions a token in backend and returns the module
// that did it plus a second, independently initialized module over the same
// backend. Neither is logged in.
func provisionedSharedToken(t *testing.T, backend storage.Backend) (*Module, *Module) {
	t.Helper()
	first := newPersistentTestModule(t, backend)
	session := loginAsNormalUser(t, first)
	require.Equal(t, CKR_OK, first.Logout(session))
	require.Equal(t, CKR_OK, first.CloseSession(session))

	second := newPersistentTestModule(t, backend)
	return first, second
}

// rwSession opens a read-write session on slot 0. The SO cannot log in while a
// read-only session is open, so every session these tests use is read-write.
func rwSession(t *testing.T, m *Module) SessionHandle {
	t.Helper()
	session, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	return session
}

// durableAttempts reads slot 0's durable counter for userType through a fresh
// ModuleStorage, bypassing both modules' caches.
func durableAttempts(t *testing.T, backend storage.Backend, userType UserType) uint32 {
	t.Helper()
	user, so, err := NewModuleStorage(backend).LoadFailedAttempts(0)
	require.NoError(t, err)
	if userType == CKU_SO {
		return so
	}
	return user
}

// ledgerCase parameterizes the cross-process tests over the two budgeted PINs.
type ledgerCase struct {
	name     string
	userType UserType
	pin      string
}

var ledgerCases = []ledgerCase{
	{name: "user", userType: CKU_USER, pin: ledgerTestUserPIN},
	{name: "so", userType: CKU_SO, pin: ledgerTestSOPIN},
}

// TestPINLedger_BudgetIsSharedAcrossInstances: three wrong guesses in total,
// split across two instances, lock the token for both. Before #1144 each
// instance enforced its own in-memory count, so each got the full budget.
func TestPINLedger_BudgetIsSharedAcrossInstances(t *testing.T) {
	for _, tc := range ledgerCases {
		t.Run(tc.name, func(t *testing.T) {
			backend := storage.NewMemory()
			a, b := provisionedSharedToken(t, backend)
			defer b.Finalize()
			sa, sb := rwSession(t, a), rwSession(t, b)

			require.Equal(t, CKR_PIN_INCORRECT, a.Login(sa, tc.userType, []byte(ledgerWrongPIN)))
			require.Equal(t, CKR_PIN_INCORRECT, b.Login(sb, tc.userType, []byte(ledgerWrongPIN)))
			require.Equal(t, CKR_PIN_LOCKED, a.Login(sa, tc.userType, []byte(ledgerWrongPIN)),
				"the third wrong guess across both instances must lock the token")

			derivations := countDerivations(t)
			assert.Equal(t, CKR_PIN_LOCKED, b.Login(sb, tc.userType, []byte(tc.pin)),
				"an instance that saw only one failure must still honor the shared lock")
			assert.Equal(t, CKR_PIN_LOCKED, a.Login(sa, tc.userType, []byte(tc.pin)))
			assert.Zero(t, derivations.Load(), "a locked token must refuse before deriving")
			assert.Equal(t, uint32(MaxPINAttempts), durableAttempts(t, backend, tc.userType))
		})
	}
}

// TestPINLedger_StaleInstanceCannotLogInOrClearLock is the second half of the
// finding: an instance whose cached counter still reads zero must not verify
// the correct PIN, and so must not reset the counter, once the durable counter
// reads LOCKED.
func TestPINLedger_StaleInstanceCannotLogInOrClearLock(t *testing.T) {
	for _, tc := range ledgerCases {
		t.Run(tc.name, func(t *testing.T) {
			backend := storage.NewMemory()
			a, stale := provisionedSharedToken(t, backend)
			defer stale.Finalize()
			sa, sStale := rwSession(t, a), rwSession(t, stale)

			for i := 0; i < MaxPINAttempts; i++ {
				a.Login(sa, tc.userType, []byte(ledgerWrongPIN))
			}
			require.Equal(t, uint32(MaxPINAttempts), durableAttempts(t, backend, tc.userType))

			failed, locked := stale.sessionManagers[0].PINAttemptStatus(tc.userType)
			require.Zero(t, failed, "precondition: the stale instance's cache has not seen the failures")
			require.False(t, locked)

			assert.Equal(t, CKR_PIN_LOCKED, stale.Login(sStale, tc.userType, []byte(tc.pin)),
				"a stale instance must not verify the correct PIN against a locked token")
			assert.Equal(t, uint32(MaxPINAttempts), durableAttempts(t, backend, tc.userType),
				"a stale instance must not clear the lock")
			assert.Equal(t, CKR_PIN_LOCKED, a.Login(sa, tc.userType, []byte(tc.pin)),
				"the lock must still hold for every instance")

			_, locked = stale.sessionManagers[0].PINAttemptStatus(tc.userType)
			assert.True(t, locked, "the refused attempt must refresh the stale instance's cache")
		})
	}
}

// TestPINLedger_ConcurrentGuessesNeverExceedBudget races wrong guesses from two
// instances and asserts no more than MaxPINAttempts of them were ever checked.
// Within one Module C_Login is serialized by Module.mu; across instances only
// the durable spend serializes them.
func TestPINLedger_ConcurrentGuessesNeverExceedBudget(t *testing.T) {
	for _, tc := range ledgerCases {
		t.Run(tc.name, func(t *testing.T) {
			backend := storage.NewMemory()
			a, b := provisionedSharedToken(t, backend)
			defer b.Finalize()

			derivations := countDerivations(t)
			const guessersPerInstance = 3
			const guessesEach = 3
			var incorrect atomic.Int32
			var wg sync.WaitGroup
			for _, m := range []*Module{a, b} {
				session := rwSession(t, m)
				for g := 0; g < guessersPerInstance; g++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for i := 0; i < guessesEach; i++ {
							switch rv := m.Login(session, tc.userType, []byte(ledgerWrongPIN)); rv {
							case CKR_PIN_INCORRECT:
								incorrect.Add(1)
							case CKR_PIN_LOCKED:
							default:
								t.Errorf("unexpected CK_RV %v for a wrong guess", rv)
							}
						}
					}()
				}
			}
			wg.Wait()

			assert.Equal(t, int32(MaxPINAttempts), derivations.Load(),
				"exactly MaxPINAttempts guesses may be checked across every instance")
			assert.Equal(t, int32(MaxPINAttempts-1), incorrect.Load(),
				"every checked guess but the last reports CKR_PIN_INCORRECT; the last locks")
			assert.Equal(t, uint32(MaxPINAttempts), durableAttempts(t, backend, tc.userType))
		})
	}
}

// TestPINLedger_CorrectPINResetsSharedBudget: a success on one instance clears
// the failures another instance charged, so the budget is consecutive failures
// across the token, not a lifetime total.
func TestPINLedger_CorrectPINResetsSharedBudget(t *testing.T) {
	for _, tc := range ledgerCases {
		t.Run(tc.name, func(t *testing.T) {
			backend := storage.NewMemory()
			a, b := provisionedSharedToken(t, backend)
			defer b.Finalize()
			sa, sb := rwSession(t, a), rwSession(t, b)

			for i := 0; i < MaxPINAttempts-1; i++ {
				require.Equal(t, CKR_PIN_INCORRECT, a.Login(sa, tc.userType, []byte(ledgerWrongPIN)))
			}
			require.Equal(t, CKR_OK, b.Login(sb, tc.userType, []byte(tc.pin)))
			require.Equal(t, CKR_OK, b.Logout(sb))
			assert.Zero(t, durableAttempts(t, backend, tc.userType), "a correct PIN must reset the shared counter")

			for i := 0; i < MaxPINAttempts-1; i++ {
				assert.Equal(t, CKR_PIN_INCORRECT, a.Login(sa, tc.userType, []byte(ledgerWrongPIN)),
					"the reset budget must be visible to the other instance")
			}
		})
	}
}

// ledgerFaultBackend is a compare-and-swap-capable backend whose guarded verbs
// can be made to fail after a set number of successes, so a test can fail the
// spend or, separately, the refund that follows a successful spend.
type ledgerFaultBackend struct {
	storage.Backend
	failAfter atomic.Int32 // guarded calls still allowed; negative = never fail
}

var errInjectedLedger = errors.New("injected ledger failure")

func newLedgerFaultBackend() *ledgerFaultBackend {
	b := &ledgerFaultBackend{Backend: storage.NewMemory()}
	b.failAfter.Store(-1)
	return b
}

func (b *ledgerFaultBackend) allow() bool {
	for {
		n := b.failAfter.Load()
		if n < 0 {
			return true
		}
		if n == 0 {
			return false
		}
		if b.failAfter.CompareAndSwap(n, n-1) {
			return true
		}
	}
}

func (b *ledgerFaultBackend) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if !b.allow() {
		return false, errInjectedLedger
	}
	return b.Backend.PutIfAbsent(ctx, key, value)
}

func (b *ledgerFaultBackend) CompareAndSwap(ctx context.Context, key string, expected, newValue []byte) (bool, []byte, error) {
	if !b.allow() {
		return false, nil, errInjectedLedger
	}
	return b.Backend.(storage.CompareAndSwapper).CompareAndSwap(ctx, key, expected, newValue)
}

// TestPINLedger_StoreErrorFailsClosed: when the durable counter cannot be
// charged, or cannot be settled after a correct PIN, the login is refused with
// CKR_DEVICE_ERROR and nothing is granted.
func TestPINLedger_StoreErrorFailsClosed(t *testing.T) {
	for _, tc := range ledgerCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, phase := range []struct {
				name      string
				failAfter int32
			}{
				{name: "spend", failAfter: 0},
				{name: "refund", failAfter: 1},
			} {
				t.Run(phase.name, func(t *testing.T) {
					backend := newLedgerFaultBackend()
					m := newPersistentTestModule(t, backend)
					defer m.Finalize()
					provision := loginAsNormalUser(t, m)
					require.Equal(t, CKR_OK, m.Logout(provision))
					session := rwSession(t, m)

					backend.failAfter.Store(phase.failAfter)
					assert.Equal(t, CKR_DEVICE_ERROR, m.Login(session, tc.userType, []byte(tc.pin)),
						"an unknown budget must fail closed, even for the correct PIN")
					assert.ErrorIs(t, m.LastStorageError(), errInjectedLedger,
						"the cause must be recorded for the operator")

					info, rv := m.GetSessionInfo(session)
					require.Equal(t, CKR_OK, rv)
					assert.Equal(t, CKS_RW_PUBLIC_SESSION, info.State, "nothing may be granted")

					backend.failAfter.Store(-1)
					assert.Equal(t, CKR_OK, m.Login(session, tc.userType, []byte(tc.pin)),
						"once the store answers again the correct PIN must work")
				})
			}
		})
	}
}

// stubLedger is an AttemptLedger whose answers a SessionManager test sets
// directly.
type stubLedger struct {
	count    uint32
	admitted bool
	err      error
	refunds  []uint32
}

func (l *stubLedger) Spend(UserType, uint32) (uint32, bool, error) {
	return l.count, l.admitted, l.err
}

func (l *stubLedger) Refund(_ UserType, spent uint32) (uint32, error) {
	l.refunds = append(l.refunds, spent)
	return 0, l.err
}

func (l *stubLedger) Reset(UserType) error { return l.err }

// TestSessionManager_LedgerIsAuthoritative pins that the ledger, not the
// in-memory counter, decides: a refusal locks even with a zero cache, an
// admission derives even with a cache that reads locked, and a ledger error
// fails closed.
func TestSessionManager_LedgerIsAuthoritative(t *testing.T) {
	newManager := func(t *testing.T, ledger AttemptLedger) (*SessionManager, SessionHandle) {
		t.Helper()
		m := NewSessionManager(0, 0)
		m.SetUserPIN(mustHashPin(ledgerTestUserPIN))
		m.SetAttemptLedger(ledger)
		handle, err := m.OpenSession(CKF_SERIAL_SESSION | CKF_RW_SESSION)
		require.NoError(t, err)
		return m, handle
	}

	t.Run("refusal locks regardless of cache", func(t *testing.T) {
		m, handle := newManager(t, &stubLedger{count: MaxPINAttempts, admitted: false})
		err := m.Login(handle, CKU_USER, []byte(ledgerTestUserPIN))
		require.ErrorIs(t, err, NewPKCS11Error(CKR_PIN_LOCKED))
	})

	t.Run("admission verifies regardless of cache", func(t *testing.T) {
		ledger := &stubLedger{count: 1, admitted: true}
		m, handle := newManager(t, ledger)
		m.RestorePINAttempts(MaxPINAttempts, 0) // a stale cache reading LOCKED
		require.NoError(t, m.Login(handle, CKU_USER, []byte(ledgerTestUserPIN)))
		assert.Equal(t, []uint32{1}, ledger.refunds, "a correct PIN refunds the attempt it spent")
		failed, locked := m.PINAttemptStatus(CKU_USER)
		assert.Zero(t, failed, "the cache follows the ledger")
		assert.False(t, locked)
	})

	t.Run("spend error fails closed", func(t *testing.T) {
		m, handle := newManager(t, &stubLedger{err: errInjectedLedger})
		err := m.Login(handle, CKU_USER, []byte(ledgerTestUserPIN))
		require.ErrorIs(t, err, NewPKCS11Error(CKR_DEVICE_ERROR))
		require.ErrorIs(t, err, errInjectedLedger)
		assert.Equal(t, loginStateNone, m.loginState.Load())
	})

	t.Run("reset error is reported", func(t *testing.T) {
		m, _ := newManager(t, &stubLedger{err: errInjectedLedger})
		err := m.ResetPINAttempts(CKU_USER)
		require.ErrorIs(t, err, NewPKCS11Error(CKR_DEVICE_ERROR))
		require.ErrorIs(t, err, errInjectedLedger)
	})
}

// TestSessionManager_InMemoryBudgetSpendsBeforeVerifying covers the store-less
// path: the in-memory counter is the budget, spent before the derivation.
func TestSessionManager_InMemoryBudgetSpendsBeforeVerifying(t *testing.T) {
	m := NewSessionManager(0, 0)
	m.SetSOPIN(mustHashPin(ledgerTestSOPIN))
	handle, err := m.OpenSession(CKF_SERIAL_SESSION | CKF_RW_SESSION)
	require.NoError(t, err)

	for i := 0; i < MaxPINAttempts-1; i++ {
		require.ErrorIs(t, m.Login(handle, CKU_SO, []byte(ledgerWrongPIN)), NewPKCS11Error(CKR_PIN_INCORRECT))
	}
	require.NoError(t, m.Login(handle, CKU_SO, []byte(ledgerTestSOPIN)))
	failed, _ := m.PINAttemptStatus(CKU_SO)
	assert.Zero(t, failed, "an uncontended success resets the budget")
	require.NoError(t, m.Logout(handle))

	for i := 0; i < MaxPINAttempts-1; i++ {
		require.ErrorIs(t, m.Login(handle, CKU_SO, []byte(ledgerWrongPIN)), NewPKCS11Error(CKR_PIN_INCORRECT))
	}
	require.ErrorIs(t, m.Login(handle, CKU_SO, []byte{}), NewPKCS11Error(CKR_PIN_LOCKED),
		"an empty PIN is a charged wrong guess")

	derivations := countDerivations(t)
	require.ErrorIs(t, m.Login(handle, CKU_SO, []byte(ledgerTestSOPIN)), NewPKCS11Error(CKR_PIN_LOCKED))
	assert.Zero(t, derivations.Load(), "a locked budget refuses before deriving")
}

// TestRefundedCount pins the refund rule each ledger applies.
func TestRefundedCount(t *testing.T) {
	cases := []struct {
		name           string
		current, spent uint32
		want           uint32
	}{
		{name: "untouched since the spend resets", current: 2, spent: 2, want: 0},
		{name: "later charges keep their share", current: 3, spent: 1, want: 2},
		{name: "reset underneath is left alone", current: 1, spent: 2, want: 1},
		{name: "already zero stays zero", current: 0, spent: 1, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, refundedCount(tc.current, tc.spent))
		})
	}
}
