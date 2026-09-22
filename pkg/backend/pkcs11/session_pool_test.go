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

//go:build pkcs11

package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/internal/softhsmtest"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
)

// newTestPool opens an independent session pool on the backend's token. Tests
// that close a pool use this rather than the backend's own pool so that the
// backend stays usable for cleanup.
func newTestPool(t *testing.T, b *Backend, size int) *SessionPool {
	t.Helper()

	slot, err := b.resolveSlot()
	require.NoError(t, err)

	pool, err := NewSessionPool(b.p11ctx, slot, b.config.PIN, size)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	return pool
}

// TestNewSessionPool_NilContext verifies the constructor rejects a nil PKCS#11
// context instead of panicking on the first OpenSession call.
func TestNewSessionPool_NilContext(t *testing.T) {
	pool, err := NewSessionPool(nil, 0, "1234", 4)
	require.Nil(t, pool)
	require.ErrorIs(t, err, ErrSessionPoolNilContext)
}

// TestNewSessionPool_DefaultSize verifies that a non-positive size falls back
// to DefaultSessionPoolSize, and that exactly that many sessions are opened and
// available.
func TestNewSessionPool_DefaultSize(t *testing.T) {
	b := newProvisionedBackend(t, "pool-default-size")

	for _, size := range []int{0, -1} {
		slot, err := b.resolveSlot()
		require.NoError(t, err)

		pool, err := NewSessionPool(b.p11ctx, slot, b.config.PIN, size)
		require.NoError(t, err)

		require.Equal(t, DefaultSessionPoolSize, cap(pool.pool), "size %d must fall back to the default", size)
		require.Len(t, pool.pool, DefaultSessionPoolSize, "every session must be pre-opened and idle")

		pool.Close()
	}
}

// TestNewSessionPool_ExplicitSize verifies a positive size is honoured exactly.
func TestNewSessionPool_ExplicitSize(t *testing.T) {
	b := newProvisionedBackend(t, "pool-explicit-size")

	pool := newTestPool(t, b, 3)
	require.Equal(t, 3, cap(pool.pool))
	require.Len(t, pool.pool, 3)
	require.Equal(t, b.p11ctx, pool.Ctx())

	slot, err := b.resolveSlot()
	require.NoError(t, err)
	require.Equal(t, slot, pool.SlotID())
}

// TestNewSessionPool_InvalidSlot verifies that a slot the module does not know
// fails construction with ErrSessionPoolOpen carrying the token's own message,
// rather than returning a pool whose channel is empty.
func TestNewSessionPool_InvalidSlot(t *testing.T) {
	b := newProvisionedBackend(t, "pool-bad-slot")

	pool, err := NewSessionPool(b.p11ctx, 0xdead, b.config.PIN, 2)
	require.Nil(t, pool)
	require.ErrorIs(t, err, ErrSessionPoolOpen)

	var detail *errs.Detail
	require.True(t, errors.As(err, &detail))
	require.Contains(t, detail.Detail, "CKR_SLOT_ID_INVALID")
}

// TestNewSessionPool_WrongPIN verifies that a failed login is reported as
// ErrSessionPoolLogin and that the sessions opened before the failure are
// closed rather than leaked.
//
// The pool is built on a private PKCS#11 context with no prior login, because
// PKCS#11 login state is per-token per application: had another pool in this
// process already authenticated, C_Login would answer
// CKR_USER_ALREADY_LOGGED_IN and the constructor would (correctly) tolerate it,
// masking the wrong PIN.
func TestNewSessionPool_WrongPIN(t *testing.T) {
	token := softhsmtest.Provision(t, "pool-wrong-pin")

	ctx := pkcs11.New(token.Library)
	require.NotNil(t, ctx)
	require.NoError(t, ctx.Initialize())
	t.Cleanup(func() {
		require.NoError(t, ctx.Finalize())
		ctx.Destroy()
	})

	slot := token.Slot(t, ctx)

	pool, err := NewSessionPool(ctx, slot, "0000", 2)
	require.Nil(t, pool, "a pool that cannot authenticate must not be handed to the caller")
	require.ErrorIs(t, err, ErrSessionPoolLogin)

	var detail *errs.Detail
	require.True(t, errors.As(err, &detail))
	require.Contains(t, detail.Detail, "CKR_PIN_INCORRECT")
}

// TestNewSessionPool_EmptyPINSkipsLogin verifies that an empty PIN opens
// sessions without logging in: the token reports a public (unauthenticated)
// session state.
func TestNewSessionPool_EmptyPINSkipsLogin(t *testing.T) {
	token := softhsmtest.Provision(t, "pool-no-login")

	ctx := pkcs11.New(token.Library)
	require.NotNil(t, ctx)
	require.NoError(t, ctx.Initialize())
	t.Cleanup(func() {
		require.NoError(t, ctx.Finalize())
		ctx.Destroy()
	})

	slot := token.Slot(t, ctx)

	pool, err := NewSessionPool(ctx, slot, "", 1)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		info, err := ctx.GetSessionInfo(session)
		if err != nil {
			return err
		}
		require.Equal(t, uint(pkcs11.CKS_RW_PUBLIC_SESSION), info.State,
			"an empty PIN must leave the session unauthenticated")
		return nil
	}))
}

// TestNewSessionPool_AlreadyLoggedIn verifies the documented tolerance of
// CKR_USER_ALREADY_LOGGED_IN: a second pool on the same token must construct
// successfully, because PKCS#11 login state is per-token and the first pool
// already established it.
func TestNewSessionPool_AlreadyLoggedIn(t *testing.T) {
	b := newProvisionedBackend(t, "pool-already-logged-in")

	first := newTestPool(t, b, 1)
	second := newTestPool(t, b, 1)

	require.NotNil(t, first)
	require.NotNil(t, second)

	require.NoError(t, second.WithSession(func(session pkcs11.SessionHandle) error {
		info, err := b.p11ctx.GetSessionInfo(session)
		if err != nil {
			return err
		}
		require.Equal(t, uint(pkcs11.CKS_RW_USER_FUNCTIONS), info.State,
			"the second pool inherits the token-wide user login")
		return nil
	}))
}

// TestSessionPool_WithSession_ReturnsSession verifies the pool invariant that a
// session is always returned, whether fn succeeds or fails. A leaked session
// would silently shrink the pool until every operation deadlocked.
func TestSessionPool_WithSession_ReturnsSession(t *testing.T) {
	b := newProvisionedBackend(t, "pool-return-session")
	pool := newTestPool(t, b, 2)

	var borrowed pkcs11.SessionHandle
	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		borrowed = session
		require.Len(t, pool.pool, 1, "the borrowed session must be out of the channel")
		return nil
	}))
	require.Len(t, pool.pool, 2, "the session must be returned after a successful call")
	require.NotZero(t, borrowed)

	sentinel := errors.New("callback failure")
	require.ErrorIs(t, pool.WithSession(func(pkcs11.SessionHandle) error {
		return sentinel
	}), sentinel, "WithSession must return the callback's error unchanged")
	require.Len(t, pool.pool, 2, "the session must be returned even when the callback fails")
}

// TestSessionPool_WithSession_ReturnsSessionOnPanic pins that a panicking
// callback does not cost the pool a session.
//
// The return used to be a plain statement after fn, so a panic skipped it: the
// session was neither put back on the channel nor closed, just lost. Nothing
// logged it and nothing failed at the time -- the pool was simply one smaller
// from then on, and once enough sessions had gone that way WithSession would
// block forever on a receive from an empty channel. A hang, arriving long
// after and nowhere near the panic that caused it.
//
// fn is arbitrary caller code (certificate parsing, attribute decoding,
// callbacks into storage), so a panic in it is an ordinary bug, not an exotic
// one.
func TestSessionPool_WithSession_ReturnsSessionOnPanic(t *testing.T) {
	b := newProvisionedBackend(t, "pool-panic-return")
	pool := newTestPool(t, b, 2)

	panicked := false
	func() {
		defer func() {
			panicked = recover() != nil
		}()
		_ = pool.WithSession(func(pkcs11.SessionHandle) error {
			panic("callback exploded")
		})
	}()

	require.True(t, panicked,
		"the panic must still reach the caller; this is about not leaking the "+
			"session on the way past, not about swallowing it")
	require.Len(t, pool.pool, 2,
		"the session must be returned even when the callback panics")

	// Full size is necessary but not sufficient: the pool must still hand out
	// a usable session afterwards.
	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		require.NotZero(t, session)
		return nil
	}))
	require.Len(t, pool.pool, 2)
}

// TestSessionPool_WithSession_DiscardsSessionPoisonedByPanic pins the harder
// half of the panic contract: the session that comes back must be CLEAN, not
// merely present.
//
// A callback can start a PKCS#11 operation and panic before finishing it --
// C_FindObjectsInit here, but C_SignInit or a multipart update behave the same
// way. Returning that session to the pool hands the next borrower an operation
// it did not start: CKR_OPERATION_ACTIVE at best, somebody else's partial
// state at worst. Counting handles cannot see that, which is why this test
// starts a real operation rather than panicking on a bare callback.
//
// The pool is sized 1 so the next checkout is necessarily the replacement.
func TestSessionPool_WithSession_DiscardsSessionPoisonedByPanic(t *testing.T) {
	b := newProvisionedBackend(t, "pool-panic-poison")
	pool := newTestPool(t, b, 1)

	certTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	}

	var poisoned pkcs11.SessionHandle
	panicked := false
	func() {
		defer func() {
			panicked = recover() != nil
		}()
		_ = pool.WithSession(func(session pkcs11.SessionHandle) error {
			poisoned = session
			// Leave a find operation running, then die.
			require.NoError(t, pool.ctx.FindObjectsInit(session, certTemplate))
			panic("callback exploded mid-operation")
		})
	}()

	require.True(t, panicked, "the panic must still reach the caller")
	require.Len(t, pool.pool, 1, "the pool must keep its size")

	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		require.NotEqual(t, poisoned, session,
			"the poisoned session must not be handed out again")

		// The operation state is the point: on an inherited find this returns
		// CKR_OPERATION_ACTIVE.
		if err := pool.ctx.FindObjectsInit(session, certTemplate); err != nil {
			return err
		}
		return pool.ctx.FindObjectsFinal(session)
	}), "the next borrower inherited operation state from the panicking callback")
}

// TestSessionPool_Close_IsIdempotent verifies Close can be called repeatedly
// and that operations afterwards fail fast with ErrSessionPoolClosed rather
// than blocking on an empty channel.
func TestSessionPool_Close_IsIdempotent(t *testing.T) {
	b := newProvisionedBackend(t, "pool-close-idempotent")
	pool := newTestPool(t, b, 2)

	pool.Close()
	pool.Close()
	pool.Close()

	require.Empty(t, pool.pool, "Close must drain every session")
	require.ErrorIs(t, pool.WithSession(func(pkcs11.SessionHandle) error {
		t.Fatal("the callback must not run on a closed pool")
		return nil
	}), ErrSessionPoolClosed)

	require.ErrorIs(t, pool.WithSOSession("87654321", "1234", func(pkcs11.SessionHandle) error {
		t.Fatal("the callback must not run on a closed pool")
		return nil
	}), ErrSessionPoolClosed)
}

// TestSessionPool_WithSession_NilChannel verifies the guard against a
// zero-value SessionPool. Several call sites in this package construct
// &SessionPool{} as an "initialized" sentinel, so a nil channel must be
// reported instead of blocking forever on a receive from nil.
func TestSessionPool_WithSession_NilChannel(t *testing.T) {
	pool := &SessionPool{}

	require.ErrorIs(t, pool.WithSession(func(pkcs11.SessionHandle) error {
		t.Fatal("the callback must not run without a session channel")
		return nil
	}), ErrSessionPoolClosed)
}

// TestSessionPool_CloseDuringCheckout verifies the branch where the pool is
// closed while a session is checked out: the in-flight session must be closed
// directly instead of being pushed back into a drained channel, and the
// callback's own result must still reach the caller.
func TestSessionPool_CloseDuringCheckout(t *testing.T) {
	b := newProvisionedBackend(t, "pool-close-during-checkout")
	pool := newTestPool(t, b, 2)

	var checkedOut pkcs11.SessionHandle
	err := pool.WithSession(func(session pkcs11.SessionHandle) error {
		checkedOut = session
		pool.Close()
		return nil
	})
	require.NoError(t, err)

	require.Empty(t, pool.pool, "the in-flight session must not be returned to a closed pool")

	// The handle must be genuinely closed: the module no longer knows it.
	_, infoErr := b.p11ctx.GetSessionInfo(checkedOut)
	require.Error(t, infoErr, "the checked-out session must have been closed")
	require.ErrorIs(t, infoErr, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID))
}

// TestSessionPool_ConcurrentCheckoutIsExclusive is the concurrency contract
// test. PKCS#11 allows only one active cryptographic operation per session
// (C_SignInit on a session that already has an operation active returns
// CKR_OPERATION_ACTIVE), so if the pool ever handed the same session to two
// goroutines at once the signatures would fail.
//
// Every signature is verified against the public key so that a session mix-up
// cannot hide behind a nil error.
//
// Run with -race to also cover the pool's internal state.
func TestSessionPool_ConcurrentCheckoutIsExclusive(t *testing.T) {
	b := newProvisionedBackend(t, "pool-concurrent-sign")

	const poolSize = 4
	pool := newTestPool(t, b, poolSize)

	id := []byte("pool-concurrent-key")
	signer, err := generateECDSAKeyPair(pool, id, id, elliptic.P256(), false, "", "")
	require.NoError(t, err)
	pub := signer.Public().(*ecdsa.PublicKey)

	digest := digestFor(t, crypto.SHA256, []byte("concurrent payload"))

	var failures atomic.Int64

	const goroutines = 16
	const iterations = 8

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
				if err != nil || !ecdsa.VerifyASN1(pub, digest, sig) {
					failures.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	require.Zero(t, failures.Load(), "every concurrent signature must succeed and verify")
	require.Len(t, pool.pool, poolSize, "every session must be back in the pool")
}

// TestSessionPool_ConcurrentCheckoutIsBounded measures the pool's semaphore
// behaviour directly: the number of callbacks running at any instant must never
// exceed the pool size, and the set of handles handed out must be no larger
// than the pool.
//
// This is the property that makes the exclusivity above true, asserted
// independently of any crypto operation.
func TestSessionPool_ConcurrentCheckoutIsBounded(t *testing.T) {
	b := newProvisionedBackend(t, "pool-concurrent-bounded")

	const poolSize = 3
	pool := newTestPool(t, b, poolSize)

	var inFlight, maxInFlight atomic.Int64
	var mu sync.Mutex
	seen := make(map[pkcs11.SessionHandle]int)

	var wg sync.WaitGroup
	const goroutines = 24
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			err := pool.WithSession(func(session pkcs11.SessionHandle) error {
				now := inFlight.Add(1)
				for {
					peak := maxInFlight.Load()
					if now <= peak || maxInFlight.CompareAndSwap(peak, now) {
						break
					}
				}

				mu.Lock()
				seen[session]++
				mu.Unlock()

				_, err := pool.Ctx().GetSessionInfo(session)
				inFlight.Add(-1)
				return err
			})
			require.NoError(t, err)
		}()
	}
	wg.Wait()

	require.LessOrEqual(t, maxInFlight.Load(), int64(poolSize),
		"the pool must not admit more concurrent callbacks than it has sessions")

	mu.Lock()
	distinct := len(seen)
	mu.Unlock()
	require.LessOrEqual(t, distinct, poolSize, "the pool must not invent session handles")
	require.Len(t, pool.pool, poolSize, "every session must be back in the pool")
}

// TestSessionPool_ConcurrentMixedWorkload exercises the pool with RSA signing,
// ECDSA signing and attribute reads interleaved from many goroutines on a pool
// smaller than the goroutine count, which forces repeated checkout contention.
func TestSessionPool_ConcurrentMixedWorkload(t *testing.T) {
	b := newProvisionedBackend(t, "pool-concurrent-mixed")

	const poolSize = 2
	pool := newTestPool(t, b, poolSize)

	rsaID := []byte("pool-mixed-rsa")
	rsaSigner, err := generateRSAKeyPair(pool, rsaID, rsaID, rsaTestKeySize, false, "", "")
	require.NoError(t, err)
	rsaPub := rsaSigner.Public().(*rsa.PublicKey)

	ecID := []byte("pool-mixed-ec")
	ecSigner, err := generateECDSAKeyPair(pool, ecID, ecID, elliptic.P256(), false, "", "")
	require.NoError(t, err)
	ecPub := ecSigner.Public().(*ecdsa.PublicKey)

	digest := digestFor(t, crypto.SHA256, []byte("mixed workload"))

	var failures atomic.Int64
	var wg sync.WaitGroup

	const goroutines = 12
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			switch g % 3 {
			case 0:
				sig, err := rsaSigner.Sign(rand.Reader, digest, crypto.SHA256)
				if err != nil || rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest, sig) != nil {
					failures.Add(1)
				}
			case 1:
				sig, err := ecSigner.Sign(rand.Reader, digest, crypto.SHA256)
				if err != nil || !ecdsa.VerifyASN1(ecPub, digest, sig) {
					failures.Add(1)
				}
			default:
				found, err := findRSASigner(pool, rsaID)
				if err != nil || found == nil {
					failures.Add(1)
				}
			}
		}(g)
	}
	wg.Wait()

	require.Zero(t, failures.Load(), "mixed concurrent workload must not corrupt session state")
	require.Len(t, pool.pool, poolSize)
}

// TestSessionPool_WithSOSession_SwitchesAndRestoresLogin verifies the
// Security Officer escalation used for YubiKey PIV key generation. The token
// itself is the oracle: C_GetSessionInfo must report CKS_RW_SO_FUNCTIONS inside
// the callback and CKS_RW_USER_FUNCTIONS again afterwards.
//
// Failing to restore the user login would leave every other session on the
// token unable to touch private objects, so the restore half is the important
// assertion.
func TestSessionPool_WithSOSession_SwitchesAndRestoresLogin(t *testing.T) {
	b := newProvisionedBackend(t, "pool-so-session")
	pool := newTestPool(t, b, 2)

	var sawSOState bool
	require.NoError(t, pool.WithSOSession(b.config.SOPIN, b.config.PIN, func(session pkcs11.SessionHandle) error {
		info, err := b.p11ctx.GetSessionInfo(session)
		if err != nil {
			return err
		}
		sawSOState = info.State == uint(pkcs11.CKS_RW_SO_FUNCTIONS)
		return nil
	}))
	require.True(t, sawSOState, "the callback must run with Security Officer authentication")

	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		info, err := b.p11ctx.GetSessionInfo(session)
		if err != nil {
			return err
		}
		require.Equal(t, uint(pkcs11.CKS_RW_USER_FUNCTIONS), info.State,
			"the user login must be restored after the SO operation")
		return nil
	}))
}

// TestSessionPool_WithSOSession_PropagatesCallbackError verifies that the
// callback's error survives the login restore, and that the restore still
// happens.
func TestSessionPool_WithSOSession_PropagatesCallbackError(t *testing.T) {
	b := newProvisionedBackend(t, "pool-so-callback-error")
	pool := newTestPool(t, b, 2)

	sentinel := errors.New("so callback failure")
	err := pool.WithSOSession(b.config.SOPIN, b.config.PIN, func(pkcs11.SessionHandle) error {
		return sentinel
	})
	require.ErrorIs(t, err, sentinel)

	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		info, infoErr := b.p11ctx.GetSessionInfo(session)
		if infoErr != nil {
			return infoErr
		}
		require.Equal(t, uint(pkcs11.CKS_RW_USER_FUNCTIONS), info.State)
		return nil
	}))
	require.Len(t, pool.pool, 2, "the session must be returned after a failed SO callback")
}

// TestSessionPool_WithSOSession_WrongSOPIN verifies that a bad Security Officer
// PIN is refused with ErrSessionPoolLogin, that the callback never runs, and
// that the user login is restored so the token remains usable.
func TestSessionPool_WithSOSession_WrongSOPIN(t *testing.T) {
	b := newProvisionedBackend(t, "pool-so-wrong-pin")
	pool := newTestPool(t, b, 2)

	var ran bool
	err := pool.WithSOSession("00000000", b.config.PIN, func(pkcs11.SessionHandle) error {
		ran = true
		return nil
	})
	require.False(t, ran, "the callback must not run without Security Officer authentication")
	require.ErrorIs(t, err, ErrSessionPoolLogin)

	var detail *errs.Detail
	require.True(t, errors.As(err, &detail))
	require.Contains(t, detail.Detail, "SO login:")

	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		info, infoErr := b.p11ctx.GetSessionInfo(session)
		if infoErr != nil {
			return infoErr
		}
		require.Equal(t, uint(pkcs11.CKS_RW_USER_FUNCTIONS), info.State,
			"a failed SO login must leave the user session intact")
		return nil
	}))
}

// TestSessionPool_WithSOSession_EmptyUserPIN verifies the branch that skips the
// user re-login: the session is left in the public state, which is the correct
// outcome when no user PIN was supplied to restore.
func TestSessionPool_WithSOSession_EmptyUserPIN(t *testing.T) {
	b := newProvisionedBackend(t, "pool-so-empty-user-pin")
	pool := newTestPool(t, b, 1)

	require.NoError(t, pool.WithSOSession(b.config.SOPIN, "", func(pkcs11.SessionHandle) error {
		return nil
	}))

	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		info, err := b.p11ctx.GetSessionInfo(session)
		if err != nil {
			return err
		}
		require.Equal(t, uint(pkcs11.CKS_RW_PUBLIC_SESSION), info.State,
			"without a user PIN there is nothing to restore, so the token is logged out")
		return nil
	}))

	// Re-establish the user login so the backend cleanup and any later
	// operations on this token behave normally.
	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		return b.p11ctx.Login(session, pkcs11.CKU_USER, b.config.PIN)
	}))
}

// TestSessionPool_WithSOSession_CloseDuringCallback verifies the deferred
// cleanup branch: if the pool is closed while the Security Officer callback is
// running, the checked-out session must be closed directly rather than pushed
// back into a drained pool.
func TestSessionPool_WithSOSession_CloseDuringCallback(t *testing.T) {
	b := newProvisionedBackend(t, "pool-so-close-during")
	pool := newTestPool(t, b, 2)

	var checkedOut pkcs11.SessionHandle
	err := pool.WithSOSession(b.config.SOPIN, b.config.PIN, func(session pkcs11.SessionHandle) error {
		checkedOut = session
		pool.Close()
		return nil
	})
	require.NoError(t, err)

	require.Empty(t, pool.pool, "the in-flight session must not return to a closed pool")

	_, infoErr := b.p11ctx.GetSessionInfo(checkedOut)
	require.ErrorIs(t, infoErr, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID),
		"the checked-out session must have been closed")
}

// TestSessionPool_WithSOSession_UserLoginRestoreFails verifies the failure mode
// that matters most in the SO escalation: if the user PIN cannot be restored
// after the Security Officer operation, the caller must be told.
//
// Silently returning the callback's success would leave the token logged out
// while every later operation failed with CKR_USER_NOT_LOGGED_IN far from the
// cause, so the restore failure is reported and the original callback result is
// carried in the detail for diagnosis.
func TestSessionPool_WithSOSession_UserLoginRestoreFails(t *testing.T) {
	b := newProvisionedBackend(t, "pool-so-restore-fails")
	pool := newTestPool(t, b, 1)

	var ran bool
	err := pool.WithSOSession(b.config.SOPIN, "0000", func(pkcs11.SessionHandle) error {
		ran = true
		return nil
	})
	require.True(t, ran, "the SO callback must still have run")
	require.ErrorIs(t, err, ErrSessionPoolLogin)

	var detail *errs.Detail
	require.True(t, errors.As(err, &detail))
	require.Contains(t, detail.Detail, "user login restore:")
	require.Contains(t, detail.Detail, "CKR_PIN_INCORRECT")

	// Put the token back in the user state so the backend cleanup and any
	// later operations on this token behave normally.
	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		return b.p11ctx.Login(session, pkcs11.CKU_USER, b.config.PIN)
	}))
}

// TestSessionPool_WithSOSession_UserLoginRestoreFails_DiscardsSession verifies
// the M4 fix: a session whose CKU_USER restore fails after the SO operation
// must not recirculate through plain release. It must instead be closed and
// replaced, exactly like the operation-poisoned session in
// TestSessionPool_WithSession_DiscardsSessionPoisonedByPanic, because its
// login state could not be driven back to known-good.
func TestSessionPool_WithSOSession_UserLoginRestoreFails_DiscardsSession(t *testing.T) {
	b := newProvisionedBackend(t, "pool-so-restore-fails-discard")
	pool := newTestPool(t, b, 1)

	var poisoned pkcs11.SessionHandle
	err := pool.WithSOSession(b.config.SOPIN, "0000", func(session pkcs11.SessionHandle) error {
		poisoned = session
		return nil
	})
	require.ErrorIs(t, err, ErrSessionPoolLogin)
	require.NotZero(t, poisoned)

	require.Len(t, pool.pool, 1, "the pool must keep its size by replacing the discarded session")

	var next pkcs11.SessionHandle
	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		next = session
		return nil
	}))
	require.NotEqual(t, poisoned, next,
		"a session whose login-state restore failed must not recirculate")

	_, infoErr := b.p11ctx.GetSessionInfo(poisoned)
	require.Error(t, infoErr,
		"the discarded session must have been closed, not merely pushed back into circulation")

	// Put the token back in the user state so the backend cleanup and any
	// later operations on this token behave normally.
	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		return b.p11ctx.Login(session, pkcs11.CKU_USER, b.config.PIN)
	}))
}

// TestSessionPool_WithSOSession_SOLoginAndRestoreBothFail_DiscardsSession
// covers the other M4 failure branch: the SO login itself fails, and the
// attempt to restore CKU_USER before returning also fails. The session's
// login state is now unknown on both sides of the swap, so it must be
// discarded rather than released.
func TestSessionPool_WithSOSession_SOLoginAndRestoreBothFail_DiscardsSession(t *testing.T) {
	b := newProvisionedBackend(t, "pool-so-login-and-restore-fail")
	pool := newTestPool(t, b, 1)

	original := <-pool.pool
	pool.pool <- original

	var ran bool
	err := pool.WithSOSession("00000000", "0000", func(pkcs11.SessionHandle) error {
		ran = true
		return nil
	})
	require.False(t, ran, "the callback must not run without Security Officer authentication")
	require.ErrorIs(t, err, ErrSessionPoolLogin)

	require.Len(t, pool.pool, 1, "the pool must keep its size by replacing the discarded session")

	replacement := <-pool.pool
	pool.pool <- replacement
	require.NotEqual(t, original, replacement,
		"a session whose login state could not be restored after a failed SO login must not recirculate")

	_, infoErr := b.p11ctx.GetSessionInfo(original)
	require.Error(t, infoErr, "the discarded session must have been closed")

	// Put the token back in the user state so the backend cleanup and any
	// later operations on this token behave normally.
	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		return b.p11ctx.Login(session, pkcs11.CKU_USER, b.config.PIN)
	}))
}

// mustNotBlock runs fn on its own goroutine and fails t if it has not returned
// within the bound.
//
// The bound is on the WAIT, not asserted after the call returns. Every
// regression these tests guard is a checkout that never returns, and a plain
// call would hang the package until the go test timeout killed it -- reporting
// "panic: test timed out" for the whole binary rather than naming the checkout
// that blocked.
func mustNotBlock(t *testing.T, what string, fn func() error) error {
	t.Helper()

	result := make(chan error, 1)
	go func() { result <- fn() }()

	select {
	case err := <-result:
		return err
	case <-time.After(30 * time.Second):
		t.Fatalf("%s blocked instead of returning: the pool can no longer serve "+
			"a session and must say so rather than park the caller forever", what)
		return nil
	}
}

// TestSessionPool_ReplacementFailureFailsThePoolTerminally pins the owner
// ruling of 2026-08-23 on #107: a pool that loses a session to a panicking
// callback and cannot open a replacement enters a TERMINAL failed state, and
// every checkout from then on returns ErrSessionPoolFailed.
//
// The version this replaces returned from discardAndReplace and left the pool
// one session smaller, on the reasoning that "a short pool is slow, a poisoned
// session is wrong". For the size-one pool below, one short IS zero: the next
// WithSession passed the closed checks and then blocked forever on an empty
// channel -- the exact hang the panic handling was added to prevent, reached by
// a different route and reported nowhere. A larger pool decays one session per
// panic until it arrives at the same place.
//
// The replacement is made to fail for a real reason rather than through a
// double: the pool is pointed at a slot the module does not have, so
// C_OpenSession answers CKR_SLOT_ID_INVALID. Nothing about the failure path is
// simulated.
func TestSessionPool_ReplacementFailureFailsThePoolTerminally(t *testing.T) {
	b := newProvisionedBackend(t, "pool-replacement-fails")
	pool := newTestPool(t, b, 1)

	// From here the pool cannot open anything: the next OpenSession -- which is
	// the replacement for the session the panic below poisons -- fails at the
	// driver.
	pool.slotID = 0xdead

	panicked := false
	func() {
		defer func() { panicked = recover() != nil }()
		_ = pool.WithSession(func(pkcs11.SessionHandle) error {
			panic("callback exploded")
		})
	}()
	require.True(t, panicked, "the panic must still reach the caller")

	// The property that matters comes first, because it is the one the previous
	// implementation got wrong: the next caller is TOLD, not parked. Asserting
	// the failed flag before this would report a missing flag where the defect
	// is a hang.
	err := mustNotBlock(t, "WithSession on a failed pool", func() error {
		return pool.WithSession(func(pkcs11.SessionHandle) error {
			t.Error("the callback must not run on a failed pool")
			return nil
		})
	})
	require.ErrorIs(t, err, ErrSessionPoolFailed)

	// WithSOSession shares the checkout, so it reports the same thing. It used
	// to do a bare `<-p.pool`, which is the block-forever receive one function
	// below the one that had already been fixed.
	err = mustNotBlock(t, "WithSOSession on a failed pool", func() error {
		return pool.WithSOSession("so", "user", func(pkcs11.SessionHandle) error {
			t.Error("the callback must not run on a failed pool")
			return nil
		})
	})
	require.ErrorIs(t, err, ErrSessionPoolFailed)

	// Terminal means terminal: nothing reopens it.
	require.ErrorIs(t, pool.WithSession(func(pkcs11.SessionHandle) error { return nil }),
		ErrSessionPoolFailed)

	require.True(t, pool.failed.Load(),
		"a pool that cannot replace the session it had to discard must fail, not shrink")
	require.Empty(t, pool.pool,
		"the failed transition must close the sessions still in the channel, not "+
			"leave them open in a pool that will never hand them out")
}

// TestSessionPool_CloseWaitsForAReplacementInFlight pins that Close cannot
// return while a replacement session is being opened for a panicked callback.
//
// Without the lifecycle mutex the interleaving is: discardAndReplace reads
// closed (false), and is descheduled; Close sets closed, drains an empty
// channel and returns; discardAndReplace's OpenSession completes and its
// non-blocking send succeeds, because the drain left the buffer with room. The
// replacement is then an open PKCS#11 session in a closed pool -- no checkout
// will ever take it, Close is idempotent so no later call drains it, and the
// caller is entitled to Finalize the context underneath it.
//
// The window is inside one call and cannot be reached by timing from outside,
// so the test holds it open with testHookReplacementOpened and asserts twice:
//
//   - Close must NOT return while the hook holds the lifecycle mutex. This is a
//     negative liveness claim, so it is checked over a window rather than at an
//     instant -- there is no other way to observe "did not happen". The window
//     is not a guess about scheduling: correct code CANNOT fire that channel
//     during it, because Close is parked on a mutex this goroutine releases
//     only afterwards, so the passing direction has no race to lose. A Close
//     that skips the mutex does a CAS, a channel close and a drain of an empty
//     channel -- microseconds against two seconds.
//   - after both goroutines have finished, the pool channel must be empty. That
//     is the leak itself, observed directly: Close drained the replacement, so
//     Close was still running when it was published.
//
// An earlier version of this test asserted only an atomic flag read at Close's
// return and PASSED against the mutant that removes the mutex, because nothing
// ordered the flag against Close and nothing waited for the discarding
// goroutine before looking at the channel.
func TestSessionPool_CloseWaitsForAReplacementInFlight(t *testing.T) {
	b := newProvisionedBackend(t, "pool-close-vs-replacement")
	pool := newTestPool(t, b, 1)

	var (
		inFlight   = make(chan struct{})
		mayPublish = make(chan struct{})
		discarded  = make(chan struct{})
		closeDone  = make(chan struct{})
	)

	testHookReplacementOpened = func() {
		close(inFlight)
		<-mayPublish
	}
	t.Cleanup(func() { testHookReplacementOpened = nil })

	go func() {
		defer close(discarded)
		defer func() { _ = recover() }()
		_ = pool.WithSession(func(pkcs11.SessionHandle) error {
			panic("callback exploded")
		})
	}()

	// The replacement is now open and unpublished, and discardAndReplace holds
	// the lifecycle mutex. Anything Close does from here has to wait for it.
	<-inFlight

	go func() {
		pool.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
		t.Fatal("Close returned while a replacement was still in flight: it did " +
			"not take the lifecycle mutex, so the replacement published after it " +
			"is an open session in a closed pool that nothing will ever drain")
	case <-time.After(2 * time.Second):
		// Correct: Close is parked on the mutex the hook is holding.
	}

	close(mayPublish)

	select {
	case <-discarded:
	case <-time.After(30 * time.Second):
		t.Fatal("the discarding goroutine never finished publishing its replacement")
	}
	select {
	case <-closeDone:
	case <-time.After(30 * time.Second):
		t.Fatal("Close never returned after the replacement was published")
	}

	require.Empty(t, pool.pool,
		"Close must drain the replacement it waited for; a handle left here is "+
			"an open session in a closed pool that nothing will ever close")
}

// TestSessionPool_WithSearch_SerializesPerHandle proves that WithSearch makes
// FindObjectsInit/FindObjects/FindObjectsFinal one critical section per
// session handle: many goroutines hammering WithSearch on the SAME handle can
// never have two of those sequences in flight at once.
//
// This is the shape of #24: a second C_FindObjectsInit landing on a handle
// while an earlier search on that same handle is still open fails the token
// with CKR_OPERATION_ACTIVE. The pool's channel already keeps two goroutines
// from holding one handle at the same time through WithSession, so this test
// bypasses that by driving WithSearch directly against a single handle taken
// out of the pool once -- the scenario the per-handle lock exists for.
func TestSessionPool_WithSearch_SerializesPerHandle(t *testing.T) {
	b := newProvisionedBackend(t, "pool-search-serialize")
	pool := newTestPool(t, b, 1)

	// Whitebox: take the pool's one session directly so every goroutine below
	// targets the identical handle, then hand it back so pool.Close (via
	// t.Cleanup) has something to drain.
	session := <-pool.pool
	t.Cleanup(func() { pool.pool <- session })

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	}

	var active int32
	var overlapped atomic.Bool
	const goroutines = 8
	const iterations = 50

	var wg sync.WaitGroup
	start := make(chan struct{})
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				err := pool.WithSearch(session, template, func() error {
					// A goroutine that slipped past the lock would land here
					// while active is already 1 and get caught by the CAS
					// below, not by a PKCS#11 error -- this is checking the
					// Go-level critical section, not relying on the token to
					// report the race.
					if !atomic.CompareAndSwapInt32(&active, 0, 1) {
						overlapped.Store(true)
					}
					_, _, findErr := pool.ctx.FindObjects(session, 1)
					atomic.StoreInt32(&active, 0)
					return findErr
				})
				require.NoError(t, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	require.False(t, overlapped.Load(),
		"two goroutines interleaved a search on the same session handle")
}

// TestSessionPool_WithSearch_FindErrorStillFinalizes verifies that WithSearch
// calls FindObjectsFinal even when find returns an error, and that the error
// find returned is the one the caller sees. If Final did not run, the next
// search on the same handle would fail with CKR_OPERATION_ACTIVE instead of
// succeeding, which is what the second WithSearch call below checks for.
func TestSessionPool_WithSearch_FindErrorStillFinalizes(t *testing.T) {
	b := newProvisionedBackend(t, "pool-search-final-on-error")
	pool := newTestPool(t, b, 1)

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	}

	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		sentinel := errors.New("boom")
		err := pool.WithSearch(session, template, func() error {
			return sentinel
		})
		require.ErrorIs(t, err, sentinel, "find's own error must reach the caller unchanged")

		err = pool.WithSearch(session, template, func() error {
			_, _, findErr := pool.ctx.FindObjects(session, 1)
			return findErr
		})
		require.NoError(t, err, "a prior search that errored must still have been finalized")

		return nil
	}))
}

// TestSessionPool_WithSearch_InitError verifies that a FindObjectsInit
// failure is reported to the caller and that find never runs -- there is no
// search for it to operate on.
func TestSessionPool_WithSearch_InitError(t *testing.T) {
	b := newProvisionedBackend(t, "pool-search-init-error")
	pool := newTestPool(t, b, 1)

	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		require.NoError(t, b.p11ctx.CloseSession(session), "kill the session before WithSearch uses it")

		called := false
		err := pool.WithSearch(session, nil, func() error {
			called = true
			return nil
		})

		require.Error(t, err, "FindObjectsInit on a closed session must fail")
		require.False(t, called, "find must not run when FindObjectsInit fails")
		require.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID))

		// The session this callback was handed is dead; hand back a value so
		// WithSession's own bookkeeping has something to return, matching
		// what TestFindRSASigner_DeadSession's WithSession does after
		// closing its session the same way.
		return nil
	}))
}
