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
