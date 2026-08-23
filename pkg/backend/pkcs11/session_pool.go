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
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/miekg/pkcs11"
)

// DefaultSessionPoolSize is the default number of sessions in the pool.
const DefaultSessionPoolSize = 8

// SessionPool provides a channel-based pool of PKCS#11 sessions. Sessions are
// pre-opened and logged in during construction. Callers check out a session via
// WithSession, use it, and it is automatically returned to the pool.
//
// Thread Safety:
// The pool is safe for concurrent use from multiple goroutines. The buffered
// channel is the semaphore that hands a session from one caller to the next.
//
// It is NOT lock-free, and the doc comment claiming it was described an earlier
// design. A channel alone cannot express the pool's LIFECYCLE, because the
// lifecycle is a set of decisions about the pool as a whole -- publish a
// replacement, enter the failed state, drain on shutdown -- and a handle that
// slips between two of those is an open PKCS#11 session in a pool nothing will
// ever drain, closed later against a context the caller may already have
// finalized. Those decisions are serialised by the lifecycle mutex; everything
// else still moves over the channel.
//
// The pool has three states, and only the first serves sessions:
//
//   - open -- the normal state.
//   - closed -- Close was called. Checkout returns ErrSessionPoolClosed.
//   - failed -- TERMINAL. A callback panicked, its session had to be discarded
//     with an unknown operation state, and the replacement could not be opened
//     or published. Checkout returns ErrSessionPoolFailed. The pool cannot honour
//     the capacity its callers were sized against, so it serves nothing rather
//     than silently running short; the caller rebuilds it. (Owner ruling
//     2026-08-23 on #107: a pool that cannot replace a lost session fails, and
//     every checkout reports that instead of blocking on a channel that is one
//     session shorter for the rest of the process's life.)
type SessionPool struct {
	ctx    *pkcs11.Ctx
	slotID uint
	pool   chan pkcs11.SessionHandle
	closed atomic.Bool
	failed atomic.Bool

	// lifecycle serialises every operation that changes what the pool IS rather
	// than which goroutine currently holds a session: opening and publishing a
	// replacement, entering the failed state, returning a handle, and Close's
	// drain. Two of those interleaving is how a handle escapes -- Close can
	// otherwise observe an empty channel, drain, and return while a replacement
	// is still being opened, and the send that follows lands in a pool nobody
	// will ever drain.
	//
	// It is held across the replacement's OpenSession deliberately. That call
	// can block in the driver, and while it does, every other returning caller
	// waits. The alternative is Close returning while an OpenSession is in
	// flight, after which the handle is closed against a *pkcs11.Ctx the caller
	// is entitled to have finalized -- a use-after-finalize in C, traded for a
	// stall on the path a callback has already panicked on.
	lifecycle sync.Mutex

	// done is closed once, under lifecycle, when the pool stops serving --
	// by Close, or by the transition to failed. It releases any caller already
	// blocked waiting for a session. A flag alone cannot do that: a caller
	// checks it, passes, and may then be preempted before its receive on pool,
	// by which time the channel has been drained and nothing will ever be sent
	// again. That goroutine would block forever -- a leak on every shutdown
	// that races in-flight work, which is exactly when shutdown happens.
	//
	// doneClosed is the guard for its single close; closing a closed channel
	// panics, and both transitions can reach it.
	done       chan struct{}
	doneClosed bool
}

// state reports why the pool cannot serve a session, or nil if it can.
//
// The flag is always set before done is closed, so a caller woken by done reads
// the reason it was woken rather than a state that has not landed yet.
func (p *SessionPool) state() error {
	if p.closed.Load() {
		return ErrSessionPoolClosed
	}
	if p.failed.Load() {
		return ErrSessionPoolFailed
	}
	return nil
}

// NewSessionPool creates a new session pool with the specified number of RW sessions.
// It opens `size` sessions on the given slot and logs in once (login is per-token
// in PKCS#11, so a single login applies to all sessions on the same token).
//
// Parameters:
//   - ctx: initialized PKCS#11 context
//   - slotID: the token slot to open sessions on
//   - pin: user PIN for authentication (empty string skips login)
//   - size: number of sessions to pre-open
func NewSessionPool(ctx *pkcs11.Ctx, slotID uint, pin string, size int) (*SessionPool, error) {
	if ctx == nil {
		return nil, ErrSessionPoolNilContext
	}
	if size <= 0 {
		size = DefaultSessionPoolSize
	}

	pool := &SessionPool{
		ctx:    ctx,
		slotID: slotID,
		pool:   make(chan pkcs11.SessionHandle, size),
		done:   make(chan struct{}),
	}

	// Open sessions and add them to the pool
	for i := 0; i < size; i++ {
		session, err := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			// Close any sessions we already opened
			pool.drainAndClose()
			return nil, &errs.Detail{Err: ErrSessionPoolOpen, Detail: fmt.Sprintf("%v", err)}
		}
		pool.pool <- session
	}

	// Login once — PKCS#11 login applies to all sessions on the token
	if pin != "" {
		// Borrow the first session for login
		session := <-pool.pool
		err := ctx.Login(session, pkcs11.CKU_USER, pin)
		pool.pool <- session
		if err != nil {
			// CKR_USER_ALREADY_LOGGED_IN is expected when the manager
			// or another pool already logged in on this token
			if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
				pool.drainAndClose()
				return nil, &errs.Detail{Err: ErrSessionPoolLogin, Detail: fmt.Sprintf("%v", err)}
			}
		}
	}

	return pool, nil
}

// acquire checks a session out of the pool, or reports why it cannot: a closed
// pool gives ErrSessionPoolClosed, a failed one ErrSessionPoolFailed. It never
// blocks past the point where the pool stops serving.
//
// Both WithSession and WithSOSession go through it. WithSOSession used to do a
// bare `<-p.pool`, which is the block-forever receive the done channel exists to
// prevent -- the same defect as WithSession's, one function further down.
func (p *SessionPool) acquire() (pkcs11.SessionHandle, error) {
	if err := p.state(); err != nil {
		return 0, err
	}
	if p.pool == nil {
		return 0, ErrSessionPoolClosed
	}

	// Wait for a session, but stay responsive to the pool stopping. Receiving
	// from pool alone reintroduces the block-forever race.
	var session pkcs11.SessionHandle
	select {
	case session = <-p.pool:
	case <-p.done:
		// A nil done channel blocks forever in a select, which is the correct
		// behaviour here: a zero-value pool has no Close to race with, so the
		// receive above is the only case that can fire.
		return 0, p.state()
	}

	// Both cases can be ready at once and select picks between them at random,
	// so a handle can arrive from a pool that has already stopped serving. Hand
	// it back to the transition that is draining rather than to the caller: the
	// ruling is that EVERY checkout on a failed pool reports the failure.
	if err := p.state(); err != nil {
		p.release(session)
		return 0, err
	}
	return session, nil
}

// WithSession checks out a session from the pool, calls fn, and returns the
// session to the pool. A closed pool gives ErrSessionPoolClosed, a failed one
// ErrSessionPoolFailed.
//
// The session handle must not be stored or used outside the fn callback.
func (p *SessionPool) WithSession(fn func(session pkcs11.SessionHandle) error) error {
	session, err := p.acquire()
	if err != nil {
		return err
	}

	// Deferred, not a plain statement after fn: fn is arbitrary caller code,
	// and a panic in it would otherwise skip this entirely -- the session
	// neither returned to the channel nor closed, just lost. The pool would be
	// permanently one smaller, silently, and enough of those turn WithSession
	// into a blocking receive on an empty channel. That hang points nowhere
	// near the panic that caused it.
	//
	// The panic still propagates; this only stops it taking a session with it.
	// WithSOSession below has always done it this way.
	defer func() {
		if r := recover(); r != nil {
			// A panicking callback may have left a PKCS#11 operation running
			// on this session -- C_FindObjectsInit, C_SignInit, a multipart
			// update -- because it never reached whatever would have finalized
			// it. Handing that back means the next borrower inherits it and
			// gets CKR_OPERATION_ACTIVE, or worse, operates on somebody else's
			// partial state.
			//
			// The session's operation state is unknown and there is no way to
			// ask, so it is closed rather than reused, and a replacement is
			// opened so the pool keeps its size. Login is per-token, not per
			// session (see NewSessionPool), so the replacement is already
			// authenticated and needs no PIN.
			p.discardAndReplace(session)
			panic(r)
		}

		p.release(session)
	}()

	return fn(session)
}

// release returns a session to the pool, or closes it if the pool has stopped
// serving. It holds lifecycle for the decision, because the decision and Close's
// drain are the two halves of the same race: checking closed, being preempted,
// and sending afterwards puts an open handle in a channel nothing will drain
// again, to be closed later against a possibly finalized *pkcs11.Ctx.
//
// The lock is held only across a non-blocking channel send, never across a
// driver call.
func (p *SessionPool) release(session pkcs11.SessionHandle) {
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()
	p.releaseLocked(session)
}

// releaseLocked is release with lifecycle already held.
func (p *SessionPool) releaseLocked(session pkcs11.SessionHandle) {
	if p.state() != nil {
		_ = p.ctx.CloseSession(session)
		return
	}
	select {
	case p.pool <- session:
	default:
		// The caller removed this handle, so the buffer has room for it and
		// this cannot be reached while the pool is open. Closing rather than
		// blocking keeps that assumption from becoming a deadlock if the
		// capacity accounting is ever wrong.
		_ = p.ctx.CloseSession(session)
	}
}

// discardAndReplace closes a session whose operation state is unknown and puts
// a fresh one in its place, so a poisoned session neither circulates nor costs
// the pool its size.
//
// If the replacement cannot be opened -- or cannot be published, which has the
// same consequence -- the pool enters its TERMINAL failed state. The earlier
// version returned instead, leaving the pool one session smaller and calling
// that "the lesser failure: a short pool is slow, a poisoned session is wrong".
// Both halves of that were wrong. A size-one pool loses its only session and
// every later WithSession blocks forever on an empty channel -- the exact hang
// the panic handling was added to prevent, reached by a different route -- and
// a larger pool degrades one session per panic with nothing reporting it, until
// it reaches the same place. A pool that cannot keep its capacity says so
// (owner ruling 2026-08-23 on #107).
//
// The whole operation runs under lifecycle. Close therefore cannot slip between
// the check and the publication: it waits for this to finish and then drains
// whatever was published, instead of returning while an OpenSession is in
// flight and leaving its result in a pool nothing will drain.
func (p *SessionPool) discardAndReplace(session pkcs11.SessionHandle) {
	_ = p.ctx.CloseSession(session)

	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()

	// A pool that has already stopped serving wants no replacement: Close will
	// drain nothing extra, and a failed pool is terminal.
	if p.state() != nil {
		return
	}

	replacement, err := p.ctx.OpenSession(p.slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		p.failLocked()
		return
	}

	if testHookReplacementOpened != nil {
		testHookReplacementOpened()
	}

	select {
	case p.pool <- replacement:
	default:
		// Unreachable while the pool is open and holding lifecycle -- this
		// goroutine removed a handle, so the buffer has room. If the accounting
		// is ever wrong, the pool has lost a session just as surely as if the
		// open had failed, so it fails rather than dropping one quietly.
		_ = p.ctx.CloseSession(replacement)
		p.failLocked()
	}
}

// testHookReplacementOpened runs under lifecycle, after a replacement session
// has been opened and before it is published. It is nil in every build; only
// this package's own tests set it, to hold the lifecycle mutex open and observe
// what Close does while a replacement is genuinely in flight.
//
// The window cannot be reached from outside the package -- it opens and closes
// inside one call -- and a test that tried to hit it by timing would be
// asserting on the scheduler rather than on the barrier.
var testHookReplacementOpened func()

// failLocked puts the pool into its terminal failed state: every checkout from
// here on returns ErrSessionPoolFailed, waiters already blocked are released,
// and the sessions still in the channel are closed rather than left open in a
// pool that will never serve them.
//
// The caller must hold lifecycle. The flag is set before done is closed so a
// released waiter reads the reason.
func (p *SessionPool) failLocked() {
	if !p.failed.CompareAndSwap(false, true) {
		return
	}
	p.signalDoneLocked()
	p.drainAndClose()
}

// signalDoneLocked closes done exactly once. Close and failLocked can both
// reach it, and closing a closed channel panics. A pool built as a zero value
// rather than through NewSessionPool has no done channel and no waiters to
// release.
//
// The caller must hold lifecycle.
func (p *SessionPool) signalDoneLocked() {
	if p.doneClosed || p.done == nil {
		return
	}
	p.doneClosed = true
	close(p.done)
}

// WithSOSession temporarily switches the token login to CKU_SO (Security Officer),
// executes fn, then restores CKU_USER login. This is required for tokens like
// YubiKey PIV where key generation requires management key authentication (CKU_SO)
// rather than user PIN (CKU_USER).
//
// Since PKCS#11 login state is per-token (shared across all sessions), the caller
// MUST hold an exclusive lock to prevent concurrent operations from seeing the
// intermediate SO login state.
//
// Parameters:
//   - soPin: Security Officer PIN (management key)
//   - userPin: user PIN to restore after the SO operation
//   - fn: operation to execute under SO authentication
func (p *SessionPool) WithSOSession(soPin, userPin string, fn func(session pkcs11.SessionHandle) error) error {
	session, err := p.acquire()
	if err != nil {
		return err
	}
	defer p.release(session)

	// Logout current user (CKU_USER)
	_ = p.ctx.Logout(session)

	// Login as Security Officer
	if err := p.ctx.Login(session, pkcs11.CKU_SO, soPin); err != nil {
		if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			// Restore user login before returning
			_ = p.ctx.Login(session, pkcs11.CKU_USER, userPin)
			return &errs.Detail{Err: ErrSessionPoolLogin, Detail: fmt.Sprintf("SO login: %v", err)}
		}
	}

	// Execute the operation under SO auth
	fnErr := fn(session)

	// Restore user login: logout SO, then login as user
	_ = p.ctx.Logout(session)
	if userPin != "" {
		if err := p.ctx.Login(session, pkcs11.CKU_USER, userPin); err != nil {
			if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
				return &errs.Detail{Err: ErrSessionPoolLogin, Detail: fmt.Sprintf("user login restore: %v (original: %v)", err, fnErr)}
			}
		}
	}

	return fnErr
}

// Ctx returns the underlying PKCS#11 context.
func (p *SessionPool) Ctx() *pkcs11.Ctx {
	return p.ctx
}

// SlotID returns the slot ID this pool operates on.
func (p *SessionPool) SlotID() uint {
	return p.slotID
}

// Close marks the pool as closed and drains all sessions, closing each one.
// After Close returns, WithSession calls will return ErrSessionPoolClosed.
// Close is idempotent.
func (p *SessionPool) Close() {
	if !p.closed.CompareAndSwap(false, true) {
		return // already closed
	}

	// Taking lifecycle is what makes Close a barrier rather than a race: a
	// replacement being opened for a panicked callback holds it, so Close waits
	// for that session to be published (and drains it below) or discarded,
	// instead of returning while a handle is still in flight.
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()

	// Release anyone already blocked on a session before draining, so a waiter
	// cannot be left holding a receive against a channel that will never be
	// written to again.
	p.signalDoneLocked()
	p.drainAndClose()
}

// drainAndClose closes all sessions currently in the pool channel.
//
// Callers hold lifecycle, except NewSessionPool's cleanup of a half-built pool,
// which has no other goroutine to race with because the pool has not been
// returned to anyone yet.
func (p *SessionPool) drainAndClose() {
	for {
		select {
		case session := <-p.pool:
			_ = p.ctx.CloseSession(session)
		default:
			return
		}
	}
}
