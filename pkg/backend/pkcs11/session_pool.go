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
	"sync/atomic"

	"github.com/miekg/pkcs11"
)

// DefaultSessionPoolSize is the default number of sessions in the pool.
const DefaultSessionPoolSize = 8

// SessionPool provides a channel-based, lock-free pool of PKCS#11 sessions.
// Sessions are pre-opened and logged in during construction. Callers check out
// a session via WithSession, use it, and it is automatically returned to the pool.
//
// Thread Safety:
// The pool is safe for concurrent use from multiple goroutines. The buffered
// channel acts as a lock-free semaphore for session checkout/return.
type SessionPool struct {
	ctx    *pkcs11.Ctx
	slotID uint
	pool   chan pkcs11.SessionHandle
	closed atomic.Bool
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
	}

	// Open sessions and add them to the pool
	for i := 0; i < size; i++ {
		session, err := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			// Close any sessions we already opened
			pool.drainAndClose()
			return nil, fmt.Errorf("%w: %v", ErrSessionPoolOpen, err)
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
				return nil, fmt.Errorf("%w: %v", ErrSessionPoolLogin, err)
			}
		}
	}

	return pool, nil
}

// WithSession checks out a session from the pool, calls fn, and returns the
// session to the pool. If the pool is closed, ErrSessionPoolClosed is returned.
//
// The session handle must not be stored or used outside the fn callback.
func (p *SessionPool) WithSession(fn func(session pkcs11.SessionHandle) error) error {
	if p.closed.Load() {
		return ErrSessionPoolClosed
	}
	if p.pool == nil {
		return ErrSessionPoolClosed
	}

	session := <-p.pool
	err := fn(session)
	if !p.closed.Load() {
		p.pool <- session
	} else {
		// Pool was closed while we held the session — close it directly
		p.ctx.CloseSession(session)
	}
	return err
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
	if p.closed.Load() {
		return ErrSessionPoolClosed
	}

	session := <-p.pool
	defer func() {
		if !p.closed.Load() {
			p.pool <- session
		} else {
			p.ctx.CloseSession(session)
		}
	}()

	// Logout current user (CKU_USER)
	_ = p.ctx.Logout(session)

	// Login as Security Officer
	if err := p.ctx.Login(session, pkcs11.CKU_SO, soPin); err != nil {
		if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			// Restore user login before returning
			_ = p.ctx.Login(session, pkcs11.CKU_USER, userPin)
			return fmt.Errorf("%w: SO login: %v", ErrSessionPoolLogin, err)
		}
	}

	// Execute the operation under SO auth
	fnErr := fn(session)

	// Restore user login: logout SO, then login as user
	_ = p.ctx.Logout(session)
	if userPin != "" {
		if err := p.ctx.Login(session, pkcs11.CKU_USER, userPin); err != nil {
			if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
				return fmt.Errorf("%w: user login restore: %v (original: %v)", ErrSessionPoolLogin, err, fnErr)
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
	p.drainAndClose()
}

// drainAndClose closes all sessions currently in the pool channel.
func (p *SessionPool) drainAndClose() {
	for {
		select {
		case session := <-p.pool:
			p.ctx.CloseSession(session)
		default:
			return
		}
	}
}
