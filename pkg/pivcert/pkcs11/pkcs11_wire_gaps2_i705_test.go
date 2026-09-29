// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"testing"

	"github.com/jeremyhahn/go-xkms/internal/softhsmtest"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	p11 "github.com/miekg/pkcs11"
)

// TestSingleSessionProvider_WithSOSession_WrongSOPIN proves WithSOSession's
// failure branch (go-xkms#705): a wrong SO PIN fails Login with something
// other than CKR_USER_ALREADY_LOGGED_IN, which must restore the CKU_USER
// session and join every error (SO login failure, USER restore result,
// pre-login logout result) rather than losing the token in a logged-out
// state or swallowing any of the three. Every existing WithSOSession test
// in this package uses the correct SO PIN, so this failure path had never
// run.
func TestSingleSessionProvider_WithSOSession_WrongSOPIN(t *testing.T) {
	tok, ctx, session, slotID := newTestSession(t, "wrong-so-pin-single")
	p := &singleSessionProvider{ctx: ctx, session: session, slotID: slotID}

	err := p.WithSOSession("0000wrong0000", tok.UserPIN, func(p11.SessionHandle) error {
		t.Error("fn must not run when the SO login itself fails")
		return nil
	})
	if err == nil {
		t.Fatal("WithSOSession() expected error for a wrong SO PIN, got nil")
	}

	// The session must still be usable as CKU_USER afterward -- the whole
	// point of the restore-on-failure branch.
	if loginErr := ctx.Login(session, p11.CKU_USER, tok.UserPIN); loginErr != nil && !isPKCS11Error(loginErr, p11.CKR_USER_ALREADY_LOGGED_IN) {
		t.Errorf("session not usable as CKU_USER after a failed SO login: %v", loginErr)
	}
}

// TestStandalonePool_WithSOSession_WrongSOPIN mirrors
// TestSingleSessionProvider_WithSOSession_WrongSOPIN for standalonePool's
// own WithSOSession implementation, which checks out and returns a pooled
// session rather than reusing a single fixed one.
func TestStandalonePool_WithSOSession_WrongSOPIN(t *testing.T) {
	tok := softhsmtest.Provision(t, "wrong-so-pin-pool")
	ctx := newSoftHSMCtx(t, tok.Library)
	slotID := tok.Slot(t, ctx)

	pool, err := newSessionPool(ctx, slotID, nil, 1)
	if err != nil {
		t.Fatalf("newSessionPool() error = %v", err)
	}
	defer func() { _ = pool.Close() }()

	callErr := pool.WithSOSession("0000wrong0000", tok.UserPIN, func(p11.SessionHandle) error {
		t.Error("fn must not run when the SO login itself fails")
		return nil
	})
	if callErr == nil {
		t.Fatal("WithSOSession() expected error for a wrong SO PIN, got nil")
	}

	// The pool must still hand back a usable session afterward (proves the
	// deferred p.ch <- sess ran and the session wasn't left stuck logged out
	// of everything).
	if useErr := pool.WithSession(func(sess p11.SessionHandle) error {
		return ctx.Login(sess, p11.CKU_USER, tok.UserPIN)
	}); useErr != nil && !isPKCS11Error(useErr, p11.CKR_USER_ALREADY_LOGGED_IN) {
		t.Errorf("pool session not usable after a failed SO login: %v", useErr)
	}
}

// TestNewSessionPool_WrongUserPIN proves newSessionPool's own PIN-login
// failure branch: a wrong PIN surfaces the PKCS#11 error (joined with the
// pool's own cleanup) rather than returning a pool that silently isn't
// logged in.
func TestNewSessionPool_WrongUserPIN(t *testing.T) {
	tok := softhsmtest.Provision(t, "newpool-wrong-pin")
	ctx := newSoftHSMCtx(t, tok.Library)
	slotID := tok.Slot(t, ctx)

	wrongPIN := newTestPIN(t, "0000wrong0000")
	if _, err := newSessionPool(ctx, slotID, wrongPIN, 1); err == nil {
		t.Error("newSessionPool() expected error for a wrong PIN, got nil")
	}
}

// TestNewSessionPool_DestroyedPINSecret proves newSessionPool surfaces the
// pin.Open() failure of an already-destroyed secret, joined with the pool's
// own cleanup, rather than panicking or logging in with garbage.
func TestNewSessionPool_DestroyedPINSecret(t *testing.T) {
	tok := softhsmtest.Provision(t, "newpool-destroyed-pin")
	ctx := newSoftHSMCtx(t, tok.Library)
	slotID := tok.Slot(t, ctx)

	pin := newTestPIN(t, tok.UserPIN)
	pin.Destroy()

	if _, err := newSessionPool(ctx, slotID, pin, 1); err == nil {
		t.Error("newSessionPool() expected error for a destroyed PIN secret, got nil")
	}
}

// TestNew_RequireSO_DestroyedSOPIN proves New's RequireSO branch surfaces
// pinPlaintext's failure for an already-destroyed SO PIN secret, and that
// the failure path releases the module reference and closes the session
// pool it had already opened (a fresh New() against the same library must
// still succeed afterward).
func TestNew_RequireSO_DestroyedSOPIN(t *testing.T) {
	tok := softhsmtest.Provision(t, "new-destroyed-so-pin")
	soPIN := newTestPIN(t, tok.SOPIN)
	soPIN.Destroy()

	config := &pivcert.PKCS11StorageConfig{
		LibraryPath: tok.Library,
		TokenLabel:  tok.Label,
		PIN:         newTestPIN(t, tok.UserPIN),
		SOPIN:       soPIN,
		RequireSO:   true,
		SlotID:      -1,
	}
	if _, err := New(config); err == nil {
		t.Error("New() expected error for a destroyed SO PIN secret, got nil")
	}

	// The failed New() must have released its module and pool; a fresh
	// New() against the same library must still succeed.
	s, err := New(&pivcert.PKCS11StorageConfig{
		LibraryPath: tok.Library,
		TokenLabel:  tok.Label,
		PIN:         newTestPIN(t, tok.UserPIN),
		SlotID:      -1,
	})
	if err != nil {
		t.Fatalf("New() after a failed RequireSO New() on the same library error = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

// TestNew_RequireSO_DestroyedUserPIN mirrors
// TestNew_RequireSO_DestroyedSOPIN for the user PIN, which New opens
// second (after the SO PIN succeeds), reaching a different pool.Close()/
// teardown() call site.
func TestNew_RequireSO_DestroyedUserPIN(t *testing.T) {
	tok := softhsmtest.Provision(t, "new-destroyed-user-pin")
	userPIN := newTestPIN(t, tok.UserPIN)
	userPIN.Destroy()

	config := &pivcert.PKCS11StorageConfig{
		LibraryPath: tok.Library,
		TokenLabel:  tok.Label,
		PIN:         userPIN,
		SOPIN:       newTestPIN(t, tok.SOPIN),
		RequireSO:   true,
		SlotID:      -1,
	}
	if _, err := New(config); err == nil {
		t.Error("New() expected error for a destroyed user PIN secret, got nil")
	}
}

// TestAcquireModule_AlreadyInitializedByAnotherConsumer proves acquireModule
// treats CKR_CRYPTOKI_ALREADY_INITIALIZED as success rather than an error
// when some other consumer in the process already called C_Initialize on
// the same library -- the scenario the moduleRef.ownsInit field exists for
// (go-xkms#705): every other acquireModule test in this package is this
// package's own first (and only) initializer of its library path, so this
// branch had never run. It's driven here by initializing the library
// directly through the raw PKCS#11 API before New ever touches it: SoftHSM2
// tracks C_Initialize state per loaded library instance, and the OS loader
// hands back the same instance for a second dlopen of the identical path
// within one process, so acquireModule's own Initialize call genuinely
// observes it as already done.
func TestAcquireModule_AlreadyInitializedByAnotherConsumer(t *testing.T) {
	tok := softhsmtest.Provision(t, "already-initialized")

	externalCtx := p11.New(tok.Library)
	if externalCtx == nil {
		t.Fatalf("p11.New(%q) returned nil", tok.Library)
	}
	if err := externalCtx.Initialize(); err != nil {
		t.Fatalf("externalCtx.Initialize() error = %v", err)
	}
	defer externalCtx.Destroy()
	// Deliberately never Finalize externalCtx: acquireModule must not be
	// the one to unwind another consumer's initialization.

	s, err := New(&pivcert.PKCS11StorageConfig{
		LibraryPath: tok.Library,
		TokenLabel:  tok.Label,
		PIN:         newTestPIN(t, tok.UserPIN),
		SlotID:      -1,
	})
	if err != nil {
		t.Fatalf("New() error = %v, want success when the library was already initialized externally", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

// newSoftHSMCtx initializes and finalizes a *p11.Ctx against a provisioned
// token's library, for tests that need a bare context (no session) to build
// a standalonePool directly.
func newSoftHSMCtx(t *testing.T, libraryPath string) *p11.Ctx {
	t.Helper()
	ctx := p11.New(libraryPath)
	if ctx == nil {
		t.Fatalf("p11.New(%q) returned nil", libraryPath)
	}
	if err := ctx.Initialize(); err != nil {
		t.Fatalf("ctx.Initialize() error = %v", err)
	}
	t.Cleanup(func() {
		_ = ctx.Finalize()
		ctx.Destroy()
	})
	return ctx
}
