// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package known_hosts_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// TestCallbackWithConfirm_NilConfirmMatchesCallback proves nil-confirm
// reproduces Callback's exact NotFoundError behavior for an unpinned host.
func TestCallbackWithConfirm_NilConfirmMatchesCallback(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	pub := newEd25519PublicKey(t)

	cb := known_hosts.CallbackWithConfirm(ctx, store, scope.User, "alice", nil)
	err := cb("ghost.example.com:22", &net.TCPAddr{}, pub)
	var nf *known_hosts.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected NotFoundError with nil confirm, got %T: %v", err, err)
	}

	// A pin must not have been written.
	if _, gerr := store.Get(ctx, scope.User, "alice", "ghost.example.com"); gerr == nil {
		t.Fatal("nil confirm must never persist a pin")
	}
}

// TestCallbackWithConfirm_AcceptPersistsPin verifies an accepting confirm
// pins the host (Source: SourceFirstContact) before the callback returns
// nil, and a subsequent call against the now-pinned host succeeds without
// consulting confirm again.
func TestCallbackWithConfirm_AcceptPersistsPin(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	pub := newEd25519PublicKey(t)

	calls := 0
	confirm := func(_ context.Context, host string, key ssh.PublicKey) (bool, error) {
		calls++
		if host != "fresh.example.com" {
			t.Fatalf("unexpected host passed to confirm: %q", host)
		}
		return true, nil
	}

	cb := known_hosts.CallbackWithConfirm(ctx, store, scope.User, "alice", confirm)
	if err := cb("fresh.example.com:22", &net.TCPAddr{}, pub); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected confirm called once, got %d", calls)
	}

	pin, err := store.Get(ctx, scope.User, "alice", "fresh.example.com")
	if err != nil {
		t.Fatalf("pin not persisted after accept: %v", err)
	}
	if pin.Fingerprint != keys.Fingerprint(pub) {
		t.Fatalf("persisted fingerprint mismatch: %s", pin.Fingerprint)
	}
	if pin.Source != known_hosts.SourceFirstContact {
		t.Fatalf("expected Source=%s, got %s", known_hosts.SourceFirstContact, pin.Source)
	}

	// A second connection to the now-pinned host must succeed WITHOUT
	// invoking confirm again (Verify matches the persisted pin directly).
	if err := cb("fresh.example.com:22", &net.TCPAddr{}, pub); err != nil {
		t.Fatalf("second dial against pinned host: %v", err)
	}
	if calls != 1 {
		t.Fatalf("confirm invoked again after pin persisted: calls=%d", calls)
	}
}

// TestCallbackWithConfirm_RejectReturnsRejectedErrorAndWritesNoPin verifies a
// declining confirm surfaces *RejectedError and leaves no pin behind.
func TestCallbackWithConfirm_RejectReturnsRejectedErrorAndWritesNoPin(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	pub := newEd25519PublicKey(t)

	confirm := func(_ context.Context, _ string, _ ssh.PublicKey) (bool, error) {
		return false, nil
	}

	cb := known_hosts.CallbackWithConfirm(ctx, store, scope.User, "alice", confirm)
	err := cb("declined.example.com:22", &net.TCPAddr{}, pub)
	var rejected *known_hosts.RejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("expected RejectedError, got %T: %v", err, err)
	}
	if rejected.Host != "declined.example.com" {
		t.Fatalf("RejectedError.Host = %q", rejected.Host)
	}
	if rejected.Fingerprint != keys.Fingerprint(pub) {
		t.Fatalf("RejectedError.Fingerprint mismatch")
	}
	if rejected.Error() == "" {
		t.Fatal("RejectedError.Error() empty")
	}

	if _, gerr := store.Get(ctx, scope.User, "alice", "declined.example.com"); gerr == nil {
		t.Fatal("rejected confirm must never persist a pin")
	}
}

// TestCallbackWithConfirm_MismatchNeverInvokesConfirm proves a MITM
// fingerprint mismatch against an EXISTING pin hard-fails without ever
// consulting confirm — TOFU only ever covers absence, never a conflict.
func TestCallbackWithConfirm_MismatchNeverInvokesConfirm(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	legit := newEd25519PublicKey(t)
	mitm := newEd25519PublicKey(t)

	if err := store.Add(ctx, known_hosts.PinFromPublicKey("bastion.example.com", scope.User, "alice", legit, known_hosts.SourceManual)); err != nil {
		t.Fatalf("Add: %v", err)
	}

	calls := 0
	confirm := func(_ context.Context, _ string, _ ssh.PublicKey) (bool, error) {
		calls++
		return true, nil
	}

	cb := known_hosts.CallbackWithConfirm(ctx, store, scope.User, "alice", confirm)
	err := cb("bastion.example.com:22", &net.TCPAddr{}, mitm)
	var mm *known_hosts.MismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected MismatchError, got %T: %v", err, err)
	}
	if calls != 0 {
		t.Fatalf("confirm must never be invoked on a mismatch, got %d calls", calls)
	}
}

// TestCallbackWithConfirm_ConfirmErrorPropagates proves a Confirmer error
// propagates unchanged as the handshake failure.
func TestCallbackWithConfirm_ConfirmErrorPropagates(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	pub := newEd25519PublicKey(t)

	boom := errors.New("prompt backend unavailable")
	confirm := func(_ context.Context, _ string, _ ssh.PublicKey) (bool, error) {
		return false, boom
	}

	cb := known_hosts.CallbackWithConfirm(ctx, store, scope.User, "alice", confirm)
	err := cb("ghost.example.com:22", &net.TCPAddr{}, pub)
	if !errors.Is(err, boom) {
		t.Fatalf("expected confirm error to propagate, got %v", err)
	}
}

// TestCallbackWithConfirm_PersistFailurePropagates verifies a failing
// store.Add on accept surfaces as the handshake error (the pin is not
// silently dropped).
func TestCallbackWithConfirm_PersistFailurePropagates(t *testing.T) {
	ctx := context.Background()
	pub := newEd25519PublicKey(t)

	confirm := func(_ context.Context, _ string, _ ssh.PublicKey) (bool, error) {
		return true, nil
	}

	cb := known_hosts.CallbackWithConfirm(ctx, addFailStore{}, scope.User, "alice", confirm)
	err := cb("fresh.example.com:22", &net.TCPAddr{}, pub)
	if err == nil {
		t.Fatal("expected error when the accepting store.Add fails")
	}
}

// addFailStore always reports the host as unpinned, and always fails Add —
// used to exercise CallbackWithConfirm's persist-failure propagation.
type addFailStore struct{}

func (addFailStore) Add(context.Context, *known_hosts.Pin) error {
	return errors.New("injected add failure")
}
func (addFailStore) Get(_ context.Context, sc scope.Scope, owner, host string) (*known_hosts.Pin, error) {
	return nil, &known_hosts.NotFoundError{Scope: string(sc), Owner: owner, Host: host}
}
func (addFailStore) List(context.Context, scope.Scope, string) ([]*known_hosts.Pin, error) {
	return nil, nil
}
func (addFailStore) Remove(_ context.Context, sc scope.Scope, owner, host string) error {
	return &known_hosts.NotFoundError{Scope: string(sc), Owner: owner, Host: host}
}
