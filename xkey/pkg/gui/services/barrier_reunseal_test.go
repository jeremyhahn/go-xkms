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

package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBarrierService_ReunsealKeepsHandedOutBackendUsable is the property the
// app-lock seal-on-lock behaviour depends on.
//
// The post-unseal hook wires every barrier-backed store once per process and
// hands each of them a backend wrapping the live barrier. If a re-unseal
// built a replacement barrier instead of reopening the existing one, those
// stores would still point at the sealed object, with no route back: the app
// would unlock while every encrypted store stayed unreadable until restart.
// Reading through the handle obtained BEFORE the lock is what proves that
// cannot happen.
func TestBarrierService_ReunsealKeepsHandedOutBackendUsable(t *testing.T) {
	svc := newTestBarrierService(t)
	ctx := context.Background()
	const password = "barrier-credential"

	require.NoError(t, svc.Initialize(password, "passphrase"))

	// The handle a downstream store received from the post-unseal hook.
	backend := svc.GetBackend()
	require.NotNil(t, backend)
	require.NoError(t, backend.Put(ctx, "secrets/entry", []byte("stored before the lock")))

	// The inactivity lock.
	require.NoError(t, svc.Seal())
	require.False(t, svc.IsUnsealed())

	// The unlock.
	require.NoError(t, svc.Unseal(password, "passphrase"))
	require.True(t, svc.IsUnsealed())

	got, err := backend.Get(ctx, "secrets/entry")
	require.NoError(t, err,
		"the backend handed to stores before the lock must still read after "+
			"the unlock; a replacement barrier would strand every store")
	assert.Equal(t, []byte("stored before the lock"), got)

	require.NoError(t, backend.Put(ctx, "secrets/after", []byte("stored after the unlock")))
	got, err = backend.Get(ctx, "secrets/after")
	require.NoError(t, err)
	assert.Equal(t, []byte("stored after the unlock"), got)
}

// TestBarrierService_ReunsealRunsPostUnsealHookOnlyOnce checks that reopening
// the barrier does not re-fire the hook. The hook initialises the data
// directory and is guarded against running twice, so calling it again on
// every unlock would report a failure on a successful unlock.
func TestBarrierService_ReunsealRunsPostUnsealHookOnlyOnce(t *testing.T) {
	svc := newTestBarrierService(t)
	const password = "barrier-credential"

	calls := 0
	svc.SetPostUnsealHook(func() error {
		calls++
		return nil
	})

	require.NoError(t, svc.Initialize(password, "passphrase"))
	after := calls

	require.NoError(t, svc.Seal())
	require.NoError(t, svc.Unseal(password, "passphrase"))

	assert.Equal(t, after, calls,
		"reopening the existing barrier must not re-run the post-unseal hook: "+
			"the stores it wires are already bound to this barrier")
}

// TestBarrierService_ReunsealIgnoresRequestedStrategy pins the reopen path
// against the strategy argument.
//
// A barrier records its own strategy in the sealed root key blob and resolves
// it from there, so the ID a caller passes to Unseal is not an input to
// reopening one. The app lock passes whatever the config holds, which can be
// empty when the barrier predates that config field, and an empty ID makes
// Unseal resolve the "best available" strategy — on a TPM-capable machine
// that is a different ID than a passphrase barrier was sealed with. If a
// mismatch pushed the call into the rebuild path, every store wired to the
// live barrier would be stranded on the sealed object.
func TestBarrierService_ReunsealIgnoresRequestedStrategy(t *testing.T) {
	svc := newTestBarrierService(t)
	ctx := context.Background()
	const password = "barrier-credential"

	require.NoError(t, svc.Initialize(password, "passphrase"))
	backend := svc.GetBackend()
	require.NotNil(t, backend)
	require.NoError(t, backend.Put(ctx, "secrets/entry", []byte("stored before the lock")))

	require.NoError(t, svc.Seal())

	// The app lock passes an empty strategy when the config does not carry one.
	require.NoError(t, svc.Unseal(password, ""))
	require.True(t, svc.IsUnsealed())

	got, err := backend.Get(ctx, "secrets/entry")
	require.NoError(t, err,
		"reopening must not depend on the caller naming the sealing strategy")
	assert.Equal(t, []byte("stored before the lock"), got)
}

// TestBarrierService_ReunsealRejectsWrongCredential checks that reopening in
// place is still a real credential check, and that a rejected attempt leaves
// the barrier sealed and retryable rather than tearing it down.
func TestBarrierService_ReunsealRejectsWrongCredential(t *testing.T) {
	svc := newTestBarrierService(t)
	const password = "barrier-credential"

	require.NoError(t, svc.Initialize(password, "passphrase"))
	require.NoError(t, svc.Seal())

	require.Error(t, svc.Unseal("wrong-credential", "passphrase"),
		"reopening in place must still verify the credential")
	assert.False(t, svc.IsUnsealed(), "a rejected attempt must leave the barrier sealed")

	require.NoError(t, svc.Unseal(password, "passphrase"),
		"a rejected attempt must not prevent a later correct one")
	assert.True(t, svc.IsUnsealed())
}
