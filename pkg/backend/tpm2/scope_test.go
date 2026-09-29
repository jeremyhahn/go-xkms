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

package tpm2

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// errScopeCause is a stand-in cause for the wrapper error tests.
var errScopeCause = errors.New("test: scope cause")

// TestKeyScope_BindParentsPerScope proves the system scope defaults the
// caller's own parent, as the backend always did, while a tenant scope binds
// a copy so the caller never keeps a transient storage-key handle.
func TestKeyScope_BindParentsPerScope(t *testing.T) {
	parent := &types.KeyAttributes{CN: "parent"}

	system := &keyScope{parent: parent}
	attrs := &types.KeyAttributes{CN: "k"}
	assert.Same(t, attrs, system.bind(attrs))
	assert.Same(t, parent, attrs.Parent)

	own := &types.KeyAttributes{CN: "own-parent"}
	explicit := &types.KeyAttributes{CN: "k", Parent: own}
	system.bind(explicit)
	assert.Same(t, own, explicit.Parent, "the system scope keeps a caller's explicit parent")

	tenant := &keyScope{tenant: "acme", parent: parent}
	caller := &types.KeyAttributes{CN: "k", TenantID: "acme", Parent: own}
	bound := tenant.bind(caller)
	assert.NotSame(t, caller, bound)
	assert.Same(t, parent, bound.Parent)
	assert.Same(t, own, caller.Parent, "the caller's attributes are untouched")
}

// TestKeyScope_CloseWithoutRelease proves an unscoped scope closes cleanly
// and a scoped one returns its release error.
func TestKeyScope_CloseWithoutRelease(t *testing.T) {
	assert.NoError(t, (&keyScope{}).close())
	scoped := &keyScope{release: func() error { return errScopeCause }}
	assert.ErrorIs(t, scoped.close(), errScopeCause)
}

// TestIsSystemTenant proves "" and "system" name the system scope and a
// tenant ID does not.
func TestIsSystemTenant(t *testing.T) {
	assert.True(t, isSystemTenant(""))
	assert.True(t, isSystemTenant("system"))
	assert.False(t, isSystemTenant("acme"))
}

// TestPublicAuthPolicy_RejectsMalformedPublic proves a public area that does
// not decode is an error, not an empty digest.
func TestPublicAuthPolicy_RejectsMalformedPublic(t *testing.T) {
	_, err := publicAuthPolicy([]byte{0x01})
	assert.Error(t, err)

	keys := store.NewFileBackend(slog.New(slog.NewTextHandler(io.Discard, nil)), storage.NewMemory())
	_, err = authPolicyOf(keys, &types.KeyAttributes{CN: "missing"})
	assert.Error(t, err, "a key with no public blob has no authPolicy")
}

// TestScopeErrors proves each scope error names its subject and unwraps to
// its cause.
func TestScopeErrors(t *testing.T) {
	scopeErr := &ScopeError{Tenant: "", Err: errScopeCause}
	assert.Contains(t, scopeErr.Error(), `"system"`)
	assert.ErrorIs(t, scopeErr, errScopeCause)

	assignErr := &AssignmentError{Tenant: "acme", Object: "key/k", Err: errScopeCause}
	assert.Contains(t, assignErr.Error(), `"key/k"`)
	assert.Contains(t, assignErr.Error(), `"acme"`)
	assert.ErrorIs(t, assignErr, errScopeCause)

	reserved := &ReservedObjectError{CN: "tpm-storage-key"}
	assert.Contains(t, reserved.Error(), "tpm-storage-key")
	assert.ErrorIs(t, reserved, ErrReservedObject)
}

// TestBackend_WithoutScopeProvider proves a backend with no provider keeps
// its single-scope behaviour: tenant IDs select nothing, reserved names are
// ordinary names, and sealing is not tenant-bound.
func TestBackend_WithoutScopeProvider(t *testing.T) {
	keys := store.NewFileBackend(slog.New(slog.NewTextHandler(io.Discard, nil)), storage.NewMemory())
	b := &Backend{keyBackend: keys}

	got, err := b.keyStore("acme")
	require.NoError(t, err)
	assert.Same(t, keys, got)
	assert.NoError(t, b.refuseReserved(&types.KeyAttributes{CN: "tpm-storage-key"}))
	assert.False(t, b.TenantBoundSealing())

	b.SetScopeProvider(nil)
	assert.False(t, b.TenantBoundSealing())
}
