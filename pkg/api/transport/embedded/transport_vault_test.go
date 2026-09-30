// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package embedded

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest/vaultservice"
)

// TestPasswordVault_Lifecycle drives the whole vault lifecycle in process
// against the real service, as the user on the context.
func TestPasswordVault_Lifecycle(t *testing.T) {
	tr, err := New(vaultservice.New(t).Service)
	require.NoError(t, err)
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "alice", TenantID: vaultservice.Tenant})

	vaulttest.RunLifecycle(t, ctx, tr)
}

// TestPasswordVault_UsersAreIsolated proves the in-process transport acts on
// the vault of the identity on each call's context and no other.
func TestPasswordVault_UsersAreIsolated(t *testing.T) {
	tr, err := New(vaultservice.New(t).Service)
	require.NoError(t, err)
	alice := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "alice", TenantID: vaultservice.Tenant})
	bob := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "bob", TenantID: vaultservice.Tenant})

	_, err = tr.PasswordVaultEnroll(alice, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: vaulttest.Passkey("alice")})
	require.NoError(t, err)

	bobVault, err := tr.PasswordVaultStatus(bob)
	require.NoError(t, err)
	assert.False(t, bobVault.Initialized)
	assert.Error(t, tr.PasswordStoreUnlock(bob, &transport.PasswordStoreUnlockRequest{PasswordVaultCredential: vaulttest.Passkey("alice")}))
}

func TestPasswordVault_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	for name, call := range vaulttest.Calls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConnected)
		})
	}
}
