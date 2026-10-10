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

package mcp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest/vaultservice"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// newVaultTransport connects this transport in process, through the MCP
// module's tool registration, to an MCP server over the real service with
// the personal vault wired in.
func newVaultTransport(t *testing.T) *Transport {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	backend, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	ks, err := xkms.New(&xkms.BackendConfig{Backend: backend, CertStorage: storage.New()})
	require.NoError(t, err)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
		DefaultBackend: "software",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	vaultservice.Wire(t, svc)
	srv, err := xkmsmcp.NewServer(&xkmsmcp.Config{
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
	})
	require.NoError(t, err)
	return connectInProcessToModule(t, srv)
}

// vaultUser returns a context carrying subject's identity in the fixture's
// tenant.
func vaultUser(subject string) context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: subject, TenantID: vaultservice.Tenant, Roles: []string{"admin"},
	})
}

// TestPasswordVault_Lifecycle drives the whole vault lifecycle through this
// transport, the MCP module and server, and the real service.
func TestPasswordVault_Lifecycle(t *testing.T) {
	vaulttest.RunLifecycle(t, vaultUser("alice"), newVaultTransport(t))
}

// TestPasswordVault_ErrorsKeepTheirCode proves a vault refusal reaches the
// caller with its JSON-RPC code: a rejected credential is Unauthorized and an
// unknown factor is Not found.
func TestPasswordVault_ErrorsKeepTheirCode(t *testing.T) {
	tr := newVaultTransport(t)
	ctx := vaultUser("alice")

	_, err := tr.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: vaulttest.Passkey("key")})
	require.NoError(t, err)
	require.NoError(t, tr.PasswordStoreLock(ctx))

	wrong := vaulttest.Passkey("key")
	wrong.Secret = make([]byte, 32)
	err = tr.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{PasswordVaultCredential: wrong})
	var rpcErr *RPCError
	require.ErrorAs(t, err, &rpcErr)
	assert.Equal(t, xkmsmcp.ErrCodeUnauthorized, rpcErr.Code)

	require.NoError(t, tr.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{PasswordVaultCredential: vaulttest.Passkey("key")}))
	err = tr.PasswordVaultRemoveFactor(ctx, &transport.PasswordVaultRemoveFactorRequest{FactorID: "no-such-factor"})
	require.Error(t, err)
	require.ErrorAs(t, err, &rpcErr)
	assert.Equal(t, sdkssh.JSONRPCCodeNotFound, rpcErr.Code)
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
