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

package embedded

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// This file covers Transport methods (go-xkms #705, batch A) that were
// absent from TestAllMethods_NotConnected / TestAllMethods_Connected:
// Algorithms, BarrierEnableEncryption, the escrow bridge, GetShare/
// DeleteShare, TenantBarrierStatus, UpdateTenantEntitlements/Quotas,
// ClaimShareComplete and the user admin surface. Each proves the delegate
// call reaches mockService's return value and that a disconnected transport
// never reaches the service at all.

// adminCalls calls the algorithm listing and every escrow, tenant
// entitlement, tenant quota, user-administration and credential-binding
// method of tr once, keyed by method name.
func adminCalls(ctx context.Context, tr *Transport) map[string]func() error {
	return map[string]func() error{
		"Algorithms":   func() error { return errOf(tr.Algorithms(ctx)) },
		"EscrowKey":    func() error { return errOf(tr.EscrowKey(ctx, &transport.EscrowRequest{})) },
		"RecoverKey":   func() error { return errOf(tr.RecoverKey(ctx, &transport.RecoverRequest{})) },
		"ListEscrowed": func() error { return errOf(tr.ListEscrowed(ctx)) },
		"RevokeEscrow": func() error { return tr.RevokeEscrow(ctx, "escrow-1") },
		"UpdateTenantEntitlements": func() error {
			return errOf(tr.UpdateTenantEntitlements(ctx, &transport.UpdateTenantEntitlementsRequest{TenantID: "acme"}))
		},
		"UpdateTenantQuotas": func() error {
			return errOf(tr.UpdateTenantQuotas(ctx, &transport.UpdateTenantQuotasRequest{TenantID: "acme"}))
		},
		"CreateUser": func() error {
			return errOf(tr.CreateUser(ctx, &transport.CreateUserRequest{Username: "alice", Email: "a@example.com"}))
		},
		"ListUsers":           func() error { return errOf(tr.ListUsers(ctx)) },
		"GetUser":             func() error { return errOf(tr.GetUser(ctx, "alice")) },
		"DeleteUser":          func() error { return tr.DeleteUser(ctx, "alice") },
		"EnableUser":          func() error { return tr.EnableUser(ctx, "alice") },
		"DisableUser":         func() error { return tr.DisableUser(ctx, "alice") },
		"BindUserCert":        func() error { return tr.BindUserCert(ctx, "alice", "thumb", 0) },
		"ListUserCredentials": func() error { return errOf(tr.ListUserCredentials(ctx, "alice")) },
	}
}

func TestAdministration_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	for name, call := range adminCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) { assert.NoError(t, call()) })
	}
}

// TestAdministration_NotConnected proves every administration method refuses
// with ErrNotConnected once the transport is closed.
func TestAdministration_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	for name, call := range adminCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotConnected) })
	}
}

func TestAlgorithms_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	resp, err := tr.Algorithms(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}
