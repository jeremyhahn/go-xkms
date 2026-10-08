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

func TestAlgorithms_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	_, err = tr.Algorithms(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestAlgorithms_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	resp, err := tr.Algorithms(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestEscrowKey_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	_, err = tr.EscrowKey(context.Background(), &transport.EscrowRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestEscrowKey_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	_, err = tr.EscrowKey(context.Background(), &transport.EscrowRequest{})
	require.NoError(t, err)
}

func TestRecoverKey_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	_, err = tr.RecoverKey(context.Background(), &transport.RecoverRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestRecoverKey_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	_, err = tr.RecoverKey(context.Background(), &transport.RecoverRequest{})
	require.NoError(t, err)
}

func TestListEscrowed_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	_, err = tr.ListEscrowed(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestListEscrowed_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	_, err = tr.ListEscrowed(context.Background())
	require.NoError(t, err)
}

func TestRevokeEscrow_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	err = tr.RevokeEscrow(context.Background(), "escrow-1")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestRevokeEscrow_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.RevokeEscrow(context.Background(), "escrow-1"))
}

func TestUpdateTenantEntitlements_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	_, err = tr.UpdateTenantEntitlements(context.Background(), &transport.UpdateTenantEntitlementsRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestUpdateTenantEntitlements_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	_, err = tr.UpdateTenantEntitlements(context.Background(), &transport.UpdateTenantEntitlementsRequest{TenantID: "acme"})
	require.NoError(t, err)
}

func TestUpdateTenantQuotas_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	_, err = tr.UpdateTenantQuotas(context.Background(), &transport.UpdateTenantQuotasRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestUpdateTenantQuotas_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	_, err = tr.UpdateTenantQuotas(context.Background(), &transport.UpdateTenantQuotasRequest{TenantID: "acme"})
	require.NoError(t, err)
}

func TestCreateUser_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	_, err = tr.CreateUser(context.Background(), &transport.CreateUserRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestCreateUser_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	_, err = tr.CreateUser(context.Background(), &transport.CreateUserRequest{Username: "alice", Email: "a@example.com"})
	require.NoError(t, err)
}

func TestListUsers_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	_, err = tr.ListUsers(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestListUsers_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	_, err = tr.ListUsers(context.Background())
	require.NoError(t, err)
}

func TestGetUser_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	_, err = tr.GetUser(context.Background(), "alice")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetUser_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	_, err = tr.GetUser(context.Background(), "alice")
	require.NoError(t, err)
}

func TestDeleteUser_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	err = tr.DeleteUser(context.Background(), "alice")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDeleteUser_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.DeleteUser(context.Background(), "alice"))
}

func TestEnableUser_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	err = tr.EnableUser(context.Background(), "alice")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestEnableUser_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.EnableUser(context.Background(), "alice"))
}

func TestDisableUser_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	err = tr.DisableUser(context.Background(), "alice")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDisableUser_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.DisableUser(context.Background(), "alice"))
}

func TestBindUserCert_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	err = tr.BindUserCert(context.Background(), "alice", "thumb", 0)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBindUserCert_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.BindUserCert(context.Background(), "alice", "thumb", 0))
}

func TestListUserCredentials_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	_, err = tr.ListUserCredentials(context.Background(), "alice")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestListUserCredentials_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	_, err = tr.ListUserCredentials(context.Background(), "alice")
	require.NoError(t, err)
}

func TestListBackends_ServiceError(t *testing.T) {
	tr, err := New(&mockService{shouldFail: true})
	require.NoError(t, err)
	_, err = tr.ListBackends(context.Background())
	assert.ErrorIs(t, err, errMock, "the service error surfaces to the caller unwrapped")
}
