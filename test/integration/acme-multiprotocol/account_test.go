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

//go:build integration

package multiprotocol

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// defaultTimeout bounds each adapter call this package's tests make.
const defaultTimeout = 30 * time.Second

// testTenantPrefix marks tenants these tests create, for identification in
// server-side logs.
const testTenantPrefix = "integration-test-"

// TestAccountOperationsMultiProtocol tests account operations via every
// configured protocol adapter. Moved from test/integration/cactl
// (go-xkms#949): this exercises pkg/acme/api's AdminAdapter directly, not
// the xkmsctl/cactl CLI, so it belongs beside this package's other
// adapter-level coverage (tenant_test.go, role_test.go) rather than the
// CLI-driven test/integration/acmeadmin.
func TestAccountOperationsMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
	defer tc.Cleanup()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("ListAccounts", func(t *testing.T) {
			testListAccounts(t, adapter, protocol)
		})

		t.Run("ListAccountsWithPagination", func(t *testing.T) {
			testListAccountsWithPagination(t, adapter, protocol)
		})

		t.Run("ListAccountsWithStatusFilter", func(t *testing.T) {
			testListAccountsWithStatusFilter(t, adapter, protocol)
		})

		t.Run("GetNonexistentAccount", func(t *testing.T) {
			testGetNonexistentAccount(t, adapter, protocol)
		})
	})
}

func testListAccounts(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req := &admin.ListAccountsRequest{
		Page:    1,
		PerPage: 20,
	}

	accounts, pagination, err := adapter.ListAccounts(ctx, req)
	require.NoError(t, err, "ListAccounts should succeed via %s", protocol)
	assert.NotNil(t, accounts, "accounts should not be nil")

	if pagination != nil {
		assert.GreaterOrEqual(t, pagination.Page, 1)
		assert.GreaterOrEqual(t, pagination.Total, 0)
	}
}

func testListAccountsWithPagination(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req1 := &admin.ListAccountsRequest{
		Page:    1,
		PerPage: 5,
	}
	accounts1, pagination1, err := adapter.ListAccounts(ctx, req1)
	require.NoError(t, err, "ListAccounts page 1 should succeed via %s", protocol)
	assert.NotNil(t, accounts1)

	if pagination1 != nil && pagination1.Total > 5 {
		req2 := &admin.ListAccountsRequest{
			Page:    2,
			PerPage: 5,
		}
		accounts2, _, err := adapter.ListAccounts(ctx, req2)
		require.NoError(t, err, "ListAccounts page 2 should succeed via %s", protocol)
		assert.NotNil(t, accounts2)
	}
}

func testListAccountsWithStatusFilter(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	reqValid := &admin.ListAccountsRequest{
		Page:    1,
		PerPage: 10,
		Status:  "valid",
	}
	validAccounts, _, err := adapter.ListAccounts(ctx, reqValid)
	require.NoError(t, err, "ListAccounts with status=valid should succeed via %s", protocol)
	for _, acc := range validAccounts {
		assert.Equal(t, "valid", acc.Status, "All returned accounts should have status=valid via %s", protocol)
	}

	reqDeactivated := &admin.ListAccountsRequest{
		Page:    1,
		PerPage: 10,
		Status:  "deactivated",
	}
	deactivatedAccounts, _, err := adapter.ListAccounts(ctx, reqDeactivated)
	require.NoError(t, err, "ListAccounts with status=deactivated should succeed via %s", protocol)
	for _, acc := range deactivatedAccounts {
		assert.Equal(t, "deactivated", acc.Status, "All returned accounts should have status=deactivated via %s", protocol)
	}
}

func testGetNonexistentAccount(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	_, err := adapter.GetAccount(ctx, 9999999999)
	assert.Error(t, err, "GetAccount for nonexistent ID should fail via %s", protocol)
}

// TestAccountErrorHandlingMultiProtocol tests account error scenarios.
func TestAccountErrorHandlingMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
	defer tc.Cleanup()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("DisableNonexistentAccount", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			err := adapter.DisableAccount(ctx, 9999999999)
			assert.Error(t, err, "DisableAccount for nonexistent ID should fail via %s", protocol)
		})
	})
}

// TestAccountBoundaryConditionsMultiProtocol tests account boundary conditions.
func TestAccountBoundaryConditionsMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
	defer tc.Cleanup()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("ListAccountsZeroPerPage", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			req := &admin.ListAccountsRequest{
				Page:    1,
				PerPage: 0,
			}
			accounts, _, err := adapter.ListAccounts(ctx, req)
			if err == nil {
				assert.NotNil(t, accounts)
			}
		})

		t.Run("ListAccountsHighPage", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			req := &admin.ListAccountsRequest{
				Page:    9999,
				PerPage: 10,
			}
			accounts, _, err := adapter.ListAccounts(ctx, req)
			require.NoError(t, err, "ListAccounts with high page should succeed via %s", protocol)
			assert.NotNil(t, accounts)
		})

		t.Run("GetAccountZeroID", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			_, err := adapter.GetAccount(ctx, 0)
			assert.Error(t, err, "GetAccount with ID 0 should fail via %s", protocol)
		})
	})
}
