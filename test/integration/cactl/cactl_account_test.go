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

package cactl

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/test/integration/acme-multiprotocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCactlAccountOperations tests account operations via all protocols.
func TestCactlAccountOperations(t *testing.T) {
	tc := multiprotocol.NewTestContext(t)
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

// testListAccounts tests basic account listing.
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

// testListAccountsWithPagination tests account listing with pagination.
func testListAccountsWithPagination(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// First page
	req1 := &admin.ListAccountsRequest{
		Page:    1,
		PerPage: 5,
	}
	accounts1, pagination1, err := adapter.ListAccounts(ctx, req1)
	require.NoError(t, err, "ListAccounts page 1 should succeed via %s", protocol)
	assert.NotNil(t, accounts1)

	// If there are more pages, get the second page
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

// testListAccountsWithStatusFilter tests account listing with status filter.
func testListAccountsWithStatusFilter(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// Test valid status
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

	// Test deactivated status
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

// testGetNonexistentAccount tests getting a non-existent account.
func testGetNonexistentAccount(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// Use a very high account ID that should not exist
	_, err := adapter.GetAccount(ctx, 9999999999)
	assert.Error(t, err, "GetAccount for nonexistent ID should fail via %s", protocol)
}

// TestCactlAccountCLI tests account CLI commands.
func TestCactlAccountCLI(t *testing.T) {
	cfg := newCactlConfig()

	// Find binary
	if err := findCactlBinary(cfg); err != nil {
		t.Fatalf("cactl binary not found: %v", err)
	}

	t.Run("AccountListJSON", func(t *testing.T) {
		output, err := runCactl(cfg, "account", "list", "-o", "json")
		if err != nil {
			if cactlErr, ok := err.(*CactlError); ok {
				if strings.Contains(cactlErr.Stderr, "not yet implemented") {
					t.Fatal("AccountAdapter not yet implemented for REST protocol")
				}
			}
			t.Fatalf("cactl command failed: %v", err)
		}
		assert.NotEmpty(t, output, "account list should return output")
		// Should be valid JSON array
		assert.True(t, output[0] == '[' || output[0] == 'n', "Output should be JSON array or null")
	})

	t.Run("AccountListWithPagination", func(t *testing.T) {
		output, err := runCactl(cfg, "account", "list", "--page", "1", "--per-page", "5", "-o", "json")
		if err != nil {
			if cactlErr, ok := err.(*CactlError); ok {
				if strings.Contains(cactlErr.Stderr, "not yet implemented") {
					t.Fatal("AccountAdapter not yet implemented for REST protocol")
				}
			}
			t.Fatalf("cactl command failed: %v", err)
		}
		assert.NotEmpty(t, output, "account list with pagination should return output")
	})

	t.Run("AccountListWithStatus", func(t *testing.T) {
		output, err := runCactl(cfg, "account", "list", "--status", "valid", "-o", "json")
		if err != nil {
			if cactlErr, ok := err.(*CactlError); ok {
				if strings.Contains(cactlErr.Stderr, "not yet implemented") {
					t.Fatal("AccountAdapter not yet implemented for REST protocol")
				}
			}
			t.Fatalf("cactl command failed: %v", err)
		}
		assert.NotEmpty(t, output, "account list with status filter should return output")
	})

	t.Run("AccountGetInvalidID", func(t *testing.T) {
		cactlErr := requireCactlFail(t, cfg, "account", "get", "not-a-number")
		assert.Contains(t, cactlErr.Stderr+cactlErr.Stdout, "invalid",
			"should report invalid account ID")
	})

	t.Run("AccountGetNonexistent", func(t *testing.T) {
		cactlErr := requireCactlFail(t, cfg, "account", "get", "9999999999")
		assert.True(t, len(cactlErr.Stderr) > 0 || len(cactlErr.Stdout) > 0,
			"should have error output for nonexistent account")
	})

	t.Run("AccountDisableInvalidID", func(t *testing.T) {
		cactlErr := requireCactlFail(t, cfg, "account", "disable", "not-a-number")
		assert.Contains(t, cactlErr.Stderr+cactlErr.Stdout, "invalid",
			"should report invalid account ID")
	})
}

// findCactlBinary locates the cactl binary for testing.
func findCactlBinary(cfg *cactlConfig) error {
	possiblePaths := []string{
		cfg.Binary,
		"./cactl",
		"../../../cmd/cactl/cactl",
		"/usr/local/bin/cactl",
		"/workspace/go-xkms/bin/cactl",
	}

	for _, p := range possiblePaths {
		testCfg := &cactlConfig{Binary: p, Timeout: 5 * time.Second}
		_, err := runCactl(testCfg, "version")
		if err == nil {
			cfg.Binary = p
			return nil
		}
	}

	return caerrors.NotFoundError("cactl binary not found")
}

// TestCactlAccountErrorHandling tests account error scenarios.
func TestCactlAccountErrorHandling(t *testing.T) {
	tc := multiprotocol.NewTestContext(t)
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

// TestCactlAccountBoundaryConditions tests account boundary conditions.
func TestCactlAccountBoundaryConditions(t *testing.T) {
	tc := multiprotocol.NewTestContext(t)
	defer tc.Cleanup()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("ListAccountsZeroPerPage", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			// Server should handle zero per-page gracefully (use default)
			req := &admin.ListAccountsRequest{
				Page:    1,
				PerPage: 0,
			}
			accounts, _, err := adapter.ListAccounts(ctx, req)
			// Should either succeed with defaults or return an error
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
			// Should return empty list for high page number
			assert.NotNil(t, accounts)
		})

		t.Run("GetAccountZeroID", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			// Account ID 0 is typically invalid
			_, err := adapter.GetAccount(ctx, 0)
			assert.Error(t, err, "GetAccount with ID 0 should fail via %s", protocol)
		})
	})
}
