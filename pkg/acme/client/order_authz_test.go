// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetOrder_EmptyURL tests error when empty URL is provided
func TestGetOrder_EmptyURL(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := DefaultConfig()
	config.DirectoryURL = "https://example.com/directory"

	client, err := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: privateKey,
		Config:        config,
		Storage:       newMockStorage(),
	})
	require.NoError(t, err)

	order, err := client.GetOrder(context.Background(), "")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidOrderURL))
	assert.Nil(t, order)
}

// TestDeactivateAuthorization_EmptyURL tests error when empty URL is provided
func TestDeactivateAuthorization_EmptyURL(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := DefaultConfig()
	config.DirectoryURL = "https://example.com/directory"

	client, err := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: privateKey,
		Config:        config,
		Storage:       newMockStorage(),
	})
	require.NoError(t, err)

	err = client.DeactivateAuthorization(context.Background(), "")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidAuthorizationURL))
}

// TestGetAuthorization_EmptyURL tests error when empty URL is provided
func TestGetAuthorization_EmptyURL(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := DefaultConfig()
	config.DirectoryURL = "https://example.com/directory"

	client, err := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: privateKey,
		Config:        config,
		Storage:       newMockStorage(),
	})
	require.NoError(t, err)

	authz, err := client.GetAuthorization(context.Background(), "")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidAuthorizationURL))
	assert.Nil(t, authz)
}

// TestNewOrderAuthzErrorTypes tests that all new error types are properly defined
func TestNewOrderAuthzErrorTypes(t *testing.T) {
	errorTypes := []struct {
		err     error
		message string
	}{
		{ErrOrderNotFound, "acme-client: order not found"},
		{ErrOrderListFailed, "acme-client: failed to list orders"},
		{ErrAuthorizationDeactivated, "acme-client: authorization deactivation failed"},
		{ErrInvalidOrderURL, "acme-client: invalid order URL"},
		{ErrInvalidAuthorizationURL, "acme-client: invalid authorization URL"},
		{ErrNoOrdersURL, "acme-client: account has no orders URL"},
	}

	for _, tc := range errorTypes {
		t.Run(tc.message, func(t *testing.T) {
			assert.Equal(t, tc.message, tc.err.Error())
		})
	}

	// Test that errors are distinct
	assert.NotEqual(t, ErrOrderNotFound, ErrOrderListFailed)
	assert.NotEqual(t, ErrInvalidOrderURL, ErrInvalidAuthorizationURL)
}

// TestOrdersListResponseUnmarshal tests the ordersListResponse struct
func TestOrdersListResponseUnmarshal(t *testing.T) {
	t.Run("empty orders list", func(t *testing.T) {
		resp := ordersListResponse{}
		assert.Empty(t, resp.Orders)
	})

	t.Run("with orders", func(t *testing.T) {
		resp := ordersListResponse{
			Orders: []string{
				"https://example.com/order/1",
				"https://example.com/order/2",
			},
		}
		assert.Len(t, resp.Orders, 2)
	})
}
