//go:build !frost

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

package mcp

import (
	"context"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_RouteFrostMethods_StubBehavior(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "frost.generateNonces",
		ID:      1,
	}

	result, frostErr, handled := server.routeFrostMethods(context.Background(), req)

	// When built without frost tag, FROST methods return an error
	assert.True(t, handled)
	assert.Nil(t, result)
	require.Error(t, frostErr)
	assert.Contains(t, frostErr.Error(), "FROST support not compiled")

	// go-xkms#930: the stub's refusal must reach dispatch as a *KeyOpError
	// carrying ErrCodeMethodNotFound (matching pkg/api/grpc/service_frost_stub.go's
	// codes.Unimplemented), not a bare error that module_mcp.go can only
	// report as wire.CodeInternal.
	var keyErr *KeyOpError
	require.ErrorAs(t, frostErr, &keyErr)
	assert.Equal(t, ErrCodeMethodNotFound, keyErr.Code)
}

// TestServer_HandleRequest_FrostMethodAsNotification tests FROST method as notification (no ID)
// Note: According to the actual implementation in server.go (lines 298-303), FROST methods
// return an error response even for notifications when an error occurs.
func TestServer_HandleRequest_FrostMethodAsNotification(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	ctx := context.Background()

	// Test a FROST method as a notification (no ID)
	// The FROST stub returns an error, and the server returns an error response
	// even for notifications in this case (see server.go lines 298-303)
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "frost.someMethod",
		// No ID = notification
	}

	resp := invokeRequest(server, ctx, req)
	// FROST methods that fail return an error response even for notifications
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	// go-xkms#930: "not compiled in" is Method not found, not Internal.
	assert.Equal(t, ErrCodeMethodNotFound, resp.Error.Code)
}

// TestServer_HandleRequest_FrostMethodWithError tests FROST method that returns error
func TestServer_HandleRequest_FrostMethodWithError(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	ctx := context.Background()

	// Without the frost build tag, every frost.* method is the stub, which
	// reports that FROST is not compiled in as ErrCodeMethodNotFound
	// (go-xkms#930), matching pkg/api/grpc/service_frost_stub.go's
	// codes.Unimplemented.
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "frost.generateNonces",
		ID:      1,
	}

	resp := invokeRequest(server, ctx, req)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeMethodNotFound, resp.Error.Code)
}
