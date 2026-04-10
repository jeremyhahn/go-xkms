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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_RouteFrostMethods_StubBehavior(t *testing.T) {
	setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "frost.generateNonces",
		ID:      1,
	}

	result, frostErr, handled := server.routeFrostMethods(req)

	// When built without frost tag, FROST methods return an error
	assert.True(t, handled)
	assert.Nil(t, result)
	assert.Error(t, frostErr)
	assert.Contains(t, frostErr.Error(), "FROST support not compiled")
}

// TestServer_HandleRequest_FrostMethodAsNotification tests FROST method as notification (no ID)
// Note: According to the actual implementation in server.go (lines 298-303), FROST methods
// return an error response even for notifications when an error occurs.
func TestServer_HandleRequest_FrostMethodAsNotification(t *testing.T) {
	setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{Addr: "localhost:0"})
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

	resp := server.handleRequest(ctx, req, nil)
	// FROST methods that fail return an error response even for notifications
	require.NotNil(t, resp)
	assert.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeInternalError, resp.Error.Code)
}
