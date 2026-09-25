//go:build frost

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

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// TestServer_HandleRequest_FrostMethodMissingParams pins the frost-tagged
// counterpart of TestServer_HandleRequest_FrostMethodWithError: with FROST
// compiled in, a frost.* call without params fails param decoding and
// reports invalid params (-32602), like every other MCP handler (#774).
func TestServer_HandleRequest_FrostMethodMissingParams(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "frost.generateNonces",
		ID:      1,
	}

	resp := invokeRequest(server, context.Background(), req)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeInvalidParams, resp.Error.Code)
}
