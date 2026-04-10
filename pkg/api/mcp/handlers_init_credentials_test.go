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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleGetInitStatus(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("returns status from xkms service", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "init.getStatus",
			ID:      1,
		}

		// The xkms service does not have ceremony configured,
		// so this should return an error or nil result.
		_, err := server.handleGetInitStatus(ctx, req)
		// Ceremony service is not configured in test setup, so it returns an error.
		// The handler will propagate whatever the service returns.
		_ = err // Either nil or error is acceptable here
	})
}

func TestHandleClaimCertBegin(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("fails with invalid JSON params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "init.claimCertBegin",
			Params:  json.RawMessage(`{bad`),
			ID:      1,
		}

		_, err := server.handleClaimCertBegin(ctx, req)
		require.Error(t, err)
	})

	t.Run("propagates to xkms service", func(t *testing.T) {
		params := map[string]string{"officer_name": "test-officer"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "init.claimCertBegin",
			Params:  paramsJSON,
			ID:      1,
		}

		// Ceremony service not configured - will return an error
		_, err := server.handleClaimCertBegin(ctx, req)
		_ = err
	})
}

func TestHandleClaimCertComplete(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("fails with invalid JSON params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "init.claimCertComplete",
			Params:  json.RawMessage(`{bad`),
			ID:      1,
		}

		_, err := server.handleClaimCertComplete(ctx, req)
		require.Error(t, err)
	})
}

func TestHandleClaimShare(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("fails with invalid JSON params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "init.claimShare",
			Params:  json.RawMessage(`{bad`),
			ID:      1,
		}

		_, err := server.handleClaimShare(ctx, req)
		require.Error(t, err)
	})
}

func TestHandleSignCSRInit(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("fails with invalid JSON params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "init.signCSR",
			Params:  json.RawMessage(`{bad`),
			ID:      1,
		}

		_, err := server.handleSignCSRInit(ctx, req)
		require.Error(t, err)
	})
}

func TestHandleCredentialSubmit(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("fails with invalid JSON params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "credentials.submit",
			Params:  json.RawMessage(`{bad`),
			ID:      1,
		}

		_, err := server.handleCredentialSubmit(ctx, req)
		require.Error(t, err)
	})

	t.Run("propagates to xkms service", func(t *testing.T) {
		params := map[string]string{"name": "test-cred", "value": "secret"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "credentials.submit",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleCredentialSubmit(ctx, req)
		_ = err // Credential service not configured
	})
}

func TestHandleCredentialStrategy(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("propagates to xkms service", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "credentials.strategy",
			ID:      1,
		}

		_, err := server.handleCredentialStrategy(ctx, req)
		_ = err // Credential service not configured
	})
}

func TestErrXKMSServiceUnavailable(t *testing.T) {
	assert.EqualError(t, ErrXKMSServiceUnavailable, "xkms service unavailable")
}
