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

//go:build !frost

package mcp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleDeleteKey_SymmetricFallback exercises the fallback path in
// handleDeleteKey where the key is not found in the "software" backend and
// the code falls through to try the "symmetric" backend.
func TestHandleDeleteKey_SymmetricFallback(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Try deleting a key that doesn't exist in either backend.
	// This exercises lines 340-344 (the symmetric fallback branch).
	params := DeleteKeyParams{KeyID: "nonexistent-key"}
	paramsJSON, err := json.Marshal(params)
	require.NoError(t, err)

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.deleteKey",
		ID:      1,
		Params:  paramsJSON,
	}

	_, err = server.handleDeleteKey(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find key")
}

// TestHandleDeleteKey_SpecificBackendNotFound exercises the error path when
// a specified backend key does not exist.
func TestHandleDeleteKey_SpecificBackendNotFound(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	params := DeleteKeyParams{KeyID: "missing-key", Backend: "software"}
	paramsJSON, err := json.Marshal(params)
	require.NoError(t, err)

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.deleteKey",
		ID:      1,
		Params:  paramsJSON,
	}

	_, err = server.handleDeleteKey(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find key")
}

// TestHandleListKeys_InvalidBackendParam exercises the error path when an
// invalid backend parameter is passed to listKeys.
func TestHandleListKeys_InvalidBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	params := ListKeysParams{Backend: "nonexistent-backend"}
	paramsJSON, err := json.Marshal(params)
	require.NoError(t, err)

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.listKeys",
		ID:      1,
		Params:  paramsJSON,
	}

	_, err = server.handleListKeys(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "backend not found")
}

// TestHandleImportKeyMaterial_InvalidParams exercises the invalid JSON params path.
func TestHandleImportKeyMaterial_InvalidParams(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.importKeyMaterial",
		ID:      1,
		Params:  json.RawMessage(`{invalid`),
	}

	_, err := server.handleImportKeyMaterial(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid params")
}

// TestHandleExportKeyMaterial_InvalidParams exercises the invalid JSON params path.
func TestHandleExportKeyMaterial_InvalidParams(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.exportKeyMaterial",
		ID:      1,
		Params:  json.RawMessage(`{invalid`),
	}

	_, err := server.handleExportKeyMaterial(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid params")
}
