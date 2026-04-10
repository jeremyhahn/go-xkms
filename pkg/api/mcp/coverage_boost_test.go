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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleCopyKey_ValidationErrors verifies all parameter validation
// branches in handleCopyKey.
func TestHandleCopyKey_ValidationErrors(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	tests := []struct {
		name        string
		params      CopyKeyParams
		expectedMsg string
	}{
		{
			name:        "missing source backend",
			params:      CopyKeyParams{SourceKeyID: "k1", DestBackend: "software", DestKeyID: "k2", Algorithm: "AES-KW"},
			expectedMsg: "source_backend is required",
		},
		{
			name:        "missing source key ID",
			params:      CopyKeyParams{SourceBackend: "software", DestBackend: "software", DestKeyID: "k2", Algorithm: "AES-KW"},
			expectedMsg: "source_key_id is required",
		},
		{
			name:        "missing dest backend",
			params:      CopyKeyParams{SourceBackend: "software", SourceKeyID: "k1", DestKeyID: "k2", Algorithm: "AES-KW"},
			expectedMsg: "dest_backend is required",
		},
		{
			name:        "missing dest key ID",
			params:      CopyKeyParams{SourceBackend: "software", SourceKeyID: "k1", DestBackend: "software", Algorithm: "AES-KW"},
			expectedMsg: "dest_key_id is required",
		},
		{
			name:        "missing algorithm",
			params:      CopyKeyParams{SourceBackend: "software", SourceKeyID: "k1", DestBackend: "software", DestKeyID: "k2"},
			expectedMsg: "algorithm is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			paramsBytes, err := json.Marshal(tc.params)
			require.NoError(t, err)

			req := &JSONRPCRequest{
				JSONRPC: "2.0",
				Method:  "xkms.copyKey",
				ID:      1,
				Params:  paramsBytes,
			}

			_, err = server.handleCopyKey(req)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedMsg)
		})
	}
}

// TestHandleCopyKey_InvalidParams verifies that handleCopyKey returns an error
// when the request parameters cannot be unmarshaled.
func TestHandleCopyKey_InvalidParams(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.copyKey",
		ID:      1,
		Params:  json.RawMessage(`{invalid`),
	}

	_, err := server.handleCopyKey(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid params")
}

// TestHandleCopyKey_NonExistentSourceBackend verifies that handleCopyKey returns
// an error when the source backend does not exist.
func TestHandleCopyKey_NonExistentSourceBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	params := CopyKeyParams{
		SourceBackend: "nonexistent",
		SourceKeyID:   "key1",
		DestBackend:   "software",
		DestKeyID:     "key2",
		Algorithm:     "AES-KW",
	}
	paramsBytes, err := json.Marshal(params)
	require.NoError(t, err)

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.copyKey",
		ID:      1,
		Params:  paramsBytes,
	}

	_, err = server.handleCopyKey(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "source backend not found")
}

// TestHandleCopyKey_NonExistentDestBackend verifies that handleCopyKey returns
// an error when the destination backend does not exist.
func TestHandleCopyKey_NonExistentDestBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	params := CopyKeyParams{
		SourceBackend: "software",
		SourceKeyID:   "key1",
		DestBackend:   "nonexistent",
		DestKeyID:     "key2",
		Algorithm:     "AES-KW",
	}
	paramsBytes, err := json.Marshal(params)
	require.NoError(t, err)

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.copyKey",
		ID:      1,
		Params:  paramsBytes,
	}

	_, err = server.handleCopyKey(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "destination backend not found")
}
