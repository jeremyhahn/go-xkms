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
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServiceUnavailable exercises the nil xkmsService error path for all handlers
// that depend on the injected XKMS service.
func TestServiceUnavailable(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{Addr: "localhost:0", XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	// Simulate a not-initialized service by nilling the injected field directly.
	// xkms.Reset() no longer affects s.xkmsService since DI is now constructor-based.
	server.xkmsService = nil

	ctx := context.Background()
	emptyParams, _ := json.Marshal(map[string]string{})
	req := &JSONRPCRequest{JSONRPC: "2.0", Params: emptyParams, ID: 1}

	handlers := []struct {
		name string
		fn   func(context.Context, *JSONRPCRequest) (interface{}, error)
	}{
		{"handleGetCABundle", server.handleGetCABundle},
		{"handleGetCACertificate", server.handleGetCACertificate},
		{"handleSignCSR", server.handleSignCSR},
		{"handleIssueCertificate", server.handleIssueCertificate},
		{"handleRevokeCertificate", server.handleRevokeCertificate},
		{"handleGenerateCRL", server.handleGenerateCRL},
		{"handleIsRevoked", server.handleIsRevoked},
		{"handleIssueEKCertificate", server.handleIssueEKCertificate},
		{"handleIssueAKCertificate", server.handleIssueAKCertificate},
		{"handleSignTCGCSR", server.handleSignTCGCSR},
		{"handleEnrollDevice", server.handleEnrollDevice},
		{"handleGetInitStatus", server.handleGetInitStatus},
		{"handleClaimCertBegin", server.handleClaimCertBegin},
		{"handleClaimCertComplete", server.handleClaimCertComplete},
		{"handleClaimShareBegin", server.handleClaimShareBegin},
		{"handleClaimShareComplete", server.handleClaimShareComplete},
	}

	for _, h := range handlers {
		t.Run(h.name, func(t *testing.T) {
			_, err := h.fn(ctx, req)
			assert.ErrorIs(t, err, ErrXKMSServiceUnavailable)
		})
	}
}

// TestPIV_InvalidParams exercises the invalid JSON error path for PIV handlers.
func TestPIV_InvalidParams(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{Addr: "localhost:0", XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	ctx := context.Background()
	badReq := &JSONRPCRequest{JSONRPC: "2.0", Params: json.RawMessage(`{bad`), ID: 1}

	handlers := []struct {
		name string
		fn   func(context.Context, *JSONRPCRequest) (interface{}, error)
	}{
		{"handleListPIVSlots", server.handleListPIVSlots},
		{"handleGetPIVCertificate", server.handleGetPIVCertificate},
		{"handleStorePIVCertificate", server.handleStorePIVCertificate},
		{"handleDeletePIVCertificate", server.handleDeletePIVCertificate},
		{"handleGeneratePIVKey", server.handleGeneratePIVKey},
		{"handleImportPIVCertificate", server.handleImportPIVCertificate},
		{"handleExportPIVCertificate", server.handleExportPIVCertificate},
		{"handleGeneratePIVCSR", server.handleGeneratePIVCSR},
	}

	for _, h := range handlers {
		t.Run(h.name, func(t *testing.T) {
			_, err := h.fn(ctx, badReq)
			assert.Error(t, err)
		})
	}
}

// TestHandlers_CopyKey_MissingFields exercises the validation error paths.
func TestHandlers_CopyKey_MissingFields(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	tests := []struct {
		name   string
		params CopyKeyParams
		errMsg string
	}{
		{"missing source_backend", CopyKeyParams{SourceKeyID: "k", DestBackend: "d", DestKeyID: "k2", Algorithm: "rsa"}, "source_backend"},
		{"missing source_key_id", CopyKeyParams{SourceBackend: "s", DestBackend: "d", DestKeyID: "k2", Algorithm: "rsa"}, "source_key_id"},
		{"missing dest_backend", CopyKeyParams{SourceBackend: "s", SourceKeyID: "k", DestKeyID: "k2", Algorithm: "rsa"}, "dest_backend"},
		{"missing dest_key_id", CopyKeyParams{SourceBackend: "s", SourceKeyID: "k", DestBackend: "d", Algorithm: "rsa"}, "dest_key_id"},
		{"missing algorithm", CopyKeyParams{SourceBackend: "s", SourceKeyID: "k", DestBackend: "d", DestKeyID: "k2"}, "algorithm"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paramsJSON, _ := json.Marshal(tt.params)
			req := &JSONRPCRequest{JSONRPC: "2.0", Params: paramsJSON, ID: 1}
			_, err := server.handleCopyKey(ctx, req)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}

	t.Run("invalid JSON", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Params: json.RawMessage(`{bad`), ID: 1}
		_, err := server.handleCopyKey(ctx, req)
		assert.Error(t, err)
	})

	t.Run("invalid source backend name", func(t *testing.T) {
		params := CopyKeyParams{
			SourceBackend: "nonexistent",
			SourceKeyID:   "k",
			DestBackend:   "software",
			DestKeyID:     "k2",
			Algorithm:     "rsa",
		}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Params: paramsJSON, ID: 1}
		_, err := server.handleCopyKey(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "source backend not found")
	})
}

// TestHandlers_ImportKeyMaterial_Validation exercises import validation paths.
func TestHandlers_ImportKeyMaterial_Validation(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("invalid JSON", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Params: json.RawMessage(`{bad`), ID: 1}
		_, err := server.handleImportKeyMaterial(ctx, req)
		assert.Error(t, err)
	})

	t.Run("missing key_id", func(t *testing.T) {
		params := map[string]string{"backend": "software"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Params: paramsJSON, ID: 1}
		_, err := server.handleImportKeyMaterial(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("invalid backend", func(t *testing.T) {
		params := map[string]string{"key_id": "test-key", "backend": "nonexistent-backend-xyz"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Params: paramsJSON, ID: 1}
		_, err := server.handleImportKeyMaterial(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid backend")
	})
}

// TestHandlers_ExportKeyMaterial_Validation exercises export validation paths.
func TestHandlers_ExportKeyMaterial_Validation(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("invalid JSON", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Params: json.RawMessage(`{bad`), ID: 1}
		_, err := server.handleExportKeyMaterial(ctx, req)
		assert.Error(t, err)
	})

	t.Run("missing key_id", func(t *testing.T) {
		params := map[string]string{"backend": "software"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Params: paramsJSON, ID: 1}
		_, err := server.handleExportKeyMaterial(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("nonexistent key", func(t *testing.T) {
		params := map[string]string{"key_id": "nonexistent-key-xyz", "backend": "software"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Params: paramsJSON, ID: 1}
		_, err := server.handleExportKeyMaterial(ctx, req)
		assert.Error(t, err)
	})
}

// TestHandlers_HandleDecrypt_Validation exercises decrypt validation paths.
func TestHandlers_HandleDecrypt_Validation(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("invalid JSON", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Params: json.RawMessage(`{bad`), ID: 1}
		_, err := server.handleDecrypt(ctx, req)
		assert.Error(t, err)
	})

	t.Run("missing key_id", func(t *testing.T) {
		params := map[string]string{"backend": "software"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Params: paramsJSON, ID: 1}
		_, err := server.handleDecrypt(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("nonexistent key no backend", func(t *testing.T) {
		params := map[string]string{"key_id": "nonexistent-key-xyz"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Params: paramsJSON, ID: 1}
		_, err := server.handleDecrypt(ctx, req)
		assert.Error(t, err)
	})

	t.Run("nonexistent key with backend", func(t *testing.T) {
		params := map[string]string{"key_id": "nonexistent-key-xyz", "backend": "software"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Params: paramsJSON, ID: 1}
		_, err := server.handleDecrypt(ctx, req)
		assert.Error(t, err)
	})
}

// TestHandlers_HandleListCerts_EmptyStore exercises the ListCerts happy path.
func TestHandlers_HandleListCerts_EmptyStore(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	params := map[string]int{"page": 1, "page_size": 10}
	paramsJSON, _ := json.Marshal(params)
	req := &JSONRPCRequest{JSONRPC: "2.0", Params: paramsJSON, ID: 1}

	result, err := server.handleListCerts(context.Background(), req)
	require.NoError(t, err)

	listResult, ok := result.(ListCertsResult)
	require.True(t, ok)
	assert.Empty(t, listResult.KeyIDs)
}

// TestInitCredentials_InvalidParams exercises invalid JSON error paths.
func TestInitCredentials_InvalidParams(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()
	badReq := &JSONRPCRequest{JSONRPC: "2.0", Params: json.RawMessage(`{bad`), ID: 1}

	handlers := []struct {
		name string
		fn   func(context.Context, *JSONRPCRequest) (interface{}, error)
	}{
		{"handleClaimCertBegin", server.handleClaimCertBegin},
		{"handleClaimCertComplete", server.handleClaimCertComplete},
		{"handleClaimShareBegin", server.handleClaimShareBegin},
		{"handleClaimShareComplete", server.handleClaimShareComplete},
	}

	for _, h := range handlers {
		t.Run(h.name, func(t *testing.T) {
			_, err := h.fn(ctx, badReq)
			assert.Error(t, err)
		})
	}
}
