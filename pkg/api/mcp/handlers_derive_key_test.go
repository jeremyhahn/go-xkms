// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// handlers_derive_key_test.go covers the MCP xkms.deriveKey method: the
// non-ECDH general-purpose KDF surface (HKDF, SP 800-108, PBKDF2), distinct
// from xkms.deriveKeyECDH.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// newDeriveKeyServer returns an MCP server backed by the standard test XKMS
// service, sufficient for the raw-input-key-material HKDF path (no backend
// key resolution is needed for that path).
func newDeriveKeyServer(t *testing.T) *Server {
	t.Helper()

	svc := setupTestXKMS(t)
	t.Cleanup(cleanupXKMS)

	server, err := NewServer(&Config{
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
	})
	require.NoError(t, err)
	return server
}

func deriveKeyRequest(t *testing.T, params interface{}) *JSONRPCRequest {
	t.Helper()

	raw, err := json.Marshal(params)
	require.NoError(t, err)

	return &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.deriveKey", Params: raw, ID: 1}
}

func TestHandleDeriveKey_Success(t *testing.T) {
	server := newDeriveKeyServer(t)

	result, err := server.handleDeriveKey(context.Background(), deriveKeyRequest(t, transport.DeriveKeyRequest{
		Algorithm:        "HKDF",
		InputKeyMaterial: []byte("a-32-byte-or-longer-base-secret"),
		Salt:             []byte("salt"),
		Info:             []byte("info"),
		KeyLength:        32,
		Hash:             "SHA-256",
	}))

	require.NoError(t, err)
	resp, ok := result.(*transport.DeriveKeyResponse)
	require.True(t, ok, "result must be *transport.DeriveKeyResponse, got %T", result)
	assert.Len(t, resp.DerivedKey, 32)
}

func TestHandleDeriveKey_RequiresAlgorithm(t *testing.T) {
	server := newDeriveKeyServer(t)

	_, err := server.handleDeriveKey(context.Background(), deriveKeyRequest(t, transport.DeriveKeyRequest{
		InputKeyMaterial: []byte("a-32-byte-or-longer-base-secret"),
		KeyLength:        32,
	}))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "algorithm")
}

// TestHandleDeriveKey_KeyLengthExceedsMaximum proves an oversized key_length
// is refused with the wire's Invalid params code rather than reaching
// pkg/crypto/kdf's adapters, which do not bound a caller-chosen length on
// their own (go-xkms#1259).
func TestHandleDeriveKey_KeyLengthExceedsMaximum(t *testing.T) {
	server := newDeriveKeyServer(t)

	_, err := server.handleDeriveKey(context.Background(), deriveKeyRequest(t, transport.DeriveKeyRequest{
		Algorithm:        "HKDF",
		InputKeyMaterial: []byte("a-32-byte-or-longer-base-secret"),
		KeyLength:        types.MaxDerivedKeyLength + 1,
	}))

	require.Error(t, err)
	var keyOpErr *KeyOpError
	require.True(t, errors.As(err, &keyOpErr), "want *KeyOpError, got %T", err)
	assert.Equal(t, ErrCodeInvalidParams, keyOpErr.Code)
}

// TestHandleDeriveKey_TenantIDNotAccepted proves a caller-supplied tenant_id
// is refused: the tenant a derivation runs under is always the authenticated
// caller's own, matching every other tenant-scoped key operation on this
// transport (see tenantForRequest).
func TestHandleDeriveKey_TenantIDNotAccepted(t *testing.T) {
	server := newDeriveKeyServer(t)

	_, err := server.handleDeriveKey(context.Background(), deriveKeyRequest(t, transport.DeriveKeyRequest{
		Algorithm:        "HKDF",
		InputKeyMaterial: []byte("a-32-byte-or-longer-base-secret"),
		KeyLength:        32,
		TenantID:         "someone-elses-tenant",
	}))

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTenantIDNotAccepted))
}
