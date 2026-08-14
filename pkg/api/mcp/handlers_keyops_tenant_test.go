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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Tenant scoping for the key operation handlers.
//
// The tenant an operation runs under comes from the authenticated identity,
// as it always has on the gRPC transport. These handlers used to decode it
// straight out of the request params, so any caller could name any tenant.
// ===========================================================================

// tenantContext returns a context carrying an authenticated identity that
// belongs to tenantID. An empty tenantID returns a context with no identity.
func tenantContext(tenantID string) context.Context {
	if tenantID == "" {
		return context.Background()
	}
	return auth.WithIdentity(context.Background(),
		&auth.Identity{Subject: "svc", TenantID: tenantID})
}

// keyOpsRequest marshals params into a JSON-RPC request for method.
func keyOpsRequest(t *testing.T, method string, params interface{}) *JSONRPCRequest {
	t.Helper()
	raw, err := json.Marshal(params)
	require.NoError(t, err)
	return &JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: raw, ID: 1}
}

// TestHandler_KeyOps_RejectSuppliedTenant proves every key-operation handler
// refuses a caller-supplied tenant, with the exact error, rather than acting
// on it or quietly ignoring it.
func TestHandler_KeyOps_RejectSuppliedTenant(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		params  interface{}
		invoke  func(*Server, context.Context, *JSONRPCRequest) (interface{}, error)
		handler string
	}{
		{
			name:   "attestKey",
			method: "xkms.attestKey",
			params: &transport.AttestKeyRequest{Backend: "tpm2", KeyID: "idevid", TenantID: "tenant-b"},
			invoke: func(s *Server, ctx context.Context, r *JSONRPCRequest) (interface{}, error) {
				return s.handleAttestKey(ctx, r)
			},
		},
		{
			name:   "deriveKeyECDH",
			method: "xkms.deriveKeyECDH",
			params: &transport.DeriveKeyECDHRequest{
				Backend: "tpm2", KeyID: "idevid", PeerPublicKey: []byte("peer"), TenantID: "tenant-b",
			},
			invoke: func(s *Server, ctx context.Context, r *JSONRPCRequest) (interface{}, error) {
				return s.handleDeriveKeyECDH(ctx, r)
			},
		},
		{
			name:   "exportKeyMaterial",
			method: "xkms.exportKeyMaterial",
			params: &transport.ExportKeyMaterialRequest{Backend: "tpm2", KeyID: "idevid", TenantID: "tenant-b"},
			invoke: func(s *Server, ctx context.Context, r *JSONRPCRequest) (interface{}, error) {
				return s.handleExportKeyMaterial(ctx, r)
			},
		},
		{
			name:   "wrapKeyByID",
			method: "xkms.wrapKeyByID",
			params: &transport.WrapKeyByIDRequest{
				WrappingKeyID: "idevid", WrappingKeyBackend: "tpm2",
				TargetKeyID: "idevid", TargetKeyBackend: "tpm2",
				Algorithm: "RSAES_OAEP_SHA_256", TenantID: "tenant-b",
			},
			invoke: func(s *Server, ctx context.Context, r *JSONRPCRequest) (interface{}, error) {
				return s.handleWrapKeyByID(ctx, r)
			},
		},
		{
			name:   "unwrapKeyByID",
			method: "xkms.unwrapKeyByID",
			params: &transport.UnwrapKeyByIDRequest{
				WrappedKey: []byte("blob"), UnwrappingKeyID: "idevid",
				UnwrappingKeyBackend: "tpm2", Algorithm: "RSAES_OAEP_SHA_256",
				TargetKeyID: "imported", TargetKeyBackend: "tpm2", TenantID: "tenant-b",
			},
			invoke: func(s *Server, ctx context.Context, r *JSONRPCRequest) (interface{}, error) {
				return s.handleUnwrapKeyByID(ctx, r)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := newFakeAttestingProvider(testAttestationStatement(),
				&types.KeyAttributes{CN: "idevid", Exportable: true})
			server := newKeyOpsServer(t, map[string]types.KeyProvider{"tpm2": provider})

			_, err := tt.invoke(server, tenantContext("tenant-a"), keyOpsRequest(t, tt.method, tt.params))
			require.Error(t, err, "a caller-named tenant must be refused, not acted on")
			assert.ErrorIs(t, err, ErrTenantIDNotAccepted)
		})
	}
}

// TestHandler_AttestKey_AcceptsParamsWithoutTenantField is the positive
// control for the rejection above: the same request, without the field, must
// reach the service layer. Without it, a handler that refused everything would
// pass the rejection tests.
func TestHandler_AttestKey_AcceptsParamsWithoutTenantField(t *testing.T) {
	provider := newFakeAttestingProvider(testAttestationStatement(),
		&types.KeyAttributes{CN: "idevid"})
	server := newKeyOpsServer(t, map[string]types.KeyProvider{"tpm2": provider})

	result, err := server.handleAttestKey(tenantContext(""),
		keyOpsRequest(t, "xkms.attestKey", &transport.AttestKeyRequest{Backend: "tpm2", KeyID: "idevid"}))
	require.NoError(t, err)
	require.NotNil(t, result)
}

// TestHandler_AttestKey_UsesAuthenticatedTenant proves the tenant that reaches
// the service layer is the authenticated caller's.
//
// The oracle is which key resolves: the fixture holds one key per tenant, and
// a tenant-scoped view of the backend contains only that tenant's. A caller
// authenticated as one tenant therefore reaches its own key and cannot reach
// the other's, which no amount of dropping or defaulting the tenant would
// reproduce.
func TestHandler_AttestKey_UsesAuthenticatedTenant(t *testing.T) {
	provider := newFakeAttestingProvider(testAttestationStatement(),
		&types.KeyAttributes{CN: "a-key", TenantID: "tenant-a"},
		&types.KeyAttributes{CN: "b-key", TenantID: "tenant-b"})
	server := newKeyOpsServer(t, map[string]types.KeyProvider{"tpm2": provider})

	attest := func(keyID, tenantID string) error {
		_, err := server.handleAttestKey(tenantContext(tenantID),
			keyOpsRequest(t, "xkms.attestKey", &transport.AttestKeyRequest{Backend: "tpm2", KeyID: keyID}))
		return err
	}

	require.NoError(t, attest("a-key", "tenant-a"),
		"a tenant must reach its own key")
	require.Error(t, attest("b-key", "tenant-a"),
		"a tenant must not reach another tenant's key by naming it")
	require.NoError(t, attest("b-key", "tenant-b"),
		"the other tenant must reach its own key")
}

// TestHandler_ExportKeyMaterial_UsesAuthenticatedTenant covers the tenant
// reaching the service on the handler that releases raw key bytes, where
// resolving another tenant's key would disclose that tenant's material.
func TestHandler_ExportKeyMaterial_UsesAuthenticatedTenant(t *testing.T) {
	material := []byte("0123456789abcdef0123456789abcdef")
	provider := newFakeIEProvider(&types.KeyAttributes{
		CN:                 "sym-key",
		TenantID:           "tenant-a",
		KeyType:            types.KeyTypeSecret,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	})
	provider.material["sym-key"] = material
	server := newKeyOpsServer(t, map[string]types.KeyProvider{"tpm2": provider})

	export := func(tenantID string) (interface{}, error) {
		return server.handleExportKeyMaterial(tenantContext(tenantID),
			keyOpsRequest(t, "xkms.exportKeyMaterial",
				&transport.ExportKeyMaterialRequest{Backend: "tpm2", KeyID: "sym-key"}))
	}

	result, err := export("tenant-a")
	require.NoError(t, err, "the owning tenant must be able to export its own key")
	resp, ok := result.(*transport.ExportKeyMaterialResponse)
	require.True(t, ok)
	assert.Equal(t, material, resp.KeyMaterial)

	_, err = export("tenant-b")
	require.Error(t, err, "another tenant must not export this key's material")

	// Positive control: an unauthenticated caller still reaches the unscoped
	// view, so single-tenant deployments are unaffected.
	_, err = export("")
	require.NoError(t, err)
}
