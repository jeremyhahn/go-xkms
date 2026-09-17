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

package mcp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Tenant scoping for the BYOK import ceremony (go-xkms#222).
//
// handleImportKeyMaterial passed no tenant to the service at all, so a
// tenant's import resolved the unscoped backend and landed under an identifier
// carrying no tenant prefix -- somewhere the importing tenant's own reads
// could not find it. handleGetImportParameters and handleCopyKey took their
// tenant straight from callerTenantID, so a caller-supplied tenant_id was
// silently dropped by the decoder rather than refused.
// ===========================================================================

// importCeremony runs the full three-step BYOK ceremony through the MCP
// handlers as tenantID, and returns the error from the import step. The
// parameter and wrap steps must succeed for every case here, so they are
// asserted rather than returned.
//
// It runs against the real software backend the key-ops fixture registers as
// the default, not a fake: the ceremony binds the wrapped material to a
// wrapping key the backend mints, so a fake that ignores the token would hide
// exactly the failure this exercises.
func importCeremony(t *testing.T, server *Server, tenantID, keyID string, material []byte) error {
	t.Helper()
	ctx := tenantContext(tenantID)

	paramsResult, err := server.handleGetImportParameters(ctx,
		keyOpsRequest(t, "xkms.getImportParameters", &GetImportParametersParams{
			KeyID:     keyID,
			Backend:   "software",
			Algorithm: "RSAES_OAEP_SHA_256",
			KeyType:   "symmetric",
			KeySize:   256,
		}))
	require.NoError(t, err)
	importParams, ok := paramsResult.(GetImportParametersResult)
	require.True(t, ok, "unexpected result type %T", paramsResult)
	require.NotEmpty(t, importParams.WrappingPublicKeyPEM)

	wrapResult, err := server.handleWrapKey(ctx,
		keyOpsRequest(t, "xkms.wrapKey", &WrapKeyParams{
			KeyMaterial:          material,
			WrappingPublicKeyPEM: importParams.WrappingPublicKeyPEM,
			ImportToken:          importParams.ImportToken,
			Algorithm:            importParams.Algorithm,
			Backend:              "software",
			KeySpec:              importParams.KeySpec,
		}))
	require.NoError(t, err)
	wrapped, ok := wrapResult.(WrapKeyResult)
	require.True(t, ok, "unexpected result type %T", wrapResult)
	require.NotEmpty(t, wrapped.WrappedKey)

	exportable := true
	_, err = server.handleImportKeyMaterial(ctx,
		keyOpsRequest(t, "xkms.importKey", &ImportKeyParams{
			KeyID:       keyID,
			Backend:     "software",
			KeyType:     "symmetric",
			KeySize:     256,
			AESKeySize:  256,
			WrappedKey:  wrapped.WrappedKey,
			Algorithm:   wrapped.Algorithm,
			ImportToken: importParams.ImportToken,
			Exportable:  &exportable,
		}))
	return err
}

// canExport reports whether tenantID can resolve keyID in the software
// backend. Export resolves the key by common name through the caller's
// tenant-scoped view, so it answers exactly the question the import defect
// turned on: which namespace did the key actually land in.
func canExport(t *testing.T, server *Server, tenantID, keyID string) bool {
	t.Helper()
	_, err := server.handleExportKey(tenantContext(tenantID),
		keyOpsRequest(t, "xkms.exportKey", &ExportKeyParams{
			KeyID:     keyID,
			Backend:   "software",
			Algorithm: "RSAES_OAEP_SHA_256",
		}))
	return err == nil
}

// TestHandler_ImportKeyMaterial_LandsInTheCallersTenant proves a tenant's
// import is written into that tenant's own namespace: the importing tenant can
// resolve the key afterwards and no other tenant can.
//
// Before the fix the import carried no tenant, so the key landed in the
// untenanted namespace and tenant-a could not resolve its own key.
//
// The oracle is the pair of assertions, not either alone: the owning tenant
// reaching the key rules out the import having gone to the untenanted
// namespace, and another tenant failing to rules out its having gone
// everywhere. An unauthenticated caller is deliberately NOT asserted against
// here -- the empty tenant is the system view, which is not a scope and sees
// every key by design (see xkms.ScopeBackendToTenant). Where the key is
// actually STORED, as opposed to which view reaches it, is asserted on the
// stored attributes in pkg/xkms/servicer_key_tenant_import_test.go.
func TestHandler_ImportKeyMaterial_LandsInTheCallersTenant(t *testing.T) {
	server := newKeyOpsServer(t, nil)
	material := []byte("0123456789abcdef0123456789abcdef")

	require.NoError(t, importCeremony(t, server, "tenant-a", "imported-kek", material))

	assert.True(t, canExport(t, server, "tenant-a", "imported-kek"),
		"the importing tenant must be able to resolve its own imported key")
	assert.False(t, canExport(t, server, "tenant-b", "imported-kek"),
		"another tenant must not resolve this tenant's imported key")
}

// TestHandler_ImportKeyMaterial_UntenantedUnchanged is the control: a
// single-tenant deployment, where no identity carries a tenant, still imports
// into the untenanted namespace and reads the key back from it.
func TestHandler_ImportKeyMaterial_UntenantedUnchanged(t *testing.T) {
	server := newKeyOpsServer(t, nil)
	material := []byte("0123456789abcdef0123456789abcdef")

	require.NoError(t, importCeremony(t, server, "", "shared-kek", material))

	assert.True(t, canExport(t, server, "", "shared-kek"),
		"an untenanted import must remain readable untenanted")
	assert.False(t, canExport(t, server, "tenant-a", "shared-kek"),
		"an untenanted key must not be visible inside a tenant")
}

// TestHandler_ImportCeremony_RejectsSuppliedTenant proves the three ceremony
// handlers refuse a caller-named tenant with the exact error, rather than
// acting on it or letting the decoder drop it. Each params struct gained a
// tenant_id field precisely so the refusal is reachable.
func TestHandler_ImportCeremony_RejectsSuppliedTenant(t *testing.T) {
	tests := []struct {
		name   string
		method string
		params interface{}
		invoke func(*Server, context.Context, *JSONRPCRequest) (interface{}, error)
	}{
		{
			name:   "getImportParameters",
			method: "xkms.getImportParameters",
			params: &GetImportParametersParams{
				KeyID: "k", Backend: "software",
				Algorithm: "RSAES_OAEP_SHA_256", TenantID: "tenant-b",
			},
			invoke: func(s *Server, ctx context.Context, r *JSONRPCRequest) (interface{}, error) {
				return s.handleGetImportParameters(ctx, r)
			},
		},
		{
			name:   "importKey",
			method: "xkms.importKey",
			params: &ImportKeyParams{
				KeyID: "k", Backend: "software", KeyType: "symmetric",
				KeySize: 256, WrappedKey: []byte("blob"),
				Algorithm: "RSAES_OAEP_SHA_256", TenantID: "tenant-b",
			},
			invoke: func(s *Server, ctx context.Context, r *JSONRPCRequest) (interface{}, error) {
				return s.handleImportKeyMaterial(ctx, r)
			},
		},
		{
			name:   "copyKey",
			method: "xkms.copyKey",
			params: &CopyKeyParams{
				SourceBackend: "software", SourceKeyID: "src",
				DestBackend: "software", DestKeyID: "dst",
				Algorithm: "RSAES_OAEP_SHA_256", TenantID: "tenant-b",
			},
			invoke: func(s *Server, ctx context.Context, r *JSONRPCRequest) (interface{}, error) {
				return s.handleCopyKey(ctx, r)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newKeyOpsServer(t, nil)

			_, err := tt.invoke(server, tenantContext("tenant-a"),
				keyOpsRequest(t, tt.method, tt.params))
			require.Error(t, err, "a caller-named tenant must be refused, not acted on")
			assert.ErrorIs(t, err, ErrTenantIDNotAccepted)
		})
	}
}
