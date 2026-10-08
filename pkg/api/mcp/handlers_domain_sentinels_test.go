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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestInvokeMethod_ImportExportDomainSentinel proves handleUnwrapKey's
// capability-boundary refusal reaches the caller as a classified *KeyOpError
// through the real Server.InvokeMethod dispatch (decodeParams, the tenant
// and authorization gates, and mapImportExportError), not merely when the
// handler is called directly. backend.ErrKeyNotExportable -> Forbidden,
// matching pkg/api/grpc's mapImportExportError (go-xkms#912).
func TestInvokeMethod_ImportExportDomainSentinel(t *testing.T) {
	provider := newFakeIEProvider(&types.KeyAttributes{CN: "k"})
	provider.unwrapErr = backend.ErrKeyNotExportable
	server := newKeyOpsServer(t, map[string]types.KeyProvider{"ie-be": provider})

	params, err := json.Marshal(&UnwrapKeyParams{
		WrappedKey:        []byte("wrapped-blob"),
		Algorithm:         "RSAES_OAEP_SHA_256",
		WrappingPublicKey: wrappingKeyPEM(t),
		Backend:           "ie-be",
	})
	require.NoError(t, err)

	_, dispatchErr := server.InvokeMethod(context.Background(), "xkms.unwrapKey", params)
	require.Error(t, dispatchErr)

	var keyErr *KeyOpError
	require.ErrorAs(t, dispatchErr, &keyErr)
	assert.Equal(t, ErrCodeForbidden, keyErr.Code)
	assert.ErrorIs(t, dispatchErr, backend.ErrKeyNotExportable)
}

// TestInvokeMethod_PIVDomainSentinel proves a PIV domain sentinel reaches
// the caller as a classified *KeyOpError through the real InvokeMethod
// dispatch. No PIV manager is wired on createTestServer's fixture, so
// xkms.ListPIVSlots answers xkms.ErrPIVNotInitialized -- ClassFailedPrecondition,
// which has no JSON-RPC equivalent and so floors to ErrCodeInternalError,
// exactly like pkg/api/mcp's other sentinel tables' documented floor for the
// same gap.
func TestInvokeMethod_PIVDomainSentinel(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	params := json.RawMessage(`{"backend": "software"}`)
	_, err := server.InvokeMethod(context.Background(), "xkms.listPIVSlots", params)
	require.Error(t, err)

	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ErrCodeInternalError, keyErr.Code)
	assert.ErrorIs(t, err, xkms.ErrPIVNotInitialized)
}

// TestInvokeMethod_CADomainSentinel proves handleGetCABundle's "no CA wired"
// condition reaches the caller as Service unavailable through the real
// InvokeMethod dispatch, matching pkg/api/grpc/service_ca.go's
// codes.Unavailable for the same condition (go-xkms#912). createTestServer's
// XKMSService has no CA configured.
func TestInvokeMethod_CADomainSentinel(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	_, err := server.InvokeMethod(context.Background(), "xkms.ca.bundle", json.RawMessage(`{}`))
	require.Error(t, err)

	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ErrCodeServiceUnavailable, keyErr.Code)
	assert.ErrorIs(t, err, xkms.ErrNotConfigured)
}

// TestInvokeMethod_CertDomainSentinel proves handleGetCert's failure for an
// unknown key ID reaches the caller as Not found through the real
// InvokeMethod dispatch, matching pkg/api/grpc/service.go's GetCert, which
// reports codes.NotFound for any failure (go-xkms#912).
func TestInvokeMethod_CertDomainSentinel(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	params, err := json.Marshal(GetCertParams{KeyID: "does-not-exist"})
	require.NoError(t, err)

	_, dispatchErr := server.InvokeMethod(context.Background(), "xkms.getCert", params)
	require.Error(t, dispatchErr)

	var keyErr *KeyOpError
	require.ErrorAs(t, dispatchErr, &keyErr)
	assert.Equal(t, sdkssh.JSONRPCCodeNotFound, keyErr.Code)
}

// TestInvokeMethod_PasswordUnlock_SystemTenant proves a caller rooted in the
// reserved "system" tenant (e.g. a WebAuthn-registered identity) opens its own
// personal session in the system tenant's password store through the real
// InvokeMethod dispatch. It used to be refused as cross-tenant: the system
// tenant had no password store of its own.
func TestInvokeMethod_PasswordUnlock_SystemTenant(t *testing.T) {
	s := newPasswordServer(t)
	s.authorizer = auth.NewAuthorizer(nil)
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "webauthn-user", TenantID: "system"})
	s.unlock(t, ctx)
	s.lock(t, ctx)
	passkey, err := json.Marshal(ctxPasskey(ctx))
	require.NoError(t, err)

	result, err := s.InvokeMethod(ctx, "password.unlock", passkey)

	require.NoError(t, err)
	status, ok := result.(PasswordStoreStatusResult)
	require.True(t, ok)
	assert.False(t, status.IsLocked)
	locked, err := s.manager.IsUserLocked("system", "webauthn-user")
	require.NoError(t, err)
	assert.False(t, locked)
}
