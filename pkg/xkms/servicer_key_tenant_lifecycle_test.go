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

package xkms

import (
	"context"
	"errors"
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// These tests pin the tenant scoping of the three key lifecycle methods that
// take no request struct -- GetKey, DeleteKey and ListKeys -- and so read the
// caller's tenant from the authenticated identity on ctx (go-xkms#1218). The
// REST and gRPC transports used to call the backend directly for these and
// scoped nothing; routing them through the service is only a fix if the
// service itself scopes.

func TestGetKey_ConfinedToTheCallersTenant(t *testing.T) {
	svc := setupDeriveService(t)
	storeExportableRSAKey(t, svc, "acme", "acme-key")

	own, err := svc.GetKey(identityCtx("acme"), "software", "acme-key")
	require.NoError(t, err)
	assert.Equal(t, "acme-key", own.KeyID)
	assert.Equal(t, "software", own.Backend)
	assert.Equal(t, 2048, own.KeySize)
	assert.True(t, strings.Contains(own.PublicKeyPEM, "BEGIN PUBLIC KEY"))

	_, crossErr := svc.GetKey(identityCtx("globex"), "software", "acme-key")
	require.Error(t, crossErr, "another tenant must not read acme's key")
	_, missErr := svc.GetKey(identityCtx("globex"), "software", "no-such-key")
	require.Error(t, missErr)
	assert.ErrorIs(t, crossErr, ErrKeyNotFound)
	assert.Equal(t, missErr.Error(), crossErr.Error(),
		"a cross-tenant refusal must read exactly like a genuine miss")
}

func TestDeleteKey_ConfinedToTheCallersTenant(t *testing.T) {
	svc := setupDeriveService(t)
	storeExportableRSAKey(t, svc, "acme", "acme-key")

	err := svc.DeleteKey(identityCtx("globex"), "software", "acme-key")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyNotFound)
	assert.True(t, tenantSeesKey(t, svc, "acme", "acme-key"),
		"acme's key must survive another tenant's delete")

	require.NoError(t, svc.DeleteKey(identityCtx("acme"), "software", "acme-key"))
	assert.False(t, tenantSeesKey(t, svc, "acme", "acme-key"))
}

func TestListKeys_ConfinedToTheCallersTenant(t *testing.T) {
	svc := setupDeriveService(t)
	storeExportableRSAKey(t, svc, "acme", "acme-key")
	storeExportableRSAKey(t, svc, "globex", "globex-key")

	for _, backendName := range []string{"software", ""} {
		resp, err := svc.ListKeys(identityCtx("acme"), backendName)
		require.NoError(t, err)
		require.Len(t, resp.Keys, 1, "backend %q: acme must see only its own key", backendName)
		assert.Equal(t, "acme-key", resp.Keys[0].KeyID)
		assert.Equal(t, 1, resp.Total)
		assert.True(t, strings.Contains(resp.Keys[0].PublicKeyPEM, "BEGIN PUBLIC KEY"),
			"each listed key carries its public key")
	}
}

// TestListKeys_PlatformScopeSeesEveryTenant pins tenantScopes' rule: no
// identity, and an identity in the reserved system tenant, are the platform
// scope and list every tenant's keys.
func TestListKeys_PlatformScopeSeesEveryTenant(t *testing.T) {
	svc := setupDeriveService(t)
	storeExportableRSAKey(t, svc, "acme", "acme-key")
	storeExportableRSAKey(t, svc, "globex", "globex-key")

	for name, ctx := range map[string]context.Context{
		"no identity":     context.Background(),
		"system identity": identityCtx(qrdbsdk.SystemTenantID),
	} {
		resp, err := svc.ListKeys(ctx, "software")
		require.NoError(t, err, name)
		assert.Len(t, resp.Keys, 2, "%s must see every tenant's keys", name)
	}
}

func TestListKeys_PaginatesBeforeReadingPublicKeys(t *testing.T) {
	svc := setupDeriveService(t)
	storeExportableRSAKey(t, svc, "", "k1")
	storeExportableRSAKey(t, svc, "", "k2")
	storeExportableRSAKey(t, svc, "", "k3")

	resp, err := svc.ListKeys(context.Background(), "software",
		transport.WithPageRequest(transport.PageRequest{Page: 2, PageSize: 2}))
	require.NoError(t, err)
	require.Len(t, resp.Keys, 1)
	assert.Equal(t, 3, resp.Total)
	assert.False(t, resp.HasMore)
	assert.NotEmpty(t, resp.Keys[0].PublicKeyPEM)
}

func TestListKeys_InvalidTenantRefused(t *testing.T) {
	svc := setupDeriveService(t)

	_, err := svc.ListKeys(identityCtx("../escape"), "software")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTenantIDRequired)
}

func TestRotateKey_ReportsKeyType(t *testing.T) {
	svc := setupDeriveService(t)
	storeExportableRSAKey(t, svc, "acme", "acme-key")

	resp, err := svc.RotateKey(context.Background(), &transport.RotateKeyRequest{
		Backend: "software", KeyID: "acme-key", TenantID: "acme",
	})
	require.NoError(t, err)
	assert.Equal(t, "ENCRYPTION", resp.KeyType)
	assert.True(t, strings.Contains(resp.PublicKeyPEM, "BEGIN PUBLIC KEY"))

	_, err = svc.RotateKey(context.Background(), &transport.RotateKeyRequest{
		Backend: "software", KeyID: "acme-key", TenantID: "globex",
	})
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

// TestExportKey_NamesTheMissingHalf proves a backend without the export half
// is refused with both the service's capability sentinel and the precise
// backend sentinel, so a transport can report which half was missing.
func TestExportKey_NamesTheMissingHalf(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	require.NoError(t, Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"plain": newMockKeyStore("plain")},
		DefaultBackend: "plain",
	}))
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ExportKey(context.Background(), &transport.ExportKeyRequest{
		Backend: "plain", KeyID: "k", Algorithm: string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported), "unexpected error: %v", err)
	assert.True(t, errors.Is(err, backend.ErrExportNotSupported), "unexpected error: %v", err)
}

// TestCopyKey_NamesTheMissingHalf is the CopyKey form: a destination that
// cannot import is refused as ErrImportNotSupported, not as the source's
// export refusal.
func TestCopyKey_NamesTheMissingHalf(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	factory, ok := GetBackendFactory(BackendSoftware)
	require.True(t, ok)
	provider, err := factory(map[string]interface{}{"key_dir": "memory"})
	require.NoError(t, err)
	software, err := New(&BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)

	require.NoError(t, Initialize(&ServiceConfig{
		Backends: map[string]Backend{
			"software": software,
			"plain":    newMockKeyStore("plain"),
		},
		DefaultBackend: "software",
	}))
	svc, err := Get()
	require.NoError(t, err)
	storeExportableRSAKey(t, svc, "", "src-key")

	_, err = svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceBackend: "software", SourceKeyID: "src-key",
		DestBackend: "plain", DestKeyID: "copy",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported), "unexpected error: %v", err)
	assert.True(t, errors.Is(err, backend.ErrImportNotSupported), "unexpected error: %v", err)
	assert.False(t, errors.Is(err, backend.ErrExportNotSupported))
}
