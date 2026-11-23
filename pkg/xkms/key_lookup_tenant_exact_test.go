// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package xkms

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// tenantKeyState is what a tenant's key looks like from its own tenant: its
// public key and its version record. A system-tenant operation must leave it
// unchanged.
type tenantKeyState struct {
	pem    string
	record *keyversion.Record
	found  bool
}

func tenantKeyOf(t *testing.T, svc *XKMSService, tenant, keyID string) tenantKeyState {
	t.Helper()
	resp, err := svc.GetKey(identityCtx(tenant), "software", keyID)
	require.NoError(t, err)
	require.NotEmpty(t, resp.PublicKeyPEM)
	rec, found, err := svc.KeyVersionStore().Load(context.Background(), tenant, "software", keyID)
	require.NoError(t, err)
	return tenantKeyState{pem: resp.PublicKeyPEM, record: rec, found: found}
}

// unscopedSoftware is the software backend's unscoped (system) view.
func unscopedSoftware(t *testing.T, svc *XKMSService) Backend {
	t.Helper()
	b, err := svc.LookupTenantBackend("software", "")
	require.NoError(t, err)
	_, scoped := b.(*TenantScopedBackend)
	require.False(t, scoped, "the system tenant's view is the unscoped backend")
	return b
}

// platformAttrs is the system tenant's own key keyID in the unscoped view.
func platformAttrs(t *testing.T, b Backend, keyID string) *types.KeyAttributes {
	t.Helper()
	keys, err := b.ListKeys(context.Background())
	require.NoError(t, err)
	for _, attrs := range keys {
		if attrs != nil && attrs.CN == keyID && recordTenant(attrs.TenantID) == "" {
			return attrs
		}
	}
	t.Fatalf("no platform key %q", keyID)
	return nil
}

// setupSameCNKeys is a service with an ECDSA key "k" in the system tenant
// and in the tenants "aaa" and "acme". It asserts the unscoped listing puts
// a tenant's "k" before the platform's, so a first-match lookup answers
// with a tenant's key: the defect these tests pin.
func setupSameCNKeys(t *testing.T) (*XKMSService, map[string]tenantKeyState) {
	t.Helper()
	svc := setupDeriveService(t)
	genKey(t, svc, "aaa", "k", "ecdsa", 0)
	genKey(t, svc, "acme", "k", "ecdsa", 0)
	genKey(t, svc, "", "k", "ecdsa", 0)

	keys, err := unscopedSoftware(t, svc).ListKeys(context.Background())
	require.NoError(t, err)
	first := ""
	for _, attrs := range keys {
		if attrs != nil && attrs.CN == "k" {
			first = recordTenant(attrs.TenantID)
			break
		}
	}
	require.NotEmpty(t, first, "the unscoped listing lists a tenant's key before the platform key")

	return svc, map[string]tenantKeyState{
		"aaa":  tenantKeyOf(t, svc, "aaa", "k"),
		"acme": tenantKeyOf(t, svc, "acme", "k"),
	}
}

func assertTenantKeysUnchanged(t *testing.T, svc *XKMSService, before map[string]tenantKeyState) {
	t.Helper()
	for tenant, want := range before {
		assert.Equal(t, want, tenantKeyOf(t, svc, tenant, "k"), "tenant %q key is unchanged", tenant)
	}
}

// systemCtxs are the two ways a caller is in the system tenant.
func systemCtxs() map[string]context.Context {
	return map[string]context.Context{
		"background":      context.Background(),
		"system-identity": identityCtx(qrdbsdk.SystemTenantID),
	}
}

func TestKeyLookup_TenantExact_SystemTenant(t *testing.T) {
	for name, ctx := range systemCtxs() {
		t.Run(name, func(t *testing.T) {
			t.Run("get", func(t *testing.T) {
				svc, tenants := setupSameCNKeys(t)
				b := unscopedSoftware(t, svc)
				want := publicKeyPEMOf(ctx, b, platformAttrs(t, b, "k"))
				require.NotEmpty(t, want)

				resp, err := svc.GetKey(ctx, "software", "k")
				require.NoError(t, err)
				assert.Equal(t, want, resp.PublicKeyPEM, "the platform key's public key")
				for tenant, st := range tenants {
					assert.NotEqual(t, st.pem, resp.PublicKeyPEM, "not tenant %q's key", tenant)
				}
			})

			t.Run("versions", func(t *testing.T) {
				svc, tenants := setupSameCNKeys(t)
				rotate(t, svc, "acme", "k")
				tenants["acme"] = tenantKeyOf(t, svc, "acme", "k")

				resp, err := svc.ListKeyVersions(ctx, &transport.ListKeyVersionsRequest{Backend: "software", KeyID: "k"})
				require.NoError(t, err)
				require.Len(t, resp.Versions, 1, "the platform key's single version, not acme's two")
				assert.Equal(t, uint32(1), resp.CurrentVersion)

				b := unscopedSoftware(t, svc)
				assert.Equal(t, publicKeyPEMOf(ctx, b, platformAttrs(t, b, "k")), resp.Versions[0].PublicKeyPEM)
				assertTenantKeysUnchanged(t, svc, tenants)
			})

			t.Run("rotate", func(t *testing.T) {
				svc, tenants := setupSameCNKeys(t)
				resp, err := svc.RotateKey(ctx, &transport.RotateKeyRequest{Backend: "software", KeyID: "k"})
				require.NoError(t, err)
				assert.Equal(t, uint32(2), resp.KeyVersion)

				rec, found, err := svc.KeyVersionStore().Load(context.Background(), "", "software", "k")
				require.NoError(t, err)
				require.True(t, found, "the platform key's rotation is recorded")
				assert.Len(t, rec.Versions, 2)
				assertTenantKeysUnchanged(t, svc, tenants)
			})

			t.Run("delete", func(t *testing.T) {
				svc, tenants := setupSameCNKeys(t)
				require.NoError(t, svc.DeleteKey(ctx, "software", "k"))

				_, err := FindKeyAttributes(context.Background(), unscopedSoftware(t, svc), "k")
				assert.ErrorIs(t, err, ErrKeyNotFound, "the platform key is deleted")
				assertTenantKeysUnchanged(t, svc, tenants)
			})
		})
	}
}

func TestKeyLookup_TenantExact_FindKeyAttributes(t *testing.T) {
	svc, _ := setupSameCNKeys(t)
	b := unscopedSoftware(t, svc)
	want := platformAttrs(t, b, "k")

	got, err := FindKeyAttributes(context.Background(), b, "k")
	require.NoError(t, err)
	assert.Equal(t, "", recordTenant(got.TenantID))
	assert.Same(t, want, got)

	got, err = findKeyAttrs(context.Background(), b, "k")
	require.NoError(t, err)
	assert.Equal(t, "", recordTenant(got.TenantID))
	assert.Same(t, want, got)
}

func TestKeyLookup_TenantExact_NoPlatformKey(t *testing.T) {
	svc := setupDeriveService(t)
	genKey(t, svc, "aaa", "only", "ecdsa", 0)
	genKey(t, svc, "acme", "only", "ecdsa", 0)
	b := unscopedSoftware(t, svc)

	_, err := FindKeyAttributes(context.Background(), b, "only")
	assert.ErrorIs(t, err, ErrKeyNotFound)
	_, err = findKeyAttrs(context.Background(), b, "only")
	assert.ErrorIs(t, err, ErrKeyNotFound)

	for name, ctx := range systemCtxs() {
		t.Run(name, func(t *testing.T) {
			_, err := svc.GetKey(ctx, "software", "only")
			assert.ErrorIs(t, err, ErrKeyNotFound)
			_, err = svc.ListKeyVersions(ctx, &transport.ListKeyVersionsRequest{Backend: "software", KeyID: "only"})
			assert.ErrorIs(t, err, ErrKeyNotFound)
			_, err = svc.RotateKey(ctx, &transport.RotateKeyRequest{Backend: "software", KeyID: "only"})
			assert.ErrorIs(t, err, ErrKeyNotFound)
			assert.ErrorIs(t, svc.DeleteKey(ctx, "software", "only"), ErrKeyNotFound)
		})
	}
	tenantKeyOf(t, svc, "aaa", "only")
	tenantKeyOf(t, svc, "acme", "only")
}

func TestKeyLookup_TenantExact_DedicatedTenant(t *testing.T) {
	ctx := identityCtx("acme")

	svc, tenants := setupSameCNKeys(t)
	resp, err := svc.GetKey(ctx, "software", "k")
	require.NoError(t, err)
	assert.Equal(t, tenants["acme"].pem, resp.PublicKeyPEM)

	vers, err := svc.ListKeyVersions(ctx, &transport.ListKeyVersionsRequest{Backend: "software", KeyID: "k", TenantID: "acme"})
	require.NoError(t, err)
	require.Len(t, vers.Versions, 1)
	assert.Equal(t, tenants["acme"].pem, vers.Versions[0].PublicKeyPEM)

	assert.Equal(t, uint32(2), rotate(t, svc, "acme", "k"))
	rec, found, err := svc.KeyVersionStore().Load(context.Background(), "acme", "software", "k")
	require.NoError(t, err)
	require.True(t, found)
	assert.Len(t, rec.Versions, 2)
	assert.Equal(t, tenants["aaa"], tenantKeyOf(t, svc, "aaa", "k"))
	_, found, err = svc.KeyVersionStore().Load(context.Background(), "", "software", "k")
	require.NoError(t, err)
	assert.False(t, found, "the platform key is not rotated")

	require.NoError(t, svc.DeleteKey(ctx, "software", "k"))
	_, err = svc.GetKey(ctx, "software", "k")
	assert.ErrorIs(t, err, ErrKeyNotFound)
	assert.Equal(t, tenants["aaa"], tenantKeyOf(t, svc, "aaa", "k"))
	_, err = FindKeyAttributes(context.Background(), unscopedSoftware(t, svc), "k")
	assert.NoError(t, err, "the platform key still exists")
}

func TestKeyLookup_TenantExact_NamedTenant(t *testing.T) {
	svc, _ := setupSameCNKeys(t)
	acme := identityCtx("acme")

	_, err := svc.Sign(acme, &transport.SignRequest{Backend: "software", KeyID: "k", Data: []byte("d"), TenantID: "aaa"})
	var denied *qrdbsdk.CrossTenantDeniedError
	assert.True(t, errors.As(err, &denied), "acme naming aaa on Sign is refused: %v", err)

	_, err = svc.GetPublicKey(acme, &transport.GetPublicKeyRequest{Backend: "software", KeyID: "k", TenantID: "aaa"})
	denied = nil
	assert.True(t, errors.As(err, &denied), "acme naming aaa on GetPublicKey is refused: %v", err)

	own, err := svc.GetPublicKey(acme, &transport.GetPublicKeyRequest{Backend: "software", KeyID: "k", TenantID: "acme"})
	require.NoError(t, err)
	sys, err := svc.GetPublicKey(context.Background(), &transport.GetPublicKeyRequest{Backend: "software", KeyID: "k", TenantID: "acme"})
	require.NoError(t, err)
	assert.Equal(t, own.PublicKey, sys.PublicKey, "a system-tenant caller naming acme resolves acme's key")

	_, err = svc.Sign(context.Background(), &transport.SignRequest{Backend: "software", KeyID: "k", Data: []byte("d"), TenantID: "acme"})
	assert.NoError(t, err)
}
