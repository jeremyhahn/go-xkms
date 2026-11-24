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
	"github.com/jeremyhahn/go-xkms/pkg/backend"
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
	assert.Equal(t, want, got)

	got, err = findKeyAttrs(context.Background(), b, "k")
	require.NoError(t, err)
	assert.Equal(t, "", recordTenant(got.TenantID))
	assert.Equal(t, want, got)
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
	svc, tenants := setupSameCNKeys(t)
	acme := identityCtx("acme")

	_, err := svc.Sign(acme, &transport.SignRequest{Backend: "software", KeyID: "k", Data: []byte("d"), TenantID: "aaa"})
	var refused *TenantBindingError
	assert.True(t, errors.As(err, &refused), "acme naming aaa on Sign is refused: %v", err)

	_, err = svc.GetPublicKey(acme, &transport.GetPublicKeyRequest{Backend: "software", KeyID: "k", TenantID: "aaa"})
	refused = nil
	assert.True(t, errors.As(err, &refused), "acme naming aaa on GetPublicKey is refused: %v", err)

	_, err = svc.GetPublicKey(acme, &transport.GetPublicKeyRequest{Backend: "software", KeyID: "k", TenantID: "acme"})
	require.NoError(t, err, "acme naming its own tenant resolves its key")

	for name, ctx := range systemCtxs() {
		_, err = svc.Sign(ctx, &transport.SignRequest{Backend: "software", KeyID: "k", Data: []byte("d"), TenantID: "acme"})
		refused = nil
		assert.True(t, errors.As(err, &refused), "%s caller naming acme on Sign is refused: %v", name, err)
	}
	assertTenantKeysUnchanged(t, svc, tenants)
}

// TestKeyLookup_TenantExact_OmittedTenantIsCaller pins that a request with
// no TenantID resolves in the caller's own tenant: an acme caller reaches
// acme's key, never the system tenant's same-named key, and a no-identity
// caller reaches the system tenant's key.
func TestKeyLookup_TenantExact_OmittedTenantIsCaller(t *testing.T) {
	svc, tenants := setupSameCNKeys(t)
	genKey(t, svc, "", "sysonly", "ecdsa", 0)
	acme := identityCtx("acme")

	own, err := svc.GetPublicKey(acme, &transport.GetPublicKeyRequest{Backend: "software", KeyID: "k", TenantID: "acme"})
	require.NoError(t, err)
	omitted, err := svc.GetPublicKey(acme, &transport.GetPublicKeyRequest{Backend: "software", KeyID: "k"})
	require.NoError(t, err)
	assert.Equal(t, own.PublicKey, omitted.PublicKey, "acme with no TenantID reads acme's key")

	vers, err := svc.ListKeyVersions(acme, &transport.ListKeyVersionsRequest{Backend: "software", KeyID: "k"})
	require.NoError(t, err)
	require.Len(t, vers.Versions, 1)
	assert.Equal(t, tenants["acme"].pem, vers.Versions[0].PublicKeyPEM, "acme with no TenantID lists acme's versions")

	_, err = svc.Sign(acme, &transport.SignRequest{Backend: "software", KeyID: "k", Data: []byte("d")})
	require.NoError(t, err, "acme with no TenantID signs with acme's key")
	_, err = svc.Sign(acme, &transport.SignRequest{Backend: "software", KeyID: "sysonly", Data: []byte("d")})
	assert.Error(t, err, "acme with no TenantID never signs with a system-tenant key")
	_, err = svc.GetPublicKey(acme, &transport.GetPublicKeyRequest{Backend: "software", KeyID: "sysonly"})
	assert.Error(t, err, "acme with no TenantID never reads a system-tenant key")

	sys, err := svc.GetPublicKey(context.Background(), &transport.GetPublicKeyRequest{Backend: "software", KeyID: "k"})
	require.NoError(t, err)
	assert.NotEqual(t, own.PublicKey, sys.PublicKey, "a no-identity caller with no TenantID reads the system key")
	_, err = svc.Sign(context.Background(), &transport.SignRequest{Backend: "software", KeyID: "sysonly", Data: []byte("d")})
	assert.NoError(t, err, "a no-identity caller signs with the system tenant's key")
	assertTenantKeysUnchanged(t, svc, tenants)
}

// TestKeyLookup_TenantExact_SystemCallerNamesTenant pins that a system-tenant
// caller naming a dedicated tenant is refused on every key path and the
// tenant's key is left untouched.
func TestKeyLookup_TenantExact_SystemCallerNamesTenant(t *testing.T) {
	svc, tenants := setupSameCNKeys(t)
	ctx := identityCtx(qrdbsdk.SystemTenantID)

	calls := map[string]func() error{
		"sign": func() error {
			_, err := svc.Sign(ctx, &transport.SignRequest{Backend: "software", KeyID: "k", Data: []byte("d"), TenantID: "acme"})
			return err
		},
		"get": func() error {
			_, err := svc.GetPublicKey(ctx, &transport.GetPublicKeyRequest{Backend: "software", KeyID: "k", TenantID: "acme"})
			return err
		},
		"versions": func() error {
			_, err := svc.ListKeyVersions(ctx, &transport.ListKeyVersionsRequest{Backend: "software", KeyID: "k", TenantID: "acme"})
			return err
		},
		"rotate": func() error {
			_, err := svc.RotateKey(ctx, &transport.RotateKeyRequest{Backend: "software", KeyID: "k", TenantID: "acme"})
			return err
		},
		"delete": func() error {
			_, err := svc.RevokeKey(ctx, &transport.RevokeKeyRequest{Backend: "software", KeyID: "k", TenantID: "acme"})
			return err
		},
	}
	for op, call := range calls {
		err := call()
		var refused *TenantBindingError
		assert.True(t, errors.As(err, &refused), "system caller naming acme on %s is refused: %v", op, err)
	}
	assertTenantKeysUnchanged(t, svc, tenants)
}

// TestKeyLookup_TenantExact_ExportBindsCaller covers the request paths that
// built their backend view from the raw request tenant: an acme caller that
// names another tenant is refused before any key is resolved.
func TestKeyLookup_TenantExact_ExportBindsCaller(t *testing.T) {
	svc, tenants := setupSameCNKeys(t)
	genKey(t, svc, "", "sysonly", "ecdsa", 0)
	acme := identityCtx("acme")

	// Same-CN exportable secrets in acme and the system tenant.
	for _, gen := range []struct {
		ctx    context.Context
		tenant string
	}{{acme, "acme"}, {context.Background(), ""}} {
		_, err := svc.GenerateKey(gen.ctx, &transport.GenerateKeyRequest{
			KeyID: "ek", Backend: "software", TenantID: gen.tenant,
			KeyType: "Symmetric", Algorithm: "Symmetric", KeySize: 256, Exportable: true,
		})
		require.NoError(t, err)
	}
	material := func(ctx context.Context, tenant string) ([]byte, error) {
		resp, err := svc.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{Backend: "software", KeyID: "ek", TenantID: tenant})
		if err != nil {
			return nil, err
		}
		return resp.KeyMaterial, nil
	}
	own, err := material(acme, "acme")
	require.NoError(t, err)
	sys, err := material(context.Background(), "")
	require.NoError(t, err)
	require.NotEqual(t, own, sys)
	omitted, err := material(acme, "")
	require.NoError(t, err)
	assert.Equal(t, own, omitted, "acme with no TenantID exports acme's key material")
	assert.NotEqual(t, sys, omitted, "acme with no TenantID never exports the system key's plaintext")

	const wrapAlg = string(backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	wrapped := func(tenant string) error {
		_, err := svc.ExportKey(acme, &transport.ExportKeyRequest{Backend: "software", KeyID: "ek", Algorithm: wrapAlg, TenantID: tenant})
		return err
	}
	// The omitted tenant exports acme's key: the wrapped blob, imported back
	// into acme and exported as material, is acme's secret, not the system's.
	exp, err := svc.ExportKey(acme, &transport.ExportKeyRequest{Backend: "software", KeyID: "ek", Algorithm: wrapAlg})
	require.NoError(t, err, "ExportKey with no TenantID exports acme's key")
	exportable := true
	_, err = svc.ImportKey(acme, &transport.ImportKeyRequest{
		Backend: "software", KeyID: "ek-rt", TenantID: "acme",
		KeyType: "symmetric", KeySize: 256, Exportable: &exportable,
		WrappedKeyMaterial: exp.WrappedKeyMaterial, Algorithm: exp.Algorithm,
		ImportToken: exp.ImportToken, Metadata: exp.Metadata,
	})
	require.NoError(t, err)
	rt, err := svc.ExportKeyMaterial(acme, &transport.ExportKeyMaterialRequest{Backend: "software", KeyID: "ek-rt", TenantID: "acme"})
	require.NoError(t, err)
	assert.Equal(t, own, rt.KeyMaterial, "ExportKey with no TenantID wraps acme's key material")
	assert.NotEqual(t, sys, rt.KeyMaterial, "ExportKey with no TenantID never wraps the system key")

	// A key version update with no TenantID never reaches the system key.
	_, _ = svc.DisableKeyVersion(acme, &transport.KeyVersionRequest{Backend: "software", KeyID: "sysonly", Version: 1})
	vers, err := svc.ListKeyVersions(context.Background(), &transport.ListKeyVersionsRequest{Backend: "software", KeyID: "sysonly"})
	require.NoError(t, err)
	require.Len(t, vers.Versions, 1)
	assert.Equal(t, "enabled", vers.Versions[0].State, "acme with no TenantID never changes a system-tenant key version")

	cases := []struct {
		name string
		call func(tenant string) error
	}{
		{"ExportKeyMaterial", func(tenant string) error {
			_, err := material(acme, tenant)
			return err
		}},
		{"ExportKey", wrapped},
		{"DisableKeyVersion", func(tenant string) error {
			_, err := svc.DisableKeyVersion(acme, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1, TenantID: tenant})
			return err
		}},
		{"RetireKeyVersion", func(tenant string) error {
			_, err := svc.RetireKeyVersion(acme, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1, TenantID: tenant})
			return err
		}},
		{"CopyKey", func(tenant string) error {
			_, err := svc.CopyKey(acme, &transport.CopyKeyRequest{SourceBackend: "software", DestBackend: "software", SourceKeyID: "ek", DestKeyID: "ek-copy", TenantID: tenant})
			return err
		}},
		{"WrapKeyByID", func(tenant string) error {
			_, err := svc.WrapKeyByID(acme, &transport.WrapKeyByIDRequest{WrappingKeyBackend: "software", WrappingKeyID: "ek", Algorithm: "AES-KWP", TargetKeyID: "ek", TenantID: tenant})
			return err
		}},
		{"UnwrapKeyByID", func(tenant string) error {
			_, err := svc.UnwrapKeyByID(acme, &transport.UnwrapKeyByIDRequest{WrappedKey: []byte("w"), UnwrappingKeyBackend: "software", UnwrappingKeyID: "ek", Algorithm: "AES-KWP", TargetKeyID: "t", TargetKeyBackend: "software", TenantID: tenant})
			return err
		}},
		{"DeriveKeyECDH", func(tenant string) error {
			_, err := svc.DeriveKeyECDH(acme, &transport.DeriveKeyECDHRequest{Backend: "software", KeyID: "k", PeerPublicKey: []byte("p"), TenantID: tenant})
			return err
		}},
		{"AttestKey", func(tenant string) error {
			_, err := svc.AttestKey(acme, &transport.AttestKeyRequest{Backend: "software", KeyID: "k", TenantID: tenant})
			return err
		}},
		{"DeriveKey", func(tenant string) error {
			_, err := svc.DeriveKey(acme, &transport.DeriveKeyRequest{Backend: "software", KeyID: "ek", Algorithm: "HKDF", Salt: []byte("s"), Info: []byte("i"), KeyLength: 32, Hash: "SHA-256", TenantID: tenant})
			return err
		}},
		{"Seal", func(tenant string) error {
			_, err := svc.Seal(acme, &transport.SealRequest{Backend: "software", KeyID: "ek", Data: []byte("d"), TenantID: tenant})
			return err
		}},
		{"Unseal", func(tenant string) error {
			_, err := svc.Unseal(acme, &transport.UnsealRequest{Backend: "software", KeyID: "ek", Ciphertext: []byte("c"), TenantID: tenant})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, other := range []string{"aaa", "platform"} {
				err := tc.call(other)
				var tbe *TenantBindingError
				assert.True(t, errors.As(err, &tbe), "acme naming tenant %q is refused with a TenantBindingError, got %v", other, err)
			}
		})
	}
	assertTenantKeysUnchanged(t, svc, tenants)
}
