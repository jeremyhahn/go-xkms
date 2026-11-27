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

package xkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// grantedRBAC is a recordingRBAC granting exactly the resource:action pairs
// in grants.
type grantedRBAC struct {
	*recordingRBAC
	grants map[string]bool
}

func (g grantedRBAC) Authorize(_ context.Context, _ *qrdbtransport.Identity, resource, action string) error {
	if g.grants[resource+":"+action] {
		return nil
	}
	return errGrantMissing
}

// signingKeyService returns a service with a Verifier wired and an
// Authorizer granting exactly grants, and a context for a tenant-a caller.
func signingKeyService(t *testing.T, grants ...string) (*XKMSService, context.Context) {
	t.Helper()
	svc := &XKMSService{}
	return svc, withSigningKeys(t, svc, grants...)
}

// withSigningKeys wires an in-memory Appraiser and an authorizer holding
// grants into svc, and returns a tenant-a caller's context.
func withSigningKeys(t *testing.T, svc *XKMSService, grants ...string) context.Context {
	t.Helper()
	store, err := appraisal.NewStore(appraisal.StoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	appraiser, err := appraisal.NewAppraiser(store)
	require.NoError(t, err)
	granted := grantedRBAC{recordingRBAC: &recordingRBAC{}, grants: map[string]bool{}}
	for _, g := range grants {
		granted.grants[g] = true
	}
	svc.SetAttestationAppraiser(appraiser)
	svc.SetAuthorizer(auth.NewAuthorizer(granted))
	return auth.WithIdentity(context.Background(), &auth.Identity{Subject: "release-manager", TenantID: "tenant-a"})
}

func TestSigningKeyBinding_SetResolveDelete(t *testing.T) {
	svc, ctx := signingKeyService(t, "attestation_signing_keys:bind", "attestation_signing_keys:get", "attestation_signing_keys:list")

	resolved, err := svc.ResolveSigningKey(ctx, &appraisal.ResolveSigningKeyRequest{Repository: "acme/app"})
	require.NoError(t, err)
	assert.Equal(t, appraisal.ReleaseSigningKeyID, resolved.KeyID)
	assert.True(t, resolved.Default)

	binding, err := svc.SetSigningKeyBinding(ctx, &appraisal.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "app-release"})
	require.NoError(t, err)
	assert.Equal(t, "app-release", binding.KeyID)

	got, err := svc.GetSigningKeyBinding(ctx, &appraisal.GetSigningKeyBindingRequest{Repository: "acme/app"})
	require.NoError(t, err)
	assert.Equal(t, binding, got)

	list, err := svc.ListSigningKeyBindings(ctx)
	require.NoError(t, err)
	require.Len(t, list.Bindings, 1)

	resolved, err = svc.ResolveSigningKey(ctx, &appraisal.ResolveSigningKeyRequest{Repository: "acme/app"})
	require.NoError(t, err)
	assert.Equal(t, "app-release", resolved.KeyID)
	assert.False(t, resolved.Default)

	require.NoError(t, svc.DeleteSigningKeyBinding(ctx, &appraisal.DeleteSigningKeyBindingRequest{Repository: "acme/app"}))
	resolved, err = svc.ResolveSigningKey(ctx, &appraisal.ResolveSigningKeyRequest{Repository: "acme/app"})
	require.NoError(t, err)
	assert.True(t, resolved.Default)
}

// TestSigningKeyBinding_RefusedWithoutBindPermission proves a caller without
// attestation_signing_keys:bind can neither set nor remove a binding, and the
// repository keeps its key. Removing the gate in authorizeSigningKeys
// makes this test fail.
func TestSigningKeyBinding_RefusedWithoutBindPermission(t *testing.T) {
	svc, ctx := signingKeyService(t, "attestation_signing_keys:get")

	_, err := svc.SetSigningKeyBinding(ctx, &appraisal.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "attacker"})
	require.ErrorIs(t, err, ErrSigningKeyForbidden)
	require.ErrorIs(t, err, errGrantMissing)
	var refusal *SigningKeyPermissionError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, "attestation_signing_keys:bind", refusal.Permission)
	assert.Contains(t, refusal.Error(), "attestation_signing_keys:bind")

	err = svc.DeleteSigningKeyBinding(ctx, &appraisal.DeleteSigningKeyBindingRequest{Repository: "acme/app"})
	require.ErrorIs(t, err, ErrSigningKeyForbidden)

	resolved, err := svc.ResolveSigningKey(ctx, &appraisal.ResolveSigningKeyRequest{Repository: "acme/app"})
	require.NoError(t, err)
	assert.True(t, resolved.Default, "a refused binding must not change the resolved key")
}

// TestSigningKeyBinding_ReadsRefusedWithoutPermission proves a caller
// without attestation_signing_keys:get cannot read a binding or resolve a
// repository's key, and one without :list cannot list the bindings, in
// process as at the wire gate.
func TestSigningKeyBinding_ReadsRefusedWithoutPermission(t *testing.T) {
	svc, ctx := signingKeyService(t, "attestation_signing_keys:bind")
	_, err := svc.SetSigningKeyBinding(ctx, &appraisal.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "app-release"})
	require.NoError(t, err)

	reads := map[string]func() error{
		"attestation_signing_keys:get": func() error {
			_, err := svc.GetSigningKeyBinding(ctx, &appraisal.GetSigningKeyBindingRequest{Repository: "acme/app"})
			return err
		},
		"attestation_signing_keys:list": func() error {
			_, err := svc.ListSigningKeyBindings(ctx)
			return err
		},
	}
	reads["resolve"] = func() error {
		_, err := svc.ResolveSigningKey(ctx, &appraisal.ResolveSigningKeyRequest{Repository: "acme/app"})
		return err
	}
	for name, read := range reads {
		err := read()
		require.ErrorIs(t, err, ErrSigningKeyForbidden, name)
		var refusal *SigningKeyPermissionError
		require.ErrorAs(t, err, &refusal, name)
		if name != "resolve" {
			assert.Equal(t, name, refusal.Permission)
		} else {
			assert.Equal(t, "attestation_signing_keys:get", refusal.Permission)
		}
	}
}

// TestSigningPublicKey_ResolvesTheTenantKey proves the service is the
// Appraiser's key source: a repository resolves to the tenant's release key
// until a binding names another of the tenant's keys.
func TestSigningPublicKey_ResolvesTheTenantKey(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	release := generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	app := generateSigningKey(t, svc, "tenant-a", "app-release")

	store, err := appraisal.NewStore(appraisal.StoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	appraiser, err := appraisal.NewAppraiser(store, appraisal.WithSigningKeySource(svc))
	require.NoError(t, err)
	keys := appraiser.TenantSigningKeys("tenant-a")

	key, err := keys.SigningKey(ctx, "acme/app")
	require.NoError(t, err)
	assert.True(t, release.(*ecdsa.PublicKey).Equal(key))

	_, err = appraiser.SetSigningKeyBinding(ctx, "tenant-a", &appraisal.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "app-release", Backend: "software"})
	require.NoError(t, err)
	key, err = keys.SigningKey(ctx, "acme/app")
	require.NoError(t, err)
	assert.True(t, app.(*ecdsa.PublicKey).Equal(key))
}

// TestSigningPublicKey_SystemTenantNeverTrustsAnotherTenantsKey proves the
// system tenant's lookup is restricted to its own keys: every tenant names its
// release key release-signing, and the unscoped system backend lists them all.
func TestSigningPublicKey_SystemTenantNeverTrustsAnotherTenantsKey(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	generateSigningKey(t, svc, "tenant-b", appraisal.ReleaseSigningKeyID)
	release := &appraisal.SigningKeyResolution{KeyID: appraisal.ReleaseSigningKeyID, Backend: "software"}

	for _, system := range []string{qrdbsdk.SystemTenantID, ""} {
		_, err := svc.SigningPublicKey(ctx, system, release)
		require.ErrorIs(t, err, ErrKeyNotFound, "system tenant %q holds no release key", system)
	}
}

// TestSigningPublicKey_EachTenantResolvesItsOwnKey proves every tenant,
// the system tenant included, resolves the shared release-signing ID to its
// own key.
func TestSigningPublicKey_EachTenantResolvesItsOwnKey(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	want := map[string]crypto.PublicKey{
		"tenant-a": generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID),
		"tenant-b": generateSigningKey(t, svc, "tenant-b", appraisal.ReleaseSigningKeyID),
	}
	want[qrdbsdk.SystemTenantID] = generateSigningKey(t, svc, qrdbsdk.SystemTenantID, appraisal.ReleaseSigningKeyID)
	release := &appraisal.SigningKeyResolution{KeyID: appraisal.ReleaseSigningKeyID, Backend: "software"}

	for tenant, pub := range want {
		got, err := svc.SigningPublicKey(ctx, tenant, release)
		require.NoError(t, err, tenant)
		assert.True(t, pub.(*ecdsa.PublicKey).Equal(got), "%s resolves its own release key", tenant)
	}
}

// generateSigningKey creates a P-256 signing key keyID in tenant on the
// software backend and returns its public half.
func generateSigningKey(t *testing.T, svc *XKMSService, tenant, keyID string) crypto.PublicKey {
	t.Helper()
	resp, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID: keyID, Backend: "software", KeyType: "signing", Algorithm: "ecdsa", Curve: "P-256", TenantID: tenant,
	})
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(resp.PublicKeyPEM))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	return pub
}

func TestSigningPublicKey_Errors(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()

	_, err := svc.SigningPublicKey(ctx, "tenant-a", nil)
	require.ErrorIs(t, err, appraisal.ErrNilRequest)

	_, err = svc.SigningPublicKey(ctx, "tenant-a", &appraisal.SigningKeyResolution{KeyID: "missing", Backend: "software"})
	require.Error(t, err, "a key the tenant does not hold resolves to nothing")

	_, err = svc.SigningPublicKey(ctx, "tenant-a", &appraisal.SigningKeyResolution{KeyID: appraisal.ReleaseSigningKeyID, Backend: "no-such-backend"})
	require.Error(t, err)
}

func TestSigningKeyBinding_NotConfigured(t *testing.T) {
	svc := &XKMSService{}
	ctx := context.Background()
	calls := map[string]func() error{
		"set": func() error {
			_, err := svc.SetSigningKeyBinding(ctx, &appraisal.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "k"})
			return err
		},
		"get": func() error {
			_, err := svc.GetSigningKeyBinding(ctx, &appraisal.GetSigningKeyBindingRequest{Repository: "acme/app"})
			return err
		},
		"list": func() error {
			_, err := svc.ListSigningKeyBindings(ctx)
			return err
		},
		"delete": func() error {
			return svc.DeleteSigningKeyBinding(ctx, &appraisal.DeleteSigningKeyBindingRequest{Repository: "acme/app"})
		},
		"resolve": func() error {
			_, err := svc.ResolveSigningKey(ctx, &appraisal.ResolveSigningKeyRequest{Repository: "acme/app"})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConfigured)
		})
	}
}
