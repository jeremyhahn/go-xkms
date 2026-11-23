// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package xkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PIV is platform-scoped: its key generator works on the unscoped backend,
// so a slot CN must name the system tenant's key only, never a dedicated
// tenant's key that happens to share the slot's name.

// pivTenantSetup stores tenant "aaa"'s key under the slot CN of 9a on the
// real software backend and returns a PIV key generator on the unscoped
// (system tenant) view, with a PIV certificate store registered for
// "software".
func pivTenantSetup(t *testing.T) (*backendPIVKeyGenerator, Backend, pivcert.PIVSlot, string) {
	t.Helper()
	svc := setupDeriveService(t)
	ResetPIV()
	t.Cleanup(ResetPIV)
	require.NoError(t, InitializePIV(&PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{"software": newMockPIVCertStorage()},
	}))

	slot := pivcert.PIVSlotAuthentication
	cn := PivSlotCN(slot)
	genKey(t, svc, "aaa", cn, "ecdsa", 0)

	b := unscopedSoftware(t, svc)
	return newBackendPIVKeyGenerator(b, types.StoreSoftware), b, slot, cn
}

// slotKeyPublic returns the public key of tenant's key under cn in the
// unscoped listing, and whether one exists.
func slotKeyPublic(t *testing.T, b Backend, cn, tenant string) (crypto.PublicKey, bool) {
	t.Helper()
	keys, err := b.ListKeys(context.Background())
	require.NoError(t, err)
	for _, ka := range keys {
		if ka != nil && ka.CN == cn && recordTenant(ka.TenantID) == tenant {
			s, err := b.Signer(context.Background(), ka)
			require.NoError(t, err)
			return s.Public(), true
		}
	}
	return nil, false
}

// requireTenantListedFirst asserts the unscoped listing names the "aaa" key
// before the platform key, so a first-match scan would pick the tenant's.
func requireTenantListedFirst(t *testing.T, b Backend, cn string) {
	t.Helper()
	keys, err := b.ListKeys(context.Background())
	require.NoError(t, err)
	for _, ka := range keys {
		if ka != nil && ka.CN == cn {
			require.Equal(t, "aaa", recordTenant(ka.TenantID),
				"the unscoped listing lists the tenant's key before the platform key")
			return
		}
	}
	t.Fatalf("no key %q listed", cn)
}

func equalPublic(t *testing.T, want, got crypto.PublicKey) bool {
	t.Helper()
	eq, ok := want.(interface{ Equal(crypto.PublicKey) bool })
	require.True(t, ok)
	return eq.Equal(got)
}

func TestPIVTenantExact_ImportOriginSignerSelfSign(t *testing.T) {
	gen, b, slot, cn := pivTenantSetup(t)
	ctx := context.Background()
	tenantPub, ok := slotKeyPublic(t, b, cn, "aaa")
	require.True(t, ok)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	// ImportPIVKey reads the provenance back through PIVKeyOrigin: it must
	// read the platform key it just imported, not the tenant's key.
	_, err = gen.ImportPIVKey(ctx, slot, "ecdsap256", cn, key)
	require.NoError(t, err)
	requireTenantListedFirst(t, b, cn)

	origin, found, err := gen.PIVKeyOrigin(slot, cn)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, types.KeyOriginImported, origin)

	signer, err := gen.GetPIVSigner(slot, cn)
	require.NoError(t, err)
	assert.True(t, equalPublic(t, key.Public(), signer.Public()), "GetPIVSigner signs with the platform key")

	certPEM, err := SelfSignExistingPIVKey(ctx, "software", string(slot), "", 30)
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, equalPublic(t, key.Public(), cert.PublicKey), "the self-signed certificate certifies the platform key")

	got, ok := slotKeyPublic(t, b, cn, "aaa")
	require.True(t, ok, "the tenant's key survives")
	assert.True(t, equalPublic(t, tenantPub, got))
}

func TestPIVTenantExact_RekeyDeletesOnlyPlatformKey(t *testing.T) {
	gen, b, slot, cn := pivTenantSetup(t)
	tenantPub, ok := slotKeyPublic(t, b, cn, "aaa")
	require.True(t, ok)

	first, err := gen.GeneratePIVKey(slot, "ecdsap256", cn)
	require.NoError(t, err)
	got, ok := slotKeyPublic(t, b, cn, "aaa")
	require.True(t, ok, "generating into the slot keeps the tenant's key")
	assert.True(t, equalPublic(t, tenantPub, got))
	requireTenantListedFirst(t, b, cn)

	// Rekey the occupied slot: only the platform key is replaced.
	second, err := gen.GeneratePIVKey(slot, "ecdsap256", cn)
	require.NoError(t, err)
	assert.False(t, equalPublic(t, first.Public(), second.Public()))

	got, ok = slotKeyPublic(t, b, cn, "aaa")
	require.True(t, ok, "the rekey keeps the tenant's key")
	assert.True(t, equalPublic(t, tenantPub, got))

	platform, ok := slotKeyPublic(t, b, cn, "")
	require.True(t, ok)
	assert.True(t, equalPublic(t, second.Public(), platform))

	signer, err := gen.GetPIVSigner(slot, cn)
	require.NoError(t, err)
	assert.True(t, equalPublic(t, second.Public(), signer.Public()))
}

func TestPIVTenantExact_OnlyTenantKey(t *testing.T) {
	gen, _, slot, cn := pivTenantSetup(t)

	_, found, err := gen.PIVKeyOrigin(slot, cn)
	require.NoError(t, err)
	assert.False(t, found, "a tenant's key is not the slot's key")

	_, err = SelfSignExistingPIVKey(context.Background(), "software", string(slot), "", 30)
	assert.ErrorIs(t, err, ErrPIVNotInitialized)
}
