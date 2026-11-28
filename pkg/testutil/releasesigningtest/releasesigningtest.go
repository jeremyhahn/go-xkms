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

// Package releasesigningtest holds the fixtures of the wire-contract tests of
// release CoRIM signing (XKMSService.SignReleaseCoRIM, go-xkms#2190): a
// service over a software backend with one tenant's release key, an
// authorizer granting only the named permissions, and an unsigned CoRIM.
package releasesigningtest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/corim"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

const (
	// Tenant is the caller's tenant.
	Tenant = "tenant-a"
	// ForeignTenant is another tenant.
	ForeignTenant = "tenant-b"
	// Repository is the repository every signing request names.
	Repository = "acme/app"
	// SignPermission is the permission CoRIM signing needs.
	SignPermission = auth.ResourceAttestationSigningKeys + ":" + auth.ActionSign
)

// errGrantMissing is the authorizer's refusal of a permission not granted.
var errGrantMissing = errors.New("releasesigningtest: permission not granted")

// grants is an RBAC client allowing exactly the named permissions.
type grants map[string]bool

func (g grants) Authorize(_ context.Context, _ *qrdbtransport.Identity, resource, action string) error {
	if g[resource+":"+action] {
		return nil
	}
	return errGrantMissing
}

func (g grants) ListPermissions(context.Context, *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, errGrantMissing
}

func (g grants) ListOwnPermissions(ctx context.Context) ([]qrdbtransport.PermissionInfo, error) {
	return g.ListPermissions(ctx, nil)
}

// Fixture is a signing service and the release key it holds.
type Fixture struct {
	// Service signs CoRIMs; its caller needs Context's identity.
	Service *xkms.XKMSService
	// ReleaseKey is the public half of keyTenant's release key.
	ReleaseKey crypto.PublicKey
}

// New returns a service over a software backend, with an appraiser, the
// release key of keyTenant, and an authorizer granting only perms. It resets
// the xkms singleton, so its tests must not run in parallel.
func New(t testing.TB, keyTenant string, perms ...string) *Fixture {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	backend, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	ks, err := xkms.New(&xkms.BackendConfig{Backend: backend, CertStorage: storage.New()})
	require.NoError(t, err)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
		DefaultBackend: "software",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	versions, err := keyversion.NewStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	svc.SetKeyVersionStore(versions)

	store, err := appraisal.NewStore(appraisal.StoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	appraiser, err := appraisal.NewAppraiser(store, appraisal.WithSigningKeySource(svc))
	require.NoError(t, err)
	svc.SetAttestationAppraiser(appraiser)
	g := grants{}
	for _, p := range perms {
		g[p] = true
	}
	svc.SetAuthorizer(auth.NewAuthorizer(g))

	resp, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID: appraisal.ReleaseSigningKeyID, Backend: "software", KeyType: "signing",
		Algorithm: "ecdsa", Curve: "P-256", TenantID: keyTenant,
	})
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(resp.PublicKeyPEM))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	return &Fixture{Service: svc, ReleaseKey: pub}
}

// Identity is the release pipeline of tenant.
func Identity(tenant string) *auth.Identity {
	return &auth.Identity{Subject: "release-pipeline", TenantID: tenant}
}

// Context carries the release pipeline of tenant.
func Context(tenant string) context.Context {
	return auth.WithIdentity(context.Background(), Identity(tenant))
}

// UnsignedCoRIM returns the CBOR of an unsigned CoRIM with one PCR value.
func UnsignedCoRIM(t testing.TB) []byte {
	t.Helper()
	throwaway, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signed, err := appraisaltest.SignCoRIMDigests([]appraisaltest.PCRDigest{{Index: 0, Hash: crypto.SHA256, Value: make([]byte, 32)}}, throwaway, nil)
	require.NoError(t, err)
	var sc corim.SignedCorim
	require.NoError(t, sc.FromCOSE(signed))
	out, err := sc.UnsignedCorim.ToCBOR()
	require.NoError(t, err)
	return out
}

// Request is the signing request of Repository over corim.
func Request(corim []byte) *transport.SignReleaseCoRIMRequest {
	return &transport.SignReleaseCoRIMRequest{Repository: Repository, CoRIM: corim}
}
