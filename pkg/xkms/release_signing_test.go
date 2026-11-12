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
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/corim"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// releaseSigningService is a service with a software backend, an appraiser
// and the caller tenant-a holding the given grants.
func releaseSigningService(t *testing.T, grants ...string) (*XKMSService, *appraisal.Appraiser, context.Context) {
	t.Helper()
	svc := setupDeriveService(t)
	store, err := appraisal.NewStore(appraisal.StoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	appraiser, err := appraisal.NewAppraiser(store, appraisal.WithSigningKeySource(svc))
	require.NoError(t, err)
	granted := grantedRBAC{recordingRBAC: &recordingRBAC{}, grants: map[string]bool{}}
	for _, g := range grants {
		granted.grants[g] = true
	}
	svc.SetAttestationAppraiser(appraiser)
	svc.SetAuthorizer(auth.NewAuthorizer(granted))
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "release-pipeline", TenantID: "tenant-a"})
	return svc, appraiser, ctx
}

// unsignedCoRIM returns the CBOR of an unsigned CoRIM with one PCR value.
func unsignedCoRIM(t *testing.T) []byte {
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

func TestSignReleaseCoRIM_SignsWithTheRepositoryKey(t *testing.T) {
	svc, appraiser, ctx := releaseSigningService(t, "attestation_signing_keys:sign")
	release := generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	app := generateSigningKey(t, svc, "tenant-a", "app-release")
	payload := unsignedCoRIM(t)

	resp, err := svc.SignReleaseCoRIM(ctx, &SignReleaseCoRIMRequest{Repository: "acme/app", CoRIM: payload})
	require.NoError(t, err)
	assert.Equal(t, appraisal.ReleaseSigningKeyID, resp.KeyID)
	m, err := refvalue.VerifySigned(resp.SignedCoRIM, refvalue.VerifyOptions{PublicKey: release})
	require.NoError(t, err)
	assert.Equal(t, "acme/app", m.Signer, "the signer name defaults to the repository")
	_, err = refvalue.VerifySigned(resp.SignedCoRIM, refvalue.VerifyOptions{PublicKey: app})
	require.ErrorIs(t, err, refvalue.ErrSignature)

	_, err = appraiser.SetSigningKeyBinding(ctx, "tenant-a", &appraisal.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "app-release", Backend: "software"})
	require.NoError(t, err)
	resp, err = svc.SignReleaseCoRIM(ctx, &SignReleaseCoRIMRequest{Repository: "acme/app", CoRIM: payload, SignerName: "Acme Releases"})
	require.NoError(t, err)
	assert.Equal(t, "app-release", resp.KeyID)
	m, err = refvalue.VerifySigned(resp.SignedCoRIM, refvalue.VerifyOptions{PublicKey: app})
	require.NoError(t, err)
	assert.Equal(t, "Acme Releases", m.Signer)
}

func TestSignReleaseCoRIM_UnknownKeyIsNotFound(t *testing.T) {
	svc, _, ctx := releaseSigningService(t, "attestation_signing_keys:sign")
	_, err := svc.SignReleaseCoRIM(ctx, &SignReleaseCoRIMRequest{Repository: "acme/app", CoRIM: unsignedCoRIM(t)})
	require.ErrorIs(t, err, ErrKeyNotFound)
}

func TestSignReleaseCoRIM_NeverSignsWithAnotherTenantsKey(t *testing.T) {
	svc, _, ctx := releaseSigningService(t, "attestation_signing_keys:sign")
	generateSigningKey(t, svc, "tenant-b", appraisal.ReleaseSigningKeyID)
	_, err := svc.SignReleaseCoRIM(ctx, &SignReleaseCoRIMRequest{Repository: "acme/app", CoRIM: unsignedCoRIM(t)})
	require.ErrorIs(t, err, ErrKeyNotFound)
}

func TestSignReleaseCoRIM_RefusedWithoutSignPermission(t *testing.T) {
	svc, _, ctx := releaseSigningService(t, "attestation_signing_keys:get")
	generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	_, err := svc.SignReleaseCoRIM(ctx, &SignReleaseCoRIMRequest{Repository: "acme/app", CoRIM: unsignedCoRIM(t)})
	require.ErrorIs(t, err, ErrSigningKeyForbidden)
	var refusal *SigningKeyPermissionError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, "attestation_signing_keys:sign", refusal.Permission)
}

func TestSignReleaseCoRIM_Refusals(t *testing.T) {
	svc, _, ctx := releaseSigningService(t, "attestation_signing_keys:sign")
	generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)

	_, err := svc.SignReleaseCoRIM(ctx, nil)
	require.ErrorIs(t, err, appraisal.ErrNilRequest)

	_, err = svc.SignReleaseCoRIM(ctx, &SignReleaseCoRIMRequest{Repository: "Acme/App", CoRIM: unsignedCoRIM(t)})
	require.ErrorIs(t, err, appraisal.ErrInvalidRepository)

	_, err = svc.SignReleaseCoRIM(ctx, &SignReleaseCoRIMRequest{Repository: "acme/app", CoRIM: []byte{0xff}})
	require.ErrorIs(t, err, refvalue.ErrMalformed)
}

func TestSignReleaseCoRIM_NotConfigured(t *testing.T) {
	svc := &XKMSService{}
	_, err := svc.SignReleaseCoRIM(context.Background(), &SignReleaseCoRIMRequest{Repository: "acme/app"})
	require.Error(t, err)
}
