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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/corim"
	"github.com/veraison/go-cose"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
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

// TestReleaseSigning_HonoursKeyPolicy disables the release key in the key
// policy store: release signing and the repository signer refuse it, as
// XKMSService.Sign does.
func TestReleaseSigning_HonoursKeyPolicy(t *testing.T) {
	svc, _, ctx := releaseSigningService(t, "attestation_signing_keys:sign")
	store, err := keypolicy.NewStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	svc.SetKeyPolicyStore(store)
	generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	_, err = svc.UpdateKeyStatus(ctx, &transport.UpdateKeyStatusRequest{Backend: "software", KeyID: appraisal.ReleaseSigningKeyID, Status: transport.KeyStatusDisabled})
	require.NoError(t, err)

	var unavailable *keypolicy.KeyUnavailableError
	_, err = svc.SignReleaseCoRIM(ctx, &SignReleaseCoRIMRequest{Repository: "acme/app", CoRIM: unsignedCoRIM(t)})
	require.ErrorAs(t, err, &unavailable)
	assert.Equal(t, keypolicy.StatusDisabled, unavailable.Status)
	_, err = svc.RepositorySigner(ctx, "acme/app")
	require.ErrorAs(t, err, &unavailable)
}

// TestRepositorySigner_AdmitsEverySign: a retained repository signer is
// admitted under key policy on each Sign, not only when it is obtained, so a
// key disabled afterwards, or one whose usage count is spent, stops signing.
func TestRepositorySigner_AdmitsEverySign(t *testing.T) {
	digest := make([]byte, 32)
	t.Run("disabled after retain", func(t *testing.T) {
		svc, _, ctx := releaseSigningService(t, "attestation_signing_keys:sign")
		store, err := keypolicy.NewStore(testutil.NewMemoryDAOFactory())
		require.NoError(t, err)
		svc.SetKeyPolicyStore(store)
		generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
		signer, err := svc.RepositorySigner(ctx, "acme/app")
		require.NoError(t, err)
		_, err = svc.UpdateKeyStatus(ctx, &transport.UpdateKeyStatusRequest{Backend: "software", KeyID: appraisal.ReleaseSigningKeyID, Status: transport.KeyStatusDisabled})
		require.NoError(t, err)
		_, err = signer.Sign(rand.Reader, digest, crypto.SHA256)
		var unavailable *keypolicy.KeyUnavailableError
		require.ErrorAs(t, err, &unavailable)
	})
	t.Run("usage count spent", func(t *testing.T) {
		svc, _, ctx := releaseSigningService(t, "attestation_signing_keys:sign")
		store, err := keypolicy.NewStore(testutil.NewMemoryDAOFactory())
		require.NoError(t, err)
		svc.SetKeyPolicyStore(store)
		generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
		_, err = svc.SetKeyPolicy(ctx, &transport.SetKeyPolicyRequest{Backend: "software", KeyID: appraisal.ReleaseSigningKeyID, Policy: &transport.KeyPolicy{MaxUsageCount: 1}})
		require.NoError(t, err)
		signer, err := svc.RepositorySigner(ctx, "acme/app")
		require.NoError(t, err)
		_, firstErr := signer.Sign(rand.Reader, digest, crypto.SHA256)
		_, err = signer.Sign(rand.Reader, digest, crypto.SHA256)
		require.Error(t, err, "a MaxUsageCount=1 key signed more than once (first sign: %v)", firstErr)
	})
}

// TestRepositorySigner_KeepsItsKeyAcrossRotation checks that a retained
// signer whose key gets a newer version either refuses or keeps signing with
// the key its Public returns; it never signs under a different key.
func TestRepositorySigner_KeepsItsKeyAcrossRotation(t *testing.T) {
	svc, _, ctx := releaseSigningService(t, "attestation_signing_keys:sign")
	store, err := keypolicy.NewStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	svc.SetKeyPolicyStore(store)
	generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	// A usage-tracking policy makes admission follow the counters to the
	// newest version.
	_, err = svc.SetKeyPolicy(ctx, &transport.SetKeyPolicyRequest{Backend: "software", KeyID: appraisal.ReleaseSigningKeyID, Policy: &transport.KeyPolicy{MaxUsageCount: 10}})
	require.NoError(t, err)
	signer, err := svc.RepositorySigner(ctx, "acme/app")
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("release"))
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err, "sign before the rotation")
	_, err = svc.RotateKey(ctx, &transport.RotateKeyRequest{Backend: "software", KeyID: appraisal.ReleaseSigningKeyID, TenantID: "tenant-a"})
	require.NoError(t, err)
	// A signer resolved after the rotation moves the usage counters to the
	// new version.
	fresh, err := svc.RepositorySigner(ctx, "acme/app")
	require.NoError(t, err)
	_, err = fresh.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err, "sign with the new version")

	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return // refusing after a rotation is acceptable
	}
	var ok bool
	switch pub := signer.Public().(type) {
	case *ecdsa.PublicKey:
		ok = ecdsa.VerifyASN1(pub, digest[:], sig)
	case *rsa.PublicKey:
		ok = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) == nil ||
			rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, nil) == nil
	default:
		t.Fatalf("unexpected public key type %T", pub)
	}
	require.True(t, ok, "the retained signer signed under a key other than its Public()")
}

// TestRepositorySigner_RefusesAnUnusableVersion checks that a retained
// signer stops signing once its key version is disabled or retired, or its
// key deleted: the version is revalidated on every Sign, with or without a
// key policy store.
func TestRepositorySigner_RefusesAnUnusableVersion(t *testing.T) {
	digest := sha256.Sum256([]byte("release"))
	version := func(n uint32) *transport.KeyVersionRequest {
		return &transport.KeyVersionRequest{Backend: "software", KeyID: appraisal.ReleaseSigningKeyID, Version: n, TenantID: "tenant-a"}
	}
	cases := map[string]func(t *testing.T, svc *XKMSService, ctx context.Context){
		// The current version cannot be disabled or retired, so both follow a
		// rotation.
		"disabled after rotation": func(t *testing.T, svc *XKMSService, ctx context.Context) {
			_, err := svc.RotateKey(ctx, &transport.RotateKeyRequest{Backend: "software", KeyID: appraisal.ReleaseSigningKeyID, TenantID: "tenant-a"})
			require.NoError(t, err)
			_, err = svc.DisableKeyVersion(ctx, version(1))
			require.NoError(t, err)
		},
		"retired after rotation": func(t *testing.T, svc *XKMSService, ctx context.Context) {
			_, err := svc.RotateKey(ctx, &transport.RotateKeyRequest{Backend: "software", KeyID: appraisal.ReleaseSigningKeyID, TenantID: "tenant-a"})
			require.NoError(t, err)
			_, err = svc.RetireKeyVersion(ctx, version(1))
			require.NoError(t, err)
		},
		"deleted": func(t *testing.T, svc *XKMSService, ctx context.Context) {
			require.NoError(t, svc.DeleteKey(ctx, "software", appraisal.ReleaseSigningKeyID))
		},
		// A new key under the same ID is not the key the signer reports.
		"deleted and re-created": func(t *testing.T, svc *XKMSService, ctx context.Context) {
			require.NoError(t, svc.DeleteKey(ctx, "software", appraisal.ReleaseSigningKeyID))
			generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
		},
	}
	for name, change := range cases {
		for _, withPolicies := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/policies=%v", name, withPolicies), func(t *testing.T) {
				svc, _, ctx := releaseSigningService(t, "attestation_signing_keys:sign")
				if withPolicies {
					store, err := keypolicy.NewStore(testutil.NewMemoryDAOFactory())
					require.NoError(t, err)
					svc.SetKeyPolicyStore(store)
				}
				generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
				signer, err := svc.RepositorySigner(ctx, "acme/app")
				require.NoError(t, err)
				_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
				require.NoError(t, err, "sign before the change")

				change(t, svc, ctx)
				_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
				require.Error(t, err, "a retained signer signed with an unusable key version")
			})
		}
	}
}

func TestCoseAlgorithm(t *testing.T) {
	for _, tc := range []struct {
		curve elliptic.Curve
		want  cose.Algorithm
	}{
		{elliptic.P256(), cose.AlgorithmES256},
		{elliptic.P384(), cose.AlgorithmES384},
		{elliptic.P521(), cose.AlgorithmES512},
	} {
		k, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		require.NoError(t, err)
		got, err := coseAlgorithm(k.Public(), x509.UnknownSignatureAlgorithm)
		require.NoError(t, err)
		assert.Equal(t, tc.want, got)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	got, err := coseAlgorithm(edPub, x509.UnknownSignatureAlgorithm)
	require.NoError(t, err)
	assert.Equal(t, cose.AlgorithmEdDSA, got)
	_, err = coseAlgorithm(struct{}{}, x509.UnknownSignatureAlgorithm)
	require.ErrorIs(t, err, refvalue.ErrUnsupportedKey)
}

// TestCoseAlgorithm_RSAFollowsTheKeyPadding: an RSA key's COSE algorithm is
// the padding its backend produces. A PKCS#1 v1.5 key (GCP KMS
// RSA_SIGN_PKCS1_*) or one whose padding is not recorded is refused, never
// labelled PS256.
func TestCoseAlgorithm_RSAFollowsTheKeyPadding(t *testing.T) {
	pub := &rsa.PublicKey{}
	for _, tc := range []struct {
		sigAlg x509.SignatureAlgorithm
		want   cose.Algorithm
	}{
		{x509.SHA256WithRSAPSS, cose.AlgorithmPS256},
		{x509.SHA384WithRSAPSS, cose.AlgorithmPS384},
		{x509.SHA512WithRSAPSS, cose.AlgorithmPS512},
	} {
		got, err := coseAlgorithm(pub, tc.sigAlg)
		require.NoError(t, err, tc.sigAlg.String())
		assert.Equal(t, tc.want, got, tc.sigAlg.String())
	}
	for _, sigAlg := range []x509.SignatureAlgorithm{
		x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA, x509.UnknownSignatureAlgorithm,
	} {
		got, err := coseAlgorithm(pub, sigAlg)
		require.ErrorIs(t, err, refvalue.ErrUnsupportedKey, sigAlg.String())
		assert.NotEqual(t, cose.AlgorithmPS256, got, sigAlg.String())
	}
}

// TestRepositorySigner_CarriesTheKeySignatureAlgorithm: the wrapped signer
// keeps the key's recorded signature algorithm so release signing can pick
// the COSE algorithm the backend produces.
func TestRepositorySigner_CarriesTheKeySignatureAlgorithm(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, err = releaseAlgorithm(opaqueSigner{signer: k, sigAlg: x509.SHA256WithRSA})
	require.ErrorIs(t, err, refvalue.ErrUnsupportedKey)
	got, err := releaseAlgorithm(opaqueSigner{signer: k, sigAlg: x509.SHA256WithRSAPSS})
	require.NoError(t, err)
	assert.Equal(t, cose.AlgorithmPS256, got)
}
