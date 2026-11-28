package xkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func samePublicKey(t *testing.T, want crypto.PublicKey, signer crypto.Signer) bool {
	t.Helper()
	pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	require.True(t, ok, "the signer's public key has no Equal")
	return pub.Equal(want)
}

func TestRepositorySigner_ReleaseKeyUnlessTheTenantNamedAnother(t *testing.T) {
	svc, appraiser, ctx := releaseSigningService(t, "attestation_signing_keys:sign")
	release := generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	app := generateSigningKey(t, svc, "tenant-a", "app-release")

	signer, err := svc.RepositorySigner(ctx, "acme/app")
	require.NoError(t, err)
	assert.True(t, samePublicKey(t, release, signer), "an unbound repository signs with the release key")

	_, err = appraiser.SetSigningKeyBinding(ctx, "tenant-a", &appraisal.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "app-release", Backend: "software"})
	require.NoError(t, err)
	signer, err = svc.RepositorySigner(ctx, "acme/app")
	require.NoError(t, err)
	assert.True(t, samePublicKey(t, app, signer), "a bound repository signs with its named key")

	signer, err = svc.RepositorySigner(ctx, "acme/other")
	require.NoError(t, err)
	assert.True(t, samePublicKey(t, release, signer), "the binding is per repository")
}

func TestRepositorySigner_RetainedSignerRefusesARebinding(t *testing.T) {
	svc, appraiser, ctx := releaseSigningService(t, "attestation_signing_keys:sign")
	generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	generateSigningKey(t, svc, "tenant-a", "app-a")
	generateSigningKey(t, svc, "tenant-a", "app-b")
	bind := func(keyID string) {
		t.Helper()
		_, err := appraiser.SetSigningKeyBinding(ctx, "tenant-a", &appraisal.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: keyID, Backend: "software"})
		require.NoError(t, err)
	}
	digest := sha256.Sum256([]byte("image"))

	bind("app-a")
	signer, err := svc.RepositorySigner(ctx, "acme/app")
	require.NoError(t, err)
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err, "sign while the binding holds")

	bind("app-b")
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	var changed *RepositorySigningKeyChangedError
	require.ErrorAs(t, err, &changed, "a retained signer refuses after the repository is bound to another key")

	bind("app-a")
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err, "binding the original key again restores the signer")

	require.NoError(t, appraiser.DeleteSigningKeyBinding(ctx, "tenant-a", &appraisal.DeleteSigningKeyBindingRequest{Repository: "acme/app"}))
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.ErrorAs(t, err, &changed, "a retained signer refuses after the repository binding is deleted")
}

func TestRepositorySigner_RetainedSignerRefusesARevokedGrant(t *testing.T) {
	svc, appraiser, ctx := releaseSigningService(t, "attestation_signing_keys:sign")
	generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	generateSigningKey(t, svc, "tenant-a", "app-a")
	_, err := appraiser.SetSigningKeyBinding(ctx, "tenant-a", &appraisal.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "app-a", Backend: "software"})
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("image"))

	signer, err := svc.RepositorySigner(ctx, "acme/app")
	require.NoError(t, err)
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err, "sign while the grant holds")

	svc.SetAuthorizer(auth.NewAuthorizer(grantedRBAC{recordingRBAC: &recordingRBAC{}, grants: map[string]bool{}}))
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	var denied *SigningKeyPermissionError
	require.ErrorAs(t, err, &denied, "a retained signer refuses after the sign grant is revoked")
}

func TestOpaqueSigner_SignsPKCS1v15(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tests := map[string]struct {
		signer crypto.Signer
		sigAlg x509.SignatureAlgorithm
		store  types.StoreType
		want   bool
	}{
		"fixed-PSS GCP key":         {signer: rsaKey, sigAlg: x509.SHA256WithRSAPSS, store: types.StoreGCPKMS, want: false},
		"PKCS#1 v1.5 GCP key":       {signer: rsaKey, sigAlg: x509.SHA256WithRSA, store: types.StoreGCPKMS, want: true},
		"GCP key of unknown alg":    {signer: rsaKey, store: types.StoreGCPKMS, want: false},
		"software key follows opts": {signer: rsaKey, sigAlg: x509.SHA256WithRSAPSS, store: types.StoreSoftware, want: true},
		"ECDSA key":                 {signer: ecKey, store: types.StoreGCPKMS, want: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			o := opaqueSigner{signer: tt.signer, sigAlg: tt.sigAlg, store: tt.store}
			assert.Equal(t, tt.want, o.SignsPKCS1v15())
		})
	}
}

// TestRepositorySigner_IsOpaque checks that the signer exposes only Public
// and Sign: a caller cannot type-assert it back to the backend's private key
// (a software backend's signer is the *ecdsa.PrivateKey itself).
func TestRepositorySigner_IsOpaque(t *testing.T) {
	svc, _, ctx := releaseSigningService(t, "attestation_signing_keys:sign")
	generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)

	signer, err := svc.RepositorySigner(ctx, "acme/app")
	require.NoError(t, err)
	_, isKey := signer.(*ecdsa.PrivateKey)
	assert.False(t, isKey, "the signer must not be the backend's private key")
	_, isPrivate := signer.(interface{ Equal(crypto.PrivateKey) bool })
	assert.False(t, isPrivate, "the signer must expose only Public and Sign")
	_, isDecrypter := signer.(crypto.Decrypter)
	assert.False(t, isDecrypter)

	digest := sha256.Sum256([]byte("release"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.True(t, ecdsa.VerifyASN1(pub, digest[:], sig), "the opaque signer still signs through the backend")
}

func TestRepositorySigner_Refusals(t *testing.T) {
	svc, _, ctx := releaseSigningService(t, "attestation_signing_keys:get")
	generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	_, err := svc.RepositorySigner(ctx, "acme/app")
	require.ErrorIs(t, err, ErrSigningKeyForbidden, "signing needs the sign permission")

	svc, _, ctx = releaseSigningService(t, "attestation_signing_keys:sign")
	generateSigningKey(t, svc, "tenant-b", appraisal.ReleaseSigningKeyID)
	_, err = svc.RepositorySigner(ctx, "acme/app")
	require.ErrorIs(t, err, ErrKeyNotFound, "never another tenant's key")

	_, err = (&XKMSService{}).RepositorySigner(context.Background(), "acme/app")
	require.Error(t, err, "no appraiser configured")
}
