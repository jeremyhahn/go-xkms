package xkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
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
