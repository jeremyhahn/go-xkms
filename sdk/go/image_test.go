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

package xkms_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/image"
	"github.com/jeremyhahn/go-xkms/pkg/signing"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time proof the image aliases are the pkg/image types, and that the
// SDK's CA is the certificate issuer an image signer asks for its
// code-signing certificate.
var (
	_ image.SignerConfig                = xkms.ImageSignerConfig{}
	_ xkms.ImageSignerConfig            = image.SignerConfig{}
	_ image.VerifierConfig[purpose]     = xkms.ImageVerifierConfig[purpose]{}
	_ xkms.ImageVerifierConfig[purpose] = image.VerifierConfig[purpose]{}
	_ *image.Attestation                = (*xkms.ImageAttestation)(nil)
	_ *xkms.ImageAttestation            = (*image.Attestation)(nil)
	_ xkms.ImageTimestamper             = (*xkms.RFC3161Client)(nil)
	_ xkms.ImageCertificateIssuer       = (*xkms.CA)(nil)
	_ xkms.ImageRootStore[purpose]      = rootStore{}
)

// purpose stands in for the trust-roots purpose type.
type purpose string

// rootStore serves one fixed set of roots for every purpose.
type rootStore struct {
	roots []*x509.Certificate
}

func (s rootStore) CertificatesByPurpose(purpose) ([]*x509.Certificate, error) {
	return s.roots, nil
}

func TestImageVerifierIsConstructableFromTheSDK(t *testing.T) {
	registry, err := xkms.NewImageRegistryClient(nil)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, registry.Close()) })

	verifier, err := xkms.NewImageVerifier(&xkms.ImageVerifierConfig[purpose]{
		Registry: registry,
		Roots:    rootStore{},
		Purpose:  "image-signer",
	})
	require.NoError(t, err)
	assert.NotNil(t, verifier)
}

func TestImageConstructorsRefuseThroughTheSDK(t *testing.T) {
	verifier, err := xkms.NewImageVerifier[purpose](nil)
	assert.Nil(t, verifier)
	assert.ErrorIs(t, err, xkms.ErrImageRegistryRequired)

	signer, err := xkms.NewImageSigner(nil)
	assert.Nil(t, signer)
	assert.ErrorIs(t, err, xkms.ErrImageSignerRequired)

	reference, err := xkms.ParseImageReference("gcr.io/MyImage:v1")
	assert.Nil(t, reference)
	assert.ErrorIs(t, err, xkms.ErrImageInvalidReference)
}

func TestParseImageReference(t *testing.T) {
	reference, err := xkms.ParseImageReference("registry.example.com/team/app:v1")
	require.NoError(t, err)
	assert.Equal(t, "registry.example.com", reference.Registry)
	assert.Equal(t, "team/app", reference.Repository)
	assert.Equal(t, "v1", reference.Tag)
}

// TestImageErrorsAreTheCanonicalSentinels pins identity rather than equality:
// an alias to a copy compiles and never matches under errors.Is.
func TestImageErrorsAreTheCanonicalSentinels(t *testing.T) {
	pairs := []struct {
		name string
		sdk  error
		pkg  error
	}{
		{"invalid reference", xkms.ErrImageInvalidReference, image.ErrInvalidReference},
		{"invalid digest", xkms.ErrImageInvalidDigest, image.ErrInvalidDigest},
		{"digest required", xkms.ErrImageDigestRequired, image.ErrDigestRequired},
		{"signer required", xkms.ErrImageSignerRequired, image.ErrSignerRequired},
		{"certificate required", xkms.ErrImageCertificateRequired, image.ErrCertificateRequired},
		{"registry required", xkms.ErrImageRegistryRequired, image.ErrRegistryRequired},
		{"issuer required", xkms.ErrImageIssuerRequired, image.ErrIssuerRequired},
		{"common name required", xkms.ErrImageCommonNameRequired, image.ErrCommonNameRequired},
		{"key mismatch", xkms.ErrImageKeyMismatch, image.ErrKeyMismatch},
		{"not code signing", xkms.ErrImageNotCodeSigning, image.ErrNotCodeSigning},
		{"certificate not valid", xkms.ErrImageCertificateNotValid, image.ErrCertificateNotValid},
		{"unsupported key", xkms.ErrImageUnsupportedKey, image.ErrUnsupportedKey},
		{"csr failed", xkms.ErrImageCSRFailed, image.ErrCSRFailed},
		{"certificate request failed", xkms.ErrImageCertificateRequestFailed, image.ErrCertificateRequestFailed},
		{"signing failed", xkms.ErrImageSigningFailed, image.ErrSigningFailed},
		{"encoding failed", xkms.ErrImageEncodingFailed, image.ErrEncodingFailed},
		{"registry request", xkms.ErrImageRegistryRequest, image.ErrRegistryRequest},
		{"registry unavailable", xkms.ErrImageRegistryUnavailable, image.ErrRegistryUnavailable},
		{"registry auth", xkms.ErrImageRegistryAuth, image.ErrRegistryAuth},
		{"registry credentials", xkms.ErrImageRegistryCredentials, image.ErrRegistryCredentials},
		{"manifest not found", xkms.ErrImageManifestNotFound, image.ErrManifestNotFound},
		{"invalid manifest", xkms.ErrImageInvalidManifest, image.ErrInvalidManifest},
		{"digest mismatch", xkms.ErrImageDigestMismatch, image.ErrDigestMismatch},
		{"response too large", xkms.ErrImageResponseTooLarge, image.ErrResponseTooLarge},
		{"response read", xkms.ErrImageResponseRead, image.ErrResponseRead},
		{"invalid upload location", xkms.ErrImageInvalidUploadLocation, image.ErrInvalidUploadLocation},
		{"redirect refused", xkms.ErrImageRedirectRefused, image.ErrRedirectRefused},
		{"invalid registry options", xkms.ErrImageInvalidRegistryOptions, image.ErrInvalidRegistryOptions},
		{"subject required", xkms.ErrImageSubjectRequired, image.ErrSubjectRequired},
		{"root store required", xkms.ErrImageRootStoreRequired, image.ErrRootStoreRequired},
		{"root purpose required", xkms.ErrImageRootPurposeRequired, image.ErrRootPurposeRequired},
		{"no trusted roots", xkms.ErrImageNoTrustedRoots, image.ErrNoTrustedRoots},
		{"no attestation", xkms.ErrImageNoAttestation, image.ErrNoAttestation},
		{"no valid attestation", xkms.ErrImageNoValidAttestation, image.ErrNoValidAttestation},
		{"invalid attestation", xkms.ErrImageInvalidAttestation, image.ErrInvalidAttestation},
		{"invalid envelope", xkms.ErrImageInvalidEnvelope, image.ErrInvalidEnvelope},
		{"invalid statement", xkms.ErrImageInvalidStatement, image.ErrInvalidStatement},
		{"subject mismatch", xkms.ErrImageSubjectMismatch, image.ErrSubjectMismatch},
		{"predicate type mismatch", xkms.ErrImagePredicateTypeMismatch, image.ErrPredicateTypeMismatch},
		{"signature invalid", xkms.ErrImageSignatureInvalid, image.ErrSignatureInvalid},
		{"untrusted signer", xkms.ErrImageUntrustedSigner, image.ErrUntrustedSigner},
		{"timestamp url invalid", xkms.ErrImageTimestampURLInvalid, image.ErrTimestampURLInvalid},
		{"timestamp data required", xkms.ErrImageTimestampDataRequired, image.ErrTimestampDataRequired},
		{"timestamp failed", xkms.ErrImageTimestampFailed, image.ErrTimestampFailed},
		{"timestamp rejected", xkms.ErrImageTimestampRejected, image.ErrTimestampRejected},
		{"invalid timestamp", xkms.ErrImageInvalidTimestamp, image.ErrInvalidTimestamp},
		{"timestamp mismatch", xkms.ErrImageTimestampMismatch, image.ErrTimestampMismatch},
		{"timestamp signature invalid", xkms.ErrImageTimestampSignatureInvalid, image.ErrTimestampSignatureInvalid},
		{"timestamp untrusted", xkms.ErrImageTimestampUntrusted, image.ErrTimestampUntrusted},
		{"timestamp extended key usage", xkms.ErrImageTimestampExtKeyUsage, image.ErrTimestampExtKeyUsage},
		{"timestamp roots required", xkms.ErrImageTimestampRootsRequired, image.ErrTimestampRootsRequired},
		{"timestamp required", xkms.ErrImageTimestampRequired, image.ErrTimestampRequired},
		{"unsupported algorithm", xkms.ErrImageUnsupportedAlgorithm, image.ErrUnsupportedAlgorithm},
		{"signing public key required", xkms.ErrSigningPublicKeyRequired, signing.ErrPublicKeyRequired},
		{"signing signature required", xkms.ErrSigningSignatureRequired, signing.ErrSignatureRequired},
		{"signing unsupported key type", xkms.ErrSigningUnsupportedKeyType, signing.ErrUnsupportedKeyType},
		{"signing invalid hash function", xkms.ErrSigningInvalidHashFunction, signing.ErrInvalidHashFunction},
		{"signing verification failed", xkms.ErrSigningVerificationFailed, signing.ErrVerificationFailed},
	}

	for _, pair := range pairs {
		t.Run(pair.name, func(t *testing.T) {
			assert.Same(t, pair.pkg, pair.sdk, "the SDK re-exports a copy rather than the sentinel")
		})
	}
}

// TestImageCodeSigningProfileIsTrustedCAs pins the profile pkg/image asks
// TrustedCA for, which it names without importing pkg/ca, to the CA's
// code-signing profile.
func TestImageCodeSigningProfileIsTrustedCAs(t *testing.T) {
	assert.Equal(t, xkms.ProfileNameCodeSigning, image.ProfileCodeSigning)
}

func TestVerifySignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("manifest"))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)

	assert.NoError(t, xkms.VerifySignature(&key.PublicKey, crypto.SHA256, digest[:], signature))
}

func TestVerifySignature_Errors(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("manifest"))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	other := sha256.Sum256([]byte("another manifest"))

	tests := []struct {
		name      string
		publicKey crypto.PublicKey
		hash      crypto.Hash
		digest    []byte
		signature []byte
		want      error
	}{
		{"no public key", nil, crypto.SHA256, digest[:], signature, xkms.ErrSigningPublicKeyRequired},
		{"ecdsa key", &ecKey.PublicKey, crypto.SHA256, digest[:], signature, xkms.ErrSigningUnsupportedKeyType},
		{"sha1", &key.PublicKey, crypto.SHA1, digest[:20], signature, xkms.ErrSigningInvalidHashFunction},
		{"no signature", &key.PublicKey, crypto.SHA256, digest[:], nil, xkms.ErrSigningSignatureRequired},
		{"other digest", &key.PublicKey, crypto.SHA256, other[:], signature, xkms.ErrSigningVerificationFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, xkms.VerifySignature(tt.publicKey, tt.hash, tt.digest, tt.signature), tt.want)
		})
	}
}
