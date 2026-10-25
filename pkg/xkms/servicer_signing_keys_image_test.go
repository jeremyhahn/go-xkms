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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/image"
)

const (
	// signedImageReference is the image every SignImage test signs; its
	// repository is acme/app.
	signedImageReference = "registry.example.com/acme/app:v1"

	// signedImageDigest is the manifest digest memoryRegistry resolves every
	// reference to.
	signedImageDigest = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
)

var (
	// errRegistryPush is the push failure memoryRegistry returns when asked to.
	errRegistryPush = errors.New("registry push refused")

	// errCAUnavailable is the failure codeSigningCA returns when asked to.
	errCAUnavailable = errors.New("ca unavailable")
)

// codeSigningCA is a CA that certifies every CSR it is given for code
// signing under its own root, recording the profile and tenant it was asked
// for.
type codeSigningCA struct {
	*mockCA
	key     *ecdsa.PrivateKey
	root    *x509.Certificate
	profile string
}

func newCodeSigningCA(t *testing.T) *codeSigningCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Image Signing Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &codeSigningCA{
		mockCA: &mockCA{bundlePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert: root},
		key:    key,
		root:   root,
	}
}

// SignCSRRaw certifies the CSR's key for code signing, or returns the
// mockCA's signCSRErr when one is set.
func (c *codeSigningCA) SignCSRRaw(_ context.Context, csrPEM []byte, profile string, _ int, tenantID string) (*x509.Certificate, error) {
	c.profile = profile
	c.signCSRTenant = tenantID
	if c.signCSRErr != nil {
		return nil, c.signCSRErr
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("no CSR PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: csr.Subject.CommonName, OrganizationalUnit: []string{tenantID}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}, c.root, csr.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// CertificatesByPurpose makes the CA's root the image verifier's trust root.
func (c *codeSigningCA) CertificatesByPurpose(string) ([]*x509.Certificate, error) {
	return []*x509.Certificate{c.root}, nil
}

// memoryRegistry is an image.RegistryClient that keeps the attestations it
// is pushed in memory and records the credentials it was built with.
type memoryRegistry struct {
	auth         *image.RegistryAuth
	password     string
	pushed       []*image.Attestation
	pushErr      error
	closed       bool
	constructErr error
}

// install makes svc build this registry for SignImage.
func (r *memoryRegistry) install(svc *XKMSService) {
	svc.imageRegistry = func(opts *image.RegistryOptions) (image.RegistryClient, error) {
		if r.constructErr != nil {
			return nil, r.constructErr
		}
		r.auth = opts.Auth
		return r, nil
	}
}

func (r *memoryRegistry) Resolve(context.Context, *image.Reference) (*image.Descriptor, error) {
	return &image.Descriptor{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: signedImageDigest, Size: 512}, nil
}

func (r *memoryRegistry) PushAttestation(ctx context.Context, _ *image.Reference, _ *image.Descriptor, att *image.Attestation) (*image.PushResult, error) {
	if r.auth != nil && r.auth.Password != nil {
		if err := r.auth.Password.WithBytes(ctx, func(b []byte) error {
			r.password = string(b)
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if r.pushErr != nil {
		return nil, r.pushErr
	}
	r.pushed = append(r.pushed, att)
	return &image.PushResult{
		Referrer:        image.Descriptor{Digest: "sha256:referrer"},
		ReferrerIndexed: true,
		AttestationTag:  "sha256-9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08.att",
	}, nil
}

func (r *memoryRegistry) Attestations(context.Context, *image.Reference) ([]*image.Attestation, error) {
	return r.pushed, nil
}

func (r *memoryRegistry) Close() error {
	r.closed = true
	return nil
}

// signingKeyOf resolves every repository to one public key, so the verifier
// refuses a signature by any other key.
type signingKeyOf struct{ key crypto.PublicKey }

func (s signingKeyOf) SigningKey(context.Context, string) (crypto.PublicKey, error) {
	return s.key, nil
}

// imageSigningService is a service whose tenant-a holds a release key,
// with a code-signing CA and an in-memory registry installed.
func imageSigningService(t *testing.T, grants ...string) (*XKMSService, context.Context, *codeSigningCA, *memoryRegistry, crypto.PublicKey) {
	t.Helper()
	svc := setupDeriveService(t)
	release := generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	ctx := withSigningKeys(t, svc, grants...)
	ca := newCodeSigningCA(t)
	svc.SetCA(ca)
	registry := &memoryRegistry{}
	registry.install(svc)
	return svc, ctx, ca, registry, release
}

func signImageRequest() *transport.SignImageRequest {
	return &transport.SignImageRequest{
		Reference: signedImageReference,
		Registry:  &transport.ImageRegistryCredentials{Username: "ci", Password: []byte("registry-password")},
	}
}

// verifySignedImage verifies the attestation in registry as an image
// verifier would, requiring key to have signed it.
func verifySignedImage(t *testing.T, ca *codeSigningCA, registry *memoryRegistry, key crypto.PublicKey) *image.VerificationResult {
	t.Helper()
	verifier, err := image.NewVerifier(&image.VerifierConfig[string]{
		Registry:    registry,
		Roots:       ca,
		Purpose:     "image-signer",
		SigningKeys: signingKeyOf{key: key},
	})
	require.NoError(t, err)
	result, err := verifier.VerifyImage(t.Context(), signedImageReference)
	require.NoError(t, err)
	return result
}

func TestSignImage_ReleaseKeyByDefault(t *testing.T) {
	svc, ctx, ca, registry, release := imageSigningService(t, corimSignPermission)

	req := signImageRequest()
	resp, err := svc.SignImage(ctx, req)
	require.NoError(t, err)

	assert.Equal(t, appraisal.SigningKeyResolution{Repository: "acme/app", KeyID: appraisal.ReleaseSigningKeyID, Default: true}, resp.Key)
	assert.Equal(t, signedImageDigest, resp.Digest)
	assert.Equal(t, "sha256:referrer", resp.Referrer)
	assert.True(t, resp.ReferrerIndexed)
	assert.NotEmpty(t, resp.AttestationTag)
	require.Len(t, registry.pushed, 1)
	assert.Equal(t, registry.pushed[0].Envelope, resp.Envelope)

	block, _ := pem.Decode(resp.Certificate)
	require.NotNil(t, block)
	certificate, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "acme/app", certificate.Subject.CommonName)
	assert.Equal(t, image.ProfileCodeSigning, ca.profile)
	assert.Equal(t, "tenant-a", ca.signCSRTenant)

	result := verifySignedImage(t, ca, registry, release)
	assert.Equal(t, signedImageDigest, result.Digest)
	assert.Equal(t, image.PredicateTypeCosign, result.Statement.PredicateType)
}

func TestSignImage_PresentsAndWipesRegistryCredentials(t *testing.T) {
	svc, ctx, _, registry, _ := imageSigningService(t, corimSignPermission)

	req := signImageRequest()
	_, err := svc.SignImage(ctx, req)
	require.NoError(t, err)

	require.NotNil(t, registry.auth)
	assert.Equal(t, "ci", registry.auth.Username)
	assert.Equal(t, "registry-password", registry.password)
	assert.False(t, registry.auth.Password.IsAlive(), "the sealed password is destroyed once the push is done")
	assert.Nil(t, req.Registry.Password, "the request's password is wiped")
	assert.True(t, registry.closed)
}

func TestSignImage_WithoutCredentialsSendsNone(t *testing.T) {
	svc, ctx, _, registry, _ := imageSigningService(t, corimSignPermission)

	_, err := svc.SignImage(ctx, &transport.SignImageRequest{Reference: signedImageReference})
	require.NoError(t, err)
	assert.Nil(t, registry.auth)
}

func TestSignImage_BoundKeySigns(t *testing.T) {
	svc, ctx, ca, registry, release := imageSigningService(t, corimSignPermission, "attestation_signing_keys:bind")
	bound := generateSigningKey(t, svc, "tenant-a", "app-release")
	_, err := svc.SetSigningKeyBinding(ctx, &appraisal.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "app-release"})
	require.NoError(t, err)

	resp, err := svc.SignImage(ctx, signImageRequest())
	require.NoError(t, err)
	assert.Equal(t, "app-release", resp.Key.KeyID)
	assert.False(t, resp.Key.Default)
	verifySignedImage(t, ca, registry, bound)

	verifier, err := image.NewVerifier(&image.VerifierConfig[string]{
		Registry: registry, Roots: ca, Purpose: "image-signer", SigningKeys: signingKeyOf{key: release},
	})
	require.NoError(t, err)
	_, err = verifier.VerifyImage(t.Context(), signedImageReference)
	require.ErrorIs(t, err, image.ErrSigningKeyMismatch, "the release key did not sign a bound repository's image")
}

func TestSignImage_NeverSignsWithAnotherTenantsKey(t *testing.T) {
	svc := setupDeriveService(t)
	generateSigningKey(t, svc, "tenant-b", appraisal.ReleaseSigningKeyID)
	ctx := withSigningKeys(t, svc, corimSignPermission)
	svc.SetCA(newCodeSigningCA(t))
	registry := &memoryRegistry{}
	registry.install(svc)

	_, err := svc.SignImage(ctx, signImageRequest())
	require.ErrorIs(t, err, ErrKeyNotFound, "tenant-a holds no release key; tenant-b's is never used")
	assert.Nil(t, registry.auth, "no registry is contacted without a key")
}

func TestSignImage_RefusesUnknownRepositoryKey(t *testing.T) {
	svc, ctx, _, _, _ := imageSigningService(t, corimSignPermission, "attestation_signing_keys:bind")
	_, err := svc.SetSigningKeyBinding(ctx, &appraisal.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "deleted-key"})
	require.NoError(t, err)

	_, err = svc.SignImage(ctx, signImageRequest())
	require.ErrorIs(t, err, ErrKeyNotFound, "a binding to a key the tenant does not hold never signs")
}

func TestSignImage_Errors(t *testing.T) {
	svc, ctx, ca, registry, _ := imageSigningService(t, corimSignPermission)

	_, err := svc.SignImage(ctx, nil)
	require.ErrorIs(t, err, appraisal.ErrNilRequest)

	req := signImageRequest()
	req.Reference = "not a reference"
	_, err = svc.SignImage(ctx, req)
	require.ErrorIs(t, err, image.ErrInvalidReference)
	assert.Nil(t, req.Registry.Password, "the password is wiped on a refused request")

	for name, tc := range map[string]struct {
		arrange func(*transport.SignImageRequest)
		want    error
	}{
		"password without a username": {func(r *transport.SignImageRequest) { r.Registry.Username = "" }, image.ErrRegistryCredentials},
		"certificate refused":         {func(*transport.SignImageRequest) { ca.signCSRErr = errCAUnavailable }, image.ErrCertificateRequestFailed},
		"ca bundle unreadable":        {func(*transport.SignImageRequest) { ca.bundleErr = errCAUnavailable }, errCAUnavailable},
		"registry unavailable":        {func(*transport.SignImageRequest) { registry.constructErr = image.ErrRegistryRequest }, image.ErrRegistryRequest},
		"push refused":                {func(*transport.SignImageRequest) { registry.pushErr = errRegistryPush }, errRegistryPush},
	} {
		ca.signCSRErr, ca.bundleErr = nil, nil
		registry.constructErr, registry.pushErr, registry.closed = nil, nil, false
		req := signImageRequest()
		tc.arrange(req)

		_, err := svc.SignImage(ctx, req)
		require.ErrorIs(t, err, tc.want, name)
		var signErr *ImageSignError
		require.ErrorAs(t, err, &signErr, name)
		assert.Equal(t, appraisal.ReleaseSigningKeyID, signErr.KeyID, name)
		assert.Contains(t, signErr.Error(), "acme/app", name)
		assert.NotContains(t, signErr.Error(), "registry-password", name)
		assert.Nil(t, req.Registry.Password, "%s: the password is wiped", name)
		assert.Equal(t, name == "push refused", registry.closed, "%s: a registry that was built is closed", name)
	}
}

func TestSignImage_RefusesSystemTenant(t *testing.T) {
	svc, _, _, registry, _ := imageSigningService(t, corimSignPermission)
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "operator", TenantID: qrdbsdk.SystemTenantID})

	req := signImageRequest()
	_, err := svc.SignImage(ctx, req)
	require.ErrorIs(t, err, ErrSystemTenantImageSigning)
	assert.Nil(t, registry.auth)
	assert.Nil(t, req.Registry.Password)
}

func TestSignImage_RefusedWithoutSignPermission(t *testing.T) {
	svc, ctx, _, registry, _ := imageSigningService(t, "attestation_signing_keys:get")

	_, err := svc.SignImage(ctx, signImageRequest())
	require.ErrorIs(t, err, ErrSigningKeyForbidden)
	var refusal *SigningKeyPermissionError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, corimSignPermission, refusal.Permission)
	assert.Nil(t, registry.auth)
}

func TestSignImage_NotConfigured(t *testing.T) {
	svc := setupDeriveService(t)
	_, err := svc.SignImage(t.Context(), signImageRequest())
	require.ErrorIs(t, err, ErrNotConfigured, "no appraiser")

	generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	ctx := withSigningKeys(t, svc, corimSignPermission)
	_, err = svc.SignImage(ctx, signImageRequest())
	require.ErrorIs(t, err, ErrNotConfigured, "no CA")
}
