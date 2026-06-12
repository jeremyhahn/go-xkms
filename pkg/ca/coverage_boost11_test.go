// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

// Package ca coverage boost, eleventh pass: targets remaining sub-91% functions
// not covered in passes 1–10. All tests are in-memory, fast, race-free.
package ca

import (
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"

	objmemory "github.com/jeremyhahn/go-objstore/pkg/memory"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// ca.go — determineSignatureAlgorithm: RSA and Ed25519 branches
// (brings determineSignatureAlgorithm from 88.9% to 100%)
// =============================================================================

// TestDetermineSignatureAlgorithm_RSA_B11 exercises the RSA case.
func TestDetermineSignatureAlgorithm_RSA_B11(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	algo := determineSignatureAlgorithm(&key.PublicKey)
	assert.Equal(t, x509.SHA256WithRSA, algo)
}

// TestDetermineSignatureAlgorithm_Ed25519_B11 exercises the Ed25519 case.
func TestDetermineSignatureAlgorithm_Ed25519_B11(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	algo := determineSignatureAlgorithm(pub)
	assert.Equal(t, x509.PureEd25519, algo)
}

// TestDetermineSignatureAlgorithm_Unknown_B11 exercises the default case.
func TestDetermineSignatureAlgorithm_Unknown_B11(t *testing.T) {
	t.Parallel()
	algo := determineSignatureAlgorithm(nil)
	assert.Equal(t, x509.UnknownSignatureAlgorithm, algo)
}

// =============================================================================
// csr.go — getECDSASignatureAlgorithm: P-384, P-521, nil-curve paths
// (brings getECDSASignatureAlgorithm from 85.7% to 100%)
// =============================================================================

// TestGetECDSASignatureAlgorithm_P384_B11 exercises the P-384 case.
func TestGetECDSASignatureAlgorithm_P384_B11(t *testing.T) {
	t.Parallel()
	algo, err := getECDSASignatureAlgorithm(elliptic.P384())
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSAWithSHA384, algo)
}

// TestGetECDSASignatureAlgorithm_P521_B11 exercises the P-521 case.
func TestGetECDSASignatureAlgorithm_P521_B11(t *testing.T) {
	t.Parallel()
	algo, err := getECDSASignatureAlgorithm(elliptic.P521())
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSAWithSHA512, algo)
}

// TestGetECDSASignatureAlgorithm_NilCurve_B11 exercises the nil-curve guard.
func TestGetECDSASignatureAlgorithm_NilCurve_B11(t *testing.T) {
	t.Parallel()
	_, err := getECDSASignatureAlgorithm(nil)
	assert.ErrorIs(t, err, ErrInvalidKeyAlgorithm)
}

// =============================================================================
// csr.go — getSignatureAlgorithm: unsupported key type error path
// =============================================================================

// TestGetSignatureAlgorithm_UnsupportedKeyType_B11 exercises the error path in
// getSignatureAlgorithm when presented with an unsupported key type.
func TestGetSignatureAlgorithm_UnsupportedKeyType_B11(t *testing.T) {
	t.Parallel()
	_, err := getSignatureAlgorithm(struct{ notAKey bool }{})
	assert.ErrorIs(t, err, ErrInvalidKeyAlgorithm)
}

// =============================================================================
// constructors.go — caConfigFromIdentity: defaultCertValidity > 0 branch
// =============================================================================

// TestCaConfigFromIdentity_WithDefaultValidity_B11 exercises the
// defaultCertValidity > 0 branch in caConfigFromIdentity.
func TestCaConfigFromIdentity_WithDefaultValidity_B11(t *testing.T) {
	t.Parallel()
	id := Identity{
		Subject: Subject{CommonName: "cfg-from-id-b11", Organization: "Test"},
		Valid:   10,
		Keys:   DefaultKeyConfig(),
		IsRoot: true,
	}
	cfg := caConfigFromIdentity(id, 730)
	assert.Equal(t, 730, cfg.DefaultCertValidityDays)
}

// TestCaConfigFromIdentity_ZeroDefaultValidity_B11 exercises the else branch
// where defaultCertValidity == 0 so the package default is used.
func TestCaConfigFromIdentity_ZeroDefaultValidity_B11(t *testing.T) {
	t.Parallel()
	id := Identity{
		Subject: Subject{CommonName: "cfg-from-id-zero-b11", Organization: "Test"},
		Valid:   10,
		Keys:   DefaultKeyConfig(),
		IsRoot: true,
	}
	cfg := caConfigFromIdentity(id, 0)
	assert.Equal(t, DefaultCertValidityDays, cfg.DefaultCertValidityDays)
}

// =============================================================================
// constructors.go — NewIntermediateCA: Config != nil (defaultValidity) branch
// =============================================================================

// TestNewIntermediateCA_WithConfig_B11 exercises the params.Config != nil
// branch in NewIntermediateCA.
func TestNewIntermediateCA_WithConfig_B11(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)
	cfg := DefaultMultiIdentityCAConfigWithIntermediate()
	cfg.Identity[0].Subject.CommonName = "IntCA Config Root B11"
	cfg.Identity[0].Keys[0].KeyType = "CA"
	cfg.Identity[1].Subject.CommonName = "IntCA Config Intermediate B11"
	cfg.Identity[1].Keys[0].KeyType = "CA"

	rootParams := &Params{
		Identity:  cfg.Identity,
		KeyStore:  backend,
		CertStore: cs,
		SerialGen: NewSerialGenerator(NewMemoryStorage()),
		Config:    &CAConfig{DefaultCertValidityDays: 365},
	}
	root, err := NewParentCA(rootParams)
	require.NoError(t, err)
	require.NoError(t, root.Init(context.Background()))

	intParams := &Params{
		Identity:  cfg.Identity,
		KeyStore:  backend,
		CertStore: cs,
		SerialGen: NewSerialGenerator(NewMemoryStorage()),
		Config:    &CAConfig{DefaultCertValidityDays: 365},
	}
	intermediate, err := NewIntermediateCA(context.Background(), intParams, root)
	require.NoError(t, err)
	assert.NotNil(t, intermediate)
	assert.True(t, intermediate.IsInitialized())
}

// =============================================================================
// ca.go — mergeSubjects: all individual field branches
// =============================================================================

// TestMergeSubjects_AllFields_B11 exercises all override branches.
func TestMergeSubjects_AllFields_B11(t *testing.T) {
	t.Parallel()
	base := pkix.Name{
		CommonName:         "base-cn",
		Organization:       []string{"base-org"},
		OrganizationalUnit: []string{"base-ou"},
		Country:            []string{"US"},
		Province:           []string{"base-province"},
		Locality:           []string{"base-locality"},
	}
	override := &Subject{
		CommonName:         "new-cn",
		Organization:       "new-org",
		OrganizationalUnit: "new-ou",
		Country:            "CA",
		Province:           "Ontario",
		Locality:           "Toronto",
	}
	merged := mergeSubjects(base, override)
	assert.Equal(t, "new-cn", merged.CommonName)
	assert.Equal(t, []string{"new-org"}, merged.Organization)
	assert.Equal(t, []string{"new-ou"}, merged.OrganizationalUnit)
	assert.Equal(t, []string{"CA"}, merged.Country)
	assert.Equal(t, []string{"Ontario"}, merged.Province)
	assert.Equal(t, []string{"Toronto"}, merged.Locality)
}

// =============================================================================
// ca.go — Verify: xsigner path + nil-cert + revoked paths
// =============================================================================

// TestVerify_NilCert_B11 exercises the nil cert guard in Verify.
func TestVerify_NilCert_B11(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	_, err := ca.Verify(nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// TestVerify_Revoked_B11 exercises the revoked cert path in Verify.
func TestVerify_Revoked_B11(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "revoked-verify-b11"},
		Valid:   365,
	})
	require.NoError(t, err)

	require.NoError(t, ca.Revoke(context.Background(), issued.Certificate.SerialNumber, 0))
	_, err = ca.Verify(issued.Certificate)
	assert.ErrorIs(t, err, ErrCertificateRevoked)
}

// =============================================================================
// ca.go — CACertificate: cert not found path (both certs nil)
// =============================================================================

// TestCACertificate_NoCert_B11 exercises ErrCertificateNotFound when both certs nil.
func TestCACertificate_NoCert_B11(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.mu.Lock()
	orig := ca.rootCert
	ca.rootCert = nil
	ca.mu.Unlock()
	defer func() {
		ca.mu.Lock()
		ca.rootCert = orig
		ca.mu.Unlock()
	}()
	_, err := ca.CACertificate()
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

// =============================================================================
// ca.go — getSigner: getCAKeyAttributes error path (no issuing identity)
// =============================================================================

// TestGetSigner_GetCAKeyAttributesError_B11 exercises the nil-issuing-identity
// error branch in getSigner.
func TestGetSigner_GetCAKeyAttributesError_B11(t *testing.T) {
	t.Parallel()
	ca := &CA{config: &MultiIdentityCAConfig{}}
	ca.initialized.Store(true)

	signer, err := ca.getSigner(context.Background())
	assert.Nil(t, signer)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// =============================================================================
// ca_extensions.go — putRevocationBlob: no-store path returns (false, nil)
// =============================================================================

// TestPutRevocationBlob_NoStore_B11 exercises the case where neither
// revocationStore nor objectStore is configured.
func TestPutRevocationBlob_NoStore_B11(t *testing.T) {
	t.Parallel()
	ca := &CA{
		revocationStore: nil,
		objectStore:     nil,
		revocations:     make(map[string]*RevocationInfo),
	}
	persisted, err := ca.putRevocationBlob(context.Background(), big.NewInt(88888), []byte(`{}`))
	require.NoError(t, err)
	assert.False(t, persisted)
}

// =============================================================================
// ca_extensions.go — listRevocationBlobs: objectStore scan coverage
// =============================================================================

// TestListRevocationBlobs_ObjectStoreRevocation_B11 exercises the objectStore
// fallback in listRevocationBlobs by revoking a cert with objectStore configured.
func TestListRevocationBlobs_ObjectStoreRevocation_B11(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = objmemory.New()

	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "revoked-listblobs-b11"},
		Valid:   365,
	})
	require.NoError(t, err)

	require.NoError(t, ca.Revoke(context.Background(), issued.Certificate.SerialNumber, 1))

	blobs, err := ca.listRevocationBlobs(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, blobs)
}

// =============================================================================
// ca.go — getOrGenerateCAKey: RSA branch
// =============================================================================

// TestGetOrGenerateCAKey_RSA_B11 exercises the RSA branch in getOrGenerateCAKey.
func TestGetOrGenerateCAKey_RSA_B11(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)

	config := DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "RSA Root B11"
	config.Identity[0].Keys = []*types.KeyConfig{
		{
			KeyAlgorithm:       types.AlgorithmRSA,
			Hash:               types.HashSHA256,
			SignatureAlgorithm: types.SigSHA256WithRSA,
			StoreType:          types.StoreSoftware,
			KeyType:            "CA",
			RSAConfig:          &types.RSAConfig{KeySize: 2048},
		},
	}

	ca := &CA{
		config:      config,
		keyStore:    backend,
		certStore:   cs,
		revocations: make(map[string]*RevocationInfo),
		serialGen:   NewSerialGenerator(NewMemoryStorage()),
		profiles:    NewDefaultProfileRegistry(),
	}
	require.NoError(t, ca.Init(context.Background()))
	assert.NotNil(t, ca.rootCert)
	assert.Equal(t, x509.SHA256WithRSA, ca.rootCert.SignatureAlgorithm)
}

// =============================================================================
// ca.go — GenerateCRL: with revocations exercises the revokedEntries loop
// =============================================================================

// TestGenerateCRL_WithRevocations_B11 exercises the revokedEntries loop body.
func TestGenerateCRL_WithRevocations_B11(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "revoked-crl-b11"},
		Valid:   365,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Revoke(context.Background(), issued.Certificate.SerialNumber, 1))

	crlDER, err := ca.GenerateCRL(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, crlDER)

	crl, err := x509.ParseRevocationList(crlDER)
	require.NoError(t, err)
	assert.Len(t, crl.RevokedCertificateEntries, 1)
}

// =============================================================================
// csr.go — getOrGenerateKey: RSA and Ed25519 branches
// =============================================================================

// TestGetOrGenerateKey_RSA_B11 exercises the RSA branch in getOrGenerateKey.
func TestGetOrGenerateKey_RSA_B11(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	req := &CertificateRequest{
		Subject: Subject{CommonName: "rsa-key-gen-b11"},
		KeyAttributes: &types.KeyAttributes{
			CN:           "rsa-key-gen-b11",
			KeyAlgorithm: x509.RSA,
			StoreType:    types.StoreSoftware,
			KeyType:      types.KeyTypeTLS,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		},
	}
	signer, err := ca.getOrGenerateKey(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, signer)
}

// TestGetOrGenerateKey_Ed25519_B11 exercises the Ed25519 branch in getOrGenerateKey.
func TestGetOrGenerateKey_Ed25519_B11(t *testing.T) {
	t.Parallel()
	ca := setupEd25519CA(t)

	req := &CertificateRequest{
		Subject: Subject{CommonName: "ed25519-key-gen-b11"},
		KeyAttributes: &types.KeyAttributes{
			CN:           "ed25519-key-gen-b11",
			KeyAlgorithm: x509.Ed25519,
			StoreType:    types.StoreSoftware,
			KeyType:      types.KeyTypeTLS,
		},
	}
	signer, err := ca.getOrGenerateKey(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, signer)
}

// =============================================================================
// ca.go — Validate (Params): KeyAttributes nil guard
// =============================================================================

// TestParams_Validate_NilKeyAttributes_B11 exercises the nil KeyAttributes
// guard in Params.Validate.
func TestParams_Validate_NilKeyAttributes_B11(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)
	config := DefaultMultiIdentityCAConfig()
	config.Identity[0].Keys[0].KeyType = "CA"

	caConfig := &CAConfig{
		Identity:     config.Identity[0].Subject.CommonName,
		Subject:      &config.Identity[0].Subject,
		ValidityDays: config.Identity[0].GetValidityDays(),
		IsRootCA:     true,
	}

	p := &Params{
		Config:        caConfig,
		KeyAttributes: nil,
		KeyStore:      backend,
		CertStore:     cs,
	}
	err := p.Validate()
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// =============================================================================
// ca_extensions.go — Signer: success and not-initialized paths
// =============================================================================

// TestSigner_NotInitialized_B11 exercises ErrNotInitialized in Signer.
func TestSigner_NotInitialized_B11(t *testing.T) {
	t.Parallel()
	ca := &CA{}
	_, err := ca.Signer(context.Background())
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// TestSigner_Success_B11 exercises the success path of Signer.
func TestSigner_Success_B11(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	signer, err := ca.Signer(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, signer)
}

// =============================================================================
// ca_extensions.go — PrivateKey success path
// =============================================================================

// TestPrivateKey_Success_B11 exercises the success path of PrivateKey.
func TestPrivateKey_Success_B11(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	cn := "privkey-success-b11"
	issueCertAndSaveToKeyStore(t, ca, cn)

	attrs := softwareKeyAttrs(cn)
	key, err := ca.PrivateKey(context.Background(), attrs)
	require.NoError(t, err)
	assert.NotNil(t, key)
}

// =============================================================================
// trust_chain.go — CABundleCertPool: both branches
// =============================================================================

// TestCABundleCertPool_RootOnly_B11 exercises CABundleCertPool with root-only CA.
func TestCABundleCertPool_RootOnly_B11(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	pool, err := ca.CABundleCertPool()
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

// TestCABundleCertPool_WithIntermediate_B11 exercises CABundleCertPool with
// root + intermediate.
func TestCABundleCertPool_WithIntermediate_B11(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithRealIntermediate(t)
	pool, err := ca.CABundleCertPool()
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

// =============================================================================
// Manufacturer-specific OID tests (tcg_oids.go) — all at 75%
// =============================================================================

// TestCreateTPMManufacturerExtension_Success_B11 exercises the success path.
func TestCreateTPMManufacturerExtension_Success_B11(t *testing.T) {
	t.Parallel()
	ext, err := CreateTPMManufacturerExtension("id:INTC")
	require.NoError(t, err)
	assert.NotEmpty(t, ext.Value)
}

// TestCreateTPMModelExtension_Success_B11 exercises the success path.
func TestCreateTPMModelExtension_Success_B11(t *testing.T) {
	t.Parallel()
	ext, err := CreateTPMModelExtension("Intel PTT")
	require.NoError(t, err)
	assert.NotEmpty(t, ext.Value)
}

// TestCreateTPMVersionExtension_Success_B11 exercises the success path.
func TestCreateTPMVersionExtension_Success_B11(t *testing.T) {
	t.Parallel()
	ext, err := CreateTPMVersionExtension("id:00070002")
	require.NoError(t, err)
	assert.NotEmpty(t, ext.Value)
}

// TestCreateTPMSpecificationExtension_Success_B11 exercises the success path.
func TestCreateTPMSpecificationExtension_Success_B11(t *testing.T) {
	t.Parallel()
	ext, err := CreateTPMSpecificationExtension(TCGTPMSpecification{Family: "2.0", Level: 1, Revision: 138})
	require.NoError(t, err)
	assert.NotEmpty(t, ext.Value)
}

// TestCreateHardwareModuleNameExtension_Success_B11 exercises the success path.
func TestCreateHardwareModuleNameExtension_Success_B11(t *testing.T) {
	t.Parallel()
	ext, err := CreateHardwareModuleNameExtension(asn1.ObjectIdentifier{1, 2, 3, 4}, []byte{0x01, 0x02, 0x03})
	require.NoError(t, err)
	assert.NotEmpty(t, ext.Value)
}

// TestCreatePermanentIdentifierExtension_Success_B11 exercises the success path.
func TestCreatePermanentIdentifierExtension_Success_B11(t *testing.T) {
	t.Parallel()
	ext, err := CreatePermanentIdentifierExtension("perm-id-b11", asn1.ObjectIdentifier{1, 2, 3, 4})
	require.NoError(t, err)
	assert.NotEmpty(t, ext.Value)
}

// TestCreatePlatformManufacturerExtension_Success_B11 exercises the success path.
func TestCreatePlatformManufacturerExtension_Success_B11(t *testing.T) {
	t.Parallel()
	ext, err := CreatePlatformManufacturerExtension("Intel Corporation")
	require.NoError(t, err)
	assert.NotEmpty(t, ext.Value)
}

// TestCreatePlatformModelExtension_Success_B11 exercises the success path.
func TestCreatePlatformModelExtension_Success_B11(t *testing.T) {
	t.Parallel()
	ext, err := CreatePlatformModelExtension("NUC13ANHi7")
	require.NoError(t, err)
	assert.NotEmpty(t, ext.Value)
}

// TestCreatePlatformVersionExtension_Success_B11 exercises the success path.
func TestCreatePlatformVersionExtension_Success_B11(t *testing.T) {
	t.Parallel()
	ext, err := CreatePlatformVersionExtension("1.0")
	require.NoError(t, err)
	assert.NotEmpty(t, ext.Value)
}

// TestCreateVerifiedTPMResidencyExtension_Success_B11 exercises the success path.
func TestCreateVerifiedTPMResidencyExtension_Success_B11(t *testing.T) {
	t.Parallel()
	ext, err := CreateVerifiedTPMResidencyExtension(true)
	require.NoError(t, err)
	assert.NotEmpty(t, ext.Value)
}

// TestCreateVerifiedTPMFixedExtension_Success_B11 exercises the success path.
func TestCreateVerifiedTPMFixedExtension_Success_B11(t *testing.T) {
	t.Parallel()
	ext, err := CreateVerifiedTPMFixedExtension(true)
	require.NoError(t, err)
	assert.NotEmpty(t, ext.Value)
}

// TestCreateTPKeyStoreExtension_Success_B11 exercises the success path.
func TestCreateTPKeyStoreExtension_Success_B11(t *testing.T) {
	t.Parallel()
	ext, err := CreateTPKeyStoreExtension("PLATFORM")
	require.NoError(t, err)
	assert.NotEmpty(t, ext.Value)
}

// TestCreateTPIssuerKeyStoreExtension_Success_B11 exercises the success path.
func TestCreateTPIssuerKeyStoreExtension_Success_B11(t *testing.T) {
	t.Parallel()
	ext, err := CreateTPIssuerKeyStoreExtension("TPMRESIDENCY")
	require.NoError(t, err)
	assert.NotEmpty(t, ext.Value)
}

// TestCreateTPFIPS140Extension_Success_B11 exercises the success path.
func TestCreateTPFIPS140Extension_Success_B11(t *testing.T) {
	t.Parallel()
	ext, err := CreateTPFIPS140Extension(true)
	require.NoError(t, err)
	assert.NotEmpty(t, ext.Value)
}
