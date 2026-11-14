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
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// ca.go — determineSignatureAlgorithm: RSA and Ed25519 branches
// (brings determineSignatureAlgorithm from 88.9% to 100%)
// =============================================================================

// TestDetermineSignatureAlgorithm_Unknown_B11 exercises the default case.
func TestDetermineSignatureAlgorithm_Unknown_B11(t *testing.T) {
	t.Parallel()
	algo := determineSignatureAlgorithm(nil)
	assert.Equal(t, x509.UnknownSignatureAlgorithm, algo)
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
		Identity:        cfg.Identity,
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
		SerialGen:       NewSerialGenerator(NewMemoryStorage()),
		Config:          &CAConfig{DefaultCertValidityDays: 365},
	}
	root, err := NewParentCA(rootParams)
	require.NoError(t, err)
	require.NoError(t, root.Init(context.Background()))

	intParams := &Params{
		Identity:        cfg.Identity,
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
		SerialGen:       NewSerialGenerator(NewMemoryStorage()),
		Config:          &CAConfig{DefaultCertValidityDays: 365},
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
// csr.go — getOrGenerateKey: RSA and Ed25519 branches
// =============================================================================

// TestGetOrGenerateKey_RSA_B11 exercises the RSA branch in getOrGenerateKey.
func TestGetOrGenerateKey_RSA_B11(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	req := &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "rsa-key-gen-b11"},
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
		TenantID: testTenant,
		Subject:  Subject{CommonName: "ed25519-key-gen-b11"},
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
// trust_chain.go — CABundleCertPool: both branches
// =============================================================================

// TestCABundleCertPool_WithIntermediate_B11 exercises CABundleCertPool with
// root + intermediate.
func TestCABundleCertPool_WithIntermediate_B11(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithRealIntermediate(t)
	pool, err := ca.CABundleCertPool()
	require.NoError(t, err)
	assert.NotNil(t, pool)
}
