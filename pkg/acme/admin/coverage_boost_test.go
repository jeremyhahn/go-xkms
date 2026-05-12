//go:build local

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package admin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// tenantEntityToInfo coverage
// ==========================================================================

func TestCoverageBoost_TenantEntityToInfo_NilTenant(t *testing.T) {
	result := tenantEntityToInfo(nil)
	assert.Nil(t, result)
}

func TestCoverageBoost_TenantEntityToInfo_WithRootCA(t *testing.T) {
	now := time.Now()
	tenant := &entities.Tenant{
		ID:     "tenant-1",
		Name:   "Test Tenant",
		Status: entities.TenantStatusActive,
		RootCA: &entities.TenantRootCA{
			CommonName:   "Root CA",
			SerialNumber: "12345",
			KeyAlgorithm: "ECDSA",
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(8760 * time.Hour),
			Status:       entities.CAStatusActive,
			CreatedAt:    now,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	info := tenantEntityToInfo(tenant)
	require.NotNil(t, info)
	assert.Equal(t, "tenant-1", info.ID)
	require.NotNil(t, info.RootCA)
	assert.Equal(t, "Root CA", info.RootCA.CommonName)
	assert.Equal(t, "12345", info.RootCA.SerialNumber)
	assert.Equal(t, "ECDSA", info.RootCA.KeyAlgorithm)
}

func TestCoverageBoost_TenantEntityToInfo_WithIntermediateCAs(t *testing.T) {
	now := time.Now()
	tenant := &entities.Tenant{
		ID:     "tenant-2",
		Name:   "Test Tenant 2",
		Status: entities.TenantStatusActive,
		IntermediateCAs: []*entities.TenantIntermediateCA{
			{
				ID:           "int-1",
				CommonName:   "Int CA 1",
				SerialNumber: "67890",
				ParentType:   "global",
				Purpose:      "signing",
				KeyAlgorithm: "ECDSA",
				NotBefore:    now.Add(-time.Hour),
				NotAfter:     now.Add(4380 * time.Hour),
				Status:       entities.CAStatusActive,
				CreatedAt:    now,
			},
		},
		DefaultIntermediateCAID: "int-1",
		CreatedAt:               now,
		UpdatedAt:               now,
	}

	info := tenantEntityToInfo(tenant)
	require.NotNil(t, info)
	assert.Equal(t, "int-1", info.DefaultIntermediateCAID)
	require.Len(t, info.IntermediateCAs, 1)
	assert.Equal(t, "Int CA 1", info.IntermediateCAs[0].CommonName)
	assert.Equal(t, "signing", info.IntermediateCAs[0].Purpose)
}

func TestCoverageBoost_TenantEntityToInfo_WithSettings(t *testing.T) {
	now := time.Now()
	tenant := &entities.Tenant{
		ID:     "tenant-3",
		Name:   "Test Tenant 3",
		Status: entities.TenantStatusActive,
		Settings: &entities.TenantSettings{
			MaxCertificates:         500,
			MaxAccounts:             50,
			AllowedKeyAlgorithms:    []string{"ECDSA", "RSA"},
			AllowedChallengeTypes:   []string{"http-01", "dns-01"},
			CertificateValidityDays: 90,
			RequireEAB:              true,
			AllowEndorse01:          true,
			AllowEnroll01:           false,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	info := tenantEntityToInfo(tenant)
	require.NotNil(t, info)
	require.NotNil(t, info.Settings)
	assert.Equal(t, 500, info.Settings.MaxCertificates)
	assert.Equal(t, 50, info.Settings.MaxAccounts)
	assert.Equal(t, []string{"ECDSA", "RSA"}, info.Settings.AllowedKeyAlgorithms)
	assert.Equal(t, []string{"http-01", "dns-01"}, info.Settings.AllowedChallengeTypes)
	assert.Equal(t, 90, info.Settings.CertificateValidityDays)
	assert.True(t, info.Settings.RequireEAB)
	assert.True(t, info.Settings.AllowEndorse01)
	assert.False(t, info.Settings.AllowEnroll01)
}

// ==========================================================================
// tenantSettingsEntityToInfo / tenantSettingsInfoToEntity coverage
// ==========================================================================

func TestCoverageBoost_TenantSettingsEntityToInfo_Nil(t *testing.T) {
	result := tenantSettingsEntityToInfo(nil)
	assert.Nil(t, result)
}

func TestCoverageBoost_TenantSettingsEntityToInfo_Full(t *testing.T) {
	settings := &entities.TenantSettings{
		MaxCertificates:         100,
		MaxAccounts:             10,
		AllowedKeyAlgorithms:    []string{"RSA"},
		AllowedChallengeTypes:   []string{"dns-01"},
		CertificateValidityDays: 365,
		RequireEAB:              false,
		AllowEndorse01:          true,
		AllowEnroll01:           true,
	}

	result := tenantSettingsEntityToInfo(settings)
	require.NotNil(t, result)
	assert.Equal(t, 100, result.MaxCertificates)
	assert.Equal(t, 10, result.MaxAccounts)
	assert.Equal(t, 365, result.CertificateValidityDays)
	assert.True(t, result.AllowEndorse01)
	assert.True(t, result.AllowEnroll01)
}

func TestCoverageBoost_TenantSettingsInfoToEntity_Nil(t *testing.T) {
	result := tenantSettingsInfoToEntity(nil)
	assert.Nil(t, result)
}

func TestCoverageBoost_TenantSettingsInfoToEntity_Full(t *testing.T) {
	info := &TenantSettingsInfo{
		MaxCertificates:         200,
		MaxAccounts:             20,
		AllowedKeyAlgorithms:    []string{"ECDSA", "Ed25519"},
		AllowedChallengeTypes:   []string{"http-01"},
		CertificateValidityDays: 180,
		RequireEAB:              true,
		AllowEndorse01:          false,
		AllowEnroll01:           true,
	}

	result := tenantSettingsInfoToEntity(info)
	require.NotNil(t, result)
	assert.Equal(t, 200, result.MaxCertificates)
	assert.Equal(t, 20, result.MaxAccounts)
	assert.Equal(t, 180, result.CertificateValidityDays)
	assert.True(t, result.RequireEAB)
	assert.False(t, result.AllowEndorse01)
	assert.True(t, result.AllowEnroll01)
}

// ==========================================================================
// parsePEMCertificate coverage
// ==========================================================================

func TestCoverageBoost_ParsePEMCertificate_InvalidPEM(t *testing.T) {
	_, err := parsePEMCertificate("not-valid-pem-data")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")
}

func TestCoverageBoost_ParsePEMCertificate_InvalidCertBytes(t *testing.T) {
	// Valid PEM structure but invalid certificate bytes
	invalidPEM := "-----BEGIN CERTIFICATE-----\nYWJjZGVm\n-----END CERTIFICATE-----\n"
	_, err := parsePEMCertificate(invalidPEM)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse certificate")
}

// ==========================================================================
// generateKeyPair coverage
// ==========================================================================

func TestCoverageBoost_GenerateKeyPair_RSA(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := qrdb.NewTestService()
	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	priv, pub, err := service.generateKeyPair(x509.RSA)
	require.NoError(t, err)
	assert.NotNil(t, priv)
	assert.NotNil(t, pub)
}

func TestCoverageBoost_GenerateKeyPair_ECDSA(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := qrdb.NewTestService()
	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	priv, pub, err := service.generateKeyPair(x509.ECDSA)
	require.NoError(t, err)
	assert.NotNil(t, priv)
	assert.NotNil(t, pub)
}

func TestCoverageBoost_GenerateKeyPair_Ed25519(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := qrdb.NewTestService()
	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	priv, pub, err := service.generateKeyPair(x509.Ed25519)
	require.NoError(t, err)
	assert.NotNil(t, priv)
	assert.NotNil(t, pub)
}

func TestCoverageBoost_GenerateKeyPair_Unsupported(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := qrdb.NewTestService()
	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	_, _, err := service.generateKeyPair(x509.DSA)
	require.Error(t, err)
	assert.Equal(t, ErrInvalidKeyAlgorithm, err)
}

// ==========================================================================
// parseKeyAlgorithm coverage
// ==========================================================================

func TestCoverageBoost_ParseKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    x509.PublicKeyAlgorithm
		wantErr bool
	}{
		{"RSA uppercase", "RSA", x509.RSA, false},
		{"RSA lowercase", "rsa", x509.RSA, false},
		{"empty defaults to RSA", "", x509.RSA, false},
		{"ECDSA uppercase", "ECDSA", x509.ECDSA, false},
		{"ECDSA lowercase", "ecdsa", x509.ECDSA, false},
		{"EC uppercase", "EC", x509.ECDSA, false},
		{"EC lowercase", "ec", x509.ECDSA, false},
		{"Ed25519 mixed case", "Ed25519", x509.Ed25519, false},
		{"ed25519 lowercase", "ed25519", x509.Ed25519, false},
		{"ED25519 uppercase", "ED25519", x509.Ed25519, false},
		{"unsupported algorithm", "UNKNOWN", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseKeyAlgorithm(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported key algorithm")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// ==========================================================================
// GetTenantSigningCA coverage
// ==========================================================================

func TestCoverageBoost_GetTenantSigningCA_NoEntry(t *testing.T) {
	logger := slog.Default()
	// No global CA either
	service := NewTenantAwareAdminService(nil, nil, nil, logger, "1.0.0")

	_, _, err := service.GetTenantSigningCA(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.Equal(t, ErrNoSigningCAAvailable, err)
}

func TestCoverageBoost_GetTenantSigningCA_WithDefaultIntCA(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := qrdb.NewTestService()
	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Create a test key pair for the intermediate CA
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert := makeTestCert(t, "Int CA")

	// Manually populate the cache
	service.mu.Lock()
	service.tenantCAs["tenant-signing"] = &tenantCAEntry{
		intermediateCAs: map[string]*tenantIntermediateCAEntry{
			"int-1": {cert: cert, signer: key},
		},
		defaultIntCA: "int-1",
	}
	service.mu.Unlock()

	signer, retCert, err := service.GetTenantSigningCA(context.Background(), "tenant-signing")
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, cert, retCert)
}

func TestCoverageBoost_GetTenantSigningCA_FallbackToRootCA(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := qrdb.NewTestService()
	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := makeTestCert(t, "Root CA")

	// Populate cache with root CA only (no intermediate CAs)
	service.mu.Lock()
	service.tenantCAs["tenant-root-only"] = &tenantCAEntry{
		rootCA:          cert,
		rootSigner:      key,
		intermediateCAs: make(map[string]*tenantIntermediateCAEntry),
	}
	service.mu.Unlock()

	signer, retCert, err := service.GetTenantSigningCA(context.Background(), "tenant-root-only")
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, cert, retCert)
}

func TestCoverageBoost_GetTenantSigningCA_FallbackFirstAvailableIntCA(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := qrdb.NewTestService()
	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := makeTestCert(t, "Fallback Int CA")

	// Set defaultIntCA to a non-existent key, but have another available
	service.mu.Lock()
	service.tenantCAs["tenant-fallback"] = &tenantCAEntry{
		intermediateCAs: map[string]*tenantIntermediateCAEntry{
			"int-available": {cert: cert, signer: key},
		},
		defaultIntCA: "int-missing",
	}
	service.mu.Unlock()

	signer, retCert, err := service.GetTenantSigningCA(context.Background(), "tenant-fallback")
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, cert, retCert)
}

func TestCoverageBoost_GetTenantSigningCA_NoAvailableSigners(t *testing.T) {
	logger := slog.Default()
	service := NewTenantAwareAdminService(nil, nil, nil, logger, "1.0.0")

	// Entry exists but no signers available and no global CA
	service.mu.Lock()
	service.tenantCAs["tenant-empty"] = &tenantCAEntry{
		intermediateCAs: map[string]*tenantIntermediateCAEntry{
			"int-suspended": {cert: makeTestCert(t, "Suspended"), signer: nil},
		},
	}
	service.mu.Unlock()

	_, _, err := service.GetTenantSigningCA(context.Background(), "tenant-empty")
	require.Error(t, err)
	assert.Equal(t, ErrNoSigningCAAvailable, err)
}

// ==========================================================================
// GetTenant additional coverage (deleted tenant, storage error paths)
// ==========================================================================

func TestCoverageBoost_GetTenant_DeletedTenant(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := qrdb.NewTestService()
	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Create and then soft-delete the tenant
	_, err := service.CreateTenant(context.Background(), CreateTenantRequest{
		ID:   "tenant-deleted",
		Name: "Deleted Tenant",
	})
	require.NoError(t, err)

	err = service.UpdateTenantStatus(context.Background(), "tenant-deleted", entities.TenantStatusDeleted)
	require.NoError(t, err)

	// Getting a deleted tenant should return ErrTenantNotFound
	_, err = service.GetTenant(context.Background(), "tenant-deleted")
	require.Error(t, err)
	assert.Equal(t, ErrTenantNotFound, err)
}

func TestCoverageBoost_GetTenant_FallbackNoPolicies(t *testing.T) {
	// Service with no tenantDAO and no policies for this tenant
	logger := slog.Default()
	service := NewTenantAwareAdminService(nil, nil, nil, logger, "1.0.0")

	_, err := service.GetTenant(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.Equal(t, ErrTenantNotFound, err)
}

// ==========================================================================
// storeKeyAndCert coverage (no keystore, no qrdb - graceful handling)
// ==========================================================================

func TestCoverageBoost_StoreKeyAndCert_NoKeystore(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := qrdb.NewTestService()
	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := makeTestCert(t, "Test CA")

	// Should not error even without a keystore - stores in KV only
	err = service.storeKeyAndCert(context.Background(), "tenant-1", "root", key, cert)
	require.NoError(t, err)
}

func TestCoverageBoost_StoreKeyAndCert_NoQRDB(t *testing.T) {
	logger := slog.Default()
	// No qrdb service at all
	service := NewTenantAwareAdminService(nil, nil, nil, logger, "1.0.0")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := makeTestCert(t, "Test CA")

	// Should not error - gracefully skips KV storage
	err = service.storeKeyAndCert(context.Background(), "tenant-1", "root", key, cert)
	require.NoError(t, err)
}

// ==========================================================================
// UpdateTenantIntermediateCAStatus coverage
// ==========================================================================

func TestCoverageBoost_UpdateTenantIntermediateCAStatus_Validation(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := qrdb.NewTestService()
	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	tests := []struct {
		name     string
		tenantID string
		caID     string
		status   string
		errMsg   string
	}{
		{"empty tenant ID", "", "ca-1", "active", "tenant ID is required"},
		{"empty CA ID", "tenant-1", "", "active", "CA ID is required"},
		{"invalid status", "tenant-1", "ca-1", "invalid", "invalid status"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.UpdateTenantIntermediateCAStatus(context.Background(), tt.tenantID, tt.caID, tt.status)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestCoverageBoost_UpdateTenantIntermediateCAStatus_NoEntry(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := qrdb.NewTestService()
	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	err := service.UpdateTenantIntermediateCAStatus(context.Background(), "nonexistent", "ca-1", "active")
	require.Error(t, err)
	assert.Equal(t, ErrTenantCANotConfigured, err)
}

func TestCoverageBoost_UpdateTenantIntermediateCAStatus_IntCANotFound(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := qrdb.NewTestService()
	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	service.mu.Lock()
	service.tenantCAs["tenant-1"] = &tenantCAEntry{
		intermediateCAs: make(map[string]*tenantIntermediateCAEntry),
	}
	service.mu.Unlock()

	err := service.UpdateTenantIntermediateCAStatus(context.Background(), "tenant-1", "missing-ca", "active")
	require.Error(t, err)
	assert.Equal(t, ErrTenantIntCANotFound, err)
}

func TestCoverageBoost_UpdateTenantIntermediateCAStatus_Suspend(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := qrdb.NewTestService()
	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Create tenant first so tenantDAO can find it
	_, err := service.CreateTenant(context.Background(), CreateTenantRequest{
		ID:   "tenant-suspend",
		Name: "Suspend Test",
	})
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	service.mu.Lock()
	service.tenantCAs["tenant-suspend"] = &tenantCAEntry{
		intermediateCAs: map[string]*tenantIntermediateCAEntry{
			"int-1": {cert: makeTestCert(t, "Int CA"), signer: key},
		},
		defaultIntCA: "int-1",
	}
	service.mu.Unlock()

	// Suspend the CA - should clear signer and default
	err = service.UpdateTenantIntermediateCAStatus(context.Background(), "tenant-suspend", "int-1", "suspended")
	require.NoError(t, err)

	service.mu.RLock()
	entry := service.tenantCAs["tenant-suspend"]
	assert.Nil(t, entry.intermediateCAs["int-1"].signer)
	assert.Empty(t, entry.defaultIntCA)
	service.mu.RUnlock()
}

func TestCoverageBoost_UpdateTenantIntermediateCAStatus_Revoke(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := qrdb.NewTestService()
	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	service.mu.Lock()
	service.tenantCAs["tenant-revoke"] = &tenantCAEntry{
		intermediateCAs: map[string]*tenantIntermediateCAEntry{
			"int-1": {cert: makeTestCert(t, "Int CA"), signer: key},
		},
		defaultIntCA: "int-1",
	}
	service.mu.Unlock()

	err = service.UpdateTenantIntermediateCAStatus(context.Background(), "tenant-revoke", "int-1", "revoked")
	require.NoError(t, err)
}

// ==========================================================================
// GetTenantCAStatus coverage
// ==========================================================================

func TestCoverageBoost_GetTenantCAStatus_EmptyTenantID(t *testing.T) {
	logger := slog.Default()
	service := NewTenantAwareAdminService(nil, nil, nil, logger, "1.0.0")

	_, err := service.GetTenantCAStatus(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant ID is required")
}

func TestCoverageBoost_GetTenantCAStatus_NoEntry_NoGlobalCA(t *testing.T) {
	logger := slog.Default()
	service := NewTenantAwareAdminService(nil, nil, nil, logger, "1.0.0")

	result, err := service.GetTenantCAStatus(context.Background(), "nonexistent")
	require.NoError(t, err)
	assert.Equal(t, "nonexistent", result.TenantID)
	assert.Equal(t, 0, result.ActiveCACount)
	assert.False(t, result.CanIssueCerts)
}

func TestCoverageBoost_GetTenantCAStatus_WithRootAndIntermediateCAs(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := qrdb.NewTestService()
	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rootCert := makeTestCert(t, "Root CA")
	intCert := makeTestCert(t, "Int CA")

	service.mu.Lock()
	service.tenantCAs["tenant-ca-status"] = &tenantCAEntry{
		rootCA:     rootCert,
		rootSigner: key,
		intermediateCAs: map[string]*tenantIntermediateCAEntry{
			"int-1": {cert: intCert, signer: key},
		},
		defaultIntCA: "int-1",
	}
	service.mu.Unlock()

	result, err := service.GetTenantCAStatus(context.Background(), "tenant-ca-status")
	require.NoError(t, err)
	assert.Equal(t, 2, result.ActiveCACount) // root + int
	assert.True(t, result.CanIssueCerts)
	assert.Equal(t, "int-1", result.DefaultIntermediateCAID)
	require.NotNil(t, result.RootCA)
	assert.Equal(t, "active", result.RootCA.Status)
	require.Len(t, result.IntermediateCAs, 1)
	assert.Equal(t, "active", result.IntermediateCAs[0].Status)
}

func TestCoverageBoost_GetTenantCAStatus_SuspendedIntCA(t *testing.T) {
	logger := slog.Default()
	service := NewTenantAwareAdminService(nil, nil, nil, logger, "1.0.0")

	intCert := makeTestCert(t, "Suspended Int CA")

	service.mu.Lock()
	service.tenantCAs["tenant-suspended-ca"] = &tenantCAEntry{
		intermediateCAs: map[string]*tenantIntermediateCAEntry{
			"int-suspended": {cert: intCert, signer: nil}, // nil signer = suspended
		},
	}
	service.mu.Unlock()

	result, err := service.GetTenantCAStatus(context.Background(), "tenant-suspended-ca")
	require.NoError(t, err)
	assert.Equal(t, 0, result.ActiveCACount)
	assert.False(t, result.CanIssueCerts)
	require.Len(t, result.IntermediateCAs, 1)
	assert.Equal(t, "suspended", result.IntermediateCAs[0].Status)
}

func TestCoverageBoost_GetTenantCAStatus_ExpiredRootCA(t *testing.T) {
	logger := slog.Default()
	service := NewTenantAwareAdminService(nil, nil, nil, logger, "1.0.0")

	expiredCert := makeTestCertWithExpiry(t, "Expired Root", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))

	service.mu.Lock()
	service.tenantCAs["tenant-expired"] = &tenantCAEntry{
		rootCA:          expiredCert,
		intermediateCAs: make(map[string]*tenantIntermediateCAEntry),
	}
	service.mu.Unlock()

	result, err := service.GetTenantCAStatus(context.Background(), "tenant-expired")
	require.NoError(t, err)
	require.NotNil(t, result.RootCA)
	assert.Equal(t, "expired", result.RootCA.Status)
	assert.Equal(t, 0, result.ActiveCACount)
}

// ==========================================================================
// UpdateTenant coverage for deleted tenant
// ==========================================================================

func TestCoverageBoost_UpdateTenant_DeletedTenant(t *testing.T) {
	service := newTenantAwareTestService(t)

	// Create and then soft-delete tenant
	_, err := service.CreateTenant(context.Background(), CreateTenantRequest{
		ID:   "tenant-to-delete",
		Name: "Delete Me",
	})
	require.NoError(t, err)

	err = service.UpdateTenantStatus(context.Background(), "tenant-to-delete", entities.TenantStatusDeleted)
	require.NoError(t, err)

	// Updating a deleted tenant should return ErrTenantDeleted
	_, err = service.UpdateTenant(context.Background(), "tenant-to-delete", UpdateTenantRequest{Name: "New Name"})
	require.Error(t, err)
	assert.Equal(t, ErrTenantDeleted, err)
}

// ==========================================================================
// wrapInputError coverage
// ==========================================================================

func TestCoverageBoost_WrapInputError(t *testing.T) {
	err := wrapInputError("field_name", "value is invalid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "field_name")
	assert.Contains(t, err.Error(), "value is invalid")
}

// ==========================================================================
// Helpers
// ==========================================================================

func makeTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	return makeTestCertWithExpiry(t, cn, time.Now().Add(-time.Hour), time.Now().Add(8760*time.Hour))
}

func makeTestCertWithExpiry(t *testing.T, cn string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
