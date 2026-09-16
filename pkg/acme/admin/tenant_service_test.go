//go:build codec_json

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

package admin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/qrdb"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	acmeobjstore "github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Mock Implementations
// ============================================================================

// newTestQRDB creates a qrdb.Service for testing.
func newTestQRDB() qrdb.Service {
	return qrdb.NewTestService()
}

// ============================================================================
// Basic Tests
// ============================================================================

func TestNewTenantAwareAdminService(t *testing.T) {
	logger := slog.Default()

	service := NewTenantAwareAdminService(nil, nil, nil, logger, "1.0.0")

	require.NotNil(t, service)
	assert.Equal(t, logger, service.logger)
	assert.NotNil(t, service.AdminService)
}

func TestTenantAwareAdminService_CreateTenant_EmptyID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	req := CreateTenantRequest{
		ID:   "",
		Name: "Test Tenant",
	}

	_, err := service.CreateTenant(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant ID is required")
}

func TestTenantAwareAdminService_CreateTenant_EmptyName(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	req := CreateTenantRequest{
		ID:   "tenant-123",
		Name: "",
	}

	_, err := service.CreateTenant(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant name is required")
}

func TestTenantAwareAdminService_CreateTenant_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")
	service.SetTenantService(newFakeTenantServicer())

	req := CreateTenantRequest{
		ID:   "tenant-success",
		Name: "Test Tenant",
	}

	tenant, err := service.CreateTenant(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, tenant)

	// Verify tenant info
	assert.Equal(t, "tenant-success", tenant.ID)
	assert.Equal(t, "Test Tenant", tenant.Name)
	assert.Equal(t, "active", tenant.Status)
	assert.False(t, tenant.CreatedAt.IsZero())
	assert.False(t, tenant.UpdatedAt.IsZero())
}

// ============================================================================
// GetTenant Tests
// ============================================================================

func TestTenantAwareAdminService_GetTenant_EmptyID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	_, err := service.GetTenant(context.Background(), "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant ID is required")
}

func TestTenantAwareAdminService_GetTenant_NotFound(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")
	service.SetTenantService(newFakeTenantServicer())

	_, err := service.GetTenant(context.Background(), "nonexistent-tenant")
	require.Error(t, err)
	assert.Equal(t, ErrTenantNotFound, err)
}

func TestTenantAwareAdminService_GetTenant_Success(t *testing.T) {
	service := newTenantAwareTestService(t)

	// Create a tenant first
	_, err := service.CreateTenant(context.Background(), CreateTenantRequest{
		ID:   "tenant-get-test",
		Name: "Get Test Tenant",
	})
	require.NoError(t, err)

	// Now get the tenant
	tenant, err := service.GetTenant(context.Background(), "tenant-get-test")
	require.NoError(t, err)
	require.NotNil(t, tenant)
	assert.Equal(t, "tenant-get-test", tenant.ID)
	assert.Equal(t, "active", tenant.Status)
}

func TestTenantAwareAdminService_GetTenant_FallbackNotFound(t *testing.T) {
	// This test verifies that ErrTenantNotFound is returned for nonexistent
	// tenants once a qrdb TenantServicer is wired (qrdb is the single tenant
	// authority; there is no local-only fallback to test here anymore).
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")
	service.SetTenantService(newFakeTenantServicer())

	_, err := service.GetTenant(context.Background(), "tenant-123")
	require.Error(t, err)
	assert.Equal(t, ErrTenantNotFound, err)
}

// ============================================================================
// UpdateTenant Tests
// ============================================================================

func TestTenantAwareAdminService_UpdateTenant_EmptyID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	_, err := service.UpdateTenant(context.Background(), "", UpdateTenantRequest{Name: "New Name"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant ID is required")
}

func TestTenantAwareAdminService_UpdateTenant_NotFound(t *testing.T) {
	service := newTenantAwareTestService(t)

	_, err := service.UpdateTenant(context.Background(), "nonexistent", UpdateTenantRequest{Name: "New Name"})
	require.Error(t, err)
	assert.Equal(t, ErrTenantNotFound, err)
}

func TestTenantAwareAdminService_UpdateTenant_Success(t *testing.T) {
	service := newTenantAwareTestService(t)

	// Create tenant first
	_, err := service.CreateTenant(context.Background(), CreateTenantRequest{
		ID:   "tenant-update-test",
		Name: "Original Name",
	})
	require.NoError(t, err)

	// Update tenant
	newSettings := &TenantSettingsInfo{
		MaxCertificates: 1000,
		RequireEAB:      true,
	}
	updated, err := service.UpdateTenant(context.Background(), "tenant-update-test", UpdateTenantRequest{
		Name:     "Updated Name",
		Settings: newSettings,
	})

	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Equal(t, "Updated Name", updated.Name)
	assert.NotNil(t, updated.Settings)
	assert.Equal(t, 1000, updated.Settings.MaxCertificates)
	assert.True(t, updated.Settings.RequireEAB)
}

func TestTenantAwareAdminService_UpdateTenant_PartialUpdate(t *testing.T) {
	service := newTenantAwareTestService(t)

	// Create tenant first
	_, err := service.CreateTenant(context.Background(), CreateTenantRequest{
		ID:   "tenant-partial-update",
		Name: "Original Name",
	})
	require.NoError(t, err)

	// Update only name
	updated, err := service.UpdateTenant(context.Background(), "tenant-partial-update", UpdateTenantRequest{
		Name: "New Name Only",
	})

	require.NoError(t, err)
	assert.Equal(t, "New Name Only", updated.Name)
}

// ============================================================================
// DeleteTenant Tests
// ============================================================================

func TestTenantAwareAdminService_DeleteTenant_EmptyID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	err := service.DeleteTenant(context.Background(), "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant ID is required")
}

func TestTenantAwareAdminService_DeleteTenant_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")
	service.SetTenantService(newFakeTenantServicer())

	// Create tenant first
	_, err := service.CreateTenant(context.Background(), CreateTenantRequest{
		ID:   "tenant-delete-test",
		Name: "Delete Test",
	})
	require.NoError(t, err)

	// Delete tenant
	err = service.DeleteTenant(context.Background(), "tenant-delete-test")
	require.NoError(t, err)

	// Verify tenant is gone
	_, err = service.GetTenant(context.Background(), "tenant-delete-test")
	assert.Equal(t, ErrTenantNotFound, err)
}

func TestTenantAwareAdminService_DeleteTenant_NotFound(t *testing.T) {
	service := newTenantAwareTestService(t)

	err := service.DeleteTenant(context.Background(), "nonexistent-tenant")
	require.Error(t, err)
	assert.Equal(t, ErrTenantNotFound, err)
}

// ============================================================================
// UpdateTenantStatus Tests
// ============================================================================

func TestTenantAwareAdminService_UpdateTenantStatus_Validation(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	tests := []struct {
		name     string
		tenantID string
		status   string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "empty tenant ID",
			tenantID: "",
			status:   "active",
			wantErr:  true,
			errMsg:   "tenant ID is required",
		},
		{
			name:     "empty status",
			tenantID: "tenant-123",
			status:   "",
			wantErr:  true,
			errMsg:   "status is required",
		},
		{
			name:     "invalid status",
			tenantID: "tenant-123",
			status:   "unknown",
			wantErr:  true,
			errMsg:   "invalid status",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := service.UpdateTenantStatus(context.Background(), tc.tenantID, tc.status)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidTenantStatuses(t *testing.T) {
	validStatuses := []string{"active", "suspended", "deleted"}

	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	for _, status := range validStatuses {
		t.Run(status, func(t *testing.T) {
			err := service.UpdateTenantStatus(context.Background(), "tenant-123", status)
			// The validation should pass - no "invalid status" error
			if err != nil {
				assert.NotContains(t, err.Error(), "invalid status")
			}
		})
	}
}

// ============================================================================
// ListTenants Tests
// ============================================================================

func TestTenantAwareAdminService_ListTenants_Defaults(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")
	service.SetTenantService(newFakeTenantServicer())

	// Test with defaults (page 0, perPage 0)
	tenants, pagination, err := service.ListTenants(context.Background(), ListTenantsRequest{})

	assert.NoError(t, err)
	assert.NotNil(t, tenants)
	assert.NotNil(t, pagination)
	assert.Equal(t, 1, pagination.Page)
	assert.Equal(t, 20, pagination.PerPage)
}

func TestTenantAwareAdminService_ListTenants_MaxPerPage(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")
	service.SetTenantService(newFakeTenantServicer())

	// Test with too high perPage
	_, pagination, err := service.ListTenants(context.Background(), ListTenantsRequest{
		Page:    1,
		PerPage: 200, // Should be capped at 100
	})

	assert.NoError(t, err)
	assert.Equal(t, 100, pagination.PerPage)
}

// ============================================================================
// storeKeyAndCert Tests
// ============================================================================

func TestTenantAwareAdminService_StoreKeyAndCert_NoCA(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Generate a test key and cert
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)

	// This should not panic even without a real CA
	err := service.storeKeyAndCert(context.Background(), "tenant-123", "root", privKey, cert)
	require.NoError(t, err)
}

func TestTenantAwareAdminService_StoreKeyAndCert_NoKV(t *testing.T) {
	logger := slog.Default()

	// Create service without KV client
	service := NewTenantAwareAdminService(nil, nil, &testServiceNoKV{}, logger, "1.0.0")

	// Generate a test key and cert
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)

	// Should still succeed (logs warning but doesn't fail)
	err := service.storeKeyAndCert(context.Background(), "tenant-123", "root", privKey, cert)
	require.NoError(t, err)
}

// testServiceNoKV implements qrdb.Service with nil KV for testing
type testServiceNoKV struct{}

func (s *testServiceNoKV) KV() db.KVClient                   { return nil }
func (s *testServiceNoKV) Admin() db.AdminClient             { return nil }
func (s *testServiceNoKV) Watch() db.WatchClient             { return nil }
func (s *testServiceNoKV) Lease() db.LeaseClient             { return nil }
func (s *testServiceNoKV) Batch() db.BatchClient             { return nil }
func (s *testServiceNoKV) Transaction() db.TransactionClient { return nil }
func (s *testServiceNoKV) Index() db.IndexClient             { return nil }
func (s *testServiceNoKV) Users() db.UserClient              { return nil }
func (s *testServiceNoKV) Roles() db.RoleClient              { return nil }
func (s *testServiceNoKV) Certs() db.CertClient              { return nil }
func (s *testServiceNoKV) Barrier() db.BarrierClient         { return nil }
func (s *testServiceNoKV) Ceremony() db.CeremonyClient       { return nil }
func (s *testServiceNoKV) Credentials() db.CredentialClient  { return nil }
func (s *testServiceNoKV) Config() *qrdb.Config              { return nil }
func (s *testServiceNoKV) Healthy(ctx context.Context) bool  { return true }
func (s *testServiceNoKV) Close() error                      { return nil }

// ============================================================================
// GetTenantSigningCA Tests
// ============================================================================

func TestTenantAwareAdminService_GetTenantSigningCA_WithIntermediateCA(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Create root and intermediate
	_, err := service.CreateTenantRootCA(context.Background(), "tenant-signing-int", CreateTenantRootCARequest{
		CommonName:   "Test Root CA",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	_, err = service.CreateTenantIntermediateCA(context.Background(), "tenant-signing-int", CreateTenantIntermediateCARequest{
		CommonName:   "Int CA",
		ParentType:   "tenant",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	// Get signing CA - should return intermediate
	signer, cert, err := service.GetTenantSigningCA(context.Background(), "tenant-signing-int")
	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, cert)
	assert.Equal(t, "Int CA", cert.Subject.CommonName)
}

func TestTenantAwareAdminService_GetTenantSigningCA_FallbackToRootCA(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Create only root CA
	_, err := service.CreateTenantRootCA(context.Background(), "tenant-signing-root", CreateTenantRootCARequest{
		CommonName:   "Test Root CA",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	// Get signing CA - should return root
	signer, cert, err := service.GetTenantSigningCA(context.Background(), "tenant-signing-root")
	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, cert)
	assert.Equal(t, "Test Root CA", cert.Subject.CommonName)
}

func TestTenantAwareAdminService_GetTenantSigningCA_NoCAConfigured(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// No CA configured and no global CA
	_, _, err := service.GetTenantSigningCA(context.Background(), "tenant-no-ca")
	require.Error(t, err)
	assert.Equal(t, ErrNoSigningCAAvailable, err)
}

func TestTenantAwareAdminService_GetTenantSigningCA_DefaultIntermediateCA(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Create root and two intermediates
	_, err := service.CreateTenantRootCA(context.Background(), "tenant-default-int-ca", CreateTenantRootCARequest{
		CommonName:   "Test Root CA",
		KeyAlgorithm: "ECDSA",
	})
	require.NoError(t, err)

	// Create first intermediate (not default)
	intCA1, err := service.CreateTenantIntermediateCA(context.Background(), "tenant-default-int-ca", CreateTenantIntermediateCARequest{
		CommonName:   "Int CA 1",
		ParentType:   "tenant",
		KeyAlgorithm: "ECDSA",
	})
	require.NoError(t, err)

	// Create second intermediate and set as default
	intCA2, err := service.CreateTenantIntermediateCA(context.Background(), "tenant-default-int-ca", CreateTenantIntermediateCARequest{
		CommonName:   "Int CA 2 (Default)",
		ParentType:   "tenant",
		KeyAlgorithm: "ECDSA",
		SetAsDefault: true,
	})
	require.NoError(t, err)

	// Get signing CA - should return default (Int CA 2)
	_, cert, err := service.GetTenantSigningCA(context.Background(), "tenant-default-int-ca")
	require.NoError(t, err)
	assert.Equal(t, intCA2.CommonName, cert.Subject.CommonName)

	// Change default to first intermediate
	err = service.SetTenantDefaultIntermediateCA(context.Background(), "tenant-default-int-ca", intCA1.ID)
	require.NoError(t, err)

	// Now should return Int CA 1
	_, cert, err = service.GetTenantSigningCA(context.Background(), "tenant-default-int-ca")
	require.NoError(t, err)
	assert.Equal(t, intCA1.CommonName, cert.Subject.CommonName)
}

func TestTenantAwareAdminService_GetTenantSigningCA_SuspendedIntermediateCA(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Create root and intermediate
	_, err := service.CreateTenantRootCA(context.Background(), "tenant-suspended-int", CreateTenantRootCARequest{
		CommonName:   "Test Root CA",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	intCA, err := service.CreateTenantIntermediateCA(context.Background(), "tenant-suspended-int", CreateTenantIntermediateCARequest{
		CommonName:   "Int CA",
		ParentType:   "tenant",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	// Suspend the intermediate CA
	err = service.UpdateTenantIntermediateCAStatus(context.Background(), "tenant-suspended-int", intCA.ID, "suspended")
	require.NoError(t, err)

	// Get signing CA - should fall back to root CA since intermediate is suspended
	_, cert, err := service.GetTenantSigningCA(context.Background(), "tenant-suspended-int")
	require.NoError(t, err)
	assert.Equal(t, "Test Root CA", cert.Subject.CommonName)
}

// ============================================================================
// Tenant CA Tests
// ============================================================================

func TestTenantAwareAdminService_CreateTenantRootCA_EmptyID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	_, err := service.CreateTenantRootCA(context.Background(), "", CreateTenantRootCARequest{
		CommonName: "Test Root CA",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant ID is required")
}

func TestTenantAwareAdminService_CreateTenantRootCA_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Create root CA with RSA
	caInfo, err := service.CreateTenantRootCA(context.Background(), "tenant-123", CreateTenantRootCARequest{
		CommonName:    "Test Tenant Root CA",
		KeyAlgorithm:  "RSA",
		ValidityYears: 10,
	})

	require.NoError(t, err)
	require.NotNil(t, caInfo)
	assert.Equal(t, "Test Tenant Root CA", caInfo.CommonName)
	assert.Equal(t, "RSA", caInfo.KeyAlgorithm)
	assert.Equal(t, "active", caInfo.Status)
	assert.NotEmpty(t, caInfo.SerialNumber)
	assert.False(t, caInfo.NotBefore.IsZero())
	assert.False(t, caInfo.NotAfter.IsZero())
}

func TestTenantAwareAdminService_CreateTenantRootCA_ECDSA(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	caInfo, err := service.CreateTenantRootCA(context.Background(), "tenant-ecdsa", CreateTenantRootCARequest{
		CommonName:    "Test ECDSA Root CA",
		KeyAlgorithm:  "ECDSA",
		ValidityYears: 5,
	})

	require.NoError(t, err)
	require.NotNil(t, caInfo)
	assert.Equal(t, "Test ECDSA Root CA", caInfo.CommonName)
	assert.Equal(t, "ECDSA", caInfo.KeyAlgorithm)
}

func TestTenantAwareAdminService_CreateTenantRootCA_Ed25519(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	caInfo, err := service.CreateTenantRootCA(context.Background(), "tenant-ed25519", CreateTenantRootCARequest{
		CommonName:    "Test Ed25519 Root CA",
		KeyAlgorithm:  "Ed25519",
		ValidityYears: 5,
	})

	require.NoError(t, err)
	require.NotNil(t, caInfo)
	assert.Equal(t, "Test Ed25519 Root CA", caInfo.CommonName)
	assert.Equal(t, "Ed25519", caInfo.KeyAlgorithm)
}

func TestTenantAwareAdminService_CreateTenantRootCA_MissingCommonName(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	_, err := service.CreateTenantRootCA(context.Background(), "tenant-123", CreateTenantRootCARequest{
		CommonName:   "", // Missing
		KeyAlgorithm: "RSA",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "common name is required")
}

func TestTenantAwareAdminService_CreateTenantRootCA_InvalidAlgorithm(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	_, err := service.CreateTenantRootCA(context.Background(), "tenant-123", CreateTenantRootCARequest{
		CommonName:   "Test Root CA",
		KeyAlgorithm: "INVALID",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key algorithm")
}

func TestTenantAwareAdminService_CreateTenantRootCA_AlreadyExists(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Create first root CA
	_, err := service.CreateTenantRootCA(context.Background(), "tenant-duplicate", CreateTenantRootCARequest{
		CommonName:   "Test Root CA",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	// Try to create second root CA - should fail
	_, err = service.CreateTenantRootCA(context.Background(), "tenant-duplicate", CreateTenantRootCARequest{
		CommonName:   "Another Root CA",
		KeyAlgorithm: "RSA",
	})
	require.Error(t, err)
	assert.Equal(t, ErrTenantRootCAExists, err)
}

func TestTenantAwareAdminService_CreateTenantIntermediateCA_EmptyID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	_, err := service.CreateTenantIntermediateCA(context.Background(), "", CreateTenantIntermediateCARequest{
		CommonName: "Test Int CA",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant ID is required")
}

func TestTenantAwareAdminService_CreateTenantIntermediateCA_WithTenantParent(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// First create a root CA for the tenant
	_, err := service.CreateTenantRootCA(context.Background(), "tenant-int", CreateTenantRootCARequest{
		CommonName:   "Test Tenant Root CA",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	// Create intermediate CA with tenant parent
	intCA, err := service.CreateTenantIntermediateCA(context.Background(), "tenant-int", CreateTenantIntermediateCARequest{
		CommonName:    "Test Intermediate CA",
		ParentType:    "tenant",
		KeyAlgorithm:  "RSA",
		ValidityYears: 3,
	})

	require.NoError(t, err)
	require.NotNil(t, intCA)
	assert.Equal(t, "Test Intermediate CA", intCA.CommonName)
	assert.Equal(t, "tenant", intCA.ParentType)
	assert.Equal(t, "active", intCA.Status)
	assert.NotEmpty(t, intCA.ID)
}

func TestTenantAwareAdminService_CreateTenantIntermediateCA_NoTenantRoot(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Try to create intermediate CA with tenant parent when no root exists
	_, err := service.CreateTenantIntermediateCA(context.Background(), "tenant-no-root", CreateTenantIntermediateCARequest{
		CommonName:   "Test Intermediate CA",
		ParentType:   "tenant",
		KeyAlgorithm: "RSA",
	})

	require.Error(t, err)
	assert.Equal(t, ErrTenantRootCANotFound, err)
}

func TestTenantAwareAdminService_CreateTenantIntermediateCA_MissingCommonName(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	_, err := service.CreateTenantIntermediateCA(context.Background(), "tenant-123", CreateTenantIntermediateCARequest{
		CommonName:   "", // Missing
		KeyAlgorithm: "RSA",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "common name is required")
}

func TestTenantAwareAdminService_CreateTenantIntermediateCA_SetAsDefault(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// First create a root CA
	_, err := service.CreateTenantRootCA(context.Background(), "tenant-default-int", CreateTenantRootCARequest{
		CommonName:   "Test Root CA",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	// Create intermediate CA with SetAsDefault
	intCA, err := service.CreateTenantIntermediateCA(context.Background(), "tenant-default-int", CreateTenantIntermediateCARequest{
		CommonName:    "Default Int CA",
		ParentType:    "tenant",
		KeyAlgorithm:  "RSA",
		ValidityYears: 3,
		SetAsDefault:  true,
	})
	require.NoError(t, err)

	// Check CA status shows this as default
	status, err := service.GetTenantCAStatus(context.Background(), "tenant-default-int")
	require.NoError(t, err)
	assert.Equal(t, intCA.ID, status.DefaultIntermediateCAID)
}

func TestTenantAwareAdminService_GetTenantIntermediateCA_Validation(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Empty tenant ID
	_, err := service.GetTenantIntermediateCA(context.Background(), "", "ca-123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant ID is required")

	// Empty CA ID
	_, err = service.GetTenantIntermediateCA(context.Background(), "tenant-123", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CA ID is required")
}

func TestTenantAwareAdminService_GetTenantIntermediateCA_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Create root and intermediate
	_, err := service.CreateTenantRootCA(context.Background(), "tenant-get-int", CreateTenantRootCARequest{
		CommonName:   "Test Root CA",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	created, err := service.CreateTenantIntermediateCA(context.Background(), "tenant-get-int", CreateTenantIntermediateCARequest{
		CommonName:   "Test Int CA",
		ParentType:   "tenant",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	// Get the intermediate CA
	retrieved, err := service.GetTenantIntermediateCA(context.Background(), "tenant-get-int", created.ID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, created.ID, retrieved.ID)
	assert.Equal(t, created.CommonName, retrieved.CommonName)
}

func TestTenantAwareAdminService_GetTenantIntermediateCA_NotFound(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Try to get non-existent CA
	_, err := service.GetTenantIntermediateCA(context.Background(), "tenant-123", "non-existent-id")
	require.Error(t, err)
	assert.Equal(t, ErrTenantCANotConfigured, err)
}

func TestTenantAwareAdminService_ListTenantIntermediateCAs_EmptyID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	_, err := service.ListTenantIntermediateCAs(context.Background(), "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant ID is required")
}

func TestTenantAwareAdminService_ListTenantIntermediateCAs_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Create root and multiple intermediates
	_, err := service.CreateTenantRootCA(context.Background(), "tenant-list-int", CreateTenantRootCARequest{
		CommonName:   "Test Root CA",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	_, err = service.CreateTenantIntermediateCA(context.Background(), "tenant-list-int", CreateTenantIntermediateCARequest{
		CommonName:   "Int CA 1",
		ParentType:   "tenant",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	_, err = service.CreateTenantIntermediateCA(context.Background(), "tenant-list-int", CreateTenantIntermediateCARequest{
		CommonName:   "Int CA 2",
		ParentType:   "tenant",
		KeyAlgorithm: "ECDSA",
	})
	require.NoError(t, err)

	// List all
	list, err := service.ListTenantIntermediateCAs(context.Background(), "tenant-list-int")
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestTenantAwareAdminService_ListTenantIntermediateCAs_Empty(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// No CAs configured
	list, err := service.ListTenantIntermediateCAs(context.Background(), "tenant-empty")
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestTenantAwareAdminService_UpdateTenantIntermediateCAStatus_Validation(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Empty tenant ID
	err := service.UpdateTenantIntermediateCAStatus(context.Background(), "", "ca-123", "active")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant ID is required")

	// Empty CA ID
	err = service.UpdateTenantIntermediateCAStatus(context.Background(), "tenant-123", "", "active")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CA ID is required")
}

func TestTenantAwareAdminService_UpdateTenantIntermediateCAStatus_Suspend(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Create root and intermediate
	_, err := service.CreateTenantRootCA(context.Background(), "tenant-suspend", CreateTenantRootCARequest{
		CommonName:   "Test Root CA",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	intCA, err := service.CreateTenantIntermediateCA(context.Background(), "tenant-suspend", CreateTenantIntermediateCARequest{
		CommonName:   "Test Int CA",
		ParentType:   "tenant",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	// Suspend the CA
	err = service.UpdateTenantIntermediateCAStatus(context.Background(), "tenant-suspend", intCA.ID, "suspended")
	require.NoError(t, err)
}

func TestTenantAwareAdminService_UpdateTenantIntermediateCAStatus_InvalidStatus(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	err := service.UpdateTenantIntermediateCAStatus(context.Background(), "tenant-123", "ca-id", "invalid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid status")
}

func TestTenantAwareAdminService_SetTenantDefaultIntermediateCA_Validation(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Empty tenant ID
	err := service.SetTenantDefaultIntermediateCA(context.Background(), "", "ca-123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant ID is required")

	// Empty CA ID
	err = service.SetTenantDefaultIntermediateCA(context.Background(), "tenant-123", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CA ID is required")
}

func TestTenantAwareAdminService_SetTenantDefaultIntermediateCA_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Create root and intermediates
	_, err := service.CreateTenantRootCA(context.Background(), "tenant-set-default", CreateTenantRootCARequest{
		CommonName:   "Test Root CA",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	intCA1, err := service.CreateTenantIntermediateCA(context.Background(), "tenant-set-default", CreateTenantIntermediateCARequest{
		CommonName:   "Int CA 1",
		ParentType:   "tenant",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	intCA2, err := service.CreateTenantIntermediateCA(context.Background(), "tenant-set-default", CreateTenantIntermediateCARequest{
		CommonName:   "Int CA 2",
		ParentType:   "tenant",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	// Set second as default
	err = service.SetTenantDefaultIntermediateCA(context.Background(), "tenant-set-default", intCA2.ID)
	require.NoError(t, err)

	// Verify default was set
	status, err := service.GetTenantCAStatus(context.Background(), "tenant-set-default")
	require.NoError(t, err)
	assert.Equal(t, intCA2.ID, status.DefaultIntermediateCAID)

	// Can also set first as default
	err = service.SetTenantDefaultIntermediateCA(context.Background(), "tenant-set-default", intCA1.ID)
	require.NoError(t, err)

	status, err = service.GetTenantCAStatus(context.Background(), "tenant-set-default")
	require.NoError(t, err)
	assert.Equal(t, intCA1.ID, status.DefaultIntermediateCAID)
}

func TestTenantAwareAdminService_SetTenantDefaultIntermediateCA_NotFound(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	err := service.SetTenantDefaultIntermediateCA(context.Background(), "tenant-nonexistent", "ca-id")
	require.Error(t, err)
	assert.Equal(t, ErrTenantCANotConfigured, err)
}

func TestTenantAwareAdminService_GetTenantCAStatus_EmptyID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	_, err := service.GetTenantCAStatus(context.Background(), "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant ID is required")
}

func TestTenantAwareAdminService_GetTenantCAStatus_Default(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	status, err := service.GetTenantCAStatus(context.Background(), "tenant-123")
	assert.NoError(t, err)
	assert.NotNil(t, status)
	assert.Equal(t, "tenant-123", status.TenantID)
	assert.Equal(t, 0, status.ActiveCACount)
	assert.False(t, status.CanIssueCerts)
}

func TestTenantAwareAdminService_GetTenantCAStatus_WithRootCA(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Create root CA only
	_, err := service.CreateTenantRootCA(context.Background(), "tenant-status-root", CreateTenantRootCARequest{
		CommonName:   "Test Root CA",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	status, err := service.GetTenantCAStatus(context.Background(), "tenant-status-root")
	require.NoError(t, err)
	require.NotNil(t, status.RootCA)
	assert.Equal(t, "Test Root CA", status.RootCA.CommonName)
	assert.Equal(t, "active", status.RootCA.Status)
	assert.Equal(t, 1, status.ActiveCACount)
	assert.True(t, status.CanIssueCerts)
}

func TestTenantAwareAdminService_GetTenantCAStatus_FullHierarchy(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Create root and intermediates
	_, err := service.CreateTenantRootCA(context.Background(), "tenant-full-status", CreateTenantRootCARequest{
		CommonName:   "Test Root CA",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	intCA, err := service.CreateTenantIntermediateCA(context.Background(), "tenant-full-status", CreateTenantIntermediateCARequest{
		CommonName:   "Int CA",
		ParentType:   "tenant",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	status, err := service.GetTenantCAStatus(context.Background(), "tenant-full-status")
	require.NoError(t, err)
	require.NotNil(t, status.RootCA)
	require.Len(t, status.IntermediateCAs, 1)
	assert.Equal(t, intCA.ID, status.DefaultIntermediateCAID)
	assert.Equal(t, 2, status.ActiveCACount)
	assert.True(t, status.CanIssueCerts)
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestParseKeyAlgorithm(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"RSA", "RSA", false},
		{"rsa", "RSA", false},
		{"ECDSA", "ECDSA", false},
		{"ecdsa", "ECDSA", false},
		{"EC", "ECDSA", false},
		{"Ed25519", "Ed25519", false},
		{"ed25519", "Ed25519", false},
		{"", "RSA", false}, // Empty defaults to RSA
		{"INVALID", "", true},
		{"AES", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			algo, err := parseKeyAlgorithm(tt.input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, algo.String())
			}
		})
	}
}

func TestGenerateEABKeyID(t *testing.T) {
	keyID1, err := generateEABKeyID()
	require.NoError(t, err)
	assert.NotEmpty(t, keyID1)
	assert.Len(t, keyID1, 22) // 16 bytes base64url encoded = 22 chars

	// Generate a second one to ensure uniqueness
	keyID2, err := generateEABKeyID()
	require.NoError(t, err)
	assert.NotEqual(t, keyID1, keyID2)
}

func TestGenerateMACKey(t *testing.T) {
	// Test 32 byte key (256 bits)
	key1, err := generateMACKey(32)
	require.NoError(t, err)
	assert.Len(t, key1, 32)

	// Test 64 byte key (512 bits)
	key2, err := generateMACKey(64)
	require.NoError(t, err)
	assert.Len(t, key2, 64)

	// Ensure keys are unique
	key3, err := generateMACKey(32)
	require.NoError(t, err)
	assert.NotEqual(t, key1, key3)
}

func TestIsValidEABPurpose(t *testing.T) {
	tests := []struct {
		purpose  string
		expected bool
	}{
		{entities.EABPurposeAccountBinding, true},
		{entities.EABPurposeEndorse01, true},
		{entities.EABPurposeEnroll01, true},
		{"invalid-purpose", false},
		{"", false},
		{"ACCOUNT_BINDING", false}, // case-sensitive
	}

	for _, tc := range tests {
		t.Run(tc.purpose, func(t *testing.T) {
			result := isValidEABPurpose(tc.purpose)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestEabEntityToInfo(t *testing.T) {
	// Test nil input
	result := eabEntityToInfo(nil)
	assert.Nil(t, result)

	// Test with full entity
	now := time.Now()
	eab := &entities.ExternalAccountBinding{
		ID:                "test-id",
		TenantID:          "tenant-1",
		Status:            "active",
		Purpose:           entities.EABPurposeAccountBinding,
		AccountID:         123,
		ExternalAccountID: "ext-account-1",
		Contact:           []string{"admin@example.com"},
		CreatedAt:         now,
		CreatedBy:         "admin",
		UsedAt:            &now,
		ExpiresAt:         &now,
		DeviceInfo: &entities.EABDeviceInfo{
			DeviceID:           "device-1",
			Manufacturer:       "Test Manufacturer",
			Model:              "Test Model",
			EKPublicKeyHash:    "hash123",
			TPMManufacturer:    "TPM Manufacturer",
			TPMFirmwareVersion: "1.0.0",
			Metadata:           map[string]string{"key": "value"},
		},
	}

	info := eabEntityToInfo(eab)
	require.NotNil(t, info)
	assert.Equal(t, "test-id", info.ID)
	assert.Equal(t, "tenant-1", info.TenantID)
	assert.Equal(t, "active", info.Status)
	assert.Equal(t, entities.EABPurposeAccountBinding, info.Purpose)
	assert.Equal(t, uint64(123), info.AccountID)
	assert.Equal(t, "ext-account-1", info.ExternalAccountID)
	assert.Equal(t, []string{"admin@example.com"}, info.Contact)
	assert.Equal(t, now, info.CreatedAt)
	assert.Equal(t, "admin", info.CreatedBy)
	assert.Equal(t, &now, info.UsedAt)
	assert.Equal(t, &now, info.ExpiresAt)

	// Check DeviceInfo
	require.NotNil(t, info.DeviceInfo)
	assert.Equal(t, "device-1", info.DeviceInfo.DeviceID)
	assert.Equal(t, "Test Manufacturer", info.DeviceInfo.Manufacturer)
	assert.Equal(t, "Test Model", info.DeviceInfo.Model)
	assert.Equal(t, "hash123", info.DeviceInfo.EKPublicKeyHash)
	assert.Equal(t, "TPM Manufacturer", info.DeviceInfo.TPMManufacturer)
	assert.Equal(t, "1.0.0", info.DeviceInfo.TPMFirmwareVersion)
	assert.Equal(t, map[string]string{"key": "value"}, info.DeviceInfo.Metadata)
}

func TestEabEntityToInfo_NoDeviceInfo(t *testing.T) {
	eab := &entities.ExternalAccountBinding{
		ID:       "test-id",
		TenantID: "tenant-1",
	}

	info := eabEntityToInfo(eab)
	require.NotNil(t, info)
	assert.Equal(t, "test-id", info.ID)
	assert.Nil(t, info.DeviceInfo)
}

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"not found error", errors.New("not found"), true},
		{"storage EAB not found", errors.New("storage: external account binding not found"), true},
		{"admin EAB not found", errors.New("admin: external account binding not found"), true},
		{"other error", errors.New("database error"), false},
		{"similar but different", errors.New("resource not found"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isNotFoundError(tc.err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestWrapInputError(t *testing.T) {
	err := wrapInputError("field", "is required")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "admin: invalid input")
	assert.Contains(t, err.Error(), "field")
	assert.Contains(t, err.Error(), "is required")
}

// ============================================================================
// EAB Tests with Mock Storage
// ============================================================================

// mockTenantAwareStorageFactory implements storage.TenantAwareFactory for testing
type mockTenantAwareStorageFactory struct {
	eabDAO        *mockEABDAO
	tenantEABDAOs map[string]*mockEABDAO
}

func newMockTenantAwareStorageFactory() *mockTenantAwareStorageFactory {
	return &mockTenantAwareStorageFactory{
		eabDAO:        newMockEABDAO(),
		tenantEABDAOs: make(map[string]*mockEABDAO),
	}
}

func (f *mockTenantAwareStorageFactory) AccountDAO() (interface{}, error)     { return nil, nil }
func (f *mockTenantAwareStorageFactory) OrderDAO(uint64) (interface{}, error) { return nil, nil }
func (f *mockTenantAwareStorageFactory) AuthorizationDAO(uint64) (interface{}, error) {
	return nil, nil
}
func (f *mockTenantAwareStorageFactory) ChallengeDAO(uint64) (interface{}, error) { return nil, nil }
func (f *mockTenantAwareStorageFactory) CertificateDAO() (interface{}, error)     { return nil, nil }
func (f *mockTenantAwareStorageFactory) NonceDAO() (interface{}, error)           { return nil, nil }

func (f *mockTenantAwareStorageFactory) ExternalAccountBindingDAO() (*mockEABDAO, error) {
	return f.eabDAO, nil
}

func (f *mockTenantAwareStorageFactory) TenantExternalAccountBindingDAO(tenantID string) (*mockEABDAO, error) {
	if dao, ok := f.tenantEABDAOs[tenantID]; ok {
		return dao, nil
	}
	dao := newMockEABDAO()
	f.tenantEABDAOs[tenantID] = dao
	return dao, nil
}

// mockEABDAO implements a mock EAB storage
type mockEABDAO struct {
	eabs      map[uint64]*entities.ExternalAccountBinding
	saveErr   error
	getErr    error
	deleteErr error
	listErr   error
}

func newMockEABDAO() *mockEABDAO {
	return &mockEABDAO{
		eabs: make(map[uint64]*entities.ExternalAccountBinding),
	}
}

func (d *mockEABDAO) Save(_ context.Context, eab *entities.ExternalAccountBinding) error {
	if d.saveErr != nil {
		return d.saveErr
	}
	d.eabs[eab.EntityID()] = eab
	return nil
}

func (d *mockEABDAO) SaveWithCondition(_ context.Context, _ *entities.ExternalAccountBinding, _ qrdbsdk.Condition) error {
	panic("not implemented")
}

func (d *mockEABDAO) SaveIfAbsent(_ context.Context, _ *entities.ExternalAccountBinding) (bool, error) {
	panic("not implemented")
}

func (d *mockEABDAO) Get(_ context.Context, id uint64) (*entities.ExternalAccountBinding, error) {
	if d.getErr != nil {
		return nil, d.getErr
	}
	if eab, ok := d.eabs[id]; ok {
		return eab, nil
	}
	return nil, errors.New("not found")
}

func (d *mockEABDAO) Delete(_ context.Context, eab *entities.ExternalAccountBinding) error {
	if d.deleteErr != nil {
		return d.deleteErr
	}
	delete(d.eabs, eab.EntityID())
	return nil
}

func (d *mockEABDAO) Count(_ context.Context) (int, error) {
	return len(d.eabs), nil
}

func (d *mockEABDAO) Page(_ context.Context, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ExternalAccountBinding], error) {
	panic("not implemented")
}

func (d *mockEABDAO) ForEachPage(_ context.Context, query qrdbsdk.PageQuery, fn qrdbsdk.PagerFunc[*entities.ExternalAccountBinding]) error {
	if d.listErr != nil {
		return d.listErr
	}
	all := make([]*entities.ExternalAccountBinding, 0, len(d.eabs))
	for _, eab := range d.eabs {
		all = append(all, eab)
	}
	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = 100
	}
	total := len(all)
	for offset := 0; offset < total; offset += pageSize {
		end := offset + pageSize
		if end > total {
			end = total
		}
		result := qrdbsdk.PageResult[*entities.ExternalAccountBinding]{
			Entities: all[offset:end],
			Page:     (offset / pageSize) + 1,
			PageSize: pageSize,
			Total:    total,
			HasMore:  end < total,
		}
		if err := fn(result); err != nil {
			return err
		}
	}
	if total == 0 {
		result := qrdbsdk.PageResult[*entities.ExternalAccountBinding]{
			Entities: nil,
			Page:     1,
			PageSize: pageSize,
			Total:    0,
			HasMore:  false,
		}
		return fn(result)
	}
	return nil
}

func (d *mockEABDAO) EntityType() string {
	return "eab"
}

func (d *mockEABDAO) QueryByIndex(_ context.Context, _ string, _ interface{}) ([]*entities.ExternalAccountBinding, error) {
	panic("not implemented")
}

func (d *mockEABDAO) QueryByCompoundIndex(_ context.Context, _ string, _ []interface{}) ([]*entities.ExternalAccountBinding, error) {
	panic("not implemented")
}

func (d *mockEABDAO) ScanByCompoundIndex(_ context.Context, _ string, _ []interface{}, _, _ interface{}) ([]*entities.ExternalAccountBinding, error) {
	panic("not implemented")
}

func (d *mockEABDAO) QueryOneByIndex(_ context.Context, fieldName string, value interface{}) (*entities.ExternalAccountBinding, error) {
	if d.getErr != nil {
		return nil, d.getErr
	}
	strVal, _ := value.(string)
	for _, eab := range d.eabs {
		switch fieldName {
		case "ID":
			if eab.ID == strVal {
				return eab, nil
			}
		case "TenantID":
			if eab.TenantID == strVal {
				return eab, nil
			}
		}
	}
	return nil, errors.New("not found")
}

func (d *mockEABDAO) ScanByIndex(_ context.Context, _ string, _, _ interface{}) ([]*entities.ExternalAccountBinding, error) {
	panic("not implemented")
}

func (d *mockEABDAO) PageByIndex(_ context.Context, _ string, _ interface{}, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ExternalAccountBinding], error) {
	panic("not implemented")
}

func (d *mockEABDAO) CountByIndex(_ context.Context, _ string, _ interface{}) (int, error) {
	panic("not implemented")
}

func (d *mockEABDAO) Find(_ context.Context) *qrdbsdk.QueryBuilder[*entities.ExternalAccountBinding] {
	panic("not implemented")
}

// storageTenantAwareWrapper wraps our mock factory to implement storage.Factory and TenantAwareFactory
type storageTenantAwareWrapper struct {
	factory *mockTenantAwareStorageFactory
}

// Implement storage.Factory interface
func (w *storageTenantAwareWrapper) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	return nil, nil
}

func (w *storageTenantAwareWrapper) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	return nil, nil
}

func (w *storageTenantAwareWrapper) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return nil, nil
}

func (w *storageTenantAwareWrapper) ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return nil, nil
}

func (w *storageTenantAwareWrapper) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return nil, nil
}

func (w *storageTenantAwareWrapper) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	return nil, nil
}

func (w *storageTenantAwareWrapper) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return w.factory.eabDAO, nil
}

// Implement storage.TenantAwareFactory interface
func (w *storageTenantAwareWrapper) TenantDAO() (qrdbsdk.GenericDAO[*entities.Tenant], error) {
	return nil, nil
}

func (w *storageTenantAwareWrapper) ForTenant(tenantID string) (storage.Factory, error) {
	return &tenantScopedWrapper{factory: w.factory, tenantID: tenantID}, nil
}

func (w *storageTenantAwareWrapper) GetTenantID() string {
	return ""
}

func (w *storageTenantAwareWrapper) TenantAccountDAO(tenantID string) (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	return nil, nil
}

func (w *storageTenantAwareWrapper) TenantOrderDAO(tenantID string, accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	return nil, nil
}

func (w *storageTenantAwareWrapper) TenantAuthorizationDAO(tenantID string, accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return nil, nil
}

func (w *storageTenantAwareWrapper) TenantChallengeDAO(tenantID string, accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return nil, nil
}

func (w *storageTenantAwareWrapper) TenantCertificateDAO(tenantID string) (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return nil, nil
}

func (w *storageTenantAwareWrapper) TenantExternalAccountBindingDAO(tenantID string) (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return w.factory.TenantExternalAccountBindingDAO(tenantID)
}

// tenantScopedWrapper wraps the mock factory to scope EAB operations to a tenant
type tenantScopedWrapper struct {
	factory  *mockTenantAwareStorageFactory
	tenantID string
}

func (w *tenantScopedWrapper) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	return nil, nil
}

func (w *tenantScopedWrapper) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	return nil, nil
}

func (w *tenantScopedWrapper) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return nil, nil
}

func (w *tenantScopedWrapper) ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return nil, nil
}

func (w *tenantScopedWrapper) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return nil, nil
}

func (w *tenantScopedWrapper) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	return nil, nil
}

func (w *tenantScopedWrapper) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return w.factory.TenantExternalAccountBindingDAO(w.tenantID)
}

// Verify that storageTenantAwareWrapper implements the interfaces
var _ storage.Factory = (*storageTenantAwareWrapper)(nil)
var _ storage.TenantAwareFactory = (*storageTenantAwareWrapper)(nil)

func TestTenantAwareAdminService_CreateTenantEAB_EmptyID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	_, err := service.CreateTenantEAB(context.Background(), "", CreateEABRequest{
		Purpose: "account-binding",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant ID is required")
}

func TestTenantAwareAdminService_CreateTenantEAB_WithDeviceInfo(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()
	factory := newMockTenantAwareStorageFactory()

	// Create admin service with mock factory
	adminSvc := NewAdminService(nil, nil, logger, "1.0.0")
	adminSvc.storageFactory = &storageTenantAwareWrapper{factory: factory}

	service := &TenantAwareAdminService{
		AdminService: adminSvc,
		qrdbService:  qrdbSvc,
		logger:       logger,
		tenantCAs:    make(map[string]*tenantCAEntry),
	}

	req := CreateEABRequest{
		Purpose:           entities.EABPurposeAccountBinding,
		ExpiresInDays:     30,
		Contact:           []string{"admin@example.com"},
		ExternalAccountID: "ext-123",
		DeviceInfo: &EABDeviceInfoDTO{
			DeviceID:           "device-1",
			Manufacturer:       "Test Corp",
			Model:              "Model X",
			EKPublicKeyHash:    "hash123",
			TPMManufacturer:    "TPM Corp",
			TPMFirmwareVersion: "2.0",
			Metadata:           map[string]string{"env": "test"},
		},
		Metadata: map[string]string{"custom": "value"},
	}

	resp, err := service.CreateTenantEAB(context.Background(), "tenant-1", req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.ID)
	assert.NotEmpty(t, resp.MACKey)
	assert.Equal(t, "HS256", resp.Algorithm)
	assert.NotNil(t, resp.ExpiresAt)
}

func TestTenantAwareAdminService_CreateTenantEAB_InvalidPurpose(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()
	factory := newMockTenantAwareStorageFactory()

	adminSvc := NewAdminService(nil, nil, logger, "1.0.0")
	adminSvc.storageFactory = &storageTenantAwareWrapper{factory: factory}

	service := &TenantAwareAdminService{
		AdminService: adminSvc,
		qrdbService:  qrdbSvc,
		logger:       logger,
		tenantCAs:    make(map[string]*tenantCAEntry),
	}

	_, err := service.CreateTenantEAB(context.Background(), "tenant-1", CreateEABRequest{
		Purpose: "invalid-purpose",
	})

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidEABPurpose, err)
}

func TestTenantAwareAdminService_CreateTenantEAB_StorageError(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()
	factory := newMockTenantAwareStorageFactory()

	adminSvc := NewAdminService(nil, nil, logger, "1.0.0")
	adminSvc.storageFactory = &storageTenantAwareWrapper{factory: factory}

	service := &TenantAwareAdminService{
		AdminService: adminSvc,
		qrdbService:  qrdbSvc,
		logger:       logger,
		tenantCAs:    make(map[string]*tenantCAEntry),
	}

	// Get the DAO and inject error
	dao, _ := factory.TenantExternalAccountBindingDAO("tenant-err")
	dao.saveErr = errors.New("storage write failed")

	_, err := service.CreateTenantEAB(context.Background(), "tenant-err", CreateEABRequest{
		Purpose: entities.EABPurposeAccountBinding,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save EAB")
}

func TestTenantAwareAdminService_GetTenantEAB_Validation(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Empty tenant ID
	_, err := service.GetTenantEAB(context.Background(), "", "eab-123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant ID is required")

	// Empty KID
	_, err = service.GetTenantEAB(context.Background(), "tenant-123", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key ID is required")
}

func TestTenantAwareAdminService_GetTenantEAB_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()
	factory := newMockTenantAwareStorageFactory()

	adminSvc := NewAdminService(nil, nil, logger, "1.0.0")
	adminSvc.storageFactory = &storageTenantAwareWrapper{factory: factory}

	service := &TenantAwareAdminService{
		AdminService: adminSvc,
		qrdbService:  qrdbSvc,
		logger:       logger,
		tenantCAs:    make(map[string]*tenantCAEntry),
	}

	// Create an EAB first
	resp, err := service.CreateTenantEAB(context.Background(), "tenant-1", CreateEABRequest{
		Purpose: entities.EABPurposeAccountBinding,
	})
	require.NoError(t, err)

	// Get the EAB
	info, err := service.GetTenantEAB(context.Background(), "tenant-1", resp.ID)
	require.NoError(t, err)
	assert.Equal(t, resp.ID, info.ID)
	assert.Equal(t, "tenant-1", info.TenantID)
	assert.Equal(t, entities.EABStatusActive, info.Status)
}

func TestTenantAwareAdminService_GetTenantEAB_NotFound(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()
	factory := newMockTenantAwareStorageFactory()

	adminSvc := NewAdminService(nil, nil, logger, "1.0.0")
	adminSvc.storageFactory = &storageTenantAwareWrapper{factory: factory}

	service := &TenantAwareAdminService{
		AdminService: adminSvc,
		qrdbService:  qrdbSvc,
		logger:       logger,
		tenantCAs:    make(map[string]*tenantCAEntry),
	}

	_, err := service.GetTenantEAB(context.Background(), "tenant-1", "nonexistent")
	assert.Error(t, err)
	assert.Equal(t, ErrEABNotFound, err)
}

func TestTenantAwareAdminService_GetTenantEAB_CrossTenantDenied(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()
	factory := newMockTenantAwareStorageFactory()

	adminSvc := NewAdminService(nil, nil, logger, "1.0.0")
	adminSvc.storageFactory = &storageTenantAwareWrapper{factory: factory}

	service := &TenantAwareAdminService{
		AdminService: adminSvc,
		qrdbService:  qrdbSvc,
		logger:       logger,
		tenantCAs:    make(map[string]*tenantCAEntry),
	}

	// Create EAB for tenant-1
	resp, err := service.CreateTenantEAB(context.Background(), "tenant-1", CreateEABRequest{
		Purpose: entities.EABPurposeAccountBinding,
	})
	require.NoError(t, err)

	// Try to get it as tenant-2 (should fail due to cross-tenant check)
	_, err = service.GetTenantEAB(context.Background(), "tenant-2", resp.ID)
	assert.Error(t, err)
	assert.Equal(t, ErrEABNotFound, err)
}

func TestTenantAwareAdminService_GetTenantEAB_StorageError(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()
	factory := newMockTenantAwareStorageFactory()

	adminSvc := NewAdminService(nil, nil, logger, "1.0.0")
	adminSvc.storageFactory = &storageTenantAwareWrapper{factory: factory}

	service := &TenantAwareAdminService{
		AdminService: adminSvc,
		qrdbService:  qrdbSvc,
		logger:       logger,
		tenantCAs:    make(map[string]*tenantCAEntry),
	}

	// Inject get error for specific tenant
	dao, _ := factory.TenantExternalAccountBindingDAO("tenant-get-err")
	dao.getErr = errors.New("database read failed")

	_, err := service.GetTenantEAB(context.Background(), "tenant-get-err", "some-id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to retrieve EAB")
}

func TestTenantAwareAdminService_DeleteTenantEAB_Validation(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Empty tenant ID
	err := service.DeleteTenantEAB(context.Background(), "", "eab-123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant ID is required")

	// Empty KID
	err = service.DeleteTenantEAB(context.Background(), "tenant-123", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key ID is required")
}

func TestTenantAwareAdminService_DeleteTenantEAB_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()
	factory := newMockTenantAwareStorageFactory()

	adminSvc := NewAdminService(nil, nil, logger, "1.0.0")
	adminSvc.storageFactory = &storageTenantAwareWrapper{factory: factory}

	service := &TenantAwareAdminService{
		AdminService: adminSvc,
		qrdbService:  qrdbSvc,
		logger:       logger,
		tenantCAs:    make(map[string]*tenantCAEntry),
	}

	// Create an EAB first
	resp, err := service.CreateTenantEAB(context.Background(), "tenant-1", CreateEABRequest{
		Purpose: entities.EABPurposeAccountBinding,
	})
	require.NoError(t, err)

	// Delete it
	err = service.DeleteTenantEAB(context.Background(), "tenant-1", resp.ID)
	require.NoError(t, err)

	// Verify it's gone
	_, err = service.GetTenantEAB(context.Background(), "tenant-1", resp.ID)
	assert.Equal(t, ErrEABNotFound, err)
}

func TestTenantAwareAdminService_DeleteTenantEAB_NotFound(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()
	factory := newMockTenantAwareStorageFactory()

	adminSvc := NewAdminService(nil, nil, logger, "1.0.0")
	adminSvc.storageFactory = &storageTenantAwareWrapper{factory: factory}

	service := &TenantAwareAdminService{
		AdminService: adminSvc,
		qrdbService:  qrdbSvc,
		logger:       logger,
		tenantCAs:    make(map[string]*tenantCAEntry),
	}

	err := service.DeleteTenantEAB(context.Background(), "tenant-1", "nonexistent")
	assert.Equal(t, ErrEABNotFound, err)
}

func TestTenantAwareAdminService_DeleteTenantEAB_CrossTenantDenied(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()
	factory := newMockTenantAwareStorageFactory()

	adminSvc := NewAdminService(nil, nil, logger, "1.0.0")
	adminSvc.storageFactory = &storageTenantAwareWrapper{factory: factory}

	service := &TenantAwareAdminService{
		AdminService: adminSvc,
		qrdbService:  qrdbSvc,
		logger:       logger,
		tenantCAs:    make(map[string]*tenantCAEntry),
	}

	// Create EAB for tenant-1
	resp, err := service.CreateTenantEAB(context.Background(), "tenant-1", CreateEABRequest{
		Purpose: entities.EABPurposeAccountBinding,
	})
	require.NoError(t, err)

	// Try to delete it as tenant-2
	err = service.DeleteTenantEAB(context.Background(), "tenant-2", resp.ID)
	assert.Equal(t, ErrEABNotFound, err)
}

func TestTenantAwareAdminService_DeleteTenantEAB_StorageError(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()
	factory := newMockTenantAwareStorageFactory()

	adminSvc := NewAdminService(nil, nil, logger, "1.0.0")
	adminSvc.storageFactory = &storageTenantAwareWrapper{factory: factory}

	service := &TenantAwareAdminService{
		AdminService: adminSvc,
		qrdbService:  qrdbSvc,
		logger:       logger,
		tenantCAs:    make(map[string]*tenantCAEntry),
	}

	// Create EAB first
	resp, err := service.CreateTenantEAB(context.Background(), "tenant-del-err", CreateEABRequest{
		Purpose: entities.EABPurposeAccountBinding,
	})
	require.NoError(t, err)

	// Inject delete error
	dao, _ := factory.TenantExternalAccountBindingDAO("tenant-del-err")
	dao.deleteErr = errors.New("delete failed")

	err = service.DeleteTenantEAB(context.Background(), "tenant-del-err", resp.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete EAB")
}

func TestTenantAwareAdminService_ListTenantEABs_EmptyID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	_, _, err := service.ListTenantEABs(context.Background(), "", ListEABRequest{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant ID is required")
}

func TestTenantAwareAdminService_ListTenantEABs_NoStorageFactory(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Should error when no storage factory is available
	_, _, err := service.ListTenantEABs(context.Background(), "tenant-123", ListEABRequest{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "storage factory not available")
}

func TestTenantAwareAdminService_ListTenantEABs_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()
	factory := newMockTenantAwareStorageFactory()

	adminSvc := NewAdminService(nil, nil, logger, "1.0.0")
	adminSvc.storageFactory = &storageTenantAwareWrapper{factory: factory}

	service := &TenantAwareAdminService{
		AdminService: adminSvc,
		qrdbService:  qrdbSvc,
		logger:       logger,
		tenantCAs:    make(map[string]*tenantCAEntry),
	}

	// Create multiple EABs
	for i := 0; i < 3; i++ {
		_, err := service.CreateTenantEAB(context.Background(), "tenant-1", CreateEABRequest{
			Purpose: entities.EABPurposeAccountBinding,
		})
		require.NoError(t, err)
	}

	// List them
	list, pagination, err := service.ListTenantEABs(context.Background(), "tenant-1", ListEABRequest{})
	require.NoError(t, err)
	assert.Len(t, list, 3)
	assert.Equal(t, 3, pagination.Total)
}

func TestTenantAwareAdminService_ListTenantEABs_FilterByStatus(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()
	factory := newMockTenantAwareStorageFactory()

	adminSvc := NewAdminService(nil, nil, logger, "1.0.0")
	adminSvc.storageFactory = &storageTenantAwareWrapper{factory: factory}

	service := &TenantAwareAdminService{
		AdminService: adminSvc,
		qrdbService:  qrdbSvc,
		logger:       logger,
		tenantCAs:    make(map[string]*tenantCAEntry),
	}

	// Create EABs
	_, err := service.CreateTenantEAB(context.Background(), "tenant-1", CreateEABRequest{
		Purpose: entities.EABPurposeAccountBinding,
	})
	require.NoError(t, err)

	_, err = service.CreateTenantEAB(context.Background(), "tenant-1", CreateEABRequest{
		Purpose: entities.EABPurposeEndorse01,
	})
	require.NoError(t, err)

	// Filter by status
	list, _, err := service.ListTenantEABs(context.Background(), "tenant-1", ListEABRequest{
		Status: entities.EABStatusActive,
	})
	require.NoError(t, err)
	assert.Len(t, list, 2) // Both are active

	// Filter by purpose
	list, _, err = service.ListTenantEABs(context.Background(), "tenant-1", ListEABRequest{
		Purpose: entities.EABPurposeEndorse01,
	})
	require.NoError(t, err)
	assert.Len(t, list, 1)
}

func TestTenantAwareAdminService_ListTenantEABs_Pagination(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()
	factory := newMockTenantAwareStorageFactory()

	adminSvc := NewAdminService(nil, nil, logger, "1.0.0")
	adminSvc.storageFactory = &storageTenantAwareWrapper{factory: factory}

	service := &TenantAwareAdminService{
		AdminService: adminSvc,
		qrdbService:  qrdbSvc,
		logger:       logger,
		tenantCAs:    make(map[string]*tenantCAEntry),
	}

	// Create 5 EABs
	for i := 0; i < 5; i++ {
		_, err := service.CreateTenantEAB(context.Background(), "tenant-1", CreateEABRequest{
			Purpose: entities.EABPurposeAccountBinding,
		})
		require.NoError(t, err)
	}

	// List with pagination
	list, pagination, err := service.ListTenantEABs(context.Background(), "tenant-1", ListEABRequest{
		Page:    1,
		PerPage: 2,
	})
	require.NoError(t, err)
	assert.Len(t, list, 2)
	assert.Equal(t, 5, pagination.Total)
	assert.Equal(t, 1, pagination.Page)
	assert.Equal(t, 2, pagination.PerPage)

	// Second page
	list, _, err = service.ListTenantEABs(context.Background(), "tenant-1", ListEABRequest{
		Page:    2,
		PerPage: 2,
	})
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestTenantAwareAdminService_ListTenantEABs_StorageError(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()
	factory := newMockTenantAwareStorageFactory()

	adminSvc := NewAdminService(nil, nil, logger, "1.0.0")
	adminSvc.storageFactory = &storageTenantAwareWrapper{factory: factory}

	service := &TenantAwareAdminService{
		AdminService: adminSvc,
		qrdbService:  qrdbSvc,
		logger:       logger,
		tenantCAs:    make(map[string]*tenantCAEntry),
	}

	// Inject list error
	dao, _ := factory.TenantExternalAccountBindingDAO("tenant-list-err")
	dao.listErr = errors.New("list operation failed")

	_, _, err := service.ListTenantEABs(context.Background(), "tenant-list-err", ListEABRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list EABs")
}

func TestTenantAwareAdminService_ImplementsInterface(t *testing.T) {
	// Verify TenantAwareAdminService implements TenantAwareService
	var _ TenantAwareService = (*TenantAwareAdminService)(nil)
}

// ============================================================================
// Request/Response Type Tests
// ============================================================================

func TestCreateTenantRequest_Fields(t *testing.T) {
	req := CreateTenantRequest{
		ID:   "tenant-123",
		Name: "Test Tenant",
	}

	assert.Equal(t, "tenant-123", req.ID)
	assert.Equal(t, "Test Tenant", req.Name)
}

func TestUpdateTenantRequest_Fields(t *testing.T) {
	settings := &TenantSettingsInfo{
		MaxCertificates: 100,
	}

	req := UpdateTenantRequest{
		Name:     "Updated Tenant",
		Settings: settings,
	}

	assert.Equal(t, "Updated Tenant", req.Name)
	assert.Equal(t, 100, req.Settings.MaxCertificates)
}

func TestTenantInfo_Fields(t *testing.T) {
	now := time.Now()

	info := &TenantInfo{
		ID:        "tenant-123",
		Name:      "Test Tenant",
		Status:    "active",
		Settings:  &TenantSettingsInfo{},
		CreatedAt: now,
		UpdatedAt: now,
	}

	assert.Equal(t, "tenant-123", info.ID)
	assert.Equal(t, "Test Tenant", info.Name)
	assert.Equal(t, "active", info.Status)
	assert.NotNil(t, info.Settings)
	assert.Equal(t, now, info.CreatedAt)
	assert.Equal(t, now, info.UpdatedAt)
}

func TestTenantAwareAdminService_CreateTenantIntermediateCA_Purpose(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	// Create root
	_, err := service.CreateTenantRootCA(context.Background(), "tenant-purpose", CreateTenantRootCARequest{
		CommonName:   "Test Root CA",
		KeyAlgorithm: "RSA",
	})
	require.NoError(t, err)

	// Create intermediate with purpose
	intCA, err := service.CreateTenantIntermediateCA(context.Background(), "tenant-purpose", CreateTenantIntermediateCARequest{
		CommonName:   "Server Auth Int CA",
		ParentType:   "tenant",
		KeyAlgorithm: "RSA",
		Purpose:      "server-auth",
	})
	require.NoError(t, err)
	assert.Contains(t, intCA.ID, "server-auth")
	assert.Equal(t, "server-auth", intCA.Purpose)
}

// ============================================================================
// Additional Coverage Tests
// ============================================================================

func TestTenantAwareAdminService_ListTenants_WithTenantDAO(t *testing.T) {
	service := newTenantAwareTestService(t)
	ctx := context.Background()

	// Create multiple tenants
	for i := 0; i < 5; i++ {
		_, err := service.CreateTenant(ctx, CreateTenantRequest{
			ID:   fmt.Sprintf("list-tenant-%d", i),
			Name: fmt.Sprintf("Tenant %d", i),
		})
		require.NoError(t, err)
	}

	// List all tenants
	tenants, pagination, err := service.ListTenants(ctx, ListTenantsRequest{
		Page:    1,
		PerPage: 10,
	})
	require.NoError(t, err)
	assert.Equal(t, 5, len(tenants))
	assert.Equal(t, 5, pagination.Total)
	assert.Equal(t, 1, pagination.Page)
	assert.Equal(t, 10, pagination.PerPage)
}

func TestTenantAwareAdminService_ListTenants_WithStatusFilter(t *testing.T) {
	service := newTenantAwareTestService(t)
	ctx := context.Background()

	// Create tenants
	for i := 0; i < 3; i++ {
		_, err := service.CreateTenant(ctx, CreateTenantRequest{
			ID:   fmt.Sprintf("status-filter-%d", i),
			Name: fmt.Sprintf("Tenant %d", i),
		})
		require.NoError(t, err)
	}

	// Suspend one tenant
	err := service.UpdateTenantStatus(ctx, "status-filter-1", entities.TenantStatusSuspended)
	require.NoError(t, err)

	// List only active tenants
	tenants, pagination, err := service.ListTenants(ctx, ListTenantsRequest{
		Page:    1,
		PerPage: 10,
		Status:  entities.TenantStatusActive,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, len(tenants))
	assert.Equal(t, 2, pagination.Total)

	// Verify all returned tenants are active
	for _, tenant := range tenants {
		assert.Equal(t, entities.TenantStatusActive, tenant.Status)
	}

	// List suspended tenants
	tenants, pagination, err = service.ListTenants(ctx, ListTenantsRequest{
		Page:    1,
		PerPage: 10,
		Status:  entities.TenantStatusSuspended,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, len(tenants))
	assert.Equal(t, 1, pagination.Total)
	assert.Equal(t, "status-filter-1", tenants[0].ID)
}

func TestTenantAwareAdminService_ListTenants_EmptyResult(t *testing.T) {
	service := newTenantAwareTestService(t)
	ctx := context.Background()

	// List when no tenants exist
	tenants, pagination, err := service.ListTenants(ctx, ListTenantsRequest{
		Page:    1,
		PerPage: 10,
	})
	require.NoError(t, err)
	assert.Equal(t, 0, len(tenants))
	assert.Equal(t, 0, pagination.Total)
}

func TestTenantAwareAdminService_ListTenants_Pagination(t *testing.T) {
	service := newTenantAwareTestService(t)
	ctx := context.Background()

	// Create 5 tenants
	for i := 0; i < 5; i++ {
		_, err := service.CreateTenant(ctx, CreateTenantRequest{
			ID:   fmt.Sprintf("page-tenant-%d", i),
			Name: fmt.Sprintf("Page Tenant %d", i),
		})
		require.NoError(t, err)
	}

	// Get first page of 2
	tenants, pagination, err := service.ListTenants(ctx, ListTenantsRequest{
		Page:    1,
		PerPage: 2,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, len(tenants))
	assert.Equal(t, 5, pagination.Total)

	// Get second page
	tenants, pagination, err = service.ListTenants(ctx, ListTenantsRequest{
		Page:    2,
		PerPage: 2,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, len(tenants))
	assert.Equal(t, 5, pagination.Total)

	// Get third page (only 1 remaining)
	tenants, pagination, err = service.ListTenants(ctx, ListTenantsRequest{
		Page:    3,
		PerPage: 2,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, len(tenants))
	assert.Equal(t, 5, pagination.Total)

	// Get page beyond total
	tenants, _, err = service.ListTenants(ctx, ListTenantsRequest{
		Page:    10,
		PerPage: 2,
	})
	require.NoError(t, err)
	assert.Equal(t, 0, len(tenants))
}

func TestTenantAwareAdminService_GetTenant_DeletedTenantReturnsNotFound(t *testing.T) {
	service := newTenantAwareTestService(t)
	ctx := context.Background()

	// Create and then soft-delete a tenant via status update
	_, err := service.CreateTenant(ctx, CreateTenantRequest{
		ID:   "tenant-soft-deleted",
		Name: "Soft Deleted",
	})
	require.NoError(t, err)

	// Set status to deleted
	err = service.UpdateTenantStatus(ctx, "tenant-soft-deleted", entities.TenantStatusDeleted)
	require.NoError(t, err)

	// GetTenant should return ErrTenantNotFound for deleted tenants
	_, err = service.GetTenant(ctx, "tenant-soft-deleted")
	assert.Equal(t, ErrTenantNotFound, err)
}

func TestTenantAwareAdminService_GetTenant_SuccessWithDAO(t *testing.T) {
	service := newTenantAwareTestService(t)
	ctx := context.Background()

	_, err := service.CreateTenant(ctx, CreateTenantRequest{
		ID:   "tenant-dao-get",
		Name: "DAO Get Tenant",
	})
	require.NoError(t, err)

	tenant, err := service.GetTenant(ctx, "tenant-dao-get")
	require.NoError(t, err)
	assert.Equal(t, "tenant-dao-get", tenant.ID)
	assert.Equal(t, "DAO Get Tenant", tenant.Name)
	assert.Equal(t, entities.TenantStatusActive, tenant.Status)
}

func TestTenantAwareAdminService_DeleteTenant_SuccessWithDAO(t *testing.T) {
	service := newTenantAwareTestService(t)
	ctx := context.Background()

	// Create tenant
	_, err := service.CreateTenant(ctx, CreateTenantRequest{
		ID:   "tenant-dao-delete",
		Name: "DAO Delete Tenant",
	})
	require.NoError(t, err)

	// Verify it exists
	tenant, err := service.GetTenant(ctx, "tenant-dao-delete")
	require.NoError(t, err)
	assert.Equal(t, "tenant-dao-delete", tenant.ID)

	// Delete tenant
	err = service.DeleteTenant(ctx, "tenant-dao-delete")
	require.NoError(t, err)

	// Should no longer be found
	_, err = service.GetTenant(ctx, "tenant-dao-delete")
	assert.Equal(t, ErrTenantNotFound, err)
}

func TestTenantAwareAdminService_DeleteTenant_NotFoundWithDAO(t *testing.T) {
	service := newTenantAwareTestService(t)
	ctx := context.Background()

	err := service.DeleteTenant(ctx, "nonexistent-dao-tenant")
	require.Error(t, err)
	assert.Equal(t, ErrTenantNotFound, err)
}

func TestTenantAwareAdminService_UpdateTenantStatus_SuccessWithDAO(t *testing.T) {
	service := newTenantAwareTestService(t)
	ctx := context.Background()

	// Create tenant
	_, err := service.CreateTenant(ctx, CreateTenantRequest{
		ID:   "tenant-status-update",
		Name: "Status Update Tenant",
	})
	require.NoError(t, err)

	// Update to suspended
	err = service.UpdateTenantStatus(ctx, "tenant-status-update", entities.TenantStatusSuspended)
	require.NoError(t, err)

	// Verify status changed
	tenant, err := service.GetTenant(ctx, "tenant-status-update")
	require.NoError(t, err)
	assert.Equal(t, entities.TenantStatusSuspended, tenant.Status)

	// Update back to active
	err = service.UpdateTenantStatus(ctx, "tenant-status-update", entities.TenantStatusActive)
	require.NoError(t, err)

	tenant, err = service.GetTenant(ctx, "tenant-status-update")
	require.NoError(t, err)
	assert.Equal(t, entities.TenantStatusActive, tenant.Status)
}

func TestTenantAwareAdminService_UpdateTenantStatus_NotFoundWithDAO(t *testing.T) {
	service := newTenantAwareTestService(t)
	ctx := context.Background()

	err := service.UpdateTenantStatus(ctx, "nonexistent-for-status", entities.TenantStatusActive)
	require.Error(t, err)
	assert.Equal(t, ErrTenantNotFound, err)
}

func TestTenantAwareAdminService_GetTenantEABDAO_NoStorageFactory(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	// Create service with nil storage factory
	service := NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "1.0.0")

	_, err := service.getTenantEABDAO("tenant-123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage factory not available")
}

func TestTenantAwareAdminService_GetTenantEABDAO_WithTenantAwareFactory(t *testing.T) {
	service := newTenantAwareTestService(t)

	dao, err := service.getTenantEABDAO("tenant-123")
	require.NoError(t, err)
	require.NotNil(t, dao)
}

func TestTenantAwareAdminService_GetTenantEABDAO_FallbackToGlobal(t *testing.T) {
	// Use a non-tenant-aware factory (NewFactoryFromKVStore returns storage.Factory, not TenantAwareFactory)
	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	require.NoError(t, err)

	factory, err := acmeobjstore.NewFactoryFromKVStore(kv)
	require.NoError(t, err)

	logger := slog.Default()
	qrdbSvc := newTestQRDB()

	service := NewTenantAwareAdminService(nil, factory, qrdbSvc, logger, "1.0.0")

	// This should hit the fallback path (non-tenant-aware factory)
	dao, err := service.getTenantEABDAO("any-tenant")
	require.NoError(t, err)
	require.NotNil(t, dao)
}

func TestTenantAwareAdminService_DeleteTenant_WithRBACAndKVCleanup(t *testing.T) {
	service := newTenantAwareTestService(t)
	ctx := context.Background()

	// Create tenant (which also creates default RBAC roles)
	_, err := service.CreateTenant(ctx, CreateTenantRequest{
		ID:   "tenant-full-delete",
		Name: "Full Delete Tenant",
	})
	require.NoError(t, err)

	// Store some CA data in KV to exercise KV cleanup
	if service.qrdbService != nil && service.qrdbService.KV() != nil {
		err = service.qrdbService.KV().Put(ctx, "tenants/tenant-full-delete/cas/root", []byte("root-ca-data"))
		require.NoError(t, err)
		err = service.qrdbService.KV().Put(ctx, "tenants/tenant-full-delete/cas/intermediate", []byte("int-ca-data"))
		require.NoError(t, err)
		err = service.qrdbService.KV().Put(ctx, "tenants/tenant-full-delete/default_intermediate_ca", []byte("int-ca-id"))
		require.NoError(t, err)
	}

	// Add a tenant CA entry to the in-memory cache
	service.mu.Lock()
	service.tenantCAs["tenant-full-delete"] = &tenantCAEntry{}
	service.mu.Unlock()

	// Delete tenant
	err = service.DeleteTenant(ctx, "tenant-full-delete")
	require.NoError(t, err)

	// Verify tenant CA cache is cleaned up
	service.mu.RLock()
	_, exists := service.tenantCAs["tenant-full-delete"]
	service.mu.RUnlock()
	assert.False(t, exists)

	// Verify KV data is cleaned up
	if service.qrdbService != nil && service.qrdbService.KV() != nil {
		val, err := service.qrdbService.KV().Get(ctx, "tenants/tenant-full-delete/default_intermediate_ca")
		// Should be deleted (either error or empty)
		if err == nil {
			assert.Empty(t, val)
		}
	}

	// Verify tenant is no longer found
	_, err = service.GetTenant(ctx, "tenant-full-delete")
	assert.Equal(t, ErrTenantNotFound, err)
}

func TestTenantAwareAdminService_UpdateTenantStatus_AllTransitions(t *testing.T) {
	service := newTenantAwareTestService(t)
	ctx := context.Background()

	// Create tenant
	_, err := service.CreateTenant(ctx, CreateTenantRequest{
		ID:   "tenant-transitions",
		Name: "Transition Tenant",
	})
	require.NoError(t, err)

	// active -> suspended
	err = service.UpdateTenantStatus(ctx, "tenant-transitions", entities.TenantStatusSuspended)
	require.NoError(t, err)
	tenant, err := service.GetTenant(ctx, "tenant-transitions")
	require.NoError(t, err)
	assert.Equal(t, entities.TenantStatusSuspended, tenant.Status)

	// suspended -> active
	err = service.UpdateTenantStatus(ctx, "tenant-transitions", entities.TenantStatusActive)
	require.NoError(t, err)
	tenant, err = service.GetTenant(ctx, "tenant-transitions")
	require.NoError(t, err)
	assert.Equal(t, entities.TenantStatusActive, tenant.Status)

	// active -> deleted
	err = service.UpdateTenantStatus(ctx, "tenant-transitions", entities.TenantStatusDeleted)
	require.NoError(t, err)
	// deleted tenant should not be found
	_, err = service.GetTenant(ctx, "tenant-transitions")
	assert.Equal(t, ErrTenantNotFound, err)
}

func TestTenantAwareAdminService_UpdateIntermediateCAStatus_WithTenantDAO(t *testing.T) {
	service := newTenantAwareTestService(t)
	ctx := context.Background()

	// Create tenant
	_, err := service.CreateTenant(ctx, CreateTenantRequest{
		ID:   "tenant-intca-status",
		Name: "IntCA Status Tenant",
	})
	require.NoError(t, err)

	// Create root CA
	_, err = service.CreateTenantRootCA(ctx, "tenant-intca-status", CreateTenantRootCARequest{
		CommonName:   "Test Root CA",
		KeyAlgorithm: "ECDSA",
	})
	require.NoError(t, err)

	// Create intermediate CA
	intCA, err := service.CreateTenantIntermediateCA(ctx, "tenant-intca-status", CreateTenantIntermediateCARequest{
		CommonName:   "Test Int CA",
		ParentType:   "tenant",
		KeyAlgorithm: "ECDSA",
	})
	require.NoError(t, err)

	// Suspend the intermediate CA (exercises the tenantDAO update path)
	err = service.UpdateTenantIntermediateCAStatus(ctx, "tenant-intca-status", intCA.ID, "suspended")
	require.NoError(t, err)

	// Verify the operation completed without error and the tenant entity was updated
	tenant, err := service.GetTenant(ctx, "tenant-intca-status")
	require.NoError(t, err)
	assert.Equal(t, "tenant-intca-status", tenant.ID)
}

func TestTenantAwareAdminService_SetDefaultIntermediateCA_WithTenantDAO(t *testing.T) {
	service := newTenantAwareTestService(t)
	ctx := context.Background()

	// Create tenant
	_, err := service.CreateTenant(ctx, CreateTenantRequest{
		ID:   "tenant-default-intca",
		Name: "Default IntCA Tenant",
	})
	require.NoError(t, err)

	// Create root CA
	_, err = service.CreateTenantRootCA(ctx, "tenant-default-intca", CreateTenantRootCARequest{
		CommonName:   "Test Root CA",
		KeyAlgorithm: "ECDSA",
	})
	require.NoError(t, err)

	// Create two intermediate CAs
	intCA1, err := service.CreateTenantIntermediateCA(ctx, "tenant-default-intca", CreateTenantIntermediateCARequest{
		CommonName:   "Int CA 1",
		ParentType:   "tenant",
		KeyAlgorithm: "ECDSA",
	})
	require.NoError(t, err)

	intCA2, err := service.CreateTenantIntermediateCA(ctx, "tenant-default-intca", CreateTenantIntermediateCARequest{
		CommonName:   "Int CA 2",
		ParentType:   "tenant",
		KeyAlgorithm: "ECDSA",
	})
	require.NoError(t, err)

	// Set default to second CA (exercises the tenantDAO update path)
	err = service.SetTenantDefaultIntermediateCA(ctx, "tenant-default-intca", intCA2.ID)
	require.NoError(t, err)

	// Verify default is set by getting signing CA
	_, cert, err := service.GetTenantSigningCA(ctx, "tenant-default-intca")
	require.NoError(t, err)
	assert.Equal(t, "Int CA 2", cert.Subject.CommonName)

	// Change default to first CA
	err = service.SetTenantDefaultIntermediateCA(ctx, "tenant-default-intca", intCA1.ID)
	require.NoError(t, err)

	_, cert, err = service.GetTenantSigningCA(ctx, "tenant-default-intca")
	require.NoError(t, err)
	assert.Equal(t, "Int CA 1", cert.Subject.CommonName)
}
