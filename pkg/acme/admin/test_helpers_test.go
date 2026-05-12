//go:build codec_json

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
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-objstore/pkg/local"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/auth"
	"github.com/jeremyhahn/go-xkms/pkg/acme/qrdb"
	acmestorage "github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	acmeobjstore "github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// createAdminUser creates an AuthenticatedUser with admin role for testing
func createAdminUser(tenantID string) *AuthenticatedUser {
	return &AuthenticatedUser{
		UserID:   "admin-user-1",
		Username: "admin",
		Email:    "admin@example.com",
		Role:     RoleAdmin,
		TenantID: tenantID,
		Roles:    []string{string(RoleAdmin)},
		Groups:   []string{"admins"},
	}
}

// createSuperAdminUser creates an AuthenticatedUser with super-admin role for testing
func createSuperAdminUser() *AuthenticatedUser {
	return &AuthenticatedUser{
		UserID:   "super-admin-user-1",
		Username: "platformadmin",
		Email:    "platformadmin@example.com",
		Role:     RoleSuperAdmin,
		TenantID: "", // Super-admins have no tenant restriction
		Roles:    []string{string(RoleSuperAdmin)},
		Groups:   []string{"super-admins"},
	}
}

// addUserToRequest adds an authenticated user to the request context
func addUserToRequest(r *http.Request, user *AuthenticatedUser) *http.Request {
	ctx := context.WithValue(r.Context(), ContextKeyUser, user)
	return r.WithContext(ctx)
}

// extractTenantIDFromResource extracts the tenant ID from a resource path.
// Resource paths follow the pattern: acme/tenants/{tenant_id}/...
// This is used in tests for verifying tenant access.
func extractTenantIDFromResource(resource string) string {
	parts := strings.Split(resource, "/")
	for i, part := range parts {
		if part == "tenants" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// newTestAuthMiddleware creates an AuthMiddleware for testing with a user of the given role
func newTestAuthMiddleware(role Role) *AuthMiddleware {
	client := auth.NewMemoryClient()
	claims := &auth.TokenClaims{
		Valid:    true,
		UserID:   "test-user",
		Username: "testuser",
		TenantID: "test-tenant",
		Roles:    []string{string(role)},
	}
	// Register both generic "test-key" and role-specific token keys for compatibility
	client.AddToken("test-key", claims)
	// Create token key based on role: test-viewer-key, test-admin-key, test-super-admin-key
	tokenKey := "test-" + strings.ToLower(strings.ReplaceAll(string(role), "_", "-")) + "-key"
	client.AddToken(tokenKey, claims)
	return NewAuthMiddleware(client)
}

// newTestAuthMiddlewareInvalid creates an AuthMiddleware with no valid tokens for testing
func newTestAuthMiddlewareInvalid() *AuthMiddleware {
	client := auth.NewMemoryClient()
	return NewAuthMiddleware(client)
}

// createTestInfrastructure creates a test CA and storage factory for testing
func createTestInfrastructure(t *testing.T) (ca.TCGCA, acmestorage.Factory, func()) {
	// Reset xkms from any previous tests
	xkmssdk.ServiceReset()

	// Create temporary directories
	tmpDir := t.TempDir()
	caDir := tmpDir + "/ca"
	storageDir := tmpDir + "/storage"

	// Create CA storage backends
	keyStorageBackend, err := xkmssdk.NewFileStorageBackend(caDir + "/keys")
	require.NoError(t, err)

	certStorageBackend, err := xkmssdk.NewFileStorageBackend(caDir + "/certs")
	require.NoError(t, err)

	// Create software backend for key operations
	softwareBackend, err := xkmssdk.NewPKCS8Backend(&xkmssdk.PKCS8BackendConfig{
		KeyStorage: keyStorageBackend,
	})
	require.NoError(t, err)

	// Create xkms (keystore) with software backend and cert storage
	keyStore, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
		Backend:     softwareBackend,
		CertStorage: certStorageBackend,
	})
	require.NoError(t, err)

	// Initialize the XKMSService with the software backend as default
	err = xkmssdk.ServiceInitialize(&xkmssdk.ServiceConfig{
		Backends: map[string]xkmssdk.ServiceBackend{
			"software": keyStore,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	certAdapter := xkmssdk.NewStorageCertAdapter(certStorageBackend)
	certStore, err := xkmssdk.NewCertStore(&xkmssdk.CertStoreConfig{
		CertStorage: certAdapter,
	})
	require.NoError(t, err)

	blobStorage := local.New()
	err = blobStorage.Configure(map[string]string{"path": caDir + "/blobs"})
	require.NoError(t, err)

	// Build a native multi-identity (root + intermediate) CA configuration with
	// algorithm agility: each identity carries ECDSA, RSA, and Ed25519 key
	// configurations. The first KeyConfig (ECDSA) is the active signing key;
	// the remaining entries are advertised via IssuingIdentity() so callers
	// can issue with alternate algorithms.
	multiKeys := []*types.KeyConfig{
		{
			KeyAlgorithm:       types.AlgorithmECDSA,
			Hash:               types.HashSHA256,
			SignatureAlgorithm: types.SigECDSAWithSHA256,
			StoreType:          types.StoreSoftware,
			ECCConfig:          &types.ECCConfig{Curve: types.CurveP256},
		},
		{
			KeyAlgorithm:       types.AlgorithmRSA,
			Hash:               types.HashSHA256,
			SignatureAlgorithm: types.SigSHA256WithRSA,
			StoreType:          types.StoreSoftware,
			RSAConfig:          &types.RSAConfig{KeySize: 2048},
		},
		{
			KeyAlgorithm:       types.AlgorithmEd25519,
			Hash:               types.HashSHA256,
			SignatureAlgorithm: types.SigEd25519,
			StoreType:          types.StoreSoftware,
		},
	}

	multiConfig := ca.DefaultMultiIdentityCAConfigWithIntermediate()
	multiConfig.HomeDir = caDir
	multiConfig.Identity[0].Subject.CommonName = "Test Root CA"
	multiConfig.Identity[0].Subject.Organization = "Test Org"
	multiConfig.Identity[0].Keys = multiKeys
	multiConfig.Identity[1].Subject.CommonName = "Test Intermediate CA"
	multiConfig.Identity[1].Subject.Organization = "Test Org"
	multiConfig.Identity[1].Keys = multiKeys

	_, intermediate, err := ca.NewCA(&ca.Params{
		Identity:    multiConfig.Identity,
		Config:      &ca.CAConfig{DefaultCertValidityDays: multiConfig.GetDefaultValidityDays()},
		KeyStore:    keyStore,
		CertStore:   certStore,
		ObjectStore: blobStorage,
	})
	require.NoError(t, err)
	testCA, ok := intermediate.(ca.TCGCA)
	require.True(t, ok, "intermediate CA must implement TCGCA")

	// Create ACME storage
	acmeStorage := local.New()
	err = acmeStorage.Configure(map[string]string{"path": storageDir})
	require.NoError(t, err)

	storageFactory, err := acmeobjstore.NewFactory(acmeStorage)
	require.NoError(t, err)

	cleanup := func() {
		_ = xkmssdk.ServiceClose()
		_ = os.RemoveAll(tmpDir)
	}

	return testCA, storageFactory, cleanup
}

// newTenantAwareTestService creates a TenantAwareAdminService backed by an
// in-memory objstore TenantAwareFactory. This provides a real tenantDAO for
// tests that need to create, get, update, or delete tenants.
func newTenantAwareTestService(t *testing.T) *TenantAwareAdminService {
	t.Helper()

	storageDir := t.TempDir()
	store := local.New()
	err := store.Configure(map[string]string{"path": storageDir})
	require.NoError(t, err)

	factory, err := acmeobjstore.NewTenantAwareFactory(store)
	require.NoError(t, err)

	logger := slog.Default()
	qrdbSvc := qrdb.NewTestService()

	return NewTenantAwareAdminService(nil, factory, qrdbSvc, logger, "1.0.0")
}
