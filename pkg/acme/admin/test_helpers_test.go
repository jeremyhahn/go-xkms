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
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-objstore/pkg/local"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/auth"
	"github.com/jeremyhahn/go-xkms/pkg/acme/qrdb"
	acmestorage "github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	acmeobjstore "github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// createAdminUser creates a tenant-scoped AuthenticatedUser holding qrdb's
// canonical admin role.
func createAdminUser(tenantID string) *AuthenticatedUser {
	return &AuthenticatedUser{
		UserID:   "admin-user-1",
		Username: "admin",
		Email:    "admin@example.com",
		TenantID: tenantID,
		Roles:    []string{qrdbsdk.RoleNameAdmin},
		Groups:   []string{"admins"},
	}
}

// createPlatformAdminUser creates an AuthenticatedUser rooted in the reserved
// system tenant. Under qrdb's system-tenant rule this is the platform-scoped
// principal that reaches every tenant — the authority the deleted local
// "super-admin" role used to express.
func createPlatformAdminUser() *AuthenticatedUser {
	return &AuthenticatedUser{
		UserID:   "platform-admin-1",
		Username: "platformadmin",
		Email:    "platformadmin@example.com",
		TenantID: "", // normalized to the system tenant by the Authorizer
		Roles:    []string{qrdbsdk.RoleNameAdmin},
		Groups:   []string{"platform-admins"},
	}
}

// addUserToRequest publishes the authenticated user and its canonical
// auth.Identity on the request context, exactly as the auth middleware does.
func addUserToRequest(r *http.Request, user *AuthenticatedUser) *http.Request {
	return r.WithContext(withUser(r.Context(), user))
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
func newTestAuthMiddleware(role string) *AuthMiddleware {
	client := auth.NewMemoryClient()
	claims := &auth.TokenClaims{
		Valid:    true,
		UserID:   "test-user",
		Username: "testuser",
		TenantID: "test-tenant",
		Roles:    []string{role},
	}
	// Register the generic "test-key", the role-specific key, and the legacy
	// role-named keys the handler tests use. The legacy names ("viewer",
	// "super-admin", "endorser") no longer name roles — they are token labels
	// only — so they are registered alongside the canonical ones.
	client.AddToken("test-key", claims)
	for _, label := range []string{role, "viewer", "super-admin", "endorser", "admin", "operator", "auditor", "so"} {
		client.AddToken("test-"+strings.ToLower(strings.ReplaceAll(label, "_", "-"))+"-key", claims)
	}
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

	// Create CA storage backends
	keyStorageBackend, err := xkmssdk.NewFileStorageBackend(caDir + "/keys")
	require.NoError(t, err)

	certStorageBackend, err := xkmssdk.NewFileStorageBackend(caDir + "/certs")
	require.NoError(t, err)

	// Create software backend for key operations. The software backend wraps
	// pkcs8 with AllowPlaintextKeys: true, which is the documented contract for
	// non-CA / passwordless test material; the raw pkcs8 backend would reject
	// the test CA's password-less root key.
	softwareBackend, err := xkmssdk.NewSoftwareBackend(&xkmssdk.SoftwareBackendConfig{
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

	_, intermediate, err := ca.NewCA(context.Background(), &ca.Params{
		Identity:    multiConfig.Identity,
		Config:      &ca.CAConfig{DefaultCertValidityDays: multiConfig.GetDefaultValidityDays()},
		KeyStore:    keyStore,
		CertStore:   certStore,
		ObjectStore: blobStorage,
	})
	require.NoError(t, err)
	testCA, ok := intermediate.(ca.TCGCA)
	require.True(t, ok, "intermediate CA must implement TCGCA")

	// Create ACME storage over the kvadapter datastore path.
	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	require.NoError(t, err)

	storageFactory, err := acmeobjstore.NewFactoryFromKVStore(kv)
	require.NoError(t, err)

	cleanup := func() {
		_ = xkmssdk.ServiceClose()
		_ = os.RemoveAll(tmpDir)
	}

	return testCA, storageFactory, cleanup
}

// newTenantAwareTestService creates a TenantAwareAdminService backed by an
// in-memory TenantAwareFactory over the kvadapter datastore path, with an
// in-memory fake qrdb TenantServicer wired via SetTenantService. qrdb is the
// single tenant identity authority, so every test that exercises
// CreateTenant/GetTenant/UpdateTenant/DeleteTenant/ListTenants needs one
// wired; the tenantDAO remains available for the CA/EAB/status linkage row.
func newTenantAwareTestService(t *testing.T) *TenantAwareAdminService {
	t.Helper()

	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	require.NoError(t, err)

	factory, err := acmeobjstore.NewTenantAwareFactoryFromKVStore(kv)
	require.NoError(t, err)

	logger := slog.Default()
	qrdbSvc := qrdb.NewTestService()

	svc := NewTenantAwareAdminService(nil, factory, qrdbSvc, logger, "1.0.0")
	svc.SetTenantService(newFakeTenantServicer())
	return svc
}
