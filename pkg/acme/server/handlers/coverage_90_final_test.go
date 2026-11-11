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

package handlers

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/kms"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock implementations for 90% coverage target
// =============================================================================

type mockTenantAwareFactory90 struct {
	storage.Factory
	tenantDAO    qrdbsdk.GenericDAO[*entities.Tenant]
	tenantDAOErr error
}

func (m *mockTenantAwareFactory90) TenantDAO() (qrdbsdk.GenericDAO[*entities.Tenant], error) {
	if m.tenantDAOErr != nil {
		return nil, m.tenantDAOErr
	}
	return m.tenantDAO, nil
}

func (m *mockTenantAwareFactory90) ForTenant(tenantID string) (storage.Factory, error) {
	return m, nil
}

func (m *mockTenantAwareFactory90) GetTenantID() string {
	return ""
}

func (m *mockTenantAwareFactory90) TenantAccountDAO(tenantID string) (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	return m.AccountDAO()
}

func (m *mockTenantAwareFactory90) TenantOrderDAO(tenantID string, accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	return m.OrderDAO(accountID)
}

func (m *mockTenantAwareFactory90) TenantAuthorizationDAO(tenantID string, accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return m.AuthorizationDAO(accountID)
}

func (m *mockTenantAwareFactory90) TenantChallengeDAO(tenantID string, accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return m.ChallengeDAO(accountID)
}

func (m *mockTenantAwareFactory90) TenantCertificateDAO(tenantID string) (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return m.CertificateDAO()
}

func (m *mockTenantAwareFactory90) TenantExternalAccountBindingDAO(tenantID string) (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return m.ExternalAccountBindingDAO()
}

type mockKMSService90 struct {
	signers      map[string]crypto.Signer
	getSignerErr error
	certificates map[string][]byte
}

func (m *mockKMSService90) CreateSigningKey(ctx context.Context, tenantID string, purpose kms.KeyPurpose, algorithm string) (*kms.KeyMetadata, error) {
	return &kms.KeyMetadata{KeyID: tenantID + "-" + string(purpose)}, nil
}

func (m *mockKMSService90) GetSigningKey(ctx context.Context, tenantID string, purpose kms.KeyPurpose) (crypto.Signer, error) {
	if m.getSignerErr != nil {
		return nil, m.getSignerErr
	}
	key := tenantID + "-" + string(purpose)
	if signer, ok := m.signers[key]; ok {
		return signer, nil
	}
	return nil, errors.New("key not found")
}

func (m *mockKMSService90) ListSigningKeys(ctx context.Context, tenantID string) ([]*kms.KeyMetadata, error) {
	return nil, nil
}

func (m *mockKMSService90) DeleteSigningKey(ctx context.Context, tenantID string, keyID string) error {
	return nil
}

func (m *mockKMSService90) EnableSigningKey(ctx context.Context, tenantID string, keyID string) error {
	return nil
}

func (m *mockKMSService90) DisableSigningKey(ctx context.Context, tenantID string, keyID string) error {
	return nil
}

func (m *mockKMSService90) StoreCertificate(ctx context.Context, tenantID string, purpose kms.KeyPurpose, certDER []byte) error {
	return nil
}

func (m *mockKMSService90) GetCertificate(ctx context.Context, tenantID string, purpose kms.KeyPurpose) ([]byte, error) {
	if m.certificates == nil {
		return nil, errors.New("not found")
	}
	key := tenantID + "-" + string(purpose)
	if cert, ok := m.certificates[key]; ok {
		return cert, nil
	}
	return nil, errors.New("not found")
}

func (m *mockKMSService90) DeleteCertificate(ctx context.Context, tenantID string, purpose kms.KeyPurpose) error {
	return nil
}

// mockOCSPResponder90 is a simple OCSP responder for testing
type mockOCSPResponder90 struct {
	response []byte
	err      error
}

func (m *mockOCSPResponder90) HandleRequest(_ context.Context, requestBytes []byte) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.response, nil
}

// =============================================================================
// Setup helper
// =============================================================================

func setupTestService90(t *testing.T) (*RestService, string, func()) {
	tmpDir, err := os.MkdirTemp("", "acme-handler-coverage90-*")
	require.NoError(t, err)

	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	require.NoError(t, err)

	factory, err := objstore.NewFactoryFromKVStore(kv)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	params := &Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		CAAIdentities:  []string{"acme.test.example.com"},
		ChallengeMap:   make(map[string]common.ChallengeVerifierFunc),
		Logger:         logger,
		StorageFactory: factory,
		TermsOfService: "https://acme.test.example.com/tos",
	}

	service, err := NewRestService(params)
	require.NoError(t, err)

	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	return service.(*RestService), tmpDir, cleanup
}

// =============================================================================
// NewAccountHandler coverage tests - targeting 60.6% -> 90%+
// =============================================================================

func TestNewAccountHandler_EABErrorPaths(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	// Enable external account required
	service.externalAccountRequired = true

	testKey := generateTestKey(t)

	t.Run("EAB required but missing", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/new-account"
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
			"contact":              []string{"mailto:test@example.com"},
			"termsOfServiceAgreed": true,
		}, false, 0)

		rr := httptest.NewRecorder()
		service.NewAccountHandler(rr, req)

		// ExternalAccountRequired returns http.StatusUnauthorized (401)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, rr.Body.String(), "externalAccountRequired")
	})
}

// =============================================================================
// OCSPHandler coverage tests - targeting 81% -> 90%+
// =============================================================================

func TestOCSPHandler_AllPaths(t *testing.T) {
	t.Run("GET method not allowed", func(t *testing.T) {
		responder := &mockOCSPResponder90{response: []byte("test-response")}
		handler := OCSPHandler(responder)

		req := httptest.NewRequest(http.MethodGet, "/ocsp", nil)
		rr := httptest.NewRecorder()

		handler(rr, req)

		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	})

	t.Run("Empty request body", func(t *testing.T) {
		responder := &mockOCSPResponder90{response: []byte("test-response")}
		handler := OCSPHandler(responder)

		req := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader([]byte{}))
		rr := httptest.NewRecorder()

		handler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "Empty OCSP request")
	})

	t.Run("Responder error", func(t *testing.T) {
		responder := &mockOCSPResponder90{err: errors.New("test error")}
		handler := OCSPHandler(responder)

		req := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader([]byte("test-request")))
		rr := httptest.NewRecorder()

		handler(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("Successful request", func(t *testing.T) {
		responder := &mockOCSPResponder90{response: []byte("test-response")}
		handler := OCSPHandler(responder)

		req := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader([]byte("test-request")))
		rr := httptest.NewRecorder()

		handler(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "application/ocsp-response", rr.Header().Get("Content-Type"))
		assert.Equal(t, "test-response", rr.Body.String())
	})
}

// =============================================================================
// resolveTenantComplianceConfig coverage tests - targeting 73.9% -> 90%+
// =============================================================================

func TestResolveTenantComplianceConfig_Paths(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("No tenant ID returns global config", func(t *testing.T) {
		account := &entities.ACMEAccount{
			ID:       12345,
			TenantID: "",
		}

		service.globalComplianceConfig = &GlobalComplianceConfig{
			ComplianceConfig: ComplianceConfig{
				Enabled: true,
			},
		}

		config := service.resolveTenantComplianceConfig(ctx, account)
		assert.NotNil(t, config)
		assert.True(t, config.Enabled)
	})

	t.Run("Non-tenant aware factory returns global config", func(t *testing.T) {
		account := &entities.ACMEAccount{
			ID:       12345,
			TenantID: "tenant1",
		}

		service.globalComplianceConfig = &GlobalComplianceConfig{
			ComplianceConfig: ComplianceConfig{
				Enabled: true,
			},
		}

		config := service.resolveTenantComplianceConfig(ctx, account)
		assert.NotNil(t, config)
	})

	t.Run("TenantDAO error returns global config", func(t *testing.T) {
		// Create mock tenant-aware factory with error
		mockFactory := &mockTenantAwareFactory90{
			Factory:      service.storageFactory,
			tenantDAOErr: errors.New("test error"),
		}
		service.storageFactory = mockFactory

		account := &entities.ACMEAccount{
			ID:       12345,
			TenantID: "tenant1",
		}

		service.globalComplianceConfig = &GlobalComplianceConfig{
			ComplianceConfig: ComplianceConfig{
				Enabled: true,
			},
		}

		config := service.resolveTenantComplianceConfig(ctx, account)
		assert.NotNil(t, config)
	})
}

// =============================================================================
// createChallenges coverage tests - targeting 88.6% -> 90%+
// =============================================================================

func TestCreateChallenges_Paths(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	// Add HTTP-01 challenge with proper type
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	// Add DNS-01 challenge with proper type
	service.challengeMap["dns-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	t.Run("DNS identifier with wildcard", func(t *testing.T) {
		id := entities.ACMEIdentifier{
			Type:  common.AuthzTypeDNS,
			Value: "example.com",
		}

		challenges, err := service.createChallenges(12345, 67890, id, true)
		require.NoError(t, err)
		// Should only include DNS-01 for wildcard
		for _, ch := range challenges {
			assert.True(t, strings.HasPrefix(ch.Type, "dns-"))
		}
	})

	t.Run("DNS identifier without wildcard", func(t *testing.T) {
		id := entities.ACMEIdentifier{
			Type:  common.AuthzTypeDNS,
			Value: "example.com",
		}

		challenges, err := service.createChallenges(12345, 67890, id, false)
		require.NoError(t, err)
		assert.True(t, len(challenges) > 0)
	})

	t.Run("Unknown identifier type error", func(t *testing.T) {
		id := entities.ACMEIdentifier{
			Type:  "unknown",
			Value: "test",
		}

		_, err := service.createChallenges(12345, 67890, id, false)
		assert.Error(t, err)
	})
}

// =============================================================================
// encodeJSONWithLogger coverage tests - targeting 75% -> 90%+
// =============================================================================
