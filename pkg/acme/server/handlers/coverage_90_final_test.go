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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/gorilla/mux"
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

func TestNewAccountHandler_OnlyReturnExisting(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)

	t.Run("Account does not exist with onlyReturnExisting", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/new-account"
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
			"onlyReturnExisting": true,
		}, false, 0)

		rr := httptest.NewRecorder()
		service.NewAccountHandler(rr, req)

		// AccountDoesNotExist returns http.StatusNotFound (404)
		assert.Equal(t, http.StatusNotFound, rr.Code)
		assert.Contains(t, rr.Body.String(), "accountDoesNotExist")
	})
}

func TestNewAccountHandler_InvalidContact(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)

	t.Run("Invalid contact URL", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/new-account"
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
			"contact":              []string{"invalid-email"},
			"termsOfServiceAgreed": true,
		}, false, 0)

		rr := httptest.NewRecorder()
		service.NewAccountHandler(rr, req)

		// Should fail validation
		assert.NotEqual(t, http.StatusCreated, rr.Code)
	})
}

// =============================================================================
// KeyChangeHandler coverage tests - targeting 71.1% -> 90%+
// =============================================================================

func TestKeyChangeHandler_ErrorPaths(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	t.Run("New key same as current key", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/key-change"

		// Create inner JWS with the SAME key (not a new one)
		innerPayload := map[string]interface{}{
			"account": account.URL,
			"oldKey": map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
			},
		}
		innerPayloadBytes, _ := json.Marshal(innerPayload)

		innerSignerOpts := &jose.SignerOptions{
			EmbedJWK: true,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url": url,
			},
		}
		innerSigner, _ := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.ES256,
			Key:       testKey.PrivateKey,
		}, innerSignerOpts)
		innerJWS, _ := innerSigner.Sign(innerPayloadBytes)

		// Create outer JWS
		req := createJWSRequest(t, service, testKey, url, json.RawMessage(innerJWS.FullSerialize()), true, account.ID)

		rr := httptest.NewRecorder()
		service.KeyChangeHandler(rr, req)

		// The old key comparison should fail since we're sending incomplete JWK
		assert.NotEqual(t, http.StatusOK, rr.Code)
	})
}

// =============================================================================
// OrderFinalizeHandler coverage tests - targeting 68.6% -> 90%+
// =============================================================================

func TestOrderFinalizeHandler_ErrorPaths(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	t.Run("Invalid order ID", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/order/invalid/finalize"
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
			"csr": "invalid-csr",
		}, true, account.ID)

		// Set up mux vars for the invalid ID
		req = mux.SetURLVars(req, map[string]string{"id": "invalid"})

		rr := httptest.NewRecorder()
		service.OrderFinalizeHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Order not found", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/order/999999/finalize"
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
			"csr": "invalid-csr",
		}, true, account.ID)

		req = mux.SetURLVars(req, map[string]string{"id": "999999"})

		rr := httptest.NewRecorder()
		service.OrderFinalizeHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
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
// ChallengeHandler coverage tests - targeting 83.8% -> 90%+
// =============================================================================

func TestChallengeHandler_ErrorPaths(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)

	t.Run("GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/acme/challenge/123", nil)
		rr := httptest.NewRecorder()

		service.ChallengeHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Invalid challenge ID", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/challenge/invalid"
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{}, true, 12345)

		rr := httptest.NewRecorder()
		service.ChallengeHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// =============================================================================
// AuthorizationHandler coverage tests - targeting 77-80% -> 90%+
// =============================================================================

func TestAuthorizationHandler_ErrorPaths(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	t.Run("Empty authorization ID", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/authz/"
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{}, true, account.ID)

		rr := httptest.NewRecorder()
		service.AuthorizationHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Invalid authorization ID format", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/authz/invalid"
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{}, true, account.ID)

		rr := httptest.NewRecorder()
		service.AuthorizationHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Authorization not found", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/authz/999999"
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{}, true, account.ID)

		rr := httptest.NewRecorder()
		service.AuthorizationHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// =============================================================================
// CertificateHandler coverage tests - targeting 81% -> 90%+
// =============================================================================

func TestCertificateHandler_ErrorPaths(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	t.Run("Invalid certificate ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/acme/cert/invalid", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "invalid"})
		rr := httptest.NewRecorder()

		service.CertificateHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Certificate not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/acme/cert/999999", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "999999"})
		rr := httptest.NewRecorder()

		service.CertificateHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// =============================================================================
// NewOrderHandler coverage tests - targeting 79.7% -> 90%+
// =============================================================================

func TestNewOrderHandler_ErrorPaths(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	t.Run("Invalid JSON payload", func(t *testing.T) {
		// Create a request with invalid payload
		nonce, _ := common.GenerateNonce(nonceSize)
		service.nonceStore.Add(nonce)

		signerOpts := &jose.SignerOptions{
			NonceSource: &staticNonceSource{nonce: nonce},
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url": "https://acme.test.example.com/acme/new-order",
				"kid": fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID),
			},
		}
		signer, _ := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.ES256,
			Key:       testKey.PrivateKey,
		}, signerOpts)

		// Sign invalid JSON
		jws, _ := signer.Sign([]byte("invalid-json"))

		req := httptest.NewRequest(http.MethodPost, "/acme/new-order", strings.NewReader(jws.FullSerialize()))
		req.Header.Set("Content-Type", "application/jose+json")

		rr := httptest.NewRecorder()
		service.NewOrderHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Unsupported identifier type", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/new-order"
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
			"identifiers": []map[string]string{
				{"type": "invalid-type", "value": "test.example.com"},
			},
		}, true, account.ID)

		rr := httptest.NewRecorder()
		service.NewOrderHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "unsupportedIdentifier")
	})

	t.Run("Invalid domain name", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/new-order"
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
			"identifiers": []map[string]string{
				{"type": "dns", "value": "-invalid-.domain"},
			},
		}, true, account.ID)

		rr := httptest.NewRecorder()
		service.NewOrderHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// =============================================================================
// OrderHandler coverage tests - targeting 81.2% -> 90%+
// =============================================================================

func TestOrderHandler_ErrorPaths(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	t.Run("GET method not allowed", func(t *testing.T) {
		// Need to set up proper JWS for parseKID
		url := "https://acme.test.example.com/acme/order/123"
		req := createJWSRequest(t, service, testKey, url, nil, true, account.ID)
		req = mux.SetURLVars(req, map[string]string{"id": "123"})
		req.Method = http.MethodGet

		rr := httptest.NewRecorder()
		service.OrderHandler(rr, req)

		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	})

	t.Run("Invalid order ID format", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/order/invalid"
		req := createJWSRequest(t, service, testKey, url, nil, true, account.ID)
		req = mux.SetURLVars(req, map[string]string{"id": "invalid"})

		rr := httptest.NewRecorder()
		service.OrderHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Order not found", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/order/999999"
		req := createJWSRequest(t, service, testKey, url, nil, true, account.ID)
		req = mux.SetURLVars(req, map[string]string{"id": "999999"})

		rr := httptest.NewRecorder()
		service.OrderHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// =============================================================================
// OrdersListHandler coverage tests - targeting 85.4% -> 90%+
// =============================================================================

func TestOrdersListHandler_ErrorPaths(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	t.Run("Invalid page parameter", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/orders"
		req := createJWSRequest(t, service, testKey, url, nil, true, account.ID)
		req = mux.SetURLVars(req, map[string]string{"page": "invalid"})

		rr := httptest.NewRecorder()
		service.OrdersListHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Method not allowed", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/orders"
		req := createJWSRequest(t, service, testKey, url, nil, true, account.ID)
		req.Method = http.MethodDelete

		rr := httptest.NewRecorder()
		service.OrdersListHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// =============================================================================
// RevokeCertHandler coverage tests - targeting 84.6% -> 90%+
// =============================================================================

func TestRevokeCertHandler_ErrorPaths(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	t.Run("Invalid certificate encoding", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/revoke-cert"
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
			"certificate": "!!!invalid-base64!!!",
		}, true, account.ID)

		rr := httptest.NewRecorder()
		service.RevokeCertHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Invalid certificate format", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/revoke-cert"
		// Valid base64 but not a certificate
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
			"certificate": base64.RawURLEncoding.EncodeToString([]byte("not-a-certificate")),
		}, true, account.ID)

		rr := httptest.NewRecorder()
		service.RevokeCertHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Invalid revocation reason", func(t *testing.T) {
		// Create a valid certificate for testing
		privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(12345),
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)

		url := "https://acme.test.example.com/acme/revoke-cert"
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
			"certificate": base64.RawURLEncoding.EncodeToString(certDER),
			"reason":      99, // Invalid reason
		}, true, account.ID)

		rr := httptest.NewRecorder()
		service.RevokeCertHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// =============================================================================
// AccountHandler coverage tests - targeting 81.6% -> 90%+
// =============================================================================

func TestAccountHandler_ErrorPaths(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	testKey := generateTestKey(t)
	account := createTestAccount(t, service, testKey)

	t.Run("Invalid status value", func(t *testing.T) {
		url := "https://acme.test.example.com/acme/account/" + fmt.Sprintf("%d", account.ID)
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
			"status": "invalid-status",
		}, true, account.ID)

		rr := httptest.NewRecorder()
		service.AccountHandler(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Deactivate already deactivated account", func(t *testing.T) {
		// First deactivate
		url := "https://acme.test.example.com/acme/account/" + fmt.Sprintf("%d", account.ID)
		req := createJWSRequest(t, service, testKey, url, map[string]interface{}{
			"status": "deactivated",
		}, true, account.ID)

		rr := httptest.NewRecorder()
		service.AccountHandler(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)

		// Update account status in memory
		ctx := context.Background()
		accountDAO, _ := service.storageFactory.AccountDAO()
		updatedAccount, _ := accountDAO.Get(ctx, account.ID)

		// Try to deactivate again - this should fail with ErrAccountDeactivated from parseKID
		testKey2 := generateTestKey(t)
		account2 := createTestAccount(t, service, testKey2)

		// First deactivate
		url2 := "https://acme.test.example.com/acme/account/" + fmt.Sprintf("%d", account2.ID)
		req2 := createJWSRequest(t, service, testKey2, url2, map[string]interface{}{
			"status": "deactivated",
		}, true, account2.ID)

		rr2 := httptest.NewRecorder()
		service.AccountHandler(rr2, req2)
		assert.Equal(t, http.StatusOK, rr2.Code)

		// Set account as deactivated in storage
		updatedAccount.Status = common.StatusDeactivated
		_ = accountDAO.Save(ctx, updatedAccount)

		// Try again - now parseKID should fail with deactivated error
		req3 := createJWSRequest(t, service, testKey, url, map[string]interface{}{
			"status": "deactivated",
		}, true, account.ID)

		rr3 := httptest.NewRecorder()
		service.AccountHandler(rr3, req3)
		// parseKID should fail since account is deactivated
		assert.Equal(t, http.StatusBadRequest, rr3.Code)
	})

	t.Run("Invalid contact update", func(t *testing.T) {
		testKey3 := generateTestKey(t)
		account3 := createTestAccount(t, service, testKey3)

		url := "https://acme.test.example.com/acme/account/" + fmt.Sprintf("%d", account3.ID)
		req := createJWSRequest(t, service, testKey3, url, map[string]interface{}{
			"contact": []string{"not-a-valid-contact"},
		}, true, account3.ID)

		rr := httptest.NewRecorder()
		service.AccountHandler(rr, req)

		// Should fail validation
		assert.NotEqual(t, http.StatusCreated, rr.Code)
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
// resolveTenantSigningCA coverage tests
// =============================================================================

func TestResolveTenantSigningCA_Paths(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("No tenant ID returns nil, nil", func(t *testing.T) {
		account := &entities.ACMEAccount{
			ID:       12345,
			TenantID: "",
		}

		result, err := service.resolveTenantSigningCA(ctx, account, "general")
		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("Non-tenant aware factory fails closed", func(t *testing.T) {
		account := &entities.ACMEAccount{
			ID:       12345,
			TenantID: "tenant1",
		}

		result, err := service.resolveTenantSigningCA(ctx, account, "general")
		assert.ErrorIs(t, err, ErrTenantStorageUnsupported)
		assert.Nil(t, result)
	})
}

// =============================================================================
// getTenantCASigner coverage tests
// =============================================================================

func TestGetTenantCASigner_Paths(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("Nil signing CA info returns nil, nil", func(t *testing.T) {
		result, err := service.getTenantCASigner(ctx, nil)
		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("UseGlobalDefault returns nil, nil", func(t *testing.T) {
		info := &entities.SigningCAInfo{
			UseGlobalDefault: true,
		}

		result, err := service.getTenantCASigner(ctx, info)
		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("No KMS service fails closed", func(t *testing.T) {
		info := &entities.SigningCAInfo{
			UseGlobalDefault: false,
			TenantID:         "tenant1",
			Type:             entities.SigningCATypeIntermediate,
		}

		result, err := service.getTenantCASigner(ctx, info)
		assert.ErrorIs(t, err, ErrTenantSignerUnavailable)
		assert.Nil(t, result)
	})

	t.Run("Unknown signing CA type fails closed", func(t *testing.T) {
		service.kmsService = &mockKMSService90{}

		info := &entities.SigningCAInfo{
			UseGlobalDefault: false,
			TenantID:         "tenant1",
			Type:             "unknown",
		}

		result, err := service.getTenantCASigner(ctx, info)
		assert.ErrorIs(t, err, ErrTenantCATypeUnsupported)
		assert.Nil(t, result)
	})
}

// =============================================================================
// NewNonceHandler coverage tests - targeting 85.7% -> 90%+
// =============================================================================

func TestNewNonceHandler_AllMethods(t *testing.T) {
	service, _, cleanup := setupTestService90(t)
	defer cleanup()

	t.Run("HEAD request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodHead, "/acme/new-nonce", nil)
		rr := httptest.NewRecorder()

		service.NewNonceHandler(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.NotEmpty(t, rr.Header().Get("Replay-Nonce"))
	})

	t.Run("GET request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/acme/new-nonce", nil)
		rr := httptest.NewRecorder()

		service.NewNonceHandler(rr, req)

		assert.Equal(t, http.StatusNoContent, rr.Code)
		assert.NotEmpty(t, rr.Header().Get("Replay-Nonce"))
	})

	t.Run("POST method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/acme/new-nonce", nil)
		rr := httptest.NewRecorder()

		service.NewNonceHandler(rr, req)

		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
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
// isValidDomainName coverage tests - targeting 92.9% -> 100%
// =============================================================================

func TestIsValidDomainName_EdgeCases(t *testing.T) {
	t.Run("Empty domain", func(t *testing.T) {
		assert.False(t, isValidDomainName(""))
	})

	t.Run("Domain too long", func(t *testing.T) {
		longDomain := strings.Repeat("a", 254)
		assert.False(t, isValidDomainName(longDomain))
	})

	t.Run("Label too long", func(t *testing.T) {
		longLabel := strings.Repeat("a", 64)
		assert.False(t, isValidDomainName(longLabel+".com"))
	})

	t.Run("Empty label", func(t *testing.T) {
		assert.False(t, isValidDomainName("example..com"))
	})

	t.Run("Label starts with hyphen", func(t *testing.T) {
		assert.False(t, isValidDomainName("-example.com"))
	})

	t.Run("Label ends with hyphen", func(t *testing.T) {
		assert.False(t, isValidDomainName("example-.com"))
	})

	t.Run("Invalid character", func(t *testing.T) {
		assert.False(t, isValidDomainName("exam_ple.com"))
	})

	t.Run("Valid domain", func(t *testing.T) {
		assert.True(t, isValidDomainName("example.com"))
		assert.True(t, isValidDomainName("sub.example.com"))
		assert.True(t, isValidDomainName("a-b.example.com"))
	})
}

// =============================================================================
// encodeJSONWithLogger coverage tests - targeting 75% -> 90%+
// =============================================================================

func TestEncodeJSONWithLogger_ErrorPath(t *testing.T) {
	t.Run("Encoding error with logger", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))

		// Create a channel which cannot be JSON encoded
		invalidData := make(chan int)

		rr := httptest.NewRecorder()
		encodeJSONWithLogger(rr, invalidData, logger)

		// Should write empty response on error
		assert.Equal(t, 0, rr.Body.Len())
	})
}
