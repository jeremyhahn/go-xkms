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

//go:build integration && tpm2

package tpm_test

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
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-objstore/pkg/local"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	"github.com/jeremyhahn/go-xkms/pkg/acme/ca"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFinalizeTCGCSR_Success tests successful TCG-CSR-IDEVID finalization
// with real TPM attestation data from swtpm
func TestFinalizeTCGCSR_Success(t *testing.T) {
	// Check if swtpm is available
	RequireSwtpm(t)

	// Setup test service with real CA
	service, cleanup := setupTestServiceWithRealCA(t)
	defer cleanup()

	// Create ACME account
	key := generateTestKeyPair(t)
	account := createTestAccountForService(t, service, key)

	// Create device identifier
	deviceID := fmt.Sprintf("test-device-%d", time.Now().Unix())

	// Create order with permanent-identifier for enroll-01
	order := createTestOrderWithPermanentID(t, service, account.ID, deviceID)

	// Connect to swtpm and generate real TCG-CSR-IDEVID
	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	err := swtpm.InitializeTPM()
	require.NoError(t, err, "Failed to initialize TPM")

	err = swtpm.Provision()
	require.NoError(t, err, "Failed to provision TPM")

	// Create IDevID and TCG-CSR-IDEVID
	qualifyingData := []byte("test-qualifying-data")
	err = swtpm.CreateIDevID(qualifyingData)
	require.NoError(t, err, "Failed to create IDevID")

	packedCSR := swtpm.GetPackedCSR()
	require.NotEmpty(t, packedCSR, "Packed CSR should not be empty")

	t.Logf("Generated TCG-CSR-IDEVID: %d bytes", len(packedCSR))

	// Create finalize request with TCG-CSR
	payload := handlers.OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(packedCSR),
	}

	// Create HTTP request
	url := fmt.Sprintf("https://acme.test.example.com/acme/order/%d/finalize", order.ID)
	req := createJWSRequestForService(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})
	req.RemoteAddr = deviceID

	// Execute request
	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code, "Expected successful finalization, got response: %s", resp.Body.String())

	var orderResp entities.ACMEOrder
	err = json.NewDecoder(resp.Body).Decode(&orderResp)
	require.NoError(t, err, "Failed to decode order response")

	assert.Equal(t, common.StatusValid, orderResp.Status, "Order should be valid after finalization")
	assert.NotEmpty(t, orderResp.Certificate, "Certificate URL should be set")
	assert.Contains(t, orderResp.Certificate, "/acme/cert/", "Certificate URL should have correct format")

	// Verify certificate was saved
	certDAO, err := service.GetStorageFactory().CertificateDAO()
	require.NoError(t, err)

	// Extract serial number from certificate URL
	// URL format: https://acme.test.example.com/acme/cert/8318666562681616638
	serialNum := extractSerialFromURL(t, orderResp.Certificate)

	cert, err := certDAO.Get(context.Background(), serialNum)
	require.NoError(t, err, "Certificate should be saved")
	assert.NotEmpty(t, cert.PEM, "Certificate PEM should not be empty")

	// Parse and verify the certificate chain (IAK + IDevID)
	parsedCerts := parseCertificateChain(t, []byte(cert.PEM))
	require.GreaterOrEqual(t, len(parsedCerts), 2, "Should have at least IAK and IDevID certificates")

	iakCert := parsedCerts[0]
	idevidCert := parsedCerts[1]

	// Both IAK and IDevID certificates have the same Common Name (device identifier)
	// They are distinguished by their X.509 extensions (IAK has tcg-kp-AIKCertificate)
	expectedCN := fmt.Sprintf("TEST-MODEL-%s", deviceID)
	assert.Equal(t, expectedCN, iakCert.Subject.CommonName, "IAK cert should have device identifier CN")
	assert.Equal(t, expectedCN, idevidCert.Subject.CommonName, "IDevID cert should have device identifier CN")

	t.Logf("IAK Certificate: CN=%s", iakCert.Subject.CommonName)
	t.Logf("IDevID Certificate: CN=%s", idevidCert.Subject.CommonName)

	// Verify IAK has the AIK Certificate marker extension (OID 2.23.133.8.3)
	hasAIKMarker := false
	for _, ext := range iakCert.Extensions {
		if ext.Id.String() == "2.23.133.8.3" {
			hasAIKMarker = true
			break
		}
	}
	assert.True(t, hasAIKMarker, "IAK certificate should have AIK marker extension")

	LogCertificate(t, iakCert, "Generated IAK Certificate")
	LogCertificate(t, idevidCert, "Generated IDevID Certificate")
}

// TestFinalizeTCGCSR_InvalidCSRData tests TCG-CSR with invalid data
func TestFinalizeTCGCSR_InvalidCSRData(t *testing.T) {
	service, cleanup := setupTestServiceWithRealCA(t)
	defer cleanup()

	key := generateTestKeyPair(t)
	account := createTestAccountForService(t, service, key)

	deviceID := "test-invalid-csr"
	order := createTestOrderWithPermanentID(t, service, account.ID, deviceID)

	// Create payload with invalid CSR data
	payload := handlers.OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString([]byte("invalid-tcg-csr-data")),
	}

	url := fmt.Sprintf("https://acme.test.example.com/acme/order/%d/finalize", order.ID)
	req := createJWSRequestForService(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})
	req.RemoteAddr = deviceID

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	// Should return malformed error
	assert.Equal(t, http.StatusBadRequest, resp.Code)

	var acmeError entities.Error
	err := json.NewDecoder(resp.Body).Decode(&acmeError)
	require.NoError(t, err)
	assert.Contains(t, acmeError.Type, common.ErrTypeMalformedError)
}

// TestFinalizeTCGCSR_VerificationFailure tests TCG-CSR with verification failures
func TestFinalizeTCGCSR_VerificationFailure(t *testing.T) {
	RequireSwtpm(t)

	service, cleanup := setupTestServiceWithRealCA(t)
	defer cleanup()

	key := generateTestKeyPair(t)
	account := createTestAccountForService(t, service, key)

	deviceID := fmt.Sprintf("test-verify-fail-%d", time.Now().Unix())
	order := createTestOrderWithPermanentID(t, service, account.ID, deviceID)

	// Generate a valid TCG-CSR but with tampered data
	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	err := swtpm.InitializeTPM()
	require.NoError(t, err)

	err = swtpm.Provision()
	require.NoError(t, err)

	err = swtpm.CreateIDevID([]byte("original-qualifying-data"))
	require.NoError(t, err)

	packedCSR := swtpm.GetPackedCSR()
	require.NotEmpty(t, packedCSR)

	// Tamper with the CSR by modifying bytes
	tamperedCSR := make([]byte, len(packedCSR))
	copy(tamperedCSR, packedCSR)
	// Flip some bits in the middle of the CSR
	if len(tamperedCSR) > 100 {
		tamperedCSR[50] ^= 0xFF
		tamperedCSR[100] ^= 0xFF
	}

	payload := handlers.OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(tamperedCSR),
	}

	url := fmt.Sprintf("https://acme.test.example.com/acme/order/%d/finalize", order.ID)
	req := createJWSRequestForService(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})
	req.RemoteAddr = deviceID

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	// Should fail verification
	assert.NotEqual(t, http.StatusOK, resp.Code, "Tampered CSR should not be accepted")
}

// TestFinalizeTCGCSR_WrongIdentifierType tests order without permanent-identifier
func TestFinalizeTCGCSR_WrongIdentifierType(t *testing.T) {
	service, cleanup := setupTestServiceWithRealCA(t)
	defer cleanup()

	key := generateTestKeyPair(t)
	account := createTestAccountForService(t, service, key)

	// Create order with DNS identifier instead of permanent-identifier
	ctx := context.Background()
	orderDAO, err := service.GetStorageFactory().OrderDAO(account.ID)
	require.NoError(t, err)

	// Generate order ID
	orderID, err := handlers.GenerateID()
	require.NoError(t, err, "Failed to generate order ID")

	order := &entities.ACMEOrder{
		ID:     orderID,
		Status: common.StatusReady,
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
		AccountID: account.ID,
	}

	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	// Try to finalize with TCG-CSR (invalid for DNS identifier)
	payload := handlers.OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString([]byte("fake-tcg-csr")),
	}

	url := fmt.Sprintf("https://acme.test.example.com/acme/order/%d/finalize", order.ID)
	req := createJWSRequestForService(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	// Should fail because DNS identifiers can't use TCG-CSR
	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

// TestFinalizeTCGCSR_WithOrderFinalizeHooks tests hook execution with TCG-CSR
func TestFinalizeTCGCSR_WithOrderFinalizeHooks(t *testing.T) {
	RequireSwtpm(t)

	service, cleanup := setupTestServiceWithRealCA(t)
	defer cleanup()

	// Track hook execution
	hookExecuted := false
	var hookContext *handlers.OrderFinalizeHookContext

	// Register hook
	registry := handlers.NewOrderFinalizeHookRegistry()
	registry.Register(func(ctx *handlers.OrderFinalizeHookContext) error {
		hookExecuted = true
		hookContext = ctx
		return nil
	})

	service.SetOrderFinalizeHooks(registry)

	// Create account and order
	key := generateTestKeyPair(t)
	account := createTestAccountForService(t, service, key)

	deviceID := fmt.Sprintf("test-hooks-%d", time.Now().Unix())
	order := createTestOrderWithPermanentID(t, service, account.ID, deviceID)

	// Generate TCG-CSR
	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	err := swtpm.InitializeTPM()
	require.NoError(t, err)

	err = swtpm.Provision()
	require.NoError(t, err)

	err = swtpm.CreateIDevID([]byte("hook-test-data"))
	require.NoError(t, err)

	packedCSR := swtpm.GetPackedCSR()

	payload := handlers.OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(packedCSR),
	}

	url := fmt.Sprintf("https://acme.test.example.com/acme/order/%d/finalize", order.ID)
	req := createJWSRequestForService(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})
	req.RemoteAddr = deviceID

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code, "Expected successful finalization, got: %s", resp.Body.String())
	assert.True(t, hookExecuted, "Hook should have been executed")

	// Verify hook context
	require.NotNil(t, hookContext)
	assert.True(t, hookContext.IsTCGCSR, "Hook context should indicate TCG-CSR")
	assert.NotNil(t, hookContext.TCGData, "TCG enrollment data should be present")
	assert.Equal(t, "TEST-MODEL", hookContext.TCGData.ProductModel)
	assert.Equal(t, deviceID, hookContext.TCGData.ProductSerial)
	assert.NotNil(t, hookContext.TCGData.EKCertificate)
	assert.NotNil(t, hookContext.TCGData.IAKCertificateDER)
	assert.NotNil(t, hookContext.TCGData.IDevIDCertificateDER)
}

// TestFinalizeTCGCSR_HookFailure tests hook failure handling
func TestFinalizeTCGCSR_HookFailure(t *testing.T) {
	RequireSwtpm(t)

	service, cleanup := setupTestServiceWithRealCA(t)
	defer cleanup()

	// Register hook that always fails
	registry := handlers.NewOrderFinalizeHookRegistry()
	registry.Register(func(ctx *handlers.OrderFinalizeHookContext) error {
		return caerrors.InternalServerError("hook execution failed")
	})

	service.SetOrderFinalizeHooks(registry)

	key := generateTestKeyPair(t)
	account := createTestAccountForService(t, service, key)

	deviceID := fmt.Sprintf("test-hook-fail-%d", time.Now().Unix())
	order := createTestOrderWithPermanentID(t, service, account.ID, deviceID)

	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	err := swtpm.InitializeTPM()
	require.NoError(t, err)

	err = swtpm.Provision()
	require.NoError(t, err)

	err = swtpm.CreateIDevID([]byte("hook-fail-test"))
	require.NoError(t, err)

	packedCSR := swtpm.GetPackedCSR()

	payload := handlers.OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(packedCSR),
	}

	url := fmt.Sprintf("https://acme.test.example.com/acme/order/%d/finalize", order.ID)
	req := createJWSRequestForService(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})
	req.RemoteAddr = deviceID

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	// Should fail due to hook error
	assert.Equal(t, http.StatusInternalServerError, resp.Code)

	var acmeError entities.Error
	err = json.NewDecoder(resp.Body).Decode(&acmeError)
	require.NoError(t, err)
	assert.Contains(t, strings.ToLower(acmeError.Detail), "hook failed")
}

// Helper functions specific to this test file

// setupTestServiceWithRealCA creates a test ACME service with a real CA for TPM tests
func setupTestServiceWithRealCA(t *testing.T) (*handlers.RestService, func()) {
	tmpDir, err := os.MkdirTemp("", "acme-tcgcsr-test-*")
	require.NoError(t, err)

	// Create storage backend
	store := local.New()
	err = store.Configure(map[string]string{"path": tmpDir})
	require.NoError(t, err)

	storageFactory, err := objstore.NewFactory(store)
	require.NoError(t, err)

	// Create real CA using the pattern from ca_fixtures.go
	realCA, caCleanup := createRealCA(t)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	params := &handlers.Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             realCA,
		CAAIdentities:  []string{"acme.test.example.com"},
		ChallengeMap:   make(map[string]common.ChallengeVerifierFunc),
		Logger:         logger,
		StorageFactory: storageFactory,
		TermsOfService: "https://acme.test.example.com/tos",
	}

	service, err := handlers.NewRestService(params)
	require.NoError(t, err)

	cleanup := func() {
		caCleanup()
		os.RemoveAll(tmpDir)
	}

	return service.(*handlers.RestService), cleanup
}

// createRealCA creates a real Certificate Authority for testing using the pattern from ca_fixtures.go
func createRealCA(t *testing.T) (*ca.CA, func()) {
	// Reset any previous facade state to ensure clean test isolation
	xkmssdk.ServiceReset()

	// Create in-memory storage backends
	keyStorage, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)
	certStorageBackend, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)

	// Create PKCS#8 backend for key storage
	pkcs8Backend, err := xkmssdk.NewPKCS8Backend(&xkmssdk.PKCS8BackendConfig{
		KeyStorage: keyStorage,
	})
	require.NoError(t, err)

	// Create xkms (keystore) with software backend
	keyStore, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
		Backend:     pkcs8Backend,
		CertStorage: certStorageBackend,
	})
	require.NoError(t, err)

	// Initialize the XKMSFacade with the software backend as default
	err = xkmssdk.ServiceInitialize(&xkmssdk.ServiceConfig{
		Backends: map[string]xkmssdk.ServiceBackend{
			"software": keyStore,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	// Create cert adapter and certstore for CA
	certAdapter := xkmssdk.NewStorageCertAdapter(certStorageBackend)
	certStore, err := xkmssdk.NewCertStore(&xkmssdk.CertStoreConfig{
		CertStorage: certAdapter,
	})
	require.NoError(t, err)

	// Create blob store using go-objstore
	blobStore := local.New()
	err = blobStore.Configure(map[string]string{"path": t.TempDir()})
	require.NoError(t, err)

	// Create CA configuration
	config := ca.Config{
		Identity: []ca.Identity{
			{
				Subject: ca.Subject{
					CommonName:   "Test Root CA",
					Organization: "Test Organization",
					Country:      "US",
				},
				Valid:        10, // 10 years for root CA
				KeyAlgorithm: x509.ECDSA,
				ECCCurve:     "P256",
				KeystoreType: "software",
				IsRoot:       true,
			},
			{
				Subject: ca.Subject{
					CommonName:   "Test Intermediate CA",
					Organization: "Test Organization",
					Country:      "US",
				},
				Valid:        5, // 5 years for intermediate CA
				KeyAlgorithm: x509.ECDSA,
				ECCCurve:     "P256",
				KeystoreType: "software",
				ParentCA:     "Test Root CA",
			},
		},
		SelectedCA:                1,   // Use intermediate CA for issuing
		DefaultValidityPeriod:     365, // 365 days
		DefaultKeyAlgorithm:       x509.ECDSA,
		DefaultSignatureAlgorithm: x509.ECDSAWithSHA256,
		DefaultHash:               crypto.SHA256,
		LazyInitialization:        false,
	}

	// Create CA (gets KeyStore from facade based on config.Identity[0].KeystoreType)
	caInstance, err := ca.New(config, certStore, blobStore)
	require.NoError(t, err)

	cleanup := func() {
		xkmssdk.ServiceReset()
	}

	return caInstance, cleanup
}

// generateTestKeyPair creates a test ECDSA key pair
func generateTestKeyPair(t *testing.T) *TestKeyPair {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return &TestKeyPair{
		PrivateKey: privateKey,
		PublicKey:  privateKey.Public(),
	}
}

// TestKeyPair holds a test keypair
type TestKeyPair struct {
	PrivateKey crypto.Signer
	PublicKey  crypto.PublicKey
}

// createTestAccountForService creates a test account
func createTestAccountForService(t *testing.T, service *handlers.RestService, key *TestKeyPair) *entities.ACMEAccount {
	ctx := context.Background()

	accountDAO, err := service.GetStorageFactory().AccountDAO()
	require.NoError(t, err)

	pubKeyPEM, err := xkmssdk.EncodePublicKeyPEM(key.PublicKey)
	require.NoError(t, err)

	accountID, err := handlers.AccountIDFromPublicKey(key.PublicKey)
	require.NoError(t, err)

	account := &entities.ACMEAccount{
		ID:                   accountID,
		Status:               common.StatusValid,
		Contact:              []string{"mailto:test@example.com"},
		TermsOfServiceAgreed: true,
		Key:                  string(pubKeyPEM),
		CreatedAt:            time.Now(),
		Orders:               fmt.Sprintf("https://acme.test.example.com/acme/account/%d/orders", accountID),
		URL:                  fmt.Sprintf("https://acme.test.example.com/acme/account/%d", accountID),
	}

	err = accountDAO.Save(ctx, account)
	require.NoError(t, err)

	return account
}

// createTestOrderWithPermanentID creates an order with permanent-identifier in READY status
func createTestOrderWithPermanentID(t *testing.T, service *handlers.RestService, accountID uint64, permanentID string) *entities.ACMEOrder {
	ctx := context.Background()

	orderDAO, err := service.GetStorageFactory().OrderDAO(accountID)
	require.NoError(t, err)

	// Generate order ID
	orderID, err := handlers.GenerateID()
	require.NoError(t, err, "Failed to generate order ID")

	order := &entities.ACMEOrder{
		ID:     orderID,
		Status: common.StatusReady,
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypePermanentIdentifier, Value: permanentID},
		},
		Expires:   time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		AccountID: accountID,
		URL:       fmt.Sprintf("https://acme.test.example.com/acme/order/%d", orderID),
		Finalize:  fmt.Sprintf("https://acme.test.example.com/acme/order/%d/finalize", orderID),
	}

	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	return order
}

// createJWSRequestForService creates a signed JWS request for testing
func createJWSRequestForService(t *testing.T, service *handlers.RestService, key *TestKeyPair, url string, payload interface{}, useKID bool, accountID uint64) *http.Request {
	// Get a valid nonce
	nonce, err := common.GenerateNonce(32)
	require.NoError(t, err)
	service.GetNonceStore().Add(nonce)

	// Create JWS
	kid := ""
	if useKID {
		kid = fmt.Sprintf("https://acme.test.example.com/acme/account/%d", accountID)
	}

	jws, err := createJWS(payload, key.PrivateKey, kid, nonce, url)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(jws))
	req.Header.Set("Content-Type", "application/jose+json")

	return req
}

// extractSerialFromURL extracts the serial number from a certificate URL
// URL format: https://acme.test.example.com/acme/cert/8318666562681616638
func extractSerialFromURL(t *testing.T, certURL string) uint64 {
	t.Helper()

	parts := strings.Split(certURL, "/")
	if len(parts) < 2 {
		t.Fatalf("Invalid certificate URL format: %s", certURL)
	}

	serialStr := parts[len(parts)-1]
	serialNum, err := strconv.ParseUint(serialStr, 10, 64)
	require.NoError(t, err, "Failed to parse serial number from URL: %s", certURL)

	return serialNum
}

// parseCertificateChain parses multiple PEM certificates
func parseCertificateChain(t *testing.T, pemData []byte) []*x509.Certificate {
	t.Helper()

	var certs []*x509.Certificate
	remaining := pemData

	for len(remaining) > 0 {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)
			certs = append(certs, cert)
		}
	}

	return certs
}
