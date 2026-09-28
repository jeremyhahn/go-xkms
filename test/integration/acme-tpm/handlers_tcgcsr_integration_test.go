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
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	acmeobjstore "github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
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

// =============================================================================
// Test infrastructure helpers
// =============================================================================

// newTestCA creates an initialized TCGCA backed by in-memory software storage.
// Returns the CA and a cleanup function that resets the xkms service singleton.
// The CA is a root+intermediate hierarchy; the intermediate is returned as the
// issuing CA because it is the one that signs device certificates.
func newTestCA(t *testing.T) (ca.TCGCA, func()) {
	t.Helper()

	// Reset any lingering singleton state from a previous test.
	xkmssdk.ServiceReset()

	// Build in-memory key storage and certificate storage.
	keyStorageBackend, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)

	certStorageBackend, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)

	// PKCS#8 provider wraps key storage. AllowPlaintextKeys is the documented
	// test-fixture escape hatch (pkg/keyprovider/pkcs8/errors.go:
	// ErrPlaintextKeyNotAllowed) for exactly this shape: an in-memory CA root
	// key with no per-key password, matching the same fixture idiom used by
	// pkg/keyprovider/pkcs8/pkcs8_test.go, test/integration/pkcs8, and
	// test/integration/tpm2/capture_helper.go. Production CA key material
	// still goes through the unmodified pkcs8 validation — this only opts in
	// the throwaway keys this in-process test CA generates and discards.
	pkcs8Backend, err := xkmssdk.NewPKCS8Backend(&xkmssdk.PKCS8BackendConfig{
		KeyStorage:         keyStorageBackend,
		AllowPlaintextKeys: true,
	})
	require.NoError(t, err)

	// xkms Backend bundles the key provider and certificate storage.
	keyStore, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
		Backend:     pkcs8Backend,
		CertStorage: certStorageBackend,
	})
	require.NoError(t, err)

	// Register the backend with the xkms service singleton.
	err = xkmssdk.ServiceInitialize(&xkmssdk.ServiceConfig{
		Backends: map[string]xkmssdk.ServiceBackend{
			"software": keyStore,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	// Build an in-memory CertStore for the CA.
	certAdapter := xkmssdk.NewStorageCertAdapter(certStorageBackend)
	certStore, err := xkmssdk.NewCertStore(&xkmssdk.CertStoreConfig{
		CertStorage: certAdapter,
	})
	require.NoError(t, err)

	// Key configuration shared across root and intermediate: ECDSA P-256.
	ecdsaKey := &types.KeyConfig{
		KeyAlgorithm:       types.AlgorithmECDSA,
		Hash:               types.HashSHA256,
		SignatureAlgorithm: types.SigECDSAWithSHA256,
		StoreType:          types.StoreSoftware,
		ECCConfig:          &types.ECCConfig{Curve: types.CurveP256},
		KeyType:            "CA",
	}

	params := &ca.Params{
		Identity: []ca.Identity{
			{
				Subject: ca.Subject{
					CommonName:   "Test Root CA",
					Organization: "Test Organization",
					Country:      "US",
				},
				Valid:         ca.DefaultRootValidityYears,
				Keys:          []*types.KeyConfig{ecdsaKey},
				IsRoot:        true,
				MaxPathLength: 1,
			},
			{
				Subject: ca.Subject{
					CommonName:   "Test Intermediate CA",
					Organization: "Test Organization",
					Country:      "US",
				},
				Valid:    ca.DefaultIntermediateValidityYears,
				Keys:     []*types.KeyConfig{ecdsaKey},
				ParentCA: "Test Root CA",
			},
		},
		Config: &ca.CAConfig{
			DefaultCertValidityDays: ca.DefaultCertValidityDays,
		},
		KeyStore:  keyStore,
		CertStore: certStore,
		// One software backend serves every CA and StoreType in this test.
		BackendForStore: func(string, types.StoreType) (xkms.Backend, error) {
			return keyStore, nil
		},
		RevocationStore: xkmsstorage.NewMemory(),
	}

	ctx := context.Background()
	_, intermediate, err := ca.NewCA(ctx, params)
	require.NoError(t, err)

	tcgCA, ok := intermediate.(ca.TCGCA)
	require.True(t, ok, "intermediate CA must implement ca.TCGCA")

	cleanup := func() {
		_ = xkmssdk.ServiceClose()
	}

	return tcgCA, cleanup
}

// setupTestServiceWithRealCA creates a test ACME service with a real CA for TPM tests.
func setupTestServiceWithRealCA(t *testing.T) (*handlers.RestService, func()) {
	t.Helper()

	// Build an in-memory KV store for ACME entity storage.
	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	require.NoError(t, err)

	storageFactory, err := acmeobjstore.NewFactoryFromKVStore(kv)
	require.NoError(t, err)

	realCA, caCleanup := newTestCA(t)

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

	return service.(*handlers.RestService), caCleanup
}

// generateTestKeyPair creates a test ECDSA key pair.
func generateTestKeyPair(t *testing.T) *TestKeyPair {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return &TestKeyPair{
		PrivateKey: privateKey,
		PublicKey:  privateKey.Public(),
	}
}

// TestKeyPair holds a test keypair.
type TestKeyPair struct {
	PrivateKey crypto.Signer
	PublicKey  crypto.PublicKey
}

// createTestAccountForService creates a test ACME account in the service's storage.
func createTestAccountForService(t *testing.T, service *handlers.RestService, key *TestKeyPair) *entities.ACMEAccount {
	t.Helper()

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

// createTestOrderWithPermanentID creates an ACME order with a permanent-identifier
// identifier in READY status, suitable for enroll-01 challenge finalization.
func createTestOrderWithPermanentID(t *testing.T, service *handlers.RestService, accountID uint64, permanentID string) *entities.ACMEOrder {
	t.Helper()

	ctx := context.Background()

	orderDAO, err := service.GetStorageFactory().OrderDAO(accountID)
	require.NoError(t, err)

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

// createJWSRequestForService creates a signed JWS HTTP request for testing ACME endpoints.
func createJWSRequestForService(t *testing.T, service *handlers.RestService, key *TestKeyPair, url string, payload interface{}, useKID bool, accountID uint64) *http.Request {
	t.Helper()

	nonce, err := service.GetNonceGenerator()()
	require.NoError(t, err)

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

// extractSerialFromURL extracts the numeric serial number from a certificate URL.
// Expected format: https://host/acme/cert/<serial>
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

// parseCertificateChain decodes all PEM CERTIFICATE blocks from pemData and
// returns the parsed x509.Certificates in order.
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
