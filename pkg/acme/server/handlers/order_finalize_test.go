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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockCAForFinalize extends MockCA to properly support certificate signing
type MockCAForFinalize struct {
	MockCA
	shouldFailSignCSR         bool
	shouldFailVerify          bool
	shouldFailIssueEK         bool
	returnedSerialNum         *big.Int
	returnedCert              *x509.Certificate
	returnCertWithNilSerial   bool
	returnCertWithLargeSerial bool
	lastEKRequest             *ca.CertificateRequest
	lastSignOptions           *ca.SignOptions
}

func (m *MockCAForFinalize) SignCSR(_ context.Context, csrPEM []byte, opts *ca.SignOptions) (*x509.Certificate, error) {
	m.lastSignOptions = opts
	if m.shouldFailSignCSR {
		return nil, caerrors.SigningFailureError("mock sign CSR error")
	}

	// Parse the CSR to get subject information
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, caerrors.SerializationFailureError("failed to decode PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Create a mock certificate with proper serial number
	serialNumber := m.returnedSerialNum
	if serialNumber == nil {
		serialNumber = big.NewInt(12345)
	}

	if m.returnCertWithLargeSerial {
		// Create a serial number larger than uint64 max
		serialNumber = new(big.Int)
		serialNumber.SetString("18446744073709551616999999999999999", 10) // > 2^64
	}

	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		Raw:          []byte("mock-cert-der"),
	}

	if m.returnCertWithNilSerial {
		cert.SerialNumber = nil
	}

	if m.returnedCert != nil {
		cert = m.returnedCert
	}

	return cert, nil
}

func (m *MockCAForFinalize) IssueEKCertificate(_ context.Context, req *ca.CertificateRequest, pubKey crypto.PublicKey) (*x509.Certificate, error) {
	m.lastEKRequest = req
	if m.shouldFailIssueEK {
		return nil, caerrors.KeyGenerationFailureError("mock issue EK error")
	}

	// Create a mock EK certificate
	serialNumber := big.NewInt(67890)
	if m.returnedSerialNum != nil {
		serialNumber = m.returnedSerialNum
	}

	if m.returnCertWithLargeSerial {
		serialNumber = new(big.Int)
		serialNumber.SetString("18446744073709551616999999999999999", 10)
	}

	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: req.Subject.CommonName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Raw:         []byte("mock-ek-cert-der"),
	}

	if m.returnCertWithNilSerial {
		cert.SerialNumber = nil
	}

	return cert, nil
}

func (m *MockCAForFinalize) Verify(cert *x509.Certificate, _ ...crypto.Signer) ([][]*x509.Certificate, error) {
	if m.shouldFailVerify {
		return nil, caerrors.VerificationFailureError("mock verify error")
	}
	return [][]*x509.Certificate{}, nil
}

// setupTestServiceWithMockCA creates a test service with enhanced MockCA
func setupTestServiceWithMockCA(t *testing.T) (*RestService, *MockCAForFinalize, func()) {
	service, _, cleanup := setupTestService(t)

	mockCA := &MockCAForFinalize{}
	service.ca = mockCA

	return service, mockCA, cleanup
}

func TestOrderFinalizeHandler_Success(t *testing.T) {
	service, mockCA, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	// Set specific serial number for the certificate
	mockCA.returnedSerialNum = big.NewInt(99999)

	// Create test account and key
	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create order in READY status
	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	// Generate a test CSR
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	// Create finalize request payload
	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	// Create JWS request
	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	// Add mux vars to the request
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	// Execute request
	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)

	var orderResp entities.ACMEOrder
	err = json.NewDecoder(resp.Body).Decode(&orderResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusValid, orderResp.Status)
	assert.NotEmpty(t, orderResp.Certificate)
	assert.Contains(t, orderResp.Certificate, "/acme/cert/")
}

func TestOrderFinalizeHandler_InvalidOrderID(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	payload := OrderFinalizeRequest{
		CSR: "dGVzdC1jc3I",
	}

	url := fmt.Sprintf("%s/acme/orders/invalid/finalize", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": "invalid"})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestOrderFinalizeHandler_OrderNotFound(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	payload := OrderFinalizeRequest{
		CSR: "dGVzdC1jc3I",
	}

	// Use a non-existent order ID
	url := fmt.Sprintf("%s/acme/orders/999999/finalize", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": "999999"})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestOrderFinalizeHandler_OrderNotReady(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create order in PENDING status (not ready)
	order := createTestOrderSimple(t, service, account.ID)
	// order.Status is already StatusPending by default

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeOrderNotReady, http.StatusForbidden)
}

func TestOrderFinalizeHandler_InvalidCSREncoding(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	// Invalid base64 CSR
	payload := OrderFinalizeRequest{
		CSR: "!@#$%invalid-base64",
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestOrderFinalizeHandler_InvalidCSRFormat(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	// Valid base64 but invalid CSR data
	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString([]byte("invalid-csr-data")),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestOrderFinalizeHandler_CSRIdentifierMismatch(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create order with specific identifier
	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypeDNS, Value: "example.com"},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	// Create CSR with different domain
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "different.com", // Mismatch!
		},
		DNSNames: []string{"different.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)

	// M2 regression: identifier validation happens before the order is ever
	// moved to "processing", so a mismatched CSR must leave it retryable.
	updated, err := orderDAO.Get(ctx, order.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusReady, updated.Status)
}

// TestOrderFinalizeHandler_MalformedCSRLeavesOrderReady is the M2
// regression test: a CSR that is neither a valid x509 CertificateRequest
// nor a valid TCG-CSR-IDEVID must leave the order retryable in "ready"
// rather than stranded in "processing" with no path back to a usable
// state.
func TestOrderFinalizeHandler_MalformedCSRLeavesOrderReady(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	require.NoError(t, orderDAO.Save(ctx, order))

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString([]byte("this is not a valid CSR of any kind")),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)

	updated, err := orderDAO.Get(ctx, order.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusReady, updated.Status,
		"a malformed CSR must not strand the order in \"processing\"")
}

// TestOrderFinalizeHandler_CNLessCSRWithAuthorizedSANsSucceeds is the C1
// regression test for the "CN-less CSR" requirement: a CSR with no
// CommonName must still finalize successfully when its DNS SAN alone
// covers the order's authorized identifier exactly.
func TestOrderFinalizeHandler_CNLessCSRWithAuthorizedSANsSucceeds(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypeDNS, Value: "example.com"},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	require.NoError(t, orderDAO.Save(ctx, order))

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// No CommonName - the DNS SAN alone must satisfy the order.
	template := &x509.CertificateRequest{
		DNSNames: []string{"example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)

	var orderResp entities.ACMEOrder
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&orderResp))
	assert.Equal(t, common.StatusValid, orderResp.Status)
}

func TestOrderFinalizeHandler_SignCSRFailure(t *testing.T) {
	service, mockCA, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	// Configure mock to fail on SignCSR
	mockCA.shouldFailSignCSR = true

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	// Create valid CSR
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)

	// M2 regression: a failure occurring after the order has moved to
	// "processing" must drive it to the terminal "invalid" state with its
	// error populated, not leave it stuck in "processing" forever.
	updated, err := orderDAO.Get(ctx, order.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusInvalid, updated.Status)
	require.NotNil(t, updated.Error)
}

func TestOrderFinalizeHandler_VerifyFailure(t *testing.T) {
	service, mockCA, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	// Configure mock to fail on Verify
	mockCA.shouldFailVerify = true

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)

	updated, err := orderDAO.Get(ctx, order.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusInvalid, updated.Status)
	require.NotNil(t, updated.Error)
}

func TestOrderFinalizeHandler_TCGCSRNotImplemented(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create order with permanent-identifier type to trigger TCG-CSR path
	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypePermanentIdentifier, Value: "test-permanent-id"},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)
	authorizeOrder(t, service, account, order, order.Identifiers[0], "enroll-01")

	// Provide invalid CSR data to trigger TCG-CSR parsing attempt
	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString([]byte("invalid-csr-triggers-tcg")),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	// Should return malformed error since TCG-CSR is not implemented
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestOrderFinalizeHandler_WrongAccount(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	// Create two different accounts
	key1 := generateTestKey(t)
	account1 := createTestAccount(t, service, key1)

	key2 := generateTestKey(t)
	account2 := createTestAccount(t, service, key2)

	// Create order belonging to account2
	order := createTestOrderSimple(t, service, account2.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account2.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	// Try to finalize account2's order using account1's credentials
	// Since orders are partitioned by account, account1 won't find the order
	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key1, url, payload, true, account1.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	// Order not found because it's in a different account's partition
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

// Helper function tests

func TestEncodeCertificatePEM(t *testing.T) {
	derBytes := []byte("test-cert-der")
	pemBytes := encodeCertificatePEM(derBytes)

	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
	assert.Equal(t, derBytes, block.Bytes)
}

func TestEncodeCSRToPEM(t *testing.T) {
	derBytes := []byte("test-csr-der")
	pemBytes := encodeCSRToPEM(derBytes)

	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE REQUEST", block.Type)
	assert.Equal(t, derBytes, block.Bytes)
}

func TestMatchesIdentifier_DNS(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	require.NoError(t, err)
	assert.True(t, matches)
}

func TestMatchesIdentifier_DNSMismatch(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "different.com",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	require.NoError(t, err)
	assert.False(t, matches)
}

// createPermanentIdentifierCSR builds and parses a certificate request whose
// subjectAltName carries an RFC 4043 permanentIdentifier otherName for
// permanentID, together with the template's own DNS and IP names.
// crypto/x509 drops the template's own names once a subjectAltName
// extension is supplied via ExtraExtensions, so all of them are re-encoded
// here alongside the otherName - the same way createEndorse01CSRWithManufacturer
// does for endorse-01's directoryName.
func createPermanentIdentifierCSR(
	t *testing.T,
	template *x509.CertificateRequest,
	key crypto.Signer,
	permanentID string,
) *x509.CertificateRequest {
	t.Helper()

	value, err := ca.MarshalPermanentIdentifier(permanentID, ca.OIDTCGOnEKPermIdSha256)
	require.NoError(t, err)

	san, err := ca.BuildSubjectAltName(
		template.Subject, template.DNSNames, nil, template.IPAddresses, nil,
		[]ca.OtherName{{TypeID: ca.OIDPermanentIdentifier, Value: value}}, nil)
	require.NoError(t, err)

	withSAN := *template
	withSAN.ExtraExtensions = append(append([]pkix.Extension(nil), template.ExtraExtensions...), san)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &withSAN, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)
	return csr
}

// requireACMEErrorType asserts err is an ACME problem of the given type.
func requireACMEErrorType(t *testing.T, err error, errType string) {
	t.Helper()
	require.Error(t, err)
	acmeErr, ok := err.(*entities.Error)
	require.True(t, ok, "error is not *entities.Error: %v", err)
	assert.Contains(t, acmeErr.Type, errType)
}

// TestMatchesIdentifier_PermanentIdentifier is the baseline case: a CSR
// carrying only the authorized permanentIdentifier otherName, and no other
// SAN, matches.
func TestMatchesIdentifier_PermanentIdentifier(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test-permanent-id",
		},
	}
	csr := createPermanentIdentifierCSR(t, template, csrKey, "test-permanent-id")

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypePermanentIdentifier, Value: "test-permanent-id"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	require.NoError(t, err)
	assert.True(t, matches)
}

// TestMatchesIdentifier_PermanentIdentifierNeverUsesCommonName is the
// regression case for go-xkms#684: a CSR whose CommonName equals the
// authorized permanent identifier, but which carries no permanentIdentifier
// otherName at all, must be rejected as badCSR - the identifier must never
// be read from the Subject Common Name.
func TestMatchesIdentifier_PermanentIdentifierNeverUsesCommonName(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test-permanent-id",
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypePermanentIdentifier, Value: "test-permanent-id"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	assert.False(t, matches)
	requireACMEErrorType(t, err, common.ErrTypeBadCSR)
}

// TestMatchesIdentifier_PermanentIdentifierRejectsUnauthorizedDNSSAN is the
// go-xkms#684 headline case: a CSR whose CommonName and permanentIdentifier
// otherName both match the order, but which also carries a DNS SAN the
// order never authorized, must be rejected rather than silently issued.
func TestMatchesIdentifier_PermanentIdentifierRejectsUnauthorizedDNSSAN(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test-permanent-id",
		},
		DNSNames: []string{"evil.example.com"},
	}
	csr := createPermanentIdentifierCSR(t, template, csrKey, "test-permanent-id")

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypePermanentIdentifier, Value: "test-permanent-id"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	assert.False(t, matches)
	requireACMEErrorType(t, err, common.ErrTypeRejectedIdentifier)
}

// TestMatchesIdentifier_PermanentIdentifierRejectsUnauthorizedIPSAN mirrors
// the DNS case for an IP SAN.
func TestMatchesIdentifier_PermanentIdentifierRejectsUnauthorizedIPSAN(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test-permanent-id",
		},
		IPAddresses: []net.IP{net.ParseIP("203.0.113.42")},
	}
	csr := createPermanentIdentifierCSR(t, template, csrKey, "test-permanent-id")

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypePermanentIdentifier, Value: "test-permanent-id"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	assert.False(t, matches)
	requireACMEErrorType(t, err, common.ErrTypeRejectedIdentifier)
}

// TestMatchesIdentifier_PermanentIdentifierMissingOtherName verifies that a
// CSR with no subjectAltName extension at all is rejected as badCSR rather
// than falling back to the CommonName.
func TestMatchesIdentifier_PermanentIdentifierMissingOtherName(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test-permanent-id"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypePermanentIdentifier, Value: "test-permanent-id"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	assert.False(t, matches)
	requireACMEErrorType(t, err, common.ErrTypeBadCSR)
}

// TestMatchesIdentifier_PermanentIdentifierWrongOtherNameValue verifies that
// a CSR carrying a permanentIdentifier otherName whose value does not equal
// the order's authorized permanent identifier is rejected.
func TestMatchesIdentifier_PermanentIdentifierWrongOtherNameValue(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test-permanent-id"},
	}
	csr := createPermanentIdentifierCSR(t, template, csrKey, "wrong-permanent-id")

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypePermanentIdentifier, Value: "test-permanent-id"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	assert.False(t, matches)
	requireACMEErrorType(t, err, common.ErrTypeRejectedIdentifier)
}

// TestMatchesIdentifier_PermanentIdentifierWrongOtherNameType verifies that
// a CSR whose subjectAltName carries an otherName of some other type (here,
// the RFC 4108 hardwareModuleName) instead of a permanentIdentifier is
// rejected as badCSR.
func TestMatchesIdentifier_PermanentIdentifierWrongOtherNameType(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hwName, err := ca.MarshalHardwareModuleName(ca.OIDTCGHwTypeTPM2, []byte("serial"))
	require.NoError(t, err)
	san, err := ca.BuildSubjectAltName(
		pkix.Name{CommonName: "test-permanent-id"}, nil, nil, nil, nil,
		[]ca.OtherName{{TypeID: ca.OIDHardwareModuleName, Value: hwName}}, nil)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: "test-permanent-id"},
		ExtraExtensions: []pkix.Extension{san},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypePermanentIdentifier, Value: "test-permanent-id"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	assert.False(t, matches)
	requireACMEErrorType(t, err, common.ErrTypeBadCSR)
}

// TestMatchesIdentifier_PermanentIdentifierMalformedSAN verifies that a
// subjectAltName extension that is not a valid GeneralNames SEQUENCE is
// rejected as badCSR instead of silently falling back to the CommonName -
// the pre-fix behavior this pins against regressing.
func TestMatchesIdentifier_PermanentIdentifierMalformedSAN(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sanValue, err := asn1.Marshal([]string{"not-a-general-names-sequence"})
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test-cn"},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: sanValue},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypePermanentIdentifier, Value: "test-cn"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	assert.False(t, matches, "a malformed SAN must never fall back to the CommonName")
	requireACMEErrorType(t, err, common.ErrTypeBadCSR)
}

// TestMatchesIdentifier_PermanentIdentifierMultiIdentifierOrderRejectsMismatch
// is the multi-identifier regression case: an order authorizing both a
// permanent-identifier and a dns identifier must have BOTH satisfied. Before
// the fix, matchesIdentifier returned on the first permanent-identifier
// order entry it found and never checked the rest.
func TestMatchesIdentifier_PermanentIdentifierMultiIdentifierOrderRejectsMismatch(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "device-1"},
		DNSNames: []string{"wrong.example.com"},
	}
	csr := createPermanentIdentifierCSR(t, template, csrKey, "device-1")

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypePermanentIdentifier, Value: "device-1"},
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	assert.False(t, matches, "the CSR's DNS SAN does not match the order's second identifier")
	requireACMEErrorType(t, err, common.ErrTypeRejectedIdentifier)
}

// TestMatchesIdentifier_PermanentIdentifierMultiIdentifierOrderMatches is the
// positive counterpart: every identifier the order authorizes, permanent and
// dns alike, is satisfied.
func TestMatchesIdentifier_PermanentIdentifierMultiIdentifierOrderMatches(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "device-1"},
		DNSNames: []string{"example.com"},
	}
	csr := createPermanentIdentifierCSR(t, template, csrKey, "device-1")

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypePermanentIdentifier, Value: "device-1"},
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	require.NoError(t, err)
	assert.True(t, matches)
}

func TestMatchesIdentifier_UnsupportedType(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: "unsupported-type", Value: "test"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	require.Error(t, err)
	assert.False(t, matches)

	acmeErr, ok := err.(*entities.Error)
	require.True(t, ok)
	assert.Contains(t, acmeErr.Type, common.ErrTypeUnsupportedIdentifier)
}

func TestMatchesIdentifier_MultipleIdentifiers(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// A CSR must cover the order's COMPLETE set of authorized identifiers,
	// not merely intersect with it: CN + SANs together account for both
	// "different.com" and "example.com" below.
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com", "different.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "different.com"},
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	require.NoError(t, err)
	assert.True(t, matches)
}

// TestMatchesIdentifier_UnauthorizedSAN is the C1 regression test: a CSR
// whose CommonName is authorized but which also carries an unauthorized
// DNS SAN must be rejected. Before the fix, matchesIdentifier only ever
// compared the CommonName, so "evil.com" here would have been silently
// copied into the issued certificate.
func TestMatchesIdentifier_UnauthorizedSAN(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com", "evil.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	require.NoError(t, err)
	assert.False(t, matches, "CSR carrying an unauthorized SAN must not match the order")
}

// TestMatchesIdentifier_UnauthorizedIPSAN covers the same C1 gap for IP SANs.
func TestMatchesIdentifier_UnauthorizedIPSAN(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		IPAddresses: []net.IP{net.ParseIP("203.0.113.5")},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	require.NoError(t, err)
	assert.False(t, matches, "CSR carrying an unauthorized IP SAN must not match the order")
}

// TestMatchesIdentifier_CNLessWithAuthorizedSANs verifies that a CSR with no
// CommonName is still valid when its SANs alone cover the authorized
// identifier set exactly.
func TestMatchesIdentifier_CNLessWithAuthorizedSANs(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		DNSNames: []string{"example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	require.NoError(t, err)
	assert.True(t, matches)
}

// TestMatchesIdentifier_MissingAuthorizedIdentifier verifies that a CSR
// which omits one of the order's authorized identifiers is rejected: the
// two sets must correspond exactly, in both directions.
func TestMatchesIdentifier_MissingAuthorizedIdentifier(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "example.com"},
			{Type: common.AuthzTypeDNS, Value: "other.example.com"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	require.NoError(t, err)
	assert.False(t, matches)
}

// TestMatchesIdentifier_EmailSANRejected verifies that a CSR carrying an
// email address SAN is rejected outright, regardless of whether its other
// identifiers are authorized.
func TestMatchesIdentifier_EmailSANRejected(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		EmailAddresses: []string{"attacker@example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	require.Error(t, err)
	assert.False(t, matches)
	acmeErr, ok := err.(*entities.Error)
	require.True(t, ok)
	assert.Contains(t, acmeErr.Type, common.ErrTypeMalformedError)
}

// TestMatchesIdentifier_URISANRejected verifies that a CSR carrying a URI
// SAN is rejected outright.
func TestMatchesIdentifier_URISANRejected(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	uri, err := url.Parse("https://example.com/attacker")
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		URIs: []*url.URL{uri},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "example.com"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	require.Error(t, err)
	assert.False(t, matches)
	acmeErr, ok := err.(*entities.Error)
	require.True(t, ok)
	assert.Contains(t, acmeErr.Type, common.ErrTypeMalformedError)
}

// TestMatchesEndorse01Identifier_RejectsUnauthorizedSAN verifies that the
// endorse-01 matching path - which intentionally does not compare the CSR's
// CommonName against the order's permanent identifier - still enforces
// exact correspondence for any DNS/IP SAN the CSR carries.
func TestMatchesEndorse01Identifier_RejectsUnauthorizedSAN(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "device-123",
		},
		DNSNames: []string{"evil.example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypePermanentIdentifier, Value: "irrelevant-ek-pubkey-b64"},
		},
	}

	matches, err := matchesEndorse01Identifier(csr, order)
	require.NoError(t, err)
	assert.False(t, matches)
}

// TestMatchesEndorse01Identifier_NoSANsMatches verifies the common
// endorse-01 case: no DNS/IP SANs requested, none authorized, and the CN is
// not checked against the permanent identifier.
func TestMatchesEndorse01Identifier_NoSANsMatches(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "device-123",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypePermanentIdentifier, Value: "irrelevant-ek-pubkey-b64"},
		},
	}

	matches, err := matchesEndorse01Identifier(csr, order)
	require.NoError(t, err)
	assert.True(t, matches)
}

// TestMatchesEndorse01Identifier_EmailSANRejected verifies the endorse-01
// path also rejects email SANs outright.
func TestMatchesEndorse01Identifier_EmailSANRejected(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "device-123",
		},
		EmailAddresses: []string{"attacker@example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypePermanentIdentifier, Value: "irrelevant-ek-pubkey-b64"},
		},
	}

	matches, err := matchesEndorse01Identifier(csr, order)
	require.Error(t, err)
	assert.False(t, matches)
}

// TestMatchesIdentifier_PermanentIdentifierError verifies that a CSR with
// neither a CommonName nor a subjectAltName extension - so there is nothing
// to even attempt to parse - is rejected as badCSR.
func TestMatchesIdentifier_PermanentIdentifierError(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypePermanentIdentifier, Value: "test-id"},
		},
	}

	matches, err := matchesIdentifier(csr, order)
	assert.False(t, matches)
	requireACMEErrorType(t, err, common.ErrTypeBadCSR)
}

func TestSendFinalizeResponse_Success(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusProcessing

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	serialNumber := "d431" // hex encoding of decimal 54321
	certPEM := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")

	w := httptest.NewRecorder()
	service.sendFinalizeResponse(ctx, orderDAO, order, account, time.Now(), serialNumber, certPEM, w)

	require.Equal(t, http.StatusOK, w.Code)

	var orderResp entities.ACMEOrder
	err = json.NewDecoder(w.Body).Decode(&orderResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusValid, orderResp.Status)
	assert.Contains(t, orderResp.Certificate, fmt.Sprintf("/acme/cert/%s", serialNumber))
}

// TestSendFinalizeResponse_FullSerialNotTruncated verifies that a serial
// number too large to fit in a uint64 (128 bits, matching pkg/ca's serial
// generator) survives sendFinalizeResponse intact: neither the certificate
// URL nor the stored ACMECertificate record truncates it. This is the
// regression test for go-xkms#744.
func TestSendFinalizeResponse_FullSerialNotTruncated(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusProcessing

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	// 128 bits of hex digits: far larger than math.MaxUint64.
	serialNumber := "ffeeddccbbaa99887766554433221100"
	certPEM := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")

	w := httptest.NewRecorder()
	service.sendFinalizeResponse(ctx, orderDAO, order, account, time.Now(), serialNumber, certPEM, w)

	require.Equal(t, http.StatusOK, w.Code)

	var orderResp entities.ACMEOrder
	err = json.NewDecoder(w.Body).Decode(&orderResp)
	require.NoError(t, err)
	assert.Contains(t, orderResp.Certificate, "/acme/cert/"+serialNumber)

	certDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)
	stored, err := certDAO.Get(ctx, entities.StringToEntityID(serialNumber))
	require.NoError(t, err)
	assert.Equal(t, serialNumber, stored.Serial)
}

func TestOrderFinalizeHandler_MalformedJWS(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	url := service.baseRESTURI + "/acme/orders/123/finalize"
	req := createInvalidJWSRequest(t, url)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestOrderFinalizeHandler_InvalidRequestPayload(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	// Create invalid payload (not JSON)
	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)

	// Create a JWS with invalid JSON payload

	// We'll use the test helper but encode invalid JSON-like string
	// Actually, let's just send malformed payload through parseKID
	// The easier way is to just test with empty/malformed CSR field

	// Send empty object which will fail CSR decoding
	payload := map[string]string{} // Missing CSR field

	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	// Should fail on CSR decoding
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestOrderFinalizeHandler_NilSerialNumber(t *testing.T) {
	service, mockCA, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	mockCA.returnCertWithNilSerial = true

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

func TestOrderFinalizeHandler_LargeSerialNumber(t *testing.T) {
	service, mockCA, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	mockCA.returnCertWithLargeSerial = true

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	// Should succeed, and the certificate URL must carry the serial's full
	// precision (hex-encoded), not a value truncated to fit a uint64
	// (go-xkms#744): the low 64 bits of this serial alone would collide
	// with other certificates the mock CA could plausibly issue.
	require.Equal(t, http.StatusOK, resp.Code)

	expectedSerial := new(big.Int)
	_, ok := expectedSerial.SetString("18446744073709551616999999999999999", 10)
	require.True(t, ok)

	var orderResp entities.ACMEOrder
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&orderResp))
	assert.Contains(t, orderResp.Certificate, "/acme/cert/"+expectedSerial.Text(16))
}

func TestOrderFinalizeHandler_PermanentIdentifierEKCertificate(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Generate an EK public key and encode it as base64url PKIX for the permanent identifier
	ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ekPubKeyBytes, err := x509.MarshalPKIXPublicKey(&ekKey.PublicKey)
	require.NoError(t, err)
	ekPubKeyB64 := base64.RawURLEncoding.EncodeToString(ekPubKeyBytes)

	// Create order with permanent-identifier for endorse-01 EK certificate flow
	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypePermanentIdentifier, Value: ekPubKeyB64},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)
	authorizeOrder(t, service, account, order, order.Identifiers[0], "endorse-01")

	// Create a valid x509 CSR (not TCG-CSR) with permanent identifier
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// No DNS/IP/email SANs: the order's only authorized identifier is the
	// permanent-identifier (the EK public key), so matchesEndorse01Identifier
	// requires the CSR to carry no other names.
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         "device-123",
			Organization:       []string{"Test Org"},
			OrganizationalUnit: []string{"Test Unit"},
			Country:            []string{"US"},
			Locality:           []string{"Test City"},
			Province:           []string{"Test State"},
		},
	}

	csrDER := createEndorse01CSR(t, template, csrKey)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	// Should succeed with EK certificate issuance
	require.Equal(t, http.StatusOK, resp.Code)

	var orderResp entities.ACMEOrder
	err = json.NewDecoder(resp.Body).Decode(&orderResp)
	require.NoError(t, err)
	assert.Equal(t, common.StatusValid, orderResp.Status)
}

// TestOrderFinalizeHandler_EndorseEKCertificateRejectsUnauthorizedSAN is the
// end-to-end C1 regression test for the endorse-01 flow: a CSR that pairs a
// permanent-identifier order with a DNS SAN the order never authorized must
// be rejected rather than have that SAN copied into the issued EK
// certificate (see pkg/ca.CA.IssueEKCertificate).
func TestOrderFinalizeHandler_EndorseEKCertificateRejectsUnauthorizedSAN(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ekPubKeyBytes, err := x509.MarshalPKIXPublicKey(&ekKey.PublicKey)
	require.NoError(t, err)
	ekPubKeyB64 := base64.RawURLEncoding.EncodeToString(ekPubKeyBytes)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypePermanentIdentifier, Value: ekPubKeyB64},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	require.NoError(t, orderDAO.Save(ctx, order))
	authorizeOrder(t, service, account, order, order.Identifiers[0], common.ChallengeTypeEndorse01)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "device-123",
		},
		// Not authorized by the order: only the permanent identifier is.
		DNSNames: []string{"unauthorized.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)

	// The order must remain retryable, not stranded in "processing" (M2):
	// identifier validation happens before the order ever transitions.
	updated, err := orderDAO.Get(ctx, order.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusReady, updated.Status)
}

func TestOrderFinalizeHandler_IssueEKCertificateFailure(t *testing.T) {
	service, mockCA, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	mockCA.shouldFailIssueEK = true

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Generate an EK public key and encode it as base64url PKIX for the permanent identifier
	ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ekPubKeyBytes, err := x509.MarshalPKIXPublicKey(&ekKey.PublicKey)
	require.NoError(t, err)
	ekPubKeyB64 := base64.RawURLEncoding.EncodeToString(ekPubKeyBytes)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypePermanentIdentifier, Value: ekPubKeyB64},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "device-123",
		},
	}

	csrDER := createEndorse01CSR(t, template, csrKey)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

func TestOrderFinalizeHandler_WithOrderFinalizeHooks(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	// Track hook execution
	hookExecuted := false

	// Register hook
	registry := NewOrderFinalizeHookRegistry()
	registry.Register(func(ctx *OrderFinalizeHookContext) error {
		hookExecuted = true
		// Verify context fields
		assert.NotNil(t, ctx.Certificate)
		assert.NotNil(t, ctx.CertificatePEM)
		assert.NotNil(t, ctx.CSR)
		assert.False(t, ctx.IsTCGCSR)
		return nil
	})

	service.params = &Params{
		OrderFinalizeHooks: registry,
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.True(t, hookExecuted, "Hook should have been executed")
}

func TestOrderFinalizeHandler_OrderFinalizeHookFailure(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	// Register hook that fails
	registry := NewOrderFinalizeHookRegistry()
	registry.Register(func(ctx *OrderFinalizeHookContext) error {
		return caerrors.InternalServerError("hook execution failed")
	})

	service.params = &Params{
		OrderFinalizeHooks: registry,
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// MockStorageFactory for testing storage failures
type MockStorageFactory struct {
	realFactory           storage.Factory
	failOrderDAOCreate    bool
	failCertDAOCreate     bool
	failCertDAOSave       bool
	failOrderDAOSave      bool
	orderDAOSaveCallCount int
}

func (m *MockStorageFactory) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	if m.failOrderDAOCreate {
		return nil, caerrors.StorageFailureError("mock order DAO creation failure")
	}
	dao, err := m.realFactory.OrderDAO(accountID)
	if err != nil {
		return nil, err
	}
	return &MockOrderDAO{
		GenericDAO:     dao,
		failSave:       m.failOrderDAOSave,
		saveCallCount:  &m.orderDAOSaveCallCount,
		saveFailOnCall: 2, // Fail on second save (after processing status update)
	}, nil
}

func (m *MockStorageFactory) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	if m.failCertDAOCreate {
		return nil, caerrors.StorageFailureError("mock certificate DAO creation failure")
	}
	dao, err := m.realFactory.CertificateDAO()
	if err != nil {
		return nil, err
	}
	return &MockCertificateDAO{
		GenericDAO: dao,
		failSave:   m.failCertDAOSave,
	}, nil
}

func (m *MockStorageFactory) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	return m.realFactory.AccountDAO()
}

func (m *MockStorageFactory) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	return m.realFactory.NonceDAO()
}

func (m *MockStorageFactory) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return m.realFactory.AuthorizationDAO(accountID)
}

func (m *MockStorageFactory) ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return m.realFactory.ChallengeDAO(accountID)
}

func (m *MockStorageFactory) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return m.realFactory.ExternalAccountBindingDAO()
}

// MockOrderDAO for testing order save failures.
// It embeds the real DAO to delegate all methods and overrides Save.
type MockOrderDAO struct {
	qrdbsdk.GenericDAO[*entities.ACMEOrder]
	failSave       bool
	saveCallCount  *int
	saveFailOnCall int
}

func (m *MockOrderDAO) Save(ctx context.Context, order *entities.ACMEOrder) error {
	*m.saveCallCount++
	if m.failSave && *m.saveCallCount >= m.saveFailOnCall {
		return caerrors.StorageFailureError("mock order save failure")
	}
	return m.GenericDAO.Save(ctx, order)
}

// MockCertificateDAO for testing certificate save failures.
// It embeds the real DAO to delegate all methods and overrides Save.
type MockCertificateDAO struct {
	qrdbsdk.GenericDAO[*entities.ACMECertificate]
	failSave bool
}

func (m *MockCertificateDAO) Save(ctx context.Context, cert *entities.ACMECertificate) error {
	if m.failSave {
		return caerrors.StorageFailureError("mock certificate save failure")
	}
	return m.GenericDAO.Save(ctx, cert)
}

// SaveIfAbsent must also fail when failSave is set: storage.SaveCertificateNoCollision
// (go-xkms#744 follow-up) tries SaveIfAbsent before ever calling Save, so a
// mock that only overrode Save would let a real SaveIfAbsent succeed and
// mask the injected failure.
func (m *MockCertificateDAO) SaveIfAbsent(ctx context.Context, cert *entities.ACMECertificate) (bool, error) {
	if m.failSave {
		return false, caerrors.StorageFailureError("mock certificate save failure")
	}
	return m.GenericDAO.SaveIfAbsent(ctx, cert)
}

func TestSendFinalizeResponse_CertDAOCreationFailure(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	// Replace storage factory with mock that fails on CertDAO creation
	mockFactory := &MockStorageFactory{
		realFactory:       service.storageFactory,
		failCertDAOCreate: true,
	}
	service.storageFactory = mockFactory

	serialNumber := "3039" // hex encoding of decimal 12345
	certPEM := []byte("test-cert-pem")

	w := httptest.NewRecorder()
	service.sendFinalizeResponse(ctx, orderDAO, order, account, time.Now(), serialNumber, certPEM, w)

	assertErrorType(t, w, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

func TestSendFinalizeResponse_CertSaveFailure(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	// Replace storage factory with mock that fails on cert save
	mockFactory := &MockStorageFactory{
		realFactory:     service.storageFactory,
		failCertDAOSave: true,
	}
	service.storageFactory = mockFactory

	serialNumber := "3039" // hex encoding of decimal 12345
	certPEM := []byte("test-cert-pem")

	w := httptest.NewRecorder()
	service.sendFinalizeResponse(ctx, orderDAO, order, account, time.Now(), serialNumber, certPEM, w)

	assertErrorType(t, w, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

func TestSendFinalizeResponse_OrderSaveFailure(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	// Save the order first
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	// Now replace the storage factory with one that fails on order saves
	// We need to ensure the certificate saves but order save fails
	mockFactory := &MockStorageFactory{
		realFactory:      service.storageFactory,
		failOrderDAOSave: true,
	}
	// The DAO will fail on the FIRST save call (saveFailOnCall=1 means fail when count >= 1)
	// But our MockOrderDAO starts counting from the first Save() call
	// Since sendFinalizeResponse will be the first to call Save on this new DAO,
	// we want it to fail immediately
	mockFactory.orderDAOSaveCallCount = 0

	service.storageFactory = mockFactory

	// Get a fresh orderDAO from the mock factory
	mockOrderDAO, err := mockFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	// Override to fail on first call (count will be 1 after first save)
	if dao, ok := mockOrderDAO.(*MockOrderDAO); ok {
		dao.saveFailOnCall = 1
	}

	serialNumber := "3039" // hex encoding of decimal 12345
	certPEM := []byte("test-cert-pem")

	w := httptest.NewRecorder()
	service.sendFinalizeResponse(ctx, mockOrderDAO, order, account, time.Now(), serialNumber, certPEM, w)

	assertErrorType(t, w, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

func TestOrderFinalizeHandler_OrderDAOCreationFailure(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Replace storage factory with mock that fails on OrderDAO creation
	mockFactory := &MockStorageFactory{
		realFactory:        service.storageFactory,
		failOrderDAOCreate: true,
	}
	service.storageFactory = mockFactory

	payload := OrderFinalizeRequest{
		CSR: "dGVzdC1jc3I",
	}

	url := fmt.Sprintf("%s/acme/orders/123/finalize", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": "123"})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

func TestOrderFinalizeHandler_OrderStatusUpdateFailure(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	// Replace storage factory with mock that fails on first order save (status update)
	mockFactory := &MockStorageFactory{
		realFactory:      service.storageFactory,
		failOrderDAOSave: true,
	}
	service.storageFactory = mockFactory

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// testEndorseTPMManufacturer is the TCG manufacturer code an endorse-01 test
// device asserts: swtpm's ("IBM").
const testEndorseTPMManufacturer = "id:49424D00"

// createEndorse01CSR signs an endorse-01 certificate request that asserts
// testEndorseTPMManufacturer, the way the endorse-01 client does.
func createEndorse01CSR(t *testing.T, template *x509.CertificateRequest, key crypto.Signer) []byte {
	t.Helper()
	return createEndorse01CSRWithManufacturer(t, template, key, testEndorseTPMManufacturer)
}

// createEndorse01CSRWithManufacturer signs a certificate request whose
// subjectAltName carries the template's DNS and IP names and a directoryName
// asserting manufacturer. crypto/x509 drops the template's own names once a
// subjectAltName extension is supplied, so all of them are encoded here.
func createEndorse01CSRWithManufacturer(t *testing.T, template *x509.CertificateRequest, key crypto.Signer, manufacturer string) []byte {
	t.Helper()
	san, err := ca.BuildSubjectAltName(template.Subject, template.DNSNames, nil, template.IPAddresses, nil, nil,
		[]pkix.Name{{ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: ca.OIDTCGAttributeTPMManufacturer, Value: manufacturer},
		}}})
	require.NoError(t, err)

	withSAN := *template
	withSAN.ExtraExtensions = append(append([]pkix.Extension(nil), template.ExtraExtensions...), san)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &withSAN, key)
	require.NoError(t, err)
	return csrDER
}

// endorse01Fixture is an account with a ready endorse-01 order awaiting
// finalize.
type endorse01Fixture struct {
	service  *RestService
	mockCA   *MockCAForFinalize
	key      *TestKey
	account  *entities.ACMEAccount
	order    *entities.ACMEOrder
	orderDAO qrdbsdk.GenericDAO[*entities.ACMEOrder]
}

// newEndorse01Fixture creates the account and its ready endorse-01 order.
func newEndorse01Fixture(t *testing.T) *endorse01Fixture {
	t.Helper()
	return newEndorse01FixtureValidatedBy(t, common.ChallengeTypeEndorse01)
}

// newEndorse01FixtureValidatedBy is newEndorse01Fixture for an order whose
// authorization challengeType validated.
func newEndorse01FixtureValidatedBy(t *testing.T, challengeType string) *endorse01Fixture {
	t.Helper()
	service, mockCA, cleanup := setupTestServiceWithMockCA(t)
	t.Cleanup(cleanup)

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ekPubKeyBytes, err := x509.MarshalPKIXPublicKey(&ekKey.PublicKey)
	require.NoError(t, err)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypePermanentIdentifier, Value: base64.RawURLEncoding.EncodeToString(ekPubKeyBytes)},
	}
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	require.NoError(t, orderDAO.Save(context.Background(), order))
	authorizeOrder(t, service, account, order, order.Identifiers[0], challengeType)

	return &endorse01Fixture{service: service, mockCA: mockCA, key: key, account: account, order: order, orderDAO: orderDAO}
}

// bindEAB records an endorse-01 external account binding for the fixture's
// account, authorizing the given TPM manufacturer code.
func (f *endorse01Fixture) bindEAB(t *testing.T, manufacturer string) {
	t.Helper()
	ctx := context.Background()
	binding := createTestEABBinding("endorse-kid-"+manufacturer, f.account.ID, entities.EABStatusUsed)
	binding.DeviceInfo = &entities.EABDeviceInfo{TPMManufacturer: manufacturer}
	eabDAO, err := f.service.storageFactory.ExternalAccountBindingDAO()
	require.NoError(t, err)
	require.NoError(t, eabDAO.Save(ctx, binding))

	f.account.ExternalAccountBinding = map[string]interface{}{"kid": binding.ID}
	accountDAO, err := f.service.storageFactory.AccountDAO()
	require.NoError(t, err)
	require.NoError(t, accountDAO.Save(ctx, f.account))
}

// finalize submits csrDER to the fixture's order.
func (f *endorse01Fixture) finalize(t *testing.T, csrDER []byte) *httptest.ResponseRecorder {
	t.Helper()
	payload := OrderFinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString(csrDER)}
	url := fmt.Sprintf("%s/acme/orders/%d/finalize", f.service.baseRESTURI, f.order.ID)
	req := createJWSRequest(t, f.service, f.key, url, payload, true, f.account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", f.order.ID)})
	resp := httptest.NewRecorder()
	f.service.OrderFinalizeHandler(resp, req)
	return resp
}

// endorse01CSRKey returns a fresh key to sign an endorse-01 request with.
func endorse01CSRKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// TestOrderFinalizeHandler_Endorse01RecordsAssertedManufacturer is the
// regression for EK certificates that could never be used for enroll-01: the
// manufacturer code the device asserts must reach the EK certificate request.
func TestOrderFinalizeHandler_Endorse01RecordsAssertedManufacturer(t *testing.T) {
	f := newEndorse01Fixture(t)
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "lab-node-5-ek"}}

	resp := f.finalize(t, createEndorse01CSR(t, template, endorse01CSRKey(t)))

	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	require.NotNil(t, f.mockCA.lastEKRequest)
	assert.Equal(t, testEndorseTPMManufacturer, f.mockCA.lastEKRequest.TPMManufacturer)
}

// TestOrderFinalizeHandler_Endorse01RefusesMissingOrMalformedManufacturer
// covers the error paths: without a well-formed code the EK certificate would
// name no TPM, so finalize is refused with badCSR, nothing is issued, and the
// order stays ready for a corrected request.
func TestOrderFinalizeHandler_Endorse01RefusesMissingOrMalformedManufacturer(t *testing.T) {
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "lab-node-5-ek"}}

	t.Run("missing", func(t *testing.T) {
		f := newEndorse01Fixture(t)
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, endorse01CSRKey(t))
		require.NoError(t, err)

		resp := f.finalize(t, csrDER)

		assertErrorType(t, resp, common.ErrTypeBadCSR, http.StatusBadRequest)
		assert.Nil(t, f.mockCA.lastEKRequest)
		updated, err := f.orderDAO.Get(context.Background(), f.order.ID)
		require.NoError(t, err)
		assert.Equal(t, common.StatusReady, updated.Status)
	})

	t.Run("malformed", func(t *testing.T) {
		f := newEndorse01Fixture(t)

		resp := f.finalize(t, createEndorse01CSRWithManufacturer(t, template, endorse01CSRKey(t), "Infineon"))

		assertErrorType(t, resp, common.ErrTypeBadCSR, http.StatusBadRequest)
		assert.Nil(t, f.mockCA.lastEKRequest)
	})
}

// TestOrderFinalizeHandler_Endorse01ManufacturerBoundByEAB covers the binding:
// an operator who registered the device with a manufacturer code limits what
// the device may assert.
func TestOrderFinalizeHandler_Endorse01ManufacturerBoundByEAB(t *testing.T) {
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "lab-node-5-ek"}}

	t.Run("matching", func(t *testing.T) {
		f := newEndorse01Fixture(t)
		f.bindEAB(t, testEndorseTPMManufacturer)

		resp := f.finalize(t, createEndorse01CSR(t, template, endorse01CSRKey(t)))

		require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
		require.NotNil(t, f.mockCA.lastEKRequest)
		assert.Equal(t, testEndorseTPMManufacturer, f.mockCA.lastEKRequest.TPMManufacturer)
	})

	t.Run("mismatched", func(t *testing.T) {
		f := newEndorse01Fixture(t)
		f.bindEAB(t, "id:49465800")

		resp := f.finalize(t, createEndorse01CSR(t, template, endorse01CSRKey(t)))

		assertErrorType(t, resp, common.ErrTypeUnauthorized, http.StatusUnauthorized)
		assert.Nil(t, f.mockCA.lastEKRequest)
		updated, err := f.orderDAO.Get(context.Background(), f.order.ID)
		require.NoError(t, err)
		assert.Equal(t, common.StatusReady, updated.Status)
	})
}
