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
	"net/http"
	"net/http/httptest"
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
}

func (m *MockCAForFinalize) SignCSR(csrPEM []byte, opts *ca.SignOptions) (*x509.Certificate, error) {
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

func (m *MockCAForFinalize) IssueEKCertificate(req *ca.CertificateRequest, pubKey crypto.PublicKey) (*x509.Certificate, error) {
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

func TestMatchesIdentifier_PermanentIdentifier(t *testing.T) {
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

func TestParseCertificateRequestPermanentIdentifier(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create CSR with common name (fallback)
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test-identifier",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	permanentID, err := parseCertificateRequestPermanentIdentifier(csr)
	require.NoError(t, err)
	assert.Equal(t, "test-identifier", permanentID)
}

func TestParseCertificateRequestPermanentIdentifier_NoCommonName(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create CSR without common name
	template := &x509.CertificateRequest{
		Subject: pkix.Name{},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	_, err = parseCertificateRequestPermanentIdentifier(csr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no permanent identifier found")
}

func TestParseCertificateRequestPermanentIdentifier_WithSANExtension(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create CSR with SAN extension
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	sanValue, err := asn1.Marshal([]string{"test-san"})
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test-cn",
		},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    sanOID,
				Value: sanValue,
			},
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	// Should still fall back to common name since we don't parse SAN properly
	permanentID, err := parseCertificateRequestPermanentIdentifier(csr)
	require.NoError(t, err)
	assert.Equal(t, "test-cn", permanentID)
}

func TestMatchesIdentifier_MultipleIdentifiers(t *testing.T) {
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

	// Order with multiple identifiers where one matches
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

func TestMatchesIdentifier_PermanentIdentifierError(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// CSR without common name to trigger error in parseCertificateRequestPermanentIdentifier
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
	require.Error(t, err)
	assert.False(t, matches)

	acmeErr, ok := err.(*entities.Error)
	require.True(t, ok)
	assert.Contains(t, acmeErr.Type, common.ErrTypeMalformedError)
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

	serialNumber := uint64(54321)
	certPEM := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")

	w := httptest.NewRecorder()
	service.sendFinalizeResponse(ctx, orderDAO, order, serialNumber, certPEM, w)

	require.Equal(t, http.StatusOK, w.Code)

	var orderResp entities.ACMEOrder
	err = json.NewDecoder(w.Body).Decode(&orderResp)
	require.NoError(t, err)

	assert.Equal(t, common.StatusValid, orderResp.Status)
	assert.Contains(t, orderResp.Certificate, fmt.Sprintf("/acme/cert/%d", serialNumber))
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

	// Get a valid nonce
	nonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(nonce)

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

	// Should succeed - large serial numbers are handled by taking modulo
	require.Equal(t, http.StatusOK, resp.Code)
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

	// Create a valid x509 CSR (not TCG-CSR) with permanent identifier
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         "device-123",
			Organization:       []string{"Test Org"},
			OrganizationalUnit: []string{"Test Unit"},
			Country:            []string{"US"},
			Locality:           []string{"Test City"},
			Province:           []string{"Test State"},
		},
		DNSNames:       []string{"device.example.com"},
		EmailAddresses: []string{"test@example.com"},
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

	// Should succeed with EK certificate issuance
	require.Equal(t, http.StatusOK, resp.Code)

	var orderResp entities.ACMEOrder
	err = json.NewDecoder(resp.Body).Decode(&orderResp)
	require.NoError(t, err)
	assert.Equal(t, common.StatusValid, orderResp.Status)
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

	serialNumber := uint64(12345)
	certPEM := []byte("test-cert-pem")

	w := httptest.NewRecorder()
	service.sendFinalizeResponse(ctx, orderDAO, order, serialNumber, certPEM, w)

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

	serialNumber := uint64(12345)
	certPEM := []byte("test-cert-pem")

	w := httptest.NewRecorder()
	service.sendFinalizeResponse(ctx, orderDAO, order, serialNumber, certPEM, w)

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

	serialNumber := uint64(12345)
	certPEM := []byte("test-cert-pem")

	w := httptest.NewRecorder()
	service.sendFinalizeResponse(ctx, mockOrderDAO, order, serialNumber, certPEM, w)

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
