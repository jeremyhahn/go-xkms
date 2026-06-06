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

package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"

	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockACMEServer creates a mock ACME server for testing
type mockACMEServer struct {
	*httptest.Server
	t             *testing.T
	nonce         string
	orderStatus   string
	authzStatus   string
	chalStatus    string
	certDER       []byte
	_             string // placeholder to maintain struct alignment
	orderCount    int
	authzCount    int
	chalCount     int
	finalizeCount int
}

// newMockACMEServer creates a new mock ACME server with httptest
func newMockACMEServer(t *testing.T) *mockACMEServer {
	m := &mockACMEServer{
		t:           t,
		nonce:       "mock-nonce-12345",
		orderStatus: "pending",
		authzStatus: "pending",
		chalStatus:  "pending",
	}

	// Generate test certificate
	certDER, _ := generateTestCert(t)
	m.certDER = certDER

	mux := http.NewServeMux()

	// Directory endpoint
	mux.HandleFunc("/directory", m.handleDirectory)

	// New nonce endpoint
	mux.HandleFunc("/acme/new-nonce", m.handleNewNonce)

	// New account endpoint
	mux.HandleFunc("/acme/new-account", m.handleNewAccount)

	// New order endpoint
	mux.HandleFunc("/acme/new-order", m.handleNewOrder)

	// Order endpoint
	mux.HandleFunc("/acme/order/", m.handleOrder)

	// Authorization endpoint
	mux.HandleFunc("/acme/authz/", m.handleAuthz)

	// Challenge endpoint
	mux.HandleFunc("/acme/challenge/", m.handleChallenge)

	// Finalize endpoint
	mux.HandleFunc("/acme/finalize/", m.handleFinalize)

	// Certificate endpoint
	mux.HandleFunc("/acme/cert/", m.handleCert)

	// CA bundle endpoint
	mux.HandleFunc("/ca-bundle", m.handleCABundle)

	m.Server = httptest.NewTLSServer(mux)
	return m
}

func (m *mockACMEServer) handleDirectory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce)
	w.Header().Set("Content-Type", "application/json")

	directory := map[string]interface{}{
		"newNonce":   m.URL + "/acme/new-nonce",
		"newAccount": m.URL + "/acme/new-account",
		"newOrder":   m.URL + "/acme/new-order",
		"revokeCert": m.URL + "/acme/revoke-cert",
		"keyChange":  m.URL + "/acme/key-change",
		"meta": map[string]interface{}{
			"termsOfService":          "https://example.com/terms",
			"externalAccountRequired": false,
		},
	}

	_ = json.NewEncoder(w).Encode(directory)
}

func (m *mockACMEServer) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (m *mockACMEServer) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", m.URL+"/acme/account/1")

	account := map[string]interface{}{
		"status":  "valid",
		"contact": []string{"mailto:test@example.com"},
		"orders":  m.URL + "/acme/account/1/orders",
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(account)
}

func (m *mockACMEServer) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	m.orderCount++
	w.Header().Set("Replay-Nonce", m.nonce)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", m.URL+"/acme/order/1")

	order := map[string]interface{}{
		"status":      m.orderStatus,
		"expires":     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"identifiers": []map[string]string{{"type": "dns", "value": "example.com"}},
		"authorizations": []string{
			m.URL + "/acme/authz/1",
		},
		"finalize": m.URL + "/acme/finalize/1",
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(order)
}

func (m *mockACMEServer) handleOrder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce)
	w.Header().Set("Content-Type", "application/json")

	order := map[string]interface{}{
		"status":      m.orderStatus,
		"expires":     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"identifiers": []map[string]string{{"type": "dns", "value": "example.com"}},
		"authorizations": []string{
			m.URL + "/acme/authz/1",
		},
		"finalize":    m.URL + "/acme/finalize/1",
		"certificate": m.URL + "/acme/cert/1",
	}

	_ = json.NewEncoder(w).Encode(order)
}

func (m *mockACMEServer) handleAuthz(w http.ResponseWriter, r *http.Request) {
	m.authzCount++
	w.Header().Set("Replay-Nonce", m.nonce)
	w.Header().Set("Content-Type", "application/json")

	authz := map[string]interface{}{
		"status": m.authzStatus,
		"identifier": map[string]string{
			"type":  "dns",
			"value": "example.com",
		},
		"challenges": []map[string]interface{}{
			{
				"type":   "http-01",
				"url":    m.URL + "/acme/challenge/1",
				"token":  "mock-challenge-token-12345",
				"status": m.chalStatus,
			},
			{
				"type":   "enroll-01",
				"url":    m.URL + "/acme/challenge/2",
				"token":  "mock-enroll-token-12345",
				"status": m.chalStatus,
			},
			{
				"type":   "device-attest-01",
				"url":    m.URL + "/acme/challenge/3",
				"token":  "mock-attest-token-12345",
				"status": m.chalStatus,
			},
		},
		"expires": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}

	_ = json.NewEncoder(w).Encode(authz)
}

func (m *mockACMEServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	m.chalCount++
	w.Header().Set("Replay-Nonce", m.nonce)
	w.Header().Set("Content-Type", "application/json")

	// After accepting challenge, set to valid
	if r.Method == http.MethodPost {
		m.chalStatus = "valid"
		m.authzStatus = "valid"
		m.orderStatus = "ready"
	}

	challenge := map[string]interface{}{
		"type":   "http-01",
		"url":    m.URL + "/acme/challenge/1",
		"token":  "mock-challenge-token-12345",
		"status": m.chalStatus,
	}

	_ = json.NewEncoder(w).Encode(challenge)
}

func (m *mockACMEServer) handleFinalize(w http.ResponseWriter, r *http.Request) {
	m.finalizeCount++
	w.Header().Set("Replay-Nonce", m.nonce)
	w.Header().Set("Content-Type", "application/json")

	m.orderStatus = "valid"

	order := map[string]interface{}{
		"status":      "valid",
		"expires":     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"identifiers": []map[string]string{{"type": "dns", "value": "example.com"}},
		"authorizations": []string{
			m.URL + "/acme/authz/1",
		},
		"finalize":    m.URL + "/acme/finalize/1",
		"certificate": m.URL + "/acme/cert/1",
	}

	_ = json.NewEncoder(w).Encode(order)
}

func (m *mockACMEServer) handleCert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce)
	w.Header().Set("Content-Type", "application/pem-certificate-chain")

	// Return PEM-encoded certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: m.certDER,
	})

	_, _ = w.Write(certPEM)
}

func (m *mockACMEServer) handleCABundle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/pem-certificate-chain")

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: m.certDER,
	})

	_, _ = w.Write(certPEM)
}

// generateTestCert creates a test certificate for mock responses
func generateTestCert(t *testing.T) ([]byte, *x509.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return certDER, cert
}

// TestMockACMEServer_Directory tests the directory endpoint
func TestMockACMEServer_Directory(t *testing.T) {
	server := newMockACMEServer(t)
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/directory")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("Replay-Nonce"))

	var directory map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&directory)
	require.NoError(t, err)

	assert.Contains(t, directory, "newNonce")
	assert.Contains(t, directory, "newAccount")
	assert.Contains(t, directory, "newOrder")
}

// TestMockACMEServer_NewNonce tests the new nonce endpoint
func TestMockACMEServer_NewNonce(t *testing.T) {
	server := newMockACMEServer(t)
	defer server.Close()

	resp, err := server.Client().Head(server.URL + "/acme/new-nonce")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("Replay-Nonce"))
}

// TestMockACMEServer_OrderFlow tests the order creation flow
func TestMockACMEServer_OrderFlow(t *testing.T) {
	server := newMockACMEServer(t)
	defer server.Close()

	// Create order
	resp, err := server.Client().Post(server.URL+"/acme/new-order", "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("Location"))

	var order map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&order)
	require.NoError(t, err)

	assert.Equal(t, "pending", order["status"])
	assert.NotNil(t, order["authorizations"])
}

// TestMockACMEServer_AuthorizationFlow tests the authorization flow
func TestMockACMEServer_AuthorizationFlow(t *testing.T) {
	server := newMockACMEServer(t)
	defer server.Close()

	// Get authorization
	resp, err := server.Client().Get(server.URL + "/acme/authz/1")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var authz map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&authz)
	require.NoError(t, err)

	assert.Equal(t, "pending", authz["status"])
	challenges := authz["challenges"].([]interface{})
	assert.Len(t, challenges, 3) // http-01, enroll-01, device-attest-01
}

// TestMockACMEServer_ChallengeAccept tests accepting a challenge
func TestMockACMEServer_ChallengeAccept(t *testing.T) {
	server := newMockACMEServer(t)
	defer server.Close()

	// Accept challenge
	resp, err := server.Client().Post(server.URL+"/acme/challenge/1", "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var challenge map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&challenge)
	require.NoError(t, err)

	assert.Equal(t, "valid", challenge["status"])
}

// TestMockACMEServer_CertificateFetch tests certificate download
func TestMockACMEServer_CertificateFetch(t *testing.T) {
	server := newMockACMEServer(t)
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/acme/cert/1")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/pem-certificate-chain", resp.Header.Get("Content-Type"))
}

// mockTPMForEnrollment creates a mock TPM module for enrollment testing
type mockTPMForEnrollment struct {
	ekPub          crypto.PublicKey
	ekCert         *x509.Certificate
	iakAttrs       *KeyAttributes
	idevidCSR      *IDevIDCSR
	quote          *TPMQuote
	activateResult []byte
	errors         map[string]error
}

func newMockTPMForEnrollment(t *testing.T) *mockTPMForEnrollment {
	// Generate test EK
	ekKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Generate test EK certificate
	ekCertDER, ekCert := generateTestCert(t)
	_ = ekCertDER

	return &mockTPMForEnrollment{
		ekPub:  &ekKey.PublicKey,
		ekCert: ekCert,
		iakAttrs: &KeyAttributes{
			KeyID:              "test-iak",
			Algorithm:          "RSA-2048",
			SignatureAlgorithm: x509.SHA256WithRSA,
			TPMPublicBytes:     []byte("mock-iak-public"),
		},
		idevidCSR: &IDevIDCSR{
			CSR:                []byte("mock-tcg-csr-data"),
			IAKPublic:          []byte("mock-iak-public"),
			QualifyingData:     []byte("mock-qualifying-data"),
			SignatureAlgorithm: x509.SHA256WithRSA,
		},
		quote: &TPMQuote{
			Quote:              []byte("mock-quote-data"),
			Signature:          []byte("mock-quote-signature"),
			PCRValues:          map[int][]byte{0: make([]byte, 32)},
			Nonce:              []byte("mock-nonce"),
			SignatureAlgorithm: x509.SHA256WithRSA,
		},
		activateResult: []byte("mock-activated-secret"),
		errors:         make(map[string]error),
	}
}

func (m *mockTPMForEnrollment) EK() crypto.PublicKey {
	return m.ekPub
}

func (m *mockTPMForEnrollment) EKCertificate() (*x509.Certificate, error) {
	if err, ok := m.errors["EKCertificate"]; ok {
		return nil, err
	}
	return m.ekCert, nil
}

func (m *mockTPMForEnrollment) EKAttributes() (*KeyAttributes, error) {
	if err, ok := m.errors["EKAttributes"]; ok {
		return nil, err
	}
	return &KeyAttributes{
		KeyID:              "test-ek",
		Algorithm:          "RSA-2048",
		SignatureAlgorithm: x509.SHA256WithRSA,
	}, nil
}

func (m *mockTPMForEnrollment) IAKAttributes() (*KeyAttributes, error) {
	if err, ok := m.errors["IAKAttributes"]; ok {
		return nil, err
	}
	return m.iakAttrs, nil
}

func (m *mockTPMForEnrollment) CreateIDevID(qualifyingData []byte) (*IDevIDCSR, error) {
	if err, ok := m.errors["CreateIDevID"]; ok {
		return nil, err
	}
	m.idevidCSR.QualifyingData = qualifyingData
	return m.idevidCSR, nil
}

func (m *mockTPMForEnrollment) ActivateCredential(credBlob, encSecret []byte) ([]byte, error) {
	if err, ok := m.errors["ActivateCredential"]; ok {
		return nil, err
	}
	return m.activateResult, nil
}

func (m *mockTPMForEnrollment) ProvisionEKCert(certDER []byte) error {
	if err, ok := m.errors["ProvisionEKCert"]; ok {
		return err
	}
	return nil
}

func (m *mockTPMForEnrollment) Quote(nonce []byte, pcrSelection []int) (*TPMQuote, error) {
	if err, ok := m.errors["Quote"]; ok {
		return nil, err
	}
	m.quote.Nonce = nonce
	return m.quote, nil
}

func (m *mockTPMForEnrollment) Close() error {
	if err, ok := m.errors["Close"]; ok {
		return err
	}
	return nil
}

// TestIDevIDCSR_Fields tests IDevIDCSR field accessibility
func TestIDevIDCSR_Fields(t *testing.T) {
	tests := []struct {
		name    string
		csr     *IDevIDCSR
		wantErr bool
	}{
		{
			name: "Valid CSR",
			csr: &IDevIDCSR{
				CSR:            []byte("csr-data"),
				IAKPublic:      []byte("iak-public"),
				QualifyingData: []byte("qualifying-data"),
			},
			wantErr: false,
		},
		{
			name: "Missing CSR",
			csr: &IDevIDCSR{
				IAKPublic:      []byte("iak-public"),
				QualifyingData: []byte("qualifying-data"),
			},
			wantErr: true,
		},
		{
			name:    "Nil CSR struct",
			csr:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.csr == nil {
				assert.True(t, tt.wantErr)
				return
			}
			// Add validation method test if exists
			isValid := len(tt.csr.CSR) > 0
			if tt.wantErr {
				assert.False(t, isValid)
			} else {
				assert.True(t, isValid)
			}
		})
	}
}

// TestTPMQuote_Fields tests TPMQuote field accessibility
func TestTPMQuote_Fields(t *testing.T) {
	tests := []struct {
		name    string
		quote   *TPMQuote
		wantErr bool
	}{
		{
			name: "Valid quote",
			quote: &TPMQuote{
				Quote:     []byte("quote-data"),
				Signature: []byte("signature"),
				PCRValues: map[int][]byte{0: make([]byte, 32)},
			},
			wantErr: false,
		},
		{
			name: "Missing quote data",
			quote: &TPMQuote{
				Signature: []byte("signature"),
				PCRValues: map[int][]byte{0: make([]byte, 32)},
			},
			wantErr: true,
		},
		{
			name: "Missing signature",
			quote: &TPMQuote{
				Quote:     []byte("quote-data"),
				PCRValues: map[int][]byte{0: make([]byte, 32)},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.quote == nil {
				assert.True(t, tt.wantErr)
				return
			}
			isValid := len(tt.quote.Quote) > 0 && len(tt.quote.Signature) > 0
			if tt.wantErr {
				assert.False(t, isValid)
			} else {
				assert.True(t, isValid)
			}
		})
	}
}

// TestBase64Encoding tests base64 encoding helpers
func TestBase64Encoding(t *testing.T) {
	testData := []byte("test data for encoding")

	// Test standard encoding
	encoded := base64.StdEncoding.EncodeToString(testData)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	assert.Equal(t, testData, decoded)

	// Test URL encoding
	urlEncoded := base64.RawURLEncoding.EncodeToString(testData)
	urlDecoded, err := base64.RawURLEncoding.DecodeString(urlEncoded)
	require.NoError(t, err)
	assert.Equal(t, testData, urlDecoded)
}

// TestMockTPMForEnrollment_AllMethods tests all TPM mock methods
func TestMockTPMForEnrollment_AllMethods(t *testing.T) {
	tpm := newMockTPMForEnrollment(t)

	// Test EK
	ek := tpm.EK()
	assert.NotNil(t, ek)

	// Test EKCertificate
	ekCert, err := tpm.EKCertificate()
	assert.NoError(t, err)
	assert.NotNil(t, ekCert)

	// Test EKAttributes
	ekAttrs, err := tpm.EKAttributes()
	assert.NoError(t, err)
	assert.NotNil(t, ekAttrs)

	// Test IAKAttributes
	iakAttrs, err := tpm.IAKAttributes()
	assert.NoError(t, err)
	assert.NotNil(t, iakAttrs)

	// Test CreateIDevID
	csr, err := tpm.CreateIDevID([]byte("qualifying-data"))
	assert.NoError(t, err)
	assert.NotNil(t, csr)

	// Test ActivateCredential
	secret, err := tpm.ActivateCredential([]byte("cred"), []byte("secret"))
	assert.NoError(t, err)
	assert.NotNil(t, secret)

	// Test ProvisionEKCert
	err = tpm.ProvisionEKCert([]byte("cert"))
	assert.NoError(t, err)

	// Test Quote
	quote, err := tpm.Quote([]byte("nonce"), []int{0, 1, 7})
	assert.NoError(t, err)
	assert.NotNil(t, quote)

	// Test Close
	err = tpm.Close()
	assert.NoError(t, err)
}

// TestMockTPMForEnrollment_WithErrors tests TPM mock error injection
func TestMockTPMForEnrollment_WithErrors(t *testing.T) {
	tpm := newMockTPMForEnrollment(t)
	testErr := caerrors.InternalServerError("test error")

	// Inject errors
	tpm.errors["EKCertificate"] = testErr
	tpm.errors["EKAttributes"] = testErr
	tpm.errors["IAKAttributes"] = testErr
	tpm.errors["CreateIDevID"] = testErr
	tpm.errors["ActivateCredential"] = testErr
	tpm.errors["ProvisionEKCert"] = testErr
	tpm.errors["Quote"] = testErr
	tpm.errors["Close"] = testErr

	// Test all error paths
	_, err := tpm.EKCertificate()
	assert.Error(t, err)

	_, err = tpm.EKAttributes()
	assert.Error(t, err)

	_, err = tpm.IAKAttributes()
	assert.Error(t, err)

	_, err = tpm.CreateIDevID(nil)
	assert.Error(t, err)

	_, err = tpm.ActivateCredential(nil, nil)
	assert.Error(t, err)

	err = tpm.ProvisionEKCert(nil)
	assert.Error(t, err)

	_, err = tpm.Quote(nil, nil)
	assert.Error(t, err)

	err = tpm.Close()
	assert.Error(t, err)
}
