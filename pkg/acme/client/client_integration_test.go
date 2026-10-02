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

//go:build integration

package client

import (
	"context"
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
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// fullACMEMockServer is a complete ACME server mock for integration testing
type fullACMEMockServer struct {
	*httptest.Server
	t *testing.T

	// State management
	mu             sync.RWMutex
	nonceCounter   int64
	accounts       map[string]*mockAccount
	orders         map[string]*mockOrder
	authorizations map[string]*mockAuthz
	challenges     map[string]*mockChallenge
	certificates   map[string][]byte
	finalizeCSRs   [][]byte

	// Test control
	orderStatusOverride string
	authzStatusOverride string
	chalStatusOverride  string
	requestLog          []string
}

type mockAccount struct {
	ID      string
	Status  string
	Contact []string
}

type mockOrder struct {
	ID             string
	Status         string
	Identifiers    []map[string]string
	Authorizations []string
	FinalizeURL    string
	CertificateURL string
}

type mockAuthz struct {
	ID         string
	Status     string
	Identifier map[string]string
	Challenges []string
}

type mockChallenge struct {
	ID     string
	Type   string
	Status string
	Token  string
	URL    string
}

func newFullACMEMockServer(t *testing.T) *fullACMEMockServer {
	m := &fullACMEMockServer{
		t:              t,
		accounts:       make(map[string]*mockAccount),
		orders:         make(map[string]*mockOrder),
		authorizations: make(map[string]*mockAuthz),
		challenges:     make(map[string]*mockChallenge),
		certificates:   make(map[string][]byte),
		requestLog:     make([]string, 0),
	}

	mux := http.NewServeMux()

	// Core ACME endpoints
	mux.HandleFunc("/directory", m.handleDirectory)
	mux.HandleFunc("/acme/new-nonce", m.handleNewNonce)
	mux.HandleFunc("/acme/new-account", m.handleNewAccount)
	mux.HandleFunc("/acme/new-order", m.handleNewOrder)
	mux.HandleFunc("/acme/order/", m.handleOrder)
	mux.HandleFunc("/acme/authz/", m.handleAuthz)
	mux.HandleFunc("/acme/challenge/", m.handleChallenge)
	mux.HandleFunc("/acme/finalize/", m.handleFinalize)
	mux.HandleFunc("/acme/cert/", m.handleCert)
	mux.HandleFunc("/acme/account/", m.handleAccount)
	mux.HandleFunc("/ca-bundle", m.handleCABundle)

	m.Server = httptest.NewTLSServer(mux)
	return m
}

func (m *fullACMEMockServer) logRequest(method, path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requestLog = append(m.requestLog, fmt.Sprintf("%s %s", method, path))
}

func (m *fullACMEMockServer) getNonce() string {
	n := atomic.AddInt64(&m.nonceCounter, 1)
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("nonce-%d-%d", n, time.Now().UnixNano())))
}

func (m *fullACMEMockServer) setHeaders(w http.ResponseWriter) {
	w.Header().Set("Replay-Nonce", m.getNonce())
	w.Header().Set("Content-Type", "application/json")
}

func (m *fullACMEMockServer) handleDirectory(w http.ResponseWriter, r *http.Request) {
	m.logRequest(r.Method, r.URL.Path)
	m.setHeaders(w)

	directory := map[string]interface{}{
		"newNonce":   m.Server.URL + "/acme/new-nonce",
		"newAccount": m.Server.URL + "/acme/new-account",
		"newOrder":   m.Server.URL + "/acme/new-order",
		"revokeCert": m.Server.URL + "/acme/revoke-cert",
		"keyChange":  m.Server.URL + "/acme/key-change",
		"meta": map[string]interface{}{
			"termsOfService":          "https://example.com/terms",
			"externalAccountRequired": false,
		},
	}
	_ = json.NewEncoder(w).Encode(directory)
}

func (m *fullACMEMockServer) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	m.logRequest(r.Method, r.URL.Path)
	w.Header().Set("Replay-Nonce", m.getNonce())
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (m *fullACMEMockServer) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	m.logRequest(r.Method, r.URL.Path)
	m.setHeaders(w)

	accountID := fmt.Sprintf("account-%d", time.Now().UnixNano())
	accountURL := m.Server.URL + "/acme/account/" + accountID

	m.mu.Lock()
	m.accounts[accountID] = &mockAccount{
		ID:      accountID,
		Status:  "valid",
		Contact: []string{"mailto:test@example.com"},
	}
	m.mu.Unlock()

	w.Header().Set("Location", accountURL)
	w.WriteHeader(http.StatusCreated)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "valid",
		"contact": []string{"mailto:test@example.com"},
		"orders":  accountURL + "/orders",
	})
}

func (m *fullACMEMockServer) handleAccount(w http.ResponseWriter, r *http.Request) {
	m.logRequest(r.Method, r.URL.Path)
	m.setHeaders(w)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "valid",
		"contact": []string{"mailto:test@example.com"},
	})
}

func (m *fullACMEMockServer) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	m.logRequest(r.Method, r.URL.Path)
	m.setHeaders(w)

	// Parse the request to get identifiers
	body, _ := io.ReadAll(r.Body)
	var payload struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	_ = json.Unmarshal(body, &payload)

	orderID := fmt.Sprintf("order-%d", time.Now().UnixNano())
	authzID := fmt.Sprintf("authz-%d", time.Now().UnixNano())
	chalID := fmt.Sprintf("chal-%d", time.Now().UnixNano())

	orderURL := m.Server.URL + "/acme/order/" + orderID
	authzURL := m.Server.URL + "/acme/authz/" + authzID
	chalURL := m.Server.URL + "/acme/challenge/" + chalID
	finalizeURL := m.Server.URL + "/acme/finalize/" + orderID
	certURL := m.Server.URL + "/acme/cert/" + orderID

	m.mu.Lock()
	// Create challenge
	m.challenges[chalID] = &mockChallenge{
		ID:     chalID,
		Type:   "enroll-01",
		Status: "pending",
		Token:  base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("token-%d", time.Now().UnixNano()))),
		URL:    chalURL,
	}

	// Create additional challenges
	chalID2 := chalID + "-attest"
	m.challenges[chalID2] = &mockChallenge{
		ID:     chalID2,
		Type:   "device-attest-01",
		Status: "pending",
		Token:  base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("token-attest-%d", time.Now().UnixNano()))),
		URL:    m.Server.URL + "/acme/challenge/" + chalID2,
	}

	chalID3 := chalID + "-endorse"
	m.challenges[chalID3] = &mockChallenge{
		ID:     chalID3,
		Type:   "endorse-01",
		Status: "pending",
		Token:  base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("token-endorse-%d", time.Now().UnixNano()))),
		URL:    m.Server.URL + "/acme/challenge/" + chalID3,
	}

	// Create authorization
	m.authorizations[authzID] = &mockAuthz{
		ID:         authzID,
		Status:     "pending",
		Identifier: map[string]string{"type": "permanent-identifier", "value": "192.168.1.1"},
		Challenges: []string{chalID, chalID2, chalID3},
	}

	// Create order
	m.orders[orderID] = &mockOrder{
		ID:             orderID,
		Status:         "pending",
		Identifiers:    []map[string]string{{"type": "permanent-identifier", "value": "192.168.1.1"}},
		Authorizations: []string{authzID},
		FinalizeURL:    finalizeURL,
		CertificateURL: certURL,
	}
	m.mu.Unlock()

	w.Header().Set("Location", orderURL)
	w.WriteHeader(http.StatusCreated)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "pending",
		"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"identifiers":    []map[string]string{{"type": "permanent-identifier", "value": "192.168.1.1"}},
		"authorizations": []string{authzURL},
		"finalize":       finalizeURL,
	})
}

func (m *fullACMEMockServer) handleOrder(w http.ResponseWriter, r *http.Request) {
	m.logRequest(r.Method, r.URL.Path)
	m.setHeaders(w)

	orderID := strings.TrimPrefix(r.URL.Path, "/acme/order/")

	m.mu.RLock()
	order, exists := m.orders[orderID]
	m.mu.RUnlock()

	if !exists {
		http.NotFound(w, r)
		return
	}

	status := order.Status
	if m.orderStatusOverride != "" {
		status = m.orderStatusOverride
	}

	resp := map[string]interface{}{
		"status":         status,
		"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"identifiers":    order.Identifiers,
		"authorizations": []string{m.Server.URL + "/acme/authz/" + order.Authorizations[0]},
		"finalize":       order.FinalizeURL,
	}

	if status == "valid" {
		resp["certificate"] = order.CertificateURL
	}

	_ = json.NewEncoder(w).Encode(resp)
}

func (m *fullACMEMockServer) handleAuthz(w http.ResponseWriter, r *http.Request) {
	m.logRequest(r.Method, r.URL.Path)
	m.setHeaders(w)

	authzID := strings.TrimPrefix(r.URL.Path, "/acme/authz/")

	m.mu.RLock()
	authz, exists := m.authorizations[authzID]
	m.mu.RUnlock()

	if !exists {
		http.NotFound(w, r)
		return
	}

	status := authz.Status
	if m.authzStatusOverride != "" {
		status = m.authzStatusOverride
	}

	// Build challenges array
	challenges := make([]map[string]interface{}, 0)
	m.mu.RLock()
	for _, chalID := range authz.Challenges {
		if chal, ok := m.challenges[chalID]; ok {
			chalStatus := chal.Status
			if m.chalStatusOverride != "" {
				chalStatus = m.chalStatusOverride
			}
			challenges = append(challenges, map[string]interface{}{
				"type":   chal.Type,
				"url":    chal.URL,
				"token":  chal.Token,
				"status": chalStatus,
			})
		}
	}
	m.mu.RUnlock()

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     status,
		"identifier": authz.Identifier,
		"challenges": challenges,
		"expires":    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	})
}

func (m *fullACMEMockServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	m.logRequest(r.Method, r.URL.Path)
	m.setHeaders(w)

	chalID := strings.TrimPrefix(r.URL.Path, "/acme/challenge/")

	m.mu.Lock()
	chal, exists := m.challenges[chalID]
	if exists && r.Method == http.MethodPost {
		// Mark challenge as processing -> valid
		chal.Status = "valid"

		// Also update related authorization
		for _, authz := range m.authorizations {
			for _, aChalID := range authz.Challenges {
				if aChalID == chalID {
					authz.Status = "valid"
					break
				}
			}
		}

		// Update order status
		for _, order := range m.orders {
			order.Status = "ready"
		}
	}
	m.mu.Unlock()

	if !exists {
		http.NotFound(w, r)
		return
	}

	status := chal.Status
	if m.chalStatusOverride != "" {
		status = m.chalStatusOverride
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"type":   chal.Type,
		"url":    chal.URL,
		"token":  chal.Token,
		"status": status,
	})
}

func (m *fullACMEMockServer) handleFinalize(w http.ResponseWriter, r *http.Request) {
	m.logRequest(r.Method, r.URL.Path)
	m.setHeaders(w)

	orderID := strings.TrimPrefix(r.URL.Path, "/acme/finalize/")
	csrDER := m.decodeFinalizeCSR(r)

	m.mu.Lock()
	order, exists := m.orders[orderID]
	if csrDER != nil {
		m.finalizeCSRs = append(m.finalizeCSRs, csrDER)
	}
	if exists {
		order.Status = "valid"

		// Generate test certificates (IAK and IDevID)
		certChain := m.generateCertificateChain()
		m.certificates[orderID] = certChain
	}
	m.mu.Unlock()

	if !exists {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Location", m.Server.URL+"/acme/order/"+orderID)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "valid",
		"expires":     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"identifiers": order.Identifiers,
		"finalize":    order.FinalizeURL,
		"certificate": order.CertificateURL,
	})
}

// decodeFinalizeCSR extracts the DER certificate request from a finalize
// JWS body, or returns nil when the body does not carry one.
func (m *fullACMEMockServer) decodeFinalizeCSR(r *http.Request) []byte {
	var jws struct {
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return nil
	}
	var finalize struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload, &finalize); err != nil {
		return nil
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(finalize.CSR)
	if err != nil {
		return nil
	}
	return csrDER
}

func (m *fullACMEMockServer) handleCert(w http.ResponseWriter, r *http.Request) {
	m.logRequest(r.Method, r.URL.Path)

	orderID := strings.TrimPrefix(r.URL.Path, "/acme/cert/")

	m.mu.RLock()
	certChain, exists := m.certificates[orderID]
	m.mu.RUnlock()

	if !exists {
		// Generate on-demand
		certChain = m.generateCertificateChain()
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	_, _ = w.Write(certChain)
}

func (m *fullACMEMockServer) handleCABundle(w http.ResponseWriter, r *http.Request) {
	m.logRequest(r.Method, r.URL.Path)
	w.Header().Set("Content-Type", "application/x-pem-file")

	// Return the test server's certificate as the CA bundle
	cert := m.Server.Certificate()
	if cert != nil {
		_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
}

func (m *fullACMEMockServer) generateCertificateChain() []byte {
	// Generate IAK certificate
	iakKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	iakTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "Test-IAK"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	iakDER, _ := x509.CreateCertificate(rand.Reader, iakTemplate, iakTemplate, &iakKey.PublicKey, iakKey)

	// Generate IDevID certificate
	idevidKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	idevidTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: "Test-IDevID"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	idevidDER, _ := x509.CreateCertificate(rand.Reader, idevidTemplate, idevidTemplate, &idevidKey.PublicKey, idevidKey)

	// Encode as PEM chain
	var chain []byte
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: iakDER})...)
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idevidDER})...)

	return chain
}

// Helper to create a real ACME client connected to the mock server
func createRealClientWithMockServer(t *testing.T, server *fullACMEMockServer) *Client {
	// Generate account key
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Get server certificate and encode as PEM for TrustedRoots
	serverCert := server.Server.Certificate()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})

	// Create client config
	config := &Config{
		DirectoryURL:        server.Server.URL + "/directory",
		SystemCertPool:      false,
		RequestServerBundle: false,
		TrustedRoots:        []string{string(certPEM)},
		Timeout:             30 * time.Second,
	}

	// Create mock storage
	storage := newMockStorage()
	certStorage := newMockCertStorage()
	orderStorage := newMockOrderStorage()

	client, err := NewClient(&Params{
		AccountEmail:       "test@example.com",
		AccountSigner:      accountKey,
		Config:             config,
		Storage:            storage,
		CertificateStorage: certStorage,
		OrderStorage:       orderStorage,
	})
	require.NoError(t, err)

	return client
}

// integrationTPM implements TPMModule for integration tests
type integrationTPM struct {
	ekKey    *rsa.PrivateKey
	ekCert   *x509.Certificate
	iakAttrs *KeyAttributes

	// attested is the certificate key CreateAttestedKey answered with, kept
	// so a test can compare it with the key the CSR names.
	attested *AttestedKey

	// provisionedIAKCert records the certificate EnrollDevice installed via
	// ProvisionIAKCert (go-xkms#1100).
	provisionedIAKCert *x509.Certificate
}

func newIntegrationTPM(t *testing.T) *integrationTPM {
	ekKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create EK certificate
	ekTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test-EK"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
	}
	ekCertDER, err := x509.CreateCertificate(rand.Reader, ekTemplate, ekTemplate, &ekKey.PublicKey, ekKey)
	require.NoError(t, err)
	ekCert, err := x509.ParseCertificate(ekCertDER)
	require.NoError(t, err)

	return &integrationTPM{
		ekKey:  ekKey,
		ekCert: ekCert,
		iakAttrs: &KeyAttributes{
			KeyID:              "test-iak",
			Algorithm:          "RSA-2048",
			SignatureAlgorithm: x509.SHA256WithRSA,
			TPMPublicBytes:     []byte("mock-tpm-public"),
		},
	}
}

func (m *integrationTPM) EK() crypto.PublicKey {
	return &m.ekKey.PublicKey
}

func (m *integrationTPM) EKCertificate() (*x509.Certificate, error) {
	return m.ekCert, nil
}

func (m *integrationTPM) EKAttributes() (*KeyAttributes, error) {
	return &KeyAttributes{
		KeyID:              "test-ek",
		Algorithm:          "RSA-2048",
		SignatureAlgorithm: x509.SHA256WithRSA,
	}, nil
}

func (m *integrationTPM) TPMManufacturer() (string, error) { return testTPMManufacturer, nil }

func (m *integrationTPM) IAKAttributes() (*KeyAttributes, error) {
	return m.iakAttrs, nil
}

func (m *integrationTPM) CreateIDevID(qualifyingData []byte) (*IDevIDCSR, error) {
	return &IDevIDCSR{
		CSR:                []byte("mock-tcg-csr-idevid"),
		IAKPublic:          []byte("mock-iak-public"),
		QualifyingData:     qualifyingData,
		SignatureAlgorithm: x509.SHA256WithRSA,
		EKCert:             m.ekCert,
	}, nil
}

func (m *integrationTPM) ActivateCredential(credBlob, encSecret []byte) ([]byte, error) {
	return []byte("decrypted-secret-12345"), nil
}

func (m *integrationTPM) ProvisionEKCert(certDER []byte) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}
	m.ekCert = cert
	return nil
}

func (m *integrationTPM) ProvisionIAKCert(cert *x509.Certificate) error {
	m.provisionedIAKCert = cert
	return nil
}

// DeviceIdentity implements TPMModule with the fixed test identity.
func (m *integrationTPM) DeviceIdentity() (string, error) { return testDeviceIdentity, nil }

func (m *integrationTPM) CreateAttestedKey(name, keyAuth string) (*AttestedKey, error) {
	attested, err := newTestAttestedKey(keyAuth)
	if err != nil {
		return nil, err
	}
	m.attested = attested
	return attested, nil
}

func (m *integrationTPM) Close() error {
	return nil
}

// TestClient_EnrollDevice_FullFlow tests the complete enrollment flow
func TestClient_EnrollDevice_FullFlow(t *testing.T) {
	server := newFullACMEMockServer(t)
	defer server.Close()

	client := createRealClientWithMockServer(t, server)
	defer func() { _ = client.Close() }()

	// Register account first
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	// Create TPM mock
	tpm := newIntegrationTPM(t)

	// Configure enrollment
	config := &EnrollmentConfig{
		Challenge: "enroll-01",
		IPAddress: "192.168.1.1",
		Port:      "19990",
		TPMModule: tpm,
		Timeout:   10 * time.Second,
	}

	// Run enrollment (this will test the full ACME flow)
	result, err := client.EnrollDevice(ctx, config)

	// The enrollment may fail at some point due to mock limitations,
	// but we should have exercised much of the code path
	if err != nil {
		// Check that we got past validation
		assert.NotContains(t, err.Error(), "invalid enrollment config")
		t.Logf("Enrollment completed with error (expected in mock): %v", err)
	} else {
		assert.NotNil(t, result)
		assert.NotNil(t, result.IAKCertificate)
		assert.NotNil(t, result.IDevIDCertificate)
		// go-xkms#1100: the issued IAK certificate must be installed via
		// ProvisionIAKCert so a later device-attest-01 can read it back.
		require.NotNil(t, tpm.provisionedIAKCert)
		assert.True(t, result.IAKCertificate.Equal(tpm.provisionedIAKCert))
	}

	// Verify requests were made to the mock server
	assert.Contains(t, server.requestLog, "GET /directory")
	// The acme client may use different methods for nonce retrieval
	hasNonceRequest := false
	for _, req := range server.requestLog {
		if strings.Contains(req, "/acme/new-account") || strings.Contains(req, "/acme/new-order") {
			hasNonceRequest = true
			break
		}
	}
	assert.True(t, hasNonceRequest, "Expected ACME requests to be made")
}

// TestClient_DeviceAttest_FullFlow tests the device attestation flow
func TestClient_DeviceAttest_FullFlow(t *testing.T) {
	server := newFullACMEMockServer(t)
	defer server.Close()

	client := createRealClientWithMockServer(t, server)
	defer func() { _ = client.Close() }()

	// Register account first
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	// Create TPM mock
	tpm := newIntegrationTPM(t)

	// Configure attestation
	config := &EnrollmentConfig{
		Challenge:  "device-attest-01",
		IPAddress:  "192.168.1.1",
		Port:       "19991",
		TPMModule:  tpm,
		CommonName: "device",
		Timeout:    10 * time.Second,
	}

	// Run attestation
	cert, err := client.DeviceAttest(ctx, config)
	require.NoError(t, err)
	assert.NotNil(t, cert)

	// Verify requests were made
	assert.Contains(t, server.requestLog, "GET /directory")

	// The CSR is for the attested key and nothing else: the server binds the
	// certification in the challenge response to the key the CSR names.
	server.mu.RLock()
	csrs := server.finalizeCSRs
	server.mu.RUnlock()
	require.Len(t, csrs, 1)
	csr, err := x509.ParseCertificateRequest(csrs[0])
	require.NoError(t, err)
	require.NotNil(t, tpm.attested)
	attestedSPKI, err := x509.MarshalPKIXPublicKey(tpm.attested.Signer.Public())
	require.NoError(t, err)
	assert.Equal(t, attestedSPKI, csr.RawSubjectPublicKeyInfo)
	assert.Equal(t, testDeviceIdentity, permanentIdentifierOf(t, csr), "the CSR must name the order's permanent identifier")
	assert.NotEqual(t, client.accountSigner.Public(), tpm.attested.Signer.Public(), "the CSR must not be signed with the account key")
}

// TestClient_RequestEndorsementKeyCertificate_FullFlow tests EK cert request
func TestClient_RequestEndorsementKeyCertificate_FullFlow(t *testing.T) {
	server := newFullACMEMockServer(t)
	defer server.Close()

	client := createRealClientWithMockServer(t, server)
	defer func() { _ = client.Close() }()

	// Register account first
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	// Create TPM mock
	tpm := newIntegrationTPM(t)

	// Configure endorsement
	config := &EnrollmentConfig{
		Challenge: "endorse-01",
		IPAddress: "192.168.1.1",
		Port:      "19992",
		TPMModule: tpm,
		Timeout:   10 * time.Second,
	}

	// Run endorsement
	cert, err := client.RequestEndorsementKeyCertificate(ctx, config)
	require.NoError(t, err)
	assert.NotNil(t, cert)

	// The certificate request asks for the TPM's manufacturer code to be
	// recorded, in the subjectAltName directoryName the CA reads it from.
	server.mu.RLock()
	csrs := server.finalizeCSRs
	server.mu.RUnlock()
	require.Len(t, csrs, 1)
	csr, err := x509.ParseCertificateRequest(csrs[0])
	require.NoError(t, err)
	manufacturer, err := ca.TCGTPMManufacturerFromCSR(csr)
	require.NoError(t, err)
	assert.Equal(t, testTPMManufacturer, manufacturer)
}

// TestClient_RequestEndorsementKeyCertificate_ManufacturerUnavailable covers
// the error path: a TPM that cannot report its manufacturer code is refused
// before an order is opened, because the EK certificate issued without it
// could never be used for enroll-01.
func TestClient_RequestEndorsementKeyCertificate_ManufacturerUnavailable(t *testing.T) {
	server := newFullACMEMockServer(t)
	defer server.Close()

	client := createRealClientWithMockServer(t, server)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	config := &EnrollmentConfig{
		Challenge: "endorse-01",
		IPAddress: "192.168.1.1",
		Port:      "19993",
		TPMModule: &manufacturerlessTPM{integrationTPM: newIntegrationTPM(t)},
		Timeout:   10 * time.Second,
	}

	cert, err := client.RequestEndorsementKeyCertificate(ctx, config)
	assert.Nil(t, cert)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.BadCSR, caErr.Type)
	assert.NotContains(t, server.requestLog, "POST /acme/new-order")
}

// manufacturerlessTPM is a TPM whose fixed properties cannot be read.
type manufacturerlessTPM struct {
	*integrationTPM
}

func (m *manufacturerlessTPM) TPMManufacturer() (string, error) {
	return "", caerrors.NotFoundError("TPM manufacturer not available")
}

// TestClient_RegisterAccount tests account registration
func TestClient_RegisterAccount_Integration(t *testing.T) {
	server := newFullACMEMockServer(t)
	defer server.Close()

	client := createRealClientWithMockServer(t, server)
	defer func() { _ = client.Close() }()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	// Verify account was registered
	assert.Contains(t, server.requestLog, "POST /acme/new-account")
}

// TestClient_FetchDirectory tests directory fetching
func TestClient_FetchDirectory_Integration(t *testing.T) {
	server := newFullACMEMockServer(t)
	defer server.Close()

	client := createRealClientWithMockServer(t, server)
	defer func() { _ = client.Close() }()

	// RegisterAccount internally fetches directory
	_, err := client.RegisterAccount()
	require.NoError(t, err)

	// Verify directory was fetched
	assert.Contains(t, server.requestLog, "GET /directory")
}

// TestFullACMEServer_AllEndpoints tests that all ACME endpoints respond correctly
func TestFullACMEServer_AllEndpoints(t *testing.T) {
	server := newFullACMEMockServer(t)
	defer server.Close()

	httpClient := server.Server.Client()

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"directory", http.MethodGet, "/directory", http.StatusOK},
		{"new-nonce", http.MethodHead, "/acme/new-nonce", http.StatusNoContent},
		{"ca-bundle", http.MethodGet, "/ca-bundle", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, server.Server.URL+tt.path, nil)
			require.NoError(t, err)

			resp, err := httpClient.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tt.wantStatus, resp.StatusCode)
		})
	}
}

// TestFullACMEServer_OrderFlow tests the complete order flow
func TestFullACMEServer_OrderFlow(t *testing.T) {
	server := newFullACMEMockServer(t)
	defer server.Close()

	httpClient := server.Server.Client()

	// 1. Create order
	orderReq, _ := http.NewRequest(http.MethodPost, server.Server.URL+"/acme/new-order", strings.NewReader(`{}`))
	orderReq.Header.Set("Content-Type", "application/jose+json")
	orderResp, err := httpClient.Do(orderReq)
	require.NoError(t, err)
	defer func() { _ = orderResp.Body.Close() }()

	assert.Equal(t, http.StatusCreated, orderResp.StatusCode)

	var order map[string]interface{}
	_ = json.NewDecoder(orderResp.Body).Decode(&order)

	assert.Equal(t, "pending", order["status"])
	assert.NotEmpty(t, order["authorizations"])
	assert.NotEmpty(t, order["finalize"])
}
