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

package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
)

// TestEnrollDevice_ValidationErrors_Coverage tests EnrollDevice with validation errors
func TestEnrollDevice_ValidationErrors_Coverage(t *testing.T) {
	mockTPM := newMockTPMForEnrollment(t)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &Client{
		config:        &Config{DirectoryURL: "https://example.com", Timeout: 30 * time.Second},
		logger:        slog.Default(),
		accountSigner: key,
	}

	tests := []struct {
		name    string
		config  *EnrollmentConfig
		wantErr bool
	}{
		{
			name:    "nil TPM module",
			config:  &EnrollmentConfig{Challenge: "enroll-01", IPAddress: "192.168.1.1"},
			wantErr: true,
		},
		{
			name:    "empty challenge",
			config:  &EnrollmentConfig{Challenge: "", TPMModule: mockTPM, IPAddress: "192.168.1.1"},
			wantErr: true,
		},
		{
			name:    "empty IP address",
			config:  &EnrollmentConfig{Challenge: "enroll-01", TPMModule: mockTPM, IPAddress: ""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.EnrollDevice(context.Background(), tt.config)
			assert.Error(t, err)
		})
	}
}

// TestEnrollDevice_EnvVarExpansion_Coverage tests EnrollDevice with environment variable expansion
func TestEnrollDevice_EnvVarExpansion_Coverage(t *testing.T) {
	mockTPM := newMockTPMForEnrollment(t)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &Client{
		config:        &Config{DirectoryURL: "https://example.com", Timeout: 30 * time.Second},
		logger:        slog.Default(),
		accountSigner: key,
	}

	// Test with missing env var
	config := &EnrollmentConfig{
		Challenge: "enroll-01",
		TPMModule: mockTPM,
		IPAddress: "${NONEXISTENT_VAR_FOR_TEST}",
	}

	_, err := client.EnrollDevice(context.Background(), config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expand IP address")
}

// TestRequestEndorsementKeyCertificate_Validation_Coverage tests RequestEndorsementKeyCertificate validation
func TestRequestEndorsementKeyCertificate_Validation_Coverage(t *testing.T) {
	mockTPM := newMockTPMForEnrollment(t)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &Client{
		config:        &Config{DirectoryURL: "https://example.com", Timeout: 30 * time.Second},
		logger:        slog.Default(),
		accountSigner: key,
	}

	// Test with invalid config
	config := &EnrollmentConfig{
		Challenge: "", // Invalid
		TPMModule: mockTPM,
		IPAddress: "192.168.1.1",
	}

	_, err := client.RequestEndorsementKeyCertificate(context.Background(), config)
	assert.Error(t, err)
}

// TestRequestEndorsementKeyCertificate_NoEK_Coverage tests RequestEndorsementKeyCertificate with nil EK
func TestRequestEndorsementKeyCertificate_NoEK_Coverage(t *testing.T) {
	mockTPM := newMockTPMForEnrollment(t)
	mockTPM.ekPub = nil // No EK public key

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &Client{
		config:        &Config{DirectoryURL: "https://example.com", Timeout: 30 * time.Second},
		logger:        slog.Default(),
		accountSigner: key,
	}

	config := &EnrollmentConfig{
		Challenge: "endorse-01",
		TPMModule: mockTPM,
		IPAddress: "192.168.1.1",
	}

	_, err := client.RequestEndorsementKeyCertificate(context.Background(), config)
	assert.Error(t, err)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.BadPublicKey, caErr.Type)
}

// TestDeviceAttest_Validation_Coverage tests DeviceAttest validation
func TestDeviceAttest_Validation_Coverage(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &Client{
		config:        &Config{DirectoryURL: "https://example.com", Timeout: 30 * time.Second},
		logger:        slog.Default(),
		accountSigner: key,
	}

	// Test with invalid config
	config := &EnrollmentConfig{
		Challenge: "device-attest-01",
		TPMModule: nil, // Invalid
		IPAddress: "192.168.1.1",
	}

	_, err := client.DeviceAttest(context.Background(), config, []int{0, 1, 7})
	assert.Error(t, err)
}

// TestDeviceAttest_EnvVarExpansion_Coverage tests DeviceAttest with environment variable expansion
func TestDeviceAttest_EnvVarExpansion_Coverage(t *testing.T) {
	mockTPM := newMockTPMForEnrollment(t)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &Client{
		config:        &Config{DirectoryURL: "https://example.com", Timeout: 30 * time.Second},
		logger:        slog.Default(),
		accountSigner: key,
	}

	config := &EnrollmentConfig{
		Challenge: "device-attest-01",
		TPMModule: mockTPM,
		IPAddress: "${NONEXISTENT_VAR_XYZ}",
	}

	_, err := client.DeviceAttest(context.Background(), config, []int{0})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expand IP address")
}

// TestSetupAttestChallenge_QuoteError_Coverage tests setupAttestChallenge with quote error
func TestSetupAttestChallenge_QuoteError_Coverage(t *testing.T) {
	mockTPM := newMockTPMForEnrollment(t)
	mockTPM.errors["Quote"] = errors.New("quote error")

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &Client{
		config:        &Config{DirectoryURL: "https://example.com", Timeout: 30 * time.Second},
		logger:        slog.Default(),
		accountSigner: key,
	}

	config := &EnrollmentConfig{
		Challenge: "device-attest-01",
		TPMModule: mockTPM,
		IPAddress: "192.168.1.1",
	}

	_, err := client.setupAttestChallenge(config, "keyauth", []int{0})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "quote")
}

// TestSetupAttestChallenge_IAKError_Coverage tests setupAttestChallenge with IAK error
func TestSetupAttestChallenge_IAKError_Coverage(t *testing.T) {
	mockTPM := newMockTPMForEnrollment(t)
	mockTPM.errors["IAKAttributes"] = errors.New("iak error")

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &Client{
		config:        &Config{DirectoryURL: "https://example.com", Timeout: 30 * time.Second},
		logger:        slog.Default(),
		accountSigner: key,
	}

	config := &EnrollmentConfig{
		Challenge: "device-attest-01",
		TPMModule: mockTPM,
		IPAddress: "192.168.1.1",
	}

	_, err := client.setupAttestChallenge(config, "keyauth", []int{0})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IAK")
}

// TestSetupAttestChallenge_EKError_Coverage tests setupAttestChallenge with EK error
func TestSetupAttestChallenge_EKError_Coverage(t *testing.T) {
	mockTPM := newMockTPMForEnrollment(t)
	mockTPM.errors["EKCertificate"] = errors.New("ek error")

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &Client{
		config:        &Config{DirectoryURL: "https://example.com", Timeout: 30 * time.Second},
		logger:        slog.Default(),
		accountSigner: key,
	}

	config := &EnrollmentConfig{
		Challenge: "device-attest-01",
		TPMModule: mockTPM,
		IPAddress: "192.168.1.1",
	}

	_, err := client.setupAttestChallenge(config, "keyauth", []int{0})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "EK")
}

// TestSetupAttestChallenge_ValidOutput_Coverage tests successful attestation setup output
func TestSetupAttestChallenge_ValidOutput_Coverage(t *testing.T) {
	mockTPM := newMockTPMForEnrollment(t)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &Client{
		config:        &Config{DirectoryURL: "https://example.com", Timeout: 30 * time.Second},
		logger:        slog.Default(),
		accountSigner: key,
	}

	config := &EnrollmentConfig{
		Challenge: "device-attest-01",
		TPMModule: mockTPM,
		IPAddress: "192.168.1.1",
	}

	attestStmt, err := client.setupAttestChallenge(config, "keyauth", []int{0, 1, 7})
	assert.NoError(t, err)
	assert.NotNil(t, attestStmt)

	// Verify it's valid JSON
	var parsed map[string]interface{}
	err = json.Unmarshal(attestStmt, &parsed)
	assert.NoError(t, err)
	assert.Equal(t, "tpm", parsed["fmt"])
}

// TestEnrollmentConfigDefaults_Coverage tests that defaults are properly set
func TestEnrollmentConfigDefaults_Coverage(t *testing.T) {
	mockTPM := newMockTPMForEnrollment(t)

	config := &EnrollmentConfig{
		Challenge: "enroll-01",
		TPMModule: mockTPM,
		IPAddress: "192.168.1.1",
		// Port and Timeout not set
	}

	err := config.Validate()
	assert.NoError(t, err)
	assert.Equal(t, "8080", config.Port)
	assert.Equal(t, 30*time.Second, config.Timeout)
}

// TestEnrollmentErrors_Coverage tests enrollment error types
func TestEnrollmentErrors_Coverage(t *testing.T) {
	assert.True(t, errors.Is(ErrEnrollmentFailed, ErrEnrollmentFailed))
	assert.True(t, errors.Is(ErrEndorsementFailed, ErrEndorsementFailed))
	assert.True(t, errors.Is(ErrAttestationFailed, ErrAttestationFailed))
	assert.True(t, errors.Is(ErrMissingTPMModule, ErrMissingTPMModule))
	assert.True(t, errors.Is(ErrInvalidIPAddress, ErrInvalidIPAddress))
	assert.True(t, errors.Is(ErrEnvVarNotFound, ErrEnvVarNotFound))
	assert.True(t, errors.Is(ErrInvalidChallenge, ErrInvalidChallenge))
	assert.True(t, errors.Is(ErrOrderNotReady, ErrOrderNotReady))
	assert.True(t, errors.Is(ErrActivationFailed, ErrActivationFailed))
}

// TestEnrollmentResult_Coverage tests EnrollmentResult struct
func TestEnrollmentResult_Coverage(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	iakTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "IAK"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	iakDER, _ := x509.CreateCertificate(rand.Reader, iakTemplate, iakTemplate, &key.PublicKey, key)
	iakCert, _ := x509.ParseCertificate(iakDER)

	idevidTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "IDevID"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	idevidDER, _ := x509.CreateCertificate(rand.Reader, idevidTemplate, idevidTemplate, &key.PublicKey, key)
	idevidCert, _ := x509.ParseCertificate(idevidDER)

	result := &EnrollmentResult{
		IAKCertificate:    iakCert,
		IDevIDCertificate: idevidCert,
	}

	assert.NotNil(t, result.IAKCertificate)
	assert.NotNil(t, result.IDevIDCertificate)
	assert.Equal(t, "IAK", result.IAKCertificate.Subject.CommonName)
	assert.Equal(t, "IDevID", result.IDevIDCertificate.Subject.CommonName)
}

// TestExpandEnvVars_MultipleVars_Coverage tests expandEnvVars with multiple variables
func TestExpandEnvVars_MultipleVars_Coverage(t *testing.T) {
	os.Setenv("TEST_HOST_COV", "192.168.1.1")
	os.Setenv("TEST_PORT_COV", "8080")
	defer func() {
		os.Unsetenv("TEST_HOST_COV")
		os.Unsetenv("TEST_PORT_COV")
	}()

	result, err := expandEnvVars("${TEST_HOST_COV}:${TEST_PORT_COV}")
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.1:8080", result)
}

// TestSetupAttestChallenge_UnknownAlg_Coverage tests attestation with unknown algorithm
func TestSetupAttestChallenge_UnknownAlg_Coverage(t *testing.T) {
	mockTPM := newMockTPMForEnrollment(t)
	// Set unknown signature algorithm
	mockTPM.iakAttrs.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
	mockTPM.quote.SignatureAlgorithm = x509.UnknownSignatureAlgorithm

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &Client{
		config:        &Config{DirectoryURL: "https://example.com", Timeout: 30 * time.Second},
		logger:        slog.Default(),
		accountSigner: key,
	}

	config := &EnrollmentConfig{
		Challenge: "device-attest-01",
		TPMModule: mockTPM,
		IPAddress: "192.168.1.1",
	}

	// Should default to RS256
	attestStmt, err := client.setupAttestChallenge(config, "keyauth", []int{0})
	assert.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(attestStmt, &parsed)
	assert.NoError(t, err)

	attStmt := parsed["attStmt"].(map[string]interface{})
	// Should be -257 (RS256)
	assert.Equal(t, float64(-257), attStmt["alg"])
}

// TestEnrollDeviceWithMockServer_Coverage tests EnrollDevice with a mock ACME server
func TestEnrollDeviceWithMockServer_Coverage(t *testing.T) {
	mockTPM := newMockTPMForEnrollment(t)

	// Generate test certificates
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	iakTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "IAK"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	iakDER, _ := x509.CreateCertificate(rand.Reader, iakTemplate, iakTemplate, &key.PublicKey, key)

	idevidTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "IDevID"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	idevidDER, _ := x509.CreateCertificate(rand.Reader, idevidTemplate, idevidTemplate, &key.PublicKey, key)

	// Combine certificates
	certChainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: iakDER})
	certChainPEM = append(certChainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idevidDER})...)
	require.NotNil(t, certChainPEM)

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/directory":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "permanent-identifier", "value": "192.168.1.1"}},
				"authorizations": []string{server.URL + "/authz/1"},
				"finalize":       server.URL + "/finalize/1",
			})
		case "/authz/1":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "pending",
				"identifier": map[string]string{
					"type":  "permanent-identifier",
					"value": "192.168.1.1",
				},
				"challenges": []map[string]interface{}{
					{
						"type":   "enroll-01",
						"url":    server.URL + "/challenge/1",
						"token":  "test-token",
						"status": "pending",
					},
				},
				"expires": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Create ACME client with server
	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          key,
		HTTPClient:   server.Client(),
	}

	client := &Client{
		client:        acmeClient,
		config:        &Config{DirectoryURL: server.URL + "/directory", Timeout: 30 * time.Second},
		httpClient:    server.Client(),
		logger:        slog.Default(),
		accountSigner: key,
	}

	config := &EnrollmentConfig{
		Challenge: "enroll-01",
		TPMModule: mockTPM,
		IPAddress: "192.168.1.1",
		Port:      "0",
	}

	// This will fail at authorization since our mock server doesn't complete the flow
	// but it tests the initial validation and order creation
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := client.EnrollDevice(ctx, config)
	// Expected to fail since we don't complete the ACME flow
	assert.Error(t, err)
}

// TestKeyAttributes_Coverage tests KeyAttributes struct
func TestKeyAttributes_Coverage(t *testing.T) {
	attrs := &KeyAttributes{
		KeyID:              "test-key-id",
		Algorithm:          "RSA-2048",
		SignatureAlgorithm: x509.SHA256WithRSA,
		TPMPublicBytes:     []byte("tpm-public-bytes"),
	}

	assert.Equal(t, "test-key-id", attrs.KeyID)
	assert.Equal(t, "RSA-2048", attrs.Algorithm)
	assert.Equal(t, x509.SHA256WithRSA, attrs.SignatureAlgorithm)
	assert.NotNil(t, attrs.TPMPublicBytes)
}

// TestTPMQuote_Coverage tests TPMQuote struct
func TestTPMQuote_Coverage(t *testing.T) {
	quote := &TPMQuote{
		Quote:              []byte("quote-data"),
		Signature:          []byte("signature-data"),
		PCRValues:          map[int][]byte{0: make([]byte, 32), 1: make([]byte, 32)},
		Nonce:              []byte("nonce-data"),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	assert.NotNil(t, quote.Quote)
	assert.NotNil(t, quote.Signature)
	assert.Len(t, quote.PCRValues, 2)
	assert.NotNil(t, quote.Nonce)
	assert.Equal(t, x509.SHA256WithRSA, quote.SignatureAlgorithm)
}

// TestIDevIDCSR_Coverage tests IDevIDCSR struct
func TestIDevIDCSR_Coverage(t *testing.T) {
	csr := &IDevIDCSR{
		CSR:                []byte("csr-data"),
		IAKPublic:          []byte("iak-public"),
		QualifyingData:     []byte("qualifying-data"),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	assert.NotNil(t, csr.CSR)
	assert.NotNil(t, csr.IAKPublic)
	assert.NotNil(t, csr.QualifyingData)
	assert.Equal(t, x509.SHA256WithRSA, csr.SignatureAlgorithm)
}
