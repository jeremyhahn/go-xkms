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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/ocsp"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// coveragePushTPMModule implements TPMModule for coverage testing
type coveragePushTPMModule struct {
	ekPubKey         crypto.PublicKey
	ekCert           *x509.Certificate
	ekAttrs          *KeyAttributes
	iakAttrs         *KeyAttributes
	idevidCSR        *IDevIDCSR
	activatedSecret  []byte
	quote            *TPMQuote
	ekCertError      error
	ekAttrsError     error
	iakAttrsError    error
	idevidCSRError   error
	activateError    error
	quoteError       error
	provisionEKError error
	closeError       error
}

func (m *coveragePushTPMModule) EK() crypto.PublicKey {
	return m.ekPubKey
}

func (m *coveragePushTPMModule) EKCertificate() (*x509.Certificate, error) {
	if m.ekCertError != nil {
		return nil, m.ekCertError
	}
	return m.ekCert, nil
}

func (m *coveragePushTPMModule) EKAttributes() (*KeyAttributes, error) {
	if m.ekAttrsError != nil {
		return nil, m.ekAttrsError
	}
	return m.ekAttrs, nil
}

func (m *coveragePushTPMModule) IAKAttributes() (*KeyAttributes, error) {
	if m.iakAttrsError != nil {
		return nil, m.iakAttrsError
	}
	return m.iakAttrs, nil
}

func (m *coveragePushTPMModule) CreateIDevID(qualifyingData []byte) (*IDevIDCSR, error) {
	if m.idevidCSRError != nil {
		return nil, m.idevidCSRError
	}
	return m.idevidCSR, nil
}

func (m *coveragePushTPMModule) ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error) {
	if m.activateError != nil {
		return nil, m.activateError
	}
	return m.activatedSecret, nil
}

func (m *coveragePushTPMModule) ProvisionEKCert(certDER []byte) error {
	return m.provisionEKError
}

func (m *coveragePushTPMModule) Quote(nonce []byte, pcrSelection []int) (*TPMQuote, error) {
	if m.quoteError != nil {
		return nil, m.quoteError
	}
	return m.quote, nil
}

func (m *coveragePushTPMModule) Close() error {
	return m.closeError
}

// coveragePushDNSProvider implements providers.Provider for coverage testing
type coveragePushDNSProvider struct {
	presentError error
	cleanupError error
}

func (m *coveragePushDNSProvider) Present(ctx context.Context, domain, fqdn, value string) error {
	return m.presentError
}

func (m *coveragePushDNSProvider) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	return m.cleanupError
}

// =============================================================================
// ListOrders Tests
// =============================================================================

func TestCoveragePush_ListOrders_Success(t *testing.T) {
	// Create mock server that returns order list
	orders := []string{
		"https://acme.example.com/orders/1",
		"https://acme.example.com/orders/2",
		"https://acme.example.com/orders/3",
	}
	ordersResp := ordersListResponse{Orders: orders}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ordersResp)
	}))
	defer server.Close()

	// Create client with mock HTTP client
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		logger:     slog.Default(),
		httpClient: server.Client(),
		config:     &Config{DirectoryURL: server.URL},
		client: &acme.Client{
			DirectoryURL: server.URL,
			Key:          privateKey,
			HTTPClient:   server.Client(),
		},
	}

	// Mock the client.GetReg by using the test server
	// Since we can't directly mock acme.Client.GetReg, we test fetchOrdersList directly
	orderURLs, err := client.fetchOrdersList(context.Background(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, orders, orderURLs)
}

func TestCoveragePush_FetchOrdersList_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		logger:     slog.Default(),
		httpClient: server.Client(),
		config:     &Config{DirectoryURL: server.URL},
		client: &acme.Client{
			DirectoryURL: server.URL,
			Key:          privateKey,
			HTTPClient:   server.Client(),
		},
	}

	_, err = client.fetchOrdersList(context.Background(), server.URL)
	require.Error(t, err)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.ConnectionFailure, caErr.Type)
}

func TestCoveragePush_FetchOrdersList_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		logger:     slog.Default(),
		httpClient: server.Client(),
		config:     &Config{DirectoryURL: server.URL},
		client: &acme.Client{
			DirectoryURL: server.URL,
			Key:          privateKey,
			HTTPClient:   server.Client(),
		},
	}

	_, err = client.fetchOrdersList(context.Background(), server.URL)
	require.Error(t, err)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.SerializationFailure, caErr.Type)
}

func TestCoveragePush_FetchOrdersList_InvalidURL(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		logger:     slog.Default(),
		httpClient: http.DefaultClient,
		config:     &Config{DirectoryURL: "http://localhost"},
		client: &acme.Client{
			DirectoryURL: "http://localhost",
			Key:          privateKey,
		},
	}

	// Use invalid URL that will fail request creation
	_, err = client.fetchOrdersList(context.Background(), "://invalid")
	require.Error(t, err)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.ConnectionFailure, caErr.Type)
}

// =============================================================================
// DNS Solver Tests
// =============================================================================

func TestCoveragePush_DNSSolver_WaitForPropagation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	provider := &coveragePushDNSProvider{}
	solver, err := NewDNSSolver(provider,
		WithPropagationCheck(100*time.Millisecond, 10*time.Millisecond),
		WithNameservers([]string{"127.0.0.1:53"}),
	)
	require.NoError(t, err)

	// waitForPropagation will timeout since there's no real DNS server
	err = solver.waitForPropagation(ctx, "_acme-challenge.test.com.", "test-value")
	require.Error(t, err)
}

func TestCoveragePush_CheckDNSFromAuthoritative_Error(t *testing.T) {
	checkFunc := CheckDNSFromAuthoritative(WithNameserverLookup(failingNameservers()))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This will fail to get authoritative nameservers for invalid domain
	err := checkFunc(ctx, "_acme-challenge.invalid-domain-xyz-123.", "test-value")
	require.Error(t, err)
}

func TestCoveragePush_CheckDNSFromPublic_RecordNotPresent(t *testing.T) {
	checkFunc := CheckDNSFromPublic(WithPropagationQuery(propagationResult(false)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Query for a non-existent ACME challenge record
	err := checkFunc(ctx, "_acme-challenge.example.test.", "non-existent-value-xyz-123")
	// Should return error because record doesn't exist with that value
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDNSRecordNotPresent)
}

func TestCoveragePush_CheckDNSFromNameservers_Success(t *testing.T) {
	checkFunc := CheckDNSFromNameservers([]string{"8.8.8.8:53"},
		WithPropagationQuery(propagationResult(false)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Query for a non-existent ACME challenge record
	err := checkFunc(ctx, "_acme-challenge.example.test.", "non-existent-value-xyz-123")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDNSRecordNotPresent)
}

func TestCoveragePush_GetAuthoritativeNameservers_ValidDomain(t *testing.T) {
	// The resolver is supplied, so this asserts what the function actually
	// does -- strip the _acme-challenge label and the trailing dot before
	// looking up, then append the DNS port -- rather than asserting that a
	// third party's domain resolves from the runner (go-xkms#243).
	var asked string
	servers, err := authoritativeNameservers("_acme-challenge.example.test.",
		func(name string) ([]*net.NS, error) {
			asked = name
			return []*net.NS{{Host: "ns1.example.test."}, {Host: "ns2.example.test."}}, nil
		})

	require.NoError(t, err)
	assert.Equal(t, "example.test", asked,
		"the _acme-challenge label and the trailing dot must be stripped before the lookup")
	assert.Equal(t, []string{"ns1.example.test.:53", "ns2.example.test.:53"}, servers)
}

func TestCoveragePush_GetAuthoritativeNameservers_InvalidDomain(t *testing.T) {
	// A domain whose NS lookup fails: the error is returned unwrapped.
	wantErr := errors.New("no such host")
	_, err := authoritativeNameservers("_acme-challenge.invalid-domain-xyz-123-abc.",
		func(string) ([]*net.NS, error) { return nil, wantErr })

	require.ErrorIs(t, err, wantErr)
}

func TestCoveragePush_GetAuthoritativeNameservers_NoNameservers(t *testing.T) {
	// A lookup that succeeds but answers with nothing must be an error, not an
	// empty list a caller would then query zero servers with.
	_, err := authoritativeNameservers("_acme-challenge.example.test.",
		func(string) ([]*net.NS, error) { return nil, nil })

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no nameservers found")
}

func TestCoveragePush_DNSSolver_PropagationWaitWithContextCancel(t *testing.T) {
	provider := &coveragePushDNSProvider{}
	solver, err := NewDNSSolver(provider,
		WithPropagationWait(100*time.Millisecond),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	challenge := &acme.Challenge{Type: "dns-01", Token: "test-token"}
	err = solver.Solve(ctx, "example.com", challenge, "key-auth")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestCoveragePush_PreCheckDNSSolver_PreCheckFails(t *testing.T) {
	provider := &coveragePushDNSProvider{}
	baseSolver, err := NewDNSSolver(provider)
	require.NoError(t, err)

	// Create pre-check solver with a function that always fails
	preCheckSolver := WrapPreCheck(baseSolver, &PreCheckOption{
		CheckFunc: func(ctx context.Context, fqdn, value string) error {
			return errors.New("pre-check always fails")
		},
		Timeout:      100 * time.Millisecond,
		Interval:     10 * time.Millisecond,
		AllowFailure: false,
	})

	challenge := &acme.Challenge{Type: "dns-01", Token: "test-token"}
	err = preCheckSolver.Solve(context.Background(), "example.com", challenge, "key-auth")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pre-check failed")
}

func TestCoveragePush_PreCheckDNSSolver_AllowFailure(t *testing.T) {
	provider := &coveragePushDNSProvider{}
	baseSolver, err := NewDNSSolver(provider)
	require.NoError(t, err)

	// Create pre-check solver that allows failure
	preCheckSolver := WrapPreCheck(baseSolver, &PreCheckOption{
		CheckFunc: func(ctx context.Context, fqdn, value string) error {
			return errors.New("pre-check fails but allowed")
		},
		Timeout:      100 * time.Millisecond,
		Interval:     10 * time.Millisecond,
		AllowFailure: true,
	})

	challenge := &acme.Challenge{Type: "dns-01", Token: "test-token"}
	err = preCheckSolver.Solve(context.Background(), "example.com", challenge, "key-auth")
	// Should succeed because AllowFailure is true
	require.NoError(t, err)
}

// =============================================================================
// Enrollment Tests
// =============================================================================

func TestCoveragePush_EnrollmentConfig_Validate(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name    string
		config  *EnrollmentConfig
		wantErr error
	}{
		{
			name:    "empty challenge",
			config:  &EnrollmentConfig{},
			wantErr: ErrInvalidChallenge,
		},
		{
			name: "invalid challenge type",
			config: &EnrollmentConfig{
				Challenge: "invalid-challenge",
			},
			wantErr: ErrInvalidChallenge,
		},
		{
			name: "missing TPM module",
			config: &EnrollmentConfig{
				Challenge: string(ChallengeTypeEnroll01),
			},
			wantErr: ErrMissingTPMModule,
		},
		{
			name: "missing IP address",
			config: &EnrollmentConfig{
				Challenge: string(ChallengeTypeEnroll01),
				TPMModule: &coveragePushTPMModule{ekPubKey: &privateKey.PublicKey},
			},
			wantErr: ErrInvalidIPAddress,
		},
		{
			name: "valid enroll-01 config",
			config: &EnrollmentConfig{
				Challenge: string(ChallengeTypeEnroll01),
				TPMModule: &coveragePushTPMModule{ekPubKey: &privateKey.PublicKey},
				IPAddress: "192.168.1.1",
			},
			wantErr: nil,
		},
		{
			name: "valid endorse-01 config",
			config: &EnrollmentConfig{
				Challenge: string(ChallengeTypeEndorse01),
				TPMModule: &coveragePushTPMModule{ekPubKey: &privateKey.PublicKey},
				IPAddress: "192.168.1.1",
			},
			wantErr: nil,
		},
		{
			name: "valid device-attest-01 config",
			config: &EnrollmentConfig{
				Challenge: string(ChallengeTypeDeviceAttest01),
				TPMModule: &coveragePushTPMModule{ekPubKey: &privateKey.PublicKey},
				IPAddress: "192.168.1.1",
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr != nil {
				require.Error(t, err)
				var caErr *caerrors.TrustedCAError
				if errors.As(err, &caErr) {
					assert.Equal(t, caerrors.Malformed, caErr.Type)
				} else {
					assert.ErrorIs(t, err, tt.wantErr)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCoveragePush_ExpandEnvVars(t *testing.T) {
	// Set test environment variable
	require.NoError(t, os.Setenv("TEST_VAR_COVERAGE", "test-value"))
	defer func() { _ = os.Unsetenv("TEST_VAR_COVERAGE") }()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{
			name:    "no env vars",
			input:   "192.168.1.1",
			want:    "192.168.1.1",
			wantErr: nil,
		},
		{
			name:    "single env var",
			input:   "${TEST_VAR_COVERAGE}",
			want:    "test-value",
			wantErr: nil,
		},
		{
			name:    "env var with prefix",
			input:   "prefix-${TEST_VAR_COVERAGE}",
			want:    "prefix-test-value",
			wantErr: nil,
		},
		{
			name:    "missing env var",
			input:   "${MISSING_VAR_COVERAGE}",
			want:    "",
			wantErr: ErrEnvVarNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := expandEnvVars(tt.input)
			if tt.wantErr != nil {
				require.Error(t, err)
				var caErr *caerrors.TrustedCAError
				if errors.As(err, &caErr) {
					assert.Equal(t, caerrors.Malformed, caErr.Type)
				} else {
					assert.ErrorIs(t, err, tt.wantErr)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, result)
			}
		})
	}
}

func TestCoveragePush_DeviceAttest_InvalidConfig(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		logger:        slog.Default(),
		accountSigner: privateKey,
		config:        &Config{DirectoryURL: "http://localhost"},
	}

	// Invalid config - missing challenge type
	config := &EnrollmentConfig{}
	_, err = client.DeviceAttest(context.Background(), config, []int{0, 1, 2})
	require.Error(t, err)
}

func TestCoveragePush_RequestEndorsementKeyCertificate_NilEK(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		logger:        slog.Default(),
		accountSigner: privateKey,
		config:        &Config{DirectoryURL: "http://localhost"},
	}

	// Mock with nil EK
	config := &EnrollmentConfig{
		Challenge: string(ChallengeTypeEndorse01),
		TPMModule: &coveragePushTPMModule{ekPubKey: nil},
		IPAddress: "192.168.1.1",
	}

	_, err = client.RequestEndorsementKeyCertificate(context.Background(), config)
	require.Error(t, err)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.BadPublicKey, caErr.Type)
}

func TestCoveragePush_EnrollDevice_InvalidEnvVar(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		logger:        slog.Default(),
		accountSigner: privateKey,
		config:        &Config{DirectoryURL: "http://localhost"},
	}

	config := &EnrollmentConfig{
		Challenge: string(ChallengeTypeEnroll01),
		TPMModule: &coveragePushTPMModule{ekPubKey: &privateKey.PublicKey},
		IPAddress: "${MISSING_ENV_VAR_COVERAGE}",
	}

	_, err = client.EnrollDevice(context.Background(), config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expand IP address")
}

// =============================================================================
// OCSP Tests
// =============================================================================

func TestCoveragePush_CheckOCSP_NilCert(t *testing.T) {
	err := CheckOCSP(context.Background(), nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestCoveragePush_CheckOCSP_NilIssuer(t *testing.T) {
	cert, _ := generateTestCertificate(t, "test")
	err := CheckOCSP(context.Background(), cert, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOCSPNoIssuer)
}

func TestCoveragePush_CheckOCSP_NoOCSPServer(t *testing.T) {
	cert, _ := generateTestCertificate(t, "test")
	issuer, _ := generateTestCertificate(t, "issuer")

	err := CheckOCSP(context.Background(), cert, issuer)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOCSPNoResponder)
}

func TestCoveragePush_GetOCSP_HTTPError(t *testing.T) {
	// Create certificate with OCSP server
	cert := coveragePushGenerateCertWithOCSP(t, "http://ocsp.invalid.test")
	issuer, _ := generateTestCertificate(t, "issuer")

	// Use short timeout to fail quickly
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := GetOCSP(ctx, cert, issuer, cert.OCSPServer[0], nil)
	require.Error(t, err)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.ConnectionFailure, caErr.Type)
}

func TestCoveragePush_GetOCSP_MockServer(t *testing.T) {
	// Create CA and end-entity certificate
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	// Create mock OCSP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create OCSP response
		now := time.Now()
		template := ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: big.NewInt(2),
			ThisUpdate:   now,
			NextUpdate:   now.Add(24 * time.Hour),
			ProducedAt:   now,
		}

		response, err := ocsp.CreateResponse(caCert, caCert, template, caKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(response)
	}))
	defer server.Close()

	// Create end-entity certificate with OCSP server
	eeTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Test EE",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		OCSPServer:  []string{server.URL},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	eeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	eeDER, err := x509.CreateCertificate(rand.Reader, eeTemplate, caCert, &eeKey.PublicKey, caKey)
	require.NoError(t, err)
	eeCert, err := x509.ParseCertificate(eeDER)
	require.NoError(t, err)

	// Test GetOCSP
	resp, err := GetOCSP(context.Background(), eeCert, caCert, server.URL, nil)
	require.NoError(t, err)
	assert.True(t, resp.IsGood())
	assert.False(t, resp.IsRevoked())
	assert.False(t, resp.IsUnknown())
}

func TestCoveragePush_GetOCSP_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	cert := coveragePushGenerateCertWithOCSP(t, server.URL)
	issuer, _ := generateTestCertificate(t, "issuer")

	_, err := GetOCSP(context.Background(), cert, issuer, server.URL, nil)
	require.Error(t, err)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.ConnectionFailure, caErr.Type)
}

func TestCoveragePush_OCSPResponse_Methods(t *testing.T) {
	now := time.Now()

	// Test nil response
	var nilResp *OCSPResponse
	assert.False(t, nilResp.IsGood())
	assert.False(t, nilResp.IsRevoked())
	assert.False(t, nilResp.IsUnknown())
	assert.True(t, nilResp.IsStale())
	assert.True(t, nilResp.ShouldRefresh())

	// Test Good response
	goodResp := &OCSPResponse{
		Response: &ocsp.Response{
			Status: ocsp.Good,
		},
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
	}
	assert.True(t, goodResp.IsGood())
	assert.False(t, goodResp.IsRevoked())
	assert.False(t, goodResp.IsUnknown())
	assert.False(t, goodResp.IsStale())
	assert.False(t, goodResp.ShouldRefresh())

	// Test Revoked response
	revokedResp := &OCSPResponse{
		Response: &ocsp.Response{
			Status: ocsp.Revoked,
		},
	}
	assert.False(t, revokedResp.IsGood())
	assert.True(t, revokedResp.IsRevoked())
	assert.False(t, revokedResp.IsUnknown())

	// Test Unknown response
	unknownResp := &OCSPResponse{
		Response: &ocsp.Response{
			Status: ocsp.Unknown,
		},
	}
	assert.False(t, unknownResp.IsGood())
	assert.False(t, unknownResp.IsRevoked())
	assert.True(t, unknownResp.IsUnknown())

	// Test stale response
	staleResp := &OCSPResponse{
		Response: &ocsp.Response{
			Status: ocsp.Good,
		},
		ThisUpdate: now.Add(-48 * time.Hour),
		NextUpdate: now.Add(-24 * time.Hour),
	}
	assert.True(t, staleResp.IsStale())
	assert.True(t, staleResp.ShouldRefresh())
}

func TestCoveragePush_HasMustStaple(t *testing.T) {
	// Test nil certificate
	assert.False(t, HasMustStaple(nil))

	// Test certificate without MustStaple
	cert, _ := generateTestCertificate(t, "test")
	assert.False(t, HasMustStaple(cert))

	// Test certificate with MustStaple
	certWithMustStaple := coveragePushGenerateCertWithMustStaple(t)
	assert.True(t, HasMustStaple(certWithMustStaple))
}

// =============================================================================
// DeactivateAccount Tests
// =============================================================================

func TestCoveragePush_DeactivateAccount_NoStorage(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status": "deactivated"}`))
	}))
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		logger:       slog.Default(),
		httpClient:   server.Client(),
		storage:      nil, // No storage
		accountEmail: "test@example.com",
		config:       &Config{DirectoryURL: server.URL},
		client: &acme.Client{
			DirectoryURL: server.URL,
			Key:          privateKey,
			HTTPClient:   server.Client(),
		},
	}

	// This will fail because acme.Client.DeactivateReg needs proper ACME directory
	err = client.DeactivateAccount(context.Background())
	// Error is expected because we don't have a real ACME server
	require.Error(t, err)
}

// =============================================================================
// COSE Algorithm Tests
// =============================================================================

func TestCoveragePush_COSEAlgorithmFromSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		sigAlgo  x509.SignatureAlgorithm
		expected COSEAlgorithm
	}{
		{"ES256", x509.ECDSAWithSHA256, COSEAlgorithmES256},
		{"ES384", x509.ECDSAWithSHA384, COSEAlgorithmES384},
		{"ES512", x509.ECDSAWithSHA512, COSEAlgorithmES512},
		{"RS256", x509.SHA256WithRSA, COSEAlgorithmRS256},
		{"RS384", x509.SHA384WithRSA, COSEAlgorithmRS384},
		{"RS512", x509.SHA512WithRSA, COSEAlgorithmRS512},
		{"PS256", x509.SHA256WithRSAPSS, COSEAlgorithmPS256},
		{"PS384", x509.SHA384WithRSAPSS, COSEAlgorithmPS384},
		{"PS512", x509.SHA512WithRSAPSS, COSEAlgorithmPS512},
		{"EdDSA", x509.PureEd25519, COSEAlgorithmEdDSA},
		{"Unknown", x509.MD5WithRSA, COSEAlgorithmUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := COSEAlgorithmFromSignatureAlgorithm(tt.sigAlgo)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCoveragePush_SignatureAlgorithmFromCOSE(t *testing.T) {
	tests := []struct {
		name     string
		coseAlg  COSEAlgorithm
		expected x509.SignatureAlgorithm
	}{
		{"ES256", COSEAlgorithmES256, x509.ECDSAWithSHA256},
		{"ES384", COSEAlgorithmES384, x509.ECDSAWithSHA384},
		{"ES512", COSEAlgorithmES512, x509.ECDSAWithSHA512},
		{"RS256", COSEAlgorithmRS256, x509.SHA256WithRSA},
		{"RS384", COSEAlgorithmRS384, x509.SHA384WithRSA},
		{"RS512", COSEAlgorithmRS512, x509.SHA512WithRSA},
		{"PS256", COSEAlgorithmPS256, x509.SHA256WithRSAPSS},
		{"PS384", COSEAlgorithmPS384, x509.SHA384WithRSAPSS},
		{"PS512", COSEAlgorithmPS512, x509.SHA512WithRSAPSS},
		{"EdDSA", COSEAlgorithmEdDSA, x509.PureEd25519},
		{"Unknown", COSEAlgorithmUnknown, x509.UnknownSignatureAlgorithm},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SignatureAlgorithmFromCOSE(tt.coseAlg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// DNS Solver Additional Coverage Tests
// =============================================================================

func TestCoveragePush_DNSSolver_WithOptions(t *testing.T) {
	provider := &coveragePushDNSProvider{}

	// Test with all options
	solver, err := NewDNSSolver(provider,
		WithPropagationWait(5*time.Second),
		WithPropagationCheck(60*time.Second, 2*time.Second),
		WithNameservers([]string{"1.1.1.1:53", "8.8.8.8:53"}),
		WithRecordTTL(300),
	)
	require.NoError(t, err)
	assert.NotNil(t, solver)
	assert.True(t, solver.checkPropagation)
	assert.Equal(t, 5*time.Second, solver.propagationWait)
	assert.Equal(t, 60*time.Second, solver.propagationTimeout)
	assert.Equal(t, 2*time.Second, solver.propagationInterval)
	assert.Equal(t, []string{"1.1.1.1:53", "8.8.8.8:53"}, solver.nameservers)
	assert.Equal(t, 300, solver.recordTTL)
}

func TestCoveragePush_DNSSolver_NilProvider(t *testing.T) {
	_, err := NewDNSSolver(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilProvider)
}

func TestCoveragePush_DNSSolver_SolveAfterClose(t *testing.T) {
	provider := &coveragePushDNSProvider{}
	solver, err := NewDNSSolver(provider)
	require.NoError(t, err)

	err = solver.Close()
	require.NoError(t, err)
	assert.True(t, solver.IsClosed())

	challenge := &acme.Challenge{Type: "dns-01", Token: "test"}
	err = solver.Solve(context.Background(), "example.com", challenge, "key-auth")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDNSSolverClosed)
}

func TestCoveragePush_DNSSolver_CleanupAfterClose(t *testing.T) {
	provider := &coveragePushDNSProvider{}
	solver, err := NewDNSSolver(provider)
	require.NoError(t, err)

	err = solver.Close()
	require.NoError(t, err)

	challenge := &acme.Challenge{Type: "dns-01", Token: "test"}
	err = solver.Cleanup(context.Background(), "example.com", challenge)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDNSSolverClosed)
}

func TestCoveragePush_DNSSolver_SolveEmptyDomain(t *testing.T) {
	provider := &coveragePushDNSProvider{}
	solver, err := NewDNSSolver(provider)
	require.NoError(t, err)

	challenge := &acme.Challenge{Type: "dns-01", Token: "test"}
	err = solver.Solve(context.Background(), "", challenge, "key-auth")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEmptyDomain)
}

func TestCoveragePush_DNSSolver_SolveNilChallenge(t *testing.T) {
	provider := &coveragePushDNSProvider{}
	solver, err := NewDNSSolver(provider)
	require.NoError(t, err)

	err = solver.Solve(context.Background(), "example.com", nil, "key-auth")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilChallenge)
}

func TestCoveragePush_DNSSolver_SolveEmptyKeyAuth(t *testing.T) {
	provider := &coveragePushDNSProvider{}
	solver, err := NewDNSSolver(provider)
	require.NoError(t, err)

	challenge := &acme.Challenge{Type: "dns-01", Token: "test"}
	err = solver.Solve(context.Background(), "example.com", challenge, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEmptyKeyAuth)
}

func TestCoveragePush_DNSSolver_CleanupEmptyDomain(t *testing.T) {
	provider := &coveragePushDNSProvider{}
	solver, err := NewDNSSolver(provider)
	require.NoError(t, err)

	challenge := &acme.Challenge{Type: "dns-01", Token: "test"}
	err = solver.Cleanup(context.Background(), "", challenge)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEmptyDomain)
}

func TestCoveragePush_DNSSolver_CleanupNilChallenge(t *testing.T) {
	provider := &coveragePushDNSProvider{}
	solver, err := NewDNSSolver(provider)
	require.NoError(t, err)

	err = solver.Cleanup(context.Background(), "example.com", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilChallenge)
}

func TestCoveragePush_DNSSolver_CleanupNonExistentRecord(t *testing.T) {
	provider := &coveragePushDNSProvider{}
	solver, err := NewDNSSolver(provider)
	require.NoError(t, err)

	// Cleanup without solving first - record doesn't exist
	challenge := &acme.Challenge{Type: "dns-01", Token: "test"}
	err = solver.Cleanup(context.Background(), "example.com", challenge)
	require.NoError(t, err)
}

func TestCoveragePush_DNSSolver_CleanupProviderError(t *testing.T) {
	provider := &coveragePushDNSProvider{cleanupError: errors.New("cleanup failed")}
	solver, err := NewDNSSolver(provider)
	require.NoError(t, err)

	// First solve to add record
	challenge := &acme.Challenge{Type: "dns-01", Token: "test"}
	err = solver.Solve(context.Background(), "example.com", challenge, "key-auth")
	require.NoError(t, err)

	// Now cleanup should fail
	err = solver.Cleanup(context.Background(), "example.com", challenge)
	require.Error(t, err)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.DNS, caErr.Type)
}

func TestCoveragePush_DNSSolver_PresentError(t *testing.T) {
	provider := &coveragePushDNSProvider{presentError: errors.New("present failed")}
	solver, err := NewDNSSolver(provider)
	require.NoError(t, err)

	challenge := &acme.Challenge{Type: "dns-01", Token: "test"}
	err = solver.Solve(context.Background(), "example.com", challenge, "key-auth")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to present record")
}

func TestCoveragePush_DNSSolver_ActiveRecordCount(t *testing.T) {
	provider := &coveragePushDNSProvider{}
	solver, err := NewDNSSolver(provider)
	require.NoError(t, err)

	assert.Equal(t, 0, solver.ActiveRecordCount())

	challenge := &acme.Challenge{Type: "dns-01", Token: "test"}
	err = solver.Solve(context.Background(), "example.com", challenge, "key-auth")
	require.NoError(t, err)

	assert.Equal(t, 1, solver.ActiveRecordCount())
}

func TestCoveragePush_ComputeDNS01ChallengeValue(t *testing.T) {
	keyAuth := "test-key-authorization"
	value := ComputeDNS01ChallengeValue(keyAuth)
	assert.NotEmpty(t, value)

	// Same input should produce same output
	value2 := ComputeDNS01ChallengeValue(keyAuth)
	assert.Equal(t, value, value2)

	// Different input should produce different output
	value3 := ComputeDNS01ChallengeValue("different-key-auth")
	assert.NotEqual(t, value, value3)
}

func TestCoveragePush_PreCheckDNSSolver_NilOption(t *testing.T) {
	provider := &coveragePushDNSProvider{}
	solver, err := NewDNSSolver(provider)
	require.NoError(t, err)

	// Test with nil option - should use defaults
	preCheckSolver := WrapPreCheck(solver, nil)
	assert.NotNil(t, preCheckSolver)
	assert.Equal(t, providers.PropagationTimeout, preCheckSolver.option.Timeout)
	assert.Equal(t, providers.PropagationPoll, preCheckSolver.option.Interval)
}

func TestCoveragePush_PreCheckDNSSolver_Methods(t *testing.T) {
	provider := &coveragePushDNSProvider{}
	solver, err := NewDNSSolver(provider)
	require.NoError(t, err)

	preCheckSolver := WrapPreCheck(solver, &PreCheckOption{
		Timeout:  10 * time.Second,
		Interval: 1 * time.Second,
	})

	assert.Equal(t, string(ChallengeTypeDNS01), preCheckSolver.Type())
	assert.False(t, preCheckSolver.IsClosed())
	assert.Equal(t, 0, preCheckSolver.ActiveRecordCount())

	err = preCheckSolver.Close()
	require.NoError(t, err)
	assert.True(t, preCheckSolver.IsClosed())
}

func TestCoveragePush_DefaultPreCheckOption(t *testing.T) {
	opt := DefaultPreCheckOption()
	assert.NotNil(t, opt)
	assert.Equal(t, providers.PropagationTimeout, opt.Timeout)
	assert.Equal(t, providers.PropagationPoll, opt.Interval)
	assert.False(t, opt.AllowFailure)
	assert.Nil(t, opt.CheckFunc)
}

// =============================================================================
// Client GetOCSP Method Test
// =============================================================================

func TestCoveragePush_Client_GetOCSP_NoCert(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		logger:     slog.Default(),
		httpClient: http.DefaultClient,
		config:     &Config{DirectoryURL: "http://localhost"},
		client: &acme.Client{
			DirectoryURL: "http://localhost",
			Key:          privateKey,
		},
	}

	_, err = client.GetOCSP(context.Background(), nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestCoveragePush_Client_GetOCSP_NoIssuer(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert, _ := generateTestCertificate(t, "test")

	client := &Client{
		logger:     slog.Default(),
		httpClient: http.DefaultClient,
		config:     &Config{DirectoryURL: "http://localhost"},
		client: &acme.Client{
			DirectoryURL: "http://localhost",
			Key:          privateKey,
		},
	}

	_, err = client.GetOCSP(context.Background(), cert, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOCSPNoIssuer)
}

func TestCoveragePush_Client_GetOCSP_NoOCSPServer(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert, _ := generateTestCertificate(t, "test")
	issuer, _ := generateTestCertificate(t, "issuer")

	client := &Client{
		logger:     slog.Default(),
		httpClient: http.DefaultClient,
		config:     &Config{DirectoryURL: "http://localhost"},
		client: &acme.Client{
			DirectoryURL: "http://localhost",
			Key:          privateKey,
		},
	}

	_, err = client.GetOCSP(context.Background(), cert, issuer)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOCSPNoResponder)
}

// =============================================================================
// Helper Functions
// =============================================================================

func coveragePushGenerateCertWithOCSP(t *testing.T, ocspURL string) *x509.Certificate {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		OCSPServer:            []string{ocspURL},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func coveragePushGenerateCertWithMustStaple(t *testing.T) *x509.Certificate {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Must-Staple extension value: status_request (5)
	mustStapleValue, err := asn1.Marshal([]int{5})
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-must-staple",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       MustStapleOID,
				Critical: false,
				Value:    mustStapleValue,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
