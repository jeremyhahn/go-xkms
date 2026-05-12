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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/internal/acmetestutil"
)

// preAuthMockServer creates a mock ACME server for pre-authorization testing
type preAuthMockServer struct {
	*httptest.Server
	t               *testing.T
	nonce           string
	supportsPreAuth bool
	authzShouldFail bool
	authzFailStatus int
	authzFailType   string
	authzFailDetail string
}

// newPreAuthMockServer creates a new mock server with pre-auth support
func newPreAuthMockServer(t *testing.T, supportsPreAuth bool) *preAuthMockServer {
	m := &preAuthMockServer{
		t:               t,
		nonce:           "preauth-nonce-12345",
		supportsPreAuth: supportsPreAuth,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/directory", m.handleDirectory)
	mux.HandleFunc("/acme/new-nonce", m.handleNewNonce)
	mux.HandleFunc("/acme/new-account", m.handleNewAccount)
	mux.HandleFunc("/acme/new-authz", m.handleNewAuthz)
	mux.HandleFunc("/acme/authz/", m.handleAuthz)
	mux.HandleFunc("/acme/account/", m.handleAccount)
	mux.HandleFunc("/ca-bundle", m.handleCABundle)

	m.Server = httptest.NewTLSServer(mux)
	return m
}

func (m *preAuthMockServer) handleDirectory(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce)
	w.Header().Set("Content-Type", "application/json")

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

	// Only include newAuthz if pre-auth is supported
	if m.supportsPreAuth {
		directory["newAuthz"] = m.Server.URL + "/acme/new-authz"
	}

	_ = json.NewEncoder(w).Encode(directory)
}

func (m *preAuthMockServer) handleNewNonce(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (m *preAuthMockServer) handleNewAccount(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", m.Server.URL+"/acme/account/1")

	account := map[string]interface{}{
		"status":  "valid",
		"contact": []string{"mailto:test@example.com"},
		"orders":  m.Server.URL + "/acme/account/1/orders",
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(account)
}

func (m *preAuthMockServer) handleAccount(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", m.Server.URL+"/acme/account/1")

	account := map[string]interface{}{
		"status":  "valid",
		"contact": []string{"mailto:test@example.com"},
		"orders":  m.Server.URL + "/acme/account/1/orders",
	}

	_ = json.NewEncoder(w).Encode(account)
}

func (m *preAuthMockServer) handleNewAuthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce)
	w.Header().Set("Content-Type", "application/json")

	if m.authzShouldFail {
		m.writeACMEError(w, m.authzFailStatus, m.authzFailType, m.authzFailDetail)
		return
	}

	// Parse the request body to get the identifier
	var req struct {
		Identifier struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifier"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// If parsing fails, use default values
		req.Identifier.Type = "dns"
		req.Identifier.Value = "example.com"
	}

	// Generate a unique authz ID
	authzID := strings.ReplaceAll(req.Identifier.Value, ".", "-")
	authzURL := m.Server.URL + "/acme/authz/" + authzID

	w.Header().Set("Location", authzURL)
	w.WriteHeader(http.StatusCreated)

	authz := map[string]interface{}{
		"status":  "pending",
		"expires": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"identifier": map[string]string{
			"type":  req.Identifier.Type,
			"value": req.Identifier.Value,
		},
		"challenges": []map[string]interface{}{
			{
				"type":   "http-01",
				"url":    m.Server.URL + "/acme/challenge/" + authzID + "/http-01",
				"token":  "test-token-http-01",
				"status": "pending",
			},
			{
				"type":   "dns-01",
				"url":    m.Server.URL + "/acme/challenge/" + authzID + "/dns-01",
				"token":  "test-token-dns-01",
				"status": "pending",
			},
		},
	}

	_ = json.NewEncoder(w).Encode(authz)
}

func (m *preAuthMockServer) handleAuthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce)
	w.Header().Set("Content-Type", "application/json")

	// Extract authz ID from URL
	authzID := strings.TrimPrefix(r.URL.Path, "/acme/authz/")
	domain := strings.ReplaceAll(authzID, "-", ".")

	authz := map[string]interface{}{
		"status":  "pending",
		"expires": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"identifier": map[string]string{
			"type":  "dns",
			"value": domain,
		},
		"challenges": []map[string]interface{}{
			{
				"type":   "http-01",
				"url":    m.Server.URL + "/acme/challenge/" + authzID + "/http-01",
				"token":  "test-token-http-01",
				"status": "pending",
			},
		},
	}

	_ = json.NewEncoder(w).Encode(authz)
}

func (m *preAuthMockServer) writeACMEError(w http.ResponseWriter, statusCode int, errType, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(statusCode)
	errorResp := map[string]interface{}{
		"type":   errType,
		"detail": detail,
		"status": statusCode,
	}
	_ = json.NewEncoder(w).Encode(errorResp)
}

func (m *preAuthMockServer) handleCABundle(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/pem-certificate-chain")

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	_, _ = w.Write(certPEM)
}

// createPreAuthTestClient creates a client configured for pre-auth testing
func createPreAuthTestClient(t *testing.T, server *preAuthMockServer) *Client {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := DefaultConfig()
	config.DirectoryURL = server.Server.URL + "/directory"
	config.SystemCertPool = false
	config.RequestServerBundle = false

	mockStore := newMockStorage()

	params := &Params{
		AccountEmail:       "test@example.com",
		AccountSigner:      privateKey,
		Config:             config,
		Logger:             logger,
		Storage:            mockStore,
		CertificateStorage: newMockCertStorage(),
		OrderStorage:       newMockOrderStorage(),
	}

	client, err := NewClient(params)
	require.NoError(t, err)

	client.httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   testutil.TLSConfigFromServer(server.Server),
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second,
	}
	client.client.HTTPClient = client.httpClient

	return client
}

// TestSupportsPreAuthorization_Supported tests when server supports pre-auth
func TestSupportsPreAuthorization_Supported(t *testing.T) {
	server := newPreAuthMockServer(t, true)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	supported := client.SupportsPreAuthorization(context.Background())

	assert.True(t, supported, "expected pre-authorization to be supported")
}

// TestSupportsPreAuthorization_NotSupported tests when server does not support pre-auth
func TestSupportsPreAuthorization_NotSupported(t *testing.T) {
	server := newPreAuthMockServer(t, false)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	supported := client.SupportsPreAuthorization(context.Background())

	assert.False(t, supported, "expected pre-authorization to not be supported")
}

// TestSupportsPreAuthorization_DiscoveryError tests when discovery fails
func TestSupportsPreAuthorization_DiscoveryError(t *testing.T) {
	// Create a server that returns invalid JSON for directory
	// Use 404 Not Found to avoid acme library's retry logic on 5xx errors
	mux := http.NewServeMux()
	mux.HandleFunc("/directory", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:malformed","detail":"not found"}`))
	})

	server := httptest.NewTLSServer(mux)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := DefaultConfig()
	config.DirectoryURL = server.URL + "/directory"
	config.SystemCertPool = false
	config.RequestServerBundle = false

	mockStore := newMockStorage()

	params := &Params{
		AccountEmail:  "test@example.com",
		AccountSigner: privateKey,
		Config:        config,
		Logger:        logger,
		Storage:       mockStore,
	}

	client, err := NewClient(params)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	client.httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   testutil.TLSConfigFromServer(server),
			DisableKeepAlives: true,
		},
		Timeout: 5 * time.Second,
	}
	client.client.HTTPClient = client.httpClient

	// Use a context with timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	supported := client.SupportsPreAuthorization(ctx)

	assert.False(t, supported, "expected false when discovery fails")
}

// TestPreAuthorize_Success tests successful pre-authorization
func TestPreAuthorize_Success(t *testing.T) {
	server := newPreAuthMockServer(t, true)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	// Register account first
	_, err := client.RegisterAccount()
	require.NoError(t, err)

	identifier := Identifier{
		Type:  "dns",
		Value: "example.com",
	}

	authz, err := client.PreAuthorize(context.Background(), identifier)

	require.NoError(t, err)
	assert.NotNil(t, authz)
	assert.Equal(t, "pending", authz.Status)
	assert.NotEmpty(t, authz.Challenges)
}

// TestPreAuthorize_NotSupported tests pre-authorization when not supported
func TestPreAuthorize_NotSupported(t *testing.T) {
	server := newPreAuthMockServer(t, false)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	// Register account first
	_, err := client.RegisterAccount()
	require.NoError(t, err)

	identifier := Identifier{
		Type:  "dns",
		Value: "example.com",
	}

	authz, err := client.PreAuthorize(context.Background(), identifier)

	assert.Nil(t, authz)
	assert.ErrorIs(t, err, ErrPreAuthNotSupported)
}

// TestPreAuthorize_InvalidIdentifier_EmptyType tests with empty type
func TestPreAuthorize_InvalidIdentifier_EmptyType(t *testing.T) {
	server := newPreAuthMockServer(t, true)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	identifier := Identifier{
		Type:  "",
		Value: "example.com",
	}

	authz, err := client.PreAuthorize(context.Background(), identifier)

	assert.Nil(t, authz)
	assert.ErrorIs(t, err, ErrPreAuthInvalidIdentifier)
}

// TestPreAuthorize_InvalidIdentifier_EmptyValue tests with empty value
func TestPreAuthorize_InvalidIdentifier_EmptyValue(t *testing.T) {
	server := newPreAuthMockServer(t, true)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	identifier := Identifier{
		Type:  "dns",
		Value: "",
	}

	authz, err := client.PreAuthorize(context.Background(), identifier)

	assert.Nil(t, authz)
	assert.ErrorIs(t, err, ErrPreAuthInvalidIdentifier)
}

// TestPreAuthorize_ServerError tests handling of server errors
func TestPreAuthorize_ServerError(t *testing.T) {
	server := newPreAuthMockServer(t, true)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	// Register account first
	_, err := client.RegisterAccount()
	require.NoError(t, err)

	// Configure server to fail
	server.authzShouldFail = true
	server.authzFailStatus = http.StatusForbidden
	server.authzFailType = "urn:ietf:params:acme:error:rejectedIdentifier"
	server.authzFailDetail = "The identifier is not allowed"

	identifier := Identifier{
		Type:  "dns",
		Value: "forbidden.example.com",
	}

	authz, err := client.PreAuthorize(context.Background(), identifier)

	assert.Nil(t, authz)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPreAuthFailed)
}

// TestPreAuthorize_ContextCancellation tests with cancelled context
func TestPreAuthorize_ContextCancellation(t *testing.T) {
	server := newPreAuthMockServer(t, true)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	// Register account first
	_, err := client.RegisterAccount()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	identifier := Identifier{
		Type:  "dns",
		Value: "example.com",
	}

	authz, err := client.PreAuthorize(ctx, identifier)

	assert.Nil(t, authz)
	assert.Error(t, err)
}

// TestPreAuthorize_IPIdentifier tests pre-authorization with IP identifier
func TestPreAuthorize_IPIdentifier(t *testing.T) {
	server := newPreAuthMockServer(t, true)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	// Register account first
	_, err := client.RegisterAccount()
	require.NoError(t, err)

	identifier := Identifier{
		Type:  "ip",
		Value: "192.0.2.1",
	}

	authz, err := client.PreAuthorize(context.Background(), identifier)

	require.NoError(t, err)
	assert.NotNil(t, authz)
	assert.Equal(t, "pending", authz.Status)
}

// TestPreAuthorizeMany_Success tests successful bulk pre-authorization
func TestPreAuthorizeMany_Success(t *testing.T) {
	server := newPreAuthMockServer(t, true)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	// Register account first
	_, err := client.RegisterAccount()
	require.NoError(t, err)

	identifiers := []Identifier{
		{Type: "dns", Value: "example1.com"},
		{Type: "dns", Value: "example2.com"},
		{Type: "dns", Value: "example3.com"},
	}

	authzs, err := client.PreAuthorizeMany(context.Background(), identifiers)

	require.NoError(t, err)
	assert.Len(t, authzs, 3)
	for i, authz := range authzs {
		assert.NotNil(t, authz, "authorization %d should not be nil", i)
		assert.Equal(t, "pending", authz.Status)
	}
}

// TestPreAuthorizeMany_EmptyList tests with empty identifier list
func TestPreAuthorizeMany_EmptyList(t *testing.T) {
	server := newPreAuthMockServer(t, true)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	authzs, err := client.PreAuthorizeMany(context.Background(), []Identifier{})

	require.NoError(t, err)
	assert.Empty(t, authzs)
}

// TestPreAuthorizeMany_NotSupported tests when server doesn't support pre-auth
func TestPreAuthorizeMany_NotSupported(t *testing.T) {
	server := newPreAuthMockServer(t, false)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	identifiers := []Identifier{
		{Type: "dns", Value: "example.com"},
	}

	authzs, err := client.PreAuthorizeMany(context.Background(), identifiers)

	assert.Nil(t, authzs)
	assert.ErrorIs(t, err, ErrPreAuthNotSupported)
}

// TestPreAuthorizeMany_PartialFailure tests when some authorizations fail
func TestPreAuthorizeMany_PartialFailure(t *testing.T) {
	server := newPreAuthMockServer(t, true)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	// Register account first
	_, err := client.RegisterAccount()
	require.NoError(t, err)

	// After first request, configure server to fail
	originalHandler := server.Server.Config.Handler
	requestCount := 0
	server.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/acme/new-authz" {
			requestCount++
			if requestCount > 1 {
				server.authzShouldFail = true
				server.authzFailStatus = http.StatusForbidden
				server.authzFailType = "urn:ietf:params:acme:error:rejectedIdentifier"
				server.authzFailDetail = "Second identifier rejected"
			}
		}
		originalHandler.ServeHTTP(w, r)
	})

	identifiers := []Identifier{
		{Type: "dns", Value: "success.example.com"},
		{Type: "dns", Value: "fail.example.com"},
	}

	authzs, err := client.PreAuthorizeMany(context.Background(), identifiers)

	// Should return error on partial failure
	assert.Nil(t, authzs)
	assert.Error(t, err)
}

// TestPreAuthorizeDomains_Success tests domain convenience method
func TestPreAuthorizeDomains_Success(t *testing.T) {
	server := newPreAuthMockServer(t, true)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	// Register account first
	_, err := client.RegisterAccount()
	require.NoError(t, err)

	authzs, err := client.PreAuthorizeDomains(context.Background(), "example1.com", "example2.com")

	require.NoError(t, err)
	assert.Len(t, authzs, 2)
	for _, authz := range authzs {
		assert.NotNil(t, authz)
		assert.Equal(t, "pending", authz.Status)
	}
}

// TestPreAuthorizeDomains_Empty tests with no domains
func TestPreAuthorizeDomains_Empty(t *testing.T) {
	server := newPreAuthMockServer(t, true)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	authzs, err := client.PreAuthorizeDomains(context.Background())

	require.NoError(t, err)
	assert.Empty(t, authzs)
}

// TestPreAuthorizeIPs_Success tests IP convenience method
func TestPreAuthorizeIPs_Success(t *testing.T) {
	server := newPreAuthMockServer(t, true)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	// Register account first
	_, err := client.RegisterAccount()
	require.NoError(t, err)

	authzs, err := client.PreAuthorizeIPs(context.Background(), "192.0.2.1", "192.0.2.2")

	require.NoError(t, err)
	assert.Len(t, authzs, 2)
}

// TestPreAuthorizeIPs_Empty tests with no IPs
func TestPreAuthorizeIPs_Empty(t *testing.T) {
	server := newPreAuthMockServer(t, true)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	authzs, err := client.PreAuthorizeIPs(context.Background())

	require.NoError(t, err)
	assert.Empty(t, authzs)
}

// TestPreAuthorize_WildcardDomain tests pre-authorization with wildcard domain
func TestPreAuthorize_WildcardDomain(t *testing.T) {
	server := newPreAuthMockServer(t, true)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	// Register account first
	_, err := client.RegisterAccount()
	require.NoError(t, err)

	identifier := Identifier{
		Type:  "dns",
		Value: "*.example.com",
	}

	authz, err := client.PreAuthorize(context.Background(), identifier)

	require.NoError(t, err)
	assert.NotNil(t, authz)
	assert.Equal(t, "pending", authz.Status)
}

// TestPreAuthorizeMany_ConcurrentExecution tests concurrent execution
func TestPreAuthorizeMany_ConcurrentExecution(t *testing.T) {
	server := newPreAuthMockServer(t, true)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	// Register account first
	_, err := client.RegisterAccount()
	require.NoError(t, err)

	// Create many identifiers to test concurrent processing
	identifiers := make([]Identifier, 10)
	for i := range identifiers {
		identifiers[i] = Identifier{
			Type:  "dns",
			Value: strings.ReplaceAll("example{i}.com", "{i}", string(rune('0'+i))),
		}
	}

	authzs, err := client.PreAuthorizeMany(context.Background(), identifiers)

	require.NoError(t, err)
	assert.Len(t, authzs, 10)

	// Verify all authorizations are present and in order
	for i, authz := range authzs {
		assert.NotNil(t, authz, "authorization %d should not be nil", i)
		assert.Equal(t, "pending", authz.Status)
	}
}

// TestPreAuthorize_IPv6 tests pre-authorization with IPv6 address
func TestPreAuthorize_IPv6(t *testing.T) {
	server := newPreAuthMockServer(t, true)
	defer server.Close()

	client := createPreAuthTestClient(t, server)
	defer func() { _ = client.Close() }()

	// Register account first
	_, err := client.RegisterAccount()
	require.NoError(t, err)

	identifier := Identifier{
		Type:  "ip",
		Value: "2001:db8::1",
	}

	authz, err := client.PreAuthorize(context.Background(), identifier)

	require.NoError(t, err)
	assert.NotNil(t, authz)
	assert.Equal(t, "pending", authz.Status)
}
