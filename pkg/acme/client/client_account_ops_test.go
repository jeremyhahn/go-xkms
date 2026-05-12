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

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// accountOpsMockServer creates a mock ACME server specifically for account operations testing
type accountOpsMockServer struct {
	*httptest.Server
	t              *testing.T
	nonce          string
	accountStatus  string
	accountContact []string
	accountURI     string

	// Error simulation flags
	updateShouldFail     bool
	deactivateShouldFail bool
}

// newAccountOpsMockServer creates a new mock ACME server for account operations
func newAccountOpsMockServer(t *testing.T) *accountOpsMockServer {
	m := &accountOpsMockServer{
		t:              t,
		nonce:          "mock-nonce-12345",
		accountStatus:  "valid",
		accountContact: []string{"mailto:test@example.com"},
	}

	mux := http.NewServeMux()

	// Directory endpoint
	mux.HandleFunc("/directory", m.handleDirectory)

	// New nonce endpoint
	mux.HandleFunc("/acme/new-nonce", m.handleNewNonce)

	// New account endpoint
	mux.HandleFunc("/acme/new-account", m.handleNewAccount)

	// Account endpoint (for updates, deactivation, and GET)
	mux.HandleFunc("/acme/account/", m.handleAccount)

	// CA bundle endpoint
	mux.HandleFunc("/ca-bundle", m.handleCABundle)

	m.Server = httptest.NewTLSServer(mux)
	m.accountURI = m.Server.URL + "/acme/account/1"
	return m
}

func (m *accountOpsMockServer) handleDirectory(w http.ResponseWriter, _ *http.Request) {
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

	_ = json.NewEncoder(w).Encode(directory)
}

func (m *accountOpsMockServer) handleNewNonce(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (m *accountOpsMockServer) handleNewAccount(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", m.accountURI)

	account := map[string]interface{}{
		"status":  m.accountStatus,
		"contact": m.accountContact,
		"orders":  m.Server.URL + "/acme/account/1/orders",
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(account)
}

func (m *accountOpsMockServer) handleAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", m.nonce)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", m.accountURI)

	// Handle update failures
	if r.Method == http.MethodPost && m.updateShouldFail {
		m.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:invalidContact",
			"Invalid contact information")
		return
	}

	// Handle deactivation failures
	if r.Method == http.MethodPost && m.deactivateShouldFail {
		m.writeACMEError(w, http.StatusForbidden, "urn:ietf:params:acme:error:unauthorized",
			"Account cannot be deactivated")
		return
	}

	// Return the current account state
	account := map[string]interface{}{
		"status":  m.accountStatus,
		"contact": m.accountContact,
		"orders":  m.Server.URL + "/acme/account/1/orders",
	}

	_ = json.NewEncoder(w).Encode(account)
}

func (m *accountOpsMockServer) writeACMEError(w http.ResponseWriter, statusCode int, errType, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(statusCode)
	errorResp := map[string]interface{}{
		"type":   errType,
		"detail": detail,
		"status": statusCode,
	}
	_ = json.NewEncoder(w).Encode(errorResp)
}

func (m *accountOpsMockServer) handleCABundle(w http.ResponseWriter, _ *http.Request) {
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

// createTestClientWithMockServer creates a client configured to use the mock server
func createTestClientWithMockServer(t *testing.T, server *accountOpsMockServer) *Client {
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

// TestUpdateAccount_Success tests successful account contact update
func TestUpdateAccount_Success(t *testing.T) {
	server := newAccountOpsMockServer(t)
	defer server.Close()

	client := createTestClientWithMockServer(t, server)
	defer func() { _ = client.Close() }()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	newContacts := []string{"updated@example.com", "backup@example.com"}
	updatedAccount, err := client.UpdateAccount(context.Background(), newContacts)

	require.NoError(t, err)
	assert.NotNil(t, updatedAccount)
	assert.Equal(t, "valid", updatedAccount.Status)
	assert.NotEmpty(t, updatedAccount.URI)
}

// TestUpdateAccount_WithMailtoPrefix tests contacts with mailto prefix
func TestUpdateAccount_WithMailtoPrefix(t *testing.T) {
	server := newAccountOpsMockServer(t)
	defer server.Close()

	client := createTestClientWithMockServer(t, server)
	defer func() { _ = client.Close() }()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	newContacts := []string{"mailto:prefixed@example.com"}
	updatedAccount, err := client.UpdateAccount(context.Background(), newContacts)

	require.NoError(t, err)
	assert.NotNil(t, updatedAccount)
}

// TestUpdateAccount_EmptyContacts tests updating with empty contacts
func TestUpdateAccount_EmptyContacts(t *testing.T) {
	server := newAccountOpsMockServer(t)
	defer server.Close()

	client := createTestClientWithMockServer(t, server)
	defer func() { _ = client.Close() }()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	updatedAccount, err := client.UpdateAccount(context.Background(), []string{})

	require.NoError(t, err)
	assert.NotNil(t, updatedAccount)
}

// TestUpdateAccount_ServerError tests handling of server errors during update
func TestUpdateAccount_ServerError(t *testing.T) {
	server := newAccountOpsMockServer(t)
	defer server.Close()

	client := createTestClientWithMockServer(t, server)
	defer func() { _ = client.Close() }()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	server.updateShouldFail = true

	_, err = client.UpdateAccount(context.Background(), []string{"fail@example.com"})

	assert.Error(t, err)
	var caErrUpdate *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErrUpdate)
	assert.Equal(t, caerrors.InternalServer, caErrUpdate.Type)
}

// TestUpdateAccount_UpdatesLocalEmail tests that local email is updated
func TestUpdateAccount_UpdatesLocalEmail(t *testing.T) {
	server := newAccountOpsMockServer(t)
	defer server.Close()

	client := createTestClientWithMockServer(t, server)
	defer func() { _ = client.Close() }()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	assert.Equal(t, "test@example.com", client.accountEmail)

	newContacts := []string{"newemail@example.com"}
	_, err = client.UpdateAccount(context.Background(), newContacts)
	require.NoError(t, err)

	assert.Equal(t, "newemail@example.com", client.accountEmail)
}

// TestUpdateAccount_ContextCancellation tests behavior with cancelled context
func TestUpdateAccount_ContextCancellation(t *testing.T) {
	server := newAccountOpsMockServer(t)
	defer server.Close()

	client := createTestClientWithMockServer(t, server)
	defer func() { _ = client.Close() }()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = client.UpdateAccount(ctx, []string{"new@example.com"})

	assert.Error(t, err)
}

// TestDeactivateAccount_Success tests successful account deactivation
func TestDeactivateAccount_Success(t *testing.T) {
	server := newAccountOpsMockServer(t)
	defer server.Close()

	client := createTestClientWithMockServer(t, server)
	defer func() { _ = client.Close() }()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	// Disable storage to avoid GetReg call in mock server
	client.storage = nil

	err = client.DeactivateAccount(context.Background())

	assert.NoError(t, err)
}

// TestDeactivateAccount_ServerError tests handling of server errors
func TestDeactivateAccount_ServerError(t *testing.T) {
	server := newAccountOpsMockServer(t)
	defer server.Close()

	client := createTestClientWithMockServer(t, server)
	defer func() { _ = client.Close() }()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	server.deactivateShouldFail = true

	err = client.DeactivateAccount(context.Background())

	assert.Error(t, err)
	var caErrDeactivate *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErrDeactivate)
	assert.Equal(t, caerrors.InternalServer, caErrDeactivate.Type)
}

// TestDeactivateAccount_ContextCancellation tests behavior with cancelled context
func TestDeactivateAccount_ContextCancellation(t *testing.T) {
	server := newAccountOpsMockServer(t)
	defer server.Close()

	client := createTestClientWithMockServer(t, server)
	defer func() { _ = client.Close() }()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = client.DeactivateAccount(ctx)

	assert.Error(t, err)
}

// TestUpdateAccount_StorageUpdate tests that storage is updated on successful update
func TestUpdateAccount_StorageUpdate(t *testing.T) {
	server := newAccountOpsMockServer(t)
	defer server.Close()

	client := createTestClientWithMockServer(t, server)
	defer func() { _ = client.Close() }()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	newContacts := []string{"storage-test@example.com"}
	_, err = client.UpdateAccount(context.Background(), newContacts)
	require.NoError(t, err)

	mockStore := client.storage.(*mockStorage)
	assert.NotEmpty(t, mockStore.accounts)
}

// TestUpdateAccount_MixedContactFormats tests mixed contact formats
func TestUpdateAccount_MixedContactFormats(t *testing.T) {
	server := newAccountOpsMockServer(t)
	defer server.Close()

	client := createTestClientWithMockServer(t, server)
	defer func() { _ = client.Close() }()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	newContacts := []string{"plain@example.com", "mailto:prefixed@example.com"}
	updatedAccount, err := client.UpdateAccount(context.Background(), newContacts)

	require.NoError(t, err)
	assert.NotNil(t, updatedAccount)
}

// TestUpdateAccount_NilStorage tests update behavior when storage is nil
func TestUpdateAccount_NilStorage(t *testing.T) {
	server := newAccountOpsMockServer(t)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := DefaultConfig()
	config.DirectoryURL = server.Server.URL + "/directory"
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
			TLSClientConfig:   testutil.TLSConfigFromServer(server.Server),
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second,
	}
	client.client.HTTPClient = client.httpClient

	_, err = client.RegisterAccount()
	require.NoError(t, err)

	client.storage = nil

	_, err = client.UpdateAccount(context.Background(), []string{"nostorage@example.com"})
	require.NoError(t, err)
}

// TestDeactivateAccount_NilStorage tests deactivation when storage is nil
func TestDeactivateAccount_NilStorage(t *testing.T) {
	server := newAccountOpsMockServer(t)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := DefaultConfig()
	config.DirectoryURL = server.Server.URL + "/directory"
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
			TLSClientConfig:   testutil.TLSConfigFromServer(server.Server),
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second,
	}
	client.client.HTTPClient = client.httpClient

	_, err = client.RegisterAccount()
	require.NoError(t, err)

	client.storage = nil

	err = client.DeactivateAccount(context.Background())
	require.NoError(t, err)
}

// TestUpdateAccount_SingleContact tests updating with a single contact
func TestUpdateAccount_SingleContact(t *testing.T) {
	server := newAccountOpsMockServer(t)
	defer server.Close()

	client := createTestClientWithMockServer(t, server)
	defer func() { _ = client.Close() }()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	newContacts := []string{"single@example.com"}
	updatedAccount, err := client.UpdateAccount(context.Background(), newContacts)

	require.NoError(t, err)
	assert.NotNil(t, updatedAccount)
}

// TestUpdateAccount_MultipleContacts tests updating with multiple contacts
func TestUpdateAccount_MultipleContacts(t *testing.T) {
	server := newAccountOpsMockServer(t)
	defer server.Close()

	client := createTestClientWithMockServer(t, server)
	defer func() { _ = client.Close() }()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	newContacts := []string{"first@example.com", "second@example.com", "third@example.com"}
	updatedAccount, err := client.UpdateAccount(context.Background(), newContacts)

	require.NoError(t, err)
	assert.NotNil(t, updatedAccount)
}

// TestDeactivateAccount_LogsWarning tests that deactivation logs a warning
func TestDeactivateAccount_LogsWarning(t *testing.T) {
	server := newAccountOpsMockServer(t)
	defer server.Close()

	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

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
	defer func() { _ = client.Close() }()

	client.httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   testutil.TLSConfigFromServer(server.Server),
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second,
	}
	client.client.HTTPClient = client.httpClient

	_, err = client.RegisterAccount()
	require.NoError(t, err)

	// Disable storage to avoid GetReg call
	client.storage = nil

	err = client.DeactivateAccount(context.Background())
	require.NoError(t, err)

	logOutput := logBuf.String()
	assert.Contains(t, logOutput, "IRREVERSIBLE")
}

// TestUpdateAccount_InvalidAccountURI tests handling of invalid account URI
func TestUpdateAccount_InvalidAccountURI(t *testing.T) {
	mux := http.NewServeMux()
	var serverURL string

	mux.HandleFunc("/directory", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")
		directory := map[string]interface{}{
			"newNonce":   serverURL + "/acme/new-nonce",
			"newAccount": serverURL + "/acme/new-account",
			"newOrder":   serverURL + "/acme/new-order",
			"revokeCert": serverURL + "/acme/revoke-cert",
			"keyChange":  serverURL + "/acme/key-change",
			"meta":       map[string]interface{}{"termsOfService": "https://example.com/terms"},
		}
		_ = json.NewEncoder(w).Encode(directory)
	})

	mux.HandleFunc("/acme/new-nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/acme/new-account", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", serverURL+"/acme/account/invalid-id")
		w.WriteHeader(http.StatusCreated)
		account := map[string]interface{}{
			"status":  "valid",
			"contact": []string{"mailto:test@example.com"},
			"orders":  serverURL + "/acme/account/invalid-id/orders",
		}
		_ = json.NewEncoder(w).Encode(account)
	})

	mux.HandleFunc("/acme/account/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", serverURL+"/acme/account/invalid-id")
		account := map[string]interface{}{
			"status":  "valid",
			"contact": []string{"mailto:test@example.com"},
		}
		_ = json.NewEncoder(w).Encode(account)
	})

	server := httptest.NewTLSServer(mux)
	serverURL = server.URL
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := DefaultConfig()
	config.DirectoryURL = serverURL + "/directory"
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
		Timeout: 10 * time.Second,
	}
	client.client.HTTPClient = client.httpClient

	_, err = client.RegisterAccount()
	require.NoError(t, err)

	_, err = client.UpdateAccount(context.Background(), []string{"new@example.com"})
	require.NoError(t, err)
}
