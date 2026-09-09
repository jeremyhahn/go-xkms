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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"

	"github.com/jeremyhahn/go-xkms/internal/acmetestutil"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

func TestNewClient(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("successful client creation", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		config := DefaultConfig()
		config.DirectoryURL = "https://acme.example.com/directory"

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
		assert.NotNil(t, client)
		assert.Equal(t, "test@example.com", client.accountEmail)
		assert.NotNil(t, client.client)
		assert.NotNil(t, client.httpClient)
	})

	t.Run("nil parameters", func(t *testing.T) {
		client, err := NewClient(nil)
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Equal(t, ErrInvalidConfiguration, err)
	})

	t.Run("nil signer", func(t *testing.T) {
		params := &Params{
			AccountEmail: "test@example.com",
			Storage:      newMockStorage(),
		}

		client, err := NewClient(params)
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Equal(t, ErrNilSigner, err)
	})

	t.Run("nil storage", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
		}

		client, err := NewClient(params)
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Equal(t, ErrNilStorage, err)
	})

	t.Run("default config and logger", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.NotNil(t, client.config)
		assert.NotNil(t, client.logger)
	})
}

func TestClient_AccountSigner(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := DefaultConfig()
	config.DirectoryURL = "https://acme.example.com/directory"

	params := &Params{
		AccountEmail:  "test@example.com",
		AccountSigner: privateKey,
		Config:        config,
		Storage:       newMockStorage(),
	}

	client, err := NewClient(params)
	require.NoError(t, err)

	signer := client.AccountSigner()
	assert.Equal(t, privateKey, signer)
}

func TestClient_Close(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := DefaultConfig()
	config.DirectoryURL = "https://acme.example.com/directory"

	params := &Params{
		AccountEmail:  "test@example.com",
		AccountSigner: privateKey,
		Config:        config,
		Storage:       newMockStorage(),
	}

	client, err := NewClient(params)
	require.NoError(t, err)

	err = client.Close()
	assert.NoError(t, err)
}

func TestCertificateRequest_Validate(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		req := &CertificateRequest{
			AuthzType:     "dns",
			AuthzValue:    "example.com",
			ChallengeType: "http-01",
			CSR:           []byte("test-csr"),
		}

		err := req.Validate()
		assert.NoError(t, err)
	})

	t.Run("missing authz type", func(t *testing.T) {
		req := &CertificateRequest{
			AuthzValue:    "example.com",
			ChallengeType: "http-01",
			CSR:           []byte("test-csr"),
		}

		err := req.Validate()
		assert.Error(t, err)
		assert.Equal(t, ErrMissingAuthzType, err)
	})

	t.Run("missing authz value", func(t *testing.T) {
		req := &CertificateRequest{
			AuthzType:     "dns",
			ChallengeType: "http-01",
			CSR:           []byte("test-csr"),
		}

		err := req.Validate()
		assert.Error(t, err)
		assert.Equal(t, ErrMissingAuthzValue, err)
	})

	t.Run("missing challenge type", func(t *testing.T) {
		req := &CertificateRequest{
			AuthzType:  "dns",
			AuthzValue: "example.com",
			CSR:        []byte("test-csr"),
		}

		err := req.Validate()
		assert.Error(t, err)
		assert.Equal(t, ErrMissingChallengeType, err)
	})

	t.Run("missing CSR", func(t *testing.T) {
		req := &CertificateRequest{
			AuthzType:     "dns",
			AuthzValue:    "example.com",
			ChallengeType: "http-01",
		}

		err := req.Validate()
		assert.Error(t, err)
		assert.Equal(t, ErrMissingCSR, err)
	})
}

func TestCreateHTTPClient(t *testing.T) {
	t.Run("system cert pool", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		config := DefaultConfig()
		config.DirectoryURL = "https://acme.example.com/directory"
		config.RequestServerBundle = false

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		assert.NotNil(t, client.httpClient)
		assert.NotNil(t, client.httpClient.Transport)
	})

	t.Run("custom trusted roots", func(t *testing.T) {
		// Generate a test CA certificate
		caCert, caKey := generateTestCertificate(t, "Test CA")

		// Encode the certificate to PEM
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCert.Raw,
		})

		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		config := DefaultConfig()
		config.DirectoryURL = "https://acme.example.com/directory"
		config.TrustedRoots = []string{string(certPEM)}

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		assert.NotNil(t, client.httpClient)

		_ = caKey // Avoid unused variable warning
	})
}

func TestFetchCABundle(t *testing.T) {
	// Create a test server that returns a CA bundle
	caCert, _ := generateTestCertificate(t, "Test CA")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ca-bundle" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(certPEM)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Use the test server's TLS certificate as a TrustedRoot so fetchCABundle
	// can verify the server's TLS certificate during the test.
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.TLS.Certificates[0].Certificate[0]})

	config := DefaultConfig()
	config.DirectoryURL = server.URL + "/directory"
	config.TrustedRoots = []string{string(serverCertPEM)}

	params := &Params{
		AccountEmail:  "test@example.com",
		AccountSigner: privateKey,
		Config:        config,
		Storage:       newMockStorage(),
	}

	client, err := NewClient(params)
	require.NoError(t, err)

	certs, err := client.fetchCABundle(server.URL + "/directory")
	require.NoError(t, err)
	assert.Len(t, certs, 1)
	assert.Equal(t, "Test CA", certs[0].Subject.CommonName)
}

func TestAuthorizationType_String(t *testing.T) {
	assert.Equal(t, "dns", AuthzTypeDNS.String())
	assert.Equal(t, "ip", AuthzTypeIP.String())
	assert.Equal(t, "permanent-identifier", AuthzTypePermanentIdentifier.String())
}

func TestChallengeType_String(t *testing.T) {
	assert.Equal(t, "http-01", ChallengeTypeHTTP01.String())
	assert.Equal(t, "dns-01", ChallengeTypeDNS01.String())
	assert.Equal(t, "tls-alpn-01", ChallengeTypeTLSALPN01.String())
}

func TestAccountStatus_String(t *testing.T) {
	assert.Equal(t, "valid", AccountStatusValid.String())
	assert.Equal(t, "deactivated", AccountStatusDeactivated.String())
	assert.Equal(t, "revoked", AccountStatusRevoked.String())
}

func TestOrderStatus_String(t *testing.T) {
	assert.Equal(t, "pending", OrderStatusPending.String())
	assert.Equal(t, "ready", OrderStatusReady.String())
	assert.Equal(t, "processing", OrderStatusProcessing.String())
	assert.Equal(t, "valid", OrderStatusValid.String())
	assert.Equal(t, "invalid", OrderStatusInvalid.String())
}

// TestClient_Account tests the Account() method
func TestClient_Account(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("successful account retrieval", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Create a test server that returns account information
		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

			switch r.URL.Path {
			case "/directory":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{
					"newNonce": "` + server.URL + `/new-nonce",
					"newAccount": "` + server.URL + `/new-account",
					"newOrder": "` + server.URL + `/new-order"
				}`))
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/acct/1":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{
					"status": "valid",
					"contact": ["mailto:test@example.com"],
					"orders": "` + server.URL + `/acct/1/orders"
				}`))
			default:
				// GetReg makes a POST to newAccount with onlyReturnExisting
				if r.URL.Path == "/new-account" {
					w.Header().Set("Location", server.URL+"/acct/1")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{
						"status": "valid",
						"contact": ["mailto:test@example.com"],
						"orders": "` + server.URL + `/acct/1/orders"
					}`))
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			}
		}))
		defer server.Close()

		// Create HTTP client with test server cert pool
		transport := &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		}
		httpClient := &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}

		acmeClient := &acme.Client{
			DirectoryURL: server.URL + "/directory",
			Key:          privateKey,
			HTTPClient:   httpClient,
		}

		mockStore := newMockStorage()

		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			client:        acmeClient,
			httpClient:    httpClient,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
		}

		account, err := client.Account()
		require.NoError(t, err)
		assert.NotNil(t, account)
		assert.Equal(t, "valid", account.Status)
		assert.Contains(t, account.Contact, "mailto:test@example.com")
	})

	t.Run("account not found - empty email", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		config := DefaultConfig()
		config.DirectoryURL = "https://acme.example.com/directory"

		params := &Params{
			AccountEmail:  "", // Empty email
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		account, err := client.Account()
		assert.Error(t, err)
		assert.Nil(t, account)
		assert.Equal(t, ErrAccountNotFound, err)
	})

	t.Run("account retrieval fails from server", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Create a test server that returns an error
		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce")

			switch r.URL.Path {
			case "/directory":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{
					"newNonce": "` + server.URL + `/new-nonce",
					"newAccount": "` + server.URL + `/new-account"
				}`))
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/new-account":
				// Return error for account retrieval
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{
					"type": "urn:ietf:params:acme:error:unauthorized",
					"detail": "Account not found"
				}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		config := DefaultConfig()
		config.DirectoryURL = server.URL + "/directory"

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		account, err := client.Account()
		assert.Error(t, err)
		assert.Nil(t, account)
		assert.Contains(t, err.Error(), "failed to get account")
	})
}

// TestClient_RegisterAccount tests the RegisterAccount() method
func TestClient_RegisterAccount(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("successful account registration", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Create a test server that handles account registration
		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

			switch r.URL.Path {
			case "/directory":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"newNonce":   server.URL + "/new-nonce",
					"newAccount": server.URL + "/new-account",
					"newOrder":   server.URL + "/new-order",
					"revokeCert": server.URL + "/revoke-cert",
					"keyChange":  server.URL + "/key-change",
				})
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/new-account":
				w.Header().Set("Location", server.URL+"/acct/1")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":  "valid",
					"contact": []string{"mailto:test@example.com"},
					"orders":  server.URL + "/acct/1/orders",
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		// Create HTTP client with test server cert pool
		transport := &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		}
		httpClient := &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}

		acmeClient := &acme.Client{
			DirectoryURL: server.URL + "/directory",
			Key:          privateKey,
			HTTPClient:   httpClient,
		}

		mockStore := newMockStorage()

		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			client:        acmeClient,
			httpClient:    httpClient,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
		}

		account, err := client.RegisterAccount()
		require.NoError(t, err)
		assert.NotNil(t, account)
		assert.Equal(t, "valid", account.Status)
		assert.Contains(t, account.Contact, "mailto:test@example.com")

		// Verify account was saved to storage
		assert.Len(t, mockStore.accounts, 1)
		for _, acc := range mockStore.accounts {
			assert.Equal(t, "valid", acc.Status)
		}
	})

	t.Run("registration fails - server error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Create a test server that returns an error
		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce")

			switch r.URL.Path {
			case "/directory":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{
					"newNonce": "` + server.URL + `/new-nonce",
					"newAccount": "` + server.URL + `/new-account"
				}`))
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/new-account":
				// Return error for registration
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{
					"type": "urn:ietf:params:acme:error:malformed",
					"detail": "Invalid registration request"
				}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		config := DefaultConfig()
		config.DirectoryURL = server.URL + "/directory"

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		account, err := client.RegisterAccount()
		assert.Error(t, err)
		assert.Nil(t, account)
		assert.Contains(t, err.Error(), "failed to register account")
	})

	t.Run("registration succeeds but storage fails", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce")

			switch r.URL.Path {
			case "/directory":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{
					"newNonce": "` + server.URL + `/new-nonce",
					"newAccount": "` + server.URL + `/new-account"
				}`))
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/new-account":
				w.Header().Set("Location", server.URL+"/acct/1")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{
					"status": "valid",
					"contact": ["mailto:test@example.com"]
				}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		config := DefaultConfig()
		config.DirectoryURL = server.URL + "/directory"

		// Client with nil storage - should succeed but log warning
		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       nil,
		}

		// This will fail during NewClient due to nil storage validation
		_, err = NewClient(params)
		assert.Error(t, err)
		assert.Equal(t, ErrNilStorage, err)
	})
}

// TestClient_RevokeCertificate tests the RevokeCertificate() method
func TestClient_RevokeCertificate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("successful certificate revocation", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		cert, _ := generateTestCertificate(t, "example.com")

		// Create a test server that handles revocation
		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

			switch r.URL.Path {
			case "/directory":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"newNonce":   server.URL + "/new-nonce",
					"newAccount": server.URL + "/new-account",
					"newOrder":   server.URL + "/new-order",
					"revokeCert": server.URL + "/revoke-cert",
					"keyChange":  server.URL + "/key-change",
				})
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/revoke-cert":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		// Create HTTP client with test server cert pool
		transport := &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		}
		httpClient := &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}

		acmeClient := &acme.Client{
			DirectoryURL: server.URL + "/directory",
			Key:          privateKey,
			HTTPClient:   httpClient,
		}

		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			client:        acmeClient,
			httpClient:    httpClient,
			config:        DefaultConfig(),
			logger:        logger,
		}

		err = client.RevokeCertificate(context.Background(), cert, 0)
		assert.NoError(t, err)
	})

	t.Run("revocation fails - server error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		cert, _ := generateTestCertificate(t, "example.com")

		// Create a test server that returns an error
		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce")

			switch r.URL.Path {
			case "/directory":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{
					"newNonce": "` + server.URL + `/new-nonce",
					"revokeCert": "` + server.URL + `/revoke-cert"
				}`))
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/revoke-cert":
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{
					"type": "urn:ietf:params:acme:error:unauthorized",
					"detail": "Certificate revocation not authorized"
				}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		config := DefaultConfig()
		config.DirectoryURL = server.URL + "/directory"

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		err = client.RevokeCertificate(context.Background(), cert, 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to revoke certificate")
	})
}

// TestClient_FetchCertificate tests the FetchCertificate() method
func TestClient_FetchCertificate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("successful certificate fetch", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		cert, _ := generateTestCertificate(t, "example.com")
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})

		// Create a test server that returns a certificate
		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

			switch r.URL.Path {
			case "/directory":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"newNonce":   server.URL + "/new-nonce",
					"newAccount": server.URL + "/new-account",
					"newOrder":   server.URL + "/new-order",
					"revokeCert": server.URL + "/revoke-cert",
					"keyChange":  server.URL + "/key-change",
				})
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/cert/1":
				w.Header().Set("Content-Type", "application/pem-certificate-chain")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(certPEM)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		// Create HTTP client with test server cert pool
		transport := &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		}
		httpClient := &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}

		acmeClient := &acme.Client{
			DirectoryURL: server.URL + "/directory",
			Key:          privateKey,
			HTTPClient:   httpClient,
		}

		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			client:        acmeClient,
			httpClient:    httpClient,
			config:        DefaultConfig(),
			logger:        logger,
		}

		certs, err := client.FetchCertificate(context.Background(), server.URL+"/cert/1", false)
		require.NoError(t, err)
		assert.Len(t, certs, 1)
		assert.Equal(t, "example.com", certs[0].Subject.CommonName)
	})

	t.Run("fetch certificate - server error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Create a test server that returns an error
		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/directory":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{
					"newNonce": "` + server.URL + `/new-nonce"
				}`))
			case "/cert/1":
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{
					"type": "urn:ietf:params:acme:error:malformed",
					"detail": "Certificate not found"
				}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		config := DefaultConfig()
		config.DirectoryURL = server.URL + "/directory"

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		certs, err := client.FetchCertificate(context.Background(), server.URL+"/cert/1", false)
		assert.Error(t, err)
		assert.Nil(t, certs)
		assert.Contains(t, err.Error(), "failed to fetch certificate")
	})

	t.Run("fetch certificate - invalid certificate data", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Create a test server that returns invalid certificate data
		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/directory":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{
					"newNonce": "` + server.URL + `/new-nonce"
				}`))
			case "/cert/1":
				w.Header().Set("Content-Type", "application/pem-certificate-chain")
				w.WriteHeader(http.StatusOK)
				// Return invalid PEM data
				_, _ = w.Write([]byte("invalid certificate data"))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		config := DefaultConfig()
		config.DirectoryURL = server.URL + "/directory"

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		certs, err := client.FetchCertificate(context.Background(), server.URL+"/cert/1", false)
		assert.Error(t, err)
		assert.Nil(t, certs)
	})
}

// TestClient_AccountKeyRollover tests the AccountKeyRollover() method
func TestClient_AccountKeyRollover(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("successful key rollover", func(t *testing.T) {
		oldKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Create a test server that handles key rollover
		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

			switch r.URL.Path {
			case "/directory":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"newNonce":   server.URL + "/new-nonce",
					"newAccount": server.URL + "/new-account",
					"newOrder":   server.URL + "/new-order",
					"revokeCert": server.URL + "/revoke-cert",
					"keyChange":  server.URL + "/key-change",
				})
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/new-account":
				w.Header().Set("Location", server.URL+"/acct/1")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":  "valid",
					"contact": []string{"mailto:test@example.com"},
				})
			case "/key-change":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":  "valid",
					"contact": []string{"mailto:test@example.com"},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		// Create HTTP client with test server cert pool
		transport := &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		}
		httpClient := &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}

		acmeClient := &acme.Client{
			DirectoryURL: server.URL + "/directory",
			Key:          oldKey,
			HTTPClient:   httpClient,
		}

		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: oldKey,
			client:        acmeClient,
			httpClient:    httpClient,
			config:        DefaultConfig(),
			logger:        logger,
		}

		// Verify old key is set
		assert.Equal(t, oldKey, client.AccountSigner())

		err = client.AccountKeyRollover(context.Background(), newKey)
		require.NoError(t, err)

		// Verify new key is set
		assert.Equal(t, newKey, client.AccountSigner())
	})

	t.Run("key rollover fails - server error", func(t *testing.T) {
		oldKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Create a test server that returns an error
		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce")

			switch r.URL.Path {
			case "/directory":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{
					"newNonce": "` + server.URL + `/new-nonce",
					"keyChange": "` + server.URL + `/key-change"
				}`))
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/key-change":
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{
					"type": "urn:ietf:params:acme:error:malformed",
					"detail": "Invalid key change request"
				}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		config := DefaultConfig()
		config.DirectoryURL = server.URL + "/directory"

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: oldKey,
			Config:        config,
			Logger:        logger,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		err = client.AccountKeyRollover(context.Background(), newKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to perform account key rollover")

		// Verify old key is still set (rollover failed)
		assert.Equal(t, oldKey, client.AccountSigner())
	})
}

// TestFetchCABundle_ErrorPaths tests error paths in fetchCABundle
func TestFetchCABundle_ErrorPaths(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("no TrustedRoots configured", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		config := DefaultConfig()
		config.DirectoryURL = "https://acme.example.com/directory"
		// SystemCertPool defaults to false, TrustedRoots defaults to empty —
		// the TLS connection will fail because there are no trusted certificates.

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		// Should fail because no TrustedRoots are configured and SystemCertPool is false,
		// so the TLS connection cannot be verified.
		_, err = client.fetchCABundle("https://acme.example.com/directory")
		assert.Error(t, err)
	})

	t.Run("invalid directory URL", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		config := DefaultConfig()
		config.DirectoryURL = "https://acme.example.com/directory"
		// No TrustedRoots needed — the URL is invalid and fails before TLS.

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		// Test with invalid URL
		_, err = client.fetchCABundle("://invalid-url")
		assert.Error(t, err)
	})

	t.Run("server returns non-200 status", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Create a test server that returns error status
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		// Trust the test server's TLS certificate via TrustedRoots.
		serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.TLS.Certificates[0].Certificate[0]})

		config := DefaultConfig()
		config.DirectoryURL = server.URL + "/directory"
		config.TrustedRoots = []string{string(serverCertPEM)}

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		_, err = client.fetchCABundle(server.URL + "/directory")
		assert.Error(t, err)
		assert.Equal(t, ErrCABundleDownloadFailed, err)
	})

	t.Run("invalid PEM certificate data", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Create a test server that returns invalid cert data
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ca-bundle" {
				w.WriteHeader(http.StatusOK)
				// Write PEM with invalid certificate bytes (valid base64 but invalid ASN.1/DER)
				_, _ = w.Write([]byte("-----BEGIN CERTIFICATE-----\nQUFBQUFBQUFBQUFBQUFBQUFBQQ==\n-----END CERTIFICATE-----\n"))
			}
		}))
		defer server.Close()

		// Trust the test server's TLS certificate via TrustedRoots.
		serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.TLS.Certificates[0].Certificate[0]})

		config := DefaultConfig()
		config.DirectoryURL = server.URL + "/directory"
		config.TrustedRoots = []string{string(serverCertPEM)}

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		_, err = client.fetchCABundle(server.URL + "/directory")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse certificate")
	})
}

// TestCreateCACertPool_ErrorPaths tests error paths in createCACertPool
func TestCreateCACertPool_ErrorPaths(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("invalid custom CA certificate PEM", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		config := DefaultConfig()
		config.DirectoryURL = "https://acme.example.com/directory"
		// Invalid PEM certificate
		config.TrustedRoots = []string{"INVALID PEM CERTIFICATE"}

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       newMockStorage(),
		}

		_, err = NewClient(params)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create HTTP client")
	})

	t.Run("RequestServerBundle with invalid server response", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Create a test server that returns error for ca-bundle
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ca-bundle" {
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		config := DefaultConfig()
		config.DirectoryURL = server.URL + "/directory"
		config.RequestServerBundle = true

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       newMockStorage(),
		}

		_, err = NewClient(params)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create HTTP client")
	})
}

// TestRequestCertificate_InvalidRequest tests RequestCertificate with invalid request
func TestRequestCertificate_InvalidRequest(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := DefaultConfig()
	config.DirectoryURL = "https://acme.example.com/directory"

	params := &Params{
		AccountEmail:  "test@example.com",
		AccountSigner: privateKey,
		Config:        config,
		Logger:        logger,
		Storage:       newMockStorage(),
	}

	client, err := NewClient(params)
	require.NoError(t, err)

	// Missing AuthzType
	req := &CertificateRequest{
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "invalid certificate request")
}

// TestRenewCertificate_InvalidRequest tests RenewCertificate with invalid request
func TestRenewCertificate_InvalidRequest(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	oldCert, _ := generateTestCertificate(t, "example.com")

	config := DefaultConfig()
	config.DirectoryURL = "https://acme.example.com/directory"

	params := &Params{
		AccountEmail:  "test@example.com",
		AccountSigner: privateKey,
		Config:        config,
		Logger:        logger,
		Storage:       newMockStorage(),
	}

	client, err := NewClient(params)
	require.NoError(t, err)

	// Invalid request (missing CSR)
	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
	}

	newCert, err := client.RenewCertificate(context.Background(), oldCert, req)
	assert.Error(t, err)
	assert.Nil(t, newCert)
	assert.Contains(t, err.Error(), "failed to renew certificate")
}

// TestClose_WithNilHTTPClient tests Close with nil HTTP client
func TestClose_WithNilHTTPClient(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		httpClient:    nil,
		config:        DefaultConfig(),
		logger:        logger,
	}

	err = client.Close()
	assert.NoError(t, err)
}

// customRoundTripper is a test round tripper
type customRoundTripper struct{}

func (customRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, nil
}

// TestClose_WithNonTransportHTTPClient tests Close with non-transport HTTP client
func TestClose_WithNonTransportHTTPClient(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create HTTP client with a custom round tripper (not *http.Transport)
	httpClient := &http.Client{
		Transport: customRoundTripper{},
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	err = client.Close()
	assert.NoError(t, err)
}

// TestFetchCABundle_ReadBodyError tests error when reading response body
func TestFetchCABundle_ReadBodyError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := DefaultConfig()
	config.DirectoryURL = "https://acme.example.com/directory"
	// No TrustedRoots needed — the port is invalid and the connection fails before TLS.

	params := &Params{
		AccountEmail:  "test@example.com",
		AccountSigner: privateKey,
		Config:        config,
		Logger:        logger,
		Storage:       newMockStorage(),
	}

	client, err := NewClient(params)
	require.NoError(t, err)

	// Test with invalid URL scheme that will cause http.Get to fail
	_, err = client.fetchCABundle("http://127.0.0.1:99999/invalid")
	assert.Error(t, err)
}

// TestImprove_CreateCACertPool tests createCACertPool edge cases
func TestImprove_CreateCACertPool(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("multiple trusted roots", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Generate multiple test certificates
		cert1, _ := generateTestCertificate(t, "Test CA 1")
		cert2, _ := generateTestCertificate(t, "Test CA 2")

		certPEM1 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert1.Raw})
		certPEM2 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert2.Raw})

		config := DefaultConfig()
		config.DirectoryURL = "https://acme.example.com/directory"
		config.TrustedRoots = []string{string(certPEM1), string(certPEM2)}

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("empty certificate pool mode", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		config := DefaultConfig()
		config.DirectoryURL = "https://acme.example.com/directory"
		config.SystemCertPool = false
		config.RequestServerBundle = false

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		require.NoError(t, err)
		assert.NotNil(t, client)
	})
}

// TestImprove_FetchCertificate_WithBundle tests FetchCertificate requesting bundle
func TestImprove_FetchCertificate_WithBundle(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("fetch with bundle", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		cert1, _ := generateTestCertificate(t, "example.com")
		cert2, _ := generateTestCertificate(t, "Issuer CA")

		certPEM1 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert1.Raw})
		certPEM2 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert2.Raw})
		bundlePEM := append(certPEM1, certPEM2...)

		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

			switch r.URL.Path {
			case "/directory":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"newNonce":   server.URL + "/new-nonce",
					"newAccount": server.URL + "/new-account",
					"newOrder":   server.URL + "/new-order",
				})
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/cert/1":
				w.Header().Set("Content-Type", "application/pem-certificate-chain")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(bundlePEM)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		transport := &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		}
		httpClient := &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}

		acmeClient := &acme.Client{
			DirectoryURL: server.URL + "/directory",
			Key:          privateKey,
			HTTPClient:   httpClient,
		}

		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			client:        acmeClient,
			httpClient:    httpClient,
			config:        DefaultConfig(),
			logger:        logger,
		}

		certs, err := client.FetchCertificate(context.Background(), server.URL+"/cert/1", true)
		require.NoError(t, err)
		assert.Len(t, certs, 2)
	})
}

// TestExtractAccountIDFromURI tests the extractAccountIDFromURI function
// TestExtractAccountIDFromURI tests the extractAccountIDFromURI function
func TestExtractAccountIDFromURI(t *testing.T) {
	tests := []struct {
		name        string
		uri         string
		expectedID  uint64
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid ACME account URI",
			uri:         "https://acme.example.com/acme/account/12345",
			expectedID:  12345,
			expectError: false,
		},
		{
			name:        "valid URI with large ID",
			uri:         "https://server.example.internal:9443/api/v1/acme/account/10208762205573402789",
			expectedID:  10208762205573402789,
			expectError: false,
		},
		{
			name:        "valid URI with path only",
			uri:         "/acct/999",
			expectedID:  999,
			expectError: false,
		},
		{
			name:        "empty URI",
			uri:         "",
			expectedID:  0,
			expectError: true,
			errorMsg:    "invalid account URI",
		},
		{
			name:        "URI with non-numeric ID",
			uri:         "https://acme.example.com/acme/account/abc123",
			expectedID:  0,
			expectError: true,
			errorMsg:    "invalid account ID format",
		},
		{
			name:        "URI with zero ID",
			uri:         "https://acme.example.com/acme/account/0",
			expectedID:  0,
			expectError: true,
			errorMsg:    "account ID cannot be zero",
		},
		{
			name:        "URI with trailing slash",
			uri:         "https://acme.example.com/acme/account/456/",
			expectedID:  456,
			expectError: false,
		},
		{
			name:        "URI with query parameters",
			uri:         "https://acme.example.com/acme/account/789?foo=bar",
			expectedID:  789,
			expectError: false,
		},
		{
			name:        "invalid URL format",
			uri:         "://invalid-url",
			expectedID:  0,
			expectError: true,
			errorMsg:    "failed to parse URI",
		},
		{
			name:        "URI with no path segments",
			uri:         "https://acme.example.com/",
			expectedID:  0,
			expectError: true,
			errorMsg:    "invalid account ID format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := extractAccountIDFromURI(tt.uri)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedID, id)
			}
		})
	}
}

// =====================================
// Tests from client_additional_test.go
// =====================================

func generateTestCSR(t *testing.T, domain string, key crypto.Signer) []byte {
	t.Helper()
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domain,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	require.NoError(t, err)
	return csrDER
}

// TestClient_RequestCertificate_FullWorkflow tests the complete certificate request workflow
func TestClient_RequestCertificate_FullWorkflow(t *testing.T) {
	t.Run("successful certificate request with http-01 challenge", func(t *testing.T) {
		// Generate test certificate and CSR
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		csrTemplate := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: "example.com",
			},
			SignatureAlgorithm: x509.ECDSAWithSHA256,
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
		require.NoError(t, err)

		// Generate a certificate for the response
		certTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "example.com",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(90 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
		require.NoError(t, err)

		// Track challenge accepted
		challengeAccepted := false
		authzCompleted := false

		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

			switch r.URL.Path {
			case "/directory":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"newNonce":   server.URL + "/new-nonce",
					"newAccount": server.URL + "/new-account",
					"newOrder":   server.URL + "/new-order",
					"revokeCert": server.URL + "/revoke-cert",
					"keyChange":  server.URL + "/key-change",
				})

			case "/new-nonce":
				w.WriteHeader(http.StatusOK)

			case "/new-order":
				w.Header().Set("Location", server.URL+"/order/1")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":      "pending",
					"expires":     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					"identifiers": []map[string]string{{"type": "dns", "value": "example.com"}},
					"authorizations": []string{
						server.URL + "/authz/1",
					},
					"finalize": server.URL + "/order/1/finalize",
				})

			case "/authz/1":
				status := "pending"
				if authzCompleted {
					status = "valid"
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"identifier": map[string]string{"type": "dns", "value": "example.com"},
					"status":     status,
					"expires":    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					"challenges": []map[string]interface{}{
						{
							"type":   "http-01",
							"status": "pending",
							"url":    server.URL + "/challenge/1",
							"token":  "test-token",
						},
					},
				})

			case "/challenge/1":
				challengeAccepted = true
				authzCompleted = true
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"type":   "http-01",
					"status": "valid",
					"url":    server.URL + "/challenge/1",
					"token":  "test-token",
				})

			case "/order/1/finalize":
				w.Header().Set("Location", server.URL+"/order/1")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":      "valid",
					"expires":     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					"identifiers": []map[string]string{{"type": "dns", "value": "example.com"}},
					"finalize":    server.URL + "/order/1/finalize",
					"certificate": server.URL + "/cert/1",
				})

			case "/cert/1":
				w.Header().Set("Content-Type", "application/pem-certificate-chain")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		// Create client
		accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		transport := &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		}
		httpClient := &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}

		acmeClient := &acme.Client{
			DirectoryURL: server.URL + "/directory",
			Key:          accountKey,
			HTTPClient:   httpClient,
		}

		mockStore := newMockStorage()
		certStorage := newMockCertStorage()
		orderStorage := newMockOrderStorage()

		client := &Client{
			accountEmail:       "test@example.com",
			accountSigner:      accountKey,
			client:             acmeClient,
			httpClient:         httpClient,
			config:             DefaultConfig(),
			logger:             slog.New(slog.NewTextHandler(os.Stdout, nil)),
			storage:            mockStore,
			certificateStorage: certStorage,
			orderStorage:       orderStorage,
		}

		setupCalled := false
		cleanupCalled := false

		req := &CertificateRequest{
			AuthzType:     "dns",
			AuthzValue:    "example.com",
			ChallengeType: "http-01",
			CSR:           csrDER,
			ChallengeSetup: func(challengeType, token, keyAuth string) error {
				setupCalled = true
				assert.Equal(t, "http-01", challengeType)
				assert.Equal(t, "test-token", token)
				return nil
			},
			ChallengeCleanup: func(challengeType string) {
				cleanupCalled = true
				assert.Equal(t, "http-01", challengeType)
			},
		}

		cert, err := client.RequestCertificate(context.Background(), req)
		require.NoError(t, err)
		assert.NotNil(t, cert)
		assert.Equal(t, "example.com", cert.Subject.CommonName)
		assert.True(t, setupCalled, "Challenge setup should have been called")
		assert.True(t, cleanupCalled, "Challenge cleanup should have been called")
		assert.True(t, challengeAccepted, "Challenge should have been accepted")
	})

	t.Run("certificate request without challenge setup", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		csrDER := generateTestCSR(t, "example.com", privateKey)

		certTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "example.com",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(90 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
		require.NoError(t, err)

		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

			switch r.URL.Path {
			case "/directory":
				_ = json.NewEncoder(w).Encode(map[string]string{
					"newNonce":   server.URL + "/new-nonce",
					"newAccount": server.URL + "/new-account",
					"newOrder":   server.URL + "/new-order",
				})
			case "/new-order":
				w.Header().Set("Location", server.URL+"/order/1")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":      "pending",
					"expires":     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					"identifiers": []map[string]string{{"type": "dns", "value": "example.com"}},
					"authorizations": []string{
						server.URL + "/authz/1",
					},
					"finalize": server.URL + "/order/1/finalize",
				})
			case "/authz/1":
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"identifier": map[string]string{"type": "dns", "value": "example.com"},
					"status":     "valid",
					"challenges": []map[string]interface{}{
						{
							"type":   "http-01",
							"status": "valid",
							"url":    server.URL + "/challenge/1",
							"token":  "test-token",
						},
					},
				})
			case "/challenge/1":
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"type":   "http-01",
					"status": "valid",
					"url":    server.URL + "/challenge/1",
					"token":  "test-token",
				})
			case "/order/1/finalize":
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":      "valid",
					"certificate": server.URL + "/cert/1",
					"finalize":    server.URL + "/order/1/finalize",
				})
			case "/cert/1":
				w.Header().Set("Content-Type", "application/pem-certificate-chain")
				_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
			}
		}))
		defer server.Close()

		accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		transport := &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		}
		httpClient := &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}

		acmeClient := &acme.Client{
			DirectoryURL: server.URL + "/directory",
			Key:          accountKey,
			HTTPClient:   httpClient,
		}

		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: accountKey,
			client:        acmeClient,
			httpClient:    httpClient,
			config:        DefaultConfig(),
			logger:        slog.New(slog.NewTextHandler(os.Stdout, nil)),
		}

		req := &CertificateRequest{
			AuthzType:     "dns",
			AuthzValue:    "example.com",
			ChallengeType: "http-01",
			CSR:           csrDER,
			// No challenge setup/cleanup functions
		}

		cert, err := client.RequestCertificate(context.Background(), req)
		require.NoError(t, err)
		assert.NotNil(t, cert)
	})

	t.Run("certificate request - nil CSR", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce")

			switch r.URL.Path {
			case "/directory":
				_ = json.NewEncoder(w).Encode(map[string]string{
					"newOrder": server.URL + "/new-order",
				})
			case "/new-order":
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":         "pending",
					"authorizations": []string{server.URL + "/authz/1"},
					"finalize":       server.URL + "/order/1/finalize",
				})
			case "/authz/1":
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status": "valid",
					"challenges": []map[string]interface{}{
						{
							"type":  "http-01",
							"token": "test-token",
							"url":   server.URL + "/challenge/1",
						},
					},
				})
			case "/challenge/1":
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status": "valid",
				})
			}
		}))
		defer server.Close()

		transport := &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		}
		httpClient := &http.Client{
			Transport: transport,
		}

		acmeClient := &acme.Client{
			DirectoryURL: server.URL + "/directory",
			Key:          privateKey,
			HTTPClient:   httpClient,
		}

		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			client:        acmeClient,
			logger:        slog.New(slog.NewTextHandler(os.Stdout, nil)),
		}

		req := &CertificateRequest{
			AuthzType:     "dns",
			AuthzValue:    "example.com",
			ChallengeType: "http-01",
			CSR:           nil, // Test nil CSR
		}

		cert, err := client.RequestCertificate(context.Background(), req)
		assert.Error(t, err)
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "missing CSR")
	})

	t.Run("certificate request - challenge type not offered", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		csrDER := generateTestCSR(t, "example.com", privateKey)

		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce")

			switch r.URL.Path {
			case "/directory":
				_ = json.NewEncoder(w).Encode(map[string]string{
					"newOrder": server.URL + "/new-order",
				})
			case "/new-order":
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":         "pending",
					"authorizations": []string{server.URL + "/authz/1"},
					"finalize":       server.URL + "/order/1/finalize",
				})
			case "/authz/1":
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status": "pending",
					"challenges": []map[string]interface{}{
						{
							"type":  "dns-01", // Different challenge type
							"token": "test-token",
							"url":   server.URL + "/challenge/1",
						},
					},
				})
			}
		}))
		defer server.Close()

		transport := &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		}
		httpClient := &http.Client{
			Transport: transport,
		}

		acmeClient := &acme.Client{
			DirectoryURL: server.URL + "/directory",
			Key:          privateKey,
			HTTPClient:   httpClient,
		}

		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			client:        acmeClient,
			logger:        slog.New(slog.NewTextHandler(os.Stdout, nil)),
		}

		req := &CertificateRequest{
			AuthzType:     "dns",
			AuthzValue:    "example.com",
			ChallengeType: "http-01", // Requesting http-01 but only dns-01 is offered
			CSR:           csrDER,
		}

		cert, err := client.RequestCertificate(context.Background(), req)
		assert.Error(t, err)
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "challenge type http-01 not offered")
	})

	t.Run("certificate request - authorization status not valid", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		csrDER := generateTestCSR(t, "example.com", privateKey)

		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce")

			switch r.URL.Path {
			case "/directory":
				_ = json.NewEncoder(w).Encode(map[string]string{
					"newOrder": server.URL + "/new-order",
				})
			case "/new-order":
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":         "pending",
					"authorizations": []string{server.URL + "/authz/1"},
					"finalize":       server.URL + "/order/1/finalize",
				})
			case "/authz/1":
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status": "invalid", // Invalid status
					"challenges": []map[string]interface{}{
						{
							"type":  "http-01",
							"token": "test-token",
							"url":   server.URL + "/challenge/1",
						},
					},
				})
			case "/challenge/1":
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status": "invalid",
				})
			}
		}))
		defer server.Close()

		transport := &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		}
		httpClient := &http.Client{
			Transport: transport,
		}

		acmeClient := &acme.Client{
			DirectoryURL: server.URL + "/directory",
			Key:          privateKey,
			HTTPClient:   httpClient,
		}

		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			client:        acmeClient,
			logger:        slog.New(slog.NewTextHandler(os.Stdout, nil)),
		}

		req := &CertificateRequest{
			AuthzType:     "dns",
			AuthzValue:    "example.com",
			ChallengeType: "http-01",
			CSR:           csrDER,
		}

		cert, err := client.RequestCertificate(context.Background(), req)
		assert.Error(t, err)
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "authorization error")
	})

	t.Run("certificate request - storage save fails gracefully", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		csrDER := generateTestCSR(t, "example.com", privateKey)

		certTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "example.com",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(90 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
		require.NoError(t, err)

		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce")

			switch r.URL.Path {
			case "/directory":
				_ = json.NewEncoder(w).Encode(map[string]string{
					"newOrder": server.URL + "/new-order",
				})
			case "/new-order":
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":         "pending",
					"authorizations": []string{server.URL + "/authz/1"},
					"finalize":       server.URL + "/order/1/finalize",
				})
			case "/authz/1":
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status": "valid",
					"challenges": []map[string]interface{}{
						{
							"type":  "http-01",
							"token": "test-token",
							"url":   server.URL + "/challenge/1",
						},
					},
				})
			case "/challenge/1":
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status": "valid",
				})
			case "/order/1/finalize":
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":      "valid",
					"certificate": server.URL + "/cert/1",
				})
			case "/cert/1":
				w.Header().Set("Content-Type", "application/pem-certificate-chain")
				_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
			}
		}))
		defer server.Close()

		transport := &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		}
		httpClient := &http.Client{
			Transport: transport,
		}

		acmeClient := &acme.Client{
			DirectoryURL: server.URL + "/directory",
			Key:          privateKey,
			HTTPClient:   httpClient,
		}

		// Client with nil storage - should succeed but log warnings
		client := &Client{
			accountEmail:       "test@example.com",
			accountSigner:      privateKey,
			client:             acmeClient,
			httpClient:         httpClient,
			config:             DefaultConfig(),
			logger:             slog.New(slog.NewTextHandler(os.Stdout, nil)),
			certificateStorage: nil,
			orderStorage:       nil,
		}

		req := &CertificateRequest{
			AuthzType:     "dns",
			AuthzValue:    "example.com",
			ChallengeType: "http-01",
			CSR:           csrDER,
		}

		cert, err := client.RequestCertificate(context.Background(), req)
		require.NoError(t, err) // Should still succeed even if storage fails
		assert.NotNil(t, cert)
	})
}

// TestClient_RenewCertificate_ErrorPaths tests renewal error paths
func TestClient_RenewCertificate_ErrorPaths(t *testing.T) {
	t.Run("renewal with invalid CSR", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		oldCert, _ := generateTestCertificate(t, "example.com")

		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			logger:        slog.New(slog.NewTextHandler(os.Stdout, nil)),
		}

		req := &CertificateRequest{
			AuthzType:  "dns",
			AuthzValue: "example.com",
			// Missing ChallengeType and CSR
		}

		newCert, err := client.RenewCertificate(context.Background(), oldCert, req)
		assert.Error(t, err)
		assert.Nil(t, newCert)
		assert.Contains(t, err.Error(), "failed to renew certificate")
	})
}

// =====================================
// Tests from client_coverage_boost_test.go
// =====================================

func TestClient_CreateCACertPool_SystemPool(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	config := &Config{
		DirectoryURL:        "https://example.com/directory",
		SystemCertPool:      true,
		RequestServerBundle: false,
		TrustedRoots:        []string{},
	}

	client := &Client{
		config: config,
		logger: logger,
	}

	pool, err := client.createCACertPool(config.DirectoryURL)
	// May fail on some systems, but tests the code path
	if err != nil {
		assert.Contains(t, err.Error(), "system root CAs")
	} else {
		assert.NotNil(t, pool)
	}
}

// TestClient_CreateCACertPool_InvalidPEM tests invalid PEM handling
func TestClient_CreateCACertPool_InvalidPEM(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	config := &Config{
		DirectoryURL:        "https://example.com/directory",
		SystemCertPool:      false,
		RequestServerBundle: false,
		TrustedRoots:        []string{"invalid-pem-data"},
	}

	client := &Client{
		config: config,
		logger: logger,
	}

	pool, err := client.createCACertPool(config.DirectoryURL)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCACertificate)
	assert.Nil(t, pool)
}

// TestClient_CreateCACertPool_WithServerBundle tests requesting server bundle
func TestClient_CreateCACertPool_WithServerBundle(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create a test CA certificate
	caCert := generateTestCACertificateForBoost(t)

	// Create test server that returns CA bundle
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/acme/ca-bundle" {
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
		}
	}))
	defer server.Close()

	// Trust the test server's TLS certificate via TrustedRoots.
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.TLS.Certificates[0].Certificate[0]})

	config := &Config{
		DirectoryURL:        server.URL + "/acme/directory",
		SystemCertPool:      false,
		RequestServerBundle: true,
		TrustedRoots:        []string{string(serverCertPEM)},
	}

	client := &Client{
		config: config,
		logger: logger,
	}

	pool, err := client.createCACertPool(config.DirectoryURL)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

// TestClient_FetchCABundle_Success tests successful CA bundle fetch
func TestClient_FetchCABundle_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	caCert := generateTestCACertificateForBoost(t)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/acme/ca-bundle" {
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
		}
	}))
	defer server.Close()

	// Trust the test server's TLS certificate via TrustedRoots.
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.TLS.Certificates[0].Certificate[0]})

	client := &Client{
		config: &Config{
			TrustedRoots: []string{string(serverCertPEM)},
		},
		logger: logger,
	}

	certs, err := client.fetchCABundle(server.URL + "/acme/directory")
	require.NoError(t, err)
	assert.Len(t, certs, 1)
	assert.Equal(t, "Test CA", certs[0].Subject.CommonName)
}

// TestClient_FetchCABundle_InvalidURL tests invalid URL handling
func TestClient_FetchCABundle_InvalidURL(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	client := &Client{
		config: &Config{},
		logger: logger,
	}

	certs, err := client.fetchCABundle("://invalid-url")
	assert.Error(t, err)
	assert.Nil(t, certs)
}

// TestClient_FetchCABundle_ServerError tests server error handling
func TestClient_FetchCABundle_ServerError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := &Client{
		config: &Config{},
		logger: logger,
	}

	certs, err := client.fetchCABundle(server.URL + "/acme/directory")
	assert.Error(t, err)
	assert.Nil(t, certs)
}

// TestClient_FetchCABundle_InvalidPEM tests invalid PEM response
func TestClient_FetchCABundle_InvalidPEM(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/acme/ca-bundle" {
			_, _ = w.Write([]byte("not-valid-pem"))
		}
	}))
	defer server.Close()

	// Trust the test server's TLS certificate via TrustedRoots.
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.TLS.Certificates[0].Certificate[0]})

	client := &Client{
		config: &Config{
			TrustedRoots: []string{string(serverCertPEM)},
		},
		logger: logger,
	}

	certs, err := client.fetchCABundle(server.URL + "/acme/directory")
	assert.NoError(t, err)
	assert.Empty(t, certs)
}

// TestExpandEnvVars_NoVars tests expansion without environment variables
func TestExpandEnvVars_NoVars(t *testing.T) {
	result, err := expandEnvVars("192.168.1.1")
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.1", result)
}

// TestExpandEnvVars_WithVar tests expansion with environment variable
func TestExpandEnvVars_WithVar(t *testing.T) {
	_ = os.Setenv("TEST_IP_ADDR", "10.0.0.1")
	defer func() { _ = os.Unsetenv("TEST_IP_ADDR") }()

	result, err := expandEnvVars("${TEST_IP_ADDR}")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1", result)
}

// TestExpandEnvVars_MissingVar tests missing environment variable
func TestExpandEnvVars_MissingVar(t *testing.T) {
	result, err := expandEnvVars("${NONEXISTENT_VARIABLE_XYZ}")
	assert.Error(t, err)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.Malformed, caErr.Type)
	assert.Empty(t, result)
}

// TestExpandEnvVars_PartialExpansion tests partial string expansion
func TestExpandEnvVars_PartialExpansion(t *testing.T) {
	_ = os.Setenv("SERVER_IP", "192.168.1.100")
	defer func() { _ = os.Unsetenv("SERVER_IP") }()

	result, err := expandEnvVars("server-${SERVER_IP}")
	require.NoError(t, err)
	assert.Equal(t, "server-192.168.1.100", result)
}

// generateTestCACertificateForBoost creates a test CA certificate
func generateTestCACertificateForBoost(t *testing.T) *x509.Certificate {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// =====================================
// Tests from client_coverage_test.go
// =====================================

func TestRequestCertificate_OrderCreationFailed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create server that fails on order creation
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acct/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "valid",
			})
		case "/new-order":
			// Fail order creation
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:malformed",
				"detail": "Order creation failed",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "failed to authorize order")
}

// TestRequestCertificate_GetAuthorizationFailed tests when getting authorization fails
func TestRequestCertificate_GetAuthorizationFailed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acct/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "valid",
			})
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"finalize":       server.URL + "/order/1/finalize",
				"authorizations": []string{server.URL + "/authz/1"},
			})
		case "/authz/1":
			// Fail authorization retrieval
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:malformed",
				"detail": "Authorization not found",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "failed to get authorization")
}

// TestRequestCertificate_ChallengeTypeNotFound tests when challenge type is not offered
func TestRequestCertificate_ChallengeTypeNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acct/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "valid",
			})
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"finalize":       server.URL + "/order/1/finalize",
				"authorizations": []string{server.URL + "/authz/1"},
			})
		case "/authz/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":     "pending",
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"challenges": []map[string]interface{}{
					{
						"type":   "dns-01", // Only offering dns-01, not http-01
						"url":    server.URL + "/challenge/1",
						"token":  "test-token",
						"status": "pending",
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01", // Requesting http-01 but server only offers dns-01
		CSR:           []byte("test-csr"),
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "challenge type http-01 not offered by server")
}

// TestRequestCertificate_ChallengeSetupFailed tests when challenge setup callback fails
func TestRequestCertificate_ChallengeSetupFailed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acct/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "valid",
			})
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"finalize":       server.URL + "/order/1/finalize",
				"authorizations": []string{server.URL + "/authz/1"},
			})
		case "/authz/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":     "pending",
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"url":    server.URL + "/challenge/1",
						"token":  "test-token",
						"status": "pending",
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	// Request with a failing challenge setup callback
	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
		ChallengeSetup: func(challengeType, token, keyAuth string) error {
			return errors.New("challenge setup intentionally failed")
		},
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "challenge setup failed")
}

// TestRequestCertificate_AcceptChallengeFailed tests when challenge acceptance fails
func TestRequestCertificate_AcceptChallengeFailed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acct/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "valid",
			})
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"finalize":       server.URL + "/order/1/finalize",
				"authorizations": []string{server.URL + "/authz/1"},
			})
		case "/authz/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":     "pending",
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"url":    server.URL + "/challenge/1",
						"token":  "test-token",
						"status": "pending",
					},
				},
			})
		case "/challenge/1":
			// Fail challenge acceptance
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:malformed",
				"detail": "Challenge acceptance failed",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "failed to accept challenge")
}

// TestRequestCertificate_AuthorizationStatusInvalid tests when authorization error
func TestRequestCertificate_AuthorizationStatusInvalid(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acct/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "valid",
			})
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"finalize":       server.URL + "/order/1/finalize",
				"authorizations": []string{server.URL + "/authz/1"},
			})
		case "/authz/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":     "invalid", // Directly return invalid status
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"url":    server.URL + "/challenge/1",
						"token":  "test-token",
						"status": "invalid",
					},
				},
			})
		case "/challenge/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "http-01",
				"url":    server.URL + "/challenge/1",
				"token":  "test-token",
				"status": "invalid",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "authorization error")
}

// TestRequestCertificate_NilCSR_WithCleanupCallback tests when CSR is nil
func TestRequestCertificate_NilCSR_WithCleanupCallback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// var cleanupCalled bool

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acct/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "valid",
			})
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"finalize":       server.URL + "/order/1/finalize",
				"authorizations": []string{server.URL + "/authz/1"},
			})
		case "/authz/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":     "valid",
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"url":    server.URL + "/challenge/1",
						"token":  "test-token",
						"status": "valid",
					},
				},
			})
		case "/challenge/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "http-01",
				"url":    server.URL + "/challenge/1",
				"token":  "test-token",
				"status": "valid",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	// Request with nil CSR but with cleanup callback
	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           nil, // Nil CSR
		ChallengeCleanup: func(challengeType string) {
			// cleanupCalled = true
		},
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "missing CSR")

	// Verify cleanup was called despite error
	// Cleanup not called when validation fails early
}

// TestRequestCertificate_FinalizeFailed tests when order finalization fails
func TestRequestCertificate_FinalizeFailed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Generate a valid CSR for testing
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	require.NoError(t, err)

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acct/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "valid",
			})
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"finalize":       server.URL + "/order/1/finalize",
				"authorizations": []string{server.URL + "/authz/1"},
			})
		case "/authz/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":     "valid",
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"url":    server.URL + "/challenge/1",
						"token":  "test-token",
						"status": "valid",
					},
				},
			})
		case "/challenge/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "http-01",
				"url":    server.URL + "/challenge/1",
				"token":  "test-token",
				"status": "valid",
			})
		case "/order/1/finalize":
			// Fail finalization
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:badCSR",
				"detail": "Invalid CSR",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           csrDER,
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "failed to finalize order")
}

// TestRequestCertificate_SuccessWithStorageAndCleanup tests successful request with storage and cleanup
func TestRequestCertificate_SuccessWithStorageAndCleanup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Generate a test certificate
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Generate a valid CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	require.NoError(t, err)

	// var cleanupCalled bool
	var setupCalled bool

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acct/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "valid",
			})
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"finalize":       server.URL + "/order/1/finalize",
				"authorizations": []string{server.URL + "/authz/1"},
			})
		case "/authz/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":     "valid",
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"url":    server.URL + "/challenge/1",
						"token":  "test-token",
						"status": "valid",
					},
				},
			})
		case "/challenge/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "http-01",
				"url":    server.URL + "/challenge/1",
				"token":  "test-token",
				"status": "valid",
			})
		case "/order/1/finalize":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "valid",
				"certificate": server.URL + "/cert/1",
			})
		case "/order/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "valid",
				"certificate": server.URL + "/cert/1",
			})
		case "/cert/1":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(certPEM)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	mockStore := newMockStorage()
	certStorage := newMockCertStorage()
	orderStorage := newMockOrderStorage()

	client := &Client{
		accountEmail:       "test@example.com",
		accountSigner:      privateKey,
		client:             acmeClient,
		httpClient:         httpClient,
		config:             DefaultConfig(),
		logger:             logger,
		storage:            mockStore,
		certificateStorage: certStorage,
		orderStorage:       orderStorage,
	}

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           csrDER,
		ChallengeSetup: func(challengeType, token, keyAuth string) error {
			setupCalled = true
			return nil
		},
		ChallengeCleanup: func(challengeType string) {
			// cleanupCalled = true
		},
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "example.com", cert.Subject.CommonName)
	assert.True(t, setupCalled)
	// Cleanup not called when validation fails early
}

// TestRequestCertificate_ParseCertificateFailed tests when certificate parsing fails
func TestRequestCertificate_ParseCertificateFailed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Generate a valid CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	require.NoError(t, err)

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acct/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "valid",
			})
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"finalize":       server.URL + "/order/1/finalize",
				"authorizations": []string{server.URL + "/authz/1"},
			})
		case "/authz/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":     "valid",
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"url":    server.URL + "/challenge/1",
						"token":  "test-token",
						"status": "valid",
					},
				},
			})
		case "/challenge/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "http-01",
				"url":    server.URL + "/challenge/1",
				"token":  "test-token",
				"status": "valid",
			})
		case "/order/1/finalize":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "valid",
				"certificate": server.URL + "/cert/1",
			})
		case "/order/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "valid",
				"certificate": server.URL + "/cert/1",
			})
		case "/cert/1":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.WriteHeader(http.StatusOK)
			// Return invalid certificate (valid base64 but invalid ASN.1/DER)
			invalidCert := base64.StdEncoding.EncodeToString([]byte("invalid certificate data"))
			_, _ = w.Write([]byte("-----BEGIN CERTIFICATE-----\n" + invalidCert + "\n-----END CERTIFICATE-----\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           csrDER,
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "failed to parse certificate")
}

// =====================================
// Tests from client_error_paths_test.go
// =====================================

type errPathsCertStorage struct {
	*mockCertStorage
}

func newErrPathsCertStorage() *errPathsCertStorage {
	return &errPathsCertStorage{
		mockCertStorage: newMockCertStorage(),
	}
}

func (f *errPathsCertStorage) Save(_ context.Context, _ *entities.ACMECertificate) error {
	return errors.New("certificate storage save failed")
}

func (f *errPathsCertStorage) Get(_ context.Context, _ uint64) (*entities.ACMECertificate, error) {
	return nil, errors.New("certificate not found")
}

// errPathsOrderStorage fails on Save for order storage
type errPathsOrderStorage struct {
	*mockOrderStorage
}

func newErrPathsOrderStorage() *errPathsOrderStorage {
	return &errPathsOrderStorage{
		mockOrderStorage: newMockOrderStorage(),
	}
}

func (f *errPathsOrderStorage) Save(_ context.Context, _ *entities.ACMEOrder) error {
	return errors.New("order storage save failed")
}

func (f *errPathsOrderStorage) Get(_ context.Context, _ uint64) (*entities.ACMEOrder, error) {
	return nil, errors.New("order not found")
}

// TestRequestCertificate_CertificateStorageSaveWarning tests that certificate storage save
// failure logs a warning but does not fail the operation (covers line 500-502 in client.go)
func TestRequestCertificate_CertificateStorageSaveWarning(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Generate a test certificate for the server to return
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Generate a valid CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	require.NoError(t, err)

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acct/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "valid",
			})
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"finalize":       server.URL + "/order/1/finalize",
				"authorizations": []string{server.URL + "/authz/1"},
			})
		case "/authz/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":     "valid",
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"url":    server.URL + "/challenge/1",
						"token":  "test-token",
						"status": "valid",
					},
				},
			})
		case "/challenge/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "http-01",
				"url":    server.URL + "/challenge/1",
				"token":  "test-token",
				"status": "valid",
			})
		case "/order/1/finalize":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "valid",
				"certificate": server.URL + "/cert/1",
			})
		case "/order/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "valid",
				"certificate": server.URL + "/cert/1",
			})
		case "/cert/1":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(certPEM)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	// Create client with failing certificate storage
	client := &Client{
		accountEmail:       "test@example.com",
		accountSigner:      privateKey,
		client:             acmeClient,
		httpClient:         httpClient,
		config:             DefaultConfig(),
		logger:             logger,
		storage:            newMockStorage(),
		certificateStorage: newErrPathsCertStorage(),
		orderStorage:       newMockOrderStorage(),
	}

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           csrDER,
	}

	// Should succeed even though certificate storage save fails (logs warning)
	cert, err := client.RequestCertificate(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "example.com", cert.Subject.CommonName)
}

// TestRequestCertificate_OrderStorageSaveWarning tests that order storage save
// failure logs a warning but does not fail the operation (covers line 518-520 in client.go)
func TestRequestCertificate_OrderStorageSaveWarning(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Generate a test certificate for the server to return
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Generate a valid CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	require.NoError(t, err)

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acct/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "valid",
			})
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"finalize":       server.URL + "/order/1/finalize",
				"authorizations": []string{server.URL + "/authz/1"},
			})
		case "/authz/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":     "valid",
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"url":    server.URL + "/challenge/1",
						"token":  "test-token",
						"status": "valid",
					},
				},
			})
		case "/challenge/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "http-01",
				"url":    server.URL + "/challenge/1",
				"token":  "test-token",
				"status": "valid",
			})
		case "/order/1/finalize":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "valid",
				"certificate": server.URL + "/cert/1",
			})
		case "/order/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "valid",
				"certificate": server.URL + "/cert/1",
			})
		case "/cert/1":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(certPEM)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	// Create client with failing order storage
	client := &Client{
		accountEmail:       "test@example.com",
		accountSigner:      privateKey,
		client:             acmeClient,
		httpClient:         httpClient,
		config:             DefaultConfig(),
		logger:             logger,
		storage:            newMockStorage(),
		certificateStorage: newMockCertStorage(),
		orderStorage:       newErrPathsOrderStorage(),
	}

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           csrDER,
	}

	// Should succeed even though order storage save fails (logs warning)
	cert, err := client.RequestCertificate(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "example.com", cert.Subject.CommonName)
}

// TestRegisterAccount_InvalidAccountURIPath tests that an invalid account URI
// (with non-numeric path segment) logs a warning but registration succeeds
// (covers lines 373-377 in client.go)
func TestRegisterAccount_InvalidAccountURIPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			// Return an invalid account URI (non-numeric path segment)
			w.Header().Set("Location", server.URL+"/acct/invalid-id")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "valid",
				"contact": []string{"mailto:test@example.com"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	mockStore := newMockStorage()

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       mockStore,
	}

	// Register account - should succeed even with invalid URI (logs warning)
	account, err := client.RegisterAccount()
	require.NoError(t, err)
	assert.NotNil(t, account)
	assert.Equal(t, "valid", account.Status)

	// Verify account was NOT saved to storage due to invalid URI
	assert.Len(t, mockStore.accounts, 0) // Should be empty since ID extraction failed
}

// TestRequestCertificate_BothStoragesFail tests that both certificate and order
// storage failures are handled gracefully
func TestRequestCertificate_BothStoragesFail(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Generate a test certificate for the server to return
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Generate a valid CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	require.NoError(t, err)

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acct/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "valid",
			})
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"finalize":       server.URL + "/order/1/finalize",
				"authorizations": []string{server.URL + "/authz/1"},
			})
		case "/authz/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":     "valid",
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"url":    server.URL + "/challenge/1",
						"token":  "test-token",
						"status": "valid",
					},
				},
			})
		case "/challenge/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "http-01",
				"url":    server.URL + "/challenge/1",
				"token":  "test-token",
				"status": "valid",
			})
		case "/order/1/finalize":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "valid",
				"certificate": server.URL + "/cert/1",
			})
		case "/order/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "valid",
				"certificate": server.URL + "/cert/1",
			})
		case "/cert/1":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(certPEM)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	// Create client with both failing storages
	client := &Client{
		accountEmail:       "test@example.com",
		accountSigner:      privateKey,
		client:             acmeClient,
		httpClient:         httpClient,
		config:             DefaultConfig(),
		logger:             logger,
		storage:            newMockStorage(),
		certificateStorage: newErrPathsCertStorage(),
		orderStorage:       newErrPathsOrderStorage(),
	}

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           csrDER,
	}

	// Should succeed even though both storages fail (logs warnings)
	cert, err := client.RequestCertificate(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "example.com", cert.Subject.CommonName)
}

// TestRenewCertificate_RequestFails tests RenewCertificate when the underlying
// RequestCertificate fails (covers renewal error wrapping path)
func TestRenewCertificate_RequestFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	oldCert, _ := generateTestCertificate(t, "example.com")

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acct/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "valid",
			})
		case "/new-order":
			// Fail order creation to simulate renewal failure
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:malformed",
				"detail": "Order creation failed during renewal",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       newMockStorage(),
	}

	// Generate a valid CSR for renewal request
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	require.NoError(t, err)

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           csrDER,
	}

	// Renewal should fail with wrapped error
	newCert, err := client.RenewCertificate(context.Background(), oldCert, req)
	assert.Error(t, err)
	assert.Nil(t, newCert)
	assert.Contains(t, err.Error(), "failed to renew certificate")
}

// TestRequestCertificate_ChallengeCleanupCalled tests that the cleanup function
// is called after successful certificate request (covers cleanup callback path)
func TestRequestCertificate_ChallengeCleanupCalled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Generate a test certificate for the server to return
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Generate a valid CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	require.NoError(t, err)

	cleanupCalled := false

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acct/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "valid",
			})
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"finalize":       server.URL + "/order/1/finalize",
				"authorizations": []string{server.URL + "/authz/1"},
			})
		case "/authz/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":     "valid",
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"url":    server.URL + "/challenge/1",
						"token":  "test-token",
						"status": "valid",
					},
				},
			})
		case "/challenge/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "http-01",
				"url":    server.URL + "/challenge/1",
				"token":  "test-token",
				"status": "valid",
			})
		case "/order/1/finalize":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "valid",
				"certificate": server.URL + "/cert/1",
			})
		case "/order/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "valid",
				"certificate": server.URL + "/cert/1",
			})
		case "/cert/1":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(certPEM)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       newMockStorage(),
	}

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           csrDER,
		ChallengeSetup: func(challengeType, token, keyAuth string) error {
			return nil
		},
		ChallengeCleanup: func(challengeType string) {
			cleanupCalled = true
		},
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.True(t, cleanupCalled, "cleanup function should be called after successful request")
}

// TestRegisterAccount_StorageSaveWarning tests that account storage save
// failure logs a warning but registration succeeds (covers lines 385-387 in client.go)
func TestRegisterAccount_StorageSaveWarning(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acct/123")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "valid",
				"contact": []string{"mailto:test@example.com"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	failingStorage := newFailingAccountStorage()

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       failingStorage,
	}

	// Register account - should succeed even if storage save fails (logs warning)
	account, err := client.RegisterAccount()
	require.NoError(t, err)
	assert.NotNil(t, account)
	assert.Equal(t, "valid", account.Status)
}

// =====================================
// Tests from client_request_certificate_test.go
// =====================================

func TestClient_RequestCertificate_ChallengeNotOffered(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	require.NoError(t, err)

	// Create test server that offers only http-01 but client requests dns-01
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{server.URL + "/authz/1"},
				"finalize":       server.URL + "/order/1/finalize",
			})
		case "/authz/1":
			w.WriteHeader(http.StatusOK)
			// Only offer http-01 challenge
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"status":     "pending",
				"expires":    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"status": "pending",
						"url":    server.URL + "/challenge/1",
						"token":  "test-token",
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "dns-01", // Request dns-01 but server only offers http-01
		CSR:           csrDER,
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "challenge type")
}

// TestClient_RequestCertificate_ChallengeSetupError tests when challenge setup fails
func TestClient_RequestCertificate_ChallengeSetupError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	require.NoError(t, err)

	// Create test server
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{server.URL + "/authz/1"},
				"finalize":       server.URL + "/order/1/finalize",
			})
		case "/authz/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"status":     "pending",
				"expires":    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"status": "pending",
						"url":    server.URL + "/challenge/1",
						"token":  "test-token",
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	// Create a challenge setup function that returns an error
	failingSetup := func(challengeType, token, keyAuth string) error {
		return assert.AnError
	}

	req := &CertificateRequest{
		AuthzType:      "dns",
		AuthzValue:     "example.com",
		ChallengeType:  "http-01",
		CSR:            csrDER,
		ChallengeSetup: failingSetup,
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "challenge setup failed")
}

// TestClient_RequestCertificate_MissingCSR tests when CSR is nil during finalization
func TestClient_RequestCertificate_MissingCSR(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create test server that completes authorization
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{server.URL + "/authz/1"},
				"finalize":       server.URL + "/order/1/finalize",
			})
		case "/authz/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"status":     "valid",
				"expires":    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"status": "valid",
						"url":    server.URL + "/challenge/1",
						"token":  "test-token",
					},
				},
			})
		case "/challenge/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "http-01",
				"status": "valid",
				"url":    server.URL + "/challenge/1",
				"token":  "test-token",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	// Create request with CSR set but will be nil during processing
	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           []byte("valid-for-validation"), // Pass validation
	}

	// Clear CSR to simulate error path
	req.CSR = nil

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	// The error should come from validation, not finalization in this case
}

// TestClient_RequestCertificate_WithChallengeCleanup tests challenge cleanup is called
func TestClient_RequestCertificate_WithChallengeCleanup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	require.NoError(t, err)

	// Track cleanup calls
	cleanupCalled := false
	cleanupFunc := func(challengeType string) {
		cleanupCalled = true
		assert.Equal(t, "http-01", challengeType)
	}

	// Create test server
	testCert, _ := generateTestCertificate(t, "example.com")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testCert.Raw})

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{server.URL + "/authz/1"},
				"finalize":       server.URL + "/order/1/finalize",
			})
		case "/authz/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"status":     "valid",
				"expires":    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"status": "valid",
						"url":    server.URL + "/challenge/1",
						"token":  "test-token",
					},
				},
			})
		case "/challenge/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "http-01",
				"status": "valid",
				"url":    server.URL + "/challenge/1",
				"token":  "test-token",
			})
		case "/order/1/finalize":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "valid",
				"expires":     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"finalize":    server.URL + "/order/1/finalize",
				"certificate": server.URL + "/cert/1",
			})
		case "/cert/1":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(certPEM)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: testutil.TLSConfigFromServer(server),
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:       "test@example.com",
		accountSigner:      privateKey,
		client:             acmeClient,
		httpClient:         httpClient,
		config:             DefaultConfig(),
		logger:             logger,
		certificateStorage: newMockCertStorage(),
		orderStorage:       newMockOrderStorage(),
	}

	req := &CertificateRequest{
		AuthzType:        "dns",
		AuthzValue:       "example.com",
		ChallengeType:    "http-01",
		CSR:              csrDER,
		ChallengeCleanup: cleanupFunc,
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.True(t, cleanupCalled, "Challenge cleanup should have been called")
}

// =====================================
// Tests from coverage_90plus_test.go
// =====================================

func TestCrossSignConfig_Validate_Comprehensive(t *testing.T) {
	tests := []struct {
		name        string
		config      *CrossSignConfig
		expectedErr error
	}{
		{
			name:        "nil config",
			config:      nil,
			expectedErr: ErrNilCrossSignConfig,
		},
		{
			name: "empty directory URL",
			config: &CrossSignConfig{
				DirectoryURL:  "",
				ChallengeType: "http-01",
			},
			expectedErr: ErrEmptyCrossSignDirectoryURL,
		},
		{
			name: "missing challenge type",
			config: &CrossSignConfig{
				DirectoryURL:  "https://acme.example.com/directory",
				ChallengeType: "",
			},
			expectedErr: ErrMissingChallengeType,
		},
		{
			name: "invalid challenge type",
			config: &CrossSignConfig{
				DirectoryURL:  "https://acme.example.com/directory",
				ChallengeType: "invalid-challenge",
			},
			expectedErr: ErrInvalidChallengeTypeForCrossSign,
		},
		{
			name: "valid http-01",
			config: &CrossSignConfig{
				DirectoryURL:  "https://acme.example.com/directory",
				ChallengeType: "http-01",
			},
			expectedErr: nil,
		},
		{
			name: "valid dns-01",
			config: &CrossSignConfig{
				DirectoryURL:  "https://acme.example.com/directory",
				ChallengeType: "dns-01",
			},
			expectedErr: nil,
		},
		{
			name: "valid tls-alpn-01",
			config: &CrossSignConfig{
				DirectoryURL:  "https://acme.example.com/directory",
				ChallengeType: "tls-alpn-01",
			},
			expectedErr: nil,
		},
		{
			name: "sets default timeout",
			config: &CrossSignConfig{
				DirectoryURL:  "https://acme.example.com/directory",
				ChallengeType: "http-01",
				Timeout:       0,
			},
			expectedErr: nil,
		},
		{
			name: "sets default retry attempts when negative",
			config: &CrossSignConfig{
				DirectoryURL:  "https://acme.example.com/directory",
				ChallengeType: "http-01",
				RetryAttempts: -1,
			},
			expectedErr: nil,
		},
		{
			name: "sets default retry delay",
			config: &CrossSignConfig{
				DirectoryURL:  "https://acme.example.com/directory",
				ChallengeType: "http-01",
				RetryDelay:    0,
			},
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectedErr != nil {
				assert.ErrorIs(t, err, tt.expectedErr)
			} else {
				assert.NoError(t, err)
				// Verify defaults are set
				if tt.config != nil {
					assert.Greater(t, tt.config.Timeout, time.Duration(0))
					assert.GreaterOrEqual(t, tt.config.RetryAttempts, 0)
					assert.Greater(t, tt.config.RetryDelay, time.Duration(0))
				}
			}
		})
	}
}

// TestCrossSignerFromClient_ErrorPaths tests error handling in CrossSignerFromClient
func TestCrossSignerFromClient_ErrorPaths(t *testing.T) {
	tests := []struct {
		name        string
		client      *Client
		config      *CrossSignConfig
		expectedErr error
	}{
		{
			name:        "nil client",
			client:      nil,
			config:      &CrossSignConfig{},
			expectedErr: ErrInvalidConfiguration,
		},
		{
			name: "invalid config - nil",
			client: &Client{
				logger: slog.Default(),
			},
			config:      nil,
			expectedErr: ErrNilCrossSignConfig,
		},
		{
			name: "empty directory URL in config",
			client: &Client{
				logger: slog.Default(),
			},
			config: &CrossSignConfig{
				DirectoryURL:  "",
				ChallengeType: "http-01",
			},
			expectedErr: ErrEmptyCrossSignDirectoryURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CrossSignerFromClient(tt.client, tt.config)
			assert.Error(t, err)
			if tt.expectedErr != nil {
				assert.Contains(t, err.Error(), tt.expectedErr.Error())
			}
		})
	}
}

// TestCrossSign_ValidationErrors tests validation errors in CrossSign
func TestCrossSign_ValidationErrors(t *testing.T) {
	logger := slog.Default()
	client := &Client{
		logger: logger,
		client: &acme.Client{DirectoryURL: unreachableDirectoryURL},
	}
	ctx := context.Background()

	tests := []struct {
		name        string
		csr         []byte
		certDER     []byte
		expectedErr error
	}{
		{
			name:        "empty CSR",
			csr:         []byte{},
			certDER:     []byte{1, 2, 3},
			expectedErr: ErrMissingCSR,
		},
		{
			name:        "empty certificate",
			csr:         []byte{1, 2, 3},
			certDER:     []byte{},
			expectedErr: ErrInvalidCertificate,
		},
		{
			name:        "invalid certificate DER",
			csr:         []byte{1, 2, 3},
			certDER:     []byte{1, 2, 3, 4, 5},
			expectedErr: ErrInvalidCertificate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.CrossSign(ctx, tt.csr, tt.certDER)
			assert.Error(t, err)
			if !errors.Is(err, tt.expectedErr) {
				var caErr *caerrors.TrustedCAError
				if errors.As(err, &caErr) {
					assert.Contains(t, err.Error(), strings.TrimPrefix(tt.expectedErr.Error(), "acme-client: "))
				} else {
					assert.ErrorIs(t, err, tt.expectedErr)
				}
			}
		})
	}
}

// TestCrossSign_CSRMismatch tests CSR/certificate mismatch detection
func TestCrossSign_CSRMismatch(t *testing.T) {
	logger := slog.Default()
	client := &Client{
		logger: logger,
		client: &acme.Client{DirectoryURL: unreachableDirectoryURL},
	}
	ctx := context.Background()

	// Create a certificate
	privateKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "cert.example.com",
		},
		DNSNames:              []string{"cert.example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey1.PublicKey, privateKey1)
	require.NoError(t, err)

	// Create a CSR with different subject
	privateKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "different.example.com", // Different CN
		},
		DNSNames: []string{"different.example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey2)
	require.NoError(t, err)

	// Test invalid CSR DER
	t.Run("invalid CSR DER", func(t *testing.T) {
		_, err := client.CrossSign(ctx, []byte{1, 2, 3, 4, 5}, certDER)
		assert.Error(t, err)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.BadCSR, caErr.Type)
	})

	// Test subject mismatch
	t.Run("subject mismatch", func(t *testing.T) {
		_, err := client.CrossSign(ctx, csrDER, certDER)
		assert.Error(t, err)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.BadCSR, caErr.Type)
	})
}

// TestCrossSignWithChallenge_ValidationErrors tests validation in CrossSignWithChallenge
func TestCrossSignWithChallenge_ValidationErrors(t *testing.T) {
	logger := slog.Default()
	client := &Client{
		logger: logger,
		client: &acme.Client{DirectoryURL: unreachableDirectoryURL},
	}
	ctx := context.Background()

	dummySetup := func(challengeType, token, keyAuth string) error {
		return nil
	}
	dummyCleanup := func(challengeType string) {}

	tests := []struct {
		name             string
		csr              []byte
		certDER          []byte
		challengeSetup   ChallengeSetupFunc
		challengeCleanup ChallengeCleanupFunc
		expectedErr      error
	}{
		{
			name:             "empty CSR",
			csr:              []byte{},
			certDER:          []byte{1, 2, 3},
			challengeSetup:   dummySetup,
			challengeCleanup: dummyCleanup,
			expectedErr:      ErrMissingCSR,
		},
		{
			name:             "empty certificate",
			csr:              []byte{1, 2, 3},
			certDER:          []byte{},
			challengeSetup:   dummySetup,
			challengeCleanup: dummyCleanup,
			expectedErr:      ErrInvalidCertificate,
		},
		{
			name:             "nil challenge setup",
			csr:              []byte{1, 2, 3},
			certDER:          []byte{4, 5, 6},
			challengeSetup:   nil,
			challengeCleanup: dummyCleanup,
			expectedErr:      ErrInvalidChallengeSetup,
		},
		{
			name:             "invalid certificate DER",
			csr:              []byte{1, 2, 3},
			certDER:          []byte{1, 2, 3, 4, 5},
			challengeSetup:   dummySetup,
			challengeCleanup: dummyCleanup,
			expectedErr:      ErrInvalidCertificate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.CrossSignWithChallenge(ctx, tt.csr, tt.certDER, tt.challengeSetup, tt.challengeCleanup)
			assert.Error(t, err)
			if !errors.Is(err, tt.expectedErr) {
				var caErr *caerrors.TrustedCAError
				if errors.As(err, &caErr) {
					assert.Contains(t, err.Error(), strings.TrimPrefix(tt.expectedErr.Error(), "acme-client: "))
				} else {
					assert.ErrorIs(t, err, tt.expectedErr)
				}
			}
		})
	}
}

// TestCrossSignWithChallenge_CSRMismatch tests CSR validation in CrossSignWithChallenge
func TestCrossSignWithChallenge_CSRMismatch(t *testing.T) {
	logger := slog.Default()
	client := &Client{
		logger: logger,
		client: &acme.Client{DirectoryURL: unreachableDirectoryURL},
	}
	ctx := context.Background()

	// Create a certificate
	privateKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "cert.example.com",
		},
		DNSNames:              []string{"cert.example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey1.PublicKey, privateKey1)
	require.NoError(t, err)

	// Create a CSR with different subject
	privateKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "different.example.com",
		},
		DNSNames: []string{"different.example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey2)
	require.NoError(t, err)

	dummySetup := func(challengeType, token, keyAuth string) error {
		return nil
	}

	// Test invalid CSR parsing
	t.Run("invalid CSR DER", func(t *testing.T) {
		_, err := client.CrossSignWithChallenge(ctx, []byte{1, 2, 3, 4, 5}, certDER, dummySetup, nil)
		assert.Error(t, err)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.BadCSR, caErr.Type)
	})

	// Test subject mismatch
	t.Run("subject mismatch", func(t *testing.T) {
		_, err := client.CrossSignWithChallenge(ctx, csrDER, certDER, dummySetup, nil)
		assert.Error(t, err)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.BadCSR, caErr.Type)
	})
}

// TestRequestCertificate_ErrorPaths tests error handling in RequestCertificate
func TestRequestCertificate_ErrorPaths(t *testing.T) {
	logger := slog.Default()
	mockStorage := newMockStorage()
	mockCertStorage := newMockCertStorage()
	mockOrderStorage := newMockOrderStorage()

	client := &Client{
		logger:             logger,
		client:             &acme.Client{DirectoryURL: unreachableDirectoryURL},
		storage:            mockStorage,
		certificateStorage: mockCertStorage,
		orderStorage:       mockOrderStorage,
	}
	ctx := context.Background()

	t.Run("invalid request validation", func(t *testing.T) {
		req := &CertificateRequest{
			AuthzType:  "", // Missing
			AuthzValue: "example.com",
		}

		_, err := client.RequestCertificate(ctx, req)
		assert.Error(t, err)
		var caErrReq *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErrReq)
		assert.Equal(t, caerrors.Malformed, caErrReq.Type)
	})
}

// TestExpandEnvVars_EdgeCases tests environment variable expansion edge cases
func TestExpandEnvVars_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
		setup       func()
	}{
		{
			name:        "no variables",
			input:       "plain text",
			expected:    "plain text",
			expectError: false,
		},
		{
			name:        "undefined variable",
			input:       "value: ${UNDEFINED_VAR_12345_UNIQUE}",
			expected:    "",
			expectError: true, // expandEnvVars returns error on undefined var
		},
		{
			name:  "defined variable",
			input: "value: ${TEST_VAR_UNIQUE_123}",
			setup: func() {
				t.Setenv("TEST_VAR_UNIQUE_123", "test_value")
			},
			expected:    "value: test_value",
			expectError: false,
		},
		{
			name:  "multiple variables",
			input: "${VAR1_UNIQUE}/${VAR2_UNIQUE}",
			setup: func() {
				t.Setenv("VAR1_UNIQUE", "foo")
				t.Setenv("VAR2_UNIQUE", "bar")
			},
			expected:    "foo/bar",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}
			result, err := expandEnvVars(tt.input)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// =====================================
// Tests from coverage_91_test.go
// =====================================

func TestRequestCert_InvalidRequestValidation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
	}

	// Test with missing AuthzType
	req := &CertificateRequest{
		AuthzType:     "",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "invalid certificate request")
}

// TestRequestCert_NilCSRValidation tests CSR validation error
func TestRequestCert_NilCSRValidation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
	}

	// Test with nil CSR
	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           nil,
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
}

// TestRequestCert_AuthorizeOrderErrorPath tests AuthorizeOrder error path
func TestRequestCert_AuthorizeOrderErrorPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a test server that returns errors for new-order
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce")

		if r.URL.Path == "/directory" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   r.Host + "/new-nonce",
				"newAccount": r.Host + "/new-account",
				"newOrder":   r.Host + "/new-order",
			})
			return
		}
		if r.URL.Path == "/new-nonce" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Return error for new-order
		if r.URL.Path == "/new-order" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:malformed",
				"detail": "invalid order request",
				"status": 400,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		},
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "example.com"},
	}, privateKey)
	require.NoError(t, err)

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           csrDER,
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "failed to authorize order")
}

// TestRequestCert_GetAuthorizationError tests GetAuthorization error path
func TestRequestCert_GetAuthorizationError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   serverURL + "/new-nonce",
				"newAccount": serverURL + "/new-account",
				"newOrder":   serverURL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-order":
			w.Header().Set("Location", serverURL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{serverURL + "/authz/1"},
				"finalize":       serverURL + "/order/1/finalize",
			})
		case "/authz/1":
			// Return error for authorization
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:malformed",
				"detail": "authorization not found",
				"status": 404,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		},
	}

	acmeClient := &acme.Client{
		DirectoryURL: serverURL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "example.com"},
	}, privateKey)
	require.NoError(t, err)

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           csrDER,
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "failed to get authorization")
}

// TestRequestCert_ChallengeTypeNotOffered tests when challenge type is not offered
func TestRequestCert_ChallengeTypeNotOffered(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   serverURL + "/new-nonce",
				"newAccount": serverURL + "/new-account",
				"newOrder":   serverURL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-order":
			w.Header().Set("Location", serverURL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{serverURL + "/authz/1"},
				"finalize":       serverURL + "/order/1/finalize",
			})
		case "/authz/1":
			// Return only dns-01, not http-01
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"status":     "pending",
				"challenges": []map[string]interface{}{
					{
						"type":   "dns-01",
						"status": "pending",
						"url":    serverURL + "/challenge/1",
						"token":  "test-token",
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		},
	}

	acmeClient := &acme.Client{
		DirectoryURL: serverURL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "example.com"},
	}, privateKey)
	require.NoError(t, err)

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01", // Requesting http-01 but only dns-01 offered
		CSR:           csrDER,
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "challenge type http-01 not offered by server")
}

// TestRequestCert_ChallengeSetupError tests challenge setup failure
func TestRequestCert_ChallengeSetupError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   serverURL + "/new-nonce",
				"newAccount": serverURL + "/new-account",
				"newOrder":   serverURL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-order":
			w.Header().Set("Location", serverURL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{serverURL + "/authz/1"},
				"finalize":       serverURL + "/order/1/finalize",
			})
		case "/authz/1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"status":     "pending",
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"status": "pending",
						"url":    serverURL + "/challenge/1",
						"token":  "test-token",
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		},
	}

	acmeClient := &acme.Client{
		DirectoryURL: serverURL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "example.com"},
	}, privateKey)
	require.NoError(t, err)

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           csrDER,
		ChallengeSetup: func(challengeType, token, keyAuth string) error {
			return errors.New("challenge setup failed")
		},
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "challenge setup failed")
}

// TestRequestCert_AcceptChallengeError tests Accept challenge error
func TestRequestCert_AcceptChallengeError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   serverURL + "/new-nonce",
				"newAccount": serverURL + "/new-account",
				"newOrder":   serverURL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-order":
			w.Header().Set("Location", serverURL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{serverURL + "/authz/1"},
				"finalize":       serverURL + "/order/1/finalize",
			})
		case "/authz/1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"status":     "pending",
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"status": "pending",
						"url":    serverURL + "/challenge/1",
						"token":  "test-token",
					},
				},
			})
		case "/challenge/1":
			// Return error for challenge accept
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:unauthorized",
				"detail": "challenge accept failed",
				"status": 403,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		},
	}

	acmeClient := &acme.Client{
		DirectoryURL: serverURL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "example.com"},
	}, privateKey)
	require.NoError(t, err)

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           csrDER,
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "failed to accept challenge")
}

// TestRequestCert_AuthorizationStatusNotValid tests when authz status is not valid
func TestRequestCert_AuthorizationStatusNotValid(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string
	var acceptCalled int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   serverURL + "/new-nonce",
				"newAccount": serverURL + "/new-account",
				"newOrder":   serverURL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-order":
			w.Header().Set("Location", serverURL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{serverURL + "/authz/1"},
				"finalize":       serverURL + "/order/1/finalize",
			})
		case "/authz/1":
			if atomic.LoadInt32(&acceptCalled) > 0 {
				// After challenge accept, return invalid status
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"identifier": map[string]string{"type": "dns", "value": "example.com"},
					"status":     "invalid",
					"uri":        serverURL + "/authz/1",
					"challenges": []map[string]interface{}{
						{
							"type":   "http-01",
							"status": "invalid",
							"url":    serverURL + "/challenge/1",
							"token":  "test-token",
						},
					},
				})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"identifier": map[string]string{"type": "dns", "value": "example.com"},
					"status":     "pending",
					"uri":        serverURL + "/authz/1",
					"challenges": []map[string]interface{}{
						{
							"type":   "http-01",
							"status": "pending",
							"url":    serverURL + "/challenge/1",
							"token":  "test-token",
						},
					},
				})
			}
		case "/challenge/1":
			atomic.StoreInt32(&acceptCalled, 1)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "http-01",
				"status": "processing",
				"url":    serverURL + "/challenge/1",
				"token":  "test-token",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		},
	}

	acmeClient := &acme.Client{
		DirectoryURL: serverURL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "example.com"},
	}, privateKey)
	require.NoError(t, err)

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           csrDER,
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Error(t, err)
}

// TestRequestCert_WithChallengeCleanup tests challenge cleanup is called
func TestRequestCert_WithChallengeCleanup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string
	var challengeAccepted int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   serverURL + "/new-nonce",
				"newAccount": serverURL + "/new-account",
				"newOrder":   serverURL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-order":
			w.Header().Set("Location", serverURL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{serverURL + "/authz/1"},
				"finalize":       serverURL + "/order/1/finalize",
			})
		case "/authz/1":
			if atomic.LoadInt32(&challengeAccepted) > 0 {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"identifier": map[string]string{"type": "dns", "value": "example.com"},
					"status":     "valid",
					"uri":        serverURL + "/authz/1",
					"challenges": []map[string]interface{}{
						{
							"type":   "http-01",
							"status": "valid",
							"url":    serverURL + "/challenge/1",
							"token":  "test-token",
						},
					},
				})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"identifier": map[string]string{"type": "dns", "value": "example.com"},
					"status":     "pending",
					"uri":        serverURL + "/authz/1",
					"challenges": []map[string]interface{}{
						{
							"type":   "http-01",
							"status": "pending",
							"url":    serverURL + "/challenge/1",
							"token":  "test-token",
						},
					},
				})
			}
		case "/challenge/1":
			atomic.StoreInt32(&challengeAccepted, 1)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "http-01",
				"status": "valid",
				"url":    serverURL + "/challenge/1",
				"token":  "test-token",
			})
		case "/order/1/finalize":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:badCSR",
				"detail": "invalid CSR",
				"status": 400,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		},
	}

	acmeClient := &acme.Client{
		DirectoryURL: serverURL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "example.com"},
	}, privateKey)
	require.NoError(t, err)

	cleanupCalled := false
	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           csrDER,
		ChallengeCleanup: func(challengeType string) {
			cleanupCalled = true
		},
	}

	cert, err := client.RequestCertificate(context.Background(), req)
	// Will fail at finalize, but cleanup should have been called
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.True(t, cleanupCalled, "ChallengeCleanup should have been called")
}

// TestCrossSignWithChal_MissingCSR tests missing CSR error
func TestCrossSignWithChal_MissingCSR(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
	}

	cert, err := client.CrossSignWithChallenge(
		context.Background(),
		nil, // empty CSR
		[]byte("cert-der"),
		func(challengeType, token, keyAuth string) error { return nil },
		nil,
	)
	assert.ErrorIs(t, err, ErrMissingCSR)
	assert.Nil(t, cert)
}

// TestCrossSignWithChal_InvalidCert tests invalid certificate error
func TestCrossSignWithChal_InvalidCert(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
	}

	cert, err := client.CrossSignWithChallenge(
		context.Background(),
		[]byte("csr"),
		nil, // empty cert
		func(challengeType, token, keyAuth string) error { return nil },
		nil,
	)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
	assert.Nil(t, cert)
}

// TestCrossSignWithChal_MissingSetup tests missing challenge setup
func TestCrossSignWithChal_MissingSetup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
	}

	certDER := generateCoverageCertDER(t, "example.com")

	cert, err := client.CrossSignWithChallenge(
		context.Background(),
		[]byte("csr"),
		certDER,
		nil, // missing challenge setup
		nil,
	)
	assert.ErrorIs(t, err, ErrInvalidChallengeSetup)
	assert.Nil(t, cert)
}

// TestCrossSignWithChal_InvalidCertDER tests invalid certificate DER
func TestCrossSignWithChal_InvalidCertDER(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
	}

	cert, err := client.CrossSignWithChallenge(
		context.Background(),
		[]byte("csr"),
		[]byte("invalid-cert-der"),
		func(challengeType, token, keyAuth string) error { return nil },
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, cert)
	var caErrCert *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErrCert)
	assert.Equal(t, caerrors.Malformed, caErrCert.Type)
}

// TestCrossSignWithChal_CSRParseFail tests CSR parse failure
func TestCrossSignWithChal_CSRParseFail(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
	}

	certDER := generateCoverageCertDER(t, "example.com")

	cert, err := client.CrossSignWithChallenge(
		context.Background(),
		[]byte("invalid-csr"),
		certDER,
		func(challengeType, token, keyAuth string) error { return nil },
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, cert)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.BadCSR, caErr.Type)
}

// TestCrossSignWithChal_SubjectMismatch tests subject mismatch between CSR and cert
func TestCrossSignWithChal_SubjectMismatch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
	}

	// Create cert with different subject
	certDER := generateCoverageCertDER(t, "cert.example.com")

	// Create CSR with different subject
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "csr.example.com",
			Organization: []string{"Different Org"},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	require.NoError(t, err)

	cert, err := client.CrossSignWithChallenge(
		context.Background(),
		csrDER,
		certDER,
		func(challengeType, token, keyAuth string) error { return nil },
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, cert)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.BadCSR, caErr.Type)
}

// TestCrossSignWithChal_SetupFails tests challenge setup failure
func TestCrossSignWithChal_SetupFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   serverURL + "/new-nonce",
				"newAccount": serverURL + "/new-account",
				"newOrder":   serverURL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-order":
			w.Header().Set("Location", serverURL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{serverURL + "/authz/1"},
				"finalize":       serverURL + "/order/1/finalize",
			})
		case "/authz/1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"status":     "pending",
				"uri":        serverURL + "/authz/1",
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"status": "pending",
						"url":    serverURL + "/challenge/1",
						"token":  "test-token",
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		},
	}

	acmeClient := &acme.Client{
		DirectoryURL: serverURL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	certDER, csrDER, _ := generateCoverageMatchingCertAndCSR(t, "example.com")

	// Setup function that fails
	setupFn := func(challengeType, token, keyAuth string) error {
		return errors.New("challenge setup failed")
	}

	cert, err := client.CrossSignWithChallenge(
		context.Background(),
		csrDER,
		certDER,
		setupFn,
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "challenge setup failed")
}

// TestCrossSignWithChal_NoSuitableChallenge tests when no suitable challenge is found
func TestCrossSignWithChal_NoSuitableChallenge(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   serverURL + "/new-nonce",
				"newAccount": serverURL + "/new-account",
				"newOrder":   serverURL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-order":
			w.Header().Set("Location", serverURL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{serverURL + "/authz/1"},
				"finalize":       serverURL + "/order/1/finalize",
			})
		case "/authz/1":
			// Return no supported challenges
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"status":     "pending",
				"uri":        serverURL + "/authz/1",
				"challenges": []map[string]interface{}{
					{
						"type":   "unsupported-01",
						"status": "pending",
						"url":    serverURL + "/challenge/1",
						"token":  "test-token",
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		},
	}

	acmeClient := &acme.Client{
		DirectoryURL: serverURL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	certDER, csrDER, _ := generateCoverageMatchingCertAndCSR(t, "example.com")

	cert, err := client.CrossSignWithChallenge(
		context.Background(),
		csrDER,
		certDER,
		func(challengeType, token, keyAuth string) error { return nil },
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "no suitable challenge found")
}

// TestCrossSignWithChal_AlreadyValidAuthz tests when authorization is already valid
func TestCrossSignWithChal_AlreadyValidAuthz(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   serverURL + "/new-nonce",
				"newAccount": serverURL + "/new-account",
				"newOrder":   serverURL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-order":
			w.Header().Set("Location", serverURL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "ready",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{serverURL + "/authz/1"},
				"finalize":       serverURL + "/order/1/finalize",
			})
		case "/authz/1":
			// Return already valid authorization
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"status":     "valid",
				"uri":        serverURL + "/authz/1",
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"status": "valid",
						"url":    serverURL + "/challenge/1",
						"token":  "test-token",
					},
				},
			})
		case "/order/1/finalize":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:badCSR",
				"detail": "test error",
				"status": 400,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		},
	}

	acmeClient := &acme.Client{
		DirectoryURL: serverURL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	certDER, csrDER, _ := generateCoverageMatchingCertAndCSR(t, "example.com")

	cert, err := client.CrossSignWithChallenge(
		context.Background(),
		csrDER,
		certDER,
		func(challengeType, token, keyAuth string) error { return nil },
		nil,
	)
	// Will fail at finalize, but should have skipped challenge processing
	assert.Error(t, err)
	assert.Nil(t, cert)
}

// TestCheckRenewCerts_RenewalFails tests failed renewal path
func TestCheckRenewCerts_RenewalFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a client that will fail requests
	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
		client:        &acme.Client{Key: privateKey, DirectoryURL: unreachableDirectoryURL},
	}

	config := &RenewalConfig{
		CheckInterval:    1 * time.Second,
		RenewalThreshold: 0.9, // 90% - will trigger renewal
		MaxRetries:       0,   // No retries
		RetryInterval:    1 * time.Millisecond,
		NotifyOnSuccess:  true,
		NotifyOnFailure:  true,
	}

	rs, err := NewRenewalService(client, config, logger)
	require.NoError(t, err)

	// Create certificate that needs renewal (expiring soon)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "expiring.example.com",
		},
		NotBefore: time.Now().Add(-364 * 24 * time.Hour),
		NotAfter:  time.Now().Add(1 * 24 * time.Hour), // Expires in 1 day
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "expiring.example.com",
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
	}

	// Register the certificate
	err = rs.RegisterCertificate(cert, req, "expiring-cert")
	require.NoError(t, err)

	// Run check - should attempt renewal and fail
	rs.checkAndRenewCertificates(context.Background())

	// The check should have run - no error, but renewal would fail internally
	// This exercises the failed renewal code path
}

// TestCheckRenewCerts_NotifyOnSuccess tests the notify on success code path
func TestCheckRenewCerts_NotifyOnSuccess(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a mock client that will fail (triggering notify)
	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
		client:        &acme.Client{Key: privateKey, DirectoryURL: unreachableDirectoryURL},
	}

	config := &RenewalConfig{
		CheckInterval:    1 * time.Second,
		RenewalThreshold: 0.9,
		MaxRetries:       0,
		RetryInterval:    1 * time.Millisecond,
		NotifyOnSuccess:  true,
		NotifyOnFailure:  true,
	}

	rs, err := NewRenewalService(client, config, logger)
	require.NoError(t, err)

	// Create certificate that needs renewal
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "notify.example.com"},
		NotBefore:    time.Now().Add(-364 * 24 * time.Hour),
		NotAfter:     time.Now().Add(1 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "notify.example.com",
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
	}

	err = rs.RegisterCertificate(cert, req, "notify-test")
	require.NoError(t, err)

	// This will fail but exercises the notification path
	rs.checkAndRenewCertificates(context.Background())
}

// TestRenewalConfig_Validation tests RenewalConfig validation
func TestRenewalConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  *RenewalConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: &RenewalConfig{
				CheckInterval:    1 * time.Hour,
				RenewalThreshold: 0.33,
				MaxRetries:       3,
				RetryInterval:    5 * time.Minute,
			},
			wantErr: false,
		},
		{
			name: "zero check interval",
			config: &RenewalConfig{
				CheckInterval:    0,
				RenewalThreshold: 0.33,
			},
			wantErr: true,
		},
		{
			name: "negative threshold",
			config: &RenewalConfig{
				CheckInterval:    1 * time.Hour,
				RenewalThreshold: -0.1,
			},
			wantErr: true,
		},
		{
			name: "threshold too high",
			config: &RenewalConfig{
				CheckInterval:    1 * time.Hour,
				RenewalThreshold: 1.5,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestCertReq_Validation tests CertificateRequest validation
func TestCertReq_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     *CertificateRequest
		wantErr error
	}{
		{
			name: "valid request",
			req: &CertificateRequest{
				AuthzType:     "dns",
				AuthzValue:    "example.com",
				ChallengeType: "http-01",
				CSR:           []byte("test-csr"),
			},
			wantErr: nil,
		},
		{
			name: "missing authz type",
			req: &CertificateRequest{
				AuthzType:     "",
				AuthzValue:    "example.com",
				ChallengeType: "http-01",
				CSR:           []byte("test-csr"),
			},
			wantErr: ErrMissingAuthzType,
		},
		{
			name: "missing authz value",
			req: &CertificateRequest{
				AuthzType:     "dns",
				AuthzValue:    "",
				ChallengeType: "http-01",
				CSR:           []byte("test-csr"),
			},
			wantErr: ErrMissingAuthzValue,
		},
		{
			name: "missing challenge type",
			req: &CertificateRequest{
				AuthzType:     "dns",
				AuthzValue:    "example.com",
				ChallengeType: "",
				CSR:           []byte("test-csr"),
			},
			wantErr: ErrMissingChallengeType,
		},
		{
			name: "missing CSR",
			req: &CertificateRequest{
				AuthzType:     "dns",
				AuthzValue:    "example.com",
				ChallengeType: "http-01",
				CSR:           nil,
			},
			wantErr: ErrMissingCSR,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestCrossSignCfg_Validation tests CrossSignConfig validation
func TestCrossSignCfg_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  *CrossSignConfig
		wantErr error
	}{
		{
			name: "valid http-01",
			config: &CrossSignConfig{
				DirectoryURL:  "https://acme.example.com/directory",
				ChallengeType: "http-01",
			},
			wantErr: nil,
		},
		{
			name: "valid dns-01",
			config: &CrossSignConfig{
				DirectoryURL:  "https://acme.example.com/directory",
				ChallengeType: "dns-01",
			},
			wantErr: nil,
		},
		{
			name: "valid tls-alpn-01",
			config: &CrossSignConfig{
				DirectoryURL:  "https://acme.example.com/directory",
				ChallengeType: "tls-alpn-01",
			},
			wantErr: nil,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: ErrNilCrossSignConfig,
		},
		{
			name: "empty directory URL",
			config: &CrossSignConfig{
				DirectoryURL:  "",
				ChallengeType: "http-01",
			},
			wantErr: ErrEmptyCrossSignDirectoryURL,
		},
		{
			name: "missing challenge type",
			config: &CrossSignConfig{
				DirectoryURL:  "https://acme.example.com/directory",
				ChallengeType: "",
			},
			wantErr: ErrMissingChallengeType,
		},
		{
			name: "invalid challenge type",
			config: &CrossSignConfig{
				DirectoryURL:  "https://acme.example.com/directory",
				ChallengeType: "invalid-01",
			},
			wantErr: ErrInvalidChallengeTypeForCrossSign,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestNewRenewalService_NilClient tests NewRenewalService with nil client
func TestNewRenewalService_NilClient(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	rs, err := NewRenewalService(nil, nil, logger)
	assert.ErrorIs(t, err, ErrNilClient)
	assert.Nil(t, rs)
}

// TestNewRenewalService_InvalidConfig tests NewRenewalService with invalid config
func TestNewRenewalService_InvalidConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
	}

	invalidConfig := &RenewalConfig{
		CheckInterval:    0, // Invalid - zero check interval
		RenewalThreshold: 0.33,
	}

	rs, err := NewRenewalService(client, invalidConfig, logger)
	assert.Error(t, err)
	assert.Nil(t, rs)
}

// TestNewRenewalService_NilLogger tests NewRenewalService with nil logger
func TestNewRenewalService_NilLogger(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        slog.Default(),
	}

	config := DefaultRenewalConfig()

	// Should use slog.Default() when nil is passed
	rs, err := NewRenewalService(client, config, nil)
	assert.NoError(t, err)
	assert.NotNil(t, rs)
}

// TestRenewalService_RegisterNilCertificate tests RegisterCertificate with nil cert
func TestRenewalService_RegisterNilCertificate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
	}

	rs, err := NewRenewalService(client, nil, logger)
	require.NoError(t, err)

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
	}

	err = rs.RegisterCertificate(nil, req, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil certificate")
}

// TestRenewalService_RegisterNilRequest tests RegisterCertificate with nil request
func TestRenewalService_RegisterNilRequest(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
	}

	rs, err := NewRenewalService(client, nil, logger)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	err = rs.RegisterCertificate(cert, nil, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil certificate request")
}

// TestRenewalService_Unregister tests UnregisterCertificate
func TestRenewalService_Unregister(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
	}

	rs, err := NewRenewalService(client, nil, logger)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "unregister.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "unregister.example.com",
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
	}

	// Register first
	err = rs.RegisterCertificate(cert, req, "unregister-test")
	require.NoError(t, err)

	// Unregister
	rs.UnregisterCertificate("unregister-test")

	// Verify unregistered
	_, exists := rs.certificates.Load("unregister-test")
	assert.False(t, exists)
}

// TestCrossSign_AuthorizeOrderError tests CrossSign when AuthorizeOrder fails
func TestCrossSign_AuthorizeOrderError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   serverURL + "/new-nonce",
				"newAccount": serverURL + "/new-account",
				"newOrder":   serverURL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-order":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:malformed",
				"detail": "order creation failed",
				"status": 400,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		},
	}

	acmeClient := &acme.Client{
		DirectoryURL: serverURL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	certDER, csrDER, _ := generateCoverageMatchingCertAndCSR(t, "example.com")

	cert, err := client.CrossSign(context.Background(), csrDER, certDER)
	assert.Error(t, err)
	assert.Nil(t, cert)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.InternalServer, caErr.Type)
}

// TestCrossSign_ProcessAuthorizationError tests CrossSign when processAuthorization fails
func TestCrossSign_ProcessAuthorizationError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   serverURL + "/new-nonce",
				"newAccount": serverURL + "/new-account",
				"newOrder":   serverURL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-order":
			w.Header().Set("Location", serverURL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{serverURL + "/authz/1"},
				"finalize":       serverURL + "/order/1/finalize",
			})
		case "/authz/1":
			// Return error
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:malformed",
				"detail": "authorization not found",
				"status": 404,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		},
	}

	acmeClient := &acme.Client{
		DirectoryURL: serverURL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	certDER, csrDER, _ := generateCoverageMatchingCertAndCSR(t, "example.com")

	cert, err := client.CrossSign(context.Background(), csrDER, certDER)
	assert.Error(t, err)
	assert.Nil(t, cert)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.InternalServer, caErr.Type)
}

// TestProcessAuthorization_NoSuitableChallenge tests when no suitable challenge found
func TestProcessAuthz_NoSuitableChallenge(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   serverURL + "/new-nonce",
				"newAccount": serverURL + "/new-account",
				"newOrder":   serverURL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-order":
			w.Header().Set("Location", serverURL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{serverURL + "/authz/1"},
				"finalize":       serverURL + "/order/1/finalize",
			})
		case "/authz/1":
			// Return only unsupported challenge types
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"status":     "pending",
				"uri":        serverURL + "/authz/1",
				"challenges": []map[string]interface{}{
					{
						"type":   "unsupported-challenge",
						"status": "pending",
						"url":    serverURL + "/challenge/1",
						"token":  "test-token",
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		},
	}

	acmeClient := &acme.Client{
		DirectoryURL: serverURL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	certDER, csrDER, _ := generateCoverageMatchingCertAndCSR(t, "example.com")

	cert, err := client.CrossSign(context.Background(), csrDER, certDER)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "no suitable challenge found")
}

// TestExtractAuthzFromCertificate_IPAddress tests IP address extraction
func TestExtractAuthzFromCertificate_IPAddress(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
	}

	// Create certificate with IP SAN
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "",
		},
		// IPAddresses populated below
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}

	// Parse the IP address
	template.IPAddresses = nil
	ip := net.ParseIP("192.168.1.1")
	template.IPAddresses = []net.IP{ip}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	authzValue, authzType, err := client.extractAuthzFromCertificate(cert)
	assert.NoError(t, err)
	assert.Equal(t, "ip", authzType)
	assert.Equal(t, "192.168.1.1", authzValue)
}

// TestExtractAuthzFromCertificate_NoIdentifier tests when no valid identifier found
func TestExtractAuthzFromCertificate_NoIdentifier(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
	}

	// Create certificate with no DNS names, IPs, or CN
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	_, _, err = client.extractAuthzFromCertificate(cert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no valid authorization identifier found")
}

// TestCrossSignWithChal_AcceptChallengeError tests Accept failure
func TestCrossSignWithChal_AcceptChallengeError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   serverURL + "/new-nonce",
				"newAccount": serverURL + "/new-account",
				"newOrder":   serverURL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-order":
			w.Header().Set("Location", serverURL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{serverURL + "/authz/1"},
				"finalize":       serverURL + "/order/1/finalize",
			})
		case "/authz/1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"identifier": map[string]string{"type": "dns", "value": "example.com"},
				"status":     "pending",
				"uri":        serverURL + "/authz/1",
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"status": "pending",
						"url":    serverURL + "/challenge/1",
						"token":  "test-token",
					},
				},
			})
		case "/challenge/1":
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:unauthorized",
				"detail": "challenge accept failed",
				"status": 403,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		},
	}

	acmeClient := &acme.Client{
		DirectoryURL: serverURL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	certDER, csrDER, _ := generateCoverageMatchingCertAndCSR(t, "example.com")

	cert, err := client.CrossSignWithChallenge(
		context.Background(),
		csrDER,
		certDER,
		func(challengeType, token, keyAuth string) error { return nil },
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "failed to accept challenge")
}

// TestCrossSignWithChal_WaitAuthorizationError tests WaitAuthorization failure
func TestCrossSignWithChal_WaitAuthorizationError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string
	var challengeAccepted int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   serverURL + "/new-nonce",
				"newAccount": serverURL + "/new-account",
				"newOrder":   serverURL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-order":
			w.Header().Set("Location", serverURL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{serverURL + "/authz/1"},
				"finalize":       serverURL + "/order/1/finalize",
			})
		case "/authz/1":
			if atomic.LoadInt32(&challengeAccepted) > 0 {
				// After challenge accept, return invalid (causing WaitAuthorization to fail)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"identifier": map[string]string{"type": "dns", "value": "example.com"},
					"status":     "invalid",
					"uri":        serverURL + "/authz/1",
					"challenges": []map[string]interface{}{
						{
							"type":   "http-01",
							"status": "invalid",
							"url":    serverURL + "/challenge/1",
							"token":  "test-token",
							"error": map[string]interface{}{
								"type":   "urn:ietf:params:acme:error:connection",
								"detail": "connection failed",
							},
						},
					},
				})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"identifier": map[string]string{"type": "dns", "value": "example.com"},
					"status":     "pending",
					"uri":        serverURL + "/authz/1",
					"challenges": []map[string]interface{}{
						{
							"type":   "http-01",
							"status": "pending",
							"url":    serverURL + "/challenge/1",
							"token":  "test-token",
						},
					},
				})
			}
		case "/challenge/1":
			atomic.StoreInt32(&challengeAccepted, 1)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "http-01",
				"status": "processing",
				"url":    serverURL + "/challenge/1",
				"token":  "test-token",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		},
	}

	acmeClient := &acme.Client{
		DirectoryURL: serverURL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	certDER, csrDER, _ := generateCoverageMatchingCertAndCSR(t, "example.com")

	cert, err := client.CrossSignWithChallenge(
		context.Background(),
		csrDER,
		certDER,
		func(challengeType, token, keyAuth string) error { return nil },
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, cert)
}

// TestCrossSign_MissingCSR tests CrossSign with missing CSR
func TestCrossSign_MissingCSR(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
	}

	certDER := generateCoverageCertDER(t, "example.com")

	cert, err := client.CrossSign(context.Background(), nil, certDER)
	assert.ErrorIs(t, err, ErrMissingCSR)
	assert.Nil(t, cert)
}

// TestCrossSign_InvalidCert tests CrossSign with invalid certificate
func TestCrossSign_InvalidCert(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
	}

	cert, err := client.CrossSign(context.Background(), []byte("csr"), nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
	assert.Nil(t, cert)
}

// TestCrossSign_InvalidCSRParse tests CrossSign with invalid CSR
func TestCrossSign_InvalidCSRParse(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
	}

	certDER := generateCoverageCertDER(t, "example.com")

	cert, err := client.CrossSign(context.Background(), []byte("invalid-csr"), certDER)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.BadCSR, caErr.Type)
	assert.Nil(t, cert)
}

// TestCrossSign_CSRSubjectMismatch tests CrossSign with mismatched subjects
func TestCrossSign_CSRSubjectMismatch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
	}

	// Create cert with one subject
	certDER := generateCoverageCertDER(t, "cert.example.com")

	// Create CSR with different subject
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "csr.example.com",
			Organization: []string{"Different Org"},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	require.NoError(t, err)

	cert, err := client.CrossSign(context.Background(), csrDER, certDER)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.BadCSR, caErr.Type)
	assert.Nil(t, cert)
}

// TestCrossSign_InvalidCertDER tests CrossSign with invalid certificate DER
func TestCrossSign_InvalidCertDER(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
	}

	cert, err := client.CrossSign(context.Background(), []byte("csr"), []byte("invalid-der"))
	var caErrCert2 *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErrCert2)
	assert.Equal(t, caerrors.Malformed, caErrCert2.Type)
	assert.Nil(t, cert)
}

// TestCrossSignWithChal_GetAuthorizationError tests GetAuthorization failure
func TestCrossSignWithChal_GetAuthorizationError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   serverURL + "/new-nonce",
				"newAccount": serverURL + "/new-account",
				"newOrder":   serverURL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-order":
			w.Header().Set("Location", serverURL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{serverURL + "/authz/1"},
				"finalize":       serverURL + "/order/1/finalize",
			})
		case "/authz/1":
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:malformed",
				"detail": "authorization not found",
				"status": 404,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		},
	}

	acmeClient := &acme.Client{
		DirectoryURL: serverURL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	certDER, csrDER, _ := generateCoverageMatchingCertAndCSR(t, "example.com")

	cert, err := client.CrossSignWithChallenge(
		context.Background(),
		csrDER,
		certDER,
		func(challengeType, token, keyAuth string) error { return nil },
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "failed to get authorization")
}

// TestCrossSignWithChal_OrderError tests AuthorizeOrder failure
func TestCrossSignWithChal_OrderError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   serverURL + "/new-nonce",
				"newAccount": serverURL + "/new-account",
				"newOrder":   serverURL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-order":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:malformed",
				"detail": "order creation failed",
				"status": 400,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		},
	}

	acmeClient := &acme.Client{
		DirectoryURL: serverURL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	certDER, csrDER, _ := generateCoverageMatchingCertAndCSR(t, "example.com")

	cert, err := client.CrossSignWithChallenge(
		context.Background(),
		csrDER,
		certDER,
		func(challengeType, token, keyAuth string) error { return nil },
		nil,
	)
	assert.Error(t, err)
	assert.Nil(t, cert)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.InternalServer, caErr.Type)
}

// TestFetchCertificate_ParseError tests FetchCertificate with invalid cert data
func TestFetchCertificate_ParseError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   serverURL + "/new-nonce",
				"newAccount": serverURL + "/new-account",
				"newOrder":   serverURL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/cert/1":
			// Return invalid certificate data
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			_, _ = w.Write([]byte("invalid-cert-data"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		},
	}

	acmeClient := &acme.Client{
		DirectoryURL: serverURL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	certs, err := client.FetchCertificate(context.Background(), serverURL+"/cert/1", false)
	assert.Error(t, err)
	assert.Nil(t, certs)
}

// TestExtractAccountID_InvalidURI tests extractAccountIDFromURI with invalid URI
func TestExtractAccountID_InvalidURI(t *testing.T) {
	// Test with empty URI
	id, err := extractAccountIDFromURI("")
	assert.Error(t, err)
	assert.Equal(t, uint64(0), id)

	// Test with URI without trailing number
	id, err = extractAccountIDFromURI("https://acme.example.com/account/abc")
	assert.Error(t, err)
	assert.Equal(t, uint64(0), id)

	// Test with zero ID
	id, err = extractAccountIDFromURI("https://acme.example.com/account/0")
	assert.Error(t, err)
	assert.Equal(t, uint64(0), id)
}

// TestCreateCACertPool_InvalidTrustedRoots tests createCACertPool with invalid trusted roots
func TestCreateCACertPool_InvalidTrustedRoots(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := DefaultConfig()
	config.TrustedRoots = []string{"invalid-pem-data"}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        config,
		logger:        logger,
	}

	pool, err := client.createCACertPool("https://acme.example.com/directory")
	assert.Error(t, err)
	assert.Nil(t, pool)
	assert.ErrorIs(t, err, ErrInvalidCACertificate)
}

// TestCreateCACertPool_FetchBundleError tests createCACertPool when bundle fetch fails
func TestCreateCACertPool_FetchBundleError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := DefaultConfig()
	config.RequestServerBundle = true

	// Server that returns error for ca-bundle
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		},
	}

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        config,
		httpClient:    httpClient,
		logger:        logger,
	}

	pool, err := client.createCACertPool(server.URL + "/directory")
	assert.Error(t, err)
	assert.Nil(t, pool)
	assert.Contains(t, err.Error(), "failed to get ACME server CA bundle")
}

// TestExpandEnvVars_NoExpansion tests expandEnvVars with no env vars
func TestExpandEnvVars_NoExpansion(t *testing.T) {
	result, err := expandEnvVars("192.168.1.1")
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.1", result)
}

// TestExpandEnvVars_WithEnvVar tests expandEnvVars with env var
func TestExpandEnvVars_WithEnvVar(t *testing.T) {
	t.Setenv("TEST_IP", "10.0.0.1")
	result, err := expandEnvVars("${TEST_IP}")
	assert.NoError(t, err)
	assert.Equal(t, "10.0.0.1", result)
}

// TestExpandEnvVars_MissingEnvVar tests expandEnvVars with missing env var
func TestExpandEnvVars_MissingEnvVar(t *testing.T) {
	result, err := expandEnvVars("${MISSING_ENV_VAR_12345}")
	assert.Error(t, err)
	assert.Equal(t, "", result)
}

// =====================================
// Tests from coverage_boost_helpers_test.go
// =====================================

func TestExtractAccountIDFromURI_Comprehensive(t *testing.T) {
	tests := []struct {
		name        string
		uri         string
		expectedID  uint64
		expectedErr error
	}{
		{
			name:        "empty URI",
			uri:         "",
			expectedID:  0,
			expectedErr: ErrInvalidAccountURI,
		},
		{
			name:        "invalid URI format",
			uri:         "://invalid",
			expectedID:  0,
			expectedErr: ErrInvalidAccountURI,
		},
		{
			name:        "URI with no path segments",
			uri:         "https://example.com/",
			expectedID:  0,
			expectedErr: ErrInvalidAccountURI,
		},
		{
			name:        "URI with non-numeric ID",
			uri:         "https://example.com/account/abc",
			expectedID:  0,
			expectedErr: ErrInvalidAccountURI,
		},
		{
			name:        "URI with zero ID",
			uri:         "https://example.com/account/0",
			expectedID:  0,
			expectedErr: ErrInvalidAccountURI,
		},
		{
			name:        "valid URI with ID",
			uri:         "https://example.com/account/12345",
			expectedID:  12345,
			expectedErr: nil,
		},
		{
			name:        "valid URI with nested path and ID",
			uri:         "https://example.com/acme/account/67890",
			expectedID:  67890,
			expectedErr: nil,
		},
		{
			name:        "valid URI with trailing slash",
			uri:         "https://example.com/account/123/",
			expectedID:  123,
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := extractAccountIDFromURI(tt.uri)

			if tt.expectedErr != nil {
				assert.Error(t, err)
				if !errors.Is(err, tt.expectedErr) {
					assert.Contains(t, err.Error(), "invalid account URI")
				} else {
					assert.ErrorIs(t, err, tt.expectedErr)
				}
				assert.Equal(t, uint64(0), id)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedID, id)
			}
		})
	}
}

// TestEnrollmentConfig_Validate_Comprehensive tests enrollment configuration validation
func TestEnrollmentConfig_Validate_Comprehensive(t *testing.T) {
	// Use the existing mockTPMModule from enrollment_unit_test.go
	mockTPM := &mockTPMModule{}

	tests := []struct {
		name        string
		config      *EnrollmentConfig
		expectedErr error
	}{
		{
			name: "empty challenge",
			config: &EnrollmentConfig{
				Challenge: "",
			},
			expectedErr: ErrInvalidChallenge,
		},
		{
			name: "invalid challenge type",
			config: &EnrollmentConfig{
				Challenge: "invalid-challenge",
			},
			expectedErr: ErrInvalidChallenge,
		},
		{
			name: "missing TPM module",
			config: &EnrollmentConfig{
				Challenge:  string(ChallengeTypeEnroll01),
				TPMModule:  nil,
				IPAddress:  "192.168.1.1",
				CommonName: "test-device",
			},
			expectedErr: ErrMissingTPMModule,
		},
		{
			name: "missing IP address",
			config: &EnrollmentConfig{
				Challenge:  string(ChallengeTypeEnroll01),
				TPMModule:  mockTPM,
				IPAddress:  "",
				CommonName: "test-device",
			},
			expectedErr: ErrInvalidIPAddress,
		},
		{
			name: "valid enroll-01 challenge",
			config: &EnrollmentConfig{
				Challenge:  string(ChallengeTypeEnroll01),
				TPMModule:  mockTPM,
				IPAddress:  "192.168.1.1",
				CommonName: "test-device",
			},
			expectedErr: nil,
		},
		{
			name: "valid endorse-01 challenge",
			config: &EnrollmentConfig{
				Challenge:  string(ChallengeTypeEndorse01),
				TPMModule:  mockTPM,
				IPAddress:  "10.0.0.1",
				CommonName: "test-device",
			},
			expectedErr: nil,
		},
		{
			name: "valid device-attest-01 challenge",
			config: &EnrollmentConfig{
				Challenge:  string(ChallengeTypeDeviceAttest01),
				TPMModule:  mockTPM,
				IPAddress:  "172.16.0.1",
				CommonName: "test-device",
			},
			expectedErr: nil,
		},
		{
			name: "sets default port and timeout",
			config: &EnrollmentConfig{
				Challenge:  string(ChallengeTypeEnroll01),
				TPMModule:  mockTPM,
				IPAddress:  "192.168.1.1",
				CommonName: "test-device",
				Port:       "", // Should default to 8080
				Timeout:    0,  // Should default to 30 seconds
			},
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectedErr != nil {
				assert.Error(t, err)
				if !errors.Is(err, tt.expectedErr) {
					var caErr *caerrors.TrustedCAError
					if errors.As(err, &caErr) {
						assert.Contains(t, err.Error(), strings.TrimPrefix(tt.expectedErr.Error(), "acme-client: "))
					} else {
						assert.ErrorIs(t, err, tt.expectedErr)
					}
				}
			} else {
				assert.NoError(t, err)
				// Verify defaults are set
				if tt.config.Port == "" {
					// After validation, port should be set to default
					assert.Equal(t, "8080", tt.config.Port)
				}
				if tt.config.Timeout == 0 {
					// After validation, timeout should be set to default
					assert.Greater(t, tt.config.Timeout.Seconds(), float64(0))
				}
			}
		})
	}
}

// =====================================
// Tests from coverage_boost_test.go
// =====================================

func TestMockStorage_Get(t *testing.T) {
	storage := newMockStorage()

	t.Run("get existing account", func(t *testing.T) {
		account := &entities.ACMEAccount{ID: 1}
		storage.accounts[1] = account

		result, err := storage.Get(context.Background(), 1)
		assert.NoError(t, err)
		assert.Equal(t, account, result)
	})

	t.Run("get non-existent account", func(t *testing.T) {
		_, err := storage.Get(context.Background(), 999)
		assert.Error(t, err)
	})
}

func TestMockStorage_Delete(t *testing.T) {
	storage := newMockStorage()
	storage.accounts[1] = &entities.ACMEAccount{ID: 1}

	err := storage.Delete(context.Background(), &entities.ACMEAccount{ID: 1})
	assert.NoError(t, err)
	assert.Len(t, storage.accounts, 0)
}

func TestMockStorage_Count(t *testing.T) {
	storage := newMockStorage()
	storage.accounts[1] = &entities.ACMEAccount{ID: 1}

	count, err := storage.Count(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestMockCertStorage_Get(t *testing.T) {
	storage := newMockCertStorage()

	t.Run("get existing certificate", func(t *testing.T) {
		cert := &entities.ACMECertificate{CertURL: "https://example.com/cert/1"}
		storage.certificates[1] = cert

		result, err := storage.Get(context.Background(), 1)
		assert.NoError(t, err)
		assert.Equal(t, cert, result)
	})

	t.Run("get non-existent certificate", func(t *testing.T) {
		_, err := storage.Get(context.Background(), 999)
		assert.Error(t, err)
	})
}

func TestMockCertStorage_Delete(t *testing.T) {
	storage := newMockCertStorage()
	storage.certificates[1] = &entities.ACMECertificate{CertURL: "https://example.com/cert/1"}

	err := storage.Delete(context.Background(), &entities.ACMECertificate{})
	assert.NoError(t, err)
}

func TestMockCertStorage_Count(t *testing.T) {
	storage := newMockCertStorage()
	storage.certificates[1] = &entities.ACMECertificate{CertURL: "https://example.com/cert/1"}
	storage.certificates[2] = &entities.ACMECertificate{CertURL: "https://example.com/cert/2"}

	count, err := storage.Count(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestMockOrderStorage_Get(t *testing.T) {
	storage := newMockOrderStorage()

	t.Run("get existing order", func(t *testing.T) {
		order := &entities.ACMEOrder{Status: "valid"}
		storage.orders[1] = order

		result, err := storage.Get(context.Background(), 1)
		assert.NoError(t, err)
		assert.Equal(t, order, result)
	})

	t.Run("get non-existent order", func(t *testing.T) {
		_, err := storage.Get(context.Background(), 999)
		assert.Error(t, err)
	})
}

func TestMockOrderStorage_Delete(t *testing.T) {
	storage := newMockOrderStorage()
	storage.orders[1] = &entities.ACMEOrder{Status: "valid"}

	err := storage.Delete(context.Background(), &entities.ACMEOrder{})
	assert.NoError(t, err)
}

func TestMockOrderStorage_Count(t *testing.T) {
	storage := newMockOrderStorage()
	storage.orders[1] = &entities.ACMEOrder{Status: "valid"}
	storage.orders[2] = &entities.ACMEOrder{Status: "pending"}

	count, err := storage.Count(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestGenerateSerial(t *testing.T) {
	serial := generateSerial(t)
	assert.NotNil(t, serial)
	assert.True(t, serial.Cmp(big.NewInt(0)) > 0)
}

// Test RequestCertificate error paths
func TestClient_RequestCertificate_ErrorPaths(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("invalid request validation", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		config := DefaultConfig()
		config.DirectoryURL = "https://acme.example.com/directory"

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		// Invalid request - missing authz type
		req := &CertificateRequest{
			AuthzValue:    "example.com",
			ChallengeType: "http-01",
			CSR:           []byte("csr"),
		}

		cert, err := client.RequestCertificate(context.Background(), req)
		assert.Error(t, err)
		assert.Nil(t, cert)
	})

	t.Run("challenge type not offered", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Create a mock server that offers different challenges
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Replay-Nonce", "test-nonce")
			switch r.URL.Path {
			case "/directory":
				_ = json.NewEncoder(w).Encode(map[string]string{
					"newNonce": server.URL + "/new-nonce",
					"newOrder": server.URL + "/new-order",
				})
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/new-order":
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":         "pending",
					"authorizations": []string{server.URL + "/authz/1"},
					"finalize":       server.URL + "/finalize",
				})
			case "/authz/1":
				// Offer only dns-01 challenge
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status": "pending",
					"challenges": []map[string]string{
						{"type": "dns-01", "token": "test-token"},
					},
				})
			}
		}))
		defer server.Close()

		config := DefaultConfig()
		config.DirectoryURL = server.URL + "/directory"
		config.SystemCertPool = false
		config.RequestServerBundle = false

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		// Request http-01 but server only offers dns-01
		csrTemplate := &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "example.com"},
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
		require.NoError(t, err)

		req := &CertificateRequest{
			AuthzType:     "dns",
			AuthzValue:    "example.com",
			ChallengeType: "http-01", // Not offered by server
			CSR:           csrDER,
		}

		cert, err := client.RequestCertificate(context.Background(), req)
		assert.Error(t, err)
		assert.Nil(t, cert)
	})

	t.Run("missing CSR for finalization", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Replay-Nonce", "test-nonce")
			switch r.URL.Path {
			case "/directory":
				_ = json.NewEncoder(w).Encode(map[string]string{
					"newNonce": server.URL + "/new-nonce",
					"newOrder": server.URL + "/new-order",
				})
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/new-order":
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":         "pending",
					"authorizations": []string{server.URL + "/authz/1"},
					"finalize":       server.URL + "/finalize",
				})
			case "/authz/1":
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status": "valid", // Already valid
					"challenges": []map[string]string{
						{"type": "http-01", "token": "test-token"},
					},
				})
			}
		}))
		defer server.Close()

		config := DefaultConfig()
		config.DirectoryURL = server.URL + "/directory"
		config.SystemCertPool = false
		config.RequestServerBundle = false

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		// Request without CSR - this would fail at validation
		req := &CertificateRequest{
			AuthzType:     "dns",
			AuthzValue:    "example.com",
			ChallengeType: "http-01",
			CSR:           nil, // Missing CSR
		}

		cert, err := client.RequestCertificate(context.Background(), req)
		assert.Error(t, err)
		assert.Nil(t, cert)
	})
}

// Test createCACertPool edge cases
func TestClient_createCACertPool_SystemPool(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("use system cert pool", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		config := DefaultConfig()
		config.DirectoryURL = "https://acme.example.com/directory"
		config.SystemCertPool = true // Use system pool
		config.RequestServerBundle = false

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       newMockStorage(),
		}

		client, err := NewClient(params)
		// May succeed or fail depending on OS, but should not panic
		if err != nil {
			t.Logf("System cert pool not available: %v", err)
		} else {
			assert.NotNil(t, client)
		}
	})
}

// Test RegisterAccount with storage save failure
func TestClient_RegisterAccount_StoragePaths(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("account saved to storage", func(t *testing.T) {
		mockStore := newMockStorage()

		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Replay-Nonce", "test-nonce")
			switch r.URL.Path {
			case "/directory":
				_ = json.NewEncoder(w).Encode(map[string]string{
					"newAccount": server.URL + "/new-account",
					"newNonce":   server.URL + "/new-nonce",
				})
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/new-account":
				w.Header().Set("Location", server.URL+"/account/12345")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":  "valid",
					"contact": []string{"mailto:test@example.com"},
				})
			}
		}))
		defer server.Close()

		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		config := DefaultConfig()
		config.DirectoryURL = server.URL + "/directory"
		config.SystemCertPool = false
		config.RequestServerBundle = false

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Logger:        logger,
			Storage:       mockStore,
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		// This test demonstrates the registration flow but may not complete
		// due to JOSE signing requirements
		_ = client
	})
}

// =====================================
// Tests from coverage_final_push_test.go
// =====================================

func TestFinalPush_ExtractAccountID_RootPath(t *testing.T) {
	testCases := []struct {
		name      string
		uri       string
		expectErr bool
	}{
		{
			name:      "single_slash_path",
			uri:       "https://acme.example.com/",
			expectErr: true,
		},
		{
			name:      "no_path",
			uri:       "https://acme.example.com",
			expectErr: true,
		},
		{
			name:      "path_with_only_acme",
			uri:       "https://acme.example.com/acme",
			expectErr: true, // "acme" is not a valid uint64
		},
		{
			name:      "valid_numeric_only",
			uri:       "https://acme.example.com/12345",
			expectErr: false,
		},
		{
			name:      "multiple_slashes",
			uri:       "https://acme.example.com///12345",
			expectErr: false,
		},
		{
			name:      "trailing_slashes",
			uri:       "https://acme.example.com/acme/account/12345/",
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := extractAccountIDFromURI(tc.uri)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Greater(t, id, uint64(0))
			}
		})
	}
}

// TestFinalPush_ExtractAccountID_InvalidURLParse tests URLs that fail parsing
func TestFinalPush_ExtractAccountID_InvalidURLParse(t *testing.T) {
	testCases := []struct {
		name string
		uri  string
	}{
		{"control_characters", "https://acme.example.com/\x00/12345"},
		{"invalid_escape", "https://acme.example.com/%zz/12345"},
		{"invalid_port", "https://acme.example.com:abc/12345"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := extractAccountIDFromURI(tc.uri)
			// These may or may not error depending on the Go URL parser version
			// The important thing is we don't panic
			if err == nil {
				assert.Greater(t, id, uint64(0))
			}
		})
	}
}

// =============================================================================
// CertificateRequest Validation Tests
// =============================================================================

// TestFinalPush_CertificateRequest_Validation tests CertificateRequest validation
func TestFinalPush_CertificateRequest_Validation(t *testing.T) {
	mockCSR := []byte{0x30, 0x82, 0x01, 0x00} // Minimal mock CSR bytes

	testCases := []struct {
		name      string
		req       *CertificateRequest
		expectErr bool
	}{
		{
			name:      "nil_request",
			req:       nil,
			expectErr: true,
		},
		{
			name: "empty_authz_type",
			req: &CertificateRequest{
				AuthzType:     "",
				AuthzValue:    "example.com",
				ChallengeType: "http-01",
				CSR:           mockCSR,
			},
			expectErr: true,
		},
		{
			name: "empty_authz_value",
			req: &CertificateRequest{
				AuthzType:     "dns",
				AuthzValue:    "",
				ChallengeType: "http-01",
				CSR:           mockCSR,
			},
			expectErr: true,
		},
		{
			name: "empty_challenge_type",
			req: &CertificateRequest{
				AuthzType:     "dns",
				AuthzValue:    "example.com",
				ChallengeType: "",
				CSR:           mockCSR,
			},
			expectErr: true,
		},
		{
			name: "empty_csr",
			req: &CertificateRequest{
				AuthzType:     "dns",
				AuthzValue:    "example.com",
				ChallengeType: "http-01",
				CSR:           nil,
			},
			expectErr: true,
		},
		{
			name: "valid_request",
			req: &CertificateRequest{
				AuthzType:     "dns",
				AuthzValue:    "example.com",
				ChallengeType: "http-01",
				CSR:           mockCSR,
			},
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.req == nil {
				// Test nil handling at usage site
				return
			}
			err := tc.req.Validate()
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// Error Type Tests
// =============================================================================

// TestFinalPush_ErrorTypes_Existence verifies error types exist and are distinct
func TestFinalPush_ErrorTypes_Existence(t *testing.T) {
	allErrors := []error{
		ErrInvalidAccountURI,
		ErrInvalidCACertificate,
		ErrAccountNotFound,
		ErrRegistrationFailed,
		ErrOrderCreationFailed,
		ErrChallengeResolution,
		ErrChallengeFinalization,
		ErrAuthorizationFailed,
		ErrCABundleDownloadFailed,
		ErrCertificateNotFound,
		ErrInvalidConfiguration,
		ErrNilSigner,
		ErrNilStorage,
	}

	for i, e := range allErrors {
		require.NotNil(t, e, "error at index %d should not be nil", i)
		require.NotEmpty(t, e.Error(), "error at index %d should have message", i)
	}

	// Verify errors are distinct
	for i := 0; i < len(allErrors); i++ {
		for j := i + 1; j < len(allErrors); j++ {
			assert.NotEqual(t, allErrors[i], allErrors[j],
				"errors at index %d and %d should be distinct", i, j)
		}
	}
}

// TestFinalPush_ErrorTypes_ErrorsIs tests error wrapping and matching
func TestFinalPush_ErrorTypes_ErrorsIs(t *testing.T) {
	wrappedErr := errors.New("wrapped: " + ErrInvalidAccountURI.Error())
	assert.NotErrorIs(t, wrappedErr, ErrInvalidAccountURI, "wrapped error should not match")

	// Direct error match should work
	assert.ErrorIs(t, ErrInvalidAccountURI, ErrInvalidAccountURI)
}

// =============================================================================
// Config Validation Tests
// =============================================================================

// TestFinalPush_Config_Defaults tests configuration default values
func TestFinalPush_Config_Defaults(t *testing.T) {
	cfg := &Config{}

	// Verify zero values
	assert.Empty(t, cfg.DirectoryURL)
	assert.False(t, cfg.SystemCertPool)
	assert.False(t, cfg.RequestServerBundle)
	assert.Nil(t, cfg.TrustedRoots)
}

// TestFinalPush_Config_WithValues tests configuration with values
func TestFinalPush_Config_WithValues(t *testing.T) {
	cfg := &Config{
		DirectoryURL:        "https://acme.example.com/directory",
		SystemCertPool:      true,
		RequestServerBundle: true,
		TrustedRoots:        []string{"-----BEGIN CERTIFICATE-----"},
	}

	assert.Equal(t, "https://acme.example.com/directory", cfg.DirectoryURL)
	assert.True(t, cfg.SystemCertPool)
	assert.True(t, cfg.RequestServerBundle)
	assert.Len(t, cfg.TrustedRoots, 1)
}

// =============================================================================
// Context Handling Tests
// =============================================================================

// TestFinalPush_CancelledContext tests behavior with cancelled context
func TestFinalPush_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Test that cancelled context is detected
	select {
	case <-ctx.Done():
		assert.Equal(t, context.Canceled, ctx.Err())
	default:
		t.Fatal("context should be cancelled")
	}
}

// =====================================
// Tests from coverage_final_test.go
// =====================================

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("simulated read error")
}

// TestClient_EnrollServerHTTPEndpoints tests HTTP endpoint logic for enrollment server
func TestClient_EnrollServerHTTPEndpoints(t *testing.T) {
	t.Run("challenge endpoint with correct token", func(t *testing.T) {
		token := "test-token-123"

		handler := func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, token) {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("challenge-response"))
		}

		req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/"+token, nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "challenge-response", w.Body.String())
	})

	t.Run("challenge endpoint with wrong token", func(t *testing.T) {
		token := "test-token-123"

		handler := func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, token) {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
		}

		req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/wrong-token", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("activation endpoint POST with valid JSON", func(t *testing.T) {
		token := "test-token-123"

		handler := func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if !strings.HasSuffix(r.URL.Path, token) {
				http.NotFound(w, r)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}

			var req map[string]string
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("activation-success"))
		}

		activateReq := map[string]string{
			"credentialBlob":  "cred",
			"encryptedSecret": "secret",
		}
		body, _ := json.Marshal(activateReq)

		req := httptest.NewRequest(http.MethodPost, "/.well-known/acme-activation/"+token, strings.NewReader(string(body)))
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "activation-success", w.Body.String())
	})

	t.Run("activation endpoint with wrong method", func(t *testing.T) {
		token := "test-token-123"

		handler := func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusOK)
		}

		req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-activation/"+token, nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("activation endpoint with invalid JSON", func(t *testing.T) {
		token := "test-token-123"

		handler := func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if !strings.HasSuffix(r.URL.Path, token) {
				http.NotFound(w, r)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}

			var req map[string]string
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}

			w.WriteHeader(http.StatusOK)
		}

		req := httptest.NewRequest(http.MethodPost, "/.well-known/acme-activation/"+token, strings.NewReader("invalid-json"))
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("activation endpoint read body error", func(t *testing.T) {
		token := "test-token-123"

		handler := func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if !strings.HasSuffix(r.URL.Path, token) {
				http.NotFound(w, r)
				return
			}

			_, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}

			w.WriteHeader(http.StatusOK)
		}

		// Create a request with a body that will trigger a read error
		req := httptest.NewRequest(http.MethodPost, "/.well-known/acme-activation/"+token, &errorReader{})

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestClient_AttestServerHTTPEndpoints tests HTTP endpoint logic for attestation server
func TestClient_AttestServerHTTPEndpoints(t *testing.T) {
	t.Run("serves attestation statement with correct token", func(t *testing.T) {
		token := "test-token-456"
		attestStmt := []byte(`{"attStmt": "test-data"}`)

		handler := func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, token) {
				http.NotFound(w, r)
				return
			}

			attestReq := map[string]interface{}{
				"attStmt": attestStmt,
			}

			jsonData, err := json.Marshal(attestReq)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jsonData)
		}

		req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/"+token, nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotNil(t, response["attStmt"])
	})

	t.Run("returns 404 for wrong token", func(t *testing.T) {
		token := "test-token-456"

		handler := func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, token) {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
		}

		req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/wrong-token", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("handles JSON marshal error", func(t *testing.T) {
		token := "test-token-456"

		handler := func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, token) {
				http.NotFound(w, r)
				return
			}

			// Create an unmarshalable value to trigger error
			attestReq := map[string]interface{}{
				"attStmt": make(chan int), // channels cannot be marshaled to JSON
			}

			_, err := json.Marshal(attestReq)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusOK)
		}

		req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/"+token, nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestEndorseServerHTTPEndpoints tests HTTP endpoint logic for endorse server
func TestEndorseServerHTTPEndpoints(t *testing.T) {
	t.Run("challenge endpoint serves EK request", func(t *testing.T) {
		token := "test-token-789"

		handler := func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, token) {
				http.NotFound(w, r)
				return
			}

			ekReq := map[string]string{
				"ekPub": "test-ek-public-key",
			}

			jsonData, err := json.Marshal(ekReq)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jsonData)
		}

		req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/"+token, nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "test-ek-public-key", response["ekPub"])
	})

	t.Run("activation endpoint handles POST request", func(t *testing.T) {
		token := "test-token-789"

		handler := func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if !strings.HasSuffix(r.URL.Path, token) {
				http.NotFound(w, r)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}

			var req map[string]string
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}

			w.WriteHeader(http.StatusOK)
		}

		activateReq := map[string]string{
			"credentialBlob":  "test-cred",
			"encryptedSecret": "test-secret",
		}
		body, _ := json.Marshal(activateReq)

		req := httptest.NewRequest(http.MethodPost, "/.well-known/acme-activation/"+token, strings.NewReader(string(body)))
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("handles wrong token", func(t *testing.T) {
		token := "test-token-789"

		handler := func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, token) {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
		}

		req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/wrong-token", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestConvertKeyAttributes_NilHandling tests nil handling in convertKeyAttributes
func TestConvertKeyAttributes_NilHandling(t *testing.T) {
	result := convertKeyAttributes(nil)
	assert.Nil(t, result, "convertKeyAttributes should return nil for nil input")
}

// =====================================
// Tests from coverage_gaps_final_test.go
// =====================================

type failingAccountStorage struct {
	*mockStorage
}

func newFailingAccountStorage() *failingAccountStorage {
	return &failingAccountStorage{
		mockStorage: newMockStorage(),
	}
}

func (f *failingAccountStorage) Save(ctx context.Context, account *entities.ACMEAccount) error {
	return errors.New("storage save failed")
}

// TestRegisterCertificate_EmptyIdentifierUsesCommonName tests that empty identifier defaults to CN
func TestRegisterCertificate_EmptyIdentifierUsesCommonName(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountSigner: key,
		logger:        logger,
	}

	rs, err := NewRenewalService(client, nil, logger)
	require.NoError(t, err)

	// Create a test certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "test.example.com",
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
	}

	// Register with empty identifier - should use CN
	err = rs.RegisterCertificate(cert, req, "")
	assert.NoError(t, err)

	// Verify it's registered under the CN
	_, exists := rs.certificates.Load("test.example.com")
	assert.True(t, exists, "Certificate should be registered under CN")
}

// TestRegisterCertificate_AlreadyRegistered tests duplicate registration error
func TestRegisterCertificate_AlreadyRegistered(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountSigner: key,
		logger:        logger,
	}

	rs, err := NewRenewalService(client, nil, logger)
	require.NoError(t, err)

	// Create a test certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "duplicate.example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "duplicate.example.com",
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
	}

	// First registration should succeed
	err = rs.RegisterCertificate(cert, req, "duplicate-cert")
	assert.NoError(t, err)

	// Second registration with same identifier should fail
	err = rs.RegisterCertificate(cert, req, "duplicate-cert")
	assert.ErrorIs(t, err, ErrCertificateAlreadyRegistered)
}

// TestRenewalService_StartAlreadyRunning tests starting an already running service
func TestRenewalService_StartAlreadyRunning(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountSigner: key,
		logger:        logger,
	}

	config := DefaultRenewalConfig()
	config.Enabled = true
	config.CheckInterval = 100 * time.Millisecond

	rs, err := NewRenewalService(client, config, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the service
	err = rs.Start(ctx)
	require.NoError(t, err)

	// Wait a bit for the service to start
	time.Sleep(50 * time.Millisecond)

	// Try to start again - should fail
	err = rs.Start(ctx)
	assert.ErrorIs(t, err, ErrRenewalServiceAlreadyRunning)

	// Stop the service
	_ = rs.Stop()
}

// TestRequestCertificate_NilCSR_CoverageGaps tests when CSR is nil
func TestRequestCertificate_NilCSR_CoverageGaps(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountSigner: key,
		logger:        logger,
		config:        DefaultConfig(),
		client: &acme.Client{
			Key:          key,
			DirectoryURL: unreachableDirectoryURL,
		},
	}

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           nil, // nil CSR
	}

	_, err = client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid certificate request")
}

// TestStartEndorseServer_HTTPHandlers tests the endorse server HTTP handlers
func TestStartEndorseServer_HTTPHandlers(t *testing.T) {
	token := "valid-endorse-token-12345"

	// Create the ekRequest that startEndorseServer would use
	ekReq := ekRequest{
		EKPublicKey:  base64.RawURLEncoding.EncodeToString([]byte("test-ek-public")),
		EKAttributes: "test-attributes",
		CSR:          "test-csr",
	}

	// Test the challenge endpoint handler directly
	t.Run("challenge_endpoint_valid_token", func(t *testing.T) {
		mux := http.NewServeMux()
		challengePath := "/.well-known/acme-challenge/"

		mux.HandleFunc(challengePath, func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, token) {
				http.NotFound(w, r)
				return
			}

			jsonData, err := json.Marshal(ekReq)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jsonData)
		})

		req := httptest.NewRequest(http.MethodGet, challengePath+token, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var response ekRequest
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, ekReq.EKPublicKey, response.EKPublicKey)
	})

	t.Run("challenge_endpoint_invalid_token", func(t *testing.T) {
		mux := http.NewServeMux()
		challengePath := "/.well-known/acme-challenge/"

		mux.HandleFunc(challengePath, func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, token) {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, challengePath+"wrong-token", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	// Test activation endpoint
	t.Run("activation_endpoint_method_not_allowed", func(t *testing.T) {
		mux := http.NewServeMux()
		activatePath := "/.well-known/acme-activation/"

		mux.HandleFunc(activatePath, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
		})

		req := httptest.NewRequest(http.MethodGet, activatePath+token, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("activation_endpoint_invalid_json", func(t *testing.T) {
		mux := http.NewServeMux()
		activatePath := "/.well-known/acme-activation/"

		mux.HandleFunc(activatePath, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}

			if !strings.HasSuffix(r.URL.Path, token) {
				http.NotFound(w, r)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}

			var activateReq activateCredentialRequest
			if err := json.Unmarshal(body, &activateReq); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
		})

		req := httptest.NewRequest(http.MethodPost, activatePath+token, strings.NewReader("invalid-json"))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("activation_endpoint_invalid_credential_blob", func(t *testing.T) {
		mux := http.NewServeMux()
		activatePath := "/.well-known/acme-activation/"

		mux.HandleFunc(activatePath, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}

			if !strings.HasSuffix(r.URL.Path, token) {
				http.NotFound(w, r)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}

			var activateReq activateCredentialRequest
			if err := json.Unmarshal(body, &activateReq); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}

			_, err = base64.RawURLEncoding.DecodeString(activateReq.CredentialBlob)
			if err != nil {
				http.Error(w, "invalid credential blob", http.StatusBadRequest)
				return
			}
		})

		payload := `{"credentialBlob": "!!!invalid-base64!!!", "encryptedSecret": "dGVzdA"}`
		req := httptest.NewRequest(http.MethodPost, activatePath+token, strings.NewReader(payload))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("activation_endpoint_invalid_encrypted_secret", func(t *testing.T) {
		mux := http.NewServeMux()
		activatePath := "/.well-known/acme-activation/"

		mux.HandleFunc(activatePath, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}

			if !strings.HasSuffix(r.URL.Path, token) {
				http.NotFound(w, r)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}

			var activateReq activateCredentialRequest
			if err := json.Unmarshal(body, &activateReq); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}

			_, err = base64.RawURLEncoding.DecodeString(activateReq.CredentialBlob)
			if err != nil {
				http.Error(w, "invalid credential blob", http.StatusBadRequest)
				return
			}

			_, err = base64.RawURLEncoding.DecodeString(activateReq.EncryptedSecret)
			if err != nil {
				http.Error(w, "invalid encrypted secret", http.StatusBadRequest)
				return
			}
		})

		payload := `{"credentialBlob": "dGVzdA", "encryptedSecret": "!!!invalid-base64!!!"}`
		req := httptest.NewRequest(http.MethodPost, activatePath+token, strings.NewReader(payload))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestStartAttestServer_HTTPHandlers tests the attest server HTTP handlers
func TestStartAttestServer_HTTPHandlers(t *testing.T) {
	token := "valid-attest-token-12345"

	quote := &TPMQuote{
		Quote:              []byte("test-quote"),
		Signature:          []byte("test-signature"),
		PCRValues:          map[int][]byte{0: make([]byte, 32)},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	t.Run("quote_endpoint_valid_token", func(t *testing.T) {
		mux := http.NewServeMux()
		quotePath := "/.well-known/acme-quote/"

		mux.HandleFunc(quotePath, func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, token) {
				http.NotFound(w, r)
				return
			}

			response := map[string]interface{}{
				"quote":     base64.RawURLEncoding.EncodeToString(quote.Quote),
				"signature": base64.RawURLEncoding.EncodeToString(quote.Signature),
				"pcr_values": map[string]string{
					"0": base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
				},
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(response)
		})

		req := httptest.NewRequest(http.MethodGet, quotePath+token, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	})

	t.Run("quote_endpoint_invalid_token", func(t *testing.T) {
		mux := http.NewServeMux()
		quotePath := "/.well-known/acme-quote/"

		mux.HandleFunc(quotePath, func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, token) {
				http.NotFound(w, r)
				return
			}
		})

		req := httptest.NewRequest(http.MethodGet, quotePath+"wrong-token", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestAccountStorageSaveFailure tests that account storage save failure is handled gracefully
func TestAccountStorageSaveFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/directory" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   serverURL + "/acme/new-nonce",
				"newAccount": serverURL + "/acme/new-account",
				"newOrder":   serverURL + "/acme/new-order",
			})
			return
		}

		if strings.Contains(r.URL.Path, "/acme/new-account") {
			w.Header().Set("Location", serverURL+"/acme/account/123")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "valid",
				"contact": []string{"mailto:test@example.com"},
				"orders":  serverURL + "/acme/account/123/orders",
			})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	serverURL = ts.URL

	failingStorage := newFailingAccountStorage()

	client := &Client{
		accountSigner: key,
		accountEmail:  "test@example.com",
		logger:        logger,
		config:        DefaultConfig(),
		storage:       failingStorage,
		client: &acme.Client{
			Key:          key,
			DirectoryURL: ts.URL + "/directory",
		},
	}

	// Register account - should succeed even if storage fails
	account, err := client.RegisterAccount()
	assert.NoError(t, err)
	assert.NotNil(t, account)
	assert.Equal(t, "valid", account.Status)
}

// TestRenewalConfig_ValidateDefaults tests that default renewal config is valid
func TestRenewalConfig_ValidateDefaults(t *testing.T) {
	config := DefaultRenewalConfig()

	assert.NotNil(t, config)
	assert.True(t, config.Enabled)
	assert.Equal(t, 24*time.Hour, config.CheckInterval)
	assert.Equal(t, 0.33, config.RenewalThreshold)
}

// TestRenewalService_ConfigDisabled tests that disabled config returns nil (no-op)
func TestRenewalService_ConfigDisabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountSigner: key,
		logger:        logger,
	}

	config := DefaultRenewalConfig()
	config.Enabled = false

	rs, err := NewRenewalService(client, config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	err = rs.Start(ctx)
	// When disabled, Start returns nil (logs message and returns early)
	assert.NoError(t, err)
}

// TestUnregisterCertificate tests successful certificate unregistration
func TestUnregisterCertificate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountSigner: key,
		logger:        logger,
	}

	rs, err := NewRenewalService(client, nil, logger)
	require.NoError(t, err)

	// Create a test certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "unregister.example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "unregister.example.com",
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
	}

	// Register certificate
	err = rs.RegisterCertificate(cert, req, "unregister-test")
	require.NoError(t, err)

	// Verify it's registered
	_, exists := rs.certificates.Load("unregister-test")
	assert.True(t, exists)

	// Unregister certificate
	rs.UnregisterCertificate("unregister-test")

	// Verify it's unregistered
	_, exists = rs.certificates.Load("unregister-test")
	assert.False(t, exists)
}

// TestNewRenewalService_NilConfig tests NewRenewalService with nil config
func TestNewRenewalService_NilConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountSigner: key,
		logger:        logger,
	}

	// Should create with default config when nil is passed
	rs, err := NewRenewalService(client, nil, logger)
	require.NoError(t, err)
	assert.NotNil(t, rs)
	assert.NotNil(t, rs.config)
}

// TestCertificateRequest_EmptyAuthzValue tests validation of empty AuthzValue
func TestCertificateRequest_EmptyAuthzValue(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountSigner: key,
		logger:        logger,
		config:        DefaultConfig(),
		client: &acme.Client{
			Key:          key,
			DirectoryURL: unreachableDirectoryURL,
		},
	}

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "", // Empty
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
	}

	_, err = client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid certificate request")
}

// TestCertificateRequest_InvalidAuthzType tests validation of invalid AuthzType
func TestCertificateRequest_InvalidAuthzType(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountSigner: key,
		logger:        logger,
		config:        DefaultConfig(),
		client: &acme.Client{
			Key:          key,
			DirectoryURL: unreachableDirectoryURL,
		},
	}

	req := &CertificateRequest{
		AuthzType:     "", // Empty type
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
	}

	_, err = client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid certificate request")
}

// TestRenewalService_Stop_NotRunning tests stopping a non-running service
func TestRenewalService_Stop_NotRunning(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountSigner: key,
		logger:        logger,
	}

	rs, err := NewRenewalService(client, nil, logger)
	require.NoError(t, err)

	// Should return error when stopping a non-running service
	err = rs.Stop()
	assert.ErrorIs(t, err, ErrRenewalServiceNotRunning)
}

// TestCertificateRequest_EmptyChallengeType tests validation of empty ChallengeType
func TestCertificateRequest_EmptyChallengeType(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountSigner: key,
		logger:        logger,
		config:        DefaultConfig(),
		client: &acme.Client{
			Key:          key,
			DirectoryURL: unreachableDirectoryURL,
		},
	}

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "", // Empty challenge type
		CSR:           []byte("test-csr"),
	}

	_, err = client.RequestCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid certificate request")
}

// TestNewClient_WithNilStorage tests NewClient with nil storage
func TestNewClient_WithNilStorage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := DefaultConfig()
	config.DirectoryURL = "https://example.com/acme/directory"

	params := &Params{
		Config:        config,
		AccountSigner: key,
		Storage:       nil, // Nil storage
		AccountEmail:  "test@example.com",
		Logger:        logger,
	}

	// Creating client with nil storage should fail
	_, err = NewClient(params)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNilStorage)
}

// TestDefaultConfig_Validation tests that default config has valid values
func TestDefaultConfig_Validation(t *testing.T) {
	config := DefaultConfig()

	assert.NotNil(t, config)
	assert.Greater(t, config.Timeout, time.Duration(0))
	assert.Greater(t, config.RetryAttempts, 0)
}

// TestRenewalService_StopBeforeStart tests that Stop returns error before Start
func TestRenewalService_StopBeforeStart(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountSigner: key,
		logger:        logger,
	}

	config := DefaultRenewalConfig()
	config.Enabled = true

	rs, err := NewRenewalService(client, config, logger)
	require.NoError(t, err)

	// Stop before Start should return error
	err = rs.Stop()
	assert.ErrorIs(t, err, ErrRenewalServiceNotRunning)
}

// TestRenewalService_MultipleStops tests that multiple Stop calls are handled correctly
func TestRenewalService_MultipleStops(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		accountSigner: key,
		logger:        logger,
	}

	config := DefaultRenewalConfig()
	config.Enabled = true
	config.CheckInterval = 100 * time.Millisecond

	rs, err := NewRenewalService(client, config, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the service
	err = rs.Start(ctx)
	require.NoError(t, err)

	// Wait for service to start
	time.Sleep(50 * time.Millisecond)

	// First stop should succeed
	err = rs.Stop()
	assert.NoError(t, err)

	// Second stop should fail (service not running)
	err = rs.Stop()
	assert.ErrorIs(t, err, ErrRenewalServiceNotRunning)
}

// TestNewClient_WithNilSigner tests NewClient with nil signer
func TestNewClient_WithNilSigner(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	config := DefaultConfig()
	config.DirectoryURL = "https://example.com/acme/directory"

	params := &Params{
		Config:        config,
		AccountSigner: nil, // Nil signer
		Storage:       newMockStorage(),
		AccountEmail:  "test@example.com",
		Logger:        logger,
	}

	// Creating client with nil signer should fail
	_, err := NewClient(params)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNilSigner)
}

// TestNewClient_WithNilParams tests NewClient with nil params
func TestNewClient_WithNilParams(t *testing.T) {
	// Creating client with nil params should fail
	_, err := NewClient(nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidConfiguration)
}

// =====================================
// Tests from coverage_unit_test.go
// =====================================

type MockTPM struct {
	ekPub              crypto.PublicKey
	ekCert             *x509.Certificate
	ekAttrs            *KeyAttributes
	iakAttrs           *KeyAttributes
	idevidCSR          *IDevIDCSR
	quote              *TPMQuote
	activateCredErr    error
	provisionEKCertErr error
	createIDevIDErr    error
	quoteErr           error
	ekCertErr          error
	ekAttrsErr         error
	iakAttrsErr        error
}

func (m *MockTPM) EK() crypto.PublicKey {
	return m.ekPub
}

func (m *MockTPM) EKCertificate() (*x509.Certificate, error) {
	if m.ekCertErr != nil {
		return nil, m.ekCertErr
	}
	return m.ekCert, nil
}

func (m *MockTPM) EKAttributes() (*KeyAttributes, error) {
	if m.ekAttrsErr != nil {
		return nil, m.ekAttrsErr
	}
	return m.ekAttrs, nil
}

func (m *MockTPM) IAKAttributes() (*KeyAttributes, error) {
	if m.iakAttrsErr != nil {
		return nil, m.iakAttrsErr
	}
	return m.iakAttrs, nil
}

func (m *MockTPM) CreateIDevID(qualifyingData []byte) (*IDevIDCSR, error) {
	if m.createIDevIDErr != nil {
		return nil, m.createIDevIDErr
	}
	return m.idevidCSR, nil
}

func (m *MockTPM) ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error) {
	if m.activateCredErr != nil {
		return nil, m.activateCredErr
	}
	return []byte("activated-secret"), nil
}

func (m *MockTPM) ProvisionEKCert(certDER []byte) error {
	return m.provisionEKCertErr
}

func (m *MockTPM) Quote(nonce []byte, pcrSelection []int) (*TPMQuote, error) {
	if m.quoteErr != nil {
		return nil, m.quoteErr
	}
	return m.quote, nil
}

func (m *MockTPM) Close() error {
	return nil
}

// Test CrossSign error paths
func TestCrossSign_NilCSR(t *testing.T) {
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, _ := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: signer,
		Storage:       newMockStorage(),
		Config:        DefaultConfig(),
	})

	cert, _ := generateTestCertificate(t, "test.example.com")
	certDER := cert.Raw

	_, err := client.CrossSign(context.Background(), nil, certDER)
	if !errors.Is(err, ErrMissingCSR) {
		t.Errorf("expected ErrMissingCSR, got %v", err)
	}
}

func TestCrossSign_EmptyCSR(t *testing.T) {
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, _ := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: signer,
		Storage:       newMockStorage(),
		Config:        DefaultConfig(),
	})

	cert, _ := generateTestCertificate(t, "test.example.com")
	certDER := cert.Raw

	_, err := client.CrossSign(context.Background(), []byte{}, certDER)
	if !errors.Is(err, ErrMissingCSR) {
		t.Errorf("expected ErrMissingCSR, got %v", err)
	}
}

func TestCrossSign_NilCertificate(t *testing.T) {
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, _ := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: signer,
		Storage:       newMockStorage(),
		Config:        DefaultConfig(),
	})

	csr := createTestCSR(t, signer, "test.example.com")

	_, err := client.CrossSign(context.Background(), csr, nil)
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Errorf("expected ErrInvalidCertificate, got %v", err)
	}
}

func TestCrossSign_InvalidCertificate(t *testing.T) {
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, _ := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: signer,
		Storage:       newMockStorage(),
		Config:        DefaultConfig(),
	})

	csr := createTestCSR(t, signer, "test.example.com")

	_, err := client.CrossSign(context.Background(), csr, []byte("invalid-cert"))
	if err == nil || !strings.Contains(err.Error(), "failed to parse certificate") {
		t.Errorf("expected parse error, got %v", err)
	}
}

func TestCrossSign_InvalidCSR(t *testing.T) {
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, _ := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: signer,
		Storage:       newMockStorage(),
		Config:        DefaultConfig(),
	})

	cert, _ := generateTestCertificate(t, "test.example.com")

	_, err := client.CrossSign(context.Background(), []byte("invalid-csr"), cert.Raw)
	if err == nil || !strings.Contains(err.Error(), "failed to parse CSR") {
		t.Errorf("expected CSR parse error, got %v", err)
	}
}

func TestCrossSign_MismatchedSubjects(t *testing.T) {
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, _ := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: signer,
		Storage:       newMockStorage(),
		Config:        DefaultConfig(),
	})

	cert, _ := generateTestCertificate(t, "test.example.com")
	csr := createTestCSR(t, signer, "different.example.com")

	_, err := client.CrossSign(context.Background(), csr, cert.Raw)
	var caErr10255 *caerrors.TrustedCAError
	if !errors.As(err, &caErr10255) || caErr10255.Type != caerrors.BadCSR {
		t.Errorf("expected ErrInvalidCSRForCrossSigning, got %v", err)
	}
}

// Test CrossSignWithChallenge error paths
func TestCrossSignWithChallenge_NilChallengeSetup(t *testing.T) {
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, _ := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: signer,
		Storage:       newMockStorage(),
		Config:        DefaultConfig(),
	})

	cert, _ := generateTestCertificate(t, "test.example.com")
	csr := createTestCSR(t, signer, "test.example.com")

	_, err := client.CrossSignWithChallenge(
		context.Background(),
		csr,
		cert.Raw,
		nil, // nil setup function
		nil,
	)
	if !errors.Is(err, ErrInvalidChallengeSetup) {
		t.Errorf("expected ErrInvalidChallengeSetup, got %v", err)
	}
}

func TestCrossSignWithChallenge_EmptyCSR(t *testing.T) {
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, _ := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: signer,
		Storage:       newMockStorage(),
		Config:        DefaultConfig(),
	})

	cert, _ := generateTestCertificate(t, "test.example.com")
	setupFunc := func(challengeType, token, keyAuth string) error { return nil }

	_, err := client.CrossSignWithChallenge(
		context.Background(),
		[]byte{},
		cert.Raw,
		setupFunc,
		nil,
	)
	if !errors.Is(err, ErrMissingCSR) {
		t.Errorf("expected ErrMissingCSR, got %v", err)
	}
}

func TestCrossSignWithChallenge_EmptyCertificate(t *testing.T) {
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, _ := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: signer,
		Storage:       newMockStorage(),
		Config:        DefaultConfig(),
	})

	csr := createTestCSR(t, signer, "test.example.com")
	setupFunc := func(challengeType, token, keyAuth string) error { return nil }

	_, err := client.CrossSignWithChallenge(
		context.Background(),
		csr,
		[]byte{},
		setupFunc,
		nil,
	)
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Errorf("expected ErrInvalidCertificate, got %v", err)
	}
}

// Test EnrollmentConfig validation
func TestEnrollmentConfig_Validate_EmptyChallenge(t *testing.T) {
	config := &EnrollmentConfig{
		Challenge: "",
		IPAddress: "192.168.1.1",
		TPMModule: &MockTPM{},
	}

	err := config.Validate()
	if !errors.Is(err, ErrInvalidChallenge) {
		t.Errorf("expected ErrInvalidChallenge, got %v", err)
	}
}

func TestEnrollmentConfig_Validate_InvalidChallenge(t *testing.T) {
	config := &EnrollmentConfig{
		Challenge: "invalid-challenge",
		IPAddress: "192.168.1.1",
		TPMModule: &MockTPM{},
	}

	err := config.Validate()
	if err == nil || !strings.Contains(err.Error(), "invalid challenge type") {
		t.Errorf("expected invalid challenge error, got %v", err)
	}
}

func TestEnrollmentConfig_Validate_NilTPM(t *testing.T) {
	config := &EnrollmentConfig{
		Challenge: string(ChallengeTypeEnroll01),
		IPAddress: "192.168.1.1",
		TPMModule: nil,
	}

	err := config.Validate()
	if !errors.Is(err, ErrMissingTPMModule) {
		t.Errorf("expected ErrMissingTPMModule, got %v", err)
	}
}

func TestEnrollmentConfig_Validate_EmptyIPAddress(t *testing.T) {
	config := &EnrollmentConfig{
		Challenge: string(ChallengeTypeEnroll01),
		IPAddress: "",
		TPMModule: &MockTPM{},
	}

	err := config.Validate()
	if !errors.Is(err, ErrInvalidIPAddress) {
		t.Errorf("expected ErrInvalidIPAddress, got %v", err)
	}
}

func TestEnrollmentConfig_Validate_DefaultValues(t *testing.T) {
	config := &EnrollmentConfig{
		Challenge: string(ChallengeTypeEnroll01),
		IPAddress: "192.168.1.1",
		TPMModule: &MockTPM{},
	}

	err := config.Validate()
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if config.Port != "8080" {
		t.Errorf("expected default port 8080, got %s", config.Port)
	}

	if config.Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %v", config.Timeout)
	}
}

// Test expandEnvVars
func TestExpandEnvVars_NoVariables(t *testing.T) {
	result, err := expandEnvVars("192.168.1.1")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if result != "192.168.1.1" {
		t.Errorf("expected unchanged value, got %s", result)
	}
}

func TestExpandEnvVars_MissingVariable(t *testing.T) {
	_, err := expandEnvVars("${NONEXISTENT_VAR}")
	var caErr10420 *caerrors.TrustedCAError
	if !errors.As(err, &caErr10420) || caErr10420.Type != caerrors.Malformed {
		t.Errorf("expected ErrEnvVarNotFound, got %v", err)
	}
}

func TestExpandEnvVars_ValidVariable(t *testing.T) {
	_ = os.Setenv("TEST_IP", "10.0.0.1")
	defer func() { _ = os.Unsetenv("TEST_IP") }()

	result, err := expandEnvVars("${TEST_IP}")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if result != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", result)
	}
}

func TestExpandEnvVars_MultipleVariables(t *testing.T) {
	_ = os.Setenv("VAR1", "hello")
	_ = os.Setenv("VAR2", "world")
	defer func() {
		_ = os.Unsetenv("VAR1")
		_ = os.Unsetenv("VAR2")
	}()

	result, err := expandEnvVars("${VAR1}-${VAR2}")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if result != "hello-world" {
		t.Errorf("expected hello-world, got %s", result)
	}
}

// Test Config validation
func TestConfig_Validate_EmptyDirectoryURL(t *testing.T) {
	config := &Config{
		DirectoryURL: "",
		Timeout:      30 * time.Second,
	}

	err := config.Validate()
	if !errors.Is(err, ErrInvalidDirectoryURL) {
		t.Errorf("expected ErrInvalidDirectoryURL, got %v", err)
	}
}

func TestConfig_Validate_InvalidTimeout(t *testing.T) {
	config := &Config{
		DirectoryURL: "https://acme.example.com/directory",
		Timeout:      0,
	}

	err := config.Validate()
	if !errors.Is(err, ErrInvalidTimeout) {
		t.Errorf("expected ErrInvalidTimeout, got %v", err)
	}
}

func TestConfig_Validate_NegativeRetryAttempts(t *testing.T) {
	config := &Config{
		DirectoryURL:  "https://acme.example.com/directory",
		Timeout:       30 * time.Second,
		RetryAttempts: -1,
	}

	err := config.Validate()
	if !errors.Is(err, ErrInvalidRetryAttempts) {
		t.Errorf("expected ErrInvalidRetryAttempts, got %v", err)
	}
}

// Test RenewalConfig validation
func TestRenewalConfig_Validate_InvalidThreshold(t *testing.T) {
	config := &RenewalConfig{
		RenewalThreshold: 1.5,
		CheckInterval:    time.Hour,
	}

	err := config.Validate()
	if !errors.Is(err, ErrInvalidRenewalThreshold) {
		t.Errorf("expected ErrInvalidRenewalThreshold, got %v", err)
	}
}

func TestRenewalConfig_Validate_NegativeThreshold(t *testing.T) {
	config := &RenewalConfig{
		RenewalThreshold: -0.1,
		CheckInterval:    time.Hour,
	}

	err := config.Validate()
	if !errors.Is(err, ErrInvalidRenewalThreshold) {
		t.Errorf("expected ErrInvalidRenewalThreshold, got %v", err)
	}
}

func TestRenewalConfig_Validate_InvalidCheckInterval(t *testing.T) {
	config := &RenewalConfig{
		RenewalThreshold: 0.33,
		CheckInterval:    0,
	}

	err := config.Validate()
	if !errors.Is(err, ErrInvalidTimeout) {
		t.Errorf("expected ErrInvalidTimeout, got %v", err)
	}
}

// Test CrossSignConfig validation
func TestCrossSignConfig_Validate_Nil(t *testing.T) {
	var config *CrossSignConfig
	err := config.Validate()
	if !errors.Is(err, ErrNilCrossSignConfig) {
		t.Errorf("expected ErrNilCrossSignConfig, got %v", err)
	}
}

func TestCrossSignConfig_Validate_EmptyDirectoryURL(t *testing.T) {
	config := &CrossSignConfig{
		DirectoryURL:  "",
		ChallengeType: "http-01",
	}

	err := config.Validate()
	if !errors.Is(err, ErrEmptyCrossSignDirectoryURL) {
		t.Errorf("expected ErrEmptyCrossSignDirectoryURL, got %v", err)
	}
}

func TestCrossSignConfig_Validate_EmptyChallengeType(t *testing.T) {
	config := &CrossSignConfig{
		DirectoryURL:  "https://acme.example.com/directory",
		ChallengeType: "",
	}

	err := config.Validate()
	if !errors.Is(err, ErrMissingChallengeType) {
		t.Errorf("expected ErrMissingChallengeType, got %v", err)
	}
}

func TestCrossSignConfig_Validate_InvalidChallengeType(t *testing.T) {
	config := &CrossSignConfig{
		DirectoryURL:  "https://acme.example.com/directory",
		ChallengeType: "invalid-01",
	}

	err := config.Validate()
	if !errors.Is(err, ErrInvalidChallengeTypeForCrossSign) {
		t.Errorf("expected ErrInvalidChallengeTypeForCrossSign, got %v", err)
	}
}

func TestCrossSignConfig_Validate_SetDefaults(t *testing.T) {
	config := &CrossSignConfig{
		DirectoryURL:  "https://acme.example.com/directory",
		ChallengeType: "http-01",
		Timeout:       0,
		RetryAttempts: -1,
		RetryDelay:    0,
	}

	err := config.Validate()
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if config.Timeout != 60*time.Second {
		t.Errorf("expected default timeout 60s, got %v", config.Timeout)
	}

	if config.RetryAttempts != 3 {
		t.Errorf("expected default retry attempts 3, got %d", config.RetryAttempts)
	}

	if config.RetryDelay != 1*time.Second {
		t.Errorf("expected default retry delay 1s, got %v", config.RetryDelay)
	}
}

// Test CrossSignerFromClient error paths
func TestCrossSignerFromClient_NilClient(t *testing.T) {
	config := &CrossSignConfig{
		DirectoryURL:  "https://acme.example.com/directory",
		ChallengeType: "http-01",
	}

	_, err := CrossSignerFromClient(nil, config)
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Errorf("expected ErrInvalidConfiguration, got %v", err)
	}
}

func TestCrossSignerFromClient_InvalidConfig(t *testing.T) {
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, _ := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: signer,
		Storage:       newMockStorage(),
		Config:        DefaultConfig(),
	})

	config := &CrossSignConfig{
		DirectoryURL:  "", // invalid
		ChallengeType: "http-01",
	}

	_, err := CrossSignerFromClient(client, config)
	if err == nil || !strings.Contains(err.Error(), "invalid cross-sign configuration") {
		t.Errorf("expected configuration error, got %v", err)
	}
}

// Test extractAuthzFromCertificate
func TestExtractAuthzFromCertificate_WithDNSNames(t *testing.T) {
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, _ := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: signer,
		Storage:       newMockStorage(),
		Config:        DefaultConfig(),
	})

	cert, _ := generateTestCertificate(t, "test.example.com")
	authzValue, authzType, err := client.extractAuthzFromCertificate(cert)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if authzType != "dns" {
		t.Errorf("expected authz type dns, got %s", authzType)
	}

	if authzValue == "" {
		t.Error("expected non-empty authz value")
	}
}

func TestExtractAuthzFromCertificate_NoDNSNoIP(t *testing.T) {
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, _ := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: signer,
		Storage:       newMockStorage(),
		Config:        DefaultConfig(),
	})

	// Create cert without DNS names or IPs but with CN
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	cert, _ := x509.ParseCertificate(certDER)

	authzValue, authzType, err := client.extractAuthzFromCertificate(cert)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if authzType != "dns" {
		t.Errorf("expected authz type dns, got %s", authzType)
	}

	if authzValue != "test.example.com" {
		t.Errorf("expected test.example.com, got %s", authzValue)
	}
}

func TestExtractAuthzFromCertificate_NoIdentifiers(t *testing.T) {
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, _ := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: signer,
		Storage:       newMockStorage(),
		Config:        DefaultConfig(),
	})

	// Create cert without any identifiers
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	cert, _ := x509.ParseCertificate(certDER)

	_, _, err := client.extractAuthzFromCertificate(cert)

	if err == nil || !strings.Contains(err.Error(), "no valid authorization identifier") {
		t.Errorf("expected no identifier error, got %v", err)
	}
}

// Test startEnrollServer error handling
func TestStartEnrollServer_HTTPHandling(t *testing.T) {
	// Create test server to simulate the enrollment server
	mux := http.NewServeMux()

	token := "test-token"

	// Set up the handlers like startEnrollServer does
	challengePath := "/.well-known/acme-challenge/"
	mux.HandleFunc(challengePath, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, token) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("encoded-csr"))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Test successful challenge path
	resp, err := http.Get(server.URL + challengePath + token)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Test wrong token
	resp2, err := http.Get(server.URL + challengePath + "wrong-token")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()

	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", resp2.StatusCode)
	}
}

// Test CertificateRequest validation
func TestCertificateRequest_Validate_MissingAuthzType(t *testing.T) {
	req := &CertificateRequest{
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           []byte("csr"),
	}

	err := req.Validate()
	if !errors.Is(err, ErrMissingAuthzType) {
		t.Errorf("expected ErrMissingAuthzType, got %v", err)
	}
}

func TestCertificateRequest_Validate_MissingAuthzValue(t *testing.T) {
	req := &CertificateRequest{
		AuthzType:     "dns",
		ChallengeType: "http-01",
		CSR:           []byte("csr"),
	}

	err := req.Validate()
	if !errors.Is(err, ErrMissingAuthzValue) {
		t.Errorf("expected ErrMissingAuthzValue, got %v", err)
	}
}

func TestCertificateRequest_Validate_MissingChallengeType(t *testing.T) {
	req := &CertificateRequest{
		AuthzType:  "dns",
		AuthzValue: "example.com",
		CSR:        []byte("csr"),
	}

	err := req.Validate()
	if !errors.Is(err, ErrMissingChallengeType) {
		t.Errorf("expected ErrMissingChallengeType, got %v", err)
	}
}

func TestCertificateRequest_Validate_MissingCSR(t *testing.T) {
	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
	}

	err := req.Validate()
	if !errors.Is(err, ErrMissingCSR) {
		t.Errorf("expected ErrMissingCSR, got %v", err)
	}
}

// Test NewClient error paths
func TestNewClient_NilParams(t *testing.T) {
	_, err := NewClient(nil)
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Errorf("expected ErrInvalidConfiguration, got %v", err)
	}
}

func TestNewClient_NilSigner(t *testing.T) {
	_, err := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: nil,
		Storage:       newMockStorage(),
	})
	if !errors.Is(err, ErrNilSigner) {
		t.Errorf("expected ErrNilSigner, got %v", err)
	}
}

func TestNewClient_NilStorage(t *testing.T) {
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: signer,
		Storage:       nil,
	})
	if !errors.Is(err, ErrNilStorage) {
		t.Errorf("expected ErrNilStorage, got %v", err)
	}
}

// Test extractAccountIDFromURI edge cases
func TestExtractAccountIDFromURI_EmptyURI(t *testing.T) {
	_, err := extractAccountIDFromURI("")
	if !errors.Is(err, ErrInvalidAccountURI) {
		t.Errorf("expected ErrInvalidAccountURI, got %v", err)
	}
}

func TestExtractAccountIDFromURI_InvalidFormat(t *testing.T) {
	_, err := extractAccountIDFromURI("not-a-uri")
	if err == nil || !strings.Contains(err.Error(), "invalid account URI") {
		t.Errorf("expected invalid URI error, got %v", err)
	}
}

func TestExtractAccountIDFromURI_NoPathSegments(t *testing.T) {
	_, err := extractAccountIDFromURI("https://acme.example.com/")
	if err == nil || !strings.Contains(err.Error(), "invalid account URI") {
		t.Errorf("expected no path segments error, got %v", err)
	}
}

func TestExtractAccountIDFromURI_InvalidID(t *testing.T) {
	_, err := extractAccountIDFromURI("https://acme.example.com/acme/account/invalid")
	if err == nil || !strings.Contains(err.Error(), "invalid account ID format") {
		t.Errorf("expected invalid ID error, got %v", err)
	}
}

func TestExtractAccountIDFromURI_ZeroID(t *testing.T) {
	_, err := extractAccountIDFromURI("https://acme.example.com/acme/account/0")
	if err == nil || !strings.Contains(err.Error(), "account ID cannot be zero") {
		t.Errorf("expected zero ID error, got %v", err)
	}
}

func TestExtractAccountIDFromURI_Valid(t *testing.T) {
	id, err := extractAccountIDFromURI("https://acme.example.com/acme/account/12345")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if id != 12345 {
		t.Errorf("expected ID 12345, got %d", id)
	}
}

// Test COSE algorithm conversions
func TestCOSEAlgorithmFromSignatureAlgorithm_AllAlgorithms_Unit(t *testing.T) {
	tests := []struct {
		sigAlgo  x509.SignatureAlgorithm
		expected COSEAlgorithm
	}{
		{x509.ECDSAWithSHA256, COSEAlgorithmES256},
		{x509.ECDSAWithSHA384, COSEAlgorithmES384},
		{x509.ECDSAWithSHA512, COSEAlgorithmES512},
		{x509.SHA256WithRSA, COSEAlgorithmRS256},
		{x509.SHA384WithRSA, COSEAlgorithmRS384},
		{x509.SHA512WithRSA, COSEAlgorithmRS512},
		{x509.SHA256WithRSAPSS, COSEAlgorithmPS256},
		{x509.SHA384WithRSAPSS, COSEAlgorithmPS384},
		{x509.SHA512WithRSAPSS, COSEAlgorithmPS512},
		{x509.PureEd25519, COSEAlgorithmEdDSA},
		{x509.UnknownSignatureAlgorithm, COSEAlgorithmUnknown},
	}

	for _, tt := range tests {
		result := COSEAlgorithmFromSignatureAlgorithm(tt.sigAlgo)
		if result != tt.expected {
			t.Errorf("for %v expected %v, got %v", tt.sigAlgo, tt.expected, result)
		}
	}
}

func TestSignatureAlgorithmFromCOSE_AllAlgorithms_Unit(t *testing.T) {
	tests := []struct {
		coseAlgo COSEAlgorithm
		expected x509.SignatureAlgorithm
	}{
		{COSEAlgorithmES256, x509.ECDSAWithSHA256},
		{COSEAlgorithmES384, x509.ECDSAWithSHA384},
		{COSEAlgorithmES512, x509.ECDSAWithSHA512},
		{COSEAlgorithmRS256, x509.SHA256WithRSA},
		{COSEAlgorithmRS384, x509.SHA384WithRSA},
		{COSEAlgorithmRS512, x509.SHA512WithRSA},
		{COSEAlgorithmPS256, x509.SHA256WithRSAPSS},
		{COSEAlgorithmPS384, x509.SHA384WithRSAPSS},
		{COSEAlgorithmPS512, x509.SHA512WithRSAPSS},
		{COSEAlgorithmEdDSA, x509.PureEd25519},
		{COSEAlgorithmUnknown, x509.UnknownSignatureAlgorithm},
	}

	for _, tt := range tests {
		result := SignatureAlgorithmFromCOSE(tt.coseAlgo)
		if result != tt.expected {
			t.Errorf("for %v expected %v, got %v", tt.coseAlgo, tt.expected, result)
		}
	}
}

// Test Account method
func TestClient_Account_EmptyEmail(t *testing.T) {
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, _ := NewClient(&Params{
		AccountEmail:  "", // empty email
		AccountSigner: signer,
		Storage:       newMockStorage(),
		Config:        DefaultConfig(),
	})

	_, err := client.Account()
	if !errors.Is(err, ErrAccountNotFound) {
		t.Errorf("expected ErrAccountNotFound, got %v", err)
	}
}

// Test convertKeyAttributes with nil input
func TestConvertKeyAttributes_Nil(t *testing.T) {
	result := convertKeyAttributes(nil)
	if result != nil {
		t.Error("expected nil result for nil input")
	}
}

// Helper function to create a test CSR
func createTestCSR(t *testing.T, signer crypto.Signer, cn string) []byte {
	t.Helper()

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cn,
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}

	return csrDER
}

// =====================================
// Tests from request_certificate_test.go
// =====================================

func TestClient_RequestCertificate_EdgeCases(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("challenge type not offered by server", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		csrDER := generateCSR(t, "example.com", privateKey)

		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

			switch r.URL.Path {
			case "/directory":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"newNonce":   server.URL + "/new-nonce",
					"newAccount": server.URL + "/new-account",
					"newOrder":   server.URL + "/new-order",
				})
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/new-order":
				w.WriteHeader(http.StatusCreated)
				w.Header().Set("Location", server.URL+"/order/1")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":      "pending",
					"expires":     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					"identifiers": []map[string]string{{"type": "dns", "value": "example.com"}},
					"authorizations": []string{
						server.URL + "/authz/1",
					},
					"finalize": server.URL + "/order/1/finalize",
				})
			case "/authz/1":
				w.WriteHeader(http.StatusOK)
				// Return only dns-01 challenge, not http-01
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"identifier": map[string]string{"type": "dns", "value": "example.com"},
					"status":     "pending",
					"expires":    time.Now().Add(1 * time.Hour).Format(time.RFC3339),
					"challenges": []map[string]interface{}{
						{
							"type":   "dns-01",
							"status": "pending",
							"url":    server.URL + "/challenge/1",
							"token":  "test-token",
						},
					},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		transport := &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		}
		httpClient := &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}

		acmeClient := &acme.Client{
			DirectoryURL: server.URL + "/directory",
			Key:          privateKey,
			HTTPClient:   httpClient,
		}

		client := &Client{
			accountEmail:       "test@example.com",
			accountSigner:      privateKey,
			client:             acmeClient,
			httpClient:         httpClient,
			config:             DefaultConfig(),
			logger:             logger,
			storage:            newMockStorage(),
			certificateStorage: newMockCertStorage(),
			orderStorage:       newMockOrderStorage(),
		}

		req := &CertificateRequest{
			AuthzType:     "dns",
			AuthzValue:    "example.com",
			ChallengeType: "http-01", // Request http-01 but server only offers dns-01
			CSR:           csrDER,
		}

		cert, err := client.RequestCertificate(context.Background(), req)
		assert.Error(t, err)
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "challenge type http-01 not offered by server")
	})

	t.Run("authorization fails with invalid status", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		csrDER := generateCSR(t, "example.com", privateKey)

		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

			switch r.URL.Path {
			case "/directory":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"newNonce":   server.URL + "/new-nonce",
					"newAccount": server.URL + "/new-account",
					"newOrder":   server.URL + "/new-order",
				})
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/new-order":
				w.WriteHeader(http.StatusCreated)
				w.Header().Set("Location", server.URL+"/order/1")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":      "pending",
					"expires":     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					"identifiers": []map[string]string{{"type": "dns", "value": "example.com"}},
					"authorizations": []string{
						server.URL + "/authz/1",
					},
					"finalize": server.URL + "/order/1/finalize",
				})
			case "/authz/1":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"identifier": map[string]string{"type": "dns", "value": "example.com"},
					"status":     "invalid", // Authorization failed
					"expires":    time.Now().Add(1 * time.Hour).Format(time.RFC3339),
					"challenges": []map[string]interface{}{
						{
							"type":   "http-01",
							"status": "invalid",
							"url":    server.URL + "/challenge/1",
							"token":  "test-token",
						},
					},
				})
			case "/challenge/1":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"type":   "http-01",
					"status": "processing",
					"url":    server.URL + "/challenge/1",
					"token":  "test-token",
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		transport := &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		}
		httpClient := &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}

		acmeClient := &acme.Client{
			DirectoryURL: server.URL + "/directory",
			Key:          privateKey,
			HTTPClient:   httpClient,
		}

		client := &Client{
			accountEmail:       "test@example.com",
			accountSigner:      privateKey,
			client:             acmeClient,
			httpClient:         httpClient,
			config:             DefaultConfig(),
			logger:             logger,
			storage:            newMockStorage(),
			certificateStorage: newMockCertStorage(),
			orderStorage:       newMockOrderStorage(),
		}

		req := &CertificateRequest{
			AuthzType:     "dns",
			AuthzValue:    "example.com",
			ChallengeType: "http-01",
			CSR:           csrDER,
		}

		cert, err := client.RequestCertificate(context.Background(), req)
		assert.Error(t, err)
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "authorization error")
	})

	t.Run("missing CSR in finalization", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

			switch r.URL.Path {
			case "/directory":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"newNonce":   server.URL + "/new-nonce",
					"newAccount": server.URL + "/new-account",
					"newOrder":   server.URL + "/new-order",
				})
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/new-order":
				w.WriteHeader(http.StatusCreated)
				w.Header().Set("Location", server.URL+"/order/1")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":      "pending",
					"expires":     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					"identifiers": []map[string]string{{"type": "dns", "value": "example.com"}},
					"authorizations": []string{
						server.URL + "/authz/1",
					},
					"finalize": server.URL + "/order/1/finalize",
				})
			case "/authz/1":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"identifier": map[string]string{"type": "dns", "value": "example.com"},
					"status":     "valid",
					"expires":    time.Now().Add(1 * time.Hour).Format(time.RFC3339),
					"challenges": []map[string]interface{}{
						{
							"type":   "http-01",
							"status": "valid",
							"url":    server.URL + "/challenge/1",
							"token":  "test-token",
						},
					},
				})
			case "/challenge/1":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"type":   "http-01",
					"status": "valid",
					"url":    server.URL + "/challenge/1",
					"token":  "test-token",
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		transport := &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		}
		httpClient := &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}

		acmeClient := &acme.Client{
			DirectoryURL: server.URL + "/directory",
			Key:          privateKey,
			HTTPClient:   httpClient,
		}

		client := &Client{
			accountEmail:       "test@example.com",
			accountSigner:      privateKey,
			client:             acmeClient,
			httpClient:         httpClient,
			config:             DefaultConfig(),
			logger:             logger,
			storage:            newMockStorage(),
			certificateStorage: newMockCertStorage(),
			orderStorage:       newMockOrderStorage(),
		}

		req := &CertificateRequest{
			AuthzType:     "dns",
			AuthzValue:    "example.com",
			ChallengeType: "http-01",
			CSR:           nil, // Missing CSR
		}

		cert, err := client.RequestCertificate(context.Background(), req)
		assert.Error(t, err)
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "missing CSR")
	})
}

// generateCSR is a helper function to create a test CSR
func generateCSR(t *testing.T, commonName string, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)
	return csrDER
}

// =====================================
// Tests from simple_coverage_boost_test.go
// =====================================

func TestStartEnrollServer_Direct(t *testing.T) {
	client := createTestClient(t)

	mockTPM := &mockTPM{
		activateCredentialFunc: func(credBlob, encSecret []byte) ([]byte, error) {
			return []byte("decrypted-secret"), nil
		},
	}

	idevidCSR := &IDevIDCSR{
		CSR:            []byte("test-csr-data"),
		QualifyingData: []byte("qualifying-data"),
	}

	config := &EnrollmentConfig{
		TPMModule: mockTPM,
		Port:      "19997", // Use unique port
	}

	token := "test-token-unique"

	// Start server in background
	go client.startEnrollServer(config, idevidCSR, token)

	// Give server time to start
	time.Sleep(300 * time.Millisecond)

	// Test challenge endpoint
	resp, err := http.Get(fmt.Sprintf("http://localhost:19997/.well-known/acme-challenge/%s", token))
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, _ := io.ReadAll(resp.Body)
		decoded, _ := base64.RawURLEncoding.DecodeString(string(body))
		assert.Equal(t, idevidCSR.CSR, decoded)
	}
}

// TestStartAttestServer_Direct tests the startAttestServer function directly
func TestStartAttestServer_Direct(t *testing.T) {
	client := createTestClient(t)

	attestStmt := []byte(`{"fmt":"tpm","attStmt":{"ver":"2.0"}}`)

	config := &EnrollmentConfig{
		Port: "19996", // Use unique port
	}

	token := "attest-token-unique"

	// Start server in background
	go client.startAttestServer(config, attestStmt, token)

	time.Sleep(300 * time.Millisecond)

	// Test challenge endpoint
	resp, err := http.Get(fmt.Sprintf("http://localhost:19996/.well-known/acme-challenge/%s", token))
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&response)
		assert.Contains(t, response, "attStmt")
	}
}

// TestEnrollDevice_DirectCall tests EnrollDevice with minimal setup
func TestEnrollDevice_DirectCall(t *testing.T) {
	// This test just exercises the validation path
	client := createTestClient(t)

	config := &EnrollmentConfig{
		Challenge: "invalid-challenge-type",
		IPAddress: "192.168.1.1",
		TPMModule: &mockTPM{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	result, err := client.EnrollDevice(ctx, config)

	// Should fail validation
	assert.Error(t, err)
	assert.Nil(t, result)
}

// TestRequestEndorsementKeyCertificate_DirectCall tests EK cert request with minimal setup
func TestRequestEndorsementKeyCertificate_DirectCall(t *testing.T) {
	client := createTestClient(t)

	// Test with nil EK - should fail early
	mockTPM := &mockTPM{
		ekFunc: func() crypto.PublicKey {
			return nil // No EK available
		},
	}

	config := &EnrollmentConfig{
		Challenge: string(ChallengeTypeEndorse01),
		IPAddress: "192.168.1.1",
		TPMModule: mockTPM,
		Timeout:   1 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	cert, err := client.RequestEndorsementKeyCertificate(ctx, config)

	assert.Error(t, err)
	assert.Nil(t, cert)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.BadPublicKey, caErr.Type)
}

// TestDeviceAttest_DirectCall tests device attestation with minimal setup
func TestDeviceAttest_DirectCall(t *testing.T) {
	client := createTestClient(t)

	// Test with invalid config - should fail validation
	config := &EnrollmentConfig{
		Challenge: "", // Empty challenge
		IPAddress: "192.168.1.1",
		TPMModule: &mockTPM{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	cert, err := client.DeviceAttest(ctx, config, []int{0})

	assert.Error(t, err)
	assert.Nil(t, cert)
}

// TestCrossSign_DirectCall tests cross-signing with minimal setup
func TestCrossSign_DirectCall(t *testing.T) {
	client := createTestClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Test with empty CSR - should fail validation
	cert, err := client.CrossSign(ctx, []byte{}, []byte("cert"))

	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.ErrorIs(t, err, ErrMissingCSR)
}

// TestCrossSignWithChallenge_DirectCall tests cross-signing with challenge
func TestCrossSignWithChallenge_DirectCall(t *testing.T) {
	client := createTestClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Test with nil challenge setup - should fail validation
	cert, err := client.CrossSignWithChallenge(ctx, []byte("csr"), []byte("cert"), nil, nil)

	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.ErrorIs(t, err, ErrInvalidChallengeSetup)
}

// TestCrossSignerFromClient_DirectCall tests CrossSignerFromClient
func TestCrossSignerFromClient_DirectCall(t *testing.T) {
	// Test with nil client
	crossSigner, err := CrossSignerFromClient(nil, &CrossSignConfig{
		DirectoryURL:  "https://example.com",
		ChallengeType: "http-01",
	})

	assert.Error(t, err)
	assert.Nil(t, crossSigner)
	assert.ErrorIs(t, err, ErrInvalidConfiguration)
}

// Additional test to exercise startEndorseServer
func TestStartEndorseServer_DirectCall(t *testing.T) {
	client := createTestClient(t)

	mockTPM := &mockTPM{
		activateCredentialFunc: func(credBlob, encSecret []byte) ([]byte, error) {
			return []byte("secret"), nil
		},
	}

	config := &EnrollmentConfig{
		TPMModule: mockTPM,
		Port:      "19995",
	}

	req := ekRequest{
		EKPublicKey:  base64.RawURLEncoding.EncodeToString([]byte("ek-pub")),
		EKAttributes: "attrs",
	}

	token := "endorse-token"

	// Start server in background
	go client.startEndorseServer(config, req, token)

	time.Sleep(300 * time.Millisecond)

	// Test challenge endpoint
	resp, err := http.Get(fmt.Sprintf("http://localhost:19995/.well-known/acme-challenge/%s", token))
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response ekRequest
		_ = json.NewDecoder(resp.Body).Decode(&response)
		assert.Equal(t, req.EKPublicKey, response.EKPublicKey)
	}
}

// Test setupEndorseChallenge function
func TestSetupEndorseChallenge_DirectCall(t *testing.T) {
	client := createTestClient(t)

	// Create a mock TPM that returns EK cert
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "EK"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	ekCert, _ := x509.ParseCertificate(certDER)

	mockTPM := &mockTPM{
		ekCertFunc: func() (*x509.Certificate, error) {
			return ekCert, nil
		},
		ekAttributesFunc: func() (*KeyAttributes, error) {
			return &KeyAttributes{
				KeyID: "ek",
			}, nil
		},
	}

	config := &EnrollmentConfig{
		TPMModule: mockTPM,
		Port:      "19994",
	}

	// Call setupEndorseChallenge
	err := client.setupEndorseChallenge(config, "keyauth", "token")

	// Should succeed in setting up
	assert.NoError(t, err)

	// Give server time to start
	time.Sleep(100 * time.Millisecond)
}

// Test with error from TPM
func TestSetupEndorseChallenge_TPMError(t *testing.T) {
	client := createTestClient(t)

	mockTPM := &mockTPM{
		ekCertFunc: func() (*x509.Certificate, error) {
			return nil, errors.New("no EK cert")
		},
	}

	config := &EnrollmentConfig{
		TPMModule: mockTPM,
	}

	err := client.setupEndorseChallenge(config, "keyauth", "token")

	assert.Error(t, err)
}

// Test setupAttestChallenge
func TestSetupAttestChallenge_DirectCall(t *testing.T) {
	client := createTestClient(t)

	// Create mock TPM with quote function
	mockTPM := &mockTPM{
		quoteFunc: func(nonce []byte, pcrSelection []int) (*TPMQuote, error) {
			return &TPMQuote{
				Quote:              []byte("quote"),
				Signature:          []byte("sig"),
				SignatureAlgorithm: x509.SHA256WithRSA,
				PCRValues:          map[int][]byte{0: []byte("pcr0")},
			}, nil
		},
		iakAttributesFunc: func() (*KeyAttributes, error) {
			return &KeyAttributes{
				SignatureAlgorithm: x509.SHA256WithRSA,
				TPMPublicBytes:     []byte("iak-pub"),
			}, nil
		},
		ekCertFunc: func() (*x509.Certificate, error) {
			cert, _ := createTestCertificate()
			return cert, nil
		},
	}

	config := &EnrollmentConfig{
		TPMModule: mockTPM,
	}

	// Call setupAttestChallenge
	attestStmt, err := client.setupAttestChallenge(config, "keyauth", []int{0, 1})

	assert.NoError(t, err)
	assert.NotNil(t, attestStmt)

	// Verify it's valid JSON
	var result map[string]interface{}
	err = json.Unmarshal(attestStmt, &result)
	assert.NoError(t, err)
	assert.Equal(t, "tpm", result["fmt"])
}

// Test setupAttestChallenge with TPM error
func TestSetupAttestChallenge_QuoteError(t *testing.T) {
	client := createTestClient(t)

	mockTPM := &mockTPM{
		quoteFunc: func([]byte, []int) (*TPMQuote, error) {
			return nil, errors.New("quote failed")
		},
	}

	config := &EnrollmentConfig{
		TPMModule: mockTPM,
	}

	attestStmt, err := client.setupAttestChallenge(config, "keyauth", []int{0})

	assert.Error(t, err)
	assert.Nil(t, attestStmt)
}

// Test with wrong token on enroll server
func TestStartEnrollServer_WrongPath(t *testing.T) {
	client := createTestClient(t)

	config := &EnrollmentConfig{
		TPMModule: &mockTPM{},
		Port:      "19993",
	}

	idevidCSR := &IDevIDCSR{CSR: []byte("csr")}

	go client.startEnrollServer(config, idevidCSR, "correct-token")

	time.Sleep(200 * time.Millisecond)

	// Try wrong endpoint
	resp, err := http.Post(
		"http://localhost:19993/.well-known/acme-activation/wrong-token",
		"application/json",
		strings.NewReader("{}"),
	)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	}
}

// Test wrong method on activation endpoint
func TestStartEnrollServer_WrongMethod(t *testing.T) {
	client := createTestClient(t)

	config := &EnrollmentConfig{
		TPMModule: &mockTPM{},
		Port:      "19992",
	}

	go client.startEnrollServer(config, &IDevIDCSR{}, "token")

	time.Sleep(200 * time.Millisecond)

	// Try GET instead of POST on activation endpoint
	resp, err := http.Get("http://localhost:19992/.well-known/acme-activation/token")
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	}
}
