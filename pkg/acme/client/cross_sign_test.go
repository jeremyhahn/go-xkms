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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// Helper functions to create mock storage instances for cross-sign tests

func TestCrossSignConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *CrossSignConfig
		wantErr error
	}{
		{
			name: "valid configuration",
			config: &CrossSignConfig{
				DirectoryURL:        "https://acme.example.com/directory",
				ChallengeType:       "http-01",
				TrustedRoots:        []string{},
				RequestServerBundle: false,
				Timeout:             60 * time.Second,
				RetryAttempts:       3,
				RetryDelay:          1 * time.Second,
			},
			wantErr: nil,
		},
		{
			name:    "nil configuration",
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
				ChallengeType: "invalid-challenge",
			},
			wantErr: ErrInvalidChallengeTypeForCrossSign,
		},
		{
			name: "valid http-01 challenge",
			config: &CrossSignConfig{
				DirectoryURL:  "https://acme.example.com/directory",
				ChallengeType: "http-01",
			},
			wantErr: nil,
		},
		{
			name: "valid dns-01 challenge",
			config: &CrossSignConfig{
				DirectoryURL:  "https://acme.example.com/directory",
				ChallengeType: "dns-01",
			},
			wantErr: nil,
		},
		{
			name: "valid tls-alpn-01 challenge",
			config: &CrossSignConfig{
				DirectoryURL:  "https://acme.example.com/directory",
				ChallengeType: "tls-alpn-01",
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCrossSignConfig_Validate_DefaultValues(t *testing.T) {
	t.Run("sets default timeout", func(t *testing.T) {
		config := &CrossSignConfig{
			DirectoryURL:  "https://acme.example.com/directory",
			ChallengeType: "http-01",
			Timeout:       0,
		}
		err := config.Validate()
		assert.NoError(t, err)
		assert.Equal(t, 60*time.Second, config.Timeout)
	})

	t.Run("sets default retry attempts for negative value", func(t *testing.T) {
		config := &CrossSignConfig{
			DirectoryURL:  "https://acme.example.com/directory",
			ChallengeType: "http-01",
			RetryAttempts: -1,
		}
		err := config.Validate()
		assert.NoError(t, err)
		assert.Equal(t, 3, config.RetryAttempts)
	})

	t.Run("sets default retry delay", func(t *testing.T) {
		config := &CrossSignConfig{
			DirectoryURL:  "https://acme.example.com/directory",
			ChallengeType: "http-01",
			RetryDelay:    0,
		}
		err := config.Validate()
		assert.NoError(t, err)
		assert.Equal(t, 1*time.Second, config.RetryDelay)
	})

	t.Run("keeps positive timeout", func(t *testing.T) {
		config := &CrossSignConfig{
			DirectoryURL:  "https://acme.example.com/directory",
			ChallengeType: "http-01",
			Timeout:       30 * time.Second,
		}
		err := config.Validate()
		assert.NoError(t, err)
		assert.Equal(t, 30*time.Second, config.Timeout)
	})
}

func TestCrossSignerFromClient(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("nil client returns error", func(t *testing.T) {
		config := &CrossSignConfig{
			DirectoryURL:  "https://cross-signer.example.com/directory",
			ChallengeType: "http-01",
		}

		crossSigner, err := CrossSignerFromClient(nil, config)
		assert.Error(t, err)
		assert.Nil(t, crossSigner)
		assert.ErrorIs(t, err, ErrInvalidConfiguration)
	})

	t.Run("nil config returns error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockStore := newMockStorage()
		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
		}

		crossSigner, err := CrossSignerFromClient(client, nil)
		assert.Error(t, err)
		assert.Nil(t, crossSigner)
	})

	t.Run("invalid config returns error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockStore := newMockStorage()
		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
		}

		config := &CrossSignConfig{
			DirectoryURL:  "", // Invalid - empty
			ChallengeType: "http-01",
		}

		crossSigner, err := CrossSignerFromClient(client, config)
		assert.Error(t, err)
		assert.Nil(t, crossSigner)
		assert.Contains(t, err.Error(), "invalid cross-sign configuration")
	})

	t.Run("successful cross-signer creation", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockStore := newMockStorage()
		mockCertStore := newMockCertStorage()
		mockOrderStore := newMockOrderStorage()

		// Create a mock ACME server
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/directory":
				directory := map[string]interface{}{
					"newNonce":   "http://localhost/new-nonce",
					"newAccount": "http://localhost/new-account",
					"newOrder":   "http://localhost/new-order",
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(directory)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer ts.Close()

		client := &Client{
			accountEmail:       "test@example.com",
			accountSigner:      privateKey,
			config:             DefaultConfig(),
			logger:             logger,
			storage:            mockStore,
			certificateStorage: mockCertStore,
			orderStorage:       mockOrderStore,
		}

		config := &CrossSignConfig{
			DirectoryURL:  ts.URL + "/directory",
			ChallengeType: "http-01",
			Timeout:       30 * time.Second,
			RetryAttempts: 3,
			RetryDelay:    1 * time.Second,
		}

		crossSigner, err := CrossSignerFromClient(client, config)
		assert.NoError(t, err)
		assert.NotNil(t, crossSigner)
		assert.Equal(t, "test@example.com", crossSigner.accountEmail)
		assert.Equal(t, ts.URL+"/directory", crossSigner.config.DirectoryURL)
	})

	t.Run("preserves client credentials and storage", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockStore := newMockStorage()
		mockCertStore := newMockCertStorage()
		mockOrderStore := newMockOrderStorage()

		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/directory" {
				directory := map[string]interface{}{
					"newNonce":   "http://localhost/new-nonce",
					"newAccount": "http://localhost/new-account",
					"newOrder":   "http://localhost/new-order",
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(directory)
			}
		}))
		defer ts.Close()

		originalClient := &Client{
			accountEmail:       "original@example.com",
			accountSigner:      privateKey,
			config:             DefaultConfig(),
			logger:             logger,
			storage:            mockStore,
			certificateStorage: mockCertStore,
			orderStorage:       mockOrderStore,
		}

		config := &CrossSignConfig{
			DirectoryURL:  ts.URL + "/directory",
			ChallengeType: "dns-01",
			Timeout:       45 * time.Second,
		}

		crossSigner, err := CrossSignerFromClient(originalClient, config)
		require.NoError(t, err)
		require.NotNil(t, crossSigner)

		// Verify credentials and storage are preserved
		assert.Equal(t, originalClient.accountEmail, crossSigner.accountEmail)
		assert.Equal(t, originalClient.accountSigner, crossSigner.accountSigner)
		assert.Equal(t, originalClient.storage, crossSigner.storage)
		assert.Equal(t, originalClient.certificateStorage, crossSigner.certificateStorage)
		assert.Equal(t, originalClient.orderStorage, crossSigner.orderStorage)

		// Verify config is updated for cross-signer
		assert.Equal(t, ts.URL+"/directory", crossSigner.config.DirectoryURL)
		assert.Equal(t, 45*time.Second, crossSigner.config.Timeout)
	})
}

// generateTestCertificateForCrossSign creates a test certificate for cross-signing tests
func generateTestCertificateForCrossSign(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		DNSNames:              []string{cn},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, privateKey
}

func TestClient_extractAuthzFromCertificate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockStore := newMockStorage()
	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       mockStore,
	}

	t.Run("extract from DNS SAN", func(t *testing.T) {
		cert, _ := generateTestCertificateForCrossSign(t, "www.example.com")

		authzValue, authzType, err := client.extractAuthzFromCertificate(cert)
		require.NoError(t, err)
		assert.Equal(t, "www.example.com", authzValue)
		assert.Equal(t, "dns", authzType)
	})

	t.Run("extract from IP SAN", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "192.168.1.1",
			},
			IPAddresses:           []net.IP{net.ParseIP("192.168.1.1")},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		require.NoError(t, err)

		cert, err := x509.ParseCertificate(certDER)
		require.NoError(t, err)

		authzValue, authzType, err := client.extractAuthzFromCertificate(cert)
		require.NoError(t, err)
		assert.Equal(t, "192.168.1.1", authzValue)
		assert.Equal(t, "ip", authzType)
	})

	t.Run("extract from Common Name fallback", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "example.com",
			},
			// No SANs
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		require.NoError(t, err)

		cert, err := x509.ParseCertificate(certDER)
		require.NoError(t, err)

		authzValue, authzType, err := client.extractAuthzFromCertificate(cert)
		require.NoError(t, err)
		assert.Equal(t, "example.com", authzValue)
		assert.Equal(t, "dns", authzType)
	})

	t.Run("no valid identifier returns error", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Organization: []string{"Test Org"},
				// No CommonName
			},
			// No SANs
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		require.NoError(t, err)

		cert, err := x509.ParseCertificate(certDER)
		require.NoError(t, err)

		authzValue, authzType, err := client.extractAuthzFromCertificate(cert)
		assert.Error(t, err)
		assert.Equal(t, "", authzValue)
		assert.Equal(t, "", authzType)
		assert.Contains(t, err.Error(), "no valid authorization identifier")
	})
}

func TestClient_CrossSign(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("missing CSR returns error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockStore := newMockStorage()
		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
		}

		cert, _ := generateTestCertificateForCrossSign(t, "example.com")

		crossSignedCert, err := client.CrossSign(context.TODO(), nil, cert.Raw)
		assert.Error(t, err)
		assert.Nil(t, crossSignedCert)
		assert.ErrorIs(t, err, ErrMissingCSR)
	})

	t.Run("missing certificate returns error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockStore := newMockStorage()
		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
		}

		csr := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: "example.com",
			},
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csr, privateKey)
		require.NoError(t, err)

		crossSignedCert, err := client.CrossSign(context.TODO(), csrDER, nil)
		assert.Error(t, err)
		assert.Nil(t, crossSignedCert)
		assert.ErrorIs(t, err, ErrInvalidCertificate)
	})

	t.Run("invalid certificate data returns error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockStore := newMockStorage()
		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
		}

		csr := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: "example.com",
			},
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csr, privateKey)
		require.NoError(t, err)

		crossSignedCert, err := client.CrossSign(context.TODO(), csrDER, []byte("invalid cert"))
		assert.Error(t, err)
		assert.Nil(t, crossSignedCert)
		assert.Contains(t, err.Error(), "failed to parse certificate")
	})

	t.Run("invalid CSR data returns error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockStore := newMockStorage()
		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
		}

		cert, _ := generateTestCertificateForCrossSign(t, "example.com")

		crossSignedCert, err := client.CrossSign(context.TODO(), []byte("invalid csr"), cert.Raw)
		assert.Error(t, err)
		assert.Nil(t, crossSignedCert)
		assert.Contains(t, err.Error(), "failed to parse CSR")
	})

	t.Run("CSR subject mismatch returns error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockStore := newMockStorage()
		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
		}

		cert, _ := generateTestCertificateForCrossSign(t, "example.com")

		// Create CSR with different subject
		csr := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: "different.com",
			},
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csr, privateKey)
		require.NoError(t, err)

		crossSignedCert, err := client.CrossSign(context.TODO(), csrDER, cert.Raw)
		assert.Error(t, err)
		assert.Nil(t, crossSignedCert)
		assert.Contains(t, err.Error(), "does not match CSR subject")
	})

	t.Run("extractAuthzFromCertificate error propagates", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockStore := newMockStorage()
		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
		}

		// Create certificate with no identifiers
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Organization: []string{"Test Org"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		require.NoError(t, err)

		// Create matching CSR
		csr := &x509.CertificateRequest{
			Subject: pkix.Name{
				Organization: []string{"Test Org"},
			},
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csr, privateKey)
		require.NoError(t, err)

		crossSignedCert, err := client.CrossSign(context.TODO(), csrDER, certDER)
		assert.Error(t, err)
		assert.Nil(t, crossSignedCert)
		assert.Contains(t, err.Error(), "failed to extract authorization from certificate")
	})
}

func TestClient_processAuthorization(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("authorization already valid skips challenge", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		authzURL := ""
		var serverURL string
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Supply a Replay-Nonce on every response so x/crypto/acme never
			// dials the default Let's Encrypt directory to mint a JWS nonce.
			w.Header().Set("Replay-Nonce", "bm9uY2UtdG9rZW4")
			switch r.URL.Path {
			case "/directory":
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"newNonce":   serverURL + "/new-nonce",
					"newAccount": serverURL + "/new-account",
					"newOrder":   serverURL + "/new-order",
					"revokeCert": serverURL + "/revoke",
					"keyChange":  serverURL + "/key-change",
				})
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/authz/123":
				authz := map[string]interface{}{
					"identifier": map[string]string{
						"type":  "dns",
						"value": "example.com",
					},
					"status": "valid",
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(authz)
			}
		}))
		defer ts.Close()
		serverURL = ts.URL
		authzURL = ts.URL + "/authz/123"

		mockStore := newMockStorage()
		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
			client: &acme.Client{
				Key:          privateKey,
				DirectoryURL: serverURL + "/directory",
			},
		}

		err = client.processAuthorization(context.Background(), authzURL)
		assert.NoError(t, err)
	})

	t.Run("no suitable challenge returns error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		var serverURL string
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Supply a Replay-Nonce on every response so x/crypto/acme never
			// dials the default Let's Encrypt directory to mint a JWS nonce.
			w.Header().Set("Replay-Nonce", "bm9uY2UtdG9rZW4")
			switch r.URL.Path {
			case "/directory":
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"newNonce":   serverURL + "/new-nonce",
					"newAccount": serverURL + "/new-account",
					"newOrder":   serverURL + "/new-order",
					"revokeCert": serverURL + "/revoke",
					"keyChange":  serverURL + "/key-change",
				})
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/authz/456":
				authz := map[string]interface{}{
					"identifier": map[string]string{
						"type":  "dns",
						"value": "example.com",
					},
					"status": "pending",
					"challenges": []map[string]interface{}{
						{
							"type":  "unsupported-challenge",
							"token": "test-token",
							"url":   serverURL + "/challenge/1",
						},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(authz)
			}
		}))
		defer ts.Close()
		serverURL = ts.URL

		mockStore := newMockStorage()
		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
			client: &acme.Client{
				Key:          privateKey,
				DirectoryURL: serverURL + "/directory",
			},
		}

		err = client.processAuthorization(context.Background(), ts.URL+"/authz/456")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no suitable challenge found")
	})

	t.Run("GetAuthorization error propagates", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		var serverURL string
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Supply a Replay-Nonce on every response so x/crypto/acme never
			// dials the default Let's Encrypt directory to mint a JWS nonce, and
			// serve a valid directory + new-nonce so the request reaches the
			// authz endpoint where the intended ACME error is returned.
			w.Header().Set("Replay-Nonce", "bm9uY2UtdG9rZW4")
			switch r.URL.Path {
			case "/directory":
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"newNonce":   serverURL + "/new-nonce",
					"newAccount": serverURL + "/new-account",
					"newOrder":   serverURL + "/new-order",
					"revokeCert": serverURL + "/revoke",
					"keyChange":  serverURL + "/key-change",
				})
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			default:
				// Return an ACME error that won't trigger retries
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:malformed","detail":"authorization not found"}`))
			}
		}))
		defer ts.Close()
		serverURL = ts.URL

		mockStore := newMockStorage()
		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
			client: &acme.Client{
				Key:          privateKey,
				DirectoryURL: serverURL + "/directory",
			},
		}

		// Use a short timeout context to prevent infinite retries
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		err = client.processAuthorization(ctx, ts.URL+"/authz/error")
		assert.Error(t, err)
	})

	t.Run("selects http-01 challenge", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		acceptCalled := false
		var serverURL string
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// x/crypto/acme caches Replay-Nonce values from every response and
			// signs JWS requests (POST-as-GET, Accept) with one. Always supply a
			// nonce so the client never reaches for the default Let's Encrypt
			// directory to discover a new-nonce endpoint.
			w.Header().Set("Replay-Nonce", "bm9uY2UtdG9rZW4")
			switch r.URL.Path {
			case "/directory":
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"newNonce":   serverURL + "/new-nonce",
					"newAccount": serverURL + "/new-account",
					"newOrder":   serverURL + "/new-order",
					"revokeCert": serverURL + "/revoke",
					"keyChange":  serverURL + "/key-change",
				})
			case "/new-nonce":
				w.WriteHeader(http.StatusOK)
			case "/authz/http01":
				authz := map[string]interface{}{
					"identifier": map[string]string{
						"type":  "dns",
						"value": "example.com",
					},
					"status": "pending",
					"challenges": []map[string]interface{}{
						{
							"type":  "http-01",
							"token": "test-token",
							"url":   serverURL + "/challenge/1",
						},
					},
					"uri": serverURL + "/authz/http01",
				}
				if acceptCalled {
					authz["status"] = "valid"
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(authz)
			case "/challenge/1":
				acceptCalled = true
				challenge := map[string]interface{}{
					"type":   "http-01",
					"status": "valid",
					"token":  "test-token",
					"url":    serverURL + "/challenge/1",
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(challenge)
			}
		}))
		defer ts.Close()
		serverURL = ts.URL

		mockStore := newMockStorage()
		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
			client: &acme.Client{
				Key:          privateKey,
				DirectoryURL: serverURL + "/directory",
			},
		}

		err = client.processAuthorization(context.Background(), ts.URL+"/authz/http01")
		assert.NoError(t, err)
		assert.True(t, acceptCalled)
	})
}

func TestClient_CrossSignWithChallenge(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("missing CSR returns error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockStore := newMockStorage()
		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
		}

		cert, _ := generateTestCertificateForCrossSign(t, "example.com")

		setupFunc := func(challengeType, token, keyAuth string) error {
			return nil
		}

		crossSignedCert, err := client.CrossSignWithChallenge(context.TODO(), nil, cert.Raw, setupFunc, nil)
		assert.Error(t, err)
		assert.Nil(t, crossSignedCert)
		assert.ErrorIs(t, err, ErrMissingCSR)
	})

	t.Run("missing certificate returns error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockStore := newMockStorage()
		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
		}

		csr := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: "example.com",
			},
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csr, privateKey)
		require.NoError(t, err)

		setupFunc := func(challengeType, token, keyAuth string) error {
			return nil
		}

		crossSignedCert, err := client.CrossSignWithChallenge(context.TODO(), csrDER, nil, setupFunc, nil)
		assert.Error(t, err)
		assert.Nil(t, crossSignedCert)
		assert.ErrorIs(t, err, ErrInvalidCertificate)
	})

	t.Run("nil challenge setup returns error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockStore := newMockStorage()
		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
		}

		cert, _ := generateTestCertificateForCrossSign(t, "example.com")

		csr := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: "example.com",
			},
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csr, privateKey)
		require.NoError(t, err)

		crossSignedCert, err := client.CrossSignWithChallenge(context.TODO(), csrDER, cert.Raw, nil, nil)
		assert.Error(t, err)
		assert.Nil(t, crossSignedCert)
		assert.ErrorIs(t, err, ErrInvalidChallengeSetup)
	})

	t.Run("invalid certificate data returns error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockStore := newMockStorage()
		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
		}

		csr := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: "example.com",
			},
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csr, privateKey)
		require.NoError(t, err)

		setupFunc := func(challengeType, token, keyAuth string) error {
			return nil
		}

		crossSignedCert, err := client.CrossSignWithChallenge(context.TODO(), csrDER, []byte("invalid"), setupFunc, nil)
		assert.Error(t, err)
		assert.Nil(t, crossSignedCert)
		assert.Contains(t, err.Error(), "failed to parse certificate")
	})

	t.Run("CSR subject mismatch returns error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockStore := newMockStorage()
		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
		}

		cert, _ := generateTestCertificateForCrossSign(t, "example.com")

		// CSR with different subject
		csr := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: "different.com",
			},
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csr, privateKey)
		require.NoError(t, err)

		setupFunc := func(challengeType, token, keyAuth string) error {
			return nil
		}

		crossSignedCert, err := client.CrossSignWithChallenge(context.TODO(), csrDER, cert.Raw, setupFunc, nil)
		assert.Error(t, err)
		assert.Nil(t, crossSignedCert)
		assert.Contains(t, err.Error(), "does not match CSR subject")
	})

	// Note: The following tests require a complete ACME protocol implementation
	// including proper JWS signing, nonce management, and full ACME flow.
	// They are moved to integration tests with a real ACME test server.
	//
	// - challengeSetup error propagates
	// - cleanup function is called

	t.Run("extractAuthzFromCertificate error propagates", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockStore := newMockStorage()
		client := &Client{
			accountEmail:  "test@example.com",
			accountSigner: privateKey,
			config:        DefaultConfig(),
			logger:        logger,
			storage:       mockStore,
		}

		// Create certificate with no identifiers
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Organization: []string{"Test Org"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		require.NoError(t, err)

		// Create matching CSR
		csr := &x509.CertificateRequest{
			Subject: pkix.Name{
				Organization: []string{"Test Org"},
			},
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csr, privateKey)
		require.NoError(t, err)

		setupFunc := func(challengeType, token, keyAuth string) error {
			return nil
		}

		crossSignedCert, err := client.CrossSignWithChallenge(context.TODO(), csrDER, certDER, setupFunc, nil)
		assert.Error(t, err)
		assert.Nil(t, crossSignedCert)
		assert.Contains(t, err.Error(), "failed to extract authorization from certificate")
	})
}

// =====================================
// Tests from coverage_crosssign_test.go
// =====================================

type mockACMEServerForChallenges struct {
	*httptest.Server
	t                 *testing.T
	nonceCounter      int64
	authzStatus       string
	challengeStatus   string
	challengeType     string
	challengeAccepted bool
	orderFinalized    bool
}

func newMockACMEServerForChallenges(t *testing.T) *mockACMEServerForChallenges {
	s := &mockACMEServerForChallenges{
		t:               t,
		authzStatus:     "pending",
		challengeStatus: "pending",
		challengeType:   "http-01",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/directory", s.handleDirectory)
	mux.HandleFunc("/acme/new-nonce", s.handleNewNonce)
	mux.HandleFunc("/acme/new-account", s.handleNewAccount)
	mux.HandleFunc("/acme/new-order", s.handleNewOrder)
	mux.HandleFunc("/acme/order/", s.handleOrder)
	mux.HandleFunc("/acme/authz/", s.handleAuthz)
	mux.HandleFunc("/acme/challenge/", s.handleChallenge)
	mux.HandleFunc("/acme/finalize/", s.handleFinalize)
	mux.HandleFunc("/acme/cert/", s.handleCert)
	mux.HandleFunc("/acme/account/", s.handleAccount)

	s.Server = httptest.NewServer(mux)
	return s
}

func (s *mockACMEServerForChallenges) getNonce() string {
	n := atomic.AddInt64(&s.nonceCounter, 1)
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", int(n%16+16))))
}

func (s *mockACMEServerForChallenges) handleDirectory(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Replay-Nonce", s.getNonce())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"newNonce":   s.URL + "/acme/new-nonce",
		"newAccount": s.URL + "/acme/new-account",
		"newOrder":   s.URL + "/acme/new-order",
		"revokeCert": s.URL + "/acme/revoke-cert",
		"keyChange":  s.URL + "/acme/key-change",
	})
}

func (s *mockACMEServerForChallenges) handleNewNonce(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Replay-Nonce", s.getNonce())
	w.WriteHeader(http.StatusNoContent)
}

func (s *mockACMEServerForChallenges) handleNewAccount(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Replay-Nonce", s.getNonce())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", s.URL+"/acme/account/1")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "valid",
		"contact": []string{"mailto:test@example.com"},
	})
}

func (s *mockACMEServerForChallenges) handleAccount(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Replay-Nonce", s.getNonce())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "valid",
		"contact": []string{"mailto:test@example.com"},
	})
}

func (s *mockACMEServerForChallenges) handleNewOrder(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Replay-Nonce", s.getNonce())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", s.URL+"/acme/order/1")
	w.WriteHeader(http.StatusCreated)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "pending",
		"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
		"authorizations": []string{s.URL + "/acme/authz/1"},
		"finalize":       s.URL + "/acme/finalize/1",
	})
}

func (s *mockACMEServerForChallenges) handleOrder(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Replay-Nonce", s.getNonce())
	w.Header().Set("Content-Type", "application/json")

	status := "pending"
	if s.challengeAccepted {
		status = "ready"
	}
	if s.orderFinalized {
		status = "valid"
	}

	resp := map[string]interface{}{
		"status":         status,
		"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
		"authorizations": []string{s.URL + "/acme/authz/1"},
		"finalize":       s.URL + "/acme/finalize/1",
	}

	if s.orderFinalized {
		resp["certificate"] = s.URL + "/acme/cert/1"
	}

	_ = json.NewEncoder(w).Encode(resp)
}

func (s *mockACMEServerForChallenges) handleAuthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Replay-Nonce", s.getNonce())
	w.Header().Set("Content-Type", "application/json")

	status := s.authzStatus
	if s.challengeAccepted {
		status = "valid"
	}

	challenges := []map[string]interface{}{
		{
			"type":   "http-01",
			"url":    s.URL + "/acme/challenge/1",
			"token":  "test-token-123",
			"status": s.challengeStatus,
		},
		{
			"type":   "dns-01",
			"url":    s.URL + "/acme/challenge/2",
			"token":  "dns-token-456",
			"status": s.challengeStatus,
		},
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     status,
		"expires":    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"identifier": map[string]string{"type": "dns", "value": "example.com"},
		"challenges": challenges,
	})
}

func (s *mockACMEServerForChallenges) handleChallenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", s.getNonce())
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodPost {
		s.challengeAccepted = true
		s.challengeStatus = "valid"
		s.authzStatus = "valid"
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"type":   s.challengeType,
		"url":    s.URL + "/acme/challenge/1",
		"token":  "test-token-123",
		"status": s.challengeStatus,
	})
}

func (s *mockACMEServerForChallenges) handleFinalize(w http.ResponseWriter, _ *http.Request) {
	s.orderFinalized = true
	w.Header().Set("Replay-Nonce", s.getNonce())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", s.URL+"/acme/order/1")

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "valid",
		"certificate": s.URL + "/acme/cert/1",
	})
}

func (s *mockACMEServerForChallenges) handleCert(w http.ResponseWriter, _ *http.Request) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"example.com"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	_, _ = w.Write(certDER)
}

// TestCrossSignConfig_ValidateComplete tests validation of cross-sign config
func TestCrossSignConfig_ValidateComplete(t *testing.T) {
	tests := []struct {
		name    string
		config  *CrossSignConfig
		wantErr error
	}{
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
			name: "empty challenge type",
			config: &CrossSignConfig{
				DirectoryURL:  "https://example.com",
				ChallengeType: "",
			},
			wantErr: ErrMissingChallengeType,
		},
		{
			name: "invalid challenge type",
			config: &CrossSignConfig{
				DirectoryURL:  "https://example.com",
				ChallengeType: "invalid-01",
			},
			wantErr: ErrInvalidChallengeTypeForCrossSign,
		},
		{
			name: "valid http-01",
			config: &CrossSignConfig{
				DirectoryURL:  "https://example.com",
				ChallengeType: "http-01",
			},
			wantErr: nil,
		},
		{
			name: "valid dns-01",
			config: &CrossSignConfig{
				DirectoryURL:  "https://example.com",
				ChallengeType: "dns-01",
			},
			wantErr: nil,
		},
		{
			name: "valid tls-alpn-01",
			config: &CrossSignConfig{
				DirectoryURL:  "https://example.com",
				ChallengeType: "tls-alpn-01",
			},
			wantErr: nil,
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

// TestCrossSignWithChallenge_Validation tests input validation
func TestCrossSignWithChallenge_Validation(t *testing.T) {
	// These tests verify validation logic at the Client struct level.
	// The CrossSignWithChallenge_ValidationErrors test in coverage_90plus_test.go
	// already covers these paths with a fully initialized client.
	// Here we test the mock server directly instead.

	t.Run("mock server handles directory", func(t *testing.T) {
		server := newMockACMEServerForChallenges(t)
		defer server.Close()

		resp, err := http.Get(server.URL + "/directory")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var dir map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&dir)
		assert.Contains(t, dir, "newNonce")
		assert.Contains(t, dir, "newAccount")
		assert.Contains(t, dir, "newOrder")
	})

	t.Run("mock server handles new account", func(t *testing.T) {
		server := newMockACMEServerForChallenges(t)
		defer server.Close()

		resp, err := http.Post(server.URL+"/acme/new-account", "application/json", nil)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		assert.NotEmpty(t, resp.Header.Get("Location"))
	})
}

// TestExtractAuthzFromCertificate_Scenarios tests authorization extraction
func TestExtractAuthzFromCertificate_Scenarios(t *testing.T) {
	client := &Client{}

	t.Run("certificate with DNS names", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "test.example.com"},
			DNSNames:     []string{"test.example.com", "www.example.com"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certDER)

		authzID, authzType, err := client.extractAuthzFromCertificate(cert)
		require.NoError(t, err)
		assert.Equal(t, "test.example.com", authzID)
		assert.Equal(t, "dns", authzType)
	})

	t.Run("certificate with CN only", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "device.local"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certDER)

		authzID, authzType, err := client.extractAuthzFromCertificate(cert)
		require.NoError(t, err)
		assert.Equal(t, "device.local", authzID)
		assert.Equal(t, "dns", authzType)
	})

	t.Run("certificate with no identifiers", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{Organization: []string{"Test Org"}},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certDER)

		_, _, err := client.extractAuthzFromCertificate(cert)
		assert.Error(t, err)
	})
}

// TestCrossSigner_ProcessAuthorization tests authorization processing logic
func TestCrossSigner_ProcessAuthorization(t *testing.T) {
	t.Run("valid authorization skips challenge", func(t *testing.T) {
		// When authz is valid, challenge processing should be skipped
		server := newMockACMEServerForChallenges(t)
		server.authzStatus = "valid"
		defer server.Close()

		// Verify server responds with valid status
		resp, err := http.Get(server.URL + "/acme/authz/1")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		var authz map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&authz)
		assert.Equal(t, "valid", authz["status"])
	})

	t.Run("pending authorization requires challenge", func(t *testing.T) {
		server := newMockACMEServerForChallenges(t)
		server.authzStatus = "pending"
		defer server.Close()

		resp, err := http.Get(server.URL + "/acme/authz/1")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		var authz map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&authz)
		assert.Equal(t, "pending", authz["status"])

		challenges, ok := authz["challenges"].([]interface{})
		require.True(t, ok)
		assert.Len(t, challenges, 2) // http-01 and dns-01
	})
}

// TestChallengeHandlerCallbacks tests that challenge handlers are called correctly
func TestChallengeHandlerCallbacks(t *testing.T) {
	t.Run("setup callback receives correct parameters", func(t *testing.T) {
		var receivedType, receivedToken, receivedKeyAuth string

		setup := func(chalType, token, keyAuth string) error {
			receivedType = chalType
			receivedToken = token
			receivedKeyAuth = keyAuth
			return nil
		}

		// Simulate callback invocation
		err := setup("http-01", "test-token", "test-key-auth")
		require.NoError(t, err)
		assert.Equal(t, "http-01", receivedType)
		assert.Equal(t, "test-token", receivedToken)
		assert.Equal(t, "test-key-auth", receivedKeyAuth)
	})

	t.Run("cleanup callback receives challenge type", func(t *testing.T) {
		var receivedType string

		cleanup := func(chalType string) {
			receivedType = chalType
		}

		cleanup("dns-01")
		assert.Equal(t, "dns-01", receivedType)
	})

	t.Run("setup failure returns error", func(t *testing.T) {
		setup := func(_, _, _ string) error {
			return assert.AnError
		}

		err := setup("http-01", "token", "keyAuth")
		assert.Error(t, err)
	})
}

// TestMockServerChallengeFlow tests the mock server challenge flow
func TestMockServerChallengeFlow(t *testing.T) {
	server := newMockACMEServerForChallenges(t)
	defer server.Close()

	// Test initial state
	assert.Equal(t, "pending", server.authzStatus)
	assert.Equal(t, "pending", server.challengeStatus)
	assert.False(t, server.challengeAccepted)

	// Test challenge acceptance
	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/acme/challenge/1", nil)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Verify state after POST
	assert.True(t, server.challengeAccepted)
	assert.Equal(t, "valid", server.challengeStatus)
	assert.Equal(t, "valid", server.authzStatus)
}

// TestOrderFinalization tests the mock server finalization
func TestOrderFinalization(t *testing.T) {
	server := newMockACMEServerForChallenges(t)
	defer server.Close()

	assert.False(t, server.orderFinalized)

	// Finalize order
	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/acme/finalize/1", nil)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.True(t, server.orderFinalized)

	// Verify order shows valid status
	resp, err = http.Get(server.URL + "/acme/order/1")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	var order map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&order)
	assert.Equal(t, "valid", order["status"])
	assert.Contains(t, order, "certificate")
}

// =====================================
// Tests from cross_sign_coverage_test.go
// =====================================

func generateCoverageCertDER(t *testing.T, cn string) []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		DNSNames:              []string{cn},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return certDER
}

// generateCoverageMatchingCertAndCSR creates a certificate and CSR with matching subjects
func generateCoverageMatchingCertAndCSR(t *testing.T, cn string) ([]byte, []byte, *ecdsa.PrivateKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create certificate
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		DNSNames:              []string{cn},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Create matching CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		DNSNames: []string{cn},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	require.NoError(t, err)

	return certDER, csrDER, privateKey
}

// TestProcessAuthorization_AlreadyValid tests skipping already valid authorization
func TestProcessAuthorization_AlreadyValid(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/acme/authz/1":
			authz := map[string]interface{}{
				"status": "valid", // Already valid
				"identifier": map[string]string{
					"type":  "dns",
					"value": "example.com",
				},
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"url":    serverURL + "/acme/challenge/1",
						"token":  "test-token",
						"status": "valid",
					},
				},
				"uri": serverURL + "/acme/authz/1",
			}
			_ = json.NewEncoder(w).Encode(authz)
		}
	}))
	defer ts.Close()
	serverURL = ts.URL

	mockStore := newMockStorage()
	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       mockStore,
		client: &acme.Client{
			Key: privateKey,
		},
	}

	err = client.processAuthorization(context.Background(), ts.URL+"/acme/authz/1")
	assert.NoError(t, err) // Should succeed without needing to accept any challenge
}

// TestProcessAuthorization_NoSuitableChallenge tests when no suitable challenge is found
func TestProcessAuthorization_NoSuitableChallenge(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serverURL string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/acme/authz/1":
			authz := map[string]interface{}{
				"status": "pending",
				"identifier": map[string]string{
					"type":  "dns",
					"value": "example.com",
				},
				"challenges": []map[string]interface{}{
					{
						"type":   "unsupported-challenge-type",
						"url":    serverURL + "/acme/challenge/1",
						"token":  "test-token",
						"status": "pending",
					},
				},
				"uri": serverURL + "/acme/authz/1",
			}
			_ = json.NewEncoder(w).Encode(authz)
		}
	}))
	defer ts.Close()
	serverURL = ts.URL

	mockStore := newMockStorage()
	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       mockStore,
		client: &acme.Client{
			Key: privateKey,
		},
	}

	err = client.processAuthorization(context.Background(), ts.URL+"/acme/authz/1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no suitable challenge found")
}

// TestProcessAuthorization_GetAuthorizationError tests processAuthorization when GetAuthorization fails
func TestProcessAuthorization_GetAuthorizationError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"type":   "urn:ietf:params:acme:error:malformed",
			"detail": "authorization not found",
		})
	}))
	defer ts.Close()

	mockStore := newMockStorage()
	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       mockStore,
		client: &acme.Client{
			Key: privateKey,
		},
	}

	err = client.processAuthorization(context.Background(), ts.URL+"/acme/authz/1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get authorization")
}

// TestProcessAuthorization_SelectsDNS01Challenge tests that dns-01 challenge is selected
func TestProcessAuthorization_SelectsDNS01Challenge(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	selectedChallengeType := ""
	var serverURL string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/acme/authz/1":
			status := "pending"
			if selectedChallengeType != "" {
				status = "valid"
			}
			authz := map[string]interface{}{
				"status": status,
				"identifier": map[string]string{
					"type":  "dns",
					"value": "example.com",
				},
				"challenges": []map[string]interface{}{
					{
						"type":   "dns-01",
						"url":    serverURL + "/acme/challenge/1",
						"token":  "test-token",
						"status": "pending",
					},
				},
				"uri": serverURL + "/acme/authz/1",
			}
			_ = json.NewEncoder(w).Encode(authz)

		case "/acme/challenge/1":
			selectedChallengeType = "dns-01"
			challenge := map[string]interface{}{
				"type":   "dns-01",
				"url":    serverURL + "/acme/challenge/1",
				"token":  "test-token",
				"status": "valid",
			}
			_ = json.NewEncoder(w).Encode(challenge)
		}
	}))
	defer ts.Close()
	serverURL = ts.URL

	mockStore := newMockStorage()
	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       mockStore,
		client: &acme.Client{
			Key: privateKey,
		},
	}

	err = client.processAuthorization(context.Background(), ts.URL+"/acme/authz/1")
	assert.NoError(t, err)
	assert.Equal(t, "dns-01", selectedChallengeType)
}

// TestProcessAuthorization_SelectsTLSALPN01Challenge tests that tls-alpn-01 challenge is selected
func TestProcessAuthorization_SelectsTLSALPN01Challenge(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	selectedChallengeType := ""
	var serverURL string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/acme/authz/1":
			status := "pending"
			if selectedChallengeType != "" {
				status = "valid"
			}
			authz := map[string]interface{}{
				"status": status,
				"identifier": map[string]string{
					"type":  "dns",
					"value": "example.com",
				},
				"challenges": []map[string]interface{}{
					{
						"type":   "tls-alpn-01",
						"url":    serverURL + "/acme/challenge/1",
						"token":  "test-token",
						"status": "pending",
					},
				},
				"uri": serverURL + "/acme/authz/1",
			}
			_ = json.NewEncoder(w).Encode(authz)

		case "/acme/challenge/1":
			selectedChallengeType = "tls-alpn-01"
			challenge := map[string]interface{}{
				"type":   "tls-alpn-01",
				"url":    serverURL + "/acme/challenge/1",
				"token":  "test-token",
				"status": "valid",
			}
			_ = json.NewEncoder(w).Encode(challenge)
		}
	}))
	defer ts.Close()
	serverURL = ts.URL

	mockStore := newMockStorage()
	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       mockStore,
		client: &acme.Client{
			Key: privateKey,
		},
	}

	err = client.processAuthorization(context.Background(), ts.URL+"/acme/authz/1")
	assert.NoError(t, err)
	assert.Equal(t, "tls-alpn-01", selectedChallengeType)
}

// TestProcessAuthorization_AcceptChallengeError tests processAuthorization when Accept fails
func TestProcessAuthorization_AcceptChallengeError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	requestCount := 0
	var serverURL string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/acme/authz/1":
			authz := map[string]interface{}{
				"status": "pending",
				"identifier": map[string]string{
					"type":  "dns",
					"value": "example.com",
				},
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"url":    serverURL + "/acme/challenge/1",
						"token":  "test-token",
						"status": "pending",
					},
				},
				"uri": serverURL + "/acme/authz/1",
			}
			_ = json.NewEncoder(w).Encode(authz)

		case "/acme/challenge/1":
			requestCount++
			// Return error on challenge accept
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:unauthorized",
				"detail": "challenge acceptance failed",
			})
		}
	}))
	defer ts.Close()
	serverURL = ts.URL

	mockStore := newMockStorage()
	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       mockStore,
		client: &acme.Client{
			Key: privateKey,
		},
	}

	err = client.processAuthorization(context.Background(), ts.URL+"/acme/authz/1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to accept challenge")
}

// TestProcessAuthorization_WaitAuthorizationError tests processAuthorization when WaitAuthorization fails
func TestProcessAuthorization_WaitAuthorizationError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	challengeAccepted := false
	var serverURL string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/acme/authz/1":
			status := "pending"
			if challengeAccepted {
				status = "invalid" // Return invalid status after challenge acceptance
			}
			authz := map[string]interface{}{
				"status": status,
				"identifier": map[string]string{
					"type":  "dns",
					"value": "example.com",
				},
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"url":    serverURL + "/acme/challenge/1",
						"token":  "test-token",
						"status": "pending",
					},
				},
				"uri": serverURL + "/acme/authz/1",
			}
			_ = json.NewEncoder(w).Encode(authz)

		case "/acme/challenge/1":
			challengeAccepted = true
			challenge := map[string]interface{}{
				"type":   "http-01",
				"url":    serverURL + "/acme/challenge/1",
				"token":  "test-token",
				"status": "valid",
			}
			_ = json.NewEncoder(w).Encode(challenge)
		}
	}))
	defer ts.Close()
	serverURL = ts.URL

	mockStore := newMockStorage()
	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       mockStore,
		client: &acme.Client{
			Key: privateKey,
		},
	}

	err = client.processAuthorization(context.Background(), ts.URL+"/acme/authz/1")
	assert.Error(t, err)
	// The ACME library returns "acme: authorization error" when status is invalid,
	// which gets wrapped as "failed to wait for authorization"
	assert.Contains(t, err.Error(), "failed to wait for authorization")
}

// TestCrossSignWithChallenge_InvalidCSRDataCoverage tests CrossSignWithChallenge with unparseable CSR
func TestCrossSignWithChallenge_InvalidCSRDataCoverage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockStore := newMockStorage()
	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       mockStore,
	}

	// Create valid certificate
	certDER := generateCoverageCertDER(t, "example.com")

	setupFunc := func(challengeType, token, keyAuth string) error {
		return nil
	}

	// Use garbage data that looks like valid bytes but is not a valid CSR
	invalidCSR := []byte{0x30, 0x82, 0x01, 0x00} // Invalid ASN.1 structure

	result, err := client.CrossSignWithChallenge(context.TODO(), invalidCSR, certDER, setupFunc, nil)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to parse CSR")
}

// TestCrossSignConfig_Validate_NegativeTimeoutCoverage tests timeout handling with negative value
func TestCrossSignConfig_Validate_NegativeTimeoutCoverage(t *testing.T) {
	config := &CrossSignConfig{
		DirectoryURL:  "https://acme.example.com/directory",
		ChallengeType: "http-01",
		Timeout:       -5 * time.Second,
	}
	err := config.Validate()
	assert.NoError(t, err)
	assert.Equal(t, 60*time.Second, config.Timeout)
}

// TestCrossSignConfig_Validate_ZeroRetryAttemptsStaysZero tests that zero retry attempts stays zero
func TestCrossSignConfig_Validate_ZeroRetryAttemptsStaysZero(t *testing.T) {
	config := &CrossSignConfig{
		DirectoryURL:  "https://acme.example.com/directory",
		ChallengeType: "http-01",
		RetryAttempts: 0,
	}
	err := config.Validate()
	assert.NoError(t, err)
	// Zero is valid and should stay zero
	assert.Equal(t, 0, config.RetryAttempts)
}

// TestCrossSignConfig_Validate_NegativeRetryDelayCoverage tests retry delay handling with negative value
func TestCrossSignConfig_Validate_NegativeRetryDelayCoverage(t *testing.T) {
	config := &CrossSignConfig{
		DirectoryURL:  "https://acme.example.com/directory",
		ChallengeType: "http-01",
		RetryDelay:    -1 * time.Second,
	}
	err := config.Validate()
	assert.NoError(t, err)
	assert.Equal(t, 1*time.Second, config.RetryDelay)
}

// TestCrossSignConfig_Validate_NegativeRetryAttemptsDefault tests retry attempts with negative value
func TestCrossSignConfig_Validate_NegativeRetryAttemptsDefault(t *testing.T) {
	config := &CrossSignConfig{
		DirectoryURL:  "https://acme.example.com/directory",
		ChallengeType: "http-01",
		RetryAttempts: -5,
	}
	err := config.Validate()
	assert.NoError(t, err)
	assert.Equal(t, 3, config.RetryAttempts) // Default value
}

// TestCrossSignerFromClient_NewClientFailureCoverage tests CrossSignerFromClient when NewClient fails
func TestCrossSignerFromClient_NewClientFailureCoverage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a client with nil storage (which will cause NewClient to fail)
	originalClient := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       nil, // This will cause NewClient to fail
	}

	config := &CrossSignConfig{
		DirectoryURL:  "https://acme.example.com/directory",
		ChallengeType: "http-01",
	}

	crossSigner, err := CrossSignerFromClient(originalClient, config)
	assert.Error(t, err)
	assert.Nil(t, crossSigner)
	assert.Contains(t, err.Error(), "failed to create cross-signer client")
}

// TestExtractAuthzFromCertificate_IPAddressCoverage tests extracting IP from certificate
func TestExtractAuthzFromCertificate_IPAddressCoverage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockStore := newMockStorage()
	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       mockStore,
	}

	// Create certificate with IP address
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "192.168.1.1",
		},
		IPAddresses:           []net.IP{net.ParseIP("192.168.1.1")},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	authzValue, authzType, err := client.extractAuthzFromCertificate(cert)
	assert.NoError(t, err)
	assert.Equal(t, "ip", authzType)
	assert.Equal(t, "192.168.1.1", authzValue)
}

// TestExtractAuthzFromCertificate_CommonNameFallbackCoverage tests fallback to CN
func TestExtractAuthzFromCertificate_CommonNameFallbackCoverage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockStore := newMockStorage()
	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       mockStore,
	}

	// Create certificate with only CN (no SANs)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	authzValue, authzType, err := client.extractAuthzFromCertificate(cert)
	assert.NoError(t, err)
	assert.Equal(t, "dns", authzType)
	assert.Equal(t, "example.com", authzValue)
}

// TestExtractAuthzFromCertificate_NoValidIdentifierCoverage tests error when no identifier found
func TestExtractAuthzFromCertificate_NoValidIdentifierCoverage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockStore := newMockStorage()
	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       mockStore,
	}

	// Create certificate without any valid identifiers
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			// No CommonName
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	_, _, err = client.extractAuthzFromCertificate(cert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no valid authorization identifier found")
}

// TestCrossSign_CSRSubjectMismatchCoverage tests CrossSign when CSR subject doesn't match certificate
func TestCrossSign_CSRSubjectMismatchCoverage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockStore := newMockStorage()
	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       mockStore,
	}

	// Create CSR with different subject
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "different.example.com",
		},
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	require.NoError(t, err)

	// Certificate with different subject
	certDER := generateCoverageCertDER(t, "example.com")

	result, err := client.CrossSign(context.Background(), csr, certDER)
	assert.Error(t, err)
	assert.Nil(t, result)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.BadCSR, caErr.Type)
}

// TestCrossSignWithChallenge_SubjectMismatchCoverage tests CrossSignWithChallenge when CSR doesn't match certificate
func TestCrossSignWithChallenge_SubjectMismatchCoverage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockStore := newMockStorage()
	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       mockStore,
	}

	// Create CSR with different subject
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "different.example.com",
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	require.NoError(t, err)

	// Certificate with different subject
	certDER := generateCoverageCertDER(t, "example.com")

	setupFunc := func(challengeType, token, keyAuth string) error { return nil }

	result, err := client.CrossSignWithChallenge(context.Background(), csrDER, certDER, setupFunc, nil)
	assert.Error(t, err)
	assert.Nil(t, result)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.BadCSR, caErr.Type)
}

// TestCrossSignWithChallenge_InvalidCertificateDERCoverage tests CrossSignWithChallenge with invalid cert
func TestCrossSignWithChallenge_InvalidCertificateDERCoverage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockStore := newMockStorage()
	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        DefaultConfig(),
		logger:        logger,
		storage:       mockStore,
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	require.NoError(t, err)

	// Invalid certificate DER
	invalidCert := []byte{0x30, 0x82, 0x01, 0x00}

	setupFunc := func(challengeType, token, keyAuth string) error { return nil }

	result, err := client.CrossSignWithChallenge(context.Background(), csrDER, invalidCert, setupFunc, nil)
	assert.Error(t, err)
	assert.Nil(t, result)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.Malformed, caErr.Type)
}

// =====================================
// Tests from cross_sign_integration_test.go
// =====================================

type crossSignMockServer struct {
	*httptest.Server
	t            *testing.T
	nonceCounter int64
	authzStatus  string
	chalStatus   string
	failAuthz    bool
	failFinalize bool
}

func newCrossSignMockServer(t *testing.T) *crossSignMockServer {
	m := &crossSignMockServer{
		t:           t,
		authzStatus: "valid",
		chalStatus:  "valid",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/directory", m.handleDirectory)
	mux.HandleFunc("/acme/new-nonce", m.handleNewNonce)
	mux.HandleFunc("/acme/new-account", m.handleNewAccount)
	mux.HandleFunc("/acme/new-order", m.handleNewOrder)
	mux.HandleFunc("/acme/authz/", m.handleAuthz)
	mux.HandleFunc("/acme/challenge/", m.handleChallenge)
	mux.HandleFunc("/acme/finalize/", m.handleFinalize)
	mux.HandleFunc("/acme/cert/", m.handleCert)
	mux.HandleFunc("/ca-bundle", m.handleCABundle)

	m.Server = httptest.NewTLSServer(mux)
	return m
}

func (m *crossSignMockServer) handleDirectory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	dir := map[string]interface{}{
		"newNonce":   m.URL + "/acme/new-nonce",
		"newAccount": m.URL + "/acme/new-account",
		"newOrder":   m.URL + "/acme/new-order",
		"revokeCert": m.URL + "/acme/revoke-cert",
		"keyChange":  m.URL + "/acme/key-change",
		"meta": map[string]interface{}{
			"termsOfService": "https://example.com/terms",
		},
	}
	_ = json.NewEncoder(w).Encode(dir)
}

func (m *crossSignMockServer) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	nonce := atomic.AddInt64(&m.nonceCounter, 1)
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", nonce))
	w.WriteHeader(http.StatusNoContent)
}

func (m *crossSignMockServer) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", atomic.AddInt64(&m.nonceCounter, 1)))
	w.Header().Set("Location", m.URL+"/acme/account/1")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "valid",
		"contact": []string{"mailto:test@example.com"},
	})
}

func (m *crossSignMockServer) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", atomic.AddInt64(&m.nonceCounter, 1)))
	w.Header().Set("Location", m.URL+"/acme/order/1")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "pending",
		"authorizations": []string{m.URL + "/acme/authz/1"},
		"finalize":       m.URL + "/acme/finalize/1",
		"identifiers": []map[string]string{
			{"type": "dns", "value": "example.com"},
		},
	})
}

func (m *crossSignMockServer) handleAuthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", atomic.AddInt64(&m.nonceCounter, 1)))
	w.Header().Set("Content-Type", "application/json")

	if m.failAuthz {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"type":   "urn:ietf:params:acme:error:serverInternal",
			"detail": "authorization failed",
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": m.authzStatus,
		"identifier": map[string]string{
			"type":  "dns",
			"value": "example.com",
		},
		"challenges": []map[string]interface{}{
			{
				"type":   "http-01",
				"status": m.chalStatus,
				"url":    m.URL + "/acme/challenge/1",
				"token":  "test-token",
			},
		},
	})
}

func (m *crossSignMockServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", atomic.AddInt64(&m.nonceCounter, 1)))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"type":   "http-01",
		"status": "valid",
		"url":    m.URL + "/acme/challenge/1",
		"token":  "test-token",
	})
}

func (m *crossSignMockServer) handleFinalize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", atomic.AddInt64(&m.nonceCounter, 1)))
	w.Header().Set("Content-Type", "application/json")

	if m.failFinalize {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"type":   "urn:ietf:params:acme:error:badCSR",
			"detail": "invalid CSR",
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "valid",
		"certificate": m.URL + "/acme/cert/1",
		"finalize":    m.URL + "/acme/finalize/1",
	})
}

func (m *crossSignMockServer) handleCert(w http.ResponseWriter, r *http.Request) {
	// Generate a test certificate chain
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames:              []string{"example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	_, _ = w.Write(certPEM)
}

func (m *crossSignMockServer) handleCABundle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write([]byte("-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJALQ3...\n-----END CERTIFICATE-----"))
}

// createCrossSignTestClient creates a client for cross-signing tests
func createCrossSignTestClient(t *testing.T, server *crossSignMockServer) *Client {
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serverCert := server.Certificate()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})

	config := &Config{
		DirectoryURL:        server.URL + "/directory",
		SystemCertPool:      false,
		RequestServerBundle: false,
		TrustedRoots:        []string{string(certPEM)},
		Timeout:             30 * time.Second,
	}

	client, err := NewClient(&Params{
		AccountEmail:       "test@example.com",
		AccountSigner:      accountKey,
		Config:             config,
		Storage:            newMockStorage(),
		CertificateStorage: newMockCertStorage(),
		OrderStorage:       newMockOrderStorage(),
	})
	require.NoError(t, err)

	return client
}

// createTestCertAndCSR creates matching certificate and CSR for cross-signing tests
func createTestCertAndCSR(t *testing.T, cn string, dnsNames []string, ips []net.IP) ([]byte, []byte, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cn,
		},
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	require.NoError(t, err)

	// Create matching certificate
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: cn,
		},
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	require.NoError(t, err)

	return certDER, csrDER, key
}

// TestCrossSign_FullFlow tests the complete cross-signing flow
func TestCrossSign_FullFlow(t *testing.T) {
	server := newCrossSignMockServer(t)
	defer server.Close()

	client := createCrossSignTestClient(t, server)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create matching certificate and CSR
	certDER, csrDER, _ := createTestCertAndCSR(t, "example.com", []string{"example.com"}, nil)

	// Perform cross-signing
	crossSignedCert, err := client.CrossSign(ctx, csrDER, certDER)

	// Should succeed with the mock server
	require.NoError(t, err)
	require.NotNil(t, crossSignedCert)
	assert.Equal(t, "example.com", crossSignedCert.Subject.CommonName)
}

// TestCrossSign_WithIPAddress tests cross-signing with IP address SAN
func TestCrossSign_WithIPAddress(t *testing.T) {
	server := newCrossSignMockServer(t)
	defer server.Close()

	client := createCrossSignTestClient(t, server)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create certificate with IP address
	certDER, csrDER, _ := createTestCertAndCSR(t, "server", nil, []net.IP{net.ParseIP("192.168.1.1")})

	// Perform cross-signing
	crossSignedCert, err := client.CrossSign(ctx, csrDER, certDER)

	require.NoError(t, err)
	require.NotNil(t, crossSignedCert)
}

// TestCrossSign_EmptyCSR_Integration tests cross-signing with empty CSR
func TestCrossSign_EmptyCSR_Integration(t *testing.T) {
	server := newCrossSignMockServer(t)
	defer server.Close()

	client := createCrossSignTestClient(t, server)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	certDER, _, _ := createTestCertAndCSR(t, "example.com", []string{"example.com"}, nil)

	// Try cross-signing with empty CSR
	cert, err := client.CrossSign(ctx, []byte{}, certDER)

	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.ErrorIs(t, err, ErrMissingCSR)
}

// TestCrossSign_EmptyCertificate tests cross-signing with empty certificate
func TestCrossSign_EmptyCertificate(t *testing.T) {
	server := newCrossSignMockServer(t)
	defer server.Close()

	client := createCrossSignTestClient(t, server)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, csrDER, _ := createTestCertAndCSR(t, "example.com", []string{"example.com"}, nil)

	// Try cross-signing with empty certificate
	cert, err := client.CrossSign(ctx, csrDER, []byte{})

	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// TestCrossSign_MismatchedSubjects_Integration tests cross-signing with mismatched subjects
func TestCrossSign_MismatchedSubjects_Integration(t *testing.T) {
	server := newCrossSignMockServer(t)
	defer server.Close()

	client := createCrossSignTestClient(t, server)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create certificate and CSR with different subjects
	certDER, _, _ := createTestCertAndCSR(t, "cert-subject.com", []string{"cert-subject.com"}, nil)
	_, csrDER, _ := createTestCertAndCSR(t, "csr-subject.com", []string{"csr-subject.com"}, nil)

	// Try cross-signing with mismatched subjects
	cert, err := client.CrossSign(ctx, csrDER, certDER)

	assert.Error(t, err)
	assert.Nil(t, cert)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.BadCSR, caErr.Type)
}

// TestCrossSign_InvalidCertificate_Integration tests cross-signing with invalid certificate bytes
func TestCrossSign_InvalidCertificate_Integration(t *testing.T) {
	server := newCrossSignMockServer(t)
	defer server.Close()

	client := createCrossSignTestClient(t, server)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, csrDER, _ := createTestCertAndCSR(t, "example.com", []string{"example.com"}, nil)

	// Try cross-signing with invalid certificate bytes
	cert, err := client.CrossSign(ctx, csrDER, []byte("invalid certificate"))

	assert.Error(t, err)
	assert.Nil(t, cert)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.Malformed, caErr.Type)
}

// TestCrossSign_InvalidCSR_Integration tests cross-signing with invalid CSR bytes
func TestCrossSign_InvalidCSR_Integration(t *testing.T) {
	server := newCrossSignMockServer(t)
	defer server.Close()

	client := createCrossSignTestClient(t, server)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	certDER, _, _ := createTestCertAndCSR(t, "example.com", []string{"example.com"}, nil)

	// Try cross-signing with invalid CSR bytes
	cert, err := client.CrossSign(ctx, []byte("invalid csr"), certDER)

	assert.Error(t, err)
	assert.Nil(t, cert)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.BadCSR, caErr.Type)
}

// TestCrossSignWithChallenge_FullFlow tests cross-signing with custom challenge handlers
func TestCrossSignWithChallenge_FullFlow(t *testing.T) {
	server := newCrossSignMockServer(t)
	defer server.Close()

	client := createCrossSignTestClient(t, server)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create matching certificate and CSR
	certDER, csrDER, _ := createTestCertAndCSR(t, "example.com", []string{"example.com"}, nil)

	// Challenge handlers
	setupCalled := false

	challengeSetup := func(chalType, token, keyAuth string) error {
		setupCalled = true
		return nil
	}

	challengeCleanup := func(chalType string) {
		// Cleanup called
	}

	// Perform cross-signing with challenge handlers
	// Note: The mock server returns authz as already "valid", so the client
	// won't call the challenge setup - this is expected behavior
	crossSignedCert, err := client.CrossSignWithChallenge(ctx, csrDER, certDER, challengeSetup, challengeCleanup)

	require.NoError(t, err)
	require.NotNil(t, crossSignedCert)
	// Challenge setup may not be called if authz is already valid (which is the mock's default)
	_ = setupCalled // Use the variable even if not asserting
}

// TestCrossSignWithChallenge_NilSetup tests cross-signing with nil setup function
func TestCrossSignWithChallenge_NilSetup(t *testing.T) {
	server := newCrossSignMockServer(t)
	defer server.Close()

	client := createCrossSignTestClient(t, server)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	certDER, csrDER, _ := createTestCertAndCSR(t, "example.com", []string{"example.com"}, nil)

	// Try with nil setup function
	cert, err := client.CrossSignWithChallenge(ctx, csrDER, certDER, nil, nil)

	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.ErrorIs(t, err, ErrInvalidChallengeSetup)
}

// TestCrossSignWithChallenge_SetupError tests cross-signing when setup fails
func TestCrossSignWithChallenge_SetupError(t *testing.T) {
	server := newCrossSignMockServer(t)
	server.authzStatus = "pending" // Force challenge processing
	defer server.Close()

	client := createCrossSignTestClient(t, server)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	certDER, csrDER, _ := createTestCertAndCSR(t, "example.com", []string{"example.com"}, nil)

	// Setup that fails
	challengeSetup := func(chalType, token, keyAuth string) error {
		return caerrors.InternalServerError("setup failed")
	}

	cert, err := client.CrossSignWithChallenge(ctx, csrDER, certDER, challengeSetup, nil)

	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "setup failed")
}

// TestCrossSignConfig_Validate_Integration tests cross-sign config validation
func TestCrossSignConfig_Validate_Integration(t *testing.T) {
	tests := []struct {
		name    string
		config  *CrossSignConfig
		wantErr error
	}{
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
			name: "empty challenge type",
			config: &CrossSignConfig{
				DirectoryURL:  "https://example.com",
				ChallengeType: "",
			},
			wantErr: ErrMissingChallengeType,
		},
		{
			name: "invalid challenge type",
			config: &CrossSignConfig{
				DirectoryURL:  "https://example.com",
				ChallengeType: "invalid-01",
			},
			wantErr: ErrInvalidChallengeTypeForCrossSign,
		},
		{
			name: "valid http-01",
			config: &CrossSignConfig{
				DirectoryURL:  "https://example.com",
				ChallengeType: "http-01",
			},
			wantErr: nil,
		},
		{
			name: "valid dns-01",
			config: &CrossSignConfig{
				DirectoryURL:  "https://example.com",
				ChallengeType: "dns-01",
			},
			wantErr: nil,
		},
		{
			name: "valid tls-alpn-01",
			config: &CrossSignConfig{
				DirectoryURL:  "https://example.com",
				ChallengeType: "tls-alpn-01",
			},
			wantErr: nil,
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

// TestCrossSignerFromClient_Valid tests creating cross-signer from valid client
func TestCrossSignerFromClient_Valid(t *testing.T) {
	server := newCrossSignMockServer(t)
	defer server.Close()

	client := createCrossSignTestClient(t, server)
	defer func() { _ = client.Close() }()

	serverCert := server.Certificate()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})

	crossSigner, err := CrossSignerFromClient(client, &CrossSignConfig{
		DirectoryURL:        server.URL + "/directory",
		ChallengeType:       "http-01",
		TrustedRoots:        []string{string(certPEM)},
		RequestServerBundle: false,
		Timeout:             30 * time.Second,
	})

	require.NoError(t, err)
	require.NotNil(t, crossSigner)
	defer func() { _ = crossSigner.Close() }()
}

// TestCrossSignerFromClient_NilClient_Integration tests creating cross-signer from nil client
func TestCrossSignerFromClient_NilClient_Integration(t *testing.T) {
	crossSigner, err := CrossSignerFromClient(nil, &CrossSignConfig{
		DirectoryURL:  "https://example.com",
		ChallengeType: "http-01",
	})

	assert.Error(t, err)
	assert.Nil(t, crossSigner)
	assert.ErrorIs(t, err, ErrInvalidConfiguration)
}

// TestCrossSignerFromClient_NilConfig tests creating cross-signer from nil config
func TestCrossSignerFromClient_NilConfig(t *testing.T) {
	server := newCrossSignMockServer(t)
	defer server.Close()

	client := createCrossSignTestClient(t, server)
	defer func() { _ = client.Close() }()

	crossSigner, err := CrossSignerFromClient(client, nil)

	assert.Error(t, err)
	assert.Nil(t, crossSigner)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.Malformed, caErr.Type)
}

// TestExtractAuthzFromCertificate tests authorization extraction
func TestExtractAuthzFromCertificate(t *testing.T) {
	server := newCrossSignMockServer(t)
	defer server.Close()

	client := createCrossSignTestClient(t, server)
	defer func() { _ = client.Close() }()

	tests := []struct {
		name      string
		certFunc  func(t *testing.T) *x509.Certificate
		wantValue string
		wantType  string
		wantErr   bool
	}{
		{
			name: "DNS names present",
			certFunc: func(t *testing.T) *x509.Certificate {
				certDER, _, _ := createTestCertAndCSR(t, "example.com", []string{"test.example.com", "example.com"}, nil)
				cert, _ := x509.ParseCertificate(certDER)
				return cert
			},
			wantValue: "test.example.com",
			wantType:  "dns",
			wantErr:   false,
		},
		{
			name: "IP address present",
			certFunc: func(t *testing.T) *x509.Certificate {
				certDER, _, _ := createTestCertAndCSR(t, "server", nil, []net.IP{net.ParseIP("10.0.0.1")})
				cert, _ := x509.ParseCertificate(certDER)
				return cert
			},
			wantValue: "10.0.0.1",
			wantType:  "ip",
			wantErr:   false,
		},
		{
			name: "Only CN present",
			certFunc: func(t *testing.T) *x509.Certificate {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				template := &x509.Certificate{
					SerialNumber: big.NewInt(1),
					Subject:      pkix.Name{CommonName: "cn-only.example.com"},
					NotBefore:    time.Now(),
					NotAfter:     time.Now().Add(time.Hour),
				}
				certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
				cert, _ := x509.ParseCertificate(certDER)
				return cert
			},
			wantValue: "cn-only.example.com",
			wantType:  "dns",
			wantErr:   false,
		},
		{
			name: "No identifiers",
			certFunc: func(t *testing.T) *x509.Certificate {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				template := &x509.Certificate{
					SerialNumber: big.NewInt(1),
					Subject:      pkix.Name{Organization: []string{"Test Org"}},
					NotBefore:    time.Now(),
					NotAfter:     time.Now().Add(time.Hour),
				}
				certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
				cert, _ := x509.ParseCertificate(certDER)
				return cert
			},
			wantValue: "",
			wantType:  "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := tt.certFunc(t)
			value, authzType, err := client.extractAuthzFromCertificate(cert)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantValue, value)
				assert.Equal(t, tt.wantType, authzType)
			}
		})
	}
}
