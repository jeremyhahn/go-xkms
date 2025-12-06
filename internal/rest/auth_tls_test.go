// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration

package rest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/internal/testutil"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/logger"
	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

// createTestKeyStore creates a simple in-memory keystore for testing
func createTestKeyStore(t *testing.T) keychain.KeyStore {
	t.Helper()

	// Create in-memory storage
	keyStorage := storage.New()
	certStorage := storage.New()

	// Create PKCS8 backend
	backend, err := pkcs8.NewBackend(&pkcs8.Config{
		KeyStorage: keyStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	// Create keystore
	ks, err := keychain.New(&keychain.Config{
		Backend:     backend,
		CertStorage: certStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	return ks
}

// waitForServer waits for the server to be ready
func waitForServer(t *testing.T, url string, client *http.Client, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Server did not become ready within %v", timeout)
}

func TestRESTServer_NoOpAuthenticator_HTTP(t *testing.T) {
	// Create test keystore
	ks := createTestKeyStore(t)
	defer func() { _ = ks.Close() }()

	// Create NoOp authenticator
	authenticator := auth.NewNoOpAuthenticator()

	// Create REST server with HTTP (no TLS)
	cfg := &Config{
		Port: 0, // Use ephemeral port
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		Authenticator: authenticator,
		Logger: logger.NewSlogAdapter(&logger.SlogConfig{
			Level: logger.LevelError,
		}),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Start()
	}()

	// Get the actual port
	port := server.Port()

	// Wait for server to be ready
	baseURL := fmt.Sprintf("http://localhost:%d", port)
	client := &http.Client{Timeout: 5 * time.Second}
	waitForServer(t, baseURL+"/health", client, 5*time.Second)

	// Test health endpoint (no auth required)
	t.Run("HealthEndpoint", func(t *testing.T) {
		resp, err := client.Get(baseURL + "/health")
		if err != nil {
			t.Fatalf("Health check failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	// Test authenticated endpoint (should succeed with NoOp auth)
	t.Run("AuthenticatedEndpoint", func(t *testing.T) {
		resp, err := client.Get(baseURL + "/api/v1/backends")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}

		if len(body) == 0 {
			t.Error("Expected non-empty response body")
		}
	})

	// Stop server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Stop(ctx); err != nil {
		t.Errorf("Failed to stop server: %v", err)
	}

	// Check if server stopped without errors
	select {
	case err := <-serverErrCh:
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("Server error: %v", err)
		}
	case <-time.After(1 * time.Second):
		// Server stopped gracefully
	}
}

func TestRESTServer_APIKeyAuthenticator_HTTP(t *testing.T) {
	// Create test keystore
	ks := createTestKeyStore(t)
	defer func() { _ = ks.Close() }()

	// Create API key authenticator with test keys
	validAPIKey := "test-api-key-12345"
	invalidAPIKey := "invalid-api-key"

	authenticator := auth.NewAPIKeyAuthenticator(&auth.APIKeyConfig{
		Keys: map[string]*auth.Identity{
			validAPIKey: {
				Subject: "test-user",
				Claims: map[string]interface{}{
					"roles": []string{"admin"},
				},
				Attributes: map[string]string{
					"scope": "full",
				},
			},
		},
	})

	// Create REST server
	cfg := &Config{
		Port: 0, // Use ephemeral port
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		Authenticator: authenticator,
		Logger: logger.NewSlogAdapter(&logger.SlogConfig{
			Level: logger.LevelError,
		}),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Start()
	}()

	port := server.Port()
	baseURL := fmt.Sprintf("http://localhost:%d", port)
	client := &http.Client{Timeout: 5 * time.Second}
	waitForServer(t, baseURL+"/health", client, 5*time.Second)

	// Test with valid API key
	t.Run("ValidAPIKey", func(t *testing.T) {
		req, err := http.NewRequest("GET", baseURL+"/api/v1/backends", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("X-API-Key", validAPIKey)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	// Test with invalid API key
	t.Run("InvalidAPIKey", func(t *testing.T) {
		req, err := http.NewRequest("GET", baseURL+"/api/v1/backends", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("X-API-Key", invalidAPIKey)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", resp.StatusCode)
		}
	})

	// Test without API key
	t.Run("NoAPIKey", func(t *testing.T) {
		resp, err := client.Get(baseURL + "/api/v1/backends")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", resp.StatusCode)
		}
	})

	// Test with API key in Authorization header
	t.Run("BearerToken", func(t *testing.T) {
		req, err := http.NewRequest("GET", baseURL+"/api/v1/backends", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+validAPIKey)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	// Stop server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Stop(ctx); err != nil {
		t.Errorf("Failed to stop server: %v", err)
	}

	// Check if server stopped without errors
	select {
	case err := <-serverErrCh:
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("Server error: %v", err)
		}
	case <-time.After(1 * time.Second):
		// Server stopped gracefully
	}
}

func TestRESTServer_TLS_NoClientCert(t *testing.T) {
	// Generate test CA and server certificate
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("Failed to generate server certificate: %v", err)
	}

	// Create test keystore
	ks := createTestKeyStore(t)
	defer func() { _ = ks.Close() }()

	// Create TLS config (no client cert required)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert.TLSCert},
		MinVersion:   tls.VersionTLS12,
	}

	// Create NoOp authenticator
	authenticator := auth.NewNoOpAuthenticator()

	// Create REST server with TLS
	cfg := &Config{
		Port: 0, // Use ephemeral port
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		TLSConfig:     tlsConfig,
		Authenticator: authenticator,
		Logger: logger.NewSlogAdapter(&logger.SlogConfig{
			Level: logger.LevelError,
		}),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Start()
	}()

	port := server.Port()
	baseURL := fmt.Sprintf("https://localhost:%d", port)

	// Create HTTPS client that trusts our CA
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(ca.CertPEM)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	waitForServer(t, baseURL+"/health", client, 5*time.Second)

	// Test HTTPS connection
	t.Run("HTTPSConnection", func(t *testing.T) {
		resp, err := client.Get(baseURL + "/health")
		if err != nil {
			t.Fatalf("HTTPS request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		// Verify we're using TLS
		if !resp.TLS.HandshakeComplete {
			t.Error("Expected completed TLS handshake")
		}
	})

	// Test authenticated endpoint over HTTPS
	t.Run("AuthenticatedOverHTTPS", func(t *testing.T) {
		resp, err := client.Get(baseURL + "/api/v1/backends")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	// Stop server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Stop(ctx); err != nil {
		t.Errorf("Failed to stop server: %v", err)
	}

	// Check if server stopped without errors
	select {
	case err := <-serverErrCh:
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("Server error: %v", err)
		}
	case <-time.After(1 * time.Second):
		// Server stopped gracefully
	}
}

func TestRESTServer_mTLS_ClientCertRequired(t *testing.T) {
	// Generate test CA, server cert, and client cert
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("Failed to generate server certificate: %v", err)
	}

	clientCert, err := testutil.GenerateTestClientCert(ca, "test-client")
	if err != nil {
		t.Fatalf("Failed to generate client certificate: %v", err)
	}

	// Create test keystore
	ks := createTestKeyStore(t)
	defer func() { _ = ks.Close() }()

	// Create CA cert pool for client verification
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(ca.CertPEM)

	// Create TLS config with client cert verification
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert.TLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Create mTLS authenticator
	authenticator := auth.NewMTLSAuthenticator(nil)

	// Create REST server with mTLS
	cfg := &Config{
		Port: 0, // Use ephemeral port
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		TLSConfig:     tlsConfig,
		Authenticator: authenticator,
		Logger: logger.NewSlogAdapter(&logger.SlogConfig{
			Level: logger.LevelError,
		}),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Start()
	}()

	port := server.Port()
	baseURL := fmt.Sprintf("https://localhost:%d", port)

	// Create HTTPS client with client certificate
	caCertPoolClient := x509.NewCertPool()
	caCertPoolClient.AppendCertsFromPEM(ca.CertPEM)

	clientWithCert := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPoolClient,
				Certificates: []tls.Certificate{clientCert.TLSCert},
			},
		},
	}

	// Client without certificate
	clientWithoutCert := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPoolClient,
			},
		},
	}

	// Wait for server
	waitForServer(t, baseURL+"/health", clientWithCert, 5*time.Second)

	// Test with valid client certificate
	t.Run("ValidClientCert", func(t *testing.T) {
		resp, err := clientWithCert.Get(baseURL + "/api/v1/backends")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		// Verify mTLS was used
		if resp.TLS == nil {
			t.Error("Expected TLS connection")
		} else if !resp.TLS.HandshakeComplete {
			t.Error("Expected completed TLS handshake")
		}
	})

	// Test without client certificate (should fail)
	t.Run("NoClientCert", func(t *testing.T) {
		_, err := clientWithoutCert.Get(baseURL + "/api/v1/backends")
		if err == nil {
			t.Error("Expected error when connecting without client cert, but got none")
		}
		// The error should be a TLS handshake failure
	})

	// Stop server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Stop(ctx); err != nil {
		t.Errorf("Failed to stop server: %v", err)
	}

	// Check if server stopped without errors
	select {
	case err := <-serverErrCh:
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("Server error: %v", err)
		}
	case <-time.After(1 * time.Second):
		// Server stopped gracefully
	}
}

func TestRESTServer_AuthenticationFailureScenarios(t *testing.T) {
	// Create test keystore
	ks := createTestKeyStore(t)
	defer func() { _ = ks.Close() }()

	tests := []struct {
		name         string
		setupAuth    func() auth.Authenticator
		setupRequest func(*http.Request)
		expectedCode int
		description  string
	}{
		{
			name: "APIKey_EmptyKey",
			setupAuth: func() auth.Authenticator {
				return auth.NewAPIKeyAuthenticator(&auth.APIKeyConfig{
					Keys: map[string]*auth.Identity{
						"valid-key": {Subject: "test"},
					},
				})
			},
			setupRequest: func(req *http.Request) {
				req.Header.Set("X-API-Key", "")
			},
			expectedCode: http.StatusUnauthorized,
			description:  "Empty API key should be rejected",
		},
		{
			name: "APIKey_WrongKey",
			setupAuth: func() auth.Authenticator {
				return auth.NewAPIKeyAuthenticator(&auth.APIKeyConfig{
					Keys: map[string]*auth.Identity{
						"valid-key": {Subject: "test"},
					},
				})
			},
			setupRequest: func(req *http.Request) {
				req.Header.Set("X-API-Key", "wrong-key")
			},
			expectedCode: http.StatusUnauthorized,
			description:  "Wrong API key should be rejected",
		},
		{
			name: "APIKey_MalformedBearer",
			setupAuth: func() auth.Authenticator {
				return auth.NewAPIKeyAuthenticator(&auth.APIKeyConfig{
					Keys: map[string]*auth.Identity{
						"valid-key": {Subject: "test"},
					},
				})
			},
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "InvalidScheme valid-key")
			},
			expectedCode: http.StatusUnauthorized,
			description:  "Malformed Authorization header should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create server with the specified authenticator
			cfg := &Config{
				Port: 0,
				Backends: map[string]keychain.KeyStore{
					"test": ks,
				},
				Authenticator: tt.setupAuth(),
				Logger: logger.NewSlogAdapter(&logger.SlogConfig{
					Level: logger.LevelError,
				}),
			}

			server, err := NewServer(cfg)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			// Start server
			serverErrCh := make(chan error, 1)
			go func() {
				serverErrCh <- server.Start()
			}()

			port := server.Port()
			baseURL := fmt.Sprintf("http://localhost:%d", port)
			client := &http.Client{Timeout: 5 * time.Second}
			waitForServer(t, baseURL+"/health", client, 5*time.Second)

			// Create and execute request
			req, err := http.NewRequest("GET", baseURL+"/api/v1/backends", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			tt.setupRequest(req)

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedCode {
				t.Errorf("%s: Expected status %d, got %d", tt.description, tt.expectedCode, resp.StatusCode)
			}

			// Stop server
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			server.Stop(ctx)

			// Check if server stopped without errors
			select {
			case err := <-serverErrCh:
				if err != nil && err != http.ErrServerClosed {
					t.Logf("Server error: %v", err)
				}
			case <-time.After(1 * time.Second):
				// Server stopped gracefully
			}
		})
	}
}
