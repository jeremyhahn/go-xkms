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
	"errors"
	"fmt"
	"log/slog"
	"math/big"
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

	"github.com/jeremyhahn/go-xkms/internal/acmetestutil"
)

// TestRenewalService_ForceRenewal tests forced renewal of a specific certificate
func TestRenewalService_ForceRenewal(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("successful force renewal", func(t *testing.T) {
		// Create test server
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

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
						{"type": "http-01", "token": "test-token", "url": server.URL + "/challenge/1"},
					},
				})
			case "/challenge/1":
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "valid"})
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

		accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		transport := &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		}
		httpClient := &http.Client{Transport: transport, Timeout: 30 * time.Second}

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
			logger:        logger,
		}

		renewalConfig := DefaultRenewalConfig()
		service, err := NewRenewalService(client, renewalConfig, logger)
		require.NoError(t, err)

		// Register a certificate
		cert, _ := generateTestCertificate(t, "example.com")
		csrDER := generateTestCSR(t, "example.com", privateKey)

		req := &CertificateRequest{
			AuthzType:     "dns",
			AuthzValue:    "example.com",
			ChallengeType: "http-01",
			CSR:           csrDER,
		}

		err = service.RegisterCertificate(cert, req, "test-cert")
		require.NoError(t, err)

		// Force renewal
		err = service.ForceRenewal(context.Background(), "test-cert")
		require.NoError(t, err)
	})

	t.Run("force renewal - certificate not found", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		config := DefaultConfig()
		config.DirectoryURL = "https://acme.example.com/directory"

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Storage:       newMockStorage(),
			Logger:        logger,
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		renewalConfig := DefaultRenewalConfig()
		service, err := NewRenewalService(client, renewalConfig, logger)
		require.NoError(t, err)

		err = service.ForceRenewal(context.Background(), "non-existent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certificate not found")
	})
}

// TestRenewalService_RenewAll tests forced renewal of all certificates
func TestRenewalService_RenewAll(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("successful renew all", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

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
						{"type": "http-01", "token": "test-token", "url": server.URL + "/challenge/1"},
					},
				})
			case "/challenge/1":
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "valid"})
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

		accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		transport := &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		}
		httpClient := &http.Client{Transport: transport, Timeout: 30 * time.Second}

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
			logger:        logger,
		}

		renewalConfig := DefaultRenewalConfig()
		service, err := NewRenewalService(client, renewalConfig, logger)
		require.NoError(t, err)

		// Register multiple certificates
		for i := 0; i < 3; i++ {
			cert, _ := generateTestCertificate(t, "example.com")
			csrDER := generateTestCSR(t, "example.com", privateKey)

			req := &CertificateRequest{
				AuthzType:     "dns",
				AuthzValue:    "example.com",
				ChallengeType: "http-01",
				CSR:           csrDER,
			}

			err = service.RegisterCertificate(cert, req, string(rune('A'+i)))
			require.NoError(t, err)
		}

		// Renew all
		err = service.RenewAll(context.Background())
		require.NoError(t, err)
	})

	t.Run("renew all with some failures", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		config := DefaultConfig()
		config.DirectoryURL = "https://acme.example.com/directory"

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Storage:       newMockStorage(),
			Logger:        logger,
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		renewalConfig := DefaultRenewalConfig()
		renewalConfig.MaxRetries = 0 // No retries
		service, err := NewRenewalService(client, renewalConfig, logger)
		require.NoError(t, err)

		// Register certificates with invalid requests
		for i := 0; i < 2; i++ {
			cert, _ := generateTestCertificate(t, "example.com")

			req := &CertificateRequest{
				AuthzType: "dns",
				// Missing required fields - will fail
			}

			err = service.RegisterCertificate(cert, req, string(rune('A'+i)))
			require.NoError(t, err)
		}

		// Renew all - should fail
		err = service.RenewAll(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to renew")
	})

	t.Run("renew all with no certificates", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		config := DefaultConfig()
		config.DirectoryURL = "https://acme.example.com/directory"

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Storage:       newMockStorage(),
			Logger:        logger,
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		renewalConfig := DefaultRenewalConfig()
		service, err := NewRenewalService(client, renewalConfig, logger)
		require.NoError(t, err)

		// Renew all with no certificates registered
		err = service.RenewAll(context.Background())
		require.NoError(t, err) // Should succeed with no errors
	})
}

// TestRenewalService_Run tests the renewal service daemon
func TestRenewalService_Run(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("run with context cancellation", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		config := DefaultConfig()
		config.DirectoryURL = "https://acme.example.com/directory"

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Storage:       newMockStorage(),
			Logger:        logger,
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		renewalConfig := DefaultRenewalConfig()
		renewalConfig.CheckInterval = 100 * time.Millisecond
		service, err := NewRenewalService(client, renewalConfig, logger)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		err = service.Start(ctx)
		require.NoError(t, err)

		assert.True(t, service.IsRunning())

		// Let it run for a bit
		time.Sleep(250 * time.Millisecond)

		// Cancel context
		cancel()

		// Wait for it to stop
		time.Sleep(250 * time.Millisecond)

		// Note: The service may still show as running until Stop() is called
		// because context cancellation doesn't automatically set running to false
	})
}

// TestRenewalService_CheckAndRenewCertificates tests the certificate checking logic
func TestRenewalService_CheckAndRenewCertificates(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("check and renew with expiring certificate", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

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
						{"type": "http-01", "token": "test-token", "url": server.URL + "/challenge/1"},
					},
				})
			case "/challenge/1":
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "valid"})
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

		accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		transport := &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		}
		httpClient := &http.Client{Transport: transport, Timeout: 30 * time.Second}

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
			logger:        logger,
		}

		renewalConfig := DefaultRenewalConfig()
		renewalConfig.RenewalThreshold = 0.99 // Renew when 99% of validity remains (almost immediately)
		renewalConfig.NotifyOnSuccess = true
		renewalConfig.NotifyOnFailure = true
		service, err := NewRenewalService(client, renewalConfig, logger)
		require.NoError(t, err)

		// Create certificate that will need renewal
		cert, _ := generateTestCertificate(t, "example.com")
		csrDER := generateTestCSR(t, "example.com", privateKey)

		req := &CertificateRequest{
			AuthzType:     "dns",
			AuthzValue:    "example.com",
			ChallengeType: "http-01",
			CSR:           csrDER,
		}

		err = service.RegisterCertificate(cert, req, "test-cert")
		require.NoError(t, err)

		// Manually trigger check and renew
		service.checkAndRenewCertificates(context.Background())
	})

	t.Run("check and renew with renewal failure", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		config := DefaultConfig()
		config.DirectoryURL = "https://acme.example.com/directory"

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Storage:       newMockStorage(),
			Logger:        logger,
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		renewalConfig := DefaultRenewalConfig()
		renewalConfig.RenewalThreshold = 0.99 // Renew immediately
		renewalConfig.NotifyOnSuccess = false
		renewalConfig.NotifyOnFailure = true
		renewalConfig.MaxRetries = 0
		service, err := NewRenewalService(client, renewalConfig, logger)
		require.NoError(t, err)

		// Create certificate with invalid request
		cert, _ := generateTestCertificate(t, "example.com")

		req := &CertificateRequest{
			AuthzType: "dns",
			// Missing required fields - will fail
		}

		err = service.RegisterCertificate(cert, req, "test-cert")
		require.NoError(t, err)

		// Manually trigger check and renew - should fail
		service.checkAndRenewCertificates(context.Background())
	})
}

// TestRenewalService_RenewCertificate_WithRetries tests retry logic
func TestRenewalService_RenewCertificate_WithRetries(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("renewal with retries - eventual success", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		attemptCount := 0
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

			// Fail first 2 attempts, succeed on 3rd
			attemptCount++

			switch r.URL.Path {
			case "/directory":
				_ = json.NewEncoder(w).Encode(map[string]string{
					"newOrder": server.URL + "/new-order",
				})
			case "/new-order":
				if attemptCount <= 2 {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
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
						{"type": "http-01", "token": "test-token", "url": server.URL + "/challenge/1"},
					},
				})
			case "/challenge/1":
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "valid"})
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

		accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		transport := &http.Transport{
			TLSClientConfig: testutil.TLSConfigFromServer(server),
		}
		httpClient := &http.Client{Transport: transport, Timeout: 30 * time.Second}

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
			logger:        logger,
		}

		renewalConfig := DefaultRenewalConfig()
		renewalConfig.MaxRetries = 3
		renewalConfig.RetryInterval = 10 * time.Millisecond
		service, err := NewRenewalService(client, renewalConfig, logger)
		require.NoError(t, err)

		cert, _ := generateTestCertificate(t, "example.com")
		csrDER := generateTestCSR(t, "example.com", privateKey)

		certInfo := &CertificateInfo{
			Certificate: cert,
			Request: &CertificateRequest{
				AuthzType:     "dns",
				AuthzValue:    "example.com",
				ChallengeType: "http-01",
				CSR:           csrDER,
			},
			Identifier: "test-cert",
		}

		err = service.renewCertificate(context.Background(), certInfo)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, attemptCount, 2, "Should have retried at least twice")
	})

	t.Run("renewal with retries - all attempts fail", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		config := DefaultConfig()
		config.DirectoryURL = "https://acme.example.com/directory"

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Storage:       newMockStorage(),
			Logger:        logger,
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		renewalConfig := DefaultRenewalConfig()
		renewalConfig.MaxRetries = 2
		renewalConfig.RetryInterval = 10 * time.Millisecond
		service, err := NewRenewalService(client, renewalConfig, logger)
		require.NoError(t, err)

		cert, _ := generateTestCertificate(t, "example.com")

		certInfo := &CertificateInfo{
			Certificate: cert,
			Request: &CertificateRequest{
				AuthzType: "dns",
				// Missing required fields - will always fail
			},
			Identifier: "test-cert",
		}

		err = service.renewCertificate(context.Background(), certInfo)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to renew certificate after")
	})

	t.Run("renewal with context cancellation during retry", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		config := DefaultConfig()
		config.DirectoryURL = "https://acme.example.com/directory"

		params := &Params{
			AccountEmail:  "test@example.com",
			AccountSigner: privateKey,
			Config:        config,
			Storage:       newMockStorage(),
			Logger:        logger,
		}

		client, err := NewClient(params)
		require.NoError(t, err)

		renewalConfig := DefaultRenewalConfig()
		renewalConfig.MaxRetries = 5
		renewalConfig.RetryInterval = 1 * time.Second
		service, err := NewRenewalService(client, renewalConfig, logger)
		require.NoError(t, err)

		cert, _ := generateTestCertificate(t, "example.com")

		certInfo := &CertificateInfo{
			Certificate: cert,
			Request: &CertificateRequest{
				AuthzType: "dns",
				// Missing required fields - will always fail
			},
			Identifier: "test-cert",
		}

		ctx, cancel := context.WithCancel(context.Background())

		// Cancel context after a short delay
		go func() {
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()

		err = service.renewCertificate(ctx, certInfo)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "context canceled"))
	})
}

// TestRenewalService_NilLogger tests service creation with nil logger
func TestRenewalService_NilLogger(t *testing.T) {
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

	renewalConfig := DefaultRenewalConfig()
	service, err := NewRenewalService(client, renewalConfig, nil)
	require.NoError(t, err)
	assert.NotNil(t, service)
	assert.NotNil(t, service.logger) // Should use default logger
}

// =====================================
// Tests from renewal_integration_test.go
// =====================================

type renewalMockServer struct {
	*httptest.Server
	t            *testing.T
	nonceCounter int64
	renewCount   int32
}

func newRenewalMockServer(t *testing.T) *renewalMockServer {
	m := &renewalMockServer{t: t}

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

func (m *renewalMockServer) handleDirectory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	dir := map[string]interface{}{
		"newNonce":   m.Server.URL + "/acme/new-nonce",
		"newAccount": m.Server.URL + "/acme/new-account",
		"newOrder":   m.Server.URL + "/acme/new-order",
		"revokeCert": m.Server.URL + "/acme/revoke-cert",
		"keyChange":  m.Server.URL + "/acme/key-change",
	}
	_ = json.NewEncoder(w).Encode(dir)
}

func (m *renewalMockServer) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	nonce := atomic.AddInt64(&m.nonceCounter, 1)
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", nonce))
	w.WriteHeader(http.StatusNoContent)
}

func (m *renewalMockServer) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", atomic.AddInt64(&m.nonceCounter, 1)))
	w.Header().Set("Location", m.Server.URL+"/acme/account/1")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "valid",
		"contact": []string{"mailto:test@example.com"},
	})
}

func (m *renewalMockServer) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", atomic.AddInt64(&m.nonceCounter, 1)))
	w.Header().Set("Location", m.Server.URL+"/acme/order/1")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "pending",
		"authorizations": []string{m.Server.URL + "/acme/authz/1"},
		"finalize":       m.Server.URL + "/acme/finalize/1",
		"identifiers": []map[string]string{
			{"type": "dns", "value": "example.com"},
		},
	})
}

func (m *renewalMockServer) handleAuthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", atomic.AddInt64(&m.nonceCounter, 1)))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "valid",
		"identifier": map[string]string{
			"type":  "dns",
			"value": "example.com",
		},
		"challenges": []map[string]interface{}{
			{
				"type":   "http-01",
				"status": "valid",
				"url":    m.Server.URL + "/acme/challenge/1",
				"token":  "test-token",
			},
		},
	})
}

func (m *renewalMockServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", atomic.AddInt64(&m.nonceCounter, 1)))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"type":   "http-01",
		"status": "valid",
		"token":  "test-token",
	})
}

func (m *renewalMockServer) handleFinalize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", atomic.AddInt64(&m.nonceCounter, 1)))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "valid",
		"certificate": m.Server.URL + "/acme/cert/1",
	})
}

func (m *renewalMockServer) handleCert(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt32(&m.renewCount, 1)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames:              []string{"example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour), // 90 days
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	_, _ = w.Write(certPEM)
}

func (m *renewalMockServer) handleCABundle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write([]byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"))
}

// createRenewalTestClient creates a client for renewal tests
func createRenewalTestClient(t *testing.T, server *renewalMockServer) *Client {
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serverCert := server.Server.Certificate()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})

	config := &Config{
		DirectoryURL:        server.Server.URL + "/directory",
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

// createExpiringCertificate creates a certificate that's about to expire
func createExpiringCertificate(t *testing.T, daysRemaining int) *x509.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	now := time.Now()
	totalDays := 90
	notBefore := now.Add(-time.Duration(totalDays-daysRemaining) * 24 * time.Hour)
	notAfter := now.Add(time.Duration(daysRemaining) * 24 * time.Hour)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames:              []string{"example.com"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// TestRenewalService_NewRenewalService_Integration tests creating a renewal service
func TestRenewalService_NewRenewalService_Integration(t *testing.T) {
	server := newRenewalMockServer(t)
	defer server.Close()

	client := createRenewalTestClient(t, server)
	defer func() { _ = client.Close() }()

	config := &RenewalConfig{
		CheckInterval:    1 * time.Hour,
		RenewalThreshold: 0.3,
		MaxRetries:       3,
		RetryInterval:    1 * time.Minute,
		NotifyOnSuccess:  true,
		NotifyOnFailure:  true,
	}

	logger := slog.Default()
	renewalService, err := NewRenewalService(client, config, logger)

	require.NoError(t, err)
	require.NotNil(t, renewalService)
	assert.Equal(t, 1*time.Hour, renewalService.config.CheckInterval)
	assert.Equal(t, 0.3, renewalService.config.RenewalThreshold)
}

// TestRenewalService_RegisterCertificate_Integration tests registering a certificate for renewal
func TestRenewalService_RegisterCertificate_Integration(t *testing.T) {
	server := newRenewalMockServer(t)
	defer server.Close()

	client := createRenewalTestClient(t, server)
	defer func() { _ = client.Close() }()

	config := &RenewalConfig{
		CheckInterval:    1 * time.Hour,
		RenewalThreshold: 0.3,
		MaxRetries:       3,
		RetryInterval:    1 * time.Minute,
	}

	logger := slog.Default()
	renewalService, err := NewRenewalService(client, config, logger)
	require.NoError(t, err)

	// Create a certificate to register
	cert := createExpiringCertificate(t, 30)

	// Create a certificate request for renewal
	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
	}

	// Register the certificate (cert, request, identifier)
	err = renewalService.RegisterCertificate(cert, req, "example.com")

	assert.NoError(t, err)
}

// TestRenewalService_RegisterCertificate_NilCert_Integration tests registering a nil certificate
func TestRenewalService_RegisterCertificate_NilCert_Integration(t *testing.T) {
	server := newRenewalMockServer(t)
	defer server.Close()

	client := createRenewalTestClient(t, server)
	defer func() { _ = client.Close() }()

	config := &RenewalConfig{
		CheckInterval:    1 * time.Hour,
		RenewalThreshold: 0.3,
	}

	logger := slog.Default()
	renewalService, err := NewRenewalService(client, config, logger)
	require.NoError(t, err)

	// Register nil certificate
	err = renewalService.RegisterCertificate(nil, nil, "example.com")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil certificate")
}

// TestRenewalService_CheckCertificate_Integration tests certificate checking
func TestRenewalService_CheckCertificate_Integration(t *testing.T) {
	server := newRenewalMockServer(t)
	defer server.Close()

	client := createRenewalTestClient(t, server)
	defer func() { _ = client.Close() }()

	config := &RenewalConfig{
		CheckInterval:    1 * time.Hour,
		RenewalThreshold: 0.3, // Renew when 30% validity remains
		MaxRetries:       3,
	}

	logger := slog.Default()
	renewalService, err := NewRenewalService(client, config, logger)
	require.NoError(t, err)

	tests := []struct {
		name          string
		daysRemaining int
		shouldRenew   bool
	}{
		{
			name:          "certificate needs renewal (10 days remaining out of 90)",
			daysRemaining: 10,
			shouldRenew:   true, // 10/90 = 11% < 30%
		},
		{
			name:          "certificate does not need renewal (60 days remaining)",
			daysRemaining: 60,
			shouldRenew:   false, // 60/90 = 66% > 30%
		},
		{
			name:          "certificate at threshold (27 days remaining)",
			daysRemaining: 27,
			shouldRenew:   true, // 27/90 = 30% <= 30%
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := createExpiringCertificate(t, tt.daysRemaining)
			certInfo := &CertificateInfo{
				Identifier:  "example.com",
				Certificate: cert,
			}

			status := renewalService.checkCertificate(certInfo)

			assert.Equal(t, tt.shouldRenew, status.ShouldRenew)
			assert.Equal(t, "example.com", status.CertificateSubject)
		})
	}
}

// TestRenewalService_StartStop_Integration tests starting and stopping the service
func TestRenewalService_StartStop_Integration(t *testing.T) {
	server := newRenewalMockServer(t)
	defer server.Close()

	client := createRenewalTestClient(t, server)
	defer func() { _ = client.Close() }()

	config := &RenewalConfig{
		CheckInterval:    100 * time.Millisecond, // Fast check for testing
		RenewalThreshold: 0.3,
		MaxRetries:       1,
		RetryInterval:    10 * time.Millisecond,
	}

	logger := slog.Default()
	renewalService, err := NewRenewalService(client, config, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Start the service
	_ = renewalService.Start(ctx)

	// Wait a bit
	time.Sleep(150 * time.Millisecond)

	// Stop the service
	_ = renewalService.Stop()

	// Should not panic and should stop gracefully
}

// TestRenewalService_CheckAndRenewCertificates_Integration tests the renewal check loop
func TestRenewalService_CheckAndRenewCertificates_Integration(t *testing.T) {
	server := newRenewalMockServer(t)
	defer server.Close()

	client := createRenewalTestClient(t, server)
	defer func() { _ = client.Close() }()

	config := &RenewalConfig{
		CheckInterval:    100 * time.Millisecond,
		RenewalThreshold: 0.3,
		MaxRetries:       1,
		RetryInterval:    10 * time.Millisecond,
		NotifyOnSuccess:  true,
		NotifyOnFailure:  true,
	}

	logger := slog.Default()
	renewalService, err := NewRenewalService(client, config, logger)
	require.NoError(t, err)

	// Register a certificate that needs renewal
	cert := createExpiringCertificate(t, 10)
	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
	}
	err = renewalService.RegisterCertificate(cert, req, "example.com")
	require.NoError(t, err)

	ctx := context.Background()

	// Call checkAndRenewCertificates directly
	renewalService.checkAndRenewCertificates(ctx)

	// The mock server should have received a renewal request
	// Note: This may not complete the full renewal flow in the mock
}

// TestRenewalConfig_Defaults_Integration tests renewal config default values
func TestRenewalConfig_Defaults_Integration(t *testing.T) {
	config := &RenewalConfig{}

	// Check that zero values are set
	assert.Equal(t, time.Duration(0), config.CheckInterval)
	assert.Equal(t, 0.0, config.RenewalThreshold)
	assert.Equal(t, 0, config.MaxRetries)
}

// TestRenewalStatus_Fields_Integration tests RenewalStatus struct
func TestRenewalStatus_Fields_Integration(t *testing.T) {
	status := &RenewalStatus{
		CertificateSubject: "test.example.com",
		NotBefore:          "2025-01-01T00:00:00Z",
		NotAfter:           "2025-12-31T23:59:59Z",
		DaysRemaining:      30,
		ShouldRenew:        true,
	}

	assert.Equal(t, "test.example.com", status.CertificateSubject)
	assert.Equal(t, 30, status.DaysRemaining)
	assert.True(t, status.ShouldRenew)
}

// TestCertificateInfo_Fields_Integration tests CertificateInfo struct
func TestCertificateInfo_Fields_Integration(t *testing.T) {
	cert := createExpiringCertificate(t, 30)

	info := &CertificateInfo{
		Identifier:  "example.com",
		Certificate: cert,
	}

	assert.Equal(t, "example.com", info.Identifier)
	assert.NotNil(t, info.Certificate)
	assert.Equal(t, "example.com", info.Certificate.Subject.CommonName)
}

// TestRenewalService_UnregisterCertificate_Integration tests unregistering a certificate
func TestRenewalService_UnregisterCertificate_Integration(t *testing.T) {
	server := newRenewalMockServer(t)
	defer server.Close()

	client := createRenewalTestClient(t, server)
	defer func() { _ = client.Close() }()

	config := &RenewalConfig{
		CheckInterval:    1 * time.Hour,
		RenewalThreshold: 0.3,
	}

	logger := slog.Default()
	renewalService, err := NewRenewalService(client, config, logger)
	require.NoError(t, err)

	// Register a certificate
	cert := createExpiringCertificate(t, 30)
	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
	}
	err = renewalService.RegisterCertificate(cert, req, "example.com")
	require.NoError(t, err)

	// Unregister it
	renewalService.UnregisterCertificate("example.com")

	// Should not be found anymore
	_, found := renewalService.certificates.Load("example.com")
	assert.False(t, found)
}

// TestRenewalService_ConcurrentRegistration_Integration tests concurrent certificate registration
func TestRenewalService_ConcurrentRegistration_Integration(t *testing.T) {
	server := newRenewalMockServer(t)
	defer server.Close()

	client := createRenewalTestClient(t, server)
	defer func() { _ = client.Close() }()

	config := &RenewalConfig{
		CheckInterval:    1 * time.Hour,
		RenewalThreshold: 0.3,
	}

	logger := slog.Default()
	renewalService, err := NewRenewalService(client, config, logger)
	require.NoError(t, err)

	// Register multiple certificates concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			cert := createExpiringCertificate(t, 30+idx)
			identifier := fmt.Sprintf("cert-%d.example.com", idx)
			req := &CertificateRequest{
				AuthzType:     "dns",
				AuthzValue:    identifier,
				ChallengeType: "http-01",
				CSR:           []byte("test-csr"),
			}
			_ = renewalService.RegisterCertificate(cert, req, identifier)
			done <- true
		}(i)
	}

	// Wait for all registrations
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all were registered
	count := 0
	renewalService.certificates.Range(func(key, value interface{}) bool {
		count++
		return true
	})

	assert.Equal(t, 10, count)
}

// =====================================
// Tests from renewal_unit_test.go
// =====================================

func TestNewRenewalService_Unit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := DefaultConfig()
	config.DirectoryURL = "https://acme.example.com/directory"

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        config,
		logger:        logger,
	}

	t.Run("nil client error", func(t *testing.T) {
		renewalConfig := DefaultRenewalConfig()
		renewalService, err := NewRenewalService(nil, renewalConfig, logger)

		assert.Error(t, err)
		assert.Nil(t, renewalService)
		assert.Equal(t, ErrNilClient, err)
	})

	t.Run("nil config uses default", func(t *testing.T) {
		renewalService, err := NewRenewalService(client, nil, logger)

		require.NoError(t, err)
		assert.NotNil(t, renewalService)
		assert.NotNil(t, renewalService.config)
	})

	t.Run("nil logger uses default", func(t *testing.T) {
		renewalConfig := DefaultRenewalConfig()
		renewalService, err := NewRenewalService(client, renewalConfig, nil)

		require.NoError(t, err)
		assert.NotNil(t, renewalService)
		assert.NotNil(t, renewalService.logger)
	})

	t.Run("invalid renewal config", func(t *testing.T) {
		invalidConfig := &RenewalConfig{
			RenewalThreshold: -1.0, // Invalid
			CheckInterval:    24 * time.Hour,
		}

		renewalService, err := NewRenewalService(client, invalidConfig, logger)

		assert.Error(t, err)
		assert.Nil(t, renewalService)
		assert.Contains(t, err.Error(), "invalid renewal config")
	})
}

func TestRenewalService_RegisterUnregister(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := DefaultConfig()
	config.DirectoryURL = "https://acme.example.com/directory"

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        config,
		logger:        logger,
	}

	renewalConfig := DefaultRenewalConfig()
	renewalService, err := NewRenewalService(client, renewalConfig, logger)
	require.NoError(t, err)

	// Generate test certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	req := &CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    "example.com",
		ChallengeType: "http-01",
		CSR:           []byte("test-csr"),
	}

	t.Run("successful registration", func(t *testing.T) {
		err := renewalService.RegisterCertificate(cert, req, "example.com")
		assert.NoError(t, err)
		assert.Equal(t, 1, renewalService.GetCertificateCount())
	})

	t.Run("nil certificate", func(t *testing.T) {
		err := renewalService.RegisterCertificate(nil, req, "test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil certificate")
	})

	t.Run("nil request", func(t *testing.T) {
		err := renewalService.RegisterCertificate(cert, nil, "test2")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil certificate request")
	})

	t.Run("unregister certificate", func(t *testing.T) {
		renewalService.UnregisterCertificate("example.com")
		assert.Equal(t, 0, renewalService.GetCertificateCount())
	})
}

func TestRenewalService_StartStop_Unit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := DefaultConfig()
	config.DirectoryURL = "https://acme.example.com/directory"

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        config,
		logger:        logger,
	}

	t.Run("stop not running service", func(t *testing.T) {
		renewalConfig := DefaultRenewalConfig()
		renewalService, err := NewRenewalService(client, renewalConfig, logger)
		require.NoError(t, err)

		err = renewalService.Stop()
		assert.Error(t, err)
		assert.Equal(t, ErrRenewalServiceNotRunning, err)
	})

	t.Run("start disabled service", func(t *testing.T) {
		renewalConfig := &RenewalConfig{
			Enabled:          false,
			CheckInterval:    100 * time.Millisecond,
			RenewalThreshold: 0.33,
			MaxRetries:       3,
		}

		renewalService, err := NewRenewalService(client, renewalConfig, logger)
		require.NoError(t, err)

		err = renewalService.Start(context.Background())
		assert.NoError(t, err)
		assert.False(t, renewalService.IsRunning())
	})

	t.Run("start and stop", func(t *testing.T) {
		renewalConfig := &RenewalConfig{
			Enabled:          true,
			CheckInterval:    100 * time.Millisecond,
			RenewalThreshold: 0.33,
			MaxRetries:       3,
		}

		renewalService, err := NewRenewalService(client, renewalConfig, logger)
		require.NoError(t, err)

		ctx := context.Background()
		err = renewalService.Start(ctx)
		assert.NoError(t, err)
		assert.True(t, renewalService.IsRunning())

		time.Sleep(50 * time.Millisecond)

		err = renewalService.Stop()
		assert.NoError(t, err)
		assert.False(t, renewalService.IsRunning())
	})
}

func TestRenewalService_GetRenewalStatus_Unit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := DefaultConfig()
	config.DirectoryURL = "https://acme.example.com/directory"

	client := &Client{
		accountEmail:  "test@example.com",
		accountSigner: privateKey,
		config:        config,
		logger:        logger,
	}

	renewalConfig := DefaultRenewalConfig()
	renewalService, err := NewRenewalService(client, renewalConfig, logger)
	require.NoError(t, err)

	// Generate test certificates
	for i := 0; i < 3; i++ {
		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)),
			Subject: pkix.Name{
				CommonName: "test" + string(rune(i)) + ".example.com",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		require.NoError(t, err)

		cert, err := x509.ParseCertificate(certDER)
		require.NoError(t, err)

		req := &CertificateRequest{
			AuthzType:     "dns",
			AuthzValue:    cert.Subject.CommonName,
			ChallengeType: "http-01",
			CSR:           []byte("test-csr"),
		}

		err = renewalService.RegisterCertificate(cert, req, cert.Subject.CommonName)
		require.NoError(t, err)
	}

	statuses := renewalService.GetRenewalStatus()
	assert.Len(t, statuses, 3)

	for _, status := range statuses {
		assert.NotEmpty(t, status.CertificateSubject)
		assert.NotEmpty(t, status.NotBefore)
		assert.NotEmpty(t, status.NotAfter)
	}
}
