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
	"testing"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
)

// createTestCertPEM creates a test certificate in PEM format
func createTestCertPEM(t *testing.T, commonName string) ([]byte, *x509.Certificate) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		Issuer:       pkix.Name{CommonName: commonName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		IsCA:         true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return certPEM, cert
}

// TestFetchCertificateWithChain_Success tests FetchCertificateWithChain with successful response
func TestFetchCertificateWithChain_Success(t *testing.T) {
	certPEM, _ := createTestCertPEM(t, "Test Root CA")

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")

		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/cert/1":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			if r.Method == http.MethodHead {
				// No Link headers - no alternate chains
				return
			}
			w.Write(certPEM)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

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

	// Test with nil options (uses defaults)
	chain, err := client.FetchCertificateWithChain(context.Background(), server.URL+"/cert/1", nil)
	require.NoError(t, err)
	assert.Len(t, chain, 1)
	assert.Equal(t, "Test Root CA", chain[0].Subject.CommonName)

	// Test with empty preferred chain (returns default)
	opts := &ChainOption{PreferredChain: "", AllowFallback: true}
	chain, err = client.FetchCertificateWithChain(context.Background(), server.URL+"/cert/1", opts)
	require.NoError(t, err)
	assert.Len(t, chain, 1)
}

// TestFetchCertificateWithChain_PreferredChainMatch tests FetchCertificateWithChain when default matches preferred
func TestFetchCertificateWithChain_PreferredChainMatch(t *testing.T) {
	certPEM, _ := createTestCertPEM(t, "Test Root CA")

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")

		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/cert/1":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.Write(certPEM)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

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

	// Test with preferred chain that matches
	opts := &ChainOption{PreferredChain: "Test Root CA", AllowFallback: true}
	chain, err := client.FetchCertificateWithChain(context.Background(), server.URL+"/cert/1", opts)
	require.NoError(t, err)
	assert.Len(t, chain, 1)
}

// TestFetchCertificateWithChain_PreferredNotFoundWithFallback tests fallback behavior
func TestFetchCertificateWithChain_PreferredNotFoundWithFallback(t *testing.T) {
	certPEM, _ := createTestCertPEM(t, "Default Root")

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")

		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/cert/1":
			if r.Method == http.MethodHead {
				// No alternate chains
				return
			}
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.Write(certPEM)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

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

	// Test with preferred chain that doesn't exist (should fallback)
	opts := &ChainOption{PreferredChain: "Nonexistent Root", AllowFallback: true}
	chain, err := client.FetchCertificateWithChain(context.Background(), server.URL+"/cert/1", opts)
	require.NoError(t, err)
	assert.Len(t, chain, 1)
	assert.Equal(t, "Default Root", chain[0].Subject.CommonName)
}

// TestFetchCertificateWithChain_PreferredNotFoundNoFallback tests error when no fallback
func TestFetchCertificateWithChain_PreferredNotFoundNoFallback(t *testing.T) {
	certPEM, _ := createTestCertPEM(t, "Default Root")

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")

		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/cert/1":
			if r.Method == http.MethodHead {
				// No alternate chains
				return
			}
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.Write(certPEM)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

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

	// Test with preferred chain that doesn't exist and no fallback
	opts := &ChainOption{PreferredChain: "Nonexistent Root", AllowFallback: false}
	_, err := client.FetchCertificateWithChain(context.Background(), server.URL+"/cert/1", opts)
	assert.ErrorIs(t, err, ErrNoAlternateChains)
}

// TestFetchCertificateWithChain_WithAlternateChains tests fetching alternate chains
func TestFetchCertificateWithChain_WithAlternateChains(t *testing.T) {
	defaultCertPEM, _ := createTestCertPEM(t, "Default Root")
	altCertPEM, _ := createTestCertPEM(t, "Preferred Root")

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")

		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/cert/1":
			if r.Method == http.MethodHead {
				// Return Link header with alternate chain
				w.Header().Set("Link", `<`+server.URL+`/cert/alt1>; rel="alternate"`)
				return
			}
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.Write(defaultCertPEM)
		case "/cert/alt1":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.Write(altCertPEM)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

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

	// Test with preferred chain that exists in alternates
	opts := &ChainOption{PreferredChain: "Preferred Root", AllowFallback: true}
	chain, err := client.FetchCertificateWithChain(context.Background(), server.URL+"/cert/1", opts)
	require.NoError(t, err)
	assert.Len(t, chain, 1)
	assert.Equal(t, "Preferred Root", chain[0].Subject.CommonName)
}

// TestGetAvailableChains_Success tests GetAvailableChains
func TestGetAvailableChains_Success(t *testing.T) {
	defaultCertPEM, _ := createTestCertPEM(t, "Default Root")
	altCertPEM, _ := createTestCertPEM(t, "Alternate Root")

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")

		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/cert/1":
			if r.Method == http.MethodHead {
				w.Header().Set("Link", `<`+server.URL+`/cert/alt1>; rel="alternate"`)
				return
			}
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.Write(defaultCertPEM)
		case "/cert/alt1":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.Write(altCertPEM)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

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

	chains, err := client.GetAvailableChains(context.Background(), server.URL+"/cert/1")
	require.NoError(t, err)
	assert.Len(t, chains, 2)
}

// TestGetAvailableChains_FetchError tests GetAvailableChains with fetch error
func TestGetAvailableChains_FetchError(t *testing.T) {
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
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

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

	_, err := client.GetAvailableChains(context.Background(), server.URL+"/cert/nonexistent")
	assert.Error(t, err)
}

// TestFetchCertificateWithChain_FetchError tests FetchCertificateWithChain with fetch error
func TestFetchCertificateWithChain_FetchError(t *testing.T) {
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
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

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

	_, err := client.FetchCertificateWithChain(context.Background(), server.URL+"/cert/nonexistent", nil)
	assert.Error(t, err)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.ConnectionFailure, caErr.Type)
}

// TestFetchCertificateWithChain_AlternateChainFetchErrorWithFallback tests fallback when alternate fetch fails
func TestFetchCertificateWithChain_AlternateChainFetchErrorWithFallback(t *testing.T) {
	defaultCertPEM, _ := createTestCertPEM(t, "Default Root")

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")

		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/cert/1":
			if r.Method == http.MethodHead {
				// Return Link header with alternate chain that will fail
				w.Header().Set("Link", `<`+server.URL+`/cert/alt-fail>; rel="alternate"`)
				return
			}
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.Write(defaultCertPEM)
		case "/cert/alt-fail":
			// Return error for alternate chain
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

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

	// With AllowFallback=true, should return default chain even when alternate fetch fails
	opts := &ChainOption{PreferredChain: "Nonexistent Root", AllowFallback: true}
	chain, err := client.FetchCertificateWithChain(context.Background(), server.URL+"/cert/1", opts)
	require.NoError(t, err)
	assert.Len(t, chain, 1)
	assert.Equal(t, "Default Root", chain[0].Subject.CommonName)
}
