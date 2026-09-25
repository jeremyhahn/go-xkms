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

// =============================================================================
// ListOrders Full Flow Tests - Target 0% -> 90%+
// =============================================================================

func TestListOrders_FullFlow_AccountError(t *testing.T) {
	// Create server that returns an error on account fetch
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-account":
			// Return error when trying to get account
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:unauthorized",
				"detail": "Account not found",
				"status": 401,
			})
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

	ctx := context.Background()
	orders, err := client.ListOrders(ctx)

	assert.Error(t, err)
	assert.Nil(t, orders)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.InternalServer, caErr.Type)
}

func TestListOrders_FullFlow_NoOrdersURL(t *testing.T) {
	// Create server that returns account without orders URL
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acme/acct/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "valid",
				"contact": []string{"mailto:test@example.com"},
				// No orders field
			})
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

	ctx := context.Background()
	orders, err := client.ListOrders(ctx)

	assert.Error(t, err)
	assert.Nil(t, orders)
	assert.ErrorIs(t, err, ErrNoOrdersURL)
}

func TestListOrders_FullFlow_FetchOrdersListError(t *testing.T) {
	// Create server that returns account with invalid orders URL
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acme/acct/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "valid",
				"contact": []string{"mailto:test@example.com"},
				"orders":  server.URL + "/acme/orders",
			})
		case "/acme/orders":
			// Return error on orders list
			w.WriteHeader(http.StatusInternalServerError)
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

	ctx := context.Background()
	orders, err := client.ListOrders(ctx)

	assert.Error(t, err)
	assert.Nil(t, orders)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.ConnectionFailure, caErr.Type)
}

func TestListOrders_FullFlow_Success(t *testing.T) {
	orderURLs := []string{
		"https://acme.example.com/orders/1",
		"https://acme.example.com/orders/2",
		"https://acme.example.com/orders/3",
	}

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acme/acct/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "valid",
				"contact": []string{"mailto:test@example.com"},
				"orders":  server.URL + "/acme/orders",
			})
		case "/acme/orders":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"orders": orderURLs,
			})
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

	ctx := context.Background()
	orders, err := client.ListOrders(ctx)

	require.NoError(t, err)
	assert.Equal(t, orderURLs, orders)
}

func TestFetchOrdersList_InvalidJSON(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	client := &Client{
		httpClient: server.Client(),
		logger:     slog.Default(),
	}

	ctx := context.Background()
	orders, err := client.fetchOrdersList(ctx, server.URL+"/orders")

	assert.Error(t, err)
	assert.Nil(t, orders)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.SerializationFailure, caErr.Type)
}

func TestFetchOrdersList_RequestCreationError(t *testing.T) {
	client := &Client{
		httpClient: http.DefaultClient,
		logger:     slog.Default(),
	}

	ctx := context.Background()
	// Invalid URL will cause request creation to fail
	orders, err := client.fetchOrdersList(ctx, "://invalid-url")

	assert.Error(t, err)
	assert.Nil(t, orders)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.ConnectionFailure, caErr.Type)
}

// =============================================================================
// FetchCertificateWithChain Tests - Target 84% -> 90%+
// =============================================================================

func TestFetchCertificateWithChain_PreferredChainNotFound_NoFallback(t *testing.T) {
	// Create test certificate
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		Issuer:       pkix.Name{CommonName: "Different Root CA"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/pem-certificate-chain")

		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/cert/1":
			if r.Method == http.MethodHead {
				// No alternate chains
				w.WriteHeader(http.StatusOK)
			} else {
				_, _ = w.Write(certPEM)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	acmeKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          acmeKey,
		HTTPClient:   server.Client(),
	}

	client := &Client{
		client:        acmeClient,
		config:        &Config{DirectoryURL: server.URL + "/directory", Timeout: 30 * time.Second},
		httpClient:    server.Client(),
		logger:        slog.Default(),
		accountSigner: acmeKey,
	}

	ctx := context.Background()
	chain, err := client.FetchCertificateWithChain(ctx, server.URL+"/cert/1", &ChainOption{
		PreferredChain: "ISRG Root X1",
		AllowFallback:  false,
	})

	assert.Error(t, err)
	assert.Nil(t, chain)
	assert.ErrorIs(t, err, ErrNoAlternateChains)
}

func TestFetchCertificateWithChain_AlternateChainsFetchError_WithFallback(t *testing.T) {
	// Create test certificate
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		Issuer:       pkix.Name{CommonName: "Different Root CA"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")

		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/cert/1":
			if r.Method == http.MethodHead {
				// HEAD request fails
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				w.Header().Set("Content-Type", "application/pem-certificate-chain")
				_, _ = w.Write(certPEM)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	acmeKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          acmeKey,
		HTTPClient:   server.Client(),
	}

	client := &Client{
		client:        acmeClient,
		config:        &Config{DirectoryURL: server.URL + "/directory", Timeout: 30 * time.Second},
		httpClient:    server.Client(),
		logger:        slog.Default(),
		accountSigner: acmeKey,
	}

	ctx := context.Background()
	chain, err := client.FetchCertificateWithChain(ctx, server.URL+"/cert/1", &ChainOption{
		PreferredChain: "ISRG Root X1",
		AllowFallback:  true,
	})

	// Should fallback to default chain
	require.NoError(t, err)
	assert.NotNil(t, chain)
}

func TestFetchCertificateWithChain_AlternateChainsFetchError_NoFallback(t *testing.T) {
	// Create test certificate
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		Issuer:       pkix.Name{CommonName: "Different Root CA"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")

		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/cert/1":
			if r.Method == http.MethodHead {
				// HEAD request fails
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				w.Header().Set("Content-Type", "application/pem-certificate-chain")
				_, _ = w.Write(certPEM)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	acmeKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          acmeKey,
		HTTPClient:   server.Client(),
	}

	client := &Client{
		client:        acmeClient,
		config:        &Config{DirectoryURL: server.URL + "/directory", Timeout: 30 * time.Second},
		httpClient:    server.Client(),
		logger:        slog.Default(),
		accountSigner: acmeKey,
	}

	ctx := context.Background()
	chain, err := client.FetchCertificateWithChain(ctx, server.URL+"/cert/1", &ChainOption{
		PreferredChain: "ISRG Root X1",
		AllowFallback:  false,
	})

	assert.Error(t, err)
	assert.Nil(t, chain)
}

func TestFetchCertificateWithChain_AlternatesSearched_PreferredNotFound_WithFallback(t *testing.T) {
	// Create test certificates - default and alternate both with different roots
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	defaultCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		Issuer:       pkix.Name{CommonName: "Default Root CA"},
	}
	defaultDER, _ := x509.CreateCertificate(rand.Reader, defaultCert, defaultCert, &key.PublicKey, key)
	defaultPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: defaultDER})

	altCert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Cert Alt"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		Issuer:       pkix.Name{CommonName: "Alternate Root CA"},
	}
	altDER, _ := x509.CreateCertificate(rand.Reader, altCert, altCert, &key.PublicKey, key)
	altPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: altDER})

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")

		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/cert/1":
			if r.Method == http.MethodHead {
				w.Header().Set("Link", `<`+server.URL+`/cert/alt>; rel="alternate"`)
				w.WriteHeader(http.StatusOK)
			} else {
				w.Header().Set("Content-Type", "application/pem-certificate-chain")
				_, _ = w.Write(defaultPEM)
			}
		case "/cert/alt":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			_, _ = w.Write(altPEM)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	acmeKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          acmeKey,
		HTTPClient:   server.Client(),
	}

	client := &Client{
		client:        acmeClient,
		config:        &Config{DirectoryURL: server.URL + "/directory", Timeout: 30 * time.Second},
		httpClient:    server.Client(),
		logger:        slog.Default(),
		accountSigner: acmeKey,
	}

	ctx := context.Background()
	chain, err := client.FetchCertificateWithChain(ctx, server.URL+"/cert/1", &ChainOption{
		PreferredChain: "ISRG Root X1", // Neither chain has this
		AllowFallback:  true,
	})

	// Should fallback to default chain
	require.NoError(t, err)
	assert.NotNil(t, chain)
}

// =============================================================================
// GetCertificateIDFromHash Tests - Target 85.7% -> 90%+
// =============================================================================

func TestGetCertificateIDFromHash_NilCertificate91(t *testing.T) {
	result := GetCertificateIDFromHash(nil)
	assert.Empty(t, result)
}

func TestGetCertificateIDFromHash_EmptyRaw91(t *testing.T) {
	cert := &x509.Certificate{
		Raw: nil,
	}
	result := GetCertificateIDFromHash(cert)
	assert.Empty(t, result)
}

func TestGetCertificateIDFromHash_ShortEncoded91(t *testing.T) {
	// Create a very small certificate DER to test short encoded path
	cert := &x509.Certificate{
		Raw: []byte{0x30, 0x00}, // Minimal DER structure
	}
	result := GetCertificateIDFromHash(cert)
	assert.NotEmpty(t, result)
	// The hash will be 43 base64 chars, so it will be truncated to 32
	assert.LessOrEqual(t, len(result), 32)
}

func TestGetCertificateIDFromHash_ValidCertificate91(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	result := GetCertificateIDFromHash(cert)
	assert.NotEmpty(t, result)
	assert.Equal(t, 32, len(result))
}

// =============================================================================
// CreateOrderWithReplaces Tests - Target 84.2% -> 90%+
// =============================================================================

func TestCreateOrderWithReplaces_EmptyDomains91(t *testing.T) {
	client := &Client{
		config:     &Config{DirectoryURL: "https://example.com/directory"},
		httpClient: http.DefaultClient,
		logger:     slog.Default(),
	}

	ctx := context.Background()
	_, err := client.CreateOrderWithReplaces(ctx, nil, "test-cert-id")

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidDomains)
}

func TestCreateOrderWithReplaces_EmptyCertID91(t *testing.T) {
	client := &Client{
		config:     &Config{DirectoryURL: "https://example.com/directory"},
		httpClient: http.DefaultClient,
		logger:     slog.Default(),
	}

	ctx := context.Background()
	_, err := client.CreateOrderWithReplaces(ctx, []string{"example.com"}, "")

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCertificateID)
}

func TestCreateOrderWithReplaces_NoRenewalInfoEndpoint91(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/directory":
			// No renewalInfo endpoint
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := &Client{
		config:     &Config{DirectoryURL: server.URL + "/directory"},
		httpClient: http.DefaultClient,
		logger:     slog.Default(),
	}

	ctx := context.Background()
	_, err := client.CreateOrderWithReplaces(ctx, []string{"example.com"}, "test-cert-id")

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrARINotSupported)
}

// =============================================================================
// CheckOCSP Tests - Target 87.5% -> 90%+
// =============================================================================

func TestCheckOCSP_UnknownStatus91(t *testing.T) {
	// Create test certificates
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		OCSPServer:   []string{"http://ocsp.example.com"},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	// Mock OCSP server returning unknown status
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a minimal OCSP response with unknown status
		// This is a simplified test - real OCSP response would be properly formatted
		w.WriteHeader(http.StatusOK)
		// The response will fail to parse, triggering error path
		_, _ = w.Write([]byte{0x30, 0x00})
	}))
	defer server.Close()

	// Update certificate to use our test server
	leafCert.OCSPServer = []string{server.URL}

	ctx := context.Background()
	err := CheckOCSP(ctx, leafCert, caCert)

	// Should return error due to invalid OCSP response
	assert.Error(t, err)
}

// =============================================================================
// PreAuthorize Tests - Target 88.2% -> 90%+
// =============================================================================

func TestPreAuthorize_DiscoverError91(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Use a short timeout HTTP client to prevent ACME library retries from hanging the test
	httpClient := server.Client()
	httpClient.Timeout = 500 * time.Millisecond

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          key,
		HTTPClient:   httpClient,
	}

	client := &Client{
		client:        acmeClient,
		config:        &Config{DirectoryURL: server.URL + "/directory", Timeout: 500 * time.Millisecond},
		httpClient:    httpClient,
		logger:        slog.Default(),
		accountSigner: key,
	}

	// Use context with short timeout to prevent retry loops
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	authz, err := client.PreAuthorize(ctx, Identifier{Type: "dns", Value: "example.com"})

	assert.Error(t, err)
	assert.Nil(t, authz)
}

func TestPreAuthorize_NoAuthzURL91(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/directory":
			// No authz URL in directory
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
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

	ctx := context.Background()
	authz, err := client.PreAuthorize(ctx, Identifier{Type: "dns", Value: "example.com"})

	assert.Error(t, err)
	assert.Nil(t, authz)
	assert.ErrorIs(t, err, ErrPreAuthNotSupported)
}

func TestPreAuthorize_AuthorizeFails91(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
				"newAuthz":   server.URL + "/new-authz",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-authz":
			// Return error
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:unauthorized",
				"detail": "Unauthorized",
				"status": 403,
			})
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

	ctx := context.Background()
	authz, err := client.PreAuthorize(ctx, Identifier{Type: "dns", Value: "example.com"})

	assert.Error(t, err)
	assert.Nil(t, authz)
	assert.ErrorIs(t, err, ErrPreAuthFailed)
}

// =============================================================================
// fetchAlternateChains Tests - Target 90.9% -> 95%+
// =============================================================================

func TestFetchAlternateChains_RequestCreationError91(t *testing.T) {
	client := &Client{
		httpClient: http.DefaultClient,
		logger:     slog.Default(),
	}

	ctx := context.Background()
	chains, err := client.fetchAlternateChains(ctx, "://invalid-url")

	assert.Error(t, err)
	assert.Nil(t, chains)
}

func TestFetchAlternateChains_AllChainsFetchFail91(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cert":
			// Return Link headers with alternate URLs that will fail
			w.Header().Set("Link", `<`+server.URL+`/alt1>; rel="alternate", <`+server.URL+`/alt2>; rel="alternate"`)
			w.WriteHeader(http.StatusOK)
		case "/alt1", "/alt2":
			// All alternates fail
			w.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := &Client{
		httpClient: http.DefaultClient,
		logger:     slog.Default(),
	}

	ctx := context.Background()
	chains, err := client.fetchAlternateChains(ctx, server.URL+"/cert")

	assert.Error(t, err)
	assert.Nil(t, chains)
	assert.ErrorIs(t, err, ErrNoAlternateChains)
}

// =============================================================================
// fetchChainFromURL Tests - Target 92.9% -> 95%+
// =============================================================================

func TestFetchChainFromURL_RequestCreationError91(t *testing.T) {
	client := &Client{
		httpClient: http.DefaultClient,
		logger:     slog.Default(),
	}

	ctx := context.Background()
	chain, err := client.fetchChainFromURL(ctx, "://invalid-url")

	assert.Error(t, err)
	assert.Nil(t, chain)
}

func TestFetchChainFromURL_HTTPError91(t *testing.T) {
	client := &Client{
		httpClient: &http.Client{Timeout: 100 * time.Millisecond},
		logger:     slog.Default(),
	}

	ctx := context.Background()
	// Use TEST-NET address that won't respond
	chain, err := client.fetchChainFromURL(ctx, "http://192.0.2.1/cert")

	assert.Error(t, err)
	assert.Nil(t, chain)
}

func TestFetchChainFromURL_NonOKStatus91(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client := &Client{
		httpClient: http.DefaultClient,
		logger:     slog.Default(),
	}

	ctx := context.Background()
	chain, err := client.fetchChainFromURL(ctx, server.URL+"/cert")

	assert.Error(t, err)
	assert.Nil(t, chain)
}

// =============================================================================
// ShouldRenewAt Tests - Target 90.9% -> 95%+
// =============================================================================

func TestShouldRenewAt_NilCertificate91(t *testing.T) {
	client := &Client{
		logger: slog.Default(),
	}

	ctx := context.Background()
	renewTime, err := client.ShouldRenewAt(ctx, nil, 0.3)

	assert.Error(t, err)
	assert.True(t, renewTime.IsZero())
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestShouldRenewAt_CertBasedFallback91(t *testing.T) {
	// Create a test server that doesn't support ARI (no renewalInfo endpoint)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				// No renewalInfo - ARI not supported
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create a test certificate
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	client := &Client{
		config:     &Config{DirectoryURL: server.URL + "/directory"},
		httpClient: http.DefaultClient,
		logger:     slog.Default(),
	}

	ctx := context.Background()
	renewTime, err := client.ShouldRenewAt(ctx, cert, 0.3)

	// Should succeed using certificate-based fallback calculation
	assert.NoError(t, err)
	assert.False(t, renewTime.IsZero())
}

// =============================================================================
// createOrderWithReplacesInternal Tests - Target 80% -> 90%+
// =============================================================================

func TestCreateOrderWithReplacesInternal_AuthorizeOrderError91(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-order":
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:unauthorized",
				"detail": "Unauthorized",
				"status": 403,
			})
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

	ctx := context.Background()
	order, err := client.createOrderWithReplacesInternal(ctx, []acme.AuthzID{{Type: "dns", Value: "example.com"}}, "test-replaces")

	assert.Error(t, err)
	assert.Nil(t, order)
}

func TestCreateOrderWithReplacesInternal_Success91(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/account/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "valid",
				"contact": []string{"mailto:test@example.com"},
				"orders":  server.URL + "/account/1/orders",
			})
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{server.URL + "/authz/1"},
				"finalize":       server.URL + "/finalize/1",
			})
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

	ctx := context.Background()
	order, err := client.createOrderWithReplacesInternal(ctx, []acme.AuthzID{{Type: "dns", Value: "example.com"}}, "test-replaces")

	require.NoError(t, err)
	assert.NotNil(t, order)
	assert.Equal(t, "pending", order.Status)
}

// =============================================================================
// getRenewalInfoEndpoint Tests - Target 90% -> 95%+
// =============================================================================

func TestGetRenewalInfoEndpoint_DirectoryRequestError91(t *testing.T) {
	client := &Client{
		config:     &Config{DirectoryURL: "://invalid-url"},
		httpClient: http.DefaultClient,
		logger:     slog.Default(),
	}

	ctx := context.Background()
	endpoint, err := client.getRenewalInfoEndpoint(ctx)

	assert.Error(t, err)
	assert.Empty(t, endpoint)
}

func TestGetRenewalInfoEndpoint_DirectoryFetchError91(t *testing.T) {
	client := &Client{
		config:     &Config{DirectoryURL: "http://192.0.2.1/directory"},
		httpClient: &http.Client{Timeout: 100 * time.Millisecond},
		logger:     slog.Default(),
	}

	ctx := context.Background()
	endpoint, err := client.getRenewalInfoEndpoint(ctx)

	assert.Error(t, err)
	assert.Empty(t, endpoint)
}
