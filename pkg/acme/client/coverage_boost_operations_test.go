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

// TestListOrders_WithMockServer tests ListOrders with a full mock server
func TestListOrders_WithMockServer(t *testing.T) {
	orderURLs := []string{
		"https://acme.example.com/orders/1",
		"https://acme.example.com/orders/2",
	}

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
		case "/acme/acct/1":
			w.Header().Set("Location", server.URL+"/acme/acct/1")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "valid",
				"contact": []string{"mailto:test@example.com"},
				"orders":  server.URL + "/acme/orders",
			})
		case "/acme/orders":
			json.NewEncoder(w).Encode(map[string]interface{}{
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
		storage:       newMockStorage(),
	}

	// Test fetchOrdersList directly
	urls, err := client.fetchOrdersList(context.Background(), server.URL+"/acme/orders")
	require.NoError(t, err)
	assert.Equal(t, orderURLs, urls)
}

// TestGetOrder_WithMockServer tests GetOrder with a full mock server
func TestGetOrder_WithMockServer(t *testing.T) {
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
		case "/acme/order/1":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "ready",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{server.URL + "/authz/1"},
				"finalize":       server.URL + "/finalize/1",
				"certificate":    server.URL + "/cert/1",
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

	order, err := client.GetOrder(context.Background(), server.URL+"/acme/order/1")
	require.NoError(t, err)
	assert.NotNil(t, order)
	assert.Equal(t, "ready", order.Status)
}

// TestGetOrder_NotFound tests GetOrder with a not found response
func TestGetOrder_NotFound(t *testing.T) {
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
		case "/acme/order/nonexistent":
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:malformed",
				"detail": "Order not found",
				"status": 404,
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

	_, err := client.GetOrder(context.Background(), server.URL+"/acme/order/nonexistent")
	assert.Error(t, err)
}

// TestGetAuthorization_WithMockServer tests GetAuthorization with a full mock server
func TestGetAuthorization_WithMockServer(t *testing.T) {
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
		case "/acme/authz/1":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "valid",
				"identifier": map[string]string{
					"type":  "dns",
					"value": "example.com",
				},
				"challenges": []map[string]interface{}{
					{
						"type":   "http-01",
						"url":    server.URL + "/challenge/1",
						"token":  "test-token",
						"status": "valid",
					},
				},
				"expires": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
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

	authz, err := client.GetAuthorization(context.Background(), server.URL+"/acme/authz/1")
	require.NoError(t, err)
	assert.NotNil(t, authz)
	assert.Equal(t, "valid", authz.Status)
}

// TestGetAuthorization_Error tests GetAuthorization with an error response
func TestGetAuthorization_Error(t *testing.T) {
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
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:unauthorized",
				"detail": "Authorization not found",
				"status": 403,
			})
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

	_, err := client.GetAuthorization(context.Background(), server.URL+"/acme/authz/1")
	assert.Error(t, err)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.InternalServer, caErr.Type)
}

// TestDeactivateAuthorization_WithMockServer tests DeactivateAuthorization with a full mock server
func TestDeactivateAuthorization_WithMockServer(t *testing.T) {
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
		case "/acme/authz/1":
			// Return deactivated authorization
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "deactivated",
				"identifier": map[string]string{
					"type":  "dns",
					"value": "example.com",
				},
				"challenges": []map[string]interface{}{},
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

	err := client.DeactivateAuthorization(context.Background(), server.URL+"/acme/authz/1")
	require.NoError(t, err)
}

// TestDeactivateAuthorization_Error tests DeactivateAuthorization with an error response
func TestDeactivateAuthorization_Error(t *testing.T) {
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
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:unauthorized",
				"detail": "Cannot deactivate",
				"status": 403,
			})
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

	err := client.DeactivateAuthorization(context.Background(), server.URL+"/acme/authz/1")
	assert.Error(t, err)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.InternalServer, caErr.Type)
}

// TestDeactivateAccount_Error tests DeactivateAccount with an error response
func TestDeactivateAccount_Error_Coverage(t *testing.T) {
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
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:unauthorized",
				"detail": "Cannot deactivate",
				"status": 403,
			})
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
		accountEmail:  "test@example.com",
	}

	err := client.DeactivateAccount(context.Background())
	assert.Error(t, err)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.InternalServer, caErr.Type)
}

// TestCreateOrderWithReplaces_WithMockServer tests CreateOrderWithReplaces
func TestCreateOrderWithReplaces_WithMockServer(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/directory":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":    server.URL + "/new-nonce",
				"newAccount":  server.URL + "/new-account",
				"newOrder":    server.URL + "/new-order",
				"renewalInfo": server.URL + "/renewalInfo",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
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

	order, err := client.CreateOrderWithReplaces(context.Background(), []string{"example.com"}, "YWtp.c2VyaWFs")
	require.NoError(t, err)
	assert.NotNil(t, order)
	assert.Equal(t, "pending", order.Status)
}

// TestCreateOrderWithReplaces_ARINotSupported tests CreateOrderWithReplaces when ARI not supported
func TestCreateOrderWithReplaces_ARINotSupported(t *testing.T) {
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
				// No renewalInfo - ARI not supported
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

	_, err := client.CreateOrderWithReplaces(context.Background(), []string{"example.com"}, "YWtp.c2VyaWFs")
	assert.ErrorIs(t, err, ErrARINotSupported)
}

// TestShouldRenewAt_WithARI tests ShouldRenewAt with ARI available
func TestShouldRenewAt_WithARI(t *testing.T) {
	startTime := time.Now().Add(24 * time.Hour)
	endTime := time.Now().Add(48 * time.Hour)

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/directory":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":    server.URL + "/new-nonce",
				"newAccount":  server.URL + "/new-account",
				"newOrder":    server.URL + "/new-order",
				"renewalInfo": server.URL + "/renewalInfo",
			})
		default:
			// Return renewal info for any certificate ID
			if len(r.URL.Path) > 12 && r.URL.Path[:12] == "/renewalInfo" {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"suggestedWindow": map[string]string{
						"start": startTime.Format(time.RFC3339),
						"end":   endTime.Format(time.RFC3339),
					},
				})
				return
			}
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &Client{
		config:        &Config{DirectoryURL: server.URL + "/directory", Timeout: 30 * time.Second},
		httpClient:    server.Client(),
		logger:        slog.Default(),
		accountSigner: key,
	}

	// Create certificate with AKI
	template := &x509.Certificate{
		SerialNumber:   big.NewInt(12345),
		Subject:        pkix.Name{CommonName: "Test"},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(90 * 24 * time.Hour),
		AuthorityKeyId: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	renewAt, err := client.ShouldRenewAt(context.Background(), cert, 0.3)
	require.NoError(t, err)
	assert.False(t, renewAt.IsZero())
}

// generateTestCertWithAKI generates a test certificate with AKI for testing
func generateTestCertWithAKI(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:   big.NewInt(12345),
		Subject:        pkix.Name{CommonName: "Test With AKI"},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(90 * 24 * time.Hour),
		AuthorityKeyId: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

// TestGetCertificateID_WithAKI tests GetCertificateID with a certificate that has AKI
func TestGetCertificateID_WithAKI(t *testing.T) {
	cert, _ := generateTestCertWithAKI(t)

	id := GetCertificateID(cert)
	assert.NotEmpty(t, id)
	assert.Contains(t, id, ".")
}

// TestGetRenewalInfo_InvalidEndTime tests GetRenewalInfo with invalid end time
func TestGetRenewalInfo_InvalidEndTime(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/directory" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"renewalInfo": server.URL + "/renewalInfo",
			})
			return
		}
		if r.URL.Path == "/renewalInfo/test-cert-id" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"suggestedWindow": map[string]string{
					"start": time.Now().Format(time.RFC3339),
					"end":   "invalid-end-time",
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &Client{
		config:        &Config{DirectoryURL: server.URL + "/directory", Timeout: 30 * time.Second},
		httpClient:    server.Client(),
		logger:        slog.Default(),
		accountSigner: key,
	}

	_, err := client.GetRenewalInfo(context.Background(), "test-cert-id")
	assert.Error(t, err)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.Malformed, caErr.Type)
}

// TestGetRenewalInfo_ACME_Error tests GetRenewalInfo with ACME error response
func TestGetRenewalInfo_ACME_Error(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/directory" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"renewalInfo": server.URL + "/renewalInfo",
			})
			return
		}
		if r.URL.Path == "/renewalInfo/test-cert-id" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:malformed",
				"detail": "Invalid certificate ID",
				"status": 400,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &Client{
		config:        &Config{DirectoryURL: server.URL + "/directory", Timeout: 30 * time.Second},
		httpClient:    server.Client(),
		logger:        slog.Default(),
		accountSigner: key,
	}

	_, err := client.GetRenewalInfo(context.Background(), "test-cert-id")
	assert.Error(t, err)
}

// TestFetchChainFromURL_Error tests fetchChainFromURL with various errors
func TestFetchChainFromURL_Error(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &Client{
		httpClient: server.Client(),
		logger:     slog.Default(),
	}
	_ = key

	_, err := client.fetchChainFromURL(context.Background(), server.URL+"/cert")
	assert.Error(t, err)
}

// Test PEM certificate chain with multiple certs
func TestParseCertificateChain_MultipleCerts(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create leaf certificate
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Leaf"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, leafTemplate, &key.PublicKey, key)

	// Create intermediate certificate
	intTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Intermediate"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	intDER, _ := x509.CreateCertificate(rand.Reader, intTemplate, intTemplate, &key.PublicKey, key)

	// Combine into chain
	chainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intDER})...)

	certs, err := parseCertificateChain(chainPEM)
	require.NoError(t, err)
	assert.Len(t, certs, 2)
	assert.Equal(t, "Leaf", certs[0].Subject.CommonName)
	assert.Equal(t, "Intermediate", certs[1].Subject.CommonName)
}
