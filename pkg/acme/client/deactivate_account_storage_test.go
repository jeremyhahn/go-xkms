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
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"

	"github.com/jeremyhahn/go-xkms/internal/acmetestutil"
)

// deactivateStorageMockServer creates a mock ACME server for testing
// DeactivateAccount with storage enabled. It tracks the number of
// new-account calls to distinguish registration from GetReg lookups.
func deactivateStorageMockServer(t *testing.T) *httptest.Server {
	t.Helper()

	var server *httptest.Server
	var newAccountCalls atomic.Int32
	var nonceCounter atomic.Int64

	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-"+strconv.FormatInt(nonceCounter.Add(1), 10))
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
				"revokeCert": server.URL + "/revoke-cert",
				"keyChange":  server.URL + "/key-change",
				"meta":       map[string]interface{}{"termsOfService": "https://example.com/terms"},
			})

		case r.URL.Path == "/new-nonce":
			w.WriteHeader(http.StatusNoContent)

		case r.URL.Path == "/new-account":
			w.Header().Set("Location", server.URL+"/acme/account/42")

			count := newAccountCalls.Add(1)
			if count == 1 {
				// First call: registration (expects 201 Created)
				w.WriteHeader(http.StatusCreated)
			} else {
				// Subsequent calls: GetReg lookup (expects 200 OK)
				w.WriteHeader(http.StatusOK)
			}

			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "valid",
				"contact": []string{"mailto:test@example.com"},
				"orders":  server.URL + "/acme/account/42/orders",
			})

		case strings.HasPrefix(r.URL.Path, "/acme/account/"):
			w.Header().Set("Location", server.URL+"/acme/account/42")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "deactivated",
				"contact": []string{"mailto:test@example.com"},
				"orders":  server.URL + "/acme/account/42/orders",
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	return server
}

// createDeactivateTestClient creates a test client for deactivate storage tests.
func createDeactivateTestClient(t *testing.T, server *httptest.Server, store *mockStorage) *Client {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := DefaultConfig()
	config.DirectoryURL = server.URL + "/directory"
	config.SystemCertPool = false
	config.RequestServerBundle = false

	params := &Params{
		AccountEmail:       "test@example.com",
		AccountSigner:      key,
		Config:             config,
		Logger:             slog.Default(),
		Storage:            store,
		CertificateStorage: newMockCertStorage(),
		OrderStorage:       newMockOrderStorage(),
	}

	client, err := NewClient(params)
	require.NoError(t, err)

	client.httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   testutil.TLSConfigFromServer(server),
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second,
	}
	client.client.HTTPClient = client.httpClient

	return client
}

// TestDeactivateAccount_WithStorage_Success tests that a successful
// deactivation updates the account status in local storage.
func TestDeactivateAccount_WithStorage_Success(t *testing.T) {
	server := deactivateStorageMockServer(t)
	defer server.Close()

	mockStore := newMockStorage()
	client := createDeactivateTestClient(t, server, mockStore)
	defer func() { _ = client.Close() }()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	require.NotNil(t, client.storage)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = client.DeactivateAccount(ctx)
	require.NoError(t, err)

	// Verify the account was saved with deactivated status
	savedAccount, ok := mockStore.accounts[1]
	require.True(t, ok, "account must be saved to storage after deactivation")
	assert.Equal(t, acme.StatusDeactivated, savedAccount.Status)
	assert.Equal(t, server.URL+"/acme/account/42", savedAccount.URL)
}

// TestDeactivateAccount_WithStorage_SaveError tests that a storage save
// failure during deactivation does not cause the overall deactivation to fail.
func TestDeactivateAccount_WithStorage_SaveError(t *testing.T) {
	server := deactivateStorageMockServer(t)
	defer server.Close()

	mockStore := newMockStorage()
	client := createDeactivateTestClient(t, server, mockStore)
	defer func() { _ = client.Close() }()

	_, err := client.RegisterAccount()
	require.NoError(t, err)

	// Configure mock storage to fail on Save
	mockStore.saveError = fmt.Errorf("simulated storage failure")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = client.DeactivateAccount(ctx)

	// Deactivation should still succeed even if storage update fails
	assert.NoError(t, err)
}
