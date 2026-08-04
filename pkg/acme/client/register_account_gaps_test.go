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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/internal/acmetestutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
)

// newAccountAlreadyExistsServer builds an httptest ACME server whose
// /new-account endpoint always responds with HTTP 200 (rather than 201),
// which per RFC 8555 §7.3 signals "account with this key already
// registered". golang.org/x/crypto/acme's Register() call turns that into
// acme.ErrAccountAlreadyExists, exercising the RegisterAccount "already
// exists" branch that no other test in this package reaches. The handler
// counts requests so callers can make the second call (GetReg, issued by
// RegisterAccount to refresh the cached account) behave differently.
func newAccountAlreadyExistsServer(t *testing.T, onSecondCall func(w http.ResponseWriter, r *http.Request) bool) *httptest.Server {
	t.Helper()

	var server *httptest.Server
	var newAccountCalls int64

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
			n := atomic.AddInt64(&newAccountCalls, 1)
			if n >= 2 && onSecondCall != nil {
				if handled := onSecondCall(w, r); handled {
					return
				}
			}
			w.Header().Set("Location", server.URL+"/acct/1")
			w.WriteHeader(http.StatusOK) // 200, not 201: account already exists
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "valid",
				"contact": []string{"mailto:test@example.com"},
				"orders":  server.URL + "/acct/1/orders",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return server
}

// TestClient_RegisterAccount_AlreadyExists_RefetchSucceeds exercises the
// path where the ACME server reports the account already exists and the
// subsequent GetReg (POST-as-GET refresh) succeeds.
func TestClient_RegisterAccount_AlreadyExists_RefetchSucceeds(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	server := newAccountAlreadyExistsServer(t, nil)
	defer server.Close()

	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: testutil.TLSConfigFromServer(server)},
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "existing@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	account, err := client.RegisterAccount()
	require.NoError(t, err)
	require.NotNil(t, account)
	assert.Equal(t, "valid", account.Status)
	assert.Contains(t, account.Contact, "mailto:test@example.com")
}

// TestClient_RegisterAccount_AlreadyExists_RefetchFails exercises the path
// where the account-already-exists refetch (GetReg) itself fails; the
// original cached account stub must still be returned rather than an error.
func TestClient_RegisterAccount_AlreadyExists_RefetchFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// 400 Bad Request is a non-retriable status per x/crypto/acme's
	// isRetriable(), so GetReg fails immediately instead of retrying with
	// backoff against a context with no deadline (which would hang).
	server := newAccountAlreadyExistsServer(t, func(w http.ResponseWriter, r *http.Request) bool {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:malformed","detail":"boom"}`))
		return true
	})
	defer server.Close()

	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: testutil.TLSConfigFromServer(server)},
		Timeout:   30 * time.Second,
	}

	acmeClient := &acme.Client{
		DirectoryURL: server.URL + "/directory",
		Key:          privateKey,
		HTTPClient:   httpClient,
	}

	client := &Client{
		accountEmail:  "existing@example.com",
		accountSigner: privateKey,
		client:        acmeClient,
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        logger,
	}

	account, err := client.RegisterAccount()
	require.NoError(t, err)
	require.NotNil(t, account)
	// The GetReg refetch failed, so RegisterAccount falls back to the
	// minimal stub account built before the register call (contact only,
	// no server-populated fields).
	assert.Contains(t, account.Contact, "mailto:existing@example.com")
}
