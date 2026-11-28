// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// TestClient_AuthorizeOrder_StalledNewAccountEndsAtContext proves the first
// order's implicit account registration runs under the order's context: a
// server that never answers newAccount must not hold the caller past its
// deadline (the HTTP client's own timeout is far longer).
func TestClient_AuthorizeOrder_StalledNewAccountEndsAtContext(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	var newOrders int64
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "nonce-"+time.Now().String())
		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
		case "/new-account":
			_, _ = io.Copy(io.Discard, r.Body)
			select {
			case <-r.Context().Done():
			case <-release:
			}
		case "/new-order":
			atomic.AddInt64(&newOrders, 1)
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	defer close(release)

	httpClient := server.Client()
	httpClient.Timeout = 60 * time.Second
	client := &Client{
		accountSigner: key,
		client:        &acme.Client{DirectoryURL: server.URL + "/directory", Key: key, HTTPClient: httpClient},
		httpClient:    httpClient,
		config:        DefaultConfig(),
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := client.authorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: "device.example"}})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("authorizeOrder succeeded against a stalled newAccount")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("authorizeOrder took %s with a 1 s context", elapsed)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("account registration ignored the order's context")
	}
	if n := atomic.LoadInt64(&newOrders); n != 0 {
		t.Fatalf("newOrder reached %d times without a registered account", n)
	}
}
