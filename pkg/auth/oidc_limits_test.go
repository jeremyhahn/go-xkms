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

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// oversizedBody writes one byte more than maxOIDCResponseBytes.
func oversizedBody(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(strings.Repeat(" ", maxOIDCResponseBytes+1)))
}

// limitsProvider serves a valid discovery document whose JWKS and userinfo
// endpoints return oversized bodies.
func limitsProvider(t *testing.T) *httptest.Server {
	t.Helper()
	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":            serverURL,
			"userinfo_endpoint": serverURL + "/userinfo",
			"jwks_uri":          serverURL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) { oversizedBody(w) })
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) { oversizedBody(w) })
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	serverURL = server.URL
	return server
}

func TestReadOIDCResponse_AtLimit(t *testing.T) {
	body := strings.Repeat("a", maxOIDCResponseBytes)
	resp := &http.Response{Body: io.NopCloser(strings.NewReader(body))}

	got, err := readOIDCResponse(resp)
	if err != nil {
		t.Fatalf("a body of exactly the limit must be accepted: %v", err)
	}
	if len(got) != maxOIDCResponseBytes {
		t.Errorf("read %d bytes, want %d", len(got), maxOIDCResponseBytes)
	}
}

func TestReadOIDCResponse_OverLimit(t *testing.T) {
	resp := &http.Response{Body: io.NopCloser(strings.NewReader(strings.Repeat("a", maxOIDCResponseBytes+1)))}

	if _, err := readOIDCResponse(resp); !errors.Is(err, ErrOIDCResponseTooLarge) {
		t.Fatalf("err = %v, want ErrOIDCResponseTooLarge", err)
	}
}

func TestOIDCAuthenticator_Discover_OversizedDocumentRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		oversizedBody(w)
	}))
	defer server.Close()

	_, err := NewOIDCAuthenticator(context.Background(), &OIDCConfig{Issuer: server.URL, ClientID: "test-client"})
	if !errors.Is(err, ErrOIDCResponseTooLarge) {
		t.Fatalf("err = %v, want ErrOIDCResponseTooLarge", err)
	}
}

func TestOIDCAuthenticator_GetJWKS_OversizedResponseRefused(t *testing.T) {
	server := limitsProvider(t)
	auth, err := NewOIDCAuthenticator(context.Background(), &OIDCConfig{Issuer: server.URL, ClientID: "test-client"})
	if err != nil {
		t.Fatalf("NewOIDCAuthenticator: %v", err)
	}

	if _, err := auth.getJWKS(context.Background()); !errors.Is(err, ErrOIDCResponseTooLarge) {
		t.Fatalf("err = %v, want ErrOIDCResponseTooLarge", err)
	}
}

func TestOIDCAuthenticator_UserInfo_OversizedResponseRefused(t *testing.T) {
	server := limitsProvider(t)
	auth, err := NewOIDCAuthenticator(context.Background(), &OIDCConfig{Issuer: server.URL, ClientID: "test-client"})
	if err != nil {
		t.Fatalf("NewOIDCAuthenticator: %v", err)
	}

	if _, err := auth.validateAccessToken(context.Background(), "opaque-token"); !errors.Is(err, ErrOIDCResponseTooLarge) {
		t.Fatalf("err = %v, want ErrOIDCResponseTooLarge", err)
	}
}
