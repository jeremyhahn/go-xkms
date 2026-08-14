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

// auth_factor_rest_client_test.go pins the method/path contract the CLI's
// auth-factor client speaks to xkmsd.
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"errors"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// recordingFactorServer captures the method and path of the last request.
type recordingFactorServer struct {
	method string
	path   string
	query  string
}

func newFactorTestClient(t *testing.T, rec *recordingFactorServer) (*authFactorRESTClient, func()) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.method = r.Method
		rec.path = r.URL.Path
		rec.query = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))

	oldFactory := initHTTPClientFactory
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	client, err := newAuthFactorRESTClient(&Config{Server: server.URL, OutputFormat: "text"})
	if err != nil {
		t.Fatalf("newAuthFactorRESTClient: %v", err)
	}

	return client, func() {
		initHTTPClientFactory = oldFactory
		server.Close()
	}
}

// TestAuthFactorRESTClient_Routes pins each operation to the method and path
// the server registers. A mismatch here is a 404 at runtime, which is exactly
// the failure mode this surface had before it was wired.
func TestAuthFactorRESTClient_Routes(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		call       func(c *authFactorRESTClient) error
		wantMethod string
		wantPath   string
		wantQuery  string
	}{
		{
			name: "list",
			call: func(c *authFactorRESTClient) error {
				_, err := c.ListAuthFactors(ctx, &qrdbtransport.AuthFactorListRequest{UserID: 42})
				return err
			},
			wantMethod: http.MethodGet,
			wantPath:   "/api/v1/factors",
			wantQuery:  "user_id=42",
		},
		{
			name: "add",
			call: func(c *authFactorRESTClient) error {
				_, err := c.AddAuthFactor(ctx, &qrdbtransport.AuthFactorAddRequest{UserID: 42, Type: "fido2"})
				return err
			},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/factors",
		},
		{
			name: "get",
			call: func(c *authFactorRESTClient) error {
				_, err := c.GetAuthFactor(ctx, &qrdbtransport.AuthFactorGetRequest{FactorID: "f-1"})
				return err
			},
			wantMethod: http.MethodGet,
			wantPath:   "/api/v1/factors/f-1",
		},
		{
			name: "remove",
			call: func(c *authFactorRESTClient) error {
				_, err := c.RemoveAuthFactor(ctx, &qrdbtransport.AuthFactorRemoveRequest{FactorID: "f-1"})
				return err
			},
			wantMethod: http.MethodDelete,
			wantPath:   "/api/v1/factors/f-1",
		},
		{
			name: "remove force",
			call: func(c *authFactorRESTClient) error {
				_, err := c.RemoveAuthFactor(ctx, &qrdbtransport.AuthFactorRemoveRequest{FactorID: "f-1", Force: true})
				return err
			},
			wantMethod: http.MethodDelete,
			wantPath:   "/api/v1/factors/f-1",
			wantQuery:  "force=true",
		},
		{
			name: "relabel",
			call: func(c *authFactorRESTClient) error {
				_, err := c.RelabelAuthFactor(ctx, &qrdbtransport.AuthFactorRelabelRequest{FactorID: "f-1", Label: "x"})
				return err
			},
			wantMethod: http.MethodPatch,
			wantPath:   "/api/v1/factors/f-1",
		},
		{
			name: "rotate",
			call: func(c *authFactorRESTClient) error {
				_, err := c.RotateAuthFactor(ctx, &qrdbtransport.AuthFactorRotateRequest{OldFactorID: "f-1"})
				return err
			},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/factors/f-1/rotate",
		},
		{
			name: "login",
			call: func(c *authFactorRESTClient) error {
				_, err := c.LoginAuthFactor(ctx, &qrdbtransport.AuthFactorLoginRequest{Type: "fido2", LookupKey: []byte("k")})
				return err
			},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/factors/login",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recordingFactorServer{}
			client, cleanup := newFactorTestClient(t, rec)
			defer cleanup()

			if err := tc.call(client); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rec.method != tc.wantMethod {
				t.Errorf("method = %q, want %q", rec.method, tc.wantMethod)
			}
			if rec.path != tc.wantPath {
				t.Errorf("path = %q, want %q", rec.path, tc.wantPath)
			}
			if tc.wantQuery != "" && rec.query != tc.wantQuery {
				t.Errorf("query = %q, want %q", rec.query, tc.wantQuery)
			}
		})
	}
}

// TestAuthFactorRESTClient_RequiresServer proves the factory refuses to build
// a client with no server configured, which is what produces the operator
// message rather than a nil dereference later.
func TestAuthFactorRESTClient_RequiresServer(t *testing.T) {
	if _, err := newAuthFactorRESTClient(&Config{}); err == nil {
		t.Fatal("expected an error when no server is configured")
	}
}

// TestDefaultUserAuthFactorClientFactory_NoServer proves the wired factory
// still reports the missing-client error when nothing is configured.
func TestDefaultUserAuthFactorClientFactory_NoServer(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "text"})

	_, _, err := defaultUserAuthFactorClientFactory(context.Background())
	if err == nil {
		t.Fatal("expected an error when no server is configured")
	}
	var missing *AuthFactorMissingClientError
	if !errors.As(err, &missing) {
		t.Fatalf("want AuthFactorMissingClientError, got %T: %v", err, err)
	}
}

// TestDefaultUserAuthFactorClientFactory_BuildsClient proves the factory now
// returns a working client instead of always erroring.
func TestDefaultUserAuthFactorClientFactory_BuildsClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	oldFactory := initHTTPClientFactory
	defer func() { initHTTPClientFactory = oldFactory }()
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) { return server.Client(), nil }

	withGlobalConfig(t, &Config{Server: server.URL, OutputFormat: "text"})

	client, closer, err := defaultUserAuthFactorClientFactory(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected a non-nil client")
	}
	if closer != nil {
		if err := closer(); err != nil {
			t.Errorf("closer returned an error: %v", err)
		}
	}
}
