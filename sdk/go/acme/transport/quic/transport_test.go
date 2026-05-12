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

package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/account"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/authorization"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/certificate"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/challenge"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/directory"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/nonce"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/order"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// mockRoundTripper implements http.RoundTripper for testing.
type mockRoundTripper struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

// testTLSConfig returns a minimal TLS configuration for testing.
func testTLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13}
}

// newTestTransportWithMock creates a transport with a mocked HTTP client.
func newTestTransportWithMock(roundTripper http.RoundTripper) *Transport {
	cfg := &transport.Config{
		Address:   "https://localhost:9444",
		TLSConfig: testTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		panic(fmt.Sprintf("failed to create test transport: %v", err))
	}
	qt := tr.(*Transport)

	qt.client = &http.Client{
		Transport: roundTripper,
		Timeout:   30 * time.Second,
	}

	return qt
}

func TestNewTransport(t *testing.T) {
	t.Run("NilConfig", func(t *testing.T) {
		_, err := NewTransport(nil)
		if err == nil {
			t.Fatal("expected error for nil config")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got: %v", err)
		}
	})

	t.Run("EmptyAddress", func(t *testing.T) {
		cfg := &transport.Config{
			Address:   "",
			TLSConfig: &tls.Config{},
		}
		_, err := NewTransport(cfg)
		if err == nil {
			t.Fatal("expected error for empty address")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got: %v", err)
		}
	})

	t.Run("NoTLSNotInsecure", func(t *testing.T) {
		cfg := &transport.Config{
			Address:  "localhost:9444",
			Insecure: false,
		}
		_, err := NewTransport(cfg)
		if err == nil {
			t.Fatal("expected error for missing TLS config")
		}
		if errors.Code(err) != errors.CodeConfiguration {
			t.Errorf("expected configuration error, got: %v", err)
		}
	})

	t.Run("InsecureMode", func(t *testing.T) {
		cfg := &transport.Config{
			Address:  "localhost:9444",
			Insecure: true,
		}
		_, err := NewTransport(cfg)
		if err == nil {
			t.Fatal("expected error for missing TLS config even with Insecure flag")
		}
		if errors.Code(err) != errors.CodeConfiguration {
			t.Errorf("expected configuration error, got: %v", err)
		}
	})

	t.Run("WithTLSConfig", func(t *testing.T) {
		cfg := &transport.Config{
			Address: "localhost:9444",
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
			},
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer tr.Close()

		if !tr.Healthy() {
			t.Error("expected transport to be healthy")
		}
	})

	t.Run("WithCustomTimeout", func(t *testing.T) {
		cfg := &transport.Config{
			Address:   "localhost:9444",
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
			Timeout:   5 * time.Second,
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer tr.Close()

		qt := tr.(*Transport)
		if qt.client.Timeout != 5*time.Second {
			t.Errorf("expected timeout 5s, got: %v", qt.client.Timeout)
		}
	})

	t.Run("AddressNormalization", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"localhost:9444", "https://localhost:9444"},
			{"https://localhost:9444", "https://localhost:9444"},
			{"https://localhost:9444/", "https://localhost:9444"},
			{"http://localhost:9444", "http://localhost:9444"},
		}

		for _, tt := range tests {
			t.Run(tt.input, func(t *testing.T) {
				cfg := &transport.Config{
					Address:   tt.input,
					TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
				}
				tr, err := NewTransport(cfg)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				defer tr.Close()

				qt := tr.(*Transport)
				if qt.baseURL != tt.expected {
					t.Errorf("expected baseURL %q, got %q", tt.expected, qt.baseURL)
				}
			})
		}
	})
}

func TestTransportClose(t *testing.T) {
	t.Run("CloseOnce", func(t *testing.T) {
		cfg := &transport.Config{
			Address:   "localhost:9444",
			TLSConfig: testTLSConfig(),
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := tr.Close(); err != nil {
			t.Errorf("unexpected error on first close: %v", err)
		}

		if err := tr.Close(); err != nil {
			t.Errorf("unexpected error on second close: %v", err)
		}

		if tr.Healthy() {
			t.Error("expected transport to not be healthy after close")
		}
	})

	t.Run("RequestAfterClose", func(t *testing.T) {
		cfg := &transport.Config{
			Address:   "localhost:9444",
			TLSConfig: testTLSConfig(),
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := tr.Close(); err != nil {
			t.Errorf("unexpected error on close: %v", err)
		}

		ctx := context.Background()
		_, err = tr.Request(ctx, "directory", "get", nil)
		if err == nil {
			t.Fatal("expected error for request after close")
		}
		if errors.Code(err) != errors.CodeConnection {
			t.Errorf("expected connection error, got: %v", err)
		}
	})
}

func TestTransportConn(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9444",
		TLSConfig: testTLSConfig(),
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer tr.Close()

	conn := tr.Conn()
	if conn == nil {
		t.Error("expected non-nil connection")
	}

	client, ok := conn.(*http.Client)
	if !ok {
		t.Error("expected *http.Client")
	}
	if client == nil {
		t.Error("expected non-nil http client")
	}
}

func TestTransportRequestStream(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9444",
		TLSConfig: testTLSConfig(),
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer tr.Close()

	ctx := context.Background()
	_, err = tr.RequestStream(ctx, "test", "method", nil)
	if err == nil {
		t.Fatal("expected error for streaming request")
	}
	if !errors.IsUnimplemented(err) {
		t.Errorf("expected unimplemented error, got: %v", err)
	}
}

func TestTransportRequestUnknownRoute(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9444",
		TLSConfig: testTLSConfig(),
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer tr.Close()

	ctx := context.Background()
	_, err = tr.Request(ctx, "unknown", "method", nil)
	if err == nil {
		t.Fatal("expected error for unknown route")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("expected invalid input error, got: %v", err)
	}
}

func TestRouteMapCompleteness(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9444",
		TLSConfig: testTLSConfig(),
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer tr.Close()

	qt := tr.(*Transport)

	expectedRoutes := []struct {
		service string
		method  string
	}{
		// ACME routes
		{"directory", "get"},
		{"nonce", "new"},
		{"account", "create"},
		{"account", "get"},
		{"account", "update"},
		{"account", "deactivate"},
		{"account", "key-change"},
		{"order", "create"},
		{"order", "get"},
		{"order", "list"},
		{"order", "finalize"},
		{"authorization", "get"},
		{"authorization", "deactivate"},
		{"challenge", "get"},
		{"challenge", "respond"},
		{"certificate", "get"},
		{"certificate", "revoke"},

		// Admin routes
		{"admin.status", "status"},
		{"admin.status", "stats"},
		{"admin.certificate", "list"},
		{"admin.certificate", "get"},
		{"admin.certificate", "revoke"},
		{"admin.account", "list"},
		{"admin.account", "get"},
		{"admin.account", "disable"},
		{"admin.tenant", "create"},
		{"admin.tenant", "list"},
		{"admin.tenant", "get"},
		{"admin.tenant", "update"},
		{"admin.tenant", "delete"},
		{"admin.tenant", "updateStatus"},
		{"admin.eab", "create"},
		{"admin.eab", "list"},
		{"admin.eab", "get"},
		{"admin.eab", "delete"},
		{"admin.role", "create"},
		{"admin.role", "list"},
		{"admin.role", "get"},
		{"admin.role", "update"},
		{"admin.role", "delete"},
		{"admin.user", "create"},
		{"admin.user", "list"},
		{"admin.user", "get"},
		{"admin.user", "update"},
		{"admin.user", "delete"},
		{"admin.order", "list"},
		{"admin.order", "get"},
		{"admin.tenant.ca", "createRootCA"},
		{"admin.tenant.ca", "status"},
		{"admin.tenant.ca", "createIntermediateCA"},
		{"admin.tenant.ca", "listIntermediateCAs"},
		{"admin.tenant.ca", "getIntermediateCA"},
		{"admin.tenant.ca", "updateIntermediateCAStatus"},
	}

	for _, rt := range expectedRoutes {
		key := routeKey{service: rt.service, method: rt.method}
		if _, ok := qt.routes[key]; !ok {
			t.Errorf("missing route: %s/%s", rt.service, rt.method)
		}
	}

	if len(qt.routes) != len(expectedRoutes) {
		t.Errorf("route count mismatch: expected %d, got %d", len(expectedRoutes), len(qt.routes))
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"localhost:9444", "https://localhost:9444"},
		{"localhost:9444/", "https://localhost:9444"},
		{"https://localhost:9444", "https://localhost:9444"},
		{"https://localhost:9444/", "https://localhost:9444"},
		{"http://localhost:9444", "http://localhost:9444"},
		{"http://localhost:9444/", "http://localhost:9444"},
		{"example.com", "https://example.com"},
		{"192.168.1.1:443", "https://192.168.1.1:443"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeBaseURL(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestResolveURL(t *testing.T) {
	cfg := &transport.Config{
		Address:   "https://localhost:9444",
		TLSConfig: testTLSConfig(),
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer tr.Close()

	qt := tr.(*Transport)

	t.Run("DirectoryGet", func(t *testing.T) {
		url := qt.resolveURL("/directory", "directory", "get", nil)
		if url != "https://localhost:9444/directory" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("AccountGet", func(t *testing.T) {
		req := &account.GetRequest{AccountURL: "https://example.com/acme/acct/123"}
		url := qt.resolveURL("", "account", "get", req)
		if url != "https://example.com/acme/acct/123" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("AccountGetEmptyURL", func(t *testing.T) {
		req := &account.GetRequest{AccountURL: ""}
		url := qt.resolveURL("", "account", "get", req)
		if url != "https://localhost:9444" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("AccountUpdate", func(t *testing.T) {
		req := &account.UpdateRequest{AccountURL: "https://example.com/acme/acct/123"}
		url := qt.resolveURL("", "account", "update", req)
		if url != "https://example.com/acme/acct/123" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("AccountUpdateEmptyURL", func(t *testing.T) {
		req := &account.UpdateRequest{AccountURL: ""}
		url := qt.resolveURL("", "account", "update", req)
		if url != "https://localhost:9444" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("AccountDeactivate", func(t *testing.T) {
		req := &account.DeactivateRequest{AccountURL: "https://example.com/acme/acct/123"}
		url := qt.resolveURL("", "account", "deactivate", req)
		if url != "https://example.com/acme/acct/123" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("AccountDeactivateEmptyURL", func(t *testing.T) {
		req := &account.DeactivateRequest{AccountURL: ""}
		url := qt.resolveURL("", "account", "deactivate", req)
		if url != "https://localhost:9444" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("AccountUnknownMethod", func(t *testing.T) {
		url := qt.resolveURL("", "account", "unknown", nil)
		if url != "https://localhost:9444" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("OrderGet", func(t *testing.T) {
		req := &order.GetRequest{OrderURL: "https://example.com/acme/order/123"}
		url := qt.resolveURL("", "order", "get", req)
		if url != "https://example.com/acme/order/123" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("OrderGetEmptyURL", func(t *testing.T) {
		req := &order.GetRequest{OrderURL: ""}
		url := qt.resolveURL("", "order", "get", req)
		if url != "https://localhost:9444" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("OrderList", func(t *testing.T) {
		req := &order.ListRequest{AccountURL: "https://example.com/acme/acct/123"}
		url := qt.resolveURL("", "order", "list", req)
		if url != "https://example.com/acme/acct/123/orders" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("OrderListEmptyURL", func(t *testing.T) {
		req := &order.ListRequest{AccountURL: ""}
		url := qt.resolveURL("", "order", "list", req)
		if url != "https://localhost:9444" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("OrderFinalize", func(t *testing.T) {
		req := &order.FinalizeRequest{FinalizeURL: "https://example.com/acme/order/123/finalize"}
		url := qt.resolveURL("", "order", "finalize", req)
		if url != "https://example.com/acme/order/123/finalize" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("OrderFinalizeEmptyURL", func(t *testing.T) {
		req := &order.FinalizeRequest{FinalizeURL: ""}
		url := qt.resolveURL("", "order", "finalize", req)
		if url != "https://localhost:9444" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("OrderUnknownMethod", func(t *testing.T) {
		url := qt.resolveURL("", "order", "unknown", nil)
		if url != "https://localhost:9444" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("AuthorizationGet", func(t *testing.T) {
		req := &authorization.GetRequest{AuthorizationURL: "https://example.com/acme/authz/123"}
		url := qt.resolveURL("", "authorization", "get", req)
		if url != "https://example.com/acme/authz/123" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("AuthorizationGetEmptyURL", func(t *testing.T) {
		req := &authorization.GetRequest{AuthorizationURL: ""}
		url := qt.resolveURL("", "authorization", "get", req)
		if url != "https://localhost:9444" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("AuthorizationDeactivate", func(t *testing.T) {
		req := &authorization.DeactivateRequest{AuthorizationURL: "https://example.com/acme/authz/123"}
		url := qt.resolveURL("", "authorization", "deactivate", req)
		if url != "https://example.com/acme/authz/123" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("AuthorizationDeactivateEmptyURL", func(t *testing.T) {
		req := &authorization.DeactivateRequest{AuthorizationURL: ""}
		url := qt.resolveURL("", "authorization", "deactivate", req)
		if url != "https://localhost:9444" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("AuthorizationUnknownMethod", func(t *testing.T) {
		url := qt.resolveURL("", "authorization", "unknown", nil)
		if url != "https://localhost:9444" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("ChallengeGet", func(t *testing.T) {
		req := &challenge.GetRequest{ChallengeURL: "https://example.com/acme/chall/123"}
		url := qt.resolveURL("", "challenge", "get", req)
		if url != "https://example.com/acme/chall/123" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("ChallengeGetEmptyURL", func(t *testing.T) {
		req := &challenge.GetRequest{ChallengeURL: ""}
		url := qt.resolveURL("", "challenge", "get", req)
		if url != "https://localhost:9444" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("ChallengeRespond", func(t *testing.T) {
		req := &challenge.RespondRequest{ChallengeURL: "https://example.com/acme/chall/123"}
		url := qt.resolveURL("", "challenge", "respond", req)
		if url != "https://example.com/acme/chall/123" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("ChallengeRespondEmptyURL", func(t *testing.T) {
		req := &challenge.RespondRequest{ChallengeURL: ""}
		url := qt.resolveURL("", "challenge", "respond", req)
		if url != "https://localhost:9444" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("ChallengeUnknownMethod", func(t *testing.T) {
		url := qt.resolveURL("", "challenge", "unknown", nil)
		if url != "https://localhost:9444" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("CertificateGet", func(t *testing.T) {
		req := &certificate.GetRequest{CertificateURL: "https://example.com/acme/cert/123"}
		url := qt.resolveURL("", "certificate", "get", req)
		if url != "https://example.com/acme/cert/123" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("CertificateGetEmptyURL", func(t *testing.T) {
		req := &certificate.GetRequest{CertificateURL: ""}
		url := qt.resolveURL("", "certificate", "get", req)
		if url != "https://localhost:9444" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("CertificateNonGetMethod", func(t *testing.T) {
		url := qt.resolveURL("", "certificate", "revoke", nil)
		if url != "https://localhost:9444" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("FallbackToBaseURL", func(t *testing.T) {
		url := qt.resolveURL("", "unknown", "method", nil)
		if url != "https://localhost:9444" {
			t.Errorf("unexpected URL: %s", url)
		}
	})

	t.Run("WrongRequestType", func(t *testing.T) {
		url := qt.resolveURL("", "account", "get", "not-a-request")
		if url != "https://localhost:9444" {
			t.Errorf("unexpected URL: %s", url)
		}
	})
}

func TestEncodeJSONBody(t *testing.T) {
	t.Run("NilRequest", func(t *testing.T) {
		body, err := encodeJSONBody(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(body) != "{}" {
			t.Errorf("expected {}, got: %s", body)
		}
	})

	t.Run("ValidRequest", func(t *testing.T) {
		req := &account.CreateRequest{
			Contact:              []string{"mailto:test@example.com"},
			TermsOfServiceAgreed: true,
		}
		body, err := encodeJSONBody(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var decoded account.CreateRequest
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatalf("failed to decode: %v", err)
		}
		if len(decoded.Contact) != 1 || decoded.Contact[0] != "mailto:test@example.com" {
			t.Error("contact mismatch")
		}
		if !decoded.TermsOfServiceAgreed {
			t.Error("termsOfServiceAgreed mismatch")
		}
	})

	t.Run("SimpleStruct", func(t *testing.T) {
		type simpleReq struct {
			Name string `json:"name"`
		}
		req := &simpleReq{Name: "test"}
		body, err := encodeJSONBody(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(body) != `{"name":"test"}` {
			t.Errorf("unexpected body: %s", body)
		}
	})
}

func TestDecodeDirectoryResponse(t *testing.T) {
	t.Run("ValidDirectory", func(t *testing.T) {
		body := []byte(`{
			"newNonce": "https://example.com/acme/new-nonce",
			"newAccount": "https://example.com/acme/new-acct",
			"newOrder": "https://example.com/acme/new-order",
			"revokeCert": "https://example.com/acme/revoke-cert",
			"keyChange": "https://example.com/acme/key-change",
			"meta": {
				"termsOfService": "https://example.com/tos",
				"website": "https://example.com"
			}
		}`)
		headers := make(http.Header)
		headers.Set(HeaderReplayNonce, "test-nonce")

		resp, err := decodeDirectoryResponse(body, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		dirResp, ok := resp.(*directory.GetResponse)
		if !ok {
			t.Fatal("expected *directory.GetResponse")
		}

		if dirResp.Directory.NewNonce != "https://example.com/acme/new-nonce" {
			t.Error("newNonce mismatch")
		}
		if dirResp.Directory.NewAccount != "https://example.com/acme/new-acct" {
			t.Error("newAccount mismatch")
		}
		if dirResp.Nonce != "test-nonce" {
			t.Error("nonce mismatch")
		}
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		body := []byte(`invalid json`)
		headers := make(http.Header)

		_, err := decodeDirectoryResponse(body, headers)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})
}

func TestDecodeNonceResponse(t *testing.T) {
	t.Run("WithNonce", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set(HeaderReplayNonce, "test-nonce-12345")

		resp, err := decodeNonceResponse(nil, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		nonceResp, ok := resp.(*nonce.NewResponse)
		if !ok {
			t.Fatal("expected *nonce.NewResponse")
		}

		if nonceResp.Nonce != "test-nonce-12345" {
			t.Errorf("expected test-nonce-12345, got: %s", nonceResp.Nonce)
		}
	})

	t.Run("EmptyNonce", func(t *testing.T) {
		headers := make(http.Header)

		resp, err := decodeNonceResponse(nil, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		nonceResp, ok := resp.(*nonce.NewResponse)
		if !ok {
			t.Fatal("expected *nonce.NewResponse")
		}

		if nonceResp.Nonce != "" {
			t.Errorf("expected empty nonce, got: %s", nonceResp.Nonce)
		}
	})
}

func TestDecodeAccountResponse(t *testing.T) {
	t.Run("ValidAccount", func(t *testing.T) {
		body := []byte(`{
			"status": "valid",
			"contact": ["mailto:test@example.com"],
			"termsOfServiceAgreed": true,
			"orders": "https://example.com/acme/acct/123/orders"
		}`)
		headers := make(http.Header)
		headers.Set(HeaderLocation, "https://example.com/acme/acct/123")
		headers.Set(HeaderReplayNonce, "test-nonce")

		resp, err := decodeAccountResponse(body, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		acctResp, ok := resp.(*account.CreateResponse)
		if !ok {
			t.Fatal("expected *account.CreateResponse")
		}

		if acctResp.Account.Status != "valid" {
			t.Error("status mismatch")
		}
		if acctResp.Location != "https://example.com/acme/acct/123" {
			t.Error("location mismatch")
		}
		if acctResp.Account.URL != "https://example.com/acme/acct/123" {
			t.Error("account URL mismatch")
		}
		if acctResp.Nonce != "test-nonce" {
			t.Error("nonce mismatch")
		}
	})

	t.Run("EmptyBody", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set(HeaderLocation, "https://example.com/acme/acct/123")

		resp, err := decodeAccountResponse(nil, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		acctResp, ok := resp.(*account.CreateResponse)
		if !ok {
			t.Fatal("expected *account.CreateResponse")
		}

		if acctResp.Account.URL != "https://example.com/acme/acct/123" {
			t.Error("account URL mismatch")
		}
	})

	t.Run("LinkHeader", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("Link", "https://example.com/acme/acct/456")

		resp, err := decodeAccountResponse(nil, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		acctResp, ok := resp.(*account.CreateResponse)
		if !ok {
			t.Fatal("expected *account.CreateResponse")
		}

		if acctResp.Account.URL != "https://example.com/acme/acct/456" {
			t.Error("account URL from Link header mismatch")
		}
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		body := []byte(`invalid json`)
		headers := make(http.Header)

		_, err := decodeAccountResponse(body, headers)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})
}

func TestDecodeOrderResponse(t *testing.T) {
	t.Run("ValidOrder", func(t *testing.T) {
		body := []byte(`{
			"status": "pending",
			"expires": "2025-12-31T23:59:59Z",
			"identifiers": [{"type": "dns", "value": "example.com"}],
			"authorizations": ["https://example.com/acme/authz/123"],
			"finalize": "https://example.com/acme/order/123/finalize"
		}`)
		headers := make(http.Header)
		headers.Set(HeaderLocation, "https://example.com/acme/order/123")
		headers.Set(HeaderReplayNonce, "test-nonce")

		resp, err := decodeOrderResponse(body, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		orderResp, ok := resp.(*order.CreateResponse)
		if !ok {
			t.Fatal("expected *order.CreateResponse")
		}

		if orderResp.Order.Status != "pending" {
			t.Error("status mismatch")
		}
		if len(orderResp.Order.Identifiers) != 1 {
			t.Error("identifiers mismatch")
		}
		if orderResp.Order.URL != "https://example.com/acme/order/123" {
			t.Error("order URL mismatch")
		}
	})

	t.Run("EmptyBody", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set(HeaderLocation, "https://example.com/acme/order/123")

		resp, err := decodeOrderResponse(nil, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		orderResp, ok := resp.(*order.CreateResponse)
		if !ok {
			t.Fatal("expected *order.CreateResponse")
		}

		if orderResp.Order.URL != "https://example.com/acme/order/123" {
			t.Error("order URL mismatch")
		}
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		body := []byte(`invalid json`)
		headers := make(http.Header)

		_, err := decodeOrderResponse(body, headers)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})
}

func TestDecodeOrderListResponse(t *testing.T) {
	t.Run("ValidOrderList", func(t *testing.T) {
		body := []byte(`{
			"orders": [
				"https://example.com/acme/order/1",
				"https://example.com/acme/order/2",
				"https://example.com/acme/order/3"
			]
		}`)
		headers := make(http.Header)
		headers.Set(HeaderReplayNonce, "test-nonce")

		resp, err := decodeOrderListResponse(body, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		listResp, ok := resp.(*order.ListResponse)
		if !ok {
			t.Fatal("expected *order.ListResponse")
		}

		if len(listResp.Orders) != 3 {
			t.Errorf("expected 3 orders, got: %d", len(listResp.Orders))
		}
		if listResp.Nonce != "test-nonce" {
			t.Error("nonce mismatch")
		}
	})

	t.Run("EmptyBody", func(t *testing.T) {
		headers := make(http.Header)

		resp, err := decodeOrderListResponse(nil, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		listResp, ok := resp.(*order.ListResponse)
		if !ok {
			t.Fatal("expected *order.ListResponse")
		}

		if len(listResp.Orders) != 0 {
			t.Errorf("expected 0 orders, got: %d", len(listResp.Orders))
		}
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		body := []byte(`invalid json`)
		headers := make(http.Header)

		_, err := decodeOrderListResponse(body, headers)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})
}

func TestDecodeAuthorizationResponse(t *testing.T) {
	t.Run("ValidAuthorization", func(t *testing.T) {
		body := []byte(`{
			"identifier": {"type": "dns", "value": "example.com"},
			"status": "pending",
			"expires": "2025-12-31T23:59:59Z",
			"challenges": [
				{
					"type": "http-01",
					"url": "https://example.com/acme/chall/123",
					"status": "pending",
					"token": "test-token"
				}
			]
		}`)
		headers := make(http.Header)
		headers.Set(HeaderLocation, "https://example.com/acme/authz/123")
		headers.Set(HeaderReplayNonce, "test-nonce")

		resp, err := decodeAuthorizationResponse(body, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		authzResp, ok := resp.(*authorization.GetResponse)
		if !ok {
			t.Fatal("expected *authorization.GetResponse")
		}

		if authzResp.Authorization.Status != "pending" {
			t.Error("status mismatch")
		}
		if authzResp.Authorization.Identifier.Value != "example.com" {
			t.Error("identifier value mismatch")
		}
		if len(authzResp.Authorization.Challenges) != 1 {
			t.Error("challenges mismatch")
		}
		if authzResp.Authorization.URL != "https://example.com/acme/authz/123" {
			t.Error("authorization URL mismatch")
		}
	})

	t.Run("EmptyBody", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set(HeaderLocation, "https://example.com/acme/authz/123")

		resp, err := decodeAuthorizationResponse(nil, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		authzResp, ok := resp.(*authorization.GetResponse)
		if !ok {
			t.Fatal("expected *authorization.GetResponse")
		}

		if authzResp.Authorization.URL != "https://example.com/acme/authz/123" {
			t.Error("authorization URL mismatch")
		}
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		body := []byte(`invalid json`)
		headers := make(http.Header)

		_, err := decodeAuthorizationResponse(body, headers)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})
}

func TestDecodeChallengeResponse(t *testing.T) {
	t.Run("ValidChallenge", func(t *testing.T) {
		body := []byte(`{
			"type": "http-01",
			"url": "https://example.com/acme/chall/123",
			"status": "pending",
			"token": "test-token-abc123"
		}`)
		headers := make(http.Header)
		headers.Set(HeaderReplayNonce, "test-nonce")

		resp, err := decodeChallengeResponse(body, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		challResp, ok := resp.(*challenge.GetResponse)
		if !ok {
			t.Fatal("expected *challenge.GetResponse")
		}

		if challResp.Challenge.Type != "http-01" {
			t.Error("type mismatch")
		}
		if challResp.Challenge.Token != "test-token-abc123" {
			t.Error("token mismatch")
		}
		if challResp.Nonce != "test-nonce" {
			t.Error("nonce mismatch")
		}
	})

	t.Run("EmptyBody", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set(HeaderReplayNonce, "test-nonce")

		resp, err := decodeChallengeResponse(nil, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		challResp, ok := resp.(*challenge.GetResponse)
		if !ok {
			t.Fatal("expected *challenge.GetResponse")
		}

		if challResp.Nonce != "test-nonce" {
			t.Error("nonce mismatch")
		}
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		body := []byte(`invalid json`)
		headers := make(http.Header)

		_, err := decodeChallengeResponse(body, headers)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})
}

func TestDecodeCertificateResponse(t *testing.T) {
	t.Run("ValidCertificate", func(t *testing.T) {
		pemData := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfLf...
-----END CERTIFICATE-----`
		body := []byte(pemData)
		headers := make(http.Header)
		headers.Set(HeaderLocation, "https://example.com/acme/cert/123")
		headers.Set(HeaderReplayNonce, "test-nonce")
		headers.Add("Link", `<https://example.com/acme/cert/123-alt>; rel="alternate"`)

		resp, err := decodeCertificateResponse(body, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		certResp, ok := resp.(*certificate.GetResponse)
		if !ok {
			t.Fatal("expected *certificate.GetResponse")
		}

		if certResp.Certificate.URL != "https://example.com/acme/cert/123" {
			t.Error("URL mismatch")
		}
		if certResp.Certificate.PEM != pemData {
			t.Error("PEM mismatch")
		}
		if certResp.Chain != pemData {
			t.Error("chain mismatch")
		}
		if len(certResp.AlternateLinks) != 1 {
			t.Error("alternate links mismatch")
		}
		if certResp.AlternateLinks[0] != "https://example.com/acme/cert/123-alt" {
			t.Errorf("unexpected alternate link: %s", certResp.AlternateLinks[0])
		}
	})

	t.Run("MultipleAlternateLinks", func(t *testing.T) {
		body := []byte("certificate data")
		headers := make(http.Header)
		headers.Add("Link", `<https://example.com/acme/cert/123-alt1>; rel="alternate"`)
		headers.Add("Link", `<https://example.com/acme/cert/123-alt2>; rel="alternate"`)
		headers.Add("Link", `<https://example.com/issuer>; rel="up"`)

		resp, err := decodeCertificateResponse(body, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		certResp, ok := resp.(*certificate.GetResponse)
		if !ok {
			t.Fatal("expected *certificate.GetResponse")
		}

		if len(certResp.AlternateLinks) != 2 {
			t.Errorf("expected 2 alternate links, got: %d", len(certResp.AlternateLinks))
		}
	})

	t.Run("NoAlternateLinks", func(t *testing.T) {
		body := []byte("certificate data")
		headers := make(http.Header)
		headers.Add("Link", `<https://example.com/issuer>; rel="up"`)

		resp, err := decodeCertificateResponse(body, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		certResp, ok := resp.(*certificate.GetResponse)
		if !ok {
			t.Fatal("expected *certificate.GetResponse")
		}

		if len(certResp.AlternateLinks) != 0 {
			t.Error("expected no alternate links")
		}
	})

	t.Run("MalformedLinkHeader", func(t *testing.T) {
		body := []byte("certificate data")
		headers := make(http.Header)
		headers.Add("Link", `malformed; rel="alternate"`)

		resp, err := decodeCertificateResponse(body, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		certResp, ok := resp.(*certificate.GetResponse)
		if !ok {
			t.Fatal("expected *certificate.GetResponse")
		}

		if len(certResp.AlternateLinks) != 0 {
			t.Error("expected no alternate links from malformed header")
		}
	})
}

func TestDecodeRevokeResponse(t *testing.T) {
	t.Run("WithNonce", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set(HeaderReplayNonce, "test-nonce")

		resp, err := decodeRevokeResponse(nil, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		revokeResp, ok := resp.(*certificate.RevokeResponse)
		if !ok {
			t.Fatal("expected *certificate.RevokeResponse")
		}

		if revokeResp.Nonce != "test-nonce" {
			t.Error("nonce mismatch")
		}
	})

	t.Run("EmptyNonce", func(t *testing.T) {
		headers := make(http.Header)

		resp, err := decodeRevokeResponse(nil, headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		revokeResp, ok := resp.(*certificate.RevokeResponse)
		if !ok {
			t.Fatal("expected *certificate.RevokeResponse")
		}

		if revokeResp.Nonce != "" {
			t.Errorf("expected empty nonce, got: %s", revokeResp.Nonce)
		}
	})
}

func TestHTTPStatusToError(t *testing.T) {
	tests := []struct {
		statusCode int
		expected   errors.ErrorCode
	}{
		{http.StatusBadRequest, errors.CodeInvalidInput},
		{http.StatusUnauthorized, errors.CodeUnauthorized},
		{http.StatusForbidden, errors.CodeForbidden},
		{http.StatusNotFound, errors.CodeNotFound},
		{http.StatusConflict, errors.CodeConflict},
		{http.StatusTooManyRequests, errors.CodeRateLimited},
		{http.StatusInternalServerError, errors.CodeInternal},
		{http.StatusServiceUnavailable, errors.CodeUnavailable},
		{http.StatusGatewayTimeout, errors.CodeTimeout},
		{599, errors.CodeInternal},
		{418, errors.CodeInvalidInput},
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.statusCode), func(t *testing.T) {
			err := httpStatusToError("test", tt.statusCode, "")
			if errors.Code(err) != tt.expected {
				t.Errorf("expected %v, got: %v", tt.expected, errors.Code(err))
			}
		})
	}

	t.Run("CustomMessage", func(t *testing.T) {
		err := httpStatusToError("test.op", 400, "custom error message")
		if errors.Message(err) != "custom error message" {
			t.Errorf("expected custom error message, got: %s", errors.Message(err))
		}
	})
}

func TestParseACMEError(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9444",
		TLSConfig: testTLSConfig(),
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer tr.Close()

	qt := tr.(*Transport)

	t.Run("BadNonce", func(t *testing.T) {
		body := []byte(`{
			"type": "urn:ietf:params:acme:error:badNonce",
			"detail": "JWS has invalid anti-replay nonce"
		}`)

		err := qt.parseACMEError("test", 400, body)
		if err == nil {
			t.Fatal("expected error")
		}

		if errors.Code(err) != errors.CodeACMEBadNonce {
			t.Errorf("expected CodeACMEBadNonce, got: %v", errors.Code(err))
		}
	})

	t.Run("Unauthorized", func(t *testing.T) {
		body := []byte(`{
			"type": "urn:ietf:params:acme:error:unauthorized",
			"detail": "Account is not authorized"
		}`)

		err := qt.parseACMEError("test", 403, body)
		if err == nil {
			t.Fatal("expected error")
		}

		if errors.Code(err) != errors.CodeACMEUnauthorized {
			t.Errorf("expected CodeACMEUnauthorized, got: %v", errors.Code(err))
		}
	})

	t.Run("TypeOnly", func(t *testing.T) {
		body := []byte(`{
			"type": "urn:ietf:params:acme:error:malformed"
		}`)

		err := qt.parseACMEError("test", 400, body)
		if err == nil {
			t.Fatal("expected error")
		}

		if errors.Code(err) != errors.CodeACMEMalformed {
			t.Errorf("expected CodeACMEMalformed, got: %v", errors.Code(err))
		}
	})

	t.Run("WithSubproblems", func(t *testing.T) {
		body := []byte(`{
			"type": "urn:ietf:params:acme:error:compound",
			"detail": "Multiple errors",
			"instance": "https://example.com/error/123",
			"subproblems": [
				{
					"type": "urn:ietf:params:acme:error:dns",
					"detail": "DNS lookup failed",
					"identifier": {"type": "dns", "value": "example.com"}
				}
			]
		}`)

		err := qt.parseACMEError("test", 400, body)
		if err == nil {
			t.Fatal("expected error")
		}

		acmeErr, ok := errors.AsACMEError(err)
		if !ok {
			t.Fatal("expected ACME error")
		}

		if len(acmeErr.Subproblems) != 1 {
			t.Errorf("expected 1 subproblem, got: %d", len(acmeErr.Subproblems))
		}

		if acmeErr.Instance != "https://example.com/error/123" {
			t.Error("instance mismatch")
		}
	})

	t.Run("SubproblemsWithoutIdentifier", func(t *testing.T) {
		body := []byte(`{
			"type": "urn:ietf:params:acme:error:compound",
			"detail": "Multiple errors",
			"subproblems": [
				{
					"type": "urn:ietf:params:acme:error:dns",
					"detail": "DNS lookup failed"
				}
			]
		}`)

		err := qt.parseACMEError("test", 400, body)
		if err == nil {
			t.Fatal("expected error")
		}

		acmeErr, ok := errors.AsACMEError(err)
		if !ok {
			t.Fatal("expected ACME error")
		}

		if len(acmeErr.Subproblems) != 1 {
			t.Errorf("expected 1 subproblem, got: %d", len(acmeErr.Subproblems))
		}

		if acmeErr.Subproblems[0].Identifier != nil {
			t.Error("expected nil identifier")
		}
	})

	t.Run("EmptyBody", func(t *testing.T) {
		err := qt.parseACMEError("test", 500, nil)
		if err == nil {
			t.Fatal("expected error")
		}

		if errors.Code(err) != errors.CodeInternal {
			t.Errorf("expected CodeInternal, got: %v", errors.Code(err))
		}
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		body := []byte(`not json`)

		err := qt.parseACMEError("test", 400, body)
		if err == nil {
			t.Fatal("expected error")
		}

		if errors.Code(err) != errors.CodeInvalidInput {
			t.Errorf("expected CodeInvalidInput, got: %v", errors.Code(err))
		}
	})

	t.Run("EmptyType", func(t *testing.T) {
		body := []byte(`{
			"detail": "Some error without type"
		}`)

		err := qt.parseACMEError("test", 400, body)
		if err == nil {
			t.Fatal("expected error")
		}

		if errors.Code(err) != errors.CodeInvalidInput {
			t.Errorf("expected CodeInvalidInput for empty type, got: %v", errors.Code(err))
		}
	})

	t.Run("UnknownACMEType", func(t *testing.T) {
		body := []byte(`{
			"type": "urn:ietf:params:acme:error:unknownType",
			"detail": "Unknown error type"
		}`)

		err := qt.parseACMEError("test", 400, body)
		if err == nil {
			t.Fatal("expected error")
		}

		if errors.Code(err) != errors.CodeUnknown {
			t.Errorf("expected CodeUnknown for unknown type, got: %v", errors.Code(err))
		}
	})
}

func TestTransportGetLastNonce(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9444",
		TLSConfig: testTLSConfig(),
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer tr.Close()

	qt := tr.(*Transport)

	if qt.GetLastNonce() != "" {
		t.Error("expected empty nonce initially")
	}

	qt.lastNonce.Store("test-nonce-value")

	if qt.GetLastNonce() != "test-nonce-value" {
		t.Error("nonce mismatch")
	}
}

func TestFactory(t *testing.T) {
	t.Run("NewFactory", func(t *testing.T) {
		factory := NewFactory()
		if factory == nil {
			t.Fatal("expected non-nil factory")
		}
	})

	t.Run("Create", func(t *testing.T) {
		factory := NewFactory()
		cfg := &transport.Config{
			Address:   "localhost:9444",
			TLSConfig: testTLSConfig(),
		}

		tr, err := factory.Create(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer tr.Close()

		if !tr.Healthy() {
			t.Error("expected transport to be healthy")
		}
	})

	t.Run("CreateWithNilConfig", func(t *testing.T) {
		factory := NewFactory()
		_, err := factory.Create(nil)
		if err == nil {
			t.Fatal("expected error for nil config")
		}
	})
}

func TestTransportHealthyState(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9444",
		TLSConfig: testTLSConfig(),
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !tr.Healthy() {
		t.Error("expected transport to be healthy initially")
	}

	tr.Close()

	if tr.Healthy() {
		t.Error("expected transport to not be healthy after close")
	}
}

func TestTLSNextProtos(t *testing.T) {
	t.Run("DefaultNextProtos", func(t *testing.T) {
		cfg := &transport.Config{
			Address:   "localhost:9444",
			TLSConfig: &tls.Config{},
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer tr.Close()

		qt := tr.(*Transport)
		if qt.h3Trans.TLSClientConfig.NextProtos[0] != "h3" {
			t.Error("expected h3 NextProto")
		}
	})

	t.Run("PreserveExistingNextProtos", func(t *testing.T) {
		cfg := &transport.Config{
			Address: "localhost:9444",
			TLSConfig: &tls.Config{
				NextProtos: []string{"h3", "h3-29"},
			},
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer tr.Close()

		qt := tr.(*Transport)
		if len(qt.h3Trans.TLSClientConfig.NextProtos) != 2 {
			t.Error("expected preserved NextProtos")
		}
	})
}

func TestCreateHTTPRequest(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9444",
		TLSConfig: testTLSConfig(),
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer tr.Close()

	qt := tr.(*Transport)
	ctx := context.Background()

	t.Run("WithBody", func(t *testing.T) {
		req, err := qt.createHTTPRequest(ctx, http.MethodPost, "https://example.com/test", []byte(`{"test": true}`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if req.Header.Get(HeaderContentType) != ContentTypeJoseJSON {
			t.Error("expected JOSE content type")
		}
	})

	t.Run("WithoutBody", func(t *testing.T) {
		req, err := qt.createHTTPRequest(ctx, http.MethodGet, "https://example.com/test", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if req.Header.Get(HeaderContentType) != "" {
			t.Error("expected no content type for GET")
		}
	})

	t.Run("AcceptHeader", func(t *testing.T) {
		req, err := qt.createHTTPRequest(ctx, http.MethodGet, "https://example.com/test", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		accept := req.Header.Get("Accept")
		if accept == "" {
			t.Error("expected Accept header")
		}
	})

	t.Run("EmptyBodySlice", func(t *testing.T) {
		req, err := qt.createHTTPRequest(ctx, http.MethodPost, "https://example.com/test", []byte{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if req.Header.Get(HeaderContentType) != "" {
			t.Error("expected no content type for empty body")
		}
	})

	t.Run("InvalidURL", func(t *testing.T) {
		_, err := qt.createHTTPRequest(ctx, http.MethodGet, "://invalid-url", nil)
		if err == nil {
			t.Fatal("expected error for invalid URL")
		}
	})
}

func TestRouteConfigs(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9444",
		TLSConfig: testTLSConfig(),
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer tr.Close()

	qt := tr.(*Transport)

	t.Run("DirectoryRoute", func(t *testing.T) {
		route := qt.routes[routeKey{service: "directory", method: "get"}]
		if route.httpMethod != http.MethodGet {
			t.Error("expected GET method")
		}
		if route.path != "/directory" {
			t.Error("expected /directory path")
		}
		if route.bodyEncoder != nil {
			t.Error("expected nil body encoder")
		}
		if route.respDecoder == nil {
			t.Error("expected non-nil response decoder")
		}
	})

	t.Run("NonceRoute", func(t *testing.T) {
		route := qt.routes[routeKey{service: "nonce", method: "new"}]
		if route.httpMethod != http.MethodHead {
			t.Error("expected HEAD method")
		}
		if route.path != "/acme/new-nonce" {
			t.Error("expected /acme/new-nonce path")
		}
	})

	t.Run("AccountCreateRoute", func(t *testing.T) {
		route := qt.routes[routeKey{service: "account", method: "create"}]
		if route.httpMethod != http.MethodPost {
			t.Error("expected POST method")
		}
		if route.path != "/acme/new-acct" {
			t.Error("expected /acme/new-acct path")
		}
	})

	t.Run("OrderCreateRoute", func(t *testing.T) {
		route := qt.routes[routeKey{service: "order", method: "create"}]
		if route.httpMethod != http.MethodPost {
			t.Error("expected POST method")
		}
		if route.path != "/acme/new-order" {
			t.Error("expected /acme/new-order path")
		}
	})

	t.Run("CertificateRevokeRoute", func(t *testing.T) {
		route := qt.routes[routeKey{service: "certificate", method: "revoke"}]
		if route.httpMethod != http.MethodPost {
			t.Error("expected POST method")
		}
		if route.path != "/acme/revoke-cert" {
			t.Error("expected /acme/revoke-cert path")
		}
	})

	t.Run("AccountKeyChangeRoute", func(t *testing.T) {
		route := qt.routes[routeKey{service: "account", method: "key-change"}]
		if route.httpMethod != http.MethodPost {
			t.Error("expected POST method")
		}
		if route.path != "/acme/key-change" {
			t.Error("expected /acme/key-change path")
		}
	})
}

func TestTransportInterfaceCompliance(t *testing.T) {
	var _ transport.Transport = (*Transport)(nil)
}

func TestFactoryInterfaceCompliance(t *testing.T) {
	var _ transport.Factory = (*Factory)(nil)
}

// Tests using mock HTTP round tripper for Request method coverage

func TestRequestWithMock(t *testing.T) {
	t.Run("DirectoryGetSuccess", func(t *testing.T) {
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet {
					t.Errorf("expected GET, got %s", req.Method)
				}
				if req.URL.Path != "/directory" {
					t.Errorf("expected /directory, got %s", req.URL.Path)
				}

				body := `{
					"newNonce": "https://localhost:9444/acme/new-nonce",
					"newAccount": "https://localhost:9444/acme/new-acct",
					"newOrder": "https://localhost:9444/acme/new-order",
					"revokeCert": "https://localhost:9444/acme/revoke-cert",
					"keyChange": "https://localhost:9444/acme/key-change"
				}`
				headers := make(http.Header)
				headers.Set(HeaderReplayNonce, "test-nonce-123")

				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
					Header:     headers,
				}, nil
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		ctx := context.Background()
		resp, err := qt.Request(ctx, "directory", "get", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		dirResp, ok := resp.(*directory.GetResponse)
		if !ok {
			t.Fatal("expected *directory.GetResponse")
		}

		if dirResp.Directory.NewNonce != "https://localhost:9444/acme/new-nonce" {
			t.Error("newNonce mismatch")
		}

		if qt.GetLastNonce() != "test-nonce-123" {
			t.Errorf("expected last nonce to be set, got: %s", qt.GetLastNonce())
		}
	})

	t.Run("NonceNewSuccess", func(t *testing.T) {
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodHead {
					t.Errorf("expected HEAD, got %s", req.Method)
				}

				headers := make(http.Header)
				headers.Set(HeaderReplayNonce, "fresh-nonce-456")

				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBuffer(nil)),
					Header:     headers,
				}, nil
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		ctx := context.Background()
		resp, err := qt.Request(ctx, "nonce", "new", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		nonceResp, ok := resp.(*nonce.NewResponse)
		if !ok {
			t.Fatal("expected *nonce.NewResponse")
		}

		if nonceResp.Nonce != "fresh-nonce-456" {
			t.Errorf("expected fresh-nonce-456, got: %s", nonceResp.Nonce)
		}
	})

	t.Run("AccountCreateSuccess", func(t *testing.T) {
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", req.Method)
				}
				if req.Header.Get(HeaderContentType) != ContentTypeJoseJSON {
					t.Error("expected JOSE content type")
				}

				body := `{
					"status": "valid",
					"contact": ["mailto:test@example.com"],
					"orders": "https://localhost:9444/acme/acct/123/orders"
				}`
				headers := make(http.Header)
				headers.Set(HeaderLocation, "https://localhost:9444/acme/acct/123")
				headers.Set(HeaderReplayNonce, "account-nonce")

				return &http.Response{
					StatusCode: http.StatusCreated,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
					Header:     headers,
				}, nil
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		ctx := context.Background()
		createReq := &account.CreateRequest{
			Contact:              []string{"mailto:test@example.com"},
			TermsOfServiceAgreed: true,
		}
		resp, err := qt.Request(ctx, "account", "create", createReq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		acctResp, ok := resp.(*account.CreateResponse)
		if !ok {
			t.Fatal("expected *account.CreateResponse")
		}

		if acctResp.Account.Status != "valid" {
			t.Error("status mismatch")
		}
		if acctResp.Location != "https://localhost:9444/acme/acct/123" {
			t.Error("location mismatch")
		}
	})

	t.Run("OrderCreateSuccess", func(t *testing.T) {
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				body := `{
					"status": "pending",
					"identifiers": [{"type": "dns", "value": "example.com"}],
					"authorizations": ["https://localhost:9444/acme/authz/123"],
					"finalize": "https://localhost:9444/acme/order/123/finalize"
				}`
				headers := make(http.Header)
				headers.Set(HeaderLocation, "https://localhost:9444/acme/order/123")
				headers.Set(HeaderReplayNonce, "order-nonce")

				return &http.Response{
					StatusCode: http.StatusCreated,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
					Header:     headers,
				}, nil
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		ctx := context.Background()
		orderReq := &order.CreateRequest{
			Identifiers: []order.Identifier{{Type: "dns", Value: "example.com"}},
		}
		resp, err := qt.Request(ctx, "order", "create", orderReq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		orderResp, ok := resp.(*order.CreateResponse)
		if !ok {
			t.Fatal("expected *order.CreateResponse")
		}

		if orderResp.Order.Status != "pending" {
			t.Error("status mismatch")
		}
	})

	t.Run("CertificateRevokeSuccess", func(t *testing.T) {
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				headers := make(http.Header)
				headers.Set(HeaderReplayNonce, "revoke-nonce")

				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBuffer(nil)),
					Header:     headers,
				}, nil
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		ctx := context.Background()
		revokeReq := &certificate.RevokeRequest{
			Certificate: "base64-cert-data",
			Reason:      1,
		}
		resp, err := qt.Request(ctx, "certificate", "revoke", revokeReq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		revokeResp, ok := resp.(*certificate.RevokeResponse)
		if !ok {
			t.Fatal("expected *certificate.RevokeResponse")
		}

		if revokeResp.Nonce != "revoke-nonce" {
			t.Error("nonce mismatch")
		}
	})

	t.Run("HTTPError400", func(t *testing.T) {
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				body := `{
					"type": "urn:ietf:params:acme:error:malformed",
					"detail": "Invalid request format"
				}`
				headers := make(http.Header)
				headers.Set(HeaderReplayNonce, "error-nonce")

				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
					Header:     headers,
				}, nil
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		ctx := context.Background()
		_, err := qt.Request(ctx, "directory", "get", nil)
		if err == nil {
			t.Fatal("expected error")
		}

		if errors.Code(err) != errors.CodeACMEMalformed {
			t.Errorf("expected CodeACMEMalformed, got: %v", errors.Code(err))
		}
	})

	t.Run("HTTPError500", func(t *testing.T) {
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				body := `{
					"type": "urn:ietf:params:acme:error:serverInternal",
					"detail": "Internal server error"
				}`
				headers := make(http.Header)

				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
					Header:     headers,
				}, nil
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		ctx := context.Background()
		_, err := qt.Request(ctx, "directory", "get", nil)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("ConnectionError", func(t *testing.T) {
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				return nil, caerrors.ConnectionFailureError("connection refused")
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		if !qt.Healthy() {
			t.Error("expected transport to be healthy initially")
		}

		ctx := context.Background()
		_, err := qt.Request(ctx, "directory", "get", nil)
		if err == nil {
			t.Fatal("expected error")
		}

		if errors.Code(err) != errors.CodeConnection {
			t.Errorf("expected CodeConnection, got: %v", errors.Code(err))
		}

		if qt.Healthy() {
			t.Error("expected transport to be unhealthy after connection error")
		}
	})

	t.Run("NilResponseDecoder", func(t *testing.T) {
		// Create transport and add a custom route with nil decoder
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				headers := make(http.Header)
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBuffer(nil)),
					Header:     headers,
				}, nil
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		// Add a custom route with nil response decoder for testing
		qt.routes[routeKey{service: "test", method: "nilresp"}] = &routeConfig{
			httpMethod:  http.MethodGet,
			path:        "/test",
			bodyEncoder: nil,
			respDecoder: nil,
		}

		ctx := context.Background()
		resp, err := qt.Request(ctx, "test", "nilresp", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp != nil {
			t.Error("expected nil response for nil decoder")
		}
	})

	t.Run("ResponseWithNonce", func(t *testing.T) {
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				body := `{
					"newNonce": "https://localhost:9444/acme/new-nonce",
					"newAccount": "https://localhost:9444/acme/new-acct",
					"newOrder": "https://localhost:9444/acme/new-order",
					"revokeCert": "https://localhost:9444/acme/revoke-cert",
					"keyChange": "https://localhost:9444/acme/key-change"
				}`
				headers := make(http.Header)
				headers.Set(HeaderReplayNonce, "response-nonce-789")

				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
					Header:     headers,
				}, nil
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		// Initially no nonce
		if qt.GetLastNonce() != "" {
			t.Error("expected empty initial nonce")
		}

		ctx := context.Background()
		_, err := qt.Request(ctx, "directory", "get", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Nonce should be stored from response
		if qt.GetLastNonce() != "response-nonce-789" {
			t.Errorf("expected response-nonce-789, got: %s", qt.GetLastNonce())
		}
	})

	t.Run("ResponseWithoutNonce", func(t *testing.T) {
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				body := `{
					"newNonce": "https://localhost:9444/acme/new-nonce",
					"newAccount": "https://localhost:9444/acme/new-acct",
					"newOrder": "https://localhost:9444/acme/new-order",
					"revokeCert": "https://localhost:9444/acme/revoke-cert",
					"keyChange": "https://localhost:9444/acme/key-change"
				}`
				headers := make(http.Header)
				// No nonce header set

				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
					Header:     headers,
				}, nil
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		// Set an initial nonce
		qt.lastNonce.Store("initial-nonce")

		ctx := context.Background()
		_, err := qt.Request(ctx, "directory", "get", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Nonce should remain unchanged since response had no nonce
		if qt.GetLastNonce() != "initial-nonce" {
			t.Errorf("expected initial-nonce, got: %s", qt.GetLastNonce())
		}
	})

	t.Run("HealthyAfterSuccess", func(t *testing.T) {
		callCount := 0
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				callCount++
				if callCount == 1 {
					// First call fails
					return nil, caerrors.ConnectionFailureError("temporary error")
				}
				// Second call succeeds
				body := `{"newNonce": "https://localhost:9444/acme/new-nonce"}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
					Header:     make(http.Header),
				}, nil
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		ctx := context.Background()

		// First request fails
		_, err := qt.Request(ctx, "directory", "get", nil)
		if err == nil {
			t.Fatal("expected error on first request")
		}
		if qt.Healthy() {
			t.Error("expected unhealthy after failed request")
		}

		// Second request succeeds
		_, err = qt.Request(ctx, "directory", "get", nil)
		if err != nil {
			t.Fatalf("unexpected error on second request: %v", err)
		}
		if !qt.Healthy() {
			t.Error("expected healthy after successful request")
		}
	})
}

func TestFetchNonce(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodHead {
					t.Errorf("expected HEAD, got %s", req.Method)
				}
				if req.URL.Path != "/acme/new-nonce" {
					t.Errorf("expected /acme/new-nonce, got %s", req.URL.Path)
				}

				headers := make(http.Header)
				headers.Set(HeaderReplayNonce, "fetched-nonce-abc")

				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBuffer(nil)),
					Header:     headers,
				}, nil
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		ctx := context.Background()
		nonceValue, err := qt.FetchNonce(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if nonceValue != "fetched-nonce-abc" {
			t.Errorf("expected fetched-nonce-abc, got: %s", nonceValue)
		}
	})

	t.Run("FallbackToLastNonce", func(t *testing.T) {
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				headers := make(http.Header)
				headers.Set(HeaderReplayNonce, "header-nonce")

				// Return a non-nonce response type by using wrong status
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
					Header:     headers,
				}, nil
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		ctx := context.Background()
		nonceValue, err := qt.FetchNonce(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should return the nonce from the response
		if nonceValue != "header-nonce" {
			t.Errorf("expected header-nonce, got: %s", nonceValue)
		}
	})

	t.Run("Error", func(t *testing.T) {
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				return nil, caerrors.ConnectionFailureError("network error")
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		ctx := context.Background()
		_, err := qt.FetchNonce(ctx)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestGetDirectory(t *testing.T) {
	t.Run("FetchSuccess", func(t *testing.T) {
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				body := `{
					"newNonce": "https://localhost:9444/acme/new-nonce",
					"newAccount": "https://localhost:9444/acme/new-acct",
					"newOrder": "https://localhost:9444/acme/new-order",
					"revokeCert": "https://localhost:9444/acme/revoke-cert",
					"keyChange": "https://localhost:9444/acme/key-change",
					"meta": {
						"termsOfService": "https://localhost:9444/tos"
					}
				}`
				headers := make(http.Header)

				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
					Header:     headers,
				}, nil
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		ctx := context.Background()
		dir, err := qt.GetDirectory(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if dir.NewNonce != "https://localhost:9444/acme/new-nonce" {
			t.Error("newNonce mismatch")
		}
		if dir.NewAccount != "https://localhost:9444/acme/new-acct" {
			t.Error("newAccount mismatch")
		}
	})

	t.Run("CachedDirectory", func(t *testing.T) {
		callCount := 0
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				callCount++
				body := `{
					"newNonce": "https://localhost:9444/acme/new-nonce",
					"newAccount": "https://localhost:9444/acme/new-acct",
					"newOrder": "https://localhost:9444/acme/new-order",
					"revokeCert": "https://localhost:9444/acme/revoke-cert",
					"keyChange": "https://localhost:9444/acme/key-change"
				}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
					Header:     make(http.Header),
				}, nil
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		ctx := context.Background()

		// First call fetches
		dir1, err := qt.GetDirectory(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Second call should use cache
		dir2, err := qt.GetDirectory(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if callCount != 1 {
			t.Errorf("expected 1 HTTP call, got: %d", callCount)
		}

		if dir1 != dir2 {
			t.Error("expected same directory instance from cache")
		}
	})

	t.Run("FetchError", func(t *testing.T) {
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				return nil, caerrors.ConnectionFailureError("network error")
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		ctx := context.Background()
		_, err := qt.GetDirectory(ctx)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("InvalidResponse", func(t *testing.T) {
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				// Return non-directory response body - simulate decoder returning different type
				body := `{"status": "ok"}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
					Header:     make(http.Header),
				}, nil
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		// Override the directory route with a custom decoder that returns wrong type
		qt.routes[routeKey{service: "directory", method: "get"}] = &routeConfig{
			httpMethod:  http.MethodGet,
			path:        "/directory",
			bodyEncoder: nil,
			respDecoder: func(body []byte, headers http.Header) (interface{}, error) {
				// Return nil directory to simulate unexpected response
				return &directory.GetResponse{Directory: nil}, nil
			},
		}

		ctx := context.Background()
		_, err := qt.GetDirectory(ctx)
		if err == nil {
			t.Fatal("expected error for nil directory")
		}
		if errors.Code(err) != errors.CodeInternal {
			t.Errorf("expected CodeInternal, got: %v", errors.Code(err))
		}
	})

	t.Run("DoubleCheckLocking", func(t *testing.T) {
		// Test that the double-check locking pattern works correctly
		callCount := 0
		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				callCount++
				body := `{
					"newNonce": "https://localhost:9444/acme/new-nonce",
					"newAccount": "https://localhost:9444/acme/new-acct",
					"newOrder": "https://localhost:9444/acme/new-order",
					"revokeCert": "https://localhost:9444/acme/revoke-cert",
					"keyChange": "https://localhost:9444/acme/key-change"
				}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
					Header:     make(http.Header),
				}, nil
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		// Pre-populate the directory
		qt.directory = &directory.Directory{
			NewNonce:   "cached-nonce",
			NewAccount: "cached-account",
		}

		ctx := context.Background()
		dir, err := qt.GetDirectory(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should return cached directory without HTTP call
		if callCount != 0 {
			t.Errorf("expected 0 HTTP calls, got: %d", callCount)
		}

		if dir.NewNonce != "cached-nonce" {
			t.Error("expected cached directory")
		}
	})
}

func TestRequestBodyEncoding(t *testing.T) {
	t.Run("EncodingError", func(t *testing.T) {
		// Create a type that cannot be JSON encoded
		type unencodable struct {
			Channel chan int `json:"channel"`
		}

		mockRT := &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				t.Fatal("should not reach HTTP call")
				return nil, nil
			},
		}

		qt := newTestTransportWithMock(mockRT)
		defer qt.Close()

		// Add a custom route that uses JSON encoding
		qt.routes[routeKey{service: "test", method: "encode"}] = &routeConfig{
			httpMethod:  http.MethodPost,
			path:        "/test",
			bodyEncoder: encodeJSONBody,
			respDecoder: nil,
		}

		ctx := context.Background()
		_, err := qt.Request(ctx, "test", "encode", &unencodable{Channel: make(chan int)})
		if err == nil {
			t.Fatal("expected error for unencodable type")
		}
		if errors.Code(err) != errors.CodeInvalidInput {
			t.Errorf("expected CodeInvalidInput, got: %v", errors.Code(err))
		}
	})
}

// Test various service/method combinations through Request

func TestRequestAllServices(t *testing.T) {
	tests := []struct {
		service   string
		method    string
		req       interface{}
		checkPath func(path string) bool
	}{
		{"directory", "get", nil, func(p string) bool { return p == "/directory" }},
		{"nonce", "new", nil, func(p string) bool { return p == "/acme/new-nonce" }},
		{"account", "create", &account.CreateRequest{}, func(p string) bool { return p == "/acme/new-acct" }},
		{"account", "get", &account.GetRequest{AccountURL: "https://localhost:9444/acme/acct/1"}, func(p string) bool { return p == "/acme/acct/1" }},
		{"account", "update", &account.UpdateRequest{AccountURL: "https://localhost:9444/acme/acct/1"}, func(p string) bool { return p == "/acme/acct/1" }},
		{"account", "deactivate", &account.DeactivateRequest{AccountURL: "https://localhost:9444/acme/acct/1"}, func(p string) bool { return p == "/acme/acct/1" }},
		{"account", "key-change", &account.KeyChangeRequest{}, func(p string) bool { return p == "/acme/key-change" }},
		{"order", "create", &order.CreateRequest{}, func(p string) bool { return p == "/acme/new-order" }},
		{"order", "get", &order.GetRequest{OrderURL: "https://localhost:9444/acme/order/1"}, func(p string) bool { return p == "/acme/order/1" }},
		{"order", "list", &order.ListRequest{AccountURL: "https://localhost:9444/acme/acct/1"}, func(p string) bool { return p == "/acme/acct/1/orders" }},
		{"order", "finalize", &order.FinalizeRequest{FinalizeURL: "https://localhost:9444/acme/order/1/finalize"}, func(p string) bool { return p == "/acme/order/1/finalize" }},
		{"authorization", "get", &authorization.GetRequest{AuthorizationURL: "https://localhost:9444/acme/authz/1"}, func(p string) bool { return p == "/acme/authz/1" }},
		{"authorization", "deactivate", &authorization.DeactivateRequest{AuthorizationURL: "https://localhost:9444/acme/authz/1"}, func(p string) bool { return p == "/acme/authz/1" }},
		{"challenge", "get", &challenge.GetRequest{ChallengeURL: "https://localhost:9444/acme/chall/1"}, func(p string) bool { return p == "/acme/chall/1" }},
		{"challenge", "respond", &challenge.RespondRequest{ChallengeURL: "https://localhost:9444/acme/chall/1"}, func(p string) bool { return p == "/acme/chall/1" }},
		{"certificate", "get", &certificate.GetRequest{CertificateURL: "https://localhost:9444/acme/cert/1"}, func(p string) bool { return p == "/acme/cert/1" }},
		{"certificate", "revoke", &certificate.RevokeRequest{}, func(p string) bool { return p == "/acme/revoke-cert" }},
	}

	for _, tt := range tests {
		t.Run(tt.service+"/"+tt.method, func(t *testing.T) {
			var capturedPath string
			mockRT := &mockRoundTripper{
				roundTripFunc: func(req *http.Request) (*http.Response, error) {
					capturedPath = req.URL.Path

					// Return appropriate response based on service
					var body string
					headers := make(http.Header)
					headers.Set(HeaderReplayNonce, "test-nonce")
					headers.Set(HeaderLocation, "https://localhost:9444"+req.URL.Path)

					switch tt.service {
					case "directory":
						body = `{"newNonce":"https://localhost:9444/acme/new-nonce","newAccount":"https://localhost:9444/acme/new-acct","newOrder":"https://localhost:9444/acme/new-order","revokeCert":"https://localhost:9444/acme/revoke-cert","keyChange":"https://localhost:9444/acme/key-change"}`
					case "nonce":
						body = ""
					case "account":
						body = `{"status":"valid"}`
					case "order":
						if tt.method == "list" {
							body = `{"orders":[]}`
						} else {
							body = `{"status":"pending","identifiers":[]}`
						}
					case "authorization":
						body = `{"status":"pending","identifier":{"type":"dns","value":"example.com"}}`
					case "challenge":
						body = `{"type":"http-01","status":"pending"}`
					case "certificate":
						if tt.method == "get" {
							body = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
						} else {
							body = ""
						}
					}

					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(body)),
						Header:     headers,
					}, nil
				},
			}

			qt := newTestTransportWithMock(mockRT)
			defer qt.Close()

			ctx := context.Background()
			_, err := qt.Request(ctx, tt.service, tt.method, tt.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !tt.checkPath(capturedPath) {
				t.Errorf("unexpected path: %s", capturedPath)
			}
		})
	}
}

// errorReader implements io.Reader that always returns an error
type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, caerrors.InternalServerError("simulated read error")
}

func TestRequestReadBodyError(t *testing.T) {
	mockRT := &mockRoundTripper{
		roundTripFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(&errorReader{}),
				Header:     make(http.Header),
			}, nil
		},
	}

	qt := newTestTransportWithMock(mockRT)
	defer qt.Close()

	ctx := context.Background()
	_, err := qt.Request(ctx, "directory", "get", nil)
	if err == nil {
		t.Fatal("expected error for read body failure")
	}
	if errors.Code(err) != errors.CodeInternal {
		t.Errorf("expected CodeInternal, got: %v", errors.Code(err))
	}
}
