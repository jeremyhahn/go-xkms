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
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// =============================================================================
// GetRenewalInfo Error Paths
// =============================================================================

func TestGetRenewalInfo_RequestCreationErrorCoverage90(t *testing.T) {
	// Create a client with an invalid URL that will cause request creation to fail
	client := createTestClientWithLoggerCoverage90("://invalid-url")

	ctx := context.Background()
	_, err := client.GetRenewalInfo(ctx, "test-cert-id")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestGetRenewalInfo_HTTPClientErrorCoverage90(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/directory":
			dir := map[string]interface{}{
				"newNonce":    server.URL + "/new-nonce",
				"newAccount":  server.URL + "/new-account",
				"renewalInfo": "http://192.0.2.1/renewal-info", // TEST-NET address, won't respond
			}
			_ = json.NewEncoder(w).Encode(dir)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := createTestClientWithLoggerCoverage90(server.URL + "/directory")

	// Set a short timeout to make the test faster
	client.httpClient.Timeout = 100 * time.Millisecond

	ctx := context.Background()
	_, err := client.GetRenewalInfo(ctx, "test-cert-id")
	if err == nil {
		t.Error("expected error for unreachable server")
	}
}

func TestGetRenewalInfo_NonOKStatusCoverage90(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/directory":
			dir := map[string]interface{}{
				"newNonce":    server.URL + "/new-nonce",
				"newAccount":  server.URL + "/new-account",
				"renewalInfo": server.URL + "/renewal-info",
			}
			_ = json.NewEncoder(w).Encode(dir)
		case "/renewal-info/test-cert-id":
			// Return non-200 status (line 144)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"detail": "service unavailable"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := createTestClientWithLoggerCoverage90(server.URL + "/directory")

	ctx := context.Background()
	_, err := client.GetRenewalInfo(ctx, "test-cert-id")
	if err == nil {
		t.Error("expected error for 503 status")
	}
}

func TestGetRenewalInfo_DecodeErrorCoverage90(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/directory":
			dir := map[string]interface{}{
				"newNonce":    server.URL + "/new-nonce",
				"newAccount":  server.URL + "/new-account",
				"renewalInfo": server.URL + "/renewal-info",
			}
			_ = json.NewEncoder(w).Encode(dir)
		case "/renewal-info/test-cert-id":
			// Return invalid JSON (line 149)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{invalid json`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := createTestClientWithLoggerCoverage90(server.URL + "/directory")

	ctx := context.Background()
	_, err := client.GetRenewalInfo(ctx, "test-cert-id")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestGetRenewalInfo_InvalidStartTimeCoverage90(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/directory":
			dir := map[string]interface{}{
				"newNonce":    server.URL + "/new-nonce",
				"newAccount":  server.URL + "/new-account",
				"renewalInfo": server.URL + "/renewal-info",
			}
			_ = json.NewEncoder(w).Encode(dir)
		case "/renewal-info/test-cert-id":
			// Return valid JSON but invalid start time (line 155)
			resp := map[string]interface{}{
				"suggestedWindow": map[string]string{
					"start": "invalid-time",
					"end":   "2024-12-31T23:59:59Z",
				},
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := createTestClientWithLoggerCoverage90(server.URL + "/directory")

	ctx := context.Background()
	_, err := client.GetRenewalInfo(ctx, "test-cert-id")
	if err == nil {
		t.Error("expected error for invalid start time")
	}
}

// =============================================================================
// CreateOrderWithReplaces Error Paths
// =============================================================================

func TestCreateOrderWithReplaces_InvalidCertIDCoverage90(t *testing.T) {
	client := createTestClientWithLoggerCoverage90("http://example.com/directory")

	ctx := context.Background()
	_, err := client.CreateOrderWithReplaces(ctx, []string{"example.com"}, "")
	if err == nil {
		t.Error("expected error for empty certID")
	}
}

func TestCreateOrderWithReplaces_InvalidDomainsCoverage90(t *testing.T) {
	client := createTestClientWithLoggerCoverage90("http://example.com/directory")

	ctx := context.Background()
	_, err := client.CreateOrderWithReplaces(ctx, nil, "test-cert-id")
	if err == nil {
		t.Error("expected error for nil domains")
	}

	_, err = client.CreateOrderWithReplaces(ctx, []string{}, "test-cert-id")
	if err == nil {
		t.Error("expected error for empty domains")
	}
}

// =============================================================================
// ShouldRenewAt ARI Debug Path
// =============================================================================

func TestShouldRenewAt_ARINotAvailableCoverage90(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/directory":
			// No renewalInfo in directory (ARI not supported)
			dir := map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
			}
			_ = json.NewEncoder(w).Encode(dir)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := createTestClientWithLoggerCoverage90(server.URL + "/directory")

	cert := createTestCertificateCoverage90()
	ctx := context.Background()

	// Should fall back to certificate-based calculation (line 549-550)
	renewAt, err := client.ShouldRenewAt(ctx, cert, 0.3)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if renewAt.IsZero() {
		t.Error("expected non-zero renewal time")
	}
}

// =============================================================================
// Resolver Error Paths
// =============================================================================

func TestChallengeResolver_SolveWithCleanup_AllChallengesFailCoverage90(t *testing.T) {
	resolver := NewChallengeResolver()

	// Register a solver that always fails
	testErr := errors.New("test solver error")
	solver := &mockSolverCoverage90{
		typeName: "http-01",
		solveFn: func(ctx context.Context, domain string, challenge *acme.Challenge, keyAuth string) error {
			return testErr
		},
	}
	_ = resolver.RegisterSolver(solver)

	authz := &acme.Authorization{
		Identifier: acme.AuthzID{Type: "dns", Value: "example.com"},
		Challenges: []*acme.Challenge{
			{Type: "http-01", Token: "test-token"},
		},
	}

	ctx := context.Background()
	err := resolver.SolveWithCleanup(ctx, authz, "key-auth", nil)
	if err == nil {
		t.Error("expected error when solver fails")
	}
}

// =============================================================================
// Helper Types and Functions
// =============================================================================

type mockSolverCoverage90 struct {
	typeName  string
	solveFn   func(ctx context.Context, domain string, challenge *acme.Challenge, keyAuth string) error
	cleanupFn func(ctx context.Context, domain string, challenge *acme.Challenge) error
}

func (m *mockSolverCoverage90) Type() string {
	return m.typeName
}

func (m *mockSolverCoverage90) Solve(ctx context.Context, domain string, challenge *acme.Challenge, keyAuth string) error {
	if m.solveFn != nil {
		return m.solveFn(ctx, domain, challenge, keyAuth)
	}
	return nil
}

func (m *mockSolverCoverage90) Cleanup(ctx context.Context, domain string, challenge *acme.Challenge) error {
	if m.cleanupFn != nil {
		return m.cleanupFn(ctx, domain, challenge)
	}
	return nil
}

func createTestClientWithLoggerCoverage90(directoryURL string) *Client {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	config := &Config{
		DirectoryURL: directoryURL,
	}

	httpClient := &http.Client{
		Transport: &http.Transport{},
		Timeout:   10 * time.Second,
	}

	return &Client{
		config:        config,
		httpClient:    httpClient,
		accountSigner: key,
		logger:        slog.Default(),
	}
}

func createTestCertificateCoverage90() *x509.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	return cert
}
