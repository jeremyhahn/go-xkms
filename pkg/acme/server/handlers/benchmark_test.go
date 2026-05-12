//go:build codec_json

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

package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-objstore/pkg/local"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// BenchmarkDirectoryHandler benchmarks the directory endpoint
func BenchmarkDirectoryHandler(b *testing.B) {
	service, _, cleanup := setupBenchmarkService(b)
	defer cleanup()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		w := httptest.NewRecorder()

		service.DirectoryHandler(w, req)

		if w.Code != http.StatusOK {
			b.Fatalf("expected status 200, got %d", w.Code)
		}
	}
}

// BenchmarkNewNonceHandler benchmarks nonce generation
func BenchmarkNewNonceHandler(b *testing.B) {
	service, _, cleanup := setupBenchmarkService(b)
	defer cleanup()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodHead, "/acme/new-nonce", nil)
		w := httptest.NewRecorder()

		service.NewNonceHandler(w, req)

		if w.Code != http.StatusNoContent {
			b.Fatalf("expected status 204, got %d", w.Code)
		}
	}
}

// BenchmarkNewAccountHandler benchmarks account creation
func BenchmarkNewAccountHandler(b *testing.B) {
	service, _, cleanup := setupBenchmarkService(b)
	defer cleanup()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		key := generateBenchmarkTestKey(b)
		req := createBenchmarkJWSRequest(b, service, key, "/acme/new-account", map[string]interface{}{
			"termsOfServiceAgreed": true,
			"contact":              []string{"mailto:benchmark@example.com"},
		}, false, 0)

		w := httptest.NewRecorder()
		service.NewAccountHandler(w, req)

		if w.Code != http.StatusCreated && w.Code != http.StatusOK {
			b.Fatalf("expected status 201 or 200, got %d", w.Code)
		}
	}
}

// BenchmarkNewOrderHandler benchmarks order creation
func BenchmarkNewOrderHandler(b *testing.B) {
	service, accountKey, cleanup := setupBenchmarkService(b)
	defer cleanup()

	// Create a test account
	account := createBenchmarkAccount(b, service, accountKey)

	orderPayload := map[string]interface{}{
		"identifiers": []map[string]string{
			{
				"type":  "dns",
				"value": "benchmark.example.com",
			},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req := createBenchmarkJWSRequest(b, service, accountKey, "/acme/new-order", orderPayload, true, account.ID)
		w := httptest.NewRecorder()

		service.NewOrderHandler(w, req)

		if w.Code != http.StatusCreated {
			b.Fatalf("expected status 201, got %d", w.Code)
		}
	}
}

// BenchmarkAuthorizationHandler benchmarks authorization retrieval
func BenchmarkAuthorizationHandler(b *testing.B) {
	service, accountKey, cleanup := setupBenchmarkService(b)
	defer cleanup()

	// Setup: Create account and order
	account := createBenchmarkAccount(b, service, accountKey)
	order := createBenchmarkOrder(b, service, account.ID)

	if len(order.Authorizations) == 0 {
		b.Fatal("order has no authorizations")
	}

	authID := extractBenchmarkIDFromURL(order.Authorizations[0])

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authID)
		req := createBenchmarkJWSRequest(b, service, accountKey, url, nil, true, account.ID)
		req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", authID)})

		w := httptest.NewRecorder()
		service.AuthorizationHandler(w, req)

		if w.Code != http.StatusOK {
			b.Fatalf("expected status 200, got %d", w.Code)
		}
	}
}

// BenchmarkChallengeHandler benchmarks challenge retrieval
func BenchmarkChallengeHandler(b *testing.B) {
	service, accountKey, cleanup := setupBenchmarkService(b)
	defer cleanup()

	// Setup: Create account, order, and get challenge
	account := createBenchmarkAccount(b, service, accountKey)
	order := createBenchmarkOrder(b, service, account.ID)

	if len(order.Authorizations) == 0 {
		b.Fatal("order has no authorizations")
	}

	authID := extractBenchmarkIDFromURL(order.Authorizations[0])
	authorization := getBenchmarkAuthorization(b, service, accountKey, account.ID, authID)

	if len(authorization.Challenges) == 0 {
		b.Fatal("authorization has no challenges")
	}

	challengeID := extractBenchmarkIDFromURL(authorization.Challenges[0].URL)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, challengeID)
		req := createBenchmarkJWSRequest(b, service, accountKey, url, map[string]interface{}{}, true, account.ID)
		req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", challengeID)})

		w := httptest.NewRecorder()
		service.ChallengeHandler(w, req)

		if w.Code != http.StatusOK {
			b.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}
	}
}

// BenchmarkOrdersListHandler benchmarks listing orders for an account
func BenchmarkOrdersListHandler(b *testing.B) {
	service, accountKey, cleanup := setupBenchmarkService(b)
	defer cleanup()

	// Setup: Create account and multiple orders
	account := createBenchmarkAccount(b, service, accountKey)

	// Pre-create 10 orders
	for i := 0; i < 10; i++ {
		createBenchmarkOrder(b, service, account.ID)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		url := fmt.Sprintf("%s/acme/account/%d/orders", service.baseRESTURI, account.ID)
		req := createBenchmarkJWSRequest(b, service, accountKey, url, nil, true, account.ID)
		req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", account.ID)})

		w := httptest.NewRecorder()
		service.OrdersListHandler(w, req)

		if w.Code != http.StatusOK {
			b.Fatalf("expected status 200, got %d", w.Code)
		}
	}
}

// Parallel benchmarks to measure concurrent handler performance

// BenchmarkDirectoryHandler_Parallel benchmarks concurrent directory requests
func BenchmarkDirectoryHandler_Parallel(b *testing.B) {
	service, _, cleanup := setupBenchmarkService(b)
	defer cleanup()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
			w := httptest.NewRecorder()

			service.DirectoryHandler(w, req)

			if w.Code != http.StatusOK {
				b.Fatalf("expected status 200, got %d", w.Code)
			}
		}
	})
}

// BenchmarkNewAccountHandler_Parallel benchmarks concurrent account creation
func BenchmarkNewAccountHandler_Parallel(b *testing.B) {
	service, _, cleanup := setupBenchmarkService(b)
	defer cleanup()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			key := generateBenchmarkTestKey(b)
			req := createBenchmarkJWSRequest(b, service, key, "/acme/new-account", map[string]interface{}{
				"termsOfServiceAgreed": true,
				"contact":              []string{"mailto:benchmark@example.com"},
			}, false, 0)

			w := httptest.NewRecorder()
			service.NewAccountHandler(w, req)

			if w.Code != http.StatusCreated && w.Code != http.StatusOK {
				b.Fatalf("expected status 201 or 200, got %d", w.Code)
			}
		}
	})
}

// BenchmarkNewOrderHandler_Parallel benchmarks concurrent order creation
func BenchmarkNewOrderHandler_Parallel(b *testing.B) {
	service, accountKey, cleanup := setupBenchmarkService(b)
	defer cleanup()

	// Pre-create account
	account := createBenchmarkAccount(b, service, accountKey)

	orderPayload := map[string]interface{}{
		"identifiers": []map[string]string{
			{
				"type":  "dns",
				"value": "benchmark.example.com",
			},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := createBenchmarkJWSRequest(b, service, accountKey, "/acme/new-order", orderPayload, true, account.ID)
			w := httptest.NewRecorder()

			service.NewOrderHandler(w, req)

			if w.Code != http.StatusCreated {
				b.Fatalf("expected status 201, got %d", w.Code)
			}
		}
	})
}

// Helper functions for benchmarking

// setupBenchmarkService creates a service instance for benchmarking
func setupBenchmarkService(b *testing.B) (*RestService, *TestKey, func()) {
	b.Helper()

	tmpDir, err := os.MkdirTemp("", "acme-benchmark-*")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}

	store := local.New()
	if err := store.Configure(map[string]string{"path": tmpDir}); err != nil {
		b.Fatalf("failed to configure store: %v", err)
	}

	factory, err := objstore.NewFactory(store)
	if err != nil {
		b.Fatalf("failed to create factory: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	params := &Params{
		BaseRESTURI:    "https://acme.benchmark.example.com",
		CA:             &MockCA{},
		CAAIdentities:  []string{"acme.benchmark.example.com"},
		ChallengeMap:   make(map[string]common.ChallengeVerifierFunc),
		Logger:         logger,
		StorageFactory: factory,
		TermsOfService: "https://acme.benchmark.example.com/tos",
	}

	service, err := NewRestService(params)
	if err != nil {
		b.Fatalf("failed to create service: %v", err)
	}

	// Generate a test key for account operations
	key := generateBenchmarkTestKey(b)

	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	return service.(*RestService), key, cleanup
}

// generateBenchmarkTestKey generates a TestKey for benchmarking
func generateBenchmarkTestKey(b *testing.B) *TestKey {
	b.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate key: %v", err)
	}

	jwk := &jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     "",
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}

	return &TestKey{
		PrivateKey: privateKey,
		PublicKey:  privateKey.Public(),
		JWK:        jwk,
	}
}

// createBenchmarkJWSRequest creates a JWS-signed request for benchmarking
func createBenchmarkJWSRequest(
	b *testing.B,
	service *RestService,
	key *TestKey,
	url string,
	payload interface{},
	useKID bool,
	accountID uint64,
) *http.Request {
	b.Helper()

	// Get a valid nonce
	nonce, err := common.GenerateNonce(nonceSize)
	if err != nil {
		b.Fatalf("failed to generate nonce: %v", err)
	}
	service.nonceStore.Add(nonce)

	// Marshal payload
	var payloadBytes []byte
	if payload != nil {
		payloadBytes, err = json.Marshal(payload)
		if err != nil {
			b.Fatalf("failed to marshal payload: %v", err)
		}
	} else {
		payloadBytes = []byte("")
	}

	// Create signer options
	signerOpts := &jose.SignerOptions{
		NonceSource: &benchmarkNonceSource{nonce: nonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	}

	if useKID {
		signerOpts.ExtraHeaders["kid"] = fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, accountID)
	} else {
		signerOpts.EmbedJWK = true
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key.PrivateKey,
	}, signerOpts)
	if err != nil {
		b.Fatalf("failed to create signer: %v", err)
	}

	jws, err := signer.Sign(payloadBytes)
	if err != nil {
		b.Fatalf("failed to sign payload: %v", err)
	}

	serialized := jws.FullSerialize()

	req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(serialized))
	req.Header.Set("Content-Type", "application/jose+json")

	return req
}

// benchmarkNonceSource provides a static nonce for benchmarking
type benchmarkNonceSource struct {
	nonce string
}

func (s *benchmarkNonceSource) Nonce() (string, error) {
	return s.nonce, nil
}

// createBenchmarkAccount creates a test account for benchmarking
func createBenchmarkAccount(b *testing.B, service *RestService, key *TestKey) *entities.ACMEAccount {
	b.Helper()

	ctx := context.Background()

	accountDAO, err := service.storageFactory.AccountDAO()
	if err != nil {
		b.Fatalf("failed to get account DAO: %v", err)
	}

	pubKeyPEM, err := xkmssdk.EncodePublicKeyPEM(key.PublicKey)
	if err != nil {
		b.Fatalf("failed to encode public key: %v", err)
	}

	accountID, err := AccountIDFromPublicKey(key.PublicKey)
	if err != nil {
		b.Fatalf("failed to generate account ID: %v", err)
	}

	account := &entities.ACMEAccount{
		ID:                   accountID,
		Status:               common.StatusValid,
		Contact:              []string{"mailto:benchmark@example.com"},
		TermsOfServiceAgreed: true,
		Key:                  string(pubKeyPEM),
		CreatedAt:            time.Now(),
		Orders:               fmt.Sprintf("%s/acme/account/%d/orders", service.baseRESTURI, accountID),
		URL:                  fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, accountID),
	}

	if err := accountDAO.Save(ctx, account); err != nil {
		b.Fatalf("failed to save account: %v", err)
	}

	return account
}

// createBenchmarkOrder creates a test order for benchmarking
func createBenchmarkOrder(b *testing.B, service *RestService, accountID uint64) *entities.ACMEOrder {
	b.Helper()

	ctx := context.Background()

	orderDAO, err := service.storageFactory.OrderDAO(accountID)
	if err != nil {
		b.Fatalf("failed to get order DAO: %v", err)
	}

	orderID, err := GenerateID()
	if err != nil {
		b.Fatalf("failed to generate order ID: %v", err)
	}

	order := &entities.ACMEOrder{
		ID:     orderID,
		Status: common.StatusPending,
		Identifiers: []entities.ACMEIdentifier{
			{Type: "dns", Value: "benchmark.example.com"},
		},
		Expires:        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Authorizations: []string{fmt.Sprintf("%s/acme/authz/1", service.baseRESTURI)},
		Finalize:       fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, orderID),
		AccountID:      accountID,
		URL:            fmt.Sprintf("%s/acme/orders/%d", service.baseRESTURI, orderID),
	}

	if err := orderDAO.Save(ctx, order); err != nil {
		b.Fatalf("failed to save order: %v", err)
	}

	return order
}

// getBenchmarkAuthorization retrieves an authorization for benchmarking
func getBenchmarkAuthorization(
	b *testing.B,
	service *RestService,
	key *TestKey,
	accountID uint64,
	authID uint64,
) *entities.ACMEAuthorization {
	b.Helper()

	url := fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authID)
	req := createBenchmarkJWSRequest(b, service, key, url, nil, true, accountID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", authID)})

	w := httptest.NewRecorder()
	service.AuthorizationHandler(w, req)

	if w.Code != http.StatusOK {
		b.Fatalf("failed to get authorization: status %d", w.Code)
	}

	var auth entities.ACMEAuthorization
	if err := json.NewDecoder(w.Body).Decode(&auth); err != nil {
		b.Fatalf("failed to decode authorization: %v", err)
	}

	return &auth
}

// extractBenchmarkIDFromURL extracts an ID from an ACME URL
func extractBenchmarkIDFromURL(url string) uint64 {
	parts := strings.Split(url, "/")
	if len(parts) == 0 {
		return 0
	}
	idStr := parts[len(parts)-1]
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return 0
	}
	return id
}

// compile-time check to silence unused warnings for helper functions
var (
	_ = generateBenchmarkCSR
	_ = base64URLEncode
)

// generateBenchmarkCSR generates a test CSR for benchmarking
func generateBenchmarkCSR(b *testing.B, domain string) []byte {
	b.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames: []string{domain},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		b.Fatalf("failed to create CSR: %v", err)
	}

	return csrDER
}

// base64URLEncode encodes data in base64 URL format
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
