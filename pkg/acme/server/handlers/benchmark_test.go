//go:build codec_json

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
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
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

		if w.Code != http.StatusOK {
			b.Fatalf("expected status 200, got %d", w.Code)
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
		req := createBenchmarkJWSRequest(b, service, key, service.baseRESTURI+"/acme/new-account", map[string]interface{}{
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
		req := createBenchmarkJWSRequest(b, service, accountKey, service.baseRESTURI+"/acme/new-order", orderPayload, true, account.ID)
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
	_, authz := createBenchmarkOrder(b, service, account.ID, common.StatusPending)
	authID := authz.ID

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

	// Setup: Create account and an order whose challenge is already valid,
	// so each request reads the challenge without re-running validation.
	account := createBenchmarkAccount(b, service, accountKey)
	_, authz := createBenchmarkOrder(b, service, account.ID, common.StatusValid)
	challengeID := authz.Challenges[0].ID

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
		createBenchmarkOrder(b, service, account.ID, common.StatusPending)
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
			req := createBenchmarkJWSRequest(b, service, key, service.baseRESTURI+"/acme/new-account", map[string]interface{}{
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
			req := createBenchmarkJWSRequest(b, service, accountKey, service.baseRESTURI+"/acme/new-order", orderPayload, true, account.ID)
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

	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	if err != nil {
		b.Fatalf("failed to create kvadapter: %v", err)
	}

	factory, err := objstore.NewFactoryFromKVStore(kv)
	if err != nil {
		b.Fatalf("failed to create factory: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	// New orders offer one challenge per registered type, so register the
	// types the unit tests do; the benchmarks never run validation.
	acceptChallenge := func(*net.Resolver, common.CertificateAuthority, string, string, string, string) error {
		return nil
	}

	params := &Params{
		BaseRESTURI:   "https://acme.benchmark.example.com",
		CA:            &MockCA{},
		CAAIdentities: []string{"acme.benchmark.example.com"},
		ChallengeMap: map[string]common.ChallengeVerifierFunc{
			"http-01": acceptChallenge,
			"dns-01":  acceptChallenge,
		},
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
	nonce, err := service.GetNonceService().Generate()
	if err != nil {
		b.Fatalf("failed to generate nonce: %v", err)
	}

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

// createBenchmarkOrder creates a test order for benchmarking with one
// authorization holding an http-01 challenge in challengeStatus.
func createBenchmarkOrder(b *testing.B, service *RestService, accountID uint64, challengeStatus string) (*entities.ACMEOrder, *entities.ACMEAuthorization) {
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

	identifier := entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "benchmark.example.com"}
	order := &entities.ACMEOrder{
		ID:          orderID,
		Status:      common.StatusPending,
		Identifiers: []entities.ACMEIdentifier{identifier},
		Expires:     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Finalize:    fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, orderID),
		AccountID:   accountID,
		URL:         fmt.Sprintf("%s/acme/orders/%d", service.baseRESTURI, orderID),
	}

	authz := createBenchmarkAuthorization(b, service, order, identifier, challengeStatus)
	order.Authorizations = []string{authz.URL}

	if err := orderDAO.Save(ctx, order); err != nil {
		b.Fatalf("failed to save order: %v", err)
	}

	return order, authz
}

// createBenchmarkAuthorization saves an authorization for order with a
// single http-01 challenge in challengeStatus.
func createBenchmarkAuthorization(
	b *testing.B,
	service *RestService,
	order *entities.ACMEOrder,
	identifier entities.ACMEIdentifier,
	challengeStatus string,
) *entities.ACMEAuthorization {
	b.Helper()

	authzDAO, err := service.storageFactory.AuthorizationDAO(order.AccountID)
	if err != nil {
		b.Fatalf("failed to get authorization DAO: %v", err)
	}

	authzID, err := GenerateID()
	if err != nil {
		b.Fatalf("failed to generate authorization ID: %v", err)
	}

	challengeID, err := GenerateID()
	if err != nil {
		b.Fatalf("failed to generate challenge ID: %v", err)
	}

	challenge := entities.ACMEChallenge{
		ID:              challengeID,
		Type:            "http-01",
		Status:          challengeStatus,
		Token:           fmt.Sprintf("benchmark-token-%d", challengeID),
		AccountID:       order.AccountID,
		AuthorizationID: authzID,
		URL:             fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, challengeID),
	}
	if challengeStatus == common.StatusValid {
		challenge.Validated = time.Now().Format(time.RFC3339)
	}

	authz := &entities.ACMEAuthorization{
		ID:         authzID,
		Identifier: identifier,
		Status:     common.StatusPending,
		Expires:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		AccountID:  order.AccountID,
		OrderID:    order.ID,
		Challenges: []entities.ACMEChallenge{challenge},
		URL:        fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authzID),
	}

	if err := authzDAO.Save(context.Background(), authz); err != nil {
		b.Fatalf("failed to save authorization: %v", err)
	}

	return authz
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
