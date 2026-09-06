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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// =============================================================================
// Rate Limiter Wait with Retry-After Wait Path (line 130)
// =============================================================================

func TestRateLimiter_Wait_RetryAfterWaitPathCoverageFinal(t *testing.T) {
	config := &RateLimiterConfig{
		Enabled:           true,
		RequestsPerSecond: 1000, // High rate so we don't hit token limit
		BurstSize:         1000,
		MaxWaitTime:       5 * time.Second,
	}

	rl := NewRateLimiter(config)

	// Deadlines are stored with nanosecond precision, so a short, exact
	// retry-after is enough to exercise the wait path.
	retryAfter := 200 * time.Millisecond
	rl.retryUntil.Store(time.Now().Add(retryAfter).UnixNano())

	ctx := context.Background()
	start := time.Now()

	// This should wait for the retry-after period then succeed
	err := rl.Wait(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("expected no error after waiting, got: %v", err)
	}

	// Verify we honoured the deadline rather than resuming early.
	if elapsed < retryAfter {
		t.Errorf("expected wait of at least %v, got %v", retryAfter, elapsed)
	}

	// Verify retry-after was cleared
	if rl.retryUntil.Load() != 0 {
		t.Error("expected retryUntil to be cleared after wait")
	}
}

func TestRateLimiter_Wait_ContextCancelDuringRetryAfterCoverageFinal(t *testing.T) {
	config := &RateLimiterConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		BurstSize:         10,
		MaxWaitTime:       10 * time.Second,
	}

	rl := NewRateLimiter(config)

	// Set retry-after to 5 seconds in the future
	rl.retryUntil.Store(time.Now().Add(5 * time.Second).UnixNano())

	// Create a context that cancels after 50ms
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// This should return context.DeadlineExceeded (line 129)
	err := rl.Wait(ctx)

	if err != context.DeadlineExceeded {
		t.Errorf("expected context.DeadlineExceeded, got: %v", err)
	}
}

// =============================================================================
// Rate Limiter Wait Deadline Exceeded Path (line 144)
// =============================================================================

func TestRateLimiter_Wait_DeadlineExceededCoverageFinal(t *testing.T) {
	config := &RateLimiterConfig{
		Enabled:           true,
		RequestsPerSecond: 1, // Very slow rate
		BurstSize:         1, // Only 1 token
		MaxWaitTime:       100 * time.Millisecond,
	}

	rl := NewRateLimiter(config)

	ctx := context.Background()

	// Exhaust the token
	if !rl.Allow() {
		t.Fatal("expected first Allow() to succeed")
	}

	// Now Wait should fail because:
	// - No tokens available
	// - Refill rate is too slow (1/sec)
	// - MaxWaitTime is only 100ms
	// This triggers the deadline exceeded path at line 144
	start := time.Now()
	err := rl.Wait(ctx)
	elapsed := time.Since(start)

	if err != ErrRateLimitExceeded {
		t.Errorf("expected ErrRateLimitExceeded, got: %v", err)
	}

	// Should have waited approximately MaxWaitTime
	if elapsed < 90*time.Millisecond {
		t.Errorf("expected wait close to MaxWaitTime (100ms), got %v", elapsed)
	}
}

// =============================================================================
// Rate Limiter Allow with Active RetryUntil (line 170)
// =============================================================================

func TestRateLimiter_Allow_ActiveRetryUntilCoverageFinal(t *testing.T) {
	config := &RateLimiterConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		BurstSize:         10,
		MaxWaitTime:       time.Second,
	}

	rl := NewRateLimiter(config)

	// Set retry-after to the future (5 seconds from now)
	futureTime := time.Now().Add(5 * time.Second).UnixNano()
	rl.retryUntil.Store(futureTime)

	// Allow should return false because we're in retry-after period (line 170-171)
	if rl.Allow() {
		t.Error("expected Allow() to return false during active retry-after period")
	}

	// Verify retryUntil was NOT cleared (it's still in the future)
	if rl.retryUntil.Load() != futureTime {
		t.Error("expected retryUntil to remain unchanged during active period")
	}
}

// =============================================================================
// ARI SupportsARI Error Path (line 347)
// =============================================================================

func TestSupportsARI_ErrorPathCoverageFinal(t *testing.T) {
	// Create a server that returns an error for directory fetch
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return invalid response to cause error
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"type": "urn:ietf:params:acme:error:serverInternal", "detail": "test error"}`))
	}))
	defer server.Close()

	client, err := createMinimalTestClientCoverageFinal(server.URL + "/directory")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	supported, err := client.SupportsARI(ctx)

	// Should return error (not ErrARINotSupported)
	if err == nil {
		t.Error("expected error from SupportsARI")
	}
	if supported {
		t.Error("expected supported=false on error")
	}
}

// =============================================================================
// ARI GetCertificateIDFromHash Return Path (line 333)
// =============================================================================

func TestGetCertificateIDFromHash_ShortHashCoverageFinal(t *testing.T) {
	// This tests the else branch at line 333 where encoded length <= 32
	// SHA256 produces 32 bytes, base64url produces ~43 chars, so this
	// path is actually never hit with real data. But we test the function works.
	cert := createTestCertWithSerialCoverageFinal(t, "test", big.NewInt(1))

	id := GetCertificateIDFromHash(cert)
	if id == "" {
		t.Error("expected non-empty certificate ID")
	}
	// SHA256 of cert DER -> 32 bytes -> base64url = 43 chars -> truncated to 32
	if len(id) != 32 {
		t.Errorf("expected ID length 32, got %d", len(id))
	}
}

func TestGetCertificateIDFromHash_EmptyRawCoverageFinal(t *testing.T) {
	// Test with certificate that has empty Raw field
	cert := &x509.Certificate{
		Raw: []byte{}, // Empty
	}

	id := GetCertificateIDFromHash(cert)
	if id != "" {
		t.Errorf("expected empty ID for cert with empty Raw, got: %s", id)
	}
}

// =============================================================================
// Resolver SolveWithCleanup Solver Not Found After Solve (line 297-299)
// =============================================================================

func TestChallengeResolver_SolveWithCleanup_SolverRemovedAfterSolveCoverageFinal(t *testing.T) {
	resolver := NewChallengeResolver()

	// Create a solver that unregisters itself after solve
	solved := false
	solver := &mockSolverWithUnregisterCoverageFinal{
		typeName: "http-01",
		solveFn: func(ctx context.Context, domain string, challenge *acme.Challenge, keyAuth string) error {
			solved = true
			// Unregister the solver after solving - simulating edge case
			resolver.UnregisterSolver("http-01")
			return nil
		},
		cleanupFn: func(ctx context.Context, domain string, challenge *acme.Challenge) error {
			return nil
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

	if !solved {
		t.Error("expected solver to be called")
	}

	// Should return ErrNoSolverRegistered because solver was unregistered
	if err == nil {
		t.Error("expected error when solver not found after solve")
	}
}

// =============================================================================
// encodePrivateKeyPEM ECDSA Marshal Error Path (line 245-247)
// =============================================================================

func TestEncodePrivateKeyPEM_ECDSAMarshalErrorCoverageFinal(t *testing.T) {
	// Create an ECDSA key with a nil curve to trigger the marshal error.
	// The raw X/Y/D fields are assigned directly and SA1019 is suppressed
	// deliberately: a key with NO curve cannot be produced by any supported
	// constructor -- ecdsa.ParseRawPrivateKey and ParseUncompressedPublicKey
	// both require a curve and validate against it -- and a key that fails to
	// marshal is precisely the input this error path exists to handle.
	invalidKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: nil,           // Invalid curve
			X:     big.NewInt(1), //nolint:staticcheck // SA1019: see above
			Y:     big.NewInt(1), //nolint:staticcheck // SA1019: see above
		},
		D: big.NewInt(1), //nolint:staticcheck // SA1019: see above
	}

	_, err := encodePrivateKeyPEM(invalidKey)
	if err == nil {
		t.Error("expected error for invalid ECDSA key")
	}
}

// =============================================================================
// encodePrivateKeyPEM Ed25519 Success Path (line 252-260)
// =============================================================================

func TestEncodePrivateKeyPEM_Ed25519SuccessCoverageFinal(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	pemData, err := encodePrivateKeyPEM(priv)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(pemData) == 0 {
		t.Error("expected non-empty PEM output")
	}

	// Verify PEM structure
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Error("expected valid PEM block")
		return
	}
	if block.Type != "PRIVATE KEY" {
		t.Errorf("expected type 'PRIVATE KEY', got %s", block.Type)
	}
}

// =============================================================================
// DNS Solver CheckDNSFromAuthoritative Error Path (line 421-423)
// =============================================================================

func TestCheckDNSFromAuthoritative_PropagationCheckErrorCoverageFinal(t *testing.T) {
	checkFunc := CheckDNSFromAuthoritative(WithNameserverLookup(failingNameservers()))

	// Use a completely invalid domain that will fail NS lookup
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := checkFunc(ctx, "_acme-challenge.invalid-domain-12345.test.", "test-value")
	if err == nil {
		t.Error("expected error for invalid domain")
	}
}

func TestCheckDNSFromPublic_PropagationCheckErrorCoverageFinal(t *testing.T) {
	checkFunc := CheckDNSFromPublic(WithPropagationQuery(propagationResult(false)))

	// Use a domain that definitely doesn't have the TXT record
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := checkFunc(ctx, "_acme-challenge.nonexistent-test-domain.example.", "expected-value")
	// Should return ErrDNSRecordNotPresent or propagation error
	if err == nil {
		t.Error("expected error for nonexistent record")
	}
}

// =============================================================================
// DNS Solver CheckDNSFromNameservers Coverage
// =============================================================================

func TestCheckDNSFromNameservers_NotPresentCoverageFinal(t *testing.T) {
	// Test with a domain that won't have our expected TXT record
	nameservers := []string{"8.8.8.8:53"}
	checkFunc := CheckDNSFromNameservers(nameservers, WithPropagationQuery(propagationResult(false)))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := checkFunc(ctx, "_acme-challenge.nonexistent-domain-test.example.com.", "expected-value")
	// Should return ErrDNSRecordNotPresent since the record doesn't exist
	if err == nil {
		t.Error("expected error for nonexistent record")
	}
}

func TestCheckDNSFromNameservers_ErrorCoverageFinal(t *testing.T) {
	// Test with invalid nameserver that will cause an error
	nameservers := []string{"192.0.2.1:53"} // TEST-NET-1, won't respond
	checkFunc := CheckDNSFromNameservers(nameservers, WithPropagationQuery(propagationFailure()))

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := checkFunc(ctx, "_acme-challenge.test.example.", "test-value")
	// Should return an error (either timeout or connection refused)
	if err == nil {
		t.Error("expected error for unreachable nameserver")
	}
}

// =============================================================================
// Rate Limiter Refill Race Condition Path (line 209)
// =============================================================================

func TestRateLimiter_RefillCASFailureCoverageFinal(t *testing.T) {
	config := &RateLimiterConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		BurstSize:         10,
		MaxWaitTime:       time.Second,
	}

	rl := NewRateLimiter(config)

	// Call Allow() multiple times concurrently to trigger CAS races
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = rl.Allow()
				time.Sleep(time.Microsecond)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// If we got here without race detector errors, the test passes
	// The CAS failure path at line 209 would have been hit
}

// =============================================================================
// Rate Limiter Wait with MaxWaitTime exceeded due to long retry-after
// =============================================================================

func TestRateLimiter_Wait_RetryAfterExceedsMaxWaitCoverageFinal(t *testing.T) {
	config := &RateLimiterConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		BurstSize:         10,
		MaxWaitTime:       100 * time.Millisecond, // Short max wait
	}

	rl := NewRateLimiter(config)

	// Set retry-after to 5 seconds in the future (exceeds MaxWaitTime)
	rl.retryUntil.Store(time.Now().Add(5 * time.Second).UnixNano())

	ctx := context.Background()

	// Should return ErrRateLimitExceeded because retry-after > MaxWaitTime
	err := rl.Wait(ctx)
	if err != ErrRateLimitExceeded {
		t.Errorf("expected ErrRateLimitExceeded, got: %v", err)
	}
}

// =============================================================================
// Rate Limiter Context Cancel During Token Wait
// =============================================================================

func TestRateLimiter_Wait_ContextCancelDuringTokenWaitCoverageFinal(t *testing.T) {
	config := &RateLimiterConfig{
		Enabled:           true,
		RequestsPerSecond: 1, // Very slow refill
		BurstSize:         1, // Only 1 token
		MaxWaitTime:       10 * time.Second,
	}

	rl := NewRateLimiter(config)

	// Exhaust the token
	if !rl.Allow() {
		t.Fatal("expected first Allow() to succeed")
	}

	// Create a context that cancels quickly
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Should return context.DeadlineExceeded
	err := rl.Wait(ctx)
	if err != context.DeadlineExceeded {
		t.Errorf("expected context.DeadlineExceeded, got: %v", err)
	}
}

// =============================================================================
// Helper Types and Functions
// =============================================================================

type mockSolverWithUnregisterCoverageFinal struct {
	typeName  string
	solveFn   func(ctx context.Context, domain string, challenge *acme.Challenge, keyAuth string) error
	cleanupFn func(ctx context.Context, domain string, challenge *acme.Challenge) error
}

func (m *mockSolverWithUnregisterCoverageFinal) Type() string {
	return m.typeName
}

func (m *mockSolverWithUnregisterCoverageFinal) Solve(ctx context.Context, domain string, challenge *acme.Challenge, keyAuth string) error {
	if m.solveFn != nil {
		return m.solveFn(ctx, domain, challenge, keyAuth)
	}
	return nil
}

func (m *mockSolverWithUnregisterCoverageFinal) Cleanup(ctx context.Context, domain string, challenge *acme.Challenge) error {
	if m.cleanupFn != nil {
		return m.cleanupFn(ctx, domain, challenge)
	}
	return nil
}

func createMinimalTestClientCoverageFinal(directoryURL string) (*Client, error) {
	// Generate a simple key for the client
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	config := &Config{
		DirectoryURL: directoryURL,
	}

	// Create HTTP client
	httpClient := &http.Client{
		Transport: &http.Transport{},
		Timeout:   10 * time.Second,
	}

	return &Client{
		config:        config,
		httpClient:    httpClient,
		accountSigner: key,
		logger:        slog.Default(),
	}, nil
}

func createTestCertWithSerialCoverageFinal(t *testing.T, cn string, serial *big.Int) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

// Unused but needed for compilation
var _ = base64.StdEncoding
