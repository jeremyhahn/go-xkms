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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// =============================================================================
// ARI Function Tests
// =============================================================================

func TestComputeRenewalTime_Coverage91(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		result := ComputeRenewalTime(nil, 0.3)
		if !result.IsZero() {
			t.Error("expected zero time for nil certificate")
		}
	})

	t.Run("default threshold", func(t *testing.T) {
		cert := createCov91TestCert(t, "Test", 90*24*time.Hour)
		result := ComputeRenewalTime(cert, 0)

		// With 0 threshold, should default to 0.3 (30% remaining)
		expectedRemaining := time.Duration(90*24*time.Hour) * 30 / 100
		expectedRenewAt := cert.NotAfter.Add(-expectedRemaining)

		diff := result.Sub(expectedRenewAt)
		if diff < -time.Minute || diff > time.Minute {
			t.Errorf("unexpected renewal time, expected around %v, got %v", expectedRenewAt, result)
		}
	})

	t.Run("negative threshold", func(t *testing.T) {
		cert := createCov91TestCert(t, "Test", 90*24*time.Hour)
		result := ComputeRenewalTime(cert, -0.5)

		// Should default to 0.3
		expectedRemaining := time.Duration(90*24*time.Hour) * 30 / 100
		expectedRenewAt := cert.NotAfter.Add(-expectedRemaining)

		diff := result.Sub(expectedRenewAt)
		if diff < -time.Minute || diff > time.Minute {
			t.Errorf("unexpected renewal time for negative threshold")
		}
	})

	t.Run("threshold >= 1", func(t *testing.T) {
		cert := createCov91TestCert(t, "Test", 90*24*time.Hour)
		result := ComputeRenewalTime(cert, 1.5)

		// Should default to 0.3
		expectedRemaining := time.Duration(90*24*time.Hour) * 30 / 100
		expectedRenewAt := cert.NotAfter.Add(-expectedRemaining)

		diff := result.Sub(expectedRenewAt)
		if diff < -time.Minute || diff > time.Minute {
			t.Errorf("unexpected renewal time for threshold >= 1")
		}
	})

	t.Run("valid threshold", func(t *testing.T) {
		cert := createCov91TestCert(t, "Test", 90*24*time.Hour)
		threshold := 0.5
		result := ComputeRenewalTime(cert, threshold)

		expectedRemaining := time.Duration(90*24*time.Hour) * 50 / 100
		expectedRenewAt := cert.NotAfter.Add(-expectedRemaining)

		diff := result.Sub(expectedRenewAt)
		if diff < -time.Minute || diff > time.Minute {
			t.Errorf("unexpected renewal time, expected around %v, got %v", expectedRenewAt, result)
		}
	})
}

func TestNeedsRenewal_Coverage91(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		result := NeedsRenewal(nil, 0.3)
		if result {
			t.Error("expected false for nil certificate")
		}
	})

	t.Run("certificate does not need renewal", func(t *testing.T) {
		cert := createCov91TestCert(t, "Fresh Cert", 90*24*time.Hour)
		result := NeedsRenewal(cert, 0.3)

		if result {
			t.Error("expected false for fresh certificate")
		}
	})

	t.Run("certificate needs renewal", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Expiring Cert"},
			NotBefore:    time.Now().Add(-23 * time.Hour),
			NotAfter:     time.Now().Add(1 * time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certDER)

		result := NeedsRenewal(cert, 0.3)
		if !result {
			t.Error("expected true for expiring certificate")
		}
	})
}

func TestDaysUntilExpiry_Coverage91(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		result := DaysUntilExpiry(nil)
		if result != 0 {
			t.Errorf("expected 0 for nil certificate, got %d", result)
		}
	})

	t.Run("expired certificate", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Expired Cert"},
			NotBefore:    time.Now().Add(-48 * time.Hour),
			NotAfter:     time.Now().Add(-24 * time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certDER)

		result := DaysUntilExpiry(cert)
		if result != 0 {
			t.Errorf("expected 0 for expired certificate, got %d", result)
		}
	})

	t.Run("valid certificate", func(t *testing.T) {
		cert := createCov91TestCert(t, "Valid Cert", 30*24*time.Hour)

		result := DaysUntilExpiry(cert)
		if result < 29 || result > 31 {
			t.Errorf("expected ~30 days until expiry, got %d", result)
		}
	})
}

func TestIsExpired_Coverage91(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		if !IsExpired(nil) {
			t.Error("expected true for nil certificate")
		}
	})

	t.Run("expired certificate", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Expired"},
			NotBefore:    time.Now().Add(-48 * time.Hour),
			NotAfter:     time.Now().Add(-1 * time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certDER)

		if !IsExpired(cert) {
			t.Error("expected true for expired certificate")
		}
	})

	t.Run("valid certificate", func(t *testing.T) {
		cert := createCov91TestCert(t, "Valid", 30*24*time.Hour)
		if IsExpired(cert) {
			t.Error("expected false for valid certificate")
		}
	})
}

func TestIsNotYetValid_Coverage91(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		if !IsNotYetValid(nil) {
			t.Error("expected true for nil certificate")
		}
	})

	t.Run("future certificate", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Future"},
			NotBefore:    time.Now().Add(24 * time.Hour),
			NotAfter:     time.Now().Add(48 * time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certDER)

		if !IsNotYetValid(cert) {
			t.Error("expected true for future certificate")
		}
	})

	t.Run("valid certificate", func(t *testing.T) {
		cert := createCov91TestCert(t, "Valid", 30*24*time.Hour)
		if IsNotYetValid(cert) {
			t.Error("expected false for valid certificate")
		}
	})
}

// =============================================================================
// Resolver Tests
// =============================================================================

func TestChallengeResolver_AdditionalCoverage91(t *testing.T) {
	t.Run("RegisterSolver nil", func(t *testing.T) {
		resolver := NewChallengeResolver()
		err := resolver.RegisterSolver(nil)
		if err == nil {
			t.Error("expected error for nil solver")
		}
	})

	t.Run("RegisterSolver when closed", func(t *testing.T) {
		resolver := NewChallengeResolver()
		_ = resolver.Close()

		err := resolver.RegisterSolver(&cov91MockChallengeSolver{})
		if !errors.Is(err, ErrResolverClosed) {
			t.Errorf("expected ErrResolverClosed, got %v", err)
		}
	})

	t.Run("GetSolver for registered type", func(t *testing.T) {
		resolver := NewChallengeResolver()
		solver := &cov91MockChallengeSolver{}
		_ = resolver.RegisterSolver(solver)

		retrieved, ok := resolver.GetSolver("mock-01")
		if !ok || retrieved == nil {
			t.Error("expected solver to be found")
		}
	})

	t.Run("GetSolver for unregistered type", func(t *testing.T) {
		resolver := NewChallengeResolver()
		_, ok := resolver.GetSolver("unknown-01")
		if ok {
			t.Error("expected false for unregistered solver")
		}
	})

	t.Run("HasSolver true", func(t *testing.T) {
		resolver := NewChallengeResolver()
		_ = resolver.RegisterSolver(&cov91MockChallengeSolver{})

		if !resolver.HasSolver("mock-01") {
			t.Error("expected HasSolver to return true")
		}
	})

	t.Run("HasSolver false", func(t *testing.T) {
		resolver := NewChallengeResolver()

		if resolver.HasSolver("unknown-01") {
			t.Error("expected HasSolver to return false")
		}
	})

	t.Run("Solve nil authorization", func(t *testing.T) {
		resolver := NewChallengeResolver()
		_, err := resolver.Solve(context.Background(), nil, "keyAuth")
		if !errors.Is(err, ErrNilAuthorization) {
			t.Errorf("expected ErrNilAuthorization, got %v", err)
		}
	})

	t.Run("Solve empty domain", func(t *testing.T) {
		resolver := NewChallengeResolver()
		authz := &acme.Authorization{
			Identifier: acme.AuthzID{Value: ""},
			Challenges: []*acme.Challenge{
				{Type: "mock-01", Status: "pending"},
			},
		}
		_, err := resolver.Solve(context.Background(), authz, "keyAuth")
		if !errors.Is(err, ErrEmptyDomain) {
			t.Errorf("expected ErrEmptyDomain, got %v", err)
		}
	})

	t.Run("Solve empty keyAuth", func(t *testing.T) {
		resolver := NewChallengeResolver()
		authz := &acme.Authorization{
			Identifier: acme.AuthzID{Value: "example.com"},
			Challenges: []*acme.Challenge{
				{Type: "mock-01", Status: "pending"},
			},
		}
		_, err := resolver.Solve(context.Background(), authz, "")
		if !errors.Is(err, ErrEmptyKeyAuth) {
			t.Errorf("expected ErrEmptyKeyAuth, got %v", err)
		}
	})

	t.Run("Solve when closed", func(t *testing.T) {
		resolver := NewChallengeResolver()
		_ = resolver.Close()

		authz := &acme.Authorization{
			Identifier: acme.AuthzID{Value: "example.com"},
			Challenges: []*acme.Challenge{
				{Type: "mock-01", Status: "pending"},
			},
		}
		_, err := resolver.Solve(context.Background(), authz, "keyAuth")
		if !errors.Is(err, ErrResolverClosed) {
			t.Errorf("expected ErrResolverClosed, got %v", err)
		}
	})

	t.Run("Solve no matching solver", func(t *testing.T) {
		resolver := NewChallengeResolver()
		authz := &acme.Authorization{
			Identifier: acme.AuthzID{Value: "example.com"},
			Challenges: []*acme.Challenge{
				{Type: "unknown-01", Status: "pending"},
			},
		}
		_, err := resolver.Solve(context.Background(), authz, "keyAuth")
		if !errors.Is(err, ErrNoChallengeSupported) {
			t.Errorf("expected ErrNoChallengeSupported, got %v", err)
		}
	})

	t.Run("UnregisterSolver", func(t *testing.T) {
		resolver := NewChallengeResolver()
		solver := &cov91MockChallengeSolver{}
		resolver.RegisterSolver(solver)

		if !resolver.HasSolver("mock-01") {
			t.Fatal("solver should be registered")
		}

		resolver.UnregisterSolver("mock-01")

		if resolver.HasSolver("mock-01") {
			t.Error("solver should have been removed")
		}
	})

	t.Run("ListSolvers", func(t *testing.T) {
		resolver := NewChallengeResolver()
		resolver.RegisterSolver(&cov91MockChallengeSolver{})

		solvers := resolver.ListSolvers()
		found := false
		for _, s := range solvers {
			if s == "mock-01" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected mock-01 in solver list")
		}
	})

	t.Run("SolverCount", func(t *testing.T) {
		resolver := NewChallengeResolver()
		initialCount := resolver.SolverCount()

		resolver.RegisterSolver(&cov91MockChallengeSolver{})

		if resolver.SolverCount() != initialCount+1 {
			t.Error("expected solver count to increase by 1")
		}
	})

	t.Run("IsClosed false", func(t *testing.T) {
		resolver := NewChallengeResolver()
		if resolver.IsClosed() {
			t.Error("expected IsClosed to return false")
		}
	})

	t.Run("IsClosed true", func(t *testing.T) {
		resolver := NewChallengeResolver()
		resolver.Close()
		if !resolver.IsClosed() {
			t.Error("expected IsClosed to return true")
		}
	})
}

// =============================================================================
// DNS Solver Tests
// =============================================================================

func TestDefaultPreCheckOption_Coverage91(t *testing.T) {
	opt := DefaultPreCheckOption()
	if opt == nil {
		t.Fatal("expected non-nil option")
	}
	if opt.Timeout <= 0 {
		t.Error("expected positive timeout")
	}
	if opt.Interval <= 0 {
		t.Error("expected positive interval")
	}
	if opt.AllowFailure {
		t.Error("expected AllowFailure to be false by default")
	}
}

func TestWrapPreCheck_Coverage91(t *testing.T) {
	solver := &DNSSolver{}

	t.Run("nil option uses defaults", func(t *testing.T) {
		wrapped := WrapPreCheck(solver, nil)
		if wrapped == nil {
			t.Fatal("expected non-nil wrapped solver")
		}
		if wrapped.option.Timeout <= 0 {
			t.Error("expected positive timeout")
		}
	})

	t.Run("custom timeout", func(t *testing.T) {
		wrapped := WrapPreCheck(solver, &PreCheckOption{
			Timeout:  5 * time.Minute,
			Interval: 10 * time.Second,
		})
		if wrapped.option.Timeout != 5*time.Minute {
			t.Errorf("expected 5m timeout, got %v", wrapped.option.Timeout)
		}
		if wrapped.option.Interval != 10*time.Second {
			t.Errorf("expected 10s interval, got %v", wrapped.option.Interval)
		}
	})
}

// =============================================================================
// Type Coverage Tests
// =============================================================================

func TestChallengeTypes_Coverage91(t *testing.T) {
	t.Run("ChallengeTypeDNS01", func(t *testing.T) {
		if ChallengeTypeDNS01.String() != "dns-01" {
			t.Errorf("expected 'dns-01', got %q", ChallengeTypeDNS01.String())
		}
	})

	t.Run("ChallengeTypeTLSALPN01", func(t *testing.T) {
		if ChallengeTypeTLSALPN01.String() != "tls-alpn-01" {
			t.Errorf("expected 'tls-alpn-01', got %q", ChallengeTypeTLSALPN01.String())
		}
	})
}

func TestAccountStatus_Coverage91(t *testing.T) {
	statuses := []AccountStatus{
		AccountStatusValid,
		AccountStatusDeactivated,
		AccountStatusRevoked,
	}

	for _, status := range statuses {
		s := status.String()
		if s == "" {
			t.Errorf("expected non-empty string for status %v", status)
		}
	}
}

func TestOrderStatus_Coverage91(t *testing.T) {
	statuses := []OrderStatus{
		OrderStatusPending,
		OrderStatusReady,
		OrderStatusProcessing,
		OrderStatusValid,
		OrderStatusInvalid,
	}

	for _, status := range statuses {
		s := status.String()
		if s == "" {
			t.Errorf("expected non-empty string for status %v", status)
		}
	}
}

// =============================================================================
// RenewalInfo Additional Tests
// =============================================================================

func TestRenewalInfo_HasExplanation_Coverage91(t *testing.T) {
	t.Run("nil RenewalInfo", func(t *testing.T) {
		var ri *RenewalInfo
		if ri.HasExplanation() {
			t.Error("expected false for nil RenewalInfo")
		}
	})

	t.Run("without explanation", func(t *testing.T) {
		ri := &RenewalInfo{}
		if ri.HasExplanation() {
			t.Error("expected false for RenewalInfo without explanation")
		}
	})

	t.Run("with explanation", func(t *testing.T) {
		ri := &RenewalInfo{}
		ri.ExplanationURL = "https://example.com/explanation"
		if !ri.HasExplanation() {
			t.Error("expected true for RenewalInfo with explanation")
		}
	})
}

// =============================================================================
// encodePrivateKeyPEM Tests
// =============================================================================

func TestEncodePrivateKeyPEM_Coverage91(t *testing.T) {
	t.Run("RSA key", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		pemData, err := encodePrivateKeyPEM(key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		block, _ := pem.Decode(pemData)
		if block == nil {
			t.Fatal("failed to decode PEM")
		}
		if block.Type != "RSA PRIVATE KEY" {
			t.Errorf("expected 'RSA PRIVATE KEY', got %q", block.Type)
		}
	})

	t.Run("ECDSA key", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}

		pemData, err := encodePrivateKeyPEM(key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		block, _ := pem.Decode(pemData)
		if block == nil {
			t.Fatal("failed to decode PEM")
		}
		if block.Type != "EC PRIVATE KEY" {
			t.Errorf("expected 'EC PRIVATE KEY', got %q", block.Type)
		}
	})

	t.Run("Ed25519 key", func(t *testing.T) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate Ed25519 key: %v", err)
		}

		pemData, err := encodePrivateKeyPEM(key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		block, _ := pem.Decode(pemData)
		if block == nil {
			t.Fatal("failed to decode PEM")
		}
		if block.Type != "PRIVATE KEY" {
			t.Errorf("expected 'PRIVATE KEY', got %q", block.Type)
		}
	})

	t.Run("unsupported key type", func(t *testing.T) {
		_, err := encodePrivateKeyPEM("not a key")
		if !errors.Is(err, ErrUnsupportedKeyType) {
			t.Errorf("expected ErrUnsupportedKeyType, got %v", err)
		}
	})
}

// =============================================================================
// OCSP HasMustStaple Tests
// =============================================================================

func TestHasMustStaple_Coverage91(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		if HasMustStaple(nil) {
			t.Error("expected false for nil certificate")
		}
	})

	t.Run("certificate without must-staple", func(t *testing.T) {
		cert := createCov91TestCert(t, "No Must-Staple", 24*time.Hour)
		if HasMustStaple(cert) {
			t.Error("expected false for certificate without must-staple")
		}
	})
}

// =============================================================================
// Solve with registered solver test
// =============================================================================

func TestChallengeResolver_SolveWithSolver_Coverage91(t *testing.T) {
	t.Run("Solve success with registered solver", func(t *testing.T) {
		resolver := NewChallengeResolver()
		solver := &cov91MockChallengeSolver{}
		resolver.RegisterSolver(solver)

		authz := &acme.Authorization{
			Identifier: acme.AuthzID{Value: "example.com"},
			Challenges: []*acme.Challenge{
				{Type: "mock-01", Status: "pending", Token: "test-token"},
			},
		}

		challenge, err := resolver.Solve(context.Background(), authz, "keyAuth123")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if challenge == nil {
			t.Error("expected non-nil challenge")
			return
		}
		if challenge.Type != "mock-01" {
			t.Errorf("expected challenge type 'mock-01', got %q", challenge.Type)
		}
	})

	t.Run("Solve with solver error", func(t *testing.T) {
		resolver := NewChallengeResolver()
		solveErr := errors.New("solver failed")
		solver := &cov91MockChallengeSolver{solveErr: solveErr}
		resolver.RegisterSolver(solver)

		authz := &acme.Authorization{
			Identifier: acme.AuthzID{Value: "example.com"},
			Challenges: []*acme.Challenge{
				{Type: "mock-01", Status: "pending", Token: "test-token"},
			},
		}

		_, err := resolver.Solve(context.Background(), authz, "keyAuth123")
		if err == nil {
			t.Error("expected error from solver")
		}
	})
}

// =============================================================================
// Cleanup Tests
// =============================================================================

func TestChallengeResolver_Cleanup_Coverage91(t *testing.T) {
	t.Run("Cleanup with empty domain", func(t *testing.T) {
		resolver := NewChallengeResolver()
		err := resolver.Cleanup(context.Background(), "", nil)
		if err == nil {
			t.Error("expected error for empty domain")
		}
	})

	t.Run("Cleanup with nil challenge", func(t *testing.T) {
		resolver := NewChallengeResolver()
		err := resolver.Cleanup(context.Background(), "example.com", nil)
		if err == nil {
			t.Error("expected error for nil challenge")
		}
	})

	t.Run("Cleanup success", func(t *testing.T) {
		resolver := NewChallengeResolver()
		solver := &cov91MockChallengeSolver{}
		resolver.RegisterSolver(solver)

		challenge := &acme.Challenge{Type: "mock-01", Token: "test-token"}

		err := resolver.Cleanup(context.Background(), "example.com", challenge)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("Cleanup with solver error", func(t *testing.T) {
		resolver := NewChallengeResolver()
		cleanupErr := errors.New("cleanup failed")
		solver := &cov91MockChallengeSolver{cleanupErr: cleanupErr}
		resolver.RegisterSolver(solver)

		challenge := &acme.Challenge{Type: "mock-01", Token: "test-token"}

		err := resolver.Cleanup(context.Background(), "example.com", challenge)
		if err == nil {
			t.Error("expected error from cleanup")
		}
	})
}

// =============================================================================
// Identifier Tests
// =============================================================================

func TestIdentifier_Coverage91(t *testing.T) {
	t.Run("DNS identifier", func(t *testing.T) {
		id := Identifier{
			Type:  "dns",
			Value: "example.com",
		}
		if id.Type != "dns" {
			t.Errorf("expected type 'dns', got %q", id.Type)
		}
		if id.Value != "example.com" {
			t.Errorf("expected value 'example.com', got %q", id.Value)
		}
	})

	t.Run("IP identifier", func(t *testing.T) {
		id := Identifier{
			Type:  "ip",
			Value: "192.168.1.1",
		}
		if id.Type != "ip" {
			t.Errorf("expected type 'ip', got %q", id.Type)
		}
	})
}

// =============================================================================
// Helper Functions
// =============================================================================

func createCov91TestCert(t *testing.T, cn string, validity time.Duration) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(validity),
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

// cov91MockChallengeSolver for testing
type cov91MockChallengeSolver struct {
	solveErr   error
	cleanupErr error
}

func (m *cov91MockChallengeSolver) Type() string {
	return "mock-01"
}

func (m *cov91MockChallengeSolver) Solve(ctx context.Context, domain string, challenge *acme.Challenge, keyAuth string) error {
	return m.solveErr
}

func (m *cov91MockChallengeSolver) Cleanup(ctx context.Context, domain string, challenge *acme.Challenge) error {
	return m.cleanupErr
}
