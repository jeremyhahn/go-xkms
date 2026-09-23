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

package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"sync"
	"testing"
	"time"
)

// mockCAService implements CAService for testing.
type mockCAService struct {
	signCSRFunc    func(csrPEM []byte) ([]byte, error)
	getCACertFunc  func() ([]byte, error)
	revokeCertFunc func(serialNumber string) error
	isRevokedFunc  func(serialNumber string) (bool, error)
}

func (m *mockCAService) SignCSR(csrPEM []byte) ([]byte, error) {
	if m.signCSRFunc != nil {
		return m.signCSRFunc(csrPEM)
	}
	// Return a real, parseable certificate embedding the CSR's own public
	// key (as a real CA would) with a unique serial number, so callers
	// that extract the serial or fingerprint the leaf's key (as
	// enrollment and VerifyAgentCertificate now do) see the same
	// certificate-issuance path xkmsd exercises in production.
	return mustTestCertPEMForCSR(csrPEM, time.Now().UnixNano()), nil
}

func (m *mockCAService) GetCACertificate() ([]byte, error) {
	if m.getCACertFunc != nil {
		return m.getCACertFunc()
	}
	return []byte("-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----\n"), nil
}

func (m *mockCAService) RevokeCertificate(serialNumber string) error {
	if m.revokeCertFunc != nil {
		return m.revokeCertFunc(serialNumber)
	}
	return nil
}

func (m *mockCAService) IsRevoked(serialNumber string) (bool, error) {
	if m.isRevokedFunc != nil {
		return m.isRevokedFunc(serialNumber)
	}
	return false, nil
}

// mustTestCertPEMForCSR mints a real, parseable certificate PEM that
// embeds the given CSR's own public key, signed by a throwaway key,
// exactly as xkmsd's CA embeds an enrolling agent's key when it signs the
// agent's CSR. Chain-of-trust is not exercised by these tests, only that
// the resulting leaf certificate's public key - and therefore its
// enrollment fingerprint - matches the CSR that produced it.
func mustTestCertPEMForCSR(csrPEM []byte, serial int64) []byte {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		panic("mustTestCertPEMForCSR: CSR is not PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		panic(err)
	}

	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, csr.PublicKey, signerKey)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test-agent"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

func testEnrollmentService(t *testing.T) (*EnrollmentService, *mockCAService) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.EnrollmentMethods = []EnrollmentMethod{
		EnrollOneTimeCode,
		EnrollAdminApproval,
	}
	ca := &mockCAService{}
	store := NewMemoryStore()
	svc, err := NewEnrollmentService(cfg, ca, store, testLogger())
	if err != nil {
		t.Fatalf("failed to create enrollment service: %v", err)
	}
	return svc, ca
}

func TestNewEnrollmentService_NilConfig(t *testing.T) {
	_, err := NewEnrollmentService(nil, &mockCAService{}, NewMemoryStore(), testLogger())
	if !errors.Is(err, ErrNilConfig) {
		t.Errorf("expected ErrNilConfig, got %v", err)
	}
}

func TestNewEnrollmentService_NilCA(t *testing.T) {
	_, err := NewEnrollmentService(DefaultConfig(), nil, NewMemoryStore(), testLogger())
	if !errors.Is(err, ErrNilCAService) {
		t.Errorf("expected ErrNilCAService, got %v", err)
	}
}

func TestNewEnrollmentService_NilStore(t *testing.T) {
	_, err := NewEnrollmentService(DefaultConfig(), &mockCAService{}, nil, testLogger())
	if !errors.Is(err, ErrNilEnrollmentStore) {
		t.Errorf("expected ErrNilEnrollmentStore, got %v", err)
	}
}

func TestNewEnrollmentService_NilLogger(t *testing.T) {
	_, err := NewEnrollmentService(DefaultConfig(), &mockCAService{}, NewMemoryStore(), nil)
	if !errors.Is(err, ErrNilLogger) {
		t.Errorf("expected ErrNilLogger, got %v", err)
	}
}

func TestGenerateOneTimeCode_Success(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	code, err := svc.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code.Code == "" {
		t.Error("code should not be empty")
	}
	if code.Used {
		t.Error("code should not be used")
	}
	if code.ExpiresAt.Before(time.Now()) {
		t.Error("code should not be expired")
	}
	if len(code.Code) != 8 {
		t.Errorf("expected code length 8, got %d", len(code.Code))
	}
}

func TestGenerateOneTimeCode_DefaultValidity(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	code, err := svc.GenerateOneTimeCode(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should use the default 15 minutes.
	expectedMin := time.Now().Add(14 * time.Minute)
	expectedMax := time.Now().Add(16 * time.Minute)
	if code.ExpiresAt.Before(expectedMin) || code.ExpiresAt.After(expectedMax) {
		t.Errorf("expiry %v should be approximately 15 minutes from now", code.ExpiresAt)
	}
}

func TestGenerateOneTimeCode_MethodNotAllowed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnrollmentMethods = []EnrollmentMethod{EnrollAdminApproval}
	svc, err := NewEnrollmentService(cfg, &mockCAService{}, NewMemoryStore(), testLogger())
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	_, err = svc.GenerateOneTimeCode(5 * time.Minute)
	if !errors.Is(err, ErrEnrollmentMethodNotAllowed) {
		t.Errorf("expected ErrEnrollmentMethodNotAllowed, got %v", err)
	}
}

func TestEnrollWithCode_Success(t *testing.T) {
	svc, _ := testEnrollmentService(t)
	csrPEM := testCSR(t)

	code, err := svc.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	certPEM, caPEM, err := svc.EnrollWithCode(code.Code, csrPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certPEM) == 0 {
		t.Error("cert PEM should not be empty")
	}
	if len(caPEM) == 0 {
		t.Error("CA PEM should not be empty")
	}
}

func TestEnrollWithCode_InvalidCode(t *testing.T) {
	svc, _ := testEnrollmentService(t)
	csrPEM := testCSR(t)

	_, _, err := svc.EnrollWithCode("nonexistent", csrPEM)
	if !errors.Is(err, ErrEnrollmentCodeInvalid) {
		t.Errorf("expected ErrEnrollmentCodeInvalid, got %v", err)
	}
}

func TestEnrollWithCode_ExpiredCode(t *testing.T) {
	svc, _ := testEnrollmentService(t)
	csrPEM := testCSR(t)

	code, err := svc.GenerateOneTimeCode(1 * time.Nanosecond)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	// Wait for the code to expire.
	time.Sleep(10 * time.Millisecond)

	_, _, err = svc.EnrollWithCode(code.Code, csrPEM)
	if !errors.Is(err, ErrEnrollmentCodeExpired) {
		t.Errorf("expected ErrEnrollmentCodeExpired, got %v", err)
	}
}

func TestEnrollWithCode_UsedCode(t *testing.T) {
	svc, _ := testEnrollmentService(t)
	csrPEM := testCSR(t)

	code, err := svc.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	// Use the code once.
	_, _, err = svc.EnrollWithCode(code.Code, csrPEM)
	if err != nil {
		t.Fatalf("first enrollment should succeed: %v", err)
	}

	// Try to use the same code again.
	_, _, err = svc.EnrollWithCode(code.Code, csrPEM)
	if !errors.Is(err, ErrEnrollmentCodeInvalid) {
		t.Errorf("expected ErrEnrollmentCodeInvalid for reused code, got %v", err)
	}
}

func TestEnrollWithCode_EmptyCSR(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	code, err := svc.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	_, _, err = svc.EnrollWithCode(code.Code, nil)
	if !errors.Is(err, ErrInvalidCSR) {
		t.Errorf("expected ErrInvalidCSR, got %v", err)
	}
}

func TestEnrollWithCode_MethodNotAllowed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnrollmentMethods = []EnrollmentMethod{EnrollAdminApproval}
	svc, err := NewEnrollmentService(cfg, &mockCAService{}, NewMemoryStore(), testLogger())
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	_, _, err = svc.EnrollWithCode("code", testCSR(t))
	if !errors.Is(err, ErrEnrollmentMethodNotAllowed) {
		t.Errorf("expected ErrEnrollmentMethodNotAllowed, got %v", err)
	}
}

func TestEnrollWithCode_MaxAgentsReached(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxAgents = 1
	store := NewMemoryStore()
	_ = store.SaveAgent(&AgentInfo{ID: "existing-agent", Status: "active"})

	svc, err := NewEnrollmentService(cfg, &mockCAService{}, store, testLogger())
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	code, err := svc.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	_, _, err = svc.EnrollWithCode(code.Code, testCSR(t))
	if !errors.Is(err, ErrMaxAgentsReached) {
		t.Errorf("expected ErrMaxAgentsReached, got %v", err)
	}
}

func TestEnrollWithCode_CASignError(t *testing.T) {
	svc, ca := testEnrollmentService(t)
	ca.signCSRFunc = func([]byte) ([]byte, error) {
		return nil, errors.New("ca error")
	}

	code, err := svc.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	_, _, err = svc.EnrollWithCode(code.Code, testCSR(t))
	if err == nil {
		t.Fatal("expected error from CA signing failure")
	}
}

func TestSubmitEnrollmentRequest_Success(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	requestID, err := svc.SubmitEnrollmentRequest(testCSR(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requestID == "" {
		t.Error("request ID should not be empty")
	}

	pending, err := svc.ListPending()
	if err != nil {
		t.Fatalf("unexpected error listing pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending request, got %d", len(pending))
	}
	if pending[0].ID != requestID {
		t.Errorf("expected request ID %q, got %q", requestID, pending[0].ID)
	}
	if pending[0].Status != "pending" {
		t.Errorf("expected status 'pending', got %q", pending[0].Status)
	}
}

func TestSubmitEnrollmentRequest_EmptyCSR(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	_, err := svc.SubmitEnrollmentRequest(nil)
	if !errors.Is(err, ErrInvalidCSR) {
		t.Errorf("expected ErrInvalidCSR, got %v", err)
	}
}

func TestSubmitEnrollmentRequest_MethodNotAllowed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnrollmentMethods = []EnrollmentMethod{EnrollOneTimeCode}
	svc, err := NewEnrollmentService(cfg, &mockCAService{}, NewMemoryStore(), testLogger())
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	_, err = svc.SubmitEnrollmentRequest(testCSR(t))
	if !errors.Is(err, ErrEnrollmentMethodNotAllowed) {
		t.Errorf("expected ErrEnrollmentMethodNotAllowed, got %v", err)
	}
}

func TestApproveEnrollment_Success(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	requestID, err := svc.SubmitEnrollmentRequest(testCSR(t))
	if err != nil {
		t.Fatalf("failed to submit request: %v", err)
	}

	certPEM, caPEM, err := svc.ApproveEnrollment(requestID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certPEM) == 0 {
		t.Error("cert PEM should not be empty")
	}
	if len(caPEM) == 0 {
		t.Error("CA PEM should not be empty")
	}

	// Pending list should be empty after approval.
	pending, _ := svc.ListPending()
	if len(pending) != 0 {
		t.Errorf("expected 0 pending requests after approval, got %d", len(pending))
	}
}

func TestApproveEnrollment_EmptyRequestID(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	_, _, err := svc.ApproveEnrollment("")
	if !errors.Is(err, ErrInvalidRequestID) {
		t.Errorf("expected ErrInvalidRequestID, got %v", err)
	}
}

func TestApproveEnrollment_NotFound(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	_, _, err := svc.ApproveEnrollment("nonexistent")
	if !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("expected ErrRequestNotFound, got %v", err)
	}
}

func TestApproveEnrollment_AlreadyRejected(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	requestID, err := svc.SubmitEnrollmentRequest(testCSR(t))
	if err != nil {
		t.Fatalf("failed to submit request: %v", err)
	}

	if err := svc.RejectEnrollment(requestID, "test"); err != nil {
		t.Fatalf("failed to reject: %v", err)
	}

	// Rejection deletes the request, so approving it afterward is
	// indistinguishable from approving a request that never existed.
	_, _, err = svc.ApproveEnrollment(requestID)
	if !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("expected ErrRequestNotFound, got %v", err)
	}
}

func TestRejectEnrollment_Success(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	requestID, err := svc.SubmitEnrollmentRequest(testCSR(t))
	if err != nil {
		t.Fatalf("failed to submit request: %v", err)
	}

	err = svc.RejectEnrollment(requestID, "not authorized")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Rejected requests should not appear in pending list.
	pending, _ := svc.ListPending()
	if len(pending) != 0 {
		t.Errorf("expected 0 pending requests after rejection, got %d", len(pending))
	}
}

func TestRejectEnrollment_EmptyRequestID(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	err := svc.RejectEnrollment("", "reason")
	if !errors.Is(err, ErrInvalidRequestID) {
		t.Errorf("expected ErrInvalidRequestID, got %v", err)
	}
}

func TestRejectEnrollment_NotFound(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	err := svc.RejectEnrollment("nonexistent", "reason")
	if !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("expected ErrRequestNotFound, got %v", err)
	}
}

func TestRejectEnrollment_AlreadyApproved(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	requestID, err := svc.SubmitEnrollmentRequest(testCSR(t))
	if err != nil {
		t.Fatalf("failed to submit request: %v", err)
	}

	if _, _, err := svc.ApproveEnrollment(requestID); err != nil {
		t.Fatalf("failed to approve: %v", err)
	}

	// Request is removed after approval, so rejection should fail.
	err = svc.RejectEnrollment(requestID, "too late")
	if !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("expected ErrRequestNotFound, got %v", err)
	}
}

func TestIsMethodAllowed(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	if !svc.IsMethodAllowed(EnrollOneTimeCode) {
		t.Error("one_time_code should be allowed")
	}
	if !svc.IsMethodAllowed(EnrollAdminApproval) {
		t.Error("admin_approval should be allowed")
	}
	if svc.IsMethodAllowed(EnrollEnterpriseCA) {
		t.Error("enterprise_ca should not be allowed")
	}
	if svc.IsMethodAllowed(EnrollNoiseDirect) {
		t.Error("noise_direct should not be allowed")
	}
}

func TestCleanExpiredCodes(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	// Generate a code that expires immediately.
	_, err := svc.GenerateOneTimeCode(1 * time.Nanosecond)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	// Generate a code that expires later.
	_, err = svc.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	removed, err := svc.CleanExpiredCodes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if removed != 1 {
		t.Errorf("expected 1 removed code, got %d", removed)
	}
}

// twoInstanceEnrollmentServices builds two independent EnrollmentService
// instances, each wrapping its own FileStore Go value (never a shared Go
// object, so no in-process state leaks between them) backed by the same
// on-disk directory - exactly the relationship between "xkey agent start"
// and a separately-invoked "xkey agent code"/"pending"/"approve" process
// sharing the same enrollment store directory. Any state one instance
// observes through the other must have crossed through the store, never
// through memory.
func twoInstanceEnrollmentServices(t *testing.T) (a, b *EnrollmentService) {
	t.Helper()

	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.EnrollmentMethods = []EnrollmentMethod{
		EnrollOneTimeCode,
		EnrollAdminApproval,
	}

	storeA, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("NewFileStore (a): %v", err)
	}
	storeB, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("NewFileStore (b): %v", err)
	}

	svcA, err := NewEnrollmentService(cfg, &mockCAService{}, storeA, testLogger())
	if err != nil {
		t.Fatalf("NewEnrollmentService (a): %v", err)
	}
	svcB, err := NewEnrollmentService(cfg, &mockCAService{}, storeB, testLogger())
	if err != nil {
		t.Fatalf("NewEnrollmentService (b): %v", err)
	}
	return svcA, svcB
}

// TestGenerateOneTimeCode_HonoredBySecondInstance proves the core
// persistence requirement: a code generated through one EnrollmentService
// instance is accepted by a second instance sharing the same store.
func TestGenerateOneTimeCode_HonoredBySecondInstance(t *testing.T) {
	a, b := twoInstanceEnrollmentServices(t)

	code, err := a.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("generate code on instance a: %v", err)
	}

	if _, _, err := b.EnrollWithCode(code.Code, testCSR(t)); err != nil {
		t.Fatalf("a code generated by instance a was not honored by instance b sharing the same store: %v", err)
	}
}

// TestEnrollWithCode_SecondUseAcrossInstancesFails proves single-use is
// enforced through the store, not through either instance's memory.
func TestEnrollWithCode_SecondUseAcrossInstancesFails(t *testing.T) {
	a, b := twoInstanceEnrollmentServices(t)

	code, err := a.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	if _, _, err := b.EnrollWithCode(code.Code, testCSR(t)); err != nil {
		t.Fatalf("first use (instance b) failed: %v", err)
	}

	// The code's originating instance must also see it as consumed.
	_, _, err = a.EnrollWithCode(code.Code, testCSR(t))
	if !errors.Is(err, ErrEnrollmentCodeInvalid) {
		t.Errorf("expected ErrEnrollmentCodeInvalid for a reused code, got %v", err)
	}
}

// TestEnrollWithCode_ExpiredAcrossInstancesFails proves expiry is honored
// through the store: an expired code generated by one instance is
// rejected, not silently accepted, by a second instance.
func TestEnrollWithCode_ExpiredAcrossInstancesFails(t *testing.T) {
	a, b := twoInstanceEnrollmentServices(t)

	code, err := a.GenerateOneTimeCode(1 * time.Nanosecond)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	_, _, err = b.EnrollWithCode(code.Code, testCSR(t))
	if !errors.Is(err, ErrEnrollmentCodeExpired) {
		t.Errorf("expected ErrEnrollmentCodeExpired, got %v", err)
	}
}

// TestEnrollWithCode_ConcurrentUseIsSingleUse proves ConsumeCode's
// atomicity claim under contention: of many concurrent attempts to
// redeem the same code, exactly one succeeds.
func TestEnrollWithCode_ConcurrentUseIsSingleUse(t *testing.T) {
	a, _ := twoInstanceEnrollmentServices(t)

	code, err := a.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	const attempts = 8
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, enrollErr := a.EnrollWithCode(code.Code, testCSR(t))
			results <- enrollErr
		}()
	}
	wg.Wait()
	close(results)

	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrEnrollmentCodeInvalid) {
			t.Errorf("unexpected error from a losing attempt: %v", err)
		}
	}
	if successes != 1 {
		t.Errorf("expected exactly 1 successful enrollment among %d concurrent attempts, got %d", attempts, successes)
	}
}

// TestApproveEnrollment_AcrossInstances proves an admin-approval request
// submitted through one instance can be approved through another sharing
// the same store, and that the approval is visible everywhere afterward.
func TestApproveEnrollment_AcrossInstances(t *testing.T) {
	a, b := twoInstanceEnrollmentServices(t)

	requestID, err := a.SubmitEnrollmentRequest(testCSR(t))
	if err != nil {
		t.Fatalf("submit on instance a: %v", err)
	}

	certPEM, caPEM, err := b.ApproveEnrollment(requestID)
	if err != nil {
		t.Fatalf("approve on instance b failed for a request submitted on instance a: %v", err)
	}
	if len(certPEM) == 0 || len(caPEM) == 0 {
		t.Error("expected certificate material from a cross-instance approval")
	}

	pending, err := a.ListPending()
	if err != nil {
		t.Fatalf("list pending on instance a: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("expected 0 pending requests visible from instance a after instance b approved, got %d", len(pending))
	}
}

// TestRejectEnrollment_AcrossInstances proves rejection is equally
// visible across instances sharing the same store.
func TestRejectEnrollment_AcrossInstances(t *testing.T) {
	a, b := twoInstanceEnrollmentServices(t)

	requestID, err := a.SubmitEnrollmentRequest(testCSR(t))
	if err != nil {
		t.Fatalf("submit on instance a: %v", err)
	}

	if err := b.RejectEnrollment(requestID, "not authorized"); err != nil {
		t.Fatalf("reject on instance b failed for a request submitted on instance a: %v", err)
	}

	pending, err := a.ListPending()
	if err != nil {
		t.Fatalf("list pending on instance a: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("expected 0 pending requests visible from instance a after instance b rejected, got %d", len(pending))
	}

	if _, _, err := a.ApproveEnrollment(requestID); !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("expected the rejected request to be gone from instance a too, got %v", err)
	}
}

func TestListPending_Empty(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	pending, err := svc.ListPending()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("expected empty list, got %d", len(pending))
	}
}

func TestCSRFingerprint_InvalidPEM(t *testing.T) {
	_, err := csrFingerprint([]byte("not pem"))
	if !errors.Is(err, ErrInvalidCSR) {
		t.Errorf("expected ErrInvalidCSR, got %v", err)
	}
}

func TestCSRFingerprint_InvalidCSR(t *testing.T) {
	badPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: []byte("not a real csr"),
	})
	_, err := csrFingerprint(badPEM)
	if !errors.Is(err, ErrInvalidCSR) {
		t.Errorf("expected ErrInvalidCSR, got %v", err)
	}
}

func TestGenerateSecureCode(t *testing.T) {
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		code, err := generateSecureCode(l)
		if err != nil {
			t.Fatalf("failed to generate code of length %d: %v", l, err)
		}
		if len(code) != l {
			t.Errorf("expected length %d, got %d", l, len(code))
		}
	}
}

func TestEnrollWithCode_RecordsCertificateSerial(t *testing.T) {
	svc, store := testEnrollmentServiceWithStore(t)

	code, err := svc.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	_, _, err = svc.EnrollWithCode(code.Code, testCSR(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	agents, err := store.ListAgents()
	if err != nil {
		t.Fatalf("list agents: %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("expected 1 enrolled agent, got %d", len(agents))
	}
	if agents[0].CertificateSerial == "" {
		t.Error("enrolled agent has no recorded certificate serial number")
	}
}

func TestEnrollWithCode_UnparseableCertificate(t *testing.T) {
	svc, ca := testEnrollmentService(t)
	ca.signCSRFunc = func([]byte) ([]byte, error) {
		return []byte("-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n"), nil
	}

	code, err := svc.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	_, _, err = svc.EnrollWithCode(code.Code, testCSR(t))
	if !errors.Is(err, ErrCertificateInvalid) {
		t.Errorf("expected ErrCertificateInvalid, got %v", err)
	}
}

// testEnrollmentServiceWithStore is like testEnrollmentService but also
// returns the backing store so tests can inspect persisted records.
func testEnrollmentServiceWithStore(t *testing.T) (*EnrollmentService, *MemoryStore) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.EnrollmentMethods = []EnrollmentMethod{
		EnrollOneTimeCode,
		EnrollAdminApproval,
	}
	store := NewMemoryStore()
	svc, err := NewEnrollmentService(cfg, &mockCAService{}, store, testLogger())
	if err != nil {
		t.Fatalf("failed to create enrollment service: %v", err)
	}
	return svc, store
}

func TestVerifyAgentCertificate_NilCertificate(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	if err := svc.VerifyAgentCertificate(nil); !errors.Is(err, ErrCertificateInvalid) {
		t.Errorf("expected ErrCertificateInvalid, got %v", err)
	}
}

func TestVerifyAgentCertificate_EnrolledAgentConnects(t *testing.T) {
	svc, store := testEnrollmentServiceWithStore(t)

	code, err := svc.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}
	csrPEM := testCSR(t)
	certPEM, _, err := svc.EnrollWithCode(code.Code, csrPEM)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	agents, err := store.ListAgents()
	if err != nil || len(agents) != 1 {
		t.Fatalf("expected 1 enrolled agent, got %d (err=%v)", len(agents), err)
	}

	leaf := parseTestCertPEM(t, certPEM)
	if err := svc.VerifyAgentCertificate(leaf); err != nil {
		t.Errorf("expected an enrolled agent's certificate to be accepted, got %v", err)
	}
}

func TestVerifyAgentCertificate_RevokedCertificateIsRefused(t *testing.T) {
	svc, ca := testEnrollmentServiceWithCA(t)

	code, err := svc.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}
	csrPEM := testCSR(t)
	certPEM, _, err := svc.EnrollWithCode(code.Code, csrPEM)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	ca.isRevokedFunc = func(string) (bool, error) { return true, nil }

	leaf := parseTestCertPEM(t, certPEM)
	err = svc.VerifyAgentCertificate(leaf)
	if !errors.Is(err, ErrCertificateRevoked) {
		t.Errorf("expected ErrCertificateRevoked, got %v", err)
	}
}

func TestVerifyAgentCertificate_RevocationCheckFailureIsRefused(t *testing.T) {
	svc, ca := testEnrollmentServiceWithCA(t)

	code, err := svc.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}
	csrPEM := testCSR(t)
	certPEM, _, err := svc.EnrollWithCode(code.Code, csrPEM)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	ca.isRevokedFunc = func(string) (bool, error) { return false, errors.New("ocsp responder unreachable") }

	leaf := parseTestCertPEM(t, certPEM)
	err = svc.VerifyAgentCertificate(leaf)
	if !errors.Is(err, ErrRevocationCheckFailed) {
		t.Errorf("expected ErrRevocationCheckFailed (fail closed), got %v", err)
	}
}

func TestVerifyAgentCertificate_RemovedAgentIsRefused(t *testing.T) {
	svc, store := testEnrollmentServiceWithStore(t)

	code, err := svc.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}
	csrPEM := testCSR(t)
	certPEM, _, err := svc.EnrollWithCode(code.Code, csrPEM)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	agents, err := store.ListAgents()
	if err != nil || len(agents) != 1 {
		t.Fatalf("expected 1 enrolled agent, got %d (err=%v)", len(agents), err)
	}
	// Simulate removal without going through RemoveAgent: the store no
	// longer has a record, but the certificate itself was never revoked
	// (e.g. the CA does not know about it, or a revocation check would
	// return false). The connection must still be refused because the
	// store lookup is an independent, mandatory check.
	if err := store.DeleteAgent(agents[0].ID); err != nil {
		t.Fatalf("delete agent: %v", err)
	}

	leaf := parseTestCertPEM(t, certPEM)
	err = svc.VerifyAgentCertificate(leaf)
	if !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("expected ErrAgentNotFound for a removed agent, got %v", err)
	}
}

func TestRemoveAgent_EmptyID(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	if err := svc.RemoveAgent(""); !errors.Is(err, ErrInvalidRequestID) {
		t.Errorf("expected ErrInvalidRequestID, got %v", err)
	}
}

func TestRemoveAgent_NotFound(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	if err := svc.RemoveAgent("nonexistent"); !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("expected ErrAgentNotFound, got %v", err)
	}
}

func TestRemoveAgent_RevokesThenDeletes(t *testing.T) {
	svc, ca := testEnrollmentServiceWithCA(t)
	store := svc.store.(*MemoryStore)

	code, err := svc.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}
	_, _, err = svc.EnrollWithCode(code.Code, testCSR(t))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	agents, _ := store.ListAgents()
	if len(agents) != 1 {
		t.Fatalf("expected 1 enrolled agent, got %d", len(agents))
	}
	id := agents[0].ID
	serial := agents[0].CertificateSerial

	var revokedSerial string
	ca.revokeCertFunc = func(s string) error {
		revokedSerial = s
		return nil
	}

	if err := svc.RemoveAgent(id); err != nil {
		t.Fatalf("RemoveAgent: %v", err)
	}
	if revokedSerial != serial {
		t.Errorf("revoked serial = %q, want %q", revokedSerial, serial)
	}
	if _, err := store.GetAgent(id); !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("expected the agent record to be deleted, got %v", err)
	}
}

func TestRemoveAgent_RevocationFailureKeepsRecord(t *testing.T) {
	svc, ca := testEnrollmentServiceWithCA(t)
	store := svc.store.(*MemoryStore)

	code, err := svc.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}
	_, _, err = svc.EnrollWithCode(code.Code, testCSR(t))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	agents, _ := store.ListAgents()
	if len(agents) != 1 {
		t.Fatalf("expected 1 enrolled agent, got %d", len(agents))
	}
	id := agents[0].ID

	ca.revokeCertFunc = func(string) error { return errors.New("ca unreachable") }

	err = svc.RemoveAgent(id)
	if !errors.Is(err, ErrAgentRevocationFailed) {
		t.Errorf("expected ErrAgentRevocationFailed, got %v", err)
	}
	if _, getErr := store.GetAgent(id); getErr != nil {
		t.Errorf("record was deleted despite the revocation failure: %v", getErr)
	}
}

func TestRemoveAgent_MissingSerialIsRefused(t *testing.T) {
	svc, store := testEnrollmentServiceWithStore(t)
	if err := store.SaveAgent(&AgentInfo{ID: "legacy-agent", Status: "active"}); err != nil {
		t.Fatalf("seed agent: %v", err)
	}

	err := svc.RemoveAgent("legacy-agent")
	if !errors.Is(err, ErrCertificateSerialMissing) {
		t.Errorf("expected ErrCertificateSerialMissing, got %v", err)
	}
	if _, getErr := store.GetAgent("legacy-agent"); getErr != nil {
		t.Errorf("record was deleted despite the missing serial: %v", getErr)
	}
}

// testEnrollmentServiceWithCA is like testEnrollmentService but exposes a
// MemoryStore-backed service for tests that need both the CA mock and
// direct store inspection.
func testEnrollmentServiceWithCA(t *testing.T) (*EnrollmentService, *mockCAService) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.EnrollmentMethods = []EnrollmentMethod{
		EnrollOneTimeCode,
		EnrollAdminApproval,
	}
	ca := &mockCAService{}
	store := NewMemoryStore()
	svc, err := NewEnrollmentService(cfg, ca, store, testLogger())
	if err != nil {
		t.Fatalf("failed to create enrollment service: %v", err)
	}
	return svc, ca
}

// parseTestCertPEM parses the leading PEM-encoded certificate.
func parseTestCertPEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatalf("certificate is not PEM: %q", certPEM)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func TestGenerateSecureCode_Unique(t *testing.T) {
	codes := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		code, err := generateSecureCode(16)
		if err != nil {
			t.Fatalf("failed to generate code: %v", err)
		}
		if _, ok := codes[code]; ok {
			t.Errorf("duplicate code generated: %q", code)
		}
		codes[code] = struct{}{}
	}
}
