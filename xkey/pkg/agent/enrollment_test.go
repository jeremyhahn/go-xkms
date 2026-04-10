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
	"testing"
	"time"
)

// mockCAService implements CAService for testing.
type mockCAService struct {
	signCSRFunc    func(csrPEM []byte) ([]byte, error)
	getCACertFunc  func() ([]byte, error)
	revokeCertFunc func(serialNumber string) error
}

func (m *mockCAService) SignCSR(csrPEM []byte) ([]byte, error) {
	if m.signCSRFunc != nil {
		return m.signCSRFunc(csrPEM)
	}
	// Return a fake cert PEM.
	return []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"), nil
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

	_, _, err = svc.ApproveEnrollment(requestID)
	if !errors.Is(err, ErrEnrollmentRejected) {
		t.Errorf("expected ErrEnrollmentRejected, got %v", err)
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

	removed := svc.CleanExpiredCodes()
	if removed != 1 {
		t.Errorf("expected 1 removed code, got %d", removed)
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
