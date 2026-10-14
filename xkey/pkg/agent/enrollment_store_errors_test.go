package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fileStoreEnrollmentService returns an EnrollmentService backed by a
// FileStore in a temporary directory, so tests can make individual store
// operations fail by tampering with the store's subdirectories.
func fileStoreEnrollmentService(t *testing.T, ca *mockCAService) (*EnrollmentService, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	cfg := DefaultConfig()
	cfg.EnrollmentMethods = []EnrollmentMethod{EnrollOneTimeCode, EnrollAdminApproval}
	svc, err := NewEnrollmentService(cfg, ca, store, testLogger())
	if err != nil {
		t.Fatalf("NewEnrollmentService: %v", err)
	}
	return svc, dir
}

// blockStoreDir replaces a store subdirectory with a regular file, so every
// read and write under it fails.
func blockStoreDir(t *testing.T, dir, sub string) {
	t.Helper()
	path := filepath.Join(dir, sub)
	if err := os.RemoveAll(path); err != nil {
		t.Fatalf("remove %s: %v", sub, err)
	}
	if err := os.WriteFile(path, []byte("blocker"), 0600); err != nil {
		t.Fatalf("write blocker %s: %v", sub, err)
	}
}

// readOnlyStoreDir makes a store subdirectory readable but not writable,
// so reads succeed while writes and deletes under it fail.
func readOnlyStoreDir(t *testing.T, dir, sub string) {
	t.Helper()
	path := filepath.Join(dir, sub)
	if err := os.Chmod(path, 0500); err != nil {
		t.Fatalf("chmod %s: %v", sub, err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(path, 0700); err != nil {
			t.Errorf("restore %s: %v", sub, err)
		}
	})
}

// wantAgentError fails the test unless err is an *AgentError for operation
// op whose underlying error is want.
func wantAgentError(t *testing.T, err error, op string, want error) {
	t.Helper()
	var agentErr *AgentError
	if !errors.As(err, &agentErr) {
		t.Fatalf("error = %v, want *AgentError", err)
	}
	if agentErr.Operation != op {
		t.Errorf("Operation = %q, want %q", agentErr.Operation, op)
	}
	if !errors.Is(err, want) {
		t.Errorf("error = %v, want %v", err, want)
	}
}

func TestGenerateOneTimeCode_StoreWriteFails(t *testing.T) {
	svc, dir := fileStoreEnrollmentService(t, &mockCAService{})
	blockStoreDir(t, dir, "codes")

	otc, err := svc.GenerateOneTimeCode(0)
	if otc != nil {
		t.Errorf("GenerateOneTimeCode() code = %+v, want nil when the store fails", otc)
	}
	wantAgentError(t, err, "generate_code", ErrStoreWrite)
}

func TestCleanExpiredCodes_StoreReadFails(t *testing.T) {
	svc, dir := fileStoreEnrollmentService(t, &mockCAService{})
	blockStoreDir(t, dir, "codes")

	removed, err := svc.CleanExpiredCodes()
	if removed != 0 {
		t.Errorf("CleanExpiredCodes() removed = %d, want 0", removed)
	}
	wantAgentError(t, err, "clean_expired_codes", ErrStoreRead)
}

func TestSubmitEnrollmentRequest_AgentListFails(t *testing.T) {
	svc, dir := fileStoreEnrollmentService(t, &mockCAService{})
	svc.config.MaxAgents = 1
	blockStoreDir(t, dir, "agents")

	_, err := svc.SubmitEnrollmentRequest(testCSR(t))
	wantAgentError(t, err, "check_max_agents", ErrStoreRead)
}

func TestSubmitEnrollmentRequest_MaxAgentsReached(t *testing.T) {
	svc, _ := fileStoreEnrollmentService(t, &mockCAService{})
	svc.config.MaxAgents = 1
	if err := svc.store.SaveAgent(&AgentInfo{ID: "existing", Status: "active"}); err != nil {
		t.Fatalf("SaveAgent: %v", err)
	}

	_, err := svc.SubmitEnrollmentRequest(testCSR(t))
	if !errors.Is(err, ErrMaxAgentsReached) {
		t.Fatalf("SubmitEnrollmentRequest() error = %v, want ErrMaxAgentsReached", err)
	}
}

func TestSubmitEnrollmentRequest_MalformedCSR(t *testing.T) {
	svc, _ := fileStoreEnrollmentService(t, &mockCAService{})

	_, err := svc.SubmitEnrollmentRequest([]byte("not a pem csr"))
	wantAgentError(t, err, "submit_enrollment", ErrInvalidCSR)

	pending, err := svc.ListPending()
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("ListPending() = %d requests, want none after a rejected CSR", len(pending))
	}
}

func TestSubmitEnrollmentRequest_StoreWriteFails(t *testing.T) {
	svc, dir := fileStoreEnrollmentService(t, &mockCAService{})
	blockStoreDir(t, dir, "pending")

	requestID, err := svc.SubmitEnrollmentRequest(testCSR(t))
	if requestID != "" {
		t.Errorf("SubmitEnrollmentRequest() id = %q, want empty when the store fails", requestID)
	}
	wantAgentError(t, err, "submit_enrollment", ErrStoreWrite)
}

func TestApproveEnrollment_MarkApprovedFails(t *testing.T) {
	signed := false
	ca := &mockCAService{signCSRFunc: func([]byte) ([]byte, error) {
		signed = true
		return nil, errors.New("must not be called")
	}}
	svc, dir := fileStoreEnrollmentService(t, ca)
	requestID, err := svc.SubmitEnrollmentRequest(testCSR(t))
	if err != nil {
		t.Fatalf("SubmitEnrollmentRequest: %v", err)
	}
	readOnlyStoreDir(t, dir, "pending")

	_, _, err = svc.ApproveEnrollment(requestID)
	wantAgentError(t, err, "approve_enrollment", ErrStoreWrite)
	if signed {
		t.Error("CSR was signed although the request could not be marked approved")
	}
}

func TestApproveEnrollment_SignFails(t *testing.T) {
	signErr := errors.New("ca offline")
	ca := &mockCAService{signCSRFunc: func([]byte) ([]byte, error) { return nil, signErr }}
	svc, _ := fileStoreEnrollmentService(t, ca)
	requestID, err := svc.SubmitEnrollmentRequest(testCSR(t))
	if err != nil {
		t.Fatalf("SubmitEnrollmentRequest: %v", err)
	}

	_, _, err = svc.ApproveEnrollment(requestID)
	wantAgentError(t, err, "approve_enrollment", signErr)

	// The request was claimed before signing, so it cannot be approved twice.
	if _, _, err := svc.ApproveEnrollment(requestID); !errors.Is(err, ErrEnrollmentFailed) {
		t.Errorf("second ApproveEnrollment() error = %v, want ErrEnrollmentFailed", err)
	}
}

func TestApproveEnrollment_UnparseableCertificate(t *testing.T) {
	ca := &mockCAService{signCSRFunc: func([]byte) ([]byte, error) { return []byte("not a certificate"), nil }}
	svc, _ := fileStoreEnrollmentService(t, ca)
	requestID, err := svc.SubmitEnrollmentRequest(testCSR(t))
	if err != nil {
		t.Fatalf("SubmitEnrollmentRequest: %v", err)
	}

	certPEM, _, err := svc.ApproveEnrollment(requestID)
	if certPEM != nil {
		t.Error("ApproveEnrollment() returned a certificate whose serial could not be recorded")
	}
	wantAgentError(t, err, "approve_enrollment", ErrCertificateInvalid)
}

func TestApproveEnrollment_CACertificateFails(t *testing.T) {
	caErr := errors.New("ca certificate unavailable")
	ca := &mockCAService{getCACertFunc: func() ([]byte, error) { return nil, caErr }}
	svc, _ := fileStoreEnrollmentService(t, ca)
	requestID, err := svc.SubmitEnrollmentRequest(testCSR(t))
	if err != nil {
		t.Fatalf("SubmitEnrollmentRequest: %v", err)
	}

	_, _, err = svc.ApproveEnrollment(requestID)
	wantAgentError(t, err, "approve_enrollment", caErr)

	agents, err := svc.store.ListAgents()
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) != 0 {
		t.Errorf("ListAgents() = %d agents, want none when approval failed", len(agents))
	}
}

func TestApproveEnrollment_AgentRecordFailureStillIssues(t *testing.T) {
	svc, dir := fileStoreEnrollmentService(t, &mockCAService{})
	requestID, err := svc.SubmitEnrollmentRequest(testCSR(t))
	if err != nil {
		t.Fatalf("SubmitEnrollmentRequest: %v", err)
	}
	// The agent record cannot be written: the failure is logged and the
	// certificate the CA already issued is still returned.
	blockStoreDir(t, dir, "agents")

	certPEM, caPEM, err := svc.ApproveEnrollment(requestID)
	if err != nil {
		t.Fatalf("ApproveEnrollment() error = %v, want nil", err)
	}
	if len(certPEM) == 0 || len(caPEM) == 0 {
		t.Fatal("ApproveEnrollment() returned empty certificate material")
	}
	if _, err := svc.store.GetPending(requestID); err == nil {
		t.Error("approved request is still pending")
	}
}

func TestRejectEnrollment_DeleteFails(t *testing.T) {
	svc, dir := fileStoreEnrollmentService(t, &mockCAService{})
	requestID, err := svc.SubmitEnrollmentRequest(testCSR(t))
	if err != nil {
		t.Fatalf("SubmitEnrollmentRequest: %v", err)
	}
	readOnlyStoreDir(t, dir, "pending")

	err = svc.RejectEnrollment(requestID, "unknown host")
	wantAgentError(t, err, "reject_enrollment", ErrStoreDelete)
}
