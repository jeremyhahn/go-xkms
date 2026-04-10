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

package grpc

import (
	"context"
	"errors"
	"sync"
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/authz"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockAuthorizer is a test authorizer that returns configurable decisions.
type mockAuthorizer struct {
	decision *authz.AuthorizationDecision
	err      error

	mu          sync.Mutex
	lastRequest *authz.AuthorizationRequest
}

func (m *mockAuthorizer) Authorize(_ context.Context, req *authz.AuthorizationRequest) (*authz.AuthorizationDecision, error) {
	m.mu.Lock()
	m.lastRequest = req
	m.mu.Unlock()
	return m.decision, m.err
}

func (m *mockAuthorizer) LastRequest() *authz.AuthorizationRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastRequest
}

// mockAuditLogger records audit events for verification.
type mockAuditLogger struct {
	mu     sync.Mutex
	events []*audit.Event
}

func (m *mockAuditLogger) Log(_ context.Context, event *audit.Event) error {
	m.mu.Lock()
	m.events = append(m.events, event)
	m.mu.Unlock()
	return nil
}

func (m *mockAuditLogger) Close() error {
	return nil
}

func (m *mockAuditLogger) Events() []*audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]*audit.Event, len(m.events))
	copy(cp, m.events)
	return cp
}

func (m *mockAuditLogger) LastEvent() *audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.events) == 0 {
		return nil
	}
	return m.events[len(m.events)-1]
}

// setupAuthzServiceTest initializes the xkms and returns a service with
// the given authorizer and audit logger.
func setupAuthzServiceTest(t *testing.T, authorizer authz.Authorizer, auditLogger audit.Logger) *Service {
	t.Helper()
	xkms.Reset()

	keyStorage := storage.New()
	certStorage := storage.New()

	backend, err := software.NewBackend(&software.Config{
		KeyStorage: keyStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	ks, err := xkms.New(&xkms.BackendConfig{
		Backend:     backend,
		CertStorage: certStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	err = xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"software": ks,
		},
		DefaultBackend: "software",
	})
	if err != nil {
		t.Fatalf("Failed to initialize xkms: %v", err)
	}

	return NewService(authorizer, auditLogger)
}

// --- authorize helper tests ---

func TestAuthz_AuthorizeAllowed(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true, Reason: "test-allow"},
	}
	auditLog := &mockAuditLogger{}
	svc := setupAuthzServiceTest(t, authorizer, auditLog)

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "user-1",
		Claims:  map[string]interface{}{"roles": "admin"},
	})

	err := svc.authorize(ctx, "keys", "read", "test-key")
	if err != nil {
		t.Fatalf("Expected nil error, got: %v", err)
	}

	// Verify the authorization request was correct
	req := authorizer.LastRequest()
	if req == nil {
		t.Fatal("Expected authorization request, got nil")
	}
	if req.Subject != "user-1" {
		t.Errorf("Expected subject 'user-1', got '%s'", req.Subject)
	}
	if req.Role != "admin" {
		t.Errorf("Expected role 'admin', got '%s'", req.Role)
	}
	if req.Resource != "keys" {
		t.Errorf("Expected resource 'keys', got '%s'", req.Resource)
	}
	if req.Action != "read" {
		t.Errorf("Expected action 'read', got '%s'", req.Action)
	}
	if req.Context["resource_id"] != "test-key" {
		t.Errorf("Expected resource_id 'test-key', got '%s'", req.Context["resource_id"])
	}

	// Verify audit log
	event := auditLog.LastEvent()
	if event == nil {
		t.Fatal("Expected audit event, got nil")
	}
	if event.Outcome != audit.OutcomeAllow {
		t.Errorf("Expected outcome 'allow', got '%s'", event.Outcome)
	}
	if event.Subject != "user-1" {
		t.Errorf("Expected audit subject 'user-1', got '%s'", event.Subject)
	}
	if event.Resource != "keys" {
		t.Errorf("Expected audit resource 'keys', got '%s'", event.Resource)
	}
	if event.ResourceID != "test-key" {
		t.Errorf("Expected audit resource_id 'test-key', got '%s'", event.ResourceID)
	}
}

func TestAuthz_AuthorizeDenied(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: false, Reason: "insufficient privileges"},
	}
	auditLog := &mockAuditLogger{}
	svc := setupAuthzServiceTest(t, authorizer, auditLog)

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "user-2",
		Claims:  map[string]interface{}{"roles": "reader"},
	})

	err := svc.authorize(ctx, "keys", "write", "my-key")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.PermissionDenied {
		t.Errorf("Expected PermissionDenied, got %s", st.Code())
	}
	if st.Message() != "insufficient privileges" {
		t.Errorf("Expected 'insufficient privileges', got '%s'", st.Message())
	}

	// Verify audit log records deny
	event := auditLog.LastEvent()
	if event == nil {
		t.Fatal("Expected audit event, got nil")
	}
	if event.Outcome != audit.OutcomeDeny {
		t.Errorf("Expected outcome 'deny', got '%s'", event.Outcome)
	}
}

func TestAuthz_AuthorizeDeniedDefaultReason(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: false, Reason: ""},
	}
	auditLog := &mockAuditLogger{}
	svc := setupAuthzServiceTest(t, authorizer, auditLog)

	err := svc.authorize(context.Background(), "keys", "read", "")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.PermissionDenied {
		t.Errorf("Expected PermissionDenied, got %s", st.Code())
	}
	if st.Message() != ErrAccessDenied.Error() {
		t.Errorf("Expected default access denied message, got '%s'", st.Message())
	}
}

func TestAuthz_AuthorizeError(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		err: errors.New("policy engine unavailable"),
	}
	auditLog := &mockAuditLogger{}
	svc := setupAuthzServiceTest(t, authorizer, auditLog)

	err := svc.authorize(context.Background(), "keys", "read", "my-key")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal, got %s", st.Code())
	}
	if st.Message() != ErrAuthorizationFailed.Error() {
		t.Errorf("Expected '%s', got '%s'", ErrAuthorizationFailed.Error(), st.Message())
	}

	// Verify audit log records deny on error
	event := auditLog.LastEvent()
	if event == nil {
		t.Fatal("Expected audit event, got nil")
	}
	if event.Outcome != audit.OutcomeDeny {
		t.Errorf("Expected outcome 'deny', got '%s'", event.Outcome)
	}
}

func TestAuthz_AuthorizeNilIdentity(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true},
	}
	auditLog := &mockAuditLogger{}
	svc := setupAuthzServiceTest(t, authorizer, auditLog)

	// Context without identity
	err := svc.authorize(context.Background(), "backends", "read", "")
	if err != nil {
		t.Fatalf("Expected nil error, got: %v", err)
	}

	req := authorizer.LastRequest()
	if req.Subject != "" {
		t.Errorf("Expected empty subject for nil identity, got '%s'", req.Subject)
	}
	if req.Role != "" {
		t.Errorf("Expected empty role for nil identity, got '%s'", req.Role)
	}

	event := auditLog.LastEvent()
	if event.Subject != "" {
		t.Errorf("Expected empty audit subject, got '%s'", event.Subject)
	}
}

// --- extractRoleFromIdentity tests ---

func TestAuthz_ExtractRoleStringSlice(t *testing.T) {
	identity := &auth.Identity{
		Claims: map[string]interface{}{
			"roles": []string{"admin", "operator"},
		},
	}
	role := extractRoleFromIdentity(identity)
	if role != "admin" {
		t.Errorf("Expected 'admin', got '%s'", role)
	}
}

func TestAuthz_ExtractRoleInterfaceSlice(t *testing.T) {
	identity := &auth.Identity{
		Claims: map[string]interface{}{
			"roles": []interface{}{"viewer", "editor"},
		},
	}
	role := extractRoleFromIdentity(identity)
	if role != "viewer" {
		t.Errorf("Expected 'viewer', got '%s'", role)
	}
}

func TestAuthz_ExtractRoleString(t *testing.T) {
	identity := &auth.Identity{
		Claims: map[string]interface{}{
			"roles": "superadmin",
		},
	}
	role := extractRoleFromIdentity(identity)
	if role != "superadmin" {
		t.Errorf("Expected 'superadmin', got '%s'", role)
	}
}

func TestAuthz_ExtractRoleNilIdentity(t *testing.T) {
	role := extractRoleFromIdentity(nil)
	if role != "" {
		t.Errorf("Expected empty string, got '%s'", role)
	}
}

func TestAuthz_ExtractRoleNilClaims(t *testing.T) {
	identity := &auth.Identity{}
	role := extractRoleFromIdentity(identity)
	if role != "" {
		t.Errorf("Expected empty string, got '%s'", role)
	}
}

func TestAuthz_ExtractRoleNoRolesClaim(t *testing.T) {
	identity := &auth.Identity{
		Claims: map[string]interface{}{
			"permissions": "read",
		},
	}
	role := extractRoleFromIdentity(identity)
	if role != "" {
		t.Errorf("Expected empty string, got '%s'", role)
	}
}

func TestAuthz_ExtractRoleEmptySlice(t *testing.T) {
	identity := &auth.Identity{
		Claims: map[string]interface{}{
			"roles": []string{},
		},
	}
	role := extractRoleFromIdentity(identity)
	if role != "" {
		t.Errorf("Expected empty string, got '%s'", role)
	}
}

func TestAuthz_ExtractRoleInterfaceSliceNonString(t *testing.T) {
	identity := &auth.Identity{
		Claims: map[string]interface{}{
			"roles": []interface{}{42},
		},
	}
	role := extractRoleFromIdentity(identity)
	if role != "" {
		t.Errorf("Expected empty string for non-string interface element, got '%s'", role)
	}
}

// --- NewService defaults tests ---

func TestAuthz_NewServiceNilDefaults(t *testing.T) {
	svc := NewService(nil, nil)
	if svc == nil {
		t.Fatal("Expected non-nil service")
	}
	if svc.authorizer == nil {
		t.Fatal("Expected non-nil authorizer (NoOp default)")
	}
	if svc.auditLogger == nil {
		t.Fatal("Expected non-nil auditLogger (NoOp default)")
	}

	// Verify NoOp authorizer always allows
	decision, err := svc.authorizer.Authorize(context.Background(), &authz.AuthorizationRequest{})
	if err != nil {
		t.Fatalf("NoOp authorizer should not error: %v", err)
	}
	if !decision.Allowed {
		t.Error("NoOp authorizer should always allow")
	}
}

func TestAuthz_NewServiceCustomAuthorizer(t *testing.T) {
	customAuthz := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: false, Reason: "custom"},
	}
	customAudit := &mockAuditLogger{}

	svc := NewService(customAuthz, customAudit)
	if svc.authorizer != customAuthz {
		t.Error("Expected custom authorizer to be set")
	}
	if svc.auditLogger != customAudit {
		t.Error("Expected custom audit logger to be set")
	}
}

// --- Resource/action mapping tests ---

// authzMapping defines the expected authorization resource and action for a method.
type authzMapping struct {
	resource   string
	action     string
	resourceID string
}

func TestAuthz_ListBackendsMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true},
	}
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	_, _ = svc.ListBackends(context.Background(), &pb.ListBackendsRequest{})

	req := authorizer.LastRequest()
	if req == nil {
		t.Fatal("Expected authorization request")
	}
	assertMapping(t, req, authzMapping{resource: "backends", action: "read", resourceID: ""})
}

func TestAuthz_GetBackendInfoMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true},
	}
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	_, _ = svc.GetBackendInfo(context.Background(), &pb.GetBackendInfoRequest{Name: "software"})

	req := authorizer.LastRequest()
	if req == nil {
		t.Fatal("Expected authorization request")
	}
	assertMapping(t, req, authzMapping{resource: "backends", action: "read", resourceID: "software"})
}

func TestAuthz_GenerateKeyMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true},
	}
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	_, _ = svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "gen-key-1",
		Backend: "software",
		KeyType: "ecdsa",
	})

	req := authorizer.LastRequest()
	if req == nil {
		t.Fatal("Expected authorization request")
	}
	assertMapping(t, req, authzMapping{resource: "keys", action: "write", resourceID: "gen-key-1"})
}

func TestAuthz_ListKeysMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true},
	}
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	_, _ = svc.ListKeys(context.Background(), &pb.ListKeysRequest{Backend: "software"})

	req := authorizer.LastRequest()
	if req == nil {
		t.Fatal("Expected authorization request")
	}
	assertMapping(t, req, authzMapping{resource: "keys", action: "read", resourceID: ""})
}

func TestAuthz_SignMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true},
	}
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	_, _ = svc.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "sign-key",
		Backend: "software",
	})

	req := authorizer.LastRequest()
	if req == nil {
		t.Fatal("Expected authorization request")
	}
	assertMapping(t, req, authzMapping{resource: "keys", action: "use", resourceID: "sign-key"})
}

func TestAuthz_DeleteKeyMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true},
	}
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	_, _ = svc.DeleteKey(context.Background(), &pb.DeleteKeyRequest{
		KeyId:   "del-key",
		Backend: "software",
	})

	req := authorizer.LastRequest()
	if req == nil {
		t.Fatal("Expected authorization request")
	}
	assertMapping(t, req, authzMapping{resource: "keys", action: "delete", resourceID: "del-key"})
}

func TestAuthz_SealMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true},
	}
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	_, _ = svc.Seal(context.Background(), &pb.SealRequest{
		Backend: "software",
		Data:    []byte("test"),
	})

	req := authorizer.LastRequest()
	if req == nil {
		t.Fatal("Expected authorization request")
	}
	assertMapping(t, req, authzMapping{resource: "seal", action: "use", resourceID: ""})
}

func TestAuthz_CanSealMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true},
	}
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	_, _ = svc.CanSeal(context.Background(), &pb.CanSealRequest{})

	req := authorizer.LastRequest()
	if req == nil {
		t.Fatal("Expected authorization request")
	}
	assertMapping(t, req, authzMapping{resource: "seal", action: "read", resourceID: ""})
}

func TestAuthz_ListCertsMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true},
	}
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	_, _ = svc.ListCerts(context.Background(), &pb.ListCertsRequest{})

	req := authorizer.LastRequest()
	if req == nil {
		t.Fatal("Expected authorization request")
	}
	assertMapping(t, req, authzMapping{resource: "certs", action: "read", resourceID: ""})
}

func TestAuthz_DeleteCertMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true},
	}
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	_, _ = svc.DeleteCert(context.Background(), &pb.DeleteCertRequest{
		KeyId: "cert-to-delete",
	})

	req := authorizer.LastRequest()
	if req == nil {
		t.Fatal("Expected authorization request")
	}
	assertMapping(t, req, authzMapping{resource: "certs", action: "delete", resourceID: "cert-to-delete"})
}

// --- Deny propagation tests ---

func TestAuthz_ListBackendsDenied(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: false, Reason: "denied"},
	}
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	_, err := svc.ListBackends(context.Background(), &pb.ListBackendsRequest{})
	if err == nil {
		t.Fatal("Expected error on denied authorization")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("Expected PermissionDenied, got %s", st.Code())
	}
}

func TestAuthz_GenerateKeyDenied(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: false, Reason: "no write access"},
	}
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "denied-key",
		Backend: "software",
		KeyType: "ecdsa",
	})
	if err == nil {
		t.Fatal("Expected error on denied authorization")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("Expected PermissionDenied, got %s", st.Code())
	}
	if st.Message() != "no write access" {
		t.Errorf("Expected reason 'no write access', got '%s'", st.Message())
	}
}

func TestAuthz_SignDenied(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: false, Reason: "use denied"},
	}
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	_, err := svc.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "sign-key",
		Backend: "software",
	})
	if err == nil {
		t.Fatal("Expected error on denied authorization")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("Expected PermissionDenied, got %s", st.Code())
	}
}

func TestAuthz_DeleteKeyDenied(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: false, Reason: "delete denied"},
	}
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	_, err := svc.DeleteKey(context.Background(), &pb.DeleteKeyRequest{
		KeyId:   "del-key",
		Backend: "software",
	})
	if err == nil {
		t.Fatal("Expected error on denied authorization")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("Expected PermissionDenied, got %s", st.Code())
	}
}

// --- Health endpoint has no authz ---

func TestAuthz_HealthNoAuthzCheck(t *testing.T) {
	defer xkms.Reset()

	// Use a denying authorizer to prove Health is not checked
	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: false, Reason: "deny all"},
	}
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	resp, err := svc.Health(context.Background(), &pb.HealthRequest{})
	if err != nil {
		t.Fatalf("Health should not be subject to authz: %v", err)
	}
	if resp.Status != "healthy" {
		t.Errorf("Expected status 'healthy', got '%s'", resp.Status)
	}

	// Verify no authorization request was made
	if authorizer.LastRequest() != nil {
		t.Error("Health endpoint should not trigger authorization")
	}
}

// --- Audit logging on allow and deny ---

func TestAuthz_AuditLogOnAllow(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true},
	}
	auditLog := &mockAuditLogger{}
	svc := setupAuthzServiceTest(t, authorizer, auditLog)

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "audited-user",
		Claims:  map[string]interface{}{"roles": "operator"},
	})

	_, _ = svc.ListBackends(ctx, &pb.ListBackendsRequest{})

	events := auditLog.Events()
	if len(events) == 0 {
		t.Fatal("Expected at least one audit event")
	}

	event := events[0]
	if event.Outcome != audit.OutcomeAllow {
		t.Errorf("Expected outcome 'allow', got '%s'", event.Outcome)
	}
	if event.Subject != "audited-user" {
		t.Errorf("Expected subject 'audited-user', got '%s'", event.Subject)
	}
	if event.Action != "read" {
		t.Errorf("Expected action 'read', got '%s'", event.Action)
	}
	if event.Resource != "backends" {
		t.Errorf("Expected resource 'backends', got '%s'", event.Resource)
	}
	if event.Details["transport"] != "grpc" {
		t.Errorf("Expected transport 'grpc', got '%s'", event.Details["transport"])
	}
	if event.Details["role"] != "operator" {
		t.Errorf("Expected role 'operator', got '%s'", event.Details["role"])
	}
}

func TestAuthz_AuditLogOnDeny(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: false, Reason: "denied"},
	}
	auditLog := &mockAuditLogger{}
	svc := setupAuthzServiceTest(t, authorizer, auditLog)

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "denied-user",
		Claims:  map[string]interface{}{"roles": []string{"guest"}},
	})

	_, _ = svc.GenerateKey(ctx, &pb.GenerateKeyRequest{
		KeyId:   "denied-key",
		Backend: "software",
		KeyType: "ecdsa",
	})

	events := auditLog.Events()
	if len(events) == 0 {
		t.Fatal("Expected at least one audit event")
	}

	event := events[0]
	if event.Outcome != audit.OutcomeDeny {
		t.Errorf("Expected outcome 'deny', got '%s'", event.Outcome)
	}
	if event.Subject != "denied-user" {
		t.Errorf("Expected subject 'denied-user', got '%s'", event.Subject)
	}
	if event.Details["role"] != "guest" {
		t.Errorf("Expected role 'guest', got '%s'", event.Details["role"])
	}
}

// --- Authorizer error propagation ---

func TestAuthz_AuthorizerErrorReturnsInternal(t *testing.T) {
	defer xkms.Reset()

	authorizer := &mockAuthorizer{
		err: errors.New("policy engine timeout"),
	}
	auditLog := &mockAuditLogger{}
	svc := setupAuthzServiceTest(t, authorizer, auditLog)

	_, err := svc.ListKeys(context.Background(), &pb.ListKeysRequest{Backend: "software"})
	if err == nil {
		t.Fatal("Expected error on authorizer failure")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal, got %s", st.Code())
	}

	// Verify audit log still records on error
	event := auditLog.LastEvent()
	if event == nil {
		t.Fatal("Expected audit event even on authorizer error")
	}
	if event.Outcome != audit.OutcomeDeny {
		t.Errorf("Expected outcome 'deny' on error, got '%s'", event.Outcome)
	}
}

// --- Validation still happens before authz ---

func TestAuthz_ValidationBeforeAuthz(t *testing.T) {
	defer xkms.Reset()

	// Create a denying authorizer to ensure authz is not reached
	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: false, Reason: "should not reach"},
	}
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	// Call with invalid arguments (missing required fields)
	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		// Missing KeyId, Backend, KeyType
	})
	if err == nil {
		t.Fatal("Expected validation error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument (validation first), got %s", st.Code())
	}

	// Authorizer should not have been called
	if authorizer.LastRequest() != nil {
		t.Error("Authorizer should not be called when validation fails")
	}
}

// assertMapping verifies the authorization request matches the expected mapping.
func assertMapping(t *testing.T, req *authz.AuthorizationRequest, expected authzMapping) {
	t.Helper()
	if req.Resource != expected.resource {
		t.Errorf("Expected resource '%s', got '%s'", expected.resource, req.Resource)
	}
	if req.Action != expected.action {
		t.Errorf("Expected action '%s', got '%s'", expected.action, req.Action)
	}
	if req.Context["resource_id"] != expected.resourceID {
		t.Errorf("Expected resource_id '%s', got '%s'", expected.resourceID, req.Context["resource_id"])
	}
}
