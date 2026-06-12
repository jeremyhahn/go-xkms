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

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeRBACClient is a configurable stand-in for the qrdb RBAC client. It
// records the last Authorize call and returns a fixed error (nil = allow).
type fakeRBACClient struct {
	err error

	mu       sync.Mutex
	lastID   *qrdbtransport.Identity
	lastRes  string
	lastAct  string
	lastSeen bool
}

func (f *fakeRBACClient) Authorize(_ context.Context, id *qrdbtransport.Identity, resource, action string) error {
	f.mu.Lock()
	f.lastID = id
	f.lastRes = resource
	f.lastAct = action
	f.lastSeen = true
	f.mu.Unlock()
	return f.err
}

func (f *fakeRBACClient) ListPermissions(_ context.Context, _ *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, nil
}

func (f *fakeRBACClient) Last() (id *qrdbtransport.Identity, resource, action string, seen bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastID, f.lastRes, f.lastAct, f.lastSeen
}

// allowAuthorizer returns an enabled Authorizer that admits every request.
func allowAuthorizer() (*auth.Authorizer, *fakeRBACClient) {
	c := &fakeRBACClient{err: nil}
	return auth.NewAuthorizer(c), c
}

// denyAuthorizer returns an enabled Authorizer that denies every request with
// the given reason.
func denyAuthorizer(reason string) (*auth.Authorizer, *fakeRBACClient) {
	c := &fakeRBACClient{err: errors.New(reason)}
	return auth.NewAuthorizer(c), c
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
func setupAuthzServiceTest(t *testing.T, authorizer *auth.Authorizer, auditLogger audit.Logger) *Service {
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

	return NewService(authorizer, auditLogger, nil)
}

// --- authorize helper tests ---

func TestAuthz_AuthorizeAllowed(t *testing.T) {
	defer xkms.Reset()

	authorizer, rbac := allowAuthorizer()
	auditLog := &mockAuditLogger{}
	svc := setupAuthzServiceTest(t, authorizer, auditLog)

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "user-1",
		Roles:   []string{"admin"},
	})

	err := svc.authorize(ctx, "keys", "get", "test-key")
	if err != nil {
		t.Fatalf("Expected nil error, got: %v", err)
	}

	// Verify the identity / resource / action threaded to the RBAC client.
	id, resource, action, seen := rbac.Last()
	if !seen {
		t.Fatal("Expected RBAC Authorize to be called")
	}
	if id == nil || id.Subject != "user-1" {
		t.Errorf("Expected subject 'user-1', got '%+v'", id)
	}
	if resource != "keys" {
		t.Errorf("Expected resource 'keys', got '%s'", resource)
	}
	if action != "get" {
		t.Errorf("Expected action 'get', got '%s'", action)
	}

	// Verify audit log.
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
	if event.Details["role"] != "admin" {
		t.Errorf("Expected audit role 'admin', got '%s'", event.Details["role"])
	}
}

func TestAuthz_AuthorizeDenied(t *testing.T) {
	defer xkms.Reset()

	authorizer, _ := denyAuthorizer("insufficient privileges")
	auditLog := &mockAuditLogger{}
	svc := setupAuthzServiceTest(t, authorizer, auditLog)

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "user-2",
		Roles:   []string{"reader"},
	})

	err := svc.authorize(ctx, "keys", "create", "my-key")
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

	// Verify audit log records deny.
	event := auditLog.LastEvent()
	if event == nil {
		t.Fatal("Expected audit event, got nil")
	}
	if event.Outcome != audit.OutcomeDeny {
		t.Errorf("Expected outcome 'deny', got '%s'", event.Outcome)
	}
}

func TestAuthz_AuthorizeUnauthenticated(t *testing.T) {
	defer xkms.Reset()

	// Enabled authorizer with no identity on the context returns
	// ErrUnauthenticated, which the helper maps to codes.Unauthenticated.
	authorizer, _ := allowAuthorizer()
	auditLog := &mockAuditLogger{}
	svc := setupAuthzServiceTest(t, authorizer, auditLog)

	err := svc.authorize(context.Background(), "keys", "get", "")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected Unauthenticated, got %s", st.Code())
	}

	// Verify audit log records deny on missing identity.
	event := auditLog.LastEvent()
	if event == nil {
		t.Fatal("Expected audit event, got nil")
	}
	if event.Outcome != audit.OutcomeDeny {
		t.Errorf("Expected outcome 'deny', got '%s'", event.Outcome)
	}
}

func TestAuthz_AuthorizeDisabledAllowsAll(t *testing.T) {
	defer xkms.Reset()

	// A nil RBAC client disables authorization (allow all), even without an
	// identity on the context.
	authorizer := auth.NewAuthorizer(nil)
	auditLog := &mockAuditLogger{}
	svc := setupAuthzServiceTest(t, authorizer, auditLog)

	if err := svc.authorize(context.Background(), "backends", "list", ""); err != nil {
		t.Fatalf("Expected nil error when authorization disabled, got: %v", err)
	}

	event := auditLog.LastEvent()
	if event == nil {
		t.Fatal("Expected audit event, got nil")
	}
	if event.Outcome != audit.OutcomeAllow {
		t.Errorf("Expected outcome 'allow', got '%s'", event.Outcome)
	}
}

// --- extractRoleFromIdentity tests ---

func TestAuthz_ExtractRoleFirstOfMany(t *testing.T) {
	identity := &auth.Identity{
		Roles: []string{"admin", "operator"},
	}
	role := extractRoleFromIdentity(identity)
	if role != "admin" {
		t.Errorf("Expected 'admin', got '%s'", role)
	}
}

func TestAuthz_ExtractRoleSingle(t *testing.T) {
	identity := &auth.Identity{Roles: []string{"platform-admin"}}
	role := extractRoleFromIdentity(identity)
	if role != "platform-admin" {
		t.Errorf("Expected 'platform-admin', got '%s'", role)
	}
}

func TestAuthz_ExtractRoleNilIdentity(t *testing.T) {
	role := extractRoleFromIdentity(nil)
	if role != "" {
		t.Errorf("Expected empty string, got '%s'", role)
	}
}

func TestAuthz_ExtractRoleNoRoles(t *testing.T) {
	identity := &auth.Identity{}
	role := extractRoleFromIdentity(identity)
	if role != "" {
		t.Errorf("Expected empty string, got '%s'", role)
	}
}

func TestAuthz_ExtractRoleEmptySlice(t *testing.T) {
	identity := &auth.Identity{Roles: []string{}}
	role := extractRoleFromIdentity(identity)
	if role != "" {
		t.Errorf("Expected empty string, got '%s'", role)
	}
}

// --- NewService defaults tests ---

func TestAuthz_NewServiceNilDefaults(t *testing.T) {
	svc := NewService(nil, nil, nil)
	if svc == nil {
		t.Fatal("Expected non-nil service")
	}
	if svc.authorizer == nil {
		t.Fatal("Expected non-nil authorizer (disabled default)")
	}
	if svc.auditLogger == nil {
		t.Fatal("Expected non-nil auditLogger (NoOp default)")
	}

	// The default authorizer is disabled (allow-all) since no RBAC client is
	// wired; Enabled() must report false and Authorize must permit.
	if svc.authorizer.Enabled() {
		t.Error("Expected default authorizer to be disabled (allow-all)")
	}
	if err := svc.authorizer.Authorize(context.Background(), nil, "keys", "get"); err != nil {
		t.Fatalf("Disabled authorizer should not error: %v", err)
	}
}

func TestAuthz_NewServiceCustomAuthorizer(t *testing.T) {
	customAuthz := auth.NewAuthorizer(&fakeRBACClient{})
	customAudit := &mockAuditLogger{}

	svc := NewService(customAuthz, customAudit, nil)
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
	resource string
	action   string
}

func TestAuthz_ListBackendsMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer, rbac := allowAuthorizer()
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "u"})
	_, _ = svc.ListBackends(ctx, &pb.ListBackendsRequest{})

	assertMapping(t, rbac, authzMapping{resource: "backends", action: "list"})
}

func TestAuthz_GetBackendInfoMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer, rbac := allowAuthorizer()
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "u"})
	_, _ = svc.GetBackendInfo(ctx, &pb.GetBackendInfoRequest{Name: "software"})

	assertMapping(t, rbac, authzMapping{resource: "backends", action: "read"})
}

func TestAuthz_GenerateKeyMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer, rbac := allowAuthorizer()
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "u"})
	_, _ = svc.GenerateKey(ctx, &pb.GenerateKeyRequest{
		KeyId:   "gen-key-1",
		Backend: "software",
		KeyType: "ecdsa",
	})

	assertMapping(t, rbac, authzMapping{resource: "keys", action: "create"})
}

func TestAuthz_ListKeysMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer, rbac := allowAuthorizer()
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "u"})
	_, _ = svc.ListKeys(ctx, &pb.ListKeysRequest{Backend: "software"})

	assertMapping(t, rbac, authzMapping{resource: "keys", action: "list"})
}

func TestAuthz_SignMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer, rbac := allowAuthorizer()
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "u"})
	_, _ = svc.Sign(ctx, &pb.SignRequest{
		KeyId:   "sign-key",
		Backend: "software",
	})

	assertMapping(t, rbac, authzMapping{resource: "keys", action: "sign"})
}

func TestAuthz_DeleteKeyMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer, rbac := allowAuthorizer()
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "u"})
	_, _ = svc.DeleteKey(ctx, &pb.DeleteKeyRequest{
		KeyId:   "del-key",
		Backend: "software",
	})

	assertMapping(t, rbac, authzMapping{resource: "keys", action: "delete"})
}

func TestAuthz_SealMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer, rbac := allowAuthorizer()
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "u"})
	_, _ = svc.Seal(ctx, &pb.SealRequest{
		Backend: "software",
		Data:    []byte("test"),
	})

	assertMapping(t, rbac, authzMapping{resource: "keys", action: "encrypt"})
}

func TestAuthz_CanSealMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer, rbac := allowAuthorizer()
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "u"})
	_, _ = svc.CanSeal(ctx, &pb.CanSealRequest{})

	assertMapping(t, rbac, authzMapping{resource: "keys", action: "get"})
}

func TestAuthz_ListCertsMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer, rbac := allowAuthorizer()
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "u"})
	_, _ = svc.ListCerts(ctx, &pb.ListCertsRequest{})

	assertMapping(t, rbac, authzMapping{resource: "certs", action: "list"})
}

func TestAuthz_DeleteCertMapping(t *testing.T) {
	defer xkms.Reset()

	authorizer, rbac := allowAuthorizer()
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "u"})
	_, _ = svc.DeleteCert(ctx, &pb.DeleteCertRequest{
		KeyId: "cert-to-delete",
	})

	assertMapping(t, rbac, authzMapping{resource: "certs", action: "revoke"})
}

// --- Deny propagation tests ---

func TestAuthz_ListBackendsDenied(t *testing.T) {
	defer xkms.Reset()

	authorizer, _ := denyAuthorizer("denied")
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "u"})
	_, err := svc.ListBackends(ctx, &pb.ListBackendsRequest{})
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

	authorizer, _ := denyAuthorizer("no write access")
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "u"})
	_, err := svc.GenerateKey(ctx, &pb.GenerateKeyRequest{
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

	authorizer, _ := denyAuthorizer("use denied")
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "u"})
	_, err := svc.Sign(ctx, &pb.SignRequest{
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

	authorizer, _ := denyAuthorizer("delete denied")
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "u"})
	_, err := svc.DeleteKey(ctx, &pb.DeleteKeyRequest{
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

	// Use a denying authorizer to prove Health is not checked.
	authorizer, rbac := denyAuthorizer("deny all")
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	resp, err := svc.Health(context.Background(), &pb.HealthRequest{})
	if err != nil {
		t.Fatalf("Health should not be subject to authz: %v", err)
	}
	if resp.Status != "healthy" {
		t.Errorf("Expected status 'healthy', got '%s'", resp.Status)
	}

	// Verify no authorization request was made.
	if _, _, _, seen := rbac.Last(); seen {
		t.Error("Health endpoint should not trigger authorization")
	}
}

// --- Audit logging on allow and deny ---

func TestAuthz_AuditLogOnAllow(t *testing.T) {
	defer xkms.Reset()

	authorizer, _ := allowAuthorizer()
	auditLog := &mockAuditLogger{}
	svc := setupAuthzServiceTest(t, authorizer, auditLog)

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "audited-user",
		Roles:   []string{"operator"},
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
	if event.Action != "list" {
		t.Errorf("Expected action 'list', got '%s'", event.Action)
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

	authorizer, _ := denyAuthorizer("denied")
	auditLog := &mockAuditLogger{}
	svc := setupAuthzServiceTest(t, authorizer, auditLog)

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "denied-user",
		Roles:   []string{"guest"},
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

// --- Validation still happens before authz ---

func TestAuthz_ValidationBeforeAuthz(t *testing.T) {
	defer xkms.Reset()

	// Create a denying authorizer to ensure authz is not reached.
	authorizer, rbac := denyAuthorizer("should not reach")
	svc := setupAuthzServiceTest(t, authorizer, &mockAuditLogger{})

	// Call with invalid arguments (missing required fields).
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

	// Authorizer should not have been called.
	if _, _, _, seen := rbac.Last(); seen {
		t.Error("Authorizer should not be called when validation fails")
	}
}

// assertMapping verifies the RBAC client received the expected resource/action.
func assertMapping(t *testing.T, rbac *fakeRBACClient, expected authzMapping) {
	t.Helper()
	_, resource, action, seen := rbac.Last()
	if !seen {
		t.Fatal("Expected authorization request")
	}
	if resource != expected.resource {
		t.Errorf("Expected resource '%s', got '%s'", expected.resource, resource)
	}
	if action != expected.action {
		t.Errorf("Expected action '%s', got '%s'", expected.action, action)
	}
}
