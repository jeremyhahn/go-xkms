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

package admin

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// errTestDenied is the deny sentinel the test RBAC clients return. It stands in
// for qrdb's PermissionDeniedError, which the Authorizer forwards verbatim.
var errTestDenied = errors.New("test: permission denied")

// discardLogger returns a logger that writes nowhere, keeping test output clean
// while still exercising the gate's logging paths.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// qrdbRoleRBAC is an RBAC client that resolves authorization exactly the way
// go-qrdb's canonical built-in roles define it: the identity's role names are
// looked up in qrdbsdk.BuiltInRoles and the union of their permission sets must
// contain the requested "resource:action".
//
// Tests use this rather than a hand-written allowlist so that "granting admin
// reaches the ACME admin surface" is asserted against the real qrdb grants. If
// a permission is ever dropped from qrdb's admin role, these tests fail.
type qrdbRoleRBAC struct {
	// requested records every resource:action the gate asked for, so a test can
	// assert the exact pair a route requests rather than only its outcome.
	mu        sync.Mutex
	requested []string
}

func (q *qrdbRoleRBAC) Authorize(_ context.Context, id *qrdbtransport.Identity, resource, action string) error {
	want := resource + ":" + action

	q.mu.Lock()
	q.requested = append(q.requested, want)
	q.mu.Unlock()

	if id == nil {
		return errTestDenied
	}

	held := make(map[string]struct{}, len(id.Roles))
	for _, r := range id.Roles {
		held[r] = struct{}{}
	}

	for _, r := range qrdbsdk.BuiltInRoles(id.TenantID) {
		if _, ok := held[r.Name]; !ok {
			continue
		}
		for _, p := range r.Permissions {
			if string(p) == want {
				return nil
			}
			// Whole-segment wildcard, expanded the way qrdb's authorizer does.
			if strings.HasSuffix(string(p), ":*") && strings.TrimSuffix(string(p), ":*") == resource {
				return nil
			}
		}
	}
	return errTestDenied
}

func (q *qrdbRoleRBAC) ListPermissions(_ context.Context, _ *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, nil
}

// requests returns a copy of every resource:action the gate asked this client
// to evaluate.
func (q *qrdbRoleRBAC) requests() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]string, len(q.requested))
	copy(out, q.requested)
	return out
}

// reset clears the recorded requests between sub-tests.
func (q *qrdbRoleRBAC) reset() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.requested = nil
}

// newQRDBGate returns a PermissionGate backed by the canonical qrdb role
// definitions, together with the recording client behind it.
func newQRDBGate() (*PermissionGate, *qrdbRoleRBAC) {
	client := &qrdbRoleRBAC{}
	return NewPermissionGate(auth.NewAuthorizer(client), discardLogger()), client
}

// identityWithRoles builds a canonical identity for the given tenant and roles.
func identityWithRoles(tenantID string, roles ...string) *auth.Identity {
	return &auth.Identity{
		Subject:  "test-subject",
		TenantID: tenantID,
		Roles:    roles,
	}
}

// newPermissiveGate returns a gate whose authorizer has no RBAC client, so
// authorization is disabled (the documented "RBAC disabled => allow all"
// posture). Handler tests that exercise behavior rather than authorization use
// it together with an authenticated request; the dedicated authorization tests
// in authz_test.go and routes_authz_test.go use newQRDBGate instead.
func newPermissiveGate() *PermissionGate {
	return NewPermissionGate(auth.NewAuthorizer(nil), discardLogger())
}

// newEnforcingGate returns a gate that evaluates the canonical qrdb role
// grants, for tests that assert a denial.
func newEnforcingGate() *PermissionGate {
	gate, _ := newQRDBGate()
	return gate
}

// authenticated attaches a canonical platform-admin identity to req, standing
// in for the authentication middleware in tests that register routes without
// one. Every ACME admin route is gated, so a request with no identity is
// answered 401 before the handler runs.
func authenticated(req *http.Request) *http.Request {
	user := &AuthenticatedUser{
		UserID:   "test-admin",
		Username: "test-admin",
		Roles:    []string{qrdbsdk.RoleNameAdmin},
	}
	return req.WithContext(withUser(req.Context(), user))
}
