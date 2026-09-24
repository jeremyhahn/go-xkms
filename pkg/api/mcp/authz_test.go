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

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// errFakeDenied is the decision a grant-less fakeRBAC returns. It deliberately
// is not auth.ErrUnauthenticated so the gate must classify it as a permission
// denial (403 / ErrCodeForbidden) rather than a missing identity.
var errFakeDenied = errors.New("permission denied by qrdb rbac")

// fakeRBAC is an in-memory stand-in for the qrdb RBACClient. It grants exactly
// the resource:action pairs it was seeded with and records every decision so a
// test can assert the MCP gate asked for the permission the other transports
// require for the same operation.
type fakeRBAC struct {
	mu      sync.Mutex
	granted map[string]struct{}
	err     error

	calls []string
}

// newFakeRBAC returns a client granting the given "resource:action" pairs.
func newFakeRBAC(grants ...string) *fakeRBAC {
	g := make(map[string]struct{}, len(grants))
	for _, grant := range grants {
		g[grant] = struct{}{}
	}
	return &fakeRBAC{granted: g}
}

func (f *fakeRBAC) Authorize(ctx context.Context, identity *qrdbtransport.Identity, resource, action string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, resource+":"+action)

	if f.err != nil {
		return f.err
	}
	if _, ok := f.granted[resource+":"+action]; ok {
		return nil
	}
	return errFakeDenied
}

func (f *fakeRBAC) ListPermissions(ctx context.Context, identity *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, errors.New("not implemented in fake")
}

// lastCall returns the most recent resource:action pair evaluated.
func (f *fakeRBAC) lastCall() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return ""
	}
	return f.calls[len(f.calls)-1]
}

// callCount returns how many authorization decisions were requested.
func (f *fakeRBAC) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// newRBACServer builds an MCP server with RBAC enabled against the given fake
// RBAC client.
func newRBACServer(t *testing.T, svc *xkms.XKMSService, rbac *fakeRBAC) *Server {
	t.Helper()

	server, err := NewServer(&Config{
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
		Authorizer:    auth.NewAuthorizer(rbac),
		EnableRBAC:    true,
	})
	require.NoError(t, err)
	return server
}

// authedCtx returns a context carrying an authenticated identity, the shape
// an mTLS-authenticated request carries on this transport.
func authedCtx() context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "operator@example.com",
		TenantID: "tenant-a",
		Roles:    []string{"operator"},
	})
}

// call drives a JSON-RPC request through the full dispatch pipeline
// (tenant scoping, authorization, and routing) via Server.InvokeMethod, the
// package's single production entry point.
func call(s *Server, ctx context.Context, method string) *JSONRPCResponse {
	return invokeRequest(s, ctx, &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  json.RawMessage(`{}`),
		ID:      1,
	})
}

// TestNewServer_RBACEnabled_NilAuthorizerRejected proves the constructor fails
// closed: a server told to enforce RBAC without an authorizer would authorize
// every method while the operator believes RBAC is on.
func TestNewServer_RBACEnabled_NilAuthorizerRejected(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
		EnableRBAC:    true,
	})

	require.ErrorIs(t, err, ErrAuthorizerRequired)
	assert.Nil(t, server, "no server must be returned when RBAC is enabled without an authorizer")
}

// TestNewServer_RBACEnabled_DisabledAuthorizerRejected proves an Authorizer
// with no backing RBAC client — which allows every request — is rejected too.
// Passing one would be indistinguishable from passing nil at request time.
func TestNewServer_RBACEnabled_DisabledAuthorizerRejected(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
		Authorizer:    auth.NewAuthorizer(nil),
		EnableRBAC:    true,
	})

	require.ErrorIs(t, err, ErrAuthorizerRequired)
	assert.Nil(t, server)
}

// TestNewServer_RBACEnabled_WithAuthorizer proves the happy path wires the
// authorizer through and records that enforcement is active.
func TestNewServer_RBACEnabled_WithAuthorizer(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server := newRBACServer(t, svc, newFakeRBAC())

	require.NotNil(t, server.authorizer)
	assert.True(t, server.authorizer.Enabled())
	assert.True(t, server.rbacEnabled)
}

// TestNewServer_RBACDisabled_DefaultsToDisabledAuthorizer proves the server
// always holds a usable Authorizer, defaulting to the same disabled instance
// the QUIC server builds (pkg/api/quic/server.go: auth.NewAuthorizer(nil)).
func TestNewServer_RBACDisabled_DefaultsToDisabledAuthorizer(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
	})
	require.NoError(t, err)

	require.NotNil(t, server.authorizer)
	assert.False(t, server.authorizer.Enabled())
	assert.False(t, server.rbacEnabled)
}

// TestMethodPermissions_CoverEveryDispatchableMethod is the anti-gap test: it
// fails if a JSON-RPC method can be dispatched without being either declared
// public or bound to a permission. A new method added to rpcMethodHandlers
// without a permission entry breaks this test rather than shipping ungated.
func TestMethodPermissions_CoverEveryDispatchableMethod(t *testing.T) {
	var unmapped []string

	dispatchable := make([]string, 0, len(rpcMethodHandlers))
	for method := range rpcMethodHandlers {
		dispatchable = append(dispatchable, method)
	}

	for _, method := range dispatchable {
		_, public := publicMethods[method]
		_, mapped := methodPermissions[method]
		if !public && !mapped {
			unmapped = append(unmapped, method)
		}
		assert.False(t, public && mapped, "method %q is both public and permission-mapped", method)
	}

	sort.Strings(unmapped)
	assert.Empty(t, unmapped, "dispatchable MCP methods without a permission mapping")

	// Every mapping must name a real resource and action.
	for method, perm := range methodPermissions {
		assert.NotEmpty(t, perm.resource, "method %q has an empty resource", method)
		assert.NotEmpty(t, perm.action, "method %q has an empty action", method)
	}

	// The FROST namespace is build-tagged; its permissions live in the table
	// unconditionally so a `-tags frost` build cannot ship unenforced.
	for _, method := range []string{
		"frost.generateKey", "frost.importKey", "frost.listKeys", "frost.getKey",
		"frost.deleteKey", "frost.generateNonces", "frost.signRound",
		"frost.aggregate", "frost.verify",
	} {
		_, mapped := methodPermissions[method]
		assert.True(t, mapped, "FROST method %q has no permission mapping", method)
	}
}

// TestAuthorizeMethod_EveryPrivilegedMethod walks the entire permission table
// and, for each method, proves both halves of the gate: a caller without the
// grant is denied before dispatch, and a caller with exactly that grant is
// admitted after the gate asked qrdb for the expected resource:action.
func TestAuthorizeMethod_EveryPrivilegedMethod(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	methods := make([]string, 0, len(methodPermissions))
	for method := range methodPermissions {
		methods = append(methods, method)
	}
	sort.Strings(methods)

	require.NotEmpty(t, methods)

	for _, method := range methods {
		perm := methodPermissions[method]
		grant := perm.resource + ":" + perm.action

		t.Run(method+"/denied_without_permission", func(t *testing.T) {
			rbac := newFakeRBAC() // no grants
			server := newRBACServer(t, svc, rbac)

			resp := call(server, authedCtx(), method)

			require.NotNil(t, resp)
			require.NotNil(t, resp.Error, "unauthorized caller must not receive a result")
			assert.Equal(t, ErrCodeForbidden, resp.Error.Code)
			assert.Equal(t, ErrPermissionDenied.Error(), resp.Error.Message)
			assert.Nil(t, resp.Result)
			assert.Equal(t, grant, rbac.lastCall(),
				"gate must request the same permission the REST/gRPC/QUIC transports require")
		})

		t.Run(method+"/allowed_with_permission", func(t *testing.T) {
			rbac := newFakeRBAC(grant)
			server := newRBACServer(t, svc, rbac)

			resp := call(server, authedCtx(), method)

			require.NotNil(t, resp)
			assert.Equal(t, grant, rbac.lastCall())
			if resp.Error != nil {
				// The handler may still reject the empty parameter object or
				// report an unconfigured sub-system; what must never happen is
				// an authorization failure once the grant is held.
				assert.NotEqual(t, ErrCodeForbidden, resp.Error.Code,
					"holder of %s must not be denied: %s", grant, resp.Error.Message)
				assert.NotEqual(t, ErrCodeUnauthorized, resp.Error.Code,
					"holder of %s must not be challenged: %s", grant, resp.Error.Message)
			}
		})
	}
}

// TestAuthorizeMethod_UnauthorizedCallerCannotGenerateKey is the regression
// test for the fixed gap: before this change an authenticated principal with
// no RBAC grant could invoke any MCP key operation. It asserts both the wire
// denial and that the handler never ran (no key was created).
func TestAuthorizeMethod_UnauthorizedCallerCannotGenerateKey(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	// The caller holds keys:list but not keys:create — authenticated, and
	// authorized for something, just not for key generation.
	rbac := newFakeRBAC("keys:list")
	server := newRBACServer(t, svc, rbac)
	ctx := authedCtx()

	resp := invokeRequest(server, ctx, &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.generateKey",
		Params:  json.RawMessage(`{"key_id":"rbac-regression-key","backend":"software","key_type":"RSA","key_size":2048}`),
		ID:      7,
	})

	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeForbidden, resp.Error.Code)
	assert.Equal(t, "keys:create", rbac.lastCall())

	// Prove the denial happened before dispatch: the key must not exist.
	listResp := invokeRequest(server, ctx, &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.listKeys",
		Params:  json.RawMessage(`{"backend":"software"}`),
		ID:      8,
	})
	require.NotNil(t, listResp)
	require.Nil(t, listResp.Error, "keys:list holder must be able to list")

	raw, err := json.Marshal(listResp.Result)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "rbac-regression-key",
		"denied generateKey must not have reached the service layer")
}

// TestAuthorizeMethod_NoIdentity_Unauthorized proves an unauthenticated
// request is challenged (401 equivalent) rather than denied (403), matching
// the REST middleware and the QUIC/gRPC ErrUnauthenticated branches.
func TestAuthorizeMethod_NoIdentity_Unauthorized(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	rbac := newFakeRBAC("keys:sign")
	server := newRBACServer(t, svc, rbac)

	resp := call(server, context.Background(), "xkms.sign")

	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeUnauthorized, resp.Error.Code)
	assert.Equal(t, auth.ErrUnauthenticated.Error(), resp.Error.Message)
	assert.Zero(t, rbac.callCount(), "qrdb must not be consulted without an identity")
}

// TestAuthorizeMethod_AuthorizerReportsUnauthenticated proves an
// ErrUnauthenticated decision coming back from the authorizer is reported as a
// challenge, not a denial.
func TestAuthorizeMethod_AuthorizerReportsUnauthenticated(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	rbac := newFakeRBAC()
	rbac.err = auth.ErrUnauthenticated
	server := newRBACServer(t, svc, rbac)

	resp := call(server, authedCtx(), "xkms.listKeys")

	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeUnauthorized, resp.Error.Code)
}

// TestAuthorizeMethod_UnmappedDispatchableMethod_Denied proves the gate fails
// closed for a dispatchable method with no permission entry. The FROST
// namespace is dispatched by prefix, so a future frost.* method that nobody
// mapped is denied instead of silently exposed.
func TestAuthorizeMethod_UnmappedDispatchableMethod_Denied(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	rbac := newFakeRBAC("keys:sign", "keys:create", "keys:list")
	server := newRBACServer(t, svc, rbac)

	err := server.authorizeMethod(authedCtx(), "frost.futureOperation")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMethodPermissionUnmapped)

	var keyOpErr *KeyOpError
	require.True(t, errors.As(err, &keyOpErr))
	assert.Equal(t, ErrCodeForbidden, keyOpErr.Code)

	resp := call(server, authedCtx(), "frost.futureOperation")
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeForbidden, resp.Error.Code)
	assert.Zero(t, rbac.callCount(), "an unmapped method is denied without consulting qrdb")
}

// TestAuthorizeMethod_UnknownMethod_StillMethodNotFound proves the gate does
// not turn an unknown method into an authorization failure — clients keep the
// standard -32601 answer and the gate leaks no information about it.
func TestAuthorizeMethod_UnknownMethod_StillMethodNotFound(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server := newRBACServer(t, svc, newFakeRBAC())

	resp := call(server, authedCtx(), "nonexistent.method")

	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeMethodNotFound, resp.Error.Code)
}

// TestAuthorizeMethod_HealthIsPublic proves liveness stays reachable without a
// grant, matching the REST RBAC middleware's SkipPaths for /health*.
func TestAuthorizeMethod_HealthIsPublic(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	rbac := newFakeRBAC()
	server := newRBACServer(t, svc, rbac)

	// Public even for a completely unauthenticated caller.
	resp := call(server, context.Background(), "health")

	require.NotNil(t, resp)
	require.Nil(t, resp.Error)
	assert.Zero(t, rbac.callCount())
}

// TestAuthorizeMethod_NotificationDenialIsReported proves a denied
// notification-shaped request (no ID) still produces an error rather than
// being silently dropped. Silently dropping it would leave the caller
// believing the operation ran.
func TestAuthorizeMethod_NotificationDenialIsReported(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server := newRBACServer(t, svc, newFakeRBAC())

	resp := invokeRequest(server, authedCtx(), &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.deleteKey",
		Params:  json.RawMessage(`{"key_id":"whatever"}`),
	})

	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeForbidden, resp.Error.Code)
}

// TestRBACDisabled_AllowsEveryMethod pins the RBAC-disabled policy: no
// authorization check runs at all, even when a denying authorizer is present.
// Authentication is unaffected.
func TestRBACDisabled_AllowsEveryMethod(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	rbac := newFakeRBAC() // denies everything
	server, err := NewServer(&Config{
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
		Authorizer:    auth.NewAuthorizer(rbac),
		// EnableRBAC intentionally false.
	})
	require.NoError(t, err)

	for _, method := range []string{"xkms.listBackends", "xkms.listKeys", "xkms.generateKey"} {
		resp := call(server, authedCtx(), method)
		require.NotNil(t, resp)
		if resp.Error != nil {
			assert.NotEqual(t, ErrCodeForbidden, resp.Error.Code, "method %s", method)
			assert.NotEqual(t, ErrCodeUnauthorized, resp.Error.Code, "method %s", method)
		}
	}

	assert.Zero(t, rbac.callCount(), "no authorization decision may be requested when RBAC is disabled")
}

// TestRBACDisabled_ParityWithRESTAndQUIC asserts the RBAC-disabled policy is
// the same across transports, so a deployment cannot end up with one open and
// one closed surface:
//
//   - REST: with RBAC off no RBACMiddleware is constructed at all; its
//     decorator, exercised here with the disabled Authorizer, admits a caller
//     that holds no grant (pkg/api/rest/server.go, rbac_middleware.go).
//   - QUIC: NewServer substitutes auth.NewAuthorizer(nil) when no Authorizer
//     is configured, and that Authorizer allows every request
//     (pkg/api/quic/server.go).
//   - MCP: authorizeMethod is a no-op when rbacEnabled is false, and the
//     server holds the same disabled Authorizer.
func TestRBACDisabled_ParityWithRESTAndQUIC(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	identity := &auth.Identity{Subject: "nobody@example.com", TenantID: "tenant-a"}

	// QUIC's disabled default, verbatim.
	quicDefault := auth.NewAuthorizer(nil)
	require.False(t, quicDefault.Enabled())
	assert.NoError(t, quicDefault.Authorize(context.Background(), identity, "keys", "sign"),
		"QUIC's default authorizer allows all when RBAC is disabled")

	// REST's decorator over the same disabled authorizer.
	middleware := rest.NewRBACMiddleware(&rest.RBACConfig{
		Authorizer: quicDefault,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	reached := false
	handler := middleware.RequirePermission("keys", "sign")(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/k1/sign", nil).
		WithContext(auth.WithIdentity(context.Background(), identity))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.True(t, reached, "REST admits the request when authorization is disabled")
	assert.Equal(t, http.StatusOK, rec.Code)

	// MCP's disabled server: same Authorizer shape, same outcome.
	server, err := NewServer(&Config{
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
	})
	require.NoError(t, err)
	require.False(t, server.authorizer.Enabled())

	assert.NoError(t, server.authorizeMethod(auth.WithIdentity(context.Background(), identity), "xkms.sign"),
		"MCP admits the request when authorization is disabled, exactly as REST and QUIC do")
}

// TestIsDispatchable classifies the two dispatch paths InvokeMethod uses.
func TestIsDispatchable(t *testing.T) {
	assert.True(t, isDispatchable("xkms.sign"), "table-dispatched method")
	assert.True(t, isDispatchable("frost.signRound"), "build-tagged namespace")
	assert.True(t, isDispatchable("frost.somethingNew"), "unknown method in a dispatched namespace")
	assert.False(t, isDispatchable("totally.unknown"))
}

// goldenMethodPermissions is the complete, literal resource:action pair every
// dispatchable JSON-RPC method requires. The strings are spelled out here
// rather than built from the auth.Resource*/auth.Action* constants on purpose:
// this table is the wire contract, so it must fail if a constant is retyped or
// repointed. Every pair is the one the transport that already enforces the
// equivalent operation demands (named per group below).
var goldenMethodPermissions = map[string]string{
	// Key, backend, certificate, sealing, and PIV surface —
	// pkg/api/grpc/service.go, pkg/api/quic/handlers*.go.
	"xkms.asymmetricDecrypt":        "keys:decrypt",
	"xkms.asymmetricEncrypt":        "keys:encrypt",
	"xkms.attestKey":                "keys:get",
	"xkms.canSeal":                  "keys:get",
	"xkms.certExists":               "certs:read",
	"xkms.copyKey":                  "keys:create",
	"xkms.decrypt":                  "keys:decrypt",
	"xkms.deleteCert":               "certs:revoke",
	"xkms.deleteKey":                "keys:delete",
	"xkms.deletePIVCertificate":     "piv:delete",
	"xkms.deleteShare":              "barrier:unseal-share",
	"xkms.deriveKeyECDH":            "keys:derive",
	"xkms.encrypt":                  "keys:encrypt",
	"xkms.exportKey":                "keys:export",
	"xkms.exportKeyMaterial":        "keys:export",
	"xkms.exportPIVCertificate":     "piv:read",
	"xkms.generateKey":              "keys:create",
	"xkms.generatePIVCSR":           "piv:use",
	"xkms.generatePIVKey":           "piv:write",
	"xkms.getBackend":               "backends:read",
	"xkms.getCert":                  "certs:read",
	"xkms.getCertChain":             "certs:read",
	"xkms.getImportParameters":      "keys:import",
	"xkms.getKey":                   "keys:get",
	"xkms.getPIVCertificate":        "piv:read",
	"xkms.getShare":                 "ceremony:status",
	"xkms.getShareCollectionStatus": "ceremony:status",
	"xkms.getTLSCertificate":        "certs:read",
	"xkms.importKey":                "keys:import",
	"xkms.importPIVCertificate":     "piv:write",
	"xkms.listBackends":             "backends:list",
	"xkms.listCerts":                "certs:list",
	"xkms.listKeys":                 "keys:list",
	"xkms.listPIVSlots":             "piv:read",
	"xkms.listShares":               "ceremony:status",
	"xkms.queryAudit":               "audit:read",
	"xkms.rotateKey":                "keys:rotate",
	"xkms.saveCert":                 "certs:generate",
	"xkms.saveCertChain":            "certs:generate",
	"xkms.seal":                     "keys:encrypt",
	"xkms.sign":                     "keys:sign",
	"xkms.storePIVCertificate":      "piv:write",
	"xkms.submitShare":              "barrier:unseal-share",
	"xkms.unseal":                   "keys:decrypt",
	"xkms.unwrapKey":                "keys:unwrap",
	"xkms.unwrapKeyByID":            "keys:unwrap",
	"xkms.verify":                   "keys:verify",
	"xkms.wrapKey":                  "keys:wrap",
	"xkms.wrapKeyByID":              "keys:wrap",

	// Certificate authority — pkg/api/quic/handlers_ca.go.
	"xkms.ca.bundle":      "certs:read",
	"xkms.ca.certificate": "certs:read",
	"xkms.ca.crl":         "certs:read",
	"xkms.ca.is-revoked":  "certs:read",
	"xkms.ca.issue":       "certs:generate",
	"xkms.ca.revoke":      "certs:revoke",
	"xkms.ca.sign-csr":    "certs:generate",

	// TCG certificate authority — pkg/api/quic/handlers_ca_tcg.go.
	"xkms.ca.tcg.enroll":   "certs:generate",
	"xkms.ca.tcg.issue-ak": "certs:generate",
	"xkms.ca.tcg.issue-ek": "certs:generate",
	"xkms.ca.tcg.sign-csr": "certs:generate",

	// Barrier lifecycle — pkg/api/quic/handlers_barrier_pin.go,
	// handlers_barrier_shamir.go, pkg/api/rest/server.go.
	"barrier.deleteRecoveryKeys":   "seal:generate_recovery",
	"barrier.enableEncryption":     "seal:enable_encryption",
	"barrier.generateRecoveryKeys": "seal:generate_recovery",
	"barrier.generateRootToken":    "seal:rotate_root_key",
	"barrier.hasRecoveryKeys":      "seal:status",
	"barrier.initialize":           "seal:bootstrap",
	"barrier.initializeShamir":     "seal:initialize_shamir",
	"barrier.recoverWithKeys":      "seal:recover_with_keys",
	"barrier.rekey":                "seal:rekey",
	"barrier.seal":                 "seal:seal",
	"barrier.status":               "seal:status",
	"barrier.unseal":               "seal:unseal",
	"barrier.unsealShare":          "barrier:unseal-share",
	"barrier.unsealShares":         "seal:unseal",

	// Trust bootstrap listener (go-xkms#632).
	"bootstrap.showKeys": "bootstrap:read",

	// Init ceremony — pkg/api/quic/handlers_init_credentials.go.
	"init.claimCertBegin":     "ceremony:claim_cert",
	"init.claimCertComplete":  "ceremony:claim_cert",
	"init.claimShareBegin":    "ceremony:claim_share_begin",
	"init.claimShareComplete": "ceremony:claim_share_complete",
	"init.getStatus":          "ceremony:status",
	"init.signCSR":            "ceremony:sign_csr",

	// Credential submission — pkg/api/quic/handlers_init_credentials.go.
	"credentials.strategy": "credentials:strategy",
	"credentials.submit":   "credentials:submit",

	// User management — pkg/api/rest/routes.go's /api/v1/users decorators.
	"user.bindCert":        "users:update",
	"user.create":          "users:create",
	"user.delete":          "users:delete",
	"user.disable":         "users:update",
	"user.enable":          "users:update",
	"user.get":             "users:read",
	"user.list":            "users:list",
	"user.listCredentials": "users:read",

	// Password vault — pkg/api/quic/handlers_password.go.
	"password.add":           "passwords:write",
	"password.delete":        "passwords:delete",
	"password.generate":      "passwords:generate",
	"password.get":           "passwords:read",
	"password.list":          "passwords:read",
	"password.lock":          "passwords:lock",
	"password.setAccessMode": "passwords:write",
	"password.status":        "passwords:read",
	"password.unlock":        "passwords:unlock",
	"password.update":        "passwords:write",

	// Platform-sealed store — pkg/api/mcp/handlers_seal_store.go. Same
	// keys:* pairs as the PKCS#11 remote-state RPCs on every other
	// transport, since both persist key-protection material.
	"sealStore.put":    "keys:write",
	"sealStore.get":    "keys:read",
	"sealStore.delete": "keys:delete",
	"sealStore.list":   "keys:list",
	"sealStore.reseal": "keys:write",
	"sealStore.status": "keys:read",

	// SSH key, known-host, and authorized-key stores —
	// pkg/api/quic/handlers_ssh.go.
	"ssh.authorizedKeys.add":    "ssh:write",
	"ssh.authorizedKeys.emit":   "ssh:read",
	"ssh.authorizedKeys.get":    "ssh:read",
	"ssh.authorizedKeys.list":   "ssh:read",
	"ssh.authorizedKeys.remove": "ssh:delete",
	"ssh.authorizedKeys.verify": "ssh:read",
	"ssh.keys.delete":           "ssh:delete",
	"ssh.keys.export":           "ssh:read",
	"ssh.keys.generate":         "ssh:write",
	"ssh.keys.get":              "ssh:read",
	"ssh.keys.import":           "ssh:write",
	"ssh.keys.list":             "ssh:read",
	"ssh.keys.sign":             "ssh:write",
	"ssh.knownHosts.add":        "ssh:write",
	"ssh.knownHosts.list":       "ssh:read",
	"ssh.knownHosts.remove":     "ssh:delete",
	"ssh.knownHosts.verify":     "ssh:read",

	// FROST threshold signatures — pkg/api/quic/handlers_frost.go.
	"frost.aggregate":      "keys:sign",
	"frost.deleteKey":      "keys:delete",
	"frost.generateKey":    "keys:create",
	"frost.generateNonces": "keys:sign",
	"frost.getKey":         "keys:get",
	"frost.importKey":      "keys:import",
	"frost.listKeys":       "keys:list",
	"frost.signRound":      "keys:sign",
	"frost.verify":         "keys:verify",
}

// TestMethodPermissions_MatchOtherTransports pins the resource:action string of
// EVERY method in the table against the literal wire contract. A silent edit —
// the kind that would quietly widen a permission, or a constant repointed at a
// different string — fails here. The check runs in both directions so neither a
// changed pair nor an added or removed method can slip through.
func TestMethodPermissions_MatchOtherTransports(t *testing.T) {
	require.Len(t, methodPermissions, len(goldenMethodPermissions),
		"a method was added to or removed from the permission table without updating the wire contract")

	for method, want := range goldenMethodPermissions {
		perm, ok := methodPermissions[method]
		require.True(t, ok, "method %q lost its permission mapping", method)
		assert.Equal(t, want, perm.resource+":"+perm.action, "method %q", method)
	}

	for method, perm := range methodPermissions {
		want, ok := goldenMethodPermissions[method]
		require.True(t, ok, "method %q was added without a wire-contract entry", method)
		assert.Equal(t, want, perm.resource+":"+perm.action, "method %q", method)
	}
}

// TestMethodPermissions_NoInventedVocabulary proves the table only uses
// resources and actions that already exist in the qrdb permission vocabulary
// as consumed by the other xkms transports.
func TestMethodPermissions_NoInventedVocabulary(t *testing.T) {
	resources := map[string]struct{}{
		auth.ResourceKeys: {}, auth.ResourceCerts: {}, auth.ResourceBackends: {},
		auth.ResourcePIV: {}, auth.ResourceSSH: {}, auth.ResourceSeal: {},
		auth.ResourceBarrier: {}, auth.ResourceCeremony: {},
		auth.ResourceCredentials: {}, auth.ResourcePasswords: {},
		auth.ResourceAudit: {}, auth.ResourceBootstrap: {},
		auth.ResourceUsers: {},
	}

	for method, perm := range methodPermissions {
		_, ok := resources[perm.resource]
		assert.True(t, ok, "method %q uses unknown resource %q", method, perm.resource)
		assert.False(t, strings.ContainsAny(perm.action, " \t"), "method %q action %q is malformed", method, perm.action)
	}
}
