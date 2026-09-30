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

package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// go-xkms#1087: pkg/api/transport/rest/transport.go called several
// collection-root endpoints without the trailing slash pkg/api/rest/routes.go
// registers them under (the same class of bug #949/PR #1086 found for
// /api/v1/tenants). In production, chi's own slash redirect silently
// tolerated the mismatch until another route claimed the bare path, and the
// call then landed on the wrong handler with no client-visible error. This
// file guards against that regression recurring: it derives the exact
// registered path from pkg/api/rest.Routes() -- never a copy of the string
// literal -- and drives each transport method against an httptest server
// that serves ONLY that literal path, with no sub-mount and no
// trailing-slash tolerance, so a reintroduced mismatch fails the test
// instead of silently working in the test harness the way it silently
// misrouted in production.

// errCollectionRouteNotFound reports that no entry in a route table matches
// the requested method and collection-resource base path.
type errCollectionRouteNotFound struct {
	Method string
	Base   string
}

func (e *errCollectionRouteNotFound) Error() string {
	return fmt.Sprintf("no registered collection-root route for %s %s (or %s/)", e.Method, e.Base, e.Base)
}

// errCollectionRouteHasParameter reports that the matching route entry
// carries a {placeholder} path segment, so it is not actually a collection
// root and asserting collection-root parity against it would be meaningless.
type errCollectionRouteHasParameter struct {
	Method  string
	Pattern string
}

func (e *errCollectionRouteHasParameter) Error() string {
	return fmt.Sprintf("%s %s carries a path parameter; it is not a collection-root route", e.Method, e.Pattern)
}

// collectionRoutePattern finds the exact Pattern specs registers for method
// against the collection resource identified by base (no trailing slash,
// e.g. "/api/v1/custodian/groups"). It is the one place the parity test
// below derives an expected path from the route table instead of
// duplicating a literal string that could drift out of sync with
// routes.go.
func collectionRoutePattern(specs []restapi.RouteSpec, method, base string) (string, error) {
	for _, spec := range specs {
		if spec.Method != method {
			continue
		}
		if spec.Pattern != base && spec.Pattern != base+"/" {
			continue
		}
		if strings.Contains(spec.Pattern, "{") {
			return "", &errCollectionRouteHasParameter{Method: method, Pattern: spec.Pattern}
		}
		return spec.Pattern, nil
	}
	return "", &errCollectionRouteNotFound{Method: method, Base: base}
}

func TestCollectionRoutePattern_Found(t *testing.T) {
	pattern, err := collectionRoutePattern(restapi.Routes(), http.MethodPost, "/api/v1/custodian/groups")
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/custodian/groups/", pattern)
}

func TestCollectionRoutePattern_NotFound(t *testing.T) {
	_, err := collectionRoutePattern(restapi.Routes(), http.MethodPost, "/api/v1/does-not-exist")
	require.Error(t, err)
	var notFound *errCollectionRouteNotFound
	assert.ErrorAs(t, err, &notFound)
}

func TestCollectionRoutePattern_HasParameter(t *testing.T) {
	_, err := collectionRoutePattern(restapi.Routes(), http.MethodGet, "/api/v1/keys/{id}")
	require.Error(t, err)
	var hasParam *errCollectionRouteHasParameter
	assert.ErrorAs(t, err, &hasParam)
}

// mustCollectionRoutePattern is the t.Fatal-on-error wrapper collectionRoutePattern
// callers in this file use once they only care about the resolved pattern.
func mustCollectionRoutePattern(t *testing.T, method, base string) string {
	t.Helper()
	pattern, err := collectionRoutePattern(restapi.Routes(), method, base)
	require.NoError(t, err)
	return pattern
}

// newCollectionRootServer starts an httptest server that serves exactly two
// routes by direct string comparison against the raw request: GET /health
// (Connect's own liveness probe) and method+pattern. There is no
// http.ServeMux involved and therefore none of its own trailing-slash
// subtree-redirect behavior to accidentally mask a mismatch -- a request
// for any path other than pattern, byte for byte, gets a plain 404. The
// returned *string is populated with the URL path of the one request that
// actually matched the collection-root route, if any.
func newCollectionRootServer(t *testing.T, method, pattern string) (*Transport, *string) {
	t.Helper()

	seen := new(string)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/health":
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
				t.Logf("failed to encode health response: %v", err)
			}
		case r.Method == method && r.URL.Path == pattern:
			*seen = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			if _, err := w.Write([]byte("{}")); err != nil {
				t.Logf("failed to write response: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	})

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	tr, err := NewWithConfig(&transport.Config{Address: srv.URL, TLSEnabled: false})
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))

	return tr, seen
}

// collectionRouteCase drives one transport method that is expected to hit a
// collection-root route, identified by base (no trailing slash).
type collectionRouteCase struct {
	name   string
	method string
	base   string
	call   func(ctx context.Context, tr *Transport) error
}

var collectionRouteCases = []collectionRouteCase{
	{
		name:   "CreateCustodianGroup",
		method: http.MethodPost,
		base:   "/api/v1/custodian/groups",
		call: func(ctx context.Context, tr *Transport) error {
			_, err := tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{})
			return err
		},
	},
	{
		name:   "ListCustodianGroups",
		method: http.MethodGet,
		base:   "/api/v1/custodian/groups",
		call: func(ctx context.Context, tr *Transport) error {
			_, err := tr.ListCustodianGroups(ctx)
			return err
		},
	},
	{
		name:   "PasswordAdd",
		method: http.MethodPost,
		base:   "/api/v1/passwords",
		call: func(ctx context.Context, tr *Transport) error {
			_, err := tr.PasswordAdd(ctx, &transport.PasswordAddRequest{Name: "n", Password: "p"})
			return err
		},
	},
	{
		name:   "PasswordList",
		method: http.MethodGet,
		base:   "/api/v1/passwords",
		call: func(ctx context.Context, tr *Transport) error {
			_, err := tr.PasswordList(ctx, nil)
			return err
		},
	},
	{
		name:   "ListShares",
		method: http.MethodGet,
		base:   "/api/v1/shares",
		call: func(ctx context.Context, tr *Transport) error {
			_, err := tr.ListShares(ctx)
			return err
		},
	},
	{
		name:   "QueryAudit",
		method: http.MethodGet,
		base:   "/api/v1/audit",
		call: func(ctx context.Context, tr *Transport) error {
			_, err := tr.QueryAudit(ctx, &transport.AuditFilter{})
			return err
		},
	},
	{
		name:   "CreateUser",
		method: http.MethodPost,
		base:   "/api/v1/users",
		call: func(ctx context.Context, tr *Transport) error {
			_, err := tr.CreateUser(ctx, &transport.CreateUserRequest{Username: "u", Email: "u@example.com"})
			return err
		},
	},
	{
		name:   "ListUsers",
		method: http.MethodGet,
		base:   "/api/v1/users",
		call: func(ctx context.Context, tr *Transport) error {
			_, err := tr.ListUsers(ctx)
			return err
		},
	},
	{
		name:   "RotateScopeKeys",
		method: http.MethodPost,
		base:   "/api/v1/keys/rotate-all",
		call: func(ctx context.Context, tr *Transport) error {
			_, err := tr.RotateScopeKeys(ctx, &transport.RotateScopeKeysRequest{TenantID: "acme"})
			return err
		},
	},
	{
		name:   "TPMPolicyCreate",
		method: http.MethodPost,
		base:   "/api/v1/tpm/policies",
		call: func(ctx context.Context, tr *Transport) error {
			_, err := tr.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{Name: "p", Branches: []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{0})}})
			return err
		},
	},
	{
		name:   "TPMPolicyList",
		method: http.MethodGet,
		base:   "/api/v1/tpm/policies",
		call: func(ctx context.Context, tr *Transport) error {
			_, err := tr.TPMPolicyList(ctx, &transport.TPMPolicyListRequest{})
			return err
		},
	},
}

// TestTransport_CollectionRootRoutes_MatchRegisteredPaths is the #1087
// regression guard described at the top of this file: for every REST
// transport method whose call targets a collection-root route, the request
// that actually leaves the transport must equal, byte for byte, the path
// pkg/api/rest.Routes() registers for it.
//
// The /api/v1/tenants collection-root calls are intentionally NOT in this
// table: go-xkms#949 / PR #1086 re-points them on a branch that has not
// merged yet, and this change is staged to land underneath it without
// touching the tenant calls so the merge stays clean.
func TestTransport_CollectionRootRoutes_MatchRegisteredPaths(t *testing.T) {
	for _, tc := range collectionRouteCases {
		t.Run(tc.name, func(t *testing.T) {
			registered := mustCollectionRoutePattern(t, tc.method, tc.base)

			tr, seen := newCollectionRootServer(t, tc.method, registered)

			err := tc.call(context.Background(), tr)
			require.NoErrorf(t, err, "%s: transport call failed against the registered route %s %s", tc.name, tc.method, registered)

			assert.Equalf(t, registered, *seen, "%s: transport requested a different path than pkg/api/rest.Routes() registers", tc.name)
		})
	}
}

// TestNewCollectionRootServer_RejectsMismatchedPath proves the harness
// above actually distinguishes a collection-root request that carries the
// registered trailing slash from one that omits it -- the exact defect
// #1087 fixed -- instead of tolerating both the way chi's own redirect did
// in production.
func TestNewCollectionRootServer_RejectsMismatchedPath(t *testing.T) {
	registered := mustCollectionRoutePattern(t, http.MethodPost, "/api/v1/custodian/groups")
	require.True(t, strings.HasSuffix(registered, "/"), "test fixture assumes the registered collection route carries a trailing slash")

	tr, seen := newCollectionRootServer(t, http.MethodPost, registered)

	mismatched := strings.TrimSuffix(registered, "/")
	_, err := tr.DoRawRequest(context.Background(), http.MethodPost, mismatched, nil)
	require.Errorf(t, err, "expected the mismatched path %q to fail against a server that only serves %q", mismatched, registered)
	assert.Emptyf(t, *seen, "mismatched request unexpectedly reached the handler at %q", *seen)
}
