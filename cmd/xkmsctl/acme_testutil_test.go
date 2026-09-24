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

// acme_testutil_test.go provides a minimal embedded.AdminServicer test
// double for the "xkmsctl acme" run tests. It drives the real
// sdk/go/acme embedded transport and the real sdk/go/acme/client/admin
// sub-clients end to end — request serialization, response mapping, and
// error classification all run for real — with a hand-wired HTTP handler
// standing in for the server side, instead of mocking admin.Client itself.
//
// Every route not wired for a given test returns 501, so a test only
// declares the handler(s) it actually exercises (map-based dispatch: see
// acmeFakeAdminServicer.dispatch).
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	trustedca "github.com/jeremyhahn/go-xkms/sdk/go/acme"
	acmeadmin "github.com/jeremyhahn/go-xkms/sdk/go/acme/client/admin"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport/embedded"
)

// Compile-time check: acmeFakeAdminServicer implements the SDK's embedded
// admin servicer interface.
var _ embedded.AdminServicer = (*acmeFakeAdminServicer)(nil)

// problemForbidden mirrors pkg/acme/admin's PermissionGate problem type
// (urn:trusted-ca:error:forbidden), so a 403 test exercises the same
// type string the real server sends.
const problemForbidden = "urn:trusted-ca:error:forbidden"

// problemNotFound is an admin-domain "not found" problem type, distinct
// from the RFC 8555 ACME URNs the embedded transport's ACME-type parser
// recognizes, so these tests also cover the HTTP-status fallback path.
const problemNotFound = "urn:trusted-ca:error:notFound"

// acmeFakeAdminServicer is a minimal embedded.AdminServicer implementation.
// Each of its 34 interface methods dispatches, by name, into routes —
// map-based dispatch rather than one switch per method.
type acmeFakeAdminServicer struct {
	routes map[string]http.HandlerFunc
}

func newACMEFakeAdminServicer() *acmeFakeAdminServicer {
	return &acmeFakeAdminServicer{routes: make(map[string]http.HandlerFunc)}
}

// on wires a handler for the named embedded.AdminServicer method and
// returns the fake for chaining.
func (f *acmeFakeAdminServicer) on(method string, h http.HandlerFunc) *acmeFakeAdminServicer {
	f.routes[method] = h
	return f
}

// dispatch resolves the handler registered for name, or a 501 stand-in
// when the test did not wire one.
func (f *acmeFakeAdminServicer) dispatch(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h, ok := f.routes[name]; ok {
			h(w, r)
			return
		}
		acmeWriteProblem(w, http.StatusNotImplemented, "about:blank", name+" not wired in test fake")
	}
}

// acmeWriteJSON writes a direct (non-problem) JSON admin response, the
// shape sdk/go/acme/client/admin's mapResponse/mapListResponse expect.
func acmeWriteJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// acmeWriteProblem writes an RFC 7807 problem response, the shape the real
// ACME admin server (pkg/acme/admin's writeProblem) and the SDK's error
// parser both expect.
func acmeWriteProblem(w http.ResponseWriter, status int, problemType, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"type":   problemType,
		"detail": detail,
		"status": status,
	})
}

// acmeDecodeBody decodes the request body into a map for assertions on
// what the CLI sent (account ID, tenant, kid, and so on).
func acmeDecodeBody(t *testing.T, r *http.Request) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if r.Body == nil {
		return body
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	return body
}

// newACMEAdminTestClient wires fake into a real sdk/go/acme embedded
// transport and returns the real admin.Client built on top of it, plus a
// close func. The transport, the sub-clients, JSON (de)serialization and
// error classification are all the genuine SDK code paths.
func newACMEAdminTestClient(t *testing.T, fake *acmeFakeAdminServicer) acmeadmin.Client {
	t.Helper()
	cl, err := trustedca.NewClient("", trustedca.WithEmbedded(fake))
	if err != nil {
		t.Fatalf("trustedca.NewClient(WithEmbedded): %v", err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	return cl.Admin()
}

// withACMEAdminClient overrides the package's ACME admin client factory to
// hand back client for the duration of the test, restoring the previous
// factory on cleanup — the same seam cluster_test.go uses for
// SetQRDBControlClientFactory.
func withACMEAdminClient(t *testing.T, client acmeadmin.Client) {
	t.Helper()
	restore := SetACMEAdminClientFactory(func(context.Context) (acmeadmin.Client, func() error, error) {
		return client, func() error { return nil }, nil
	})
	t.Cleanup(restore)
}

// ---------------------------------------------------------------------------
// embedded.AdminServicer interface satisfaction (map-based dispatch)
// ---------------------------------------------------------------------------

func (f *acmeFakeAdminServicer) StatusHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("StatusHandler")(w, r)
}
func (f *acmeFakeAdminServicer) StatsHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("StatsHandler")(w, r)
}
func (f *acmeFakeAdminServicer) ListCertificatesHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("ListCertificatesHandler")(w, r)
}
func (f *acmeFakeAdminServicer) GetCertificateHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("GetCertificateHandler")(w, r)
}
func (f *acmeFakeAdminServicer) RevokeCertificateHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("RevokeCertificateHandler")(w, r)
}
func (f *acmeFakeAdminServicer) ListAccountsHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("ListAccountsHandler")(w, r)
}
func (f *acmeFakeAdminServicer) GetAccountHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("GetAccountHandler")(w, r)
}
func (f *acmeFakeAdminServicer) DisableAccountHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("DisableAccountHandler")(w, r)
}
func (f *acmeFakeAdminServicer) CreateTenantHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("CreateTenantHandler")(w, r)
}
func (f *acmeFakeAdminServicer) ListTenantsHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("ListTenantsHandler")(w, r)
}
func (f *acmeFakeAdminServicer) GetTenantHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("GetTenantHandler")(w, r)
}
func (f *acmeFakeAdminServicer) UpdateTenantHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("UpdateTenantHandler")(w, r)
}
func (f *acmeFakeAdminServicer) DeleteTenantHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("DeleteTenantHandler")(w, r)
}
func (f *acmeFakeAdminServicer) UpdateTenantStatusHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("UpdateTenantStatusHandler")(w, r)
}
func (f *acmeFakeAdminServicer) CreateEABHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("CreateEABHandler")(w, r)
}
func (f *acmeFakeAdminServicer) ListEABHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("ListEABHandler")(w, r)
}
func (f *acmeFakeAdminServicer) GetEABHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("GetEABHandler")(w, r)
}
func (f *acmeFakeAdminServicer) DeleteEABHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("DeleteEABHandler")(w, r)
}
func (f *acmeFakeAdminServicer) CreateRoleHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("CreateRoleHandler")(w, r)
}
func (f *acmeFakeAdminServicer) ListRolesHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("ListRolesHandler")(w, r)
}
func (f *acmeFakeAdminServicer) GetRoleHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("GetRoleHandler")(w, r)
}
func (f *acmeFakeAdminServicer) UpdateRoleHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("UpdateRoleHandler")(w, r)
}
func (f *acmeFakeAdminServicer) DeleteRoleHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("DeleteRoleHandler")(w, r)
}
func (f *acmeFakeAdminServicer) CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("CreateUserHandler")(w, r)
}
func (f *acmeFakeAdminServicer) ListUsersHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("ListUsersHandler")(w, r)
}
func (f *acmeFakeAdminServicer) GetUserHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("GetUserHandler")(w, r)
}
func (f *acmeFakeAdminServicer) UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("UpdateUserHandler")(w, r)
}
func (f *acmeFakeAdminServicer) DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("DeleteUserHandler")(w, r)
}
func (f *acmeFakeAdminServicer) ListOrdersHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("ListOrdersHandler")(w, r)
}
func (f *acmeFakeAdminServicer) GetOrderHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("GetOrderHandler")(w, r)
}
func (f *acmeFakeAdminServicer) CreateRootCAHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("CreateRootCAHandler")(w, r)
}
func (f *acmeFakeAdminServicer) CAStatusHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("CAStatusHandler")(w, r)
}
func (f *acmeFakeAdminServicer) CreateIntermediateCAHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("CreateIntermediateCAHandler")(w, r)
}
func (f *acmeFakeAdminServicer) ListIntermediateCAsHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("ListIntermediateCAsHandler")(w, r)
}
func (f *acmeFakeAdminServicer) GetIntermediateCAHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("GetIntermediateCAHandler")(w, r)
}
func (f *acmeFakeAdminServicer) UpdateIntermediateCAStatusHandler(w http.ResponseWriter, r *http.Request) {
	f.dispatch("UpdateIntermediateCAStatusHandler")(w, r)
}
