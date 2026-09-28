// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package main

// Tests for go-xkms#1075:
//
//  1. finalizeAdminModule refuses to build the ACME admin surface's
//     authorizer against a nil qrdb client (ErrAdminQRDBClientRequired)
//     instead of falling back to auth.NewAuthorizer(nil), which would allow
//     every request.
//  2. With ACME disabled, every published admin route answers without
//     panicking — walking the router exactly as admin_authz_test.go does,
//     but asserting the absence of a panic directly (a failure here reports
//     which route panicked) rather than admin_authz_test.go's own
//     recover-and-report-500, which that file's comment documents as
//     deliberately tolerating the go-xkms#1075 bug this test now closes.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/server"
)

// newServerWithoutQRDB builds a real *server.Server whose storage backend is
// not "qrdb", so no embedded qrdb node is constructed and QRDBClient()
// legitimately returns nil (pkg/server/server_acme_accessors.go QRDBClient
// doc comment; pkg/server/qrdb_storage.go initializeQRDBStorage is a no-op
// for any backend other than "qrdb").
func newServerWithoutQRDB(t *testing.T) *server.Server {
	t.Helper()
	tempDir := t.TempDir()
	cfg := &config.Config{
		Server:    config.ServerConfig{Host: "127.0.0.1", RESTPort: 0},
		Protocols: config.ProtocolsConfig{Unix: true},
		Unix: config.UnixConfig{
			Enabled:    true,
			SocketPath: filepath.Join(tempDir, "xkms.sock"),
			Protocol:   "grpc",
		},
		Logging: config.LoggingConfig{Level: "error", Format: "json"},
		TLS:     config.TLSConfig{Enabled: false},
		Auth:    config.AuthConfig{Enabled: false},
		Storage: config.StorageConfig{
			Backend: "memory",
		},
		Default: config.DefaultConfig("software"),
		Backends: config.BackendsConfig{
			Software: &config.SoftwareConfig{Enabled: true, Path: filepath.Join(tempDir, "software")},
		},
	}

	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	t.Cleanup(func() {
		if err := srv.Shutdown(); err != nil {
			t.Errorf("server.Shutdown: %v", err)
		}
	})
	if srv.QRDBClient() != nil {
		t.Fatal("fixture setup: QRDBClient() != nil with a memory storage backend")
	}
	return srv
}

// TestFinalizeAdminModule_NilQRDBClientRefused proves finalizeAdminModule
// fails closed (refuses to build the admin surface) rather than falling back
// to a disabled, allow-all authorizer when no qrdb client is available.
func TestFinalizeAdminModule_NilQRDBClientRefused(t *testing.T) {
	srv := newServerWithoutQRDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	err := finalizeAdminModule(srv, nil, logger)
	if err == nil {
		t.Fatal("finalizeAdminModule with a nil qrdb client = nil error, want a refusal")
	}
	if !errors.Is(err, ErrAdminQRDBClientRequired) {
		t.Fatalf("finalizeAdminModule error = %v, want ErrAdminQRDBClientRequired", err)
	}
	var initErr *acmeInitError
	if !errors.As(err, &initErr) {
		t.Fatalf("finalizeAdminModule error = %T, want *acmeInitError", err)
	}

	if h := adminRouterState.Load(); h != nil {
		t.Fatal("finalizeAdminModule published a router despite refusing to build the admin service")
	}
}

// TestAdminPlane_ACMEDisabled_NoRouteEverPanics is the go-xkms#1075
// regression: with ACME disabled (finalizeAdminModule receives a nil
// *acmeServer, as run() does when acme.enabled is false), every route the
// published admin router serves must answer without panicking, for both a
// caller the gate grants and one it denies. Before the fix, every AdminService
// method reading the nil CA or nil storage factory panicked with a nil pointer
// dereference the moment a request reached it.
func TestAdminPlane_ACMEDisabled_NoRouteEverPanics(t *testing.T) {
	f := newAdminAuthzFixture(t)
	admin := firstBootAdmin(t, f.client)
	cert := bindClientCert(t, f.client, admin)

	for _, route := range f.routes {
		t.Run(route.String(), func(t *testing.T) {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("%s panicked: %v", route, r)
					}
				}()
				req := httptest.NewRequest(route.method, route.path, nil)
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
				rec := httptest.NewRecorder()
				f.router.ServeHTTP(rec, req)
			}()
		})
	}
}

// TestAdminPlane_ACMEDisabled_CABackedRoutesAnswerNotImplemented proves the
// specific typed-degradation contract for the routes that read the ACME CA
// or storage factory directly (no path-variable parsing stands between the
// request and the AdminService call, unlike GetAccount/GetOrder/DisableAccount,
// whose placeholder path variable is rejected as a malformed ID first): with
// ACME disabled they answer 501 with the "not implemented" problem type,
// never a bare 200 with invented data and never an unhandled 500.
func TestAdminPlane_ACMEDisabled_CABackedRoutesAnswerNotImplemented(t *testing.T) {
	f := newAdminAuthzFixture(t)
	cert := bindClientCert(t, f.client, firstBootAdmin(t, f.client))

	for _, route := range []adminRoute{
		{method: "GET", path: "/admin/certificates"},
		{method: "GET", path: "/admin/certificates/expiring"},
		{method: "GET", path: "/admin/certificates/123456"},
		{method: "GET", path: "/admin/accounts"},
		{method: "GET", path: "/admin/orders"},
		{method: "GET", path: "/admin/status"},
		{method: "GET", path: "/admin/stats"},
	} {
		t.Run(route.String(), func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
			rec := httptest.NewRecorder()
			f.router.ServeHTTP(rec, req)

			if rec.Code != 501 {
				t.Fatalf("%s = %d, want 501 (Not Implemented); body = %s", route, rec.Code, rec.Body.String())
			}
		})
	}
}
