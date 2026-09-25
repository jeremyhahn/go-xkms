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

// Tests for admin.go's embeddedQRDBService adapter and finalizeAdminModule,
// both of which need a real *qrdbsdk.Client: go-qrdb's Client has no
// lightweight test constructor (NewClient requires a transport.Transport),
// so these tests stand up a real *server.Server over an embedded qrdb node
// rooted at a temp dir -- the same "embedded" transport production selects
// for a standalone deployment -- rather than faking the client.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	acmeentities "github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	acmeqrdb "github.com/jeremyhahn/go-xkms/pkg/acme/qrdb"
	acmestorage "github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/server"
)

// newEmbeddedQRDBServer builds a real *server.Server backed by an embedded
// (in-process) qrdb node rooted at a temp dir, so tests below get a real
// *qrdbsdk.Client (srv.QRDBClient()) rather than a hand-rolled fake.
func newEmbeddedQRDBServer(t *testing.T) (*server.Server, *config.Config) {
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
			Backend: "qrdb",
			Path:    tempDir,
			QRDB:    config.QRDBConfig{Transport: "embedded"},
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
	if srv.QRDBClient() == nil {
		t.Fatal("fixture setup: QRDBClient() = nil with a qrdb storage backend")
	}
	return srv, cfg
}

func TestEmbeddedQRDBService_Config(t *testing.T) {
	srv, _ := newEmbeddedQRDBServer(t)
	svc := &embeddedQRDBService{Client: srv.QRDBClient()}
	cfg := svc.Config()
	if cfg == nil || cfg.Mode != acmeqrdb.ModeStandalone {
		t.Fatalf("Config() = %+v, want Mode=%v", cfg, acmeqrdb.ModeStandalone)
	}
}

func TestEmbeddedQRDBService_Healthy(t *testing.T) {
	srv, _ := newEmbeddedQRDBServer(t)
	svc := &embeddedQRDBService{Client: srv.QRDBClient()}
	if !svc.Healthy(context.Background()) {
		t.Fatal("Healthy(ctx) = false for a freshly constructed embedded node, want true")
	}
}

// TestEmbeddedQRDBService_Close proves Close is the documented no-op: it
// must return nil, and, unlike a real Close, must leave the underlying
// client usable afterward, since its lifecycle belongs to pkg/server
// (stopQRDBNode), not to this adapter.
func TestEmbeddedQRDBService_Close(t *testing.T) {
	srv, _ := newEmbeddedQRDBServer(t)
	svc := &embeddedQRDBService{Client: srv.QRDBClient()}
	if err := svc.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}
	if !svc.Healthy(context.Background()) {
		t.Fatal("client unusable after embeddedQRDBService.Close(), want Close to be a no-op")
	}
}

// TestFinalizeAdminModule_Success proves finalizeAdminModule builds and
// publishes the admin router against a real embedded qrdb node with ACME
// disabled (nil *acmeServer, the same shape run() passes when acme.enabled
// is false): the published router answers a real registered route rather
// than the 503 adminRouterState starts with, and rejects the unauthenticated
// request exactly as production does, since no mTLS client certificate is
// presented.
func TestFinalizeAdminModule_Success(t *testing.T) {
	srv, _ := newEmbeddedQRDBServer(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := finalizeAdminModule(srv, nil, logger); err != nil {
		t.Fatalf("finalizeAdminModule: %v", err)
	}

	h := adminRouterState.Load()
	if h == nil {
		t.Fatal("finalizeAdminModule did not publish adminRouterState")
	}

	ts := httptest.NewServer(*h)
	t.Cleanup(ts.Close)
	client := ts.Client()
	t.Cleanup(client.CloseIdleConnections)

	resp, err := client.Get(ts.URL + "/admin/status")
	if err != nil {
		t.Fatalf("GET /admin/status: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Fatal("GET /admin/status = 503, want the admin surface reachable (not the pre-publish placeholder)")
	}
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /admin/status without an mTLS client cert = %d, want 401/403", resp.StatusCode)
	}
}

// stubFailingTenantDAOFactory implements storage.TenantAwareFactory with a
// TenantDAO() that always errors, so finalizeAdminModule's construction of
// the tenant-aware admin service is exercised on its refusal path -- a
// TenantAwareFactory that promises tenant-aware support and cannot deliver
// it (see NewTenantAwareAdminService's doc comment).
type stubFailingTenantDAOFactory struct{}

func (stubFailingTenantDAOFactory) AccountDAO() (qrdbsdk.GenericDAO[*acmeentities.ACMEAccount], error) {
	return nil, nil
}
func (stubFailingTenantDAOFactory) OrderDAO(uint64) (qrdbsdk.GenericDAO[*acmeentities.ACMEOrder], error) {
	return nil, nil
}
func (stubFailingTenantDAOFactory) AuthorizationDAO(uint64) (qrdbsdk.GenericDAO[*acmeentities.ACMEAuthorization], error) {
	return nil, nil
}
func (stubFailingTenantDAOFactory) ChallengeDAO(uint64) (qrdbsdk.GenericDAO[*acmeentities.ACMEChallenge], error) {
	return nil, nil
}
func (stubFailingTenantDAOFactory) CertificateDAO() (qrdbsdk.GenericDAO[*acmeentities.ACMECertificate], error) {
	return nil, nil
}
func (stubFailingTenantDAOFactory) NonceDAO() (qrdbsdk.GenericDAO[*acmeentities.ACMENonce], error) {
	return nil, nil
}
func (stubFailingTenantDAOFactory) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*acmeentities.ExternalAccountBinding], error) {
	return nil, nil
}
func (stubFailingTenantDAOFactory) TenantDAO() (qrdbsdk.GenericDAO[*acmeentities.Tenant], error) {
	return nil, errStubTenantDAO
}
func (stubFailingTenantDAOFactory) ForTenant(string) (acmestorage.Factory, error) {
	return nil, nil
}
func (stubFailingTenantDAOFactory) GetTenantID() string { return "" }

var _ acmestorage.TenantAwareFactory = stubFailingTenantDAOFactory{}

var errStubTenantDAO = errors.New("stub: TenantDAO always fails")

// TestFinalizeAdminModule_TenantDAOFailure proves a storage factory that
// implements TenantAwareFactory but cannot produce its TenantDAO refuses
// construction (via the wrapped *acmeInitError) instead of silently
// degrading or panicking; NewTenantAwareAdminService's own doc comment draws
// the same distinction against the "no TenantAwareFactory at all" case
// covered by TestFinalizeAdminModule_Success.
func TestFinalizeAdminModule_TenantDAOFailure(t *testing.T) {
	srv, _ := newEmbeddedQRDBServer(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	acme := &acmeServer{storageFactory: stubFailingTenantDAOFactory{}}

	err := finalizeAdminModule(srv, acme, logger)
	if err == nil {
		t.Fatal("finalizeAdminModule with a failing TenantDAO = nil error, want a refusal")
	}
	var initErr *acmeInitError
	if !errors.As(err, &initErr) {
		t.Fatalf("finalizeAdminModule error = %T, want *acmeInitError", err)
	}
	if !errors.Is(err, errStubTenantDAO) {
		t.Fatalf("finalizeAdminModule error does not wrap the underlying TenantDAO failure: %v", err)
	}
}
