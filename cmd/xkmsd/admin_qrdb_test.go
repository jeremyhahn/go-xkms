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

// Tests for admin.go's finalizeAdminModule, which needs a real *qrdbsdk.Client: go-qrdb's Client has no
// lightweight test constructor (NewClient requires a transport.Transport),
// so these tests stand up a real *server.Server over an embedded qrdb node
// rooted at a temp dir -- the same "embedded" transport production selects
// for a standalone deployment -- rather than faking the client.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	acmeentities "github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	acmestorage "github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	nativeca "github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/server"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// embeddedQRDBConfig returns the base configuration every embedded-qrdb
// fixture in this package shares: an embedded qrdb node rooted at a fresh
// temp dir, network protocols off (RESTPort 0, only the node's TLS Unix
// socket enabled, serving its bootstrap certificate), and a single software
// backend. It passes config.Config.Validate (standalone datastore plus
// tls.enabled, which the Unix socket requires) -- the "compliant
// server.New fixture" #705's triage asked for, shared by every caller below
// rather than each hand-rolling its own literal.
// jwtAuthConfig returns a JWT auth configuration whose verification key is a
// freshly generated P-256 public key written under dir. xkmsd has no
// unauthenticated mode, so every test server needs a real authenticator.
func jwtAuthConfig(t *testing.T, dir string) config.AuthConfig {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate JWT key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal JWT public key: %v", err)
	}
	keyFile := filepath.Join(dir, "jwt-public.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write JWT public key: %v", err)
	}
	return config.AuthConfig{
		Enabled: true,
		Type:    "jwt",
		JWT: &config.JWTConfig{
			PublicKeyFile: keyFile,
			Issuer:        "xkmsd-test",
			Audience:      []string{"xkmsd-test"},
		},
	}
}

func embeddedQRDBConfig(t *testing.T) *config.Config {
	t.Helper()
	tempDir := t.TempDir()
	return &config.Config{
		Server:    config.ServerConfig{Host: "127.0.0.1", RESTPort: 0},
		Protocols: config.ProtocolsConfig{Unix: true},
		Unix: config.UnixConfig{
			SocketPath: filepath.Join(tempDir, "xkms.sock"),
		},
		Logging:   config.LoggingConfig{Level: "error", Format: "json"},
		TLS:       config.TLSConfig{Enabled: true},
		Auth:      jwtAuthConfig(t, tempDir),
		Datastore: config.DatastoreConfig{Path: tempDir},
		Default:   config.DefaultConfig("software"),
		Backends: config.BackendsConfig{
			Software: &config.SoftwareConfig{Enabled: true, Path: filepath.Join(tempDir, "software")},
		},
	}
}

// newEmbeddedQRDBServer builds a real *server.Server backed by an embedded
// (in-process) qrdb node rooted at a temp dir, so tests below get a real
// *qrdbsdk.Client (srv.QRDBClient()) rather than a hand-rolled fake.
func newEmbeddedQRDBServer(t *testing.T) (*server.Server, *config.Config) {
	t.Helper()
	cfg := embeddedQRDBConfig(t)

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

// newEmbeddedQRDBServerWithCA builds the same embedded-qrdb fixture as
// newEmbeddedQRDBServer, plus a real software-backed self-signed root CA, for
// tests that need a working srv.CA() -- startACMEServer's success path
// (acme_success_test.go) chief among them.
func newEmbeddedQRDBServerWithCA(t *testing.T) (*server.Server, *config.Config) {
	t.Helper()
	cfg := embeddedQRDBConfig(t)
	cfg.CA = &nativeca.MultiIdentityCAConfig{
		SelectedCA:          0,
		DefaultValidityDays: 365,
		Identity: []nativeca.Identity{
			{
				IsRoot: true,
				Valid:  1,
				Subject: nativeca.Subject{
					CommonName:   "xkmsd test root CA",
					Organization: "go-xkms",
					Country:      "US",
				},
				Keys: []*types.KeyConfig{
					{
						KeyAlgorithm: types.AlgorithmECDSA,
						ECCConfig:    &types.ECCConfig{Curve: types.CurveP256},
					},
				},
			},
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
	if srv.CA() == nil {
		t.Fatal("fixture setup: CA() = nil with a CA identity configured")
	}
	return srv, cfg
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
