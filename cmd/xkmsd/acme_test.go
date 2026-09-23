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

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	acmesdk "github.com/jeremyhahn/go-xkms/sdk/go/acme"
)

// TestStartACMEServer_Disabled verifies that startACMEServer is a no-op when
// the ACME configuration is absent or disabled. No listener should be
// created and no error should be returned.
func TestStartACMEServer_Disabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cases := []struct {
		name string
		cfg  *config.Config
	}{
		{"acme_nil", &config.Config{}},
		{"acme_disabled", &config.Config{ACME: &config.ACMEConfig{Enabled: false}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			as, err := startACMEServer(nil, tc.cfg, logger)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if as != nil {
				t.Fatalf("expected nil acmeServer when disabled, got %#v", as)
			}
			// Shutting down a nil acmeServer must be safe.
			if err := as.Shutdown(context.Background()); err != nil {
				t.Fatalf("Shutdown(nil) returned error: %v", err)
			}
		})
	}
}

// TestACMEConfig_Validate exercises the validation rules for ACMEConfig.
func TestACMEConfig_Validate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *config.ACMEConfig
		wantErr error
	}{
		{"nil_is_ok", nil, nil},
		{"disabled_is_ok", &config.ACMEConfig{Enabled: false}, nil},
		{
			"missing_addr",
			&config.ACMEConfig{Enabled: true},
			config.ErrACMEMissingHTTPSAddr,
		},
		{
			"missing_external_url",
			&config.ACMEConfig{Enabled: true, HTTPSAddr: ":8443"},
			config.ErrACMEMissingExternalURL,
		},
		{
			"missing_keystore_backend",
			&config.ACMEConfig{Enabled: true, HTTPSAddr: ":8443", ExternalURL: "https://acme.example.com"},
			config.ErrACMEMissingKeystoreBackend,
		},
		{
			"missing_caa_identities",
			&config.ACMEConfig{
				Enabled:         true,
				HTTPSAddr:       ":8443",
				ExternalURL:     "https://acme.example.com",
				KeystoreBackend: "software",
			},
			config.ErrACMEMissingCAAIdentities,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestBuildChallengeMap_Selection verifies that buildChallengeMap registers
// verifiers only for challenge types that have been enabled.
func TestBuildChallengeMap_Selection(t *testing.T) {
	m := buildChallengeMap(config.ACMEChallengesConfig{HTTP01: true, DNS01: false})
	if _, ok := m[common.ChallengeTypeHTTP01]; !ok {
		t.Fatalf("expected http-01 verifier to be registered")
	}
	if _, ok := m[common.ChallengeTypeDNS01]; ok {
		t.Fatalf("expected dns-01 verifier to be absent when disabled")
	}

	m = buildChallengeMap(config.ACMEChallengesConfig{HTTP01: false, DNS01: true})
	if _, ok := m[common.ChallengeTypeHTTP01]; ok {
		t.Fatalf("expected http-01 verifier to be absent when disabled")
	}
	if _, ok := m[common.ChallengeTypeDNS01]; !ok {
		t.Fatalf("expected dns-01 verifier to be registered")
	}

	// enroll-01 / endorse-01 TPM attestation challenges.
	m = buildChallengeMap(config.ACMEChallengesConfig{Enroll01: true, Endorse01: true})
	if _, ok := m[common.ChallengeTypeEnroll01]; !ok {
		t.Fatalf("expected enroll-01 verifier to be registered")
	}
	if _, ok := m[common.ChallengeTypeEndorse01]; !ok {
		t.Fatalf("expected endorse-01 verifier to be registered")
	}
	if _, ok := m[common.ChallengeTypeHTTP01]; ok {
		t.Fatalf("expected http-01 verifier to be absent when only attestation enabled")
	}

	// The enroll-01 verifier rejects a CA that does not implement the TCG
	// verification surface (a nil/placeholder CA fails the type assertion).
	verify := m[common.ChallengeTypeEnroll01]
	if err := verify(nil, nil, "device", "8080", "tok", "ka"); !errors.Is(err, acmesdk.ErrACMEEnrollCAUnsupported) {
		t.Fatalf("enroll-01 with unsupported CA = %v, want ErrACMEEnrollCAUnsupported", err)
	}
}

// stubRestService implements handlers.RestServicer for router-wiring tests.
// Each handler records whether it was invoked so tests can assert that the
// mux routes requests to the expected endpoint.
type stubRestService struct {
	directoryCalled atomic.Bool
	newNonceCalled  atomic.Bool
	newOrderCalled  atomic.Bool
}

func (s *stubRestService) AccountHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) AuthorizationHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) CABundleHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) CertificateHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) ChallengeHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) DirectoryHandler(w http.ResponseWriter, _ *http.Request) {
	s.directoryCalled.Store(true)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"newNonce":   "https://acme.example.com/acme/new-nonce",
		"newAccount": "https://acme.example.com/acme/new-account",
		"newOrder":   "https://acme.example.com/acme/new-order",
		"revokeCert": "https://acme.example.com/acme/revoke-cert",
		"keyChange":  "https://acme.example.com/acme/key-change",
	})
}

func (s *stubRestService) KeyChangeHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) NewAccountHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) NewNonceHandler(w http.ResponseWriter, _ *http.Request) {
	s.newNonceCalled.Store(true)
	w.Header().Set("Replay-Nonce", "test-nonce")
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) NewOrderHandler(w http.ResponseWriter, _ *http.Request) {
	s.newOrderCalled.Store(true)
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) OrderFinalizeHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) OrderHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) OrdersListHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) RevokeCertHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// Compile-time assertion that stubRestService satisfies handlers.RestServicer.
var _ handlers.RestServicer = (*stubRestService)(nil)

// TestBuildACMERouter_DirectoryEndpoint verifies that buildACMERouter
// produces a gorilla/mux router that dispatches GET /acme/directory to the
// DirectoryHandler and returns a valid ACME directory JSON document. This
// exercises the route wiring without requiring a full CA/storage bootstrap.
func TestBuildACMERouter_DirectoryEndpoint(t *testing.T) {
	svc := &stubRestService{}
	router := buildACMERouter(svc, "/acme")

	ts := httptest.NewServer(router)
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/acme/directory")
	if err != nil {
		t.Fatalf("GET /acme/directory: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected HTTP 200, got %d: %s", resp.StatusCode, string(body))
	}
	if !svc.directoryCalled.Load() {
		t.Fatalf("DirectoryHandler was not invoked")
	}

	var directory map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&directory); err != nil {
		t.Fatalf("decode directory: %v", err)
	}
	for _, field := range []string{"newNonce", "newAccount", "newOrder", "revokeCert", "keyChange"} {
		if _, ok := directory[field]; !ok {
			t.Fatalf("expected %q in directory, got %+v", field, directory)
		}
	}
}

// TestBuildACMERouter_RouteMethods verifies that methods are correctly
// enforced on ACME routes. In particular, GET /acme/new-nonce should
// succeed while GET /acme/new-order should be rejected (POST-only).
func TestBuildACMERouter_RouteMethods(t *testing.T) {
	svc := &stubRestService{}
	router := buildACMERouter(svc, "/acme")
	ts := httptest.NewServer(router)
	t.Cleanup(ts.Close)

	// new-nonce accepts GET per RFC 8555.
	resp, err := http.Get(ts.URL + "/acme/new-nonce")
	if err != nil {
		t.Fatalf("GET /acme/new-nonce: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 on GET new-nonce, got %d", resp.StatusCode)
	}
	if !svc.newNonceCalled.Load() {
		t.Fatalf("NewNonceHandler was not invoked")
	}

	// new-order requires POST; GET must be rejected.
	resp, err = http.Get(ts.URL + "/acme/new-order")
	if err != nil {
		t.Fatalf("GET /acme/new-order: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on GET new-order, got %d", resp.StatusCode)
	}
	if svc.newOrderCalled.Load() {
		t.Fatalf("NewOrderHandler should not have been invoked on GET")
	}

	// POST is accepted.
	resp, err = http.Post(ts.URL+"/acme/new-order", "application/jose+json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST /acme/new-order: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 on POST new-order, got %d", resp.StatusCode)
	}
	if !svc.newOrderCalled.Load() {
		t.Fatalf("NewOrderHandler was not invoked on POST")
	}
}

// TestBuildACMETLSConfig_RejectsReuse verifies that the TLS builder rejects
// the reuse_tls option until that support is implemented in a follow-up.
func TestBuildACMETLSConfig_RejectsReuse(t *testing.T) {
	_, err := buildACMETLSConfig(&config.ACMEConfig{ReuseTLS: true})
	if err == nil {
		t.Fatalf("expected error when reuse_tls is set")
	}
}

// TestBuildACMETLSConfig_RejectsUnparseableClientCA proves that a
// client_cas file with no PEM certificate blocks fails with the typed
// ErrACMENoClientCAPEM sentinel, reachable with errors.Is, rather than an
// inline error (#700).
func TestBuildACMETLSConfig_RejectsUnparseableClientCA(t *testing.T) {
	dir := t.TempDir()

	certFile, keyFile := writeTestCertKeyPair(t, dir)

	garbageCA := filepath.Join(dir, "client-ca.pem")
	if err := os.WriteFile(garbageCA, []byte("not a PEM certificate"), 0o600); err != nil {
		t.Fatalf("write garbage client CA: %v", err)
	}

	_, err := buildACMETLSConfig(&config.ACMEConfig{
		TLS: config.ACMETLSConfig{
			CertFile:   certFile,
			KeyFile:    keyFile,
			ClientAuth: "require_and_verify",
			ClientCAs:  []string{garbageCA},
		},
	})
	if err == nil {
		t.Fatal("expected error for a client CA file with no PEM certificates")
	}
	if !errors.Is(err, ErrACMENoClientCAPEM) {
		t.Errorf("err = %v, want errors.Is match against ErrACMENoClientCAPEM", err)
	}
}

// writeTestCertKeyPair writes a minimal self-signed certificate and its
// private key, PEM-encoded, under dir, and returns their paths.
func writeTestCertKeyPair(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "acme-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certFile = filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	return certFile, keyFile
}

// TestBuildClusterPreSignHooks_GatedOff verifies that the SPIFFE URI-SAN hook
// registry is nil when cluster ACME enrollment is not enabled, so ordinary ACME
// issuance registers no cluster-specific pre-sign extensions.
func TestBuildClusterPreSignHooks_GatedOff(t *testing.T) {
	// Cluster disabled entirely.
	if got := buildClusterPreSignHooks(&config.Config{}); got != nil {
		t.Errorf("cluster disabled: got %v, want nil", got)
	}
	// Cluster enabled but ACME enrollment off.
	cfg := &config.Config{Cluster: config.ClusterConfig{Enabled: true}}
	if got := buildClusterPreSignHooks(cfg); got != nil {
		t.Errorf("ACME enrollment off: got %v, want nil", got)
	}
}

// TestBuildClusterPreSignHooks_Enabled verifies that enabling cluster ACME
// enrollment registers exactly one pre-sign hook (the SPIFFE URI-SAN hook).
func TestBuildClusterPreSignHooks_Enabled(t *testing.T) {
	cfg := &config.Config{Cluster: config.ClusterConfig{
		Enabled: true,
		RaftEnrollment: config.RaftEnrollmentConfig{
			ACME: config.RaftACMEEnrollmentConfig{Enabled: true},
		},
	}}
	registry := buildClusterPreSignHooks(cfg)
	if registry == nil {
		t.Fatal("expected a non-nil pre-sign hook registry")
	}
	if got := registry.Count(); got != 1 {
		t.Errorf("registry.Count() = %d, want 1", got)
	}
}
