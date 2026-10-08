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
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// testNodeConfig returns the *config.Config executeCeremony's single-admin
// path opens the durable qrdb node with: qrdb-backed storage rooted at
// dataDir, and the node's own barrier engaged with the "none" strategy so
// the node auto-unseals unattended and the test needs no SO-pin credential
// plumbing.
func testNodeConfig(dataDir string) *config.Config {
	return &config.Config{
		Datastore: config.DatastoreConfig{Path: dataDir},
		Barrier:   config.BarrierConfig{Enabled: true, Strategy: "none"},
	}
}

// silentLogger returns a slog.Logger that discards all output. Suitable for
// helpers under test that emit log lines we don't want polluting test output.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
}

// generateECDSACSR returns a PEM-encoded ECDSA P-256 CSR with the given CN.
// Mirrors the helper in the existing init_test.go but lives here so the
// ceremony tests don't depend on the other test file's ordering.
func generateECDSACSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificateRequest: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

// =============================================================================
// newBootstrapCA / caArtifacts
// =============================================================================

func TestNewBootstrapCA_Success(t *testing.T) {
	env := &ceremonyEnv{logger: silentLogger(), hostname: "localhost", dataDir: t.TempDir()}
	caInstance, err := newBootstrapCA(context.Background(), env, testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("newBootstrapCA: %v", err)
	}
	if caInstance == nil {
		t.Fatal("newBootstrapCA returned nil CA")
	}
	if !caInstance.IsInitialized() {
		t.Error("CA should be initialized")
	}
	cert, err := caInstance.CACertificate()
	if err != nil {
		t.Fatalf("CACertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("CACertificate returned nil")
		return
	}
	if cert.Subject.CommonName != caCommonName {
		t.Errorf("CN mismatch: want %q got %q", caCommonName, cert.Subject.CommonName)
	}
	if !cert.IsCA {
		t.Error("CA cert IsCA flag must be true")
	}
	// Self-signed root: issuer == subject.
	if cert.Subject.String() != cert.Issuer.String() {
		t.Error("root CA must be self-signed")
	}
}

// TestNewBootstrapCA_StoresCertificateThroughFactory proves the ceremony CA
// keeps its certificate as a DAO entity in the factory it is given: a
// certificate store opened over the same factory finds the root.
func TestNewBootstrapCA_StoresCertificateThroughFactory(t *testing.T) {
	daos := testutil.NewMemoryDAOFactory()
	caInstance, err := newBootstrapCA(context.Background(), &ceremonyEnv{logger: silentLogger()}, daos)
	if err != nil {
		t.Fatalf("newBootstrapCA: %v", err)
	}
	root, err := caInstance.CACertificate()
	if err != nil {
		t.Fatalf("CACertificate: %v", err)
	}

	store, err := certstore.New(&certstore.Config{DAOs: daos})
	if err != nil {
		t.Fatalf("certstore.New: %v", err)
	}
	stored, err := store.GetCertificate(caCommonName)
	if err != nil {
		t.Fatalf("GetCertificate(%q): %v", caCommonName, err)
	}
	if !stored.Equal(root) {
		t.Error("the stored certificate must be the CA's root")
	}
}

// TestNewBootstrapCA_CADatabaseNotServed proves a factory with no store for
// the CA's database fails the ceremony CA with ErrCACertStoreCreateFailed.
func TestNewBootstrapCA_CADatabaseNotServed(t *testing.T) {
	_, err := newBootstrapCA(context.Background(), &ceremonyEnv{logger: silentLogger()}, dao.NewStoreFactory(nil))
	if !errors.Is(err, ErrCACertStoreCreateFailed) {
		t.Fatalf("expected ErrCACertStoreCreateFailed, got %v", err)
	}
	var unavailable *dao.DatabaseUnavailableError
	if !errors.As(err, &unavailable) || unavailable.Database != certstore.DatabaseName {
		t.Errorf("expected the CA database %q reported unavailable, got %v", certstore.DatabaseName, err)
	}
}

func TestCAArtifacts_DerivesBundleAndPin(t *testing.T) {
	caInstance, err := newBootstrapCA(context.Background(), &ceremonyEnv{logger: silentLogger()}, testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("newBootstrapCA: %v", err)
	}
	result, err := caArtifacts(caInstance)
	if err != nil {
		t.Fatalf("caArtifacts: %v", err)
	}
	cert, err := caInstance.CACertificate()
	if err != nil {
		t.Fatalf("CACertificate: %v", err)
	}
	if want := initialize.SPKIPin(cert); result.SPKIPin != want {
		t.Errorf("SPKI pin: want %q got %q", want, result.SPKIPin)
	}
	if len(result.CABundlePEM) == 0 {
		t.Error("expected a non-empty CA bundle")
	}
}

type failingBundleCA struct {
	initialize.CeremonyCA
	bundleErr error
	certErr   error
}

func (c failingBundleCA) CABundle() ([]byte, error) {
	if c.bundleErr != nil {
		return nil, c.bundleErr
	}
	return c.CeremonyCA.CABundle()
}

func (c failingBundleCA) CACertificate() (*x509.Certificate, error) {
	if c.certErr != nil {
		return nil, c.certErr
	}
	return c.CeremonyCA.CACertificate()
}

func TestCAArtifacts_ReadFailures(t *testing.T) {
	caInstance, err := newBootstrapCA(context.Background(), &ceremonyEnv{logger: silentLogger()}, testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("newBootstrapCA: %v", err)
	}
	boom := errors.New("boom")
	for name, ca := range map[string]initialize.CeremonyCA{
		"bundle":      failingBundleCA{CeremonyCA: caInstance, bundleErr: boom},
		"certificate": failingBundleCA{CeremonyCA: caInstance, certErr: boom},
	} {
		if _, err := caArtifacts(ca); !errors.Is(err, ErrCABundleReadFailed) {
			t.Errorf("%s: expected ErrCABundleReadFailed, got %v", name, err)
		}
	}
}

// =============================================================================
// executeBootstrap
// =============================================================================

func TestExecuteBootstrap_WritesArtifacts(t *testing.T) {
	dataDir := t.TempDir()
	env := &ceremonyEnv{
		logger:   silentLogger(),
		hostname: "test.example.com",
		dataDir:  dataDir,
		nodeCfg:  testNodeConfig(dataDir),
	}

	result, err := executeBootstrap(context.Background(), env)
	if err != nil {
		t.Fatalf("executeBootstrap: %v", err)
	}
	if result.SPKIPin == "" {
		t.Error("expected non-empty SPKI pin")
	}
	if len(result.CABundlePEM) == 0 {
		t.Error("expected non-empty CA bundle PEM")
	}

	// CA bundle persisted.
	caBundle, err := os.ReadFile(filepath.Join(dataDir, "ca-bundle.pem"))
	if err != nil {
		t.Fatalf("read ca-bundle.pem: %v", err)
	}
	if string(caBundle) != string(result.CABundlePEM) {
		t.Error("persisted CA bundle does not match result")
	}

	// SPKI pin persisted, trailing newline included.
	pinBytes, err := os.ReadFile(filepath.Join(dataDir, "spki-pin.txt"))
	if err != nil {
		t.Fatalf("read spki-pin.txt: %v", err)
	}
	if want := result.SPKIPin + "\n"; string(pinBytes) != want {
		t.Errorf("SPKI pin file mismatch: want %q got %q", want, string(pinBytes))
	}
}

func TestExecuteBootstrap_NodeConfigRequired(t *testing.T) {
	env := &ceremonyEnv{logger: silentLogger(), hostname: "localhost", dataDir: t.TempDir()}
	if _, err := executeBootstrap(context.Background(), env); !errors.Is(err, ErrNodeConfigRequired) {
		t.Fatalf("expected ErrNodeConfigRequired, got %v", err)
	}
}

// =============================================================================
// persistCABundle / persistSPKIPin
// =============================================================================

func TestPersistCABundle_Success(t *testing.T) {
	dir := t.TempDir()
	result := &bootstrapResult{CABundlePEM: []byte("ca-bytes")}
	if err := persistCABundle(dir, result); err != nil {
		t.Fatalf("persistCABundle: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "ca-bundle.pem"))
	if err != nil {
		t.Fatalf("read ca-bundle.pem: %v", err)
	}
	if string(got) != "ca-bytes" {
		t.Errorf("ca-bundle content: want %q got %q", "ca-bytes", string(got))
	}
}

func TestPersistCABundle_EmptyIsNoop(t *testing.T) {
	dir := t.TempDir()
	if err := persistCABundle(dir, &bootstrapResult{}); err != nil {
		t.Fatalf("persistCABundle: %v", err)
	}
	// The file must NOT have been created when the bundle is empty.
	if _, err := os.Stat(filepath.Join(dir, "ca-bundle.pem")); !os.IsNotExist(err) {
		t.Errorf("ca-bundle.pem should not exist when the bundle is empty; err=%v", err)
	}
}

func TestPersistCABundle_BadDataDir(t *testing.T) {
	// Pointing at an existing file forces MkdirAll to fail because the
	// path component is not a directory. /dev/null is reliably present on
	// the test platforms covered by this repo.
	err := persistCABundle("/dev/null/cannot-mkdir", &bootstrapResult{CABundlePEM: []byte("x")})
	if err == nil {
		t.Fatal("expected error for non-directory data dir")
	}
	if !errors.Is(err, ErrCABundleWriteFailed) {
		t.Errorf("expected ErrCABundleWriteFailed, got %v", err)
	}
}

func TestPersistSPKIPin_Success(t *testing.T) {
	dir := t.TempDir()
	if err := persistSPKIPin(dir, &bootstrapResult{SPKIPin: "abc123"}); err != nil {
		t.Fatalf("persistSPKIPin: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "spki-pin.txt"))
	if err != nil {
		t.Fatalf("read spki-pin.txt: %v", err)
	}
	if string(got) != "abc123\n" {
		t.Errorf("pin file content: want %q got %q", "abc123\n", string(got))
	}
}

func TestPersistSPKIPin_EmptyIsNoop(t *testing.T) {
	dir := t.TempDir()
	if err := persistSPKIPin(dir, &bootstrapResult{}); err != nil {
		t.Fatalf("persistSPKIPin: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "spki-pin.txt")); !os.IsNotExist(err) {
		t.Errorf("spki-pin.txt should not exist when SPKIPin is empty; err=%v", err)
	}
}

func TestPersistSPKIPin_BadDataDir(t *testing.T) {
	err := persistSPKIPin("/dev/null/cannot-mkdir", &bootstrapResult{SPKIPin: "x"})
	if err == nil {
		t.Fatal("expected error for non-directory data dir")
	}
	if !errors.Is(err, ErrSPKIPinWriteFailed) {
		t.Errorf("expected ErrSPKIPinWriteFailed, got %v", err)
	}
}

// =============================================================================
// printBootstrapOutcome — smoke coverage
// =============================================================================

// captureStderr runs fn with os.Stderr redirected and returns what it wrote.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	originalStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = originalStderr })

	fn()
	_ = w.Close()
	os.Stderr = originalStderr

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return string(got)
}

func TestPrintBootstrapOutcome_ReportsArtifacts(t *testing.T) {
	env := &ceremonyEnv{dataDir: "/var/lib/xkms"}
	result := &bootstrapResult{SPKIPin: "deadbeef", CABundlePEM: []byte("ca")}
	out := captureStderr(t, func() { printBootstrapOutcome(env, result) })
	for _, want := range []string{"Bootstrap Outcome", "deadbeef", "/var/lib/xkms"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q; got:\n%s", want, out)
		}
	}
}

// TestPrintBootstrapOutcome_ListsEnrolledFactors proves the "Login factors:"
// summary line (printEnrolledFactors, invoked via printBootstrapOutcome's
// defer) lists every factor the bootstrap enrolled.
func TestPrintBootstrapOutcome_ListsEnrolledFactors(t *testing.T) {
	env := &ceremonyEnv{
		dataDir: "/var/lib/xkms",
		enrolledFactors: []qrdbsdk.AdminEnrollmentResult{
			{Factor: "passkey"},
			{Factor: "totp"},
		},
	}
	out := captureStderr(t, func() { printBootstrapOutcome(env, &bootstrapResult{}) })
	if !strings.Contains(out, "Login factors: passkey, totp") {
		t.Errorf("expected output to list enrolled factors \"passkey, totp\"; got:\n%s", out)
	}
}

// =============================================================================
// preflightAdminFactors
// =============================================================================

// TestPreflightAdminFactors_NilPlanIsANoOp proves the probe-only guarantee
// documented on preflightAdminFactors: with no --admin-factor plan there is
// nothing to preflight, so the ceremony proceeds without opening any
// registry.
func TestPreflightAdminFactors_NilPlanIsANoOp(t *testing.T) {
	env := &ceremonyEnv{logger: silentLogger()}
	if err := preflightAdminFactors(context.Background(), env); err != nil {
		t.Fatalf("preflightAdminFactors(nil plan) = %v, want nil", err)
	}
}

// TestPreflightAdminFactors_RefusesAPlanItCannotEnroll proves the whole point
// of running preflight before the bootstrap changes any state: a planned PIV
// factor with no PIV hardware handler configured must be refused up front,
// costing the operator one retry instead of an initialized barrier behind a
// half-enrolled administrator.
func TestPreflightAdminFactors_RefusesAPlanItCannotEnroll(t *testing.T) {
	plan, err := qrdbsdk.NewAdminEnrollmentPlan([]qrdbsdk.AdminFactor{qrdbsdk.FactorPIV})
	if err != nil {
		t.Fatalf("NewAdminEnrollmentPlan: %v", err)
	}
	env := &ceremonyEnv{logger: silentLogger(), enrollmentPlan: plan}

	if err := preflightAdminFactors(context.Background(), env); err == nil {
		t.Fatal("preflightAdminFactors accepted a PIV plan with no PIV hardware configured")
	}
}

// TestPreflightAdminFactors_AcceptsAPlanItCanEnroll proves the success side:
// an mTLS-only plan (the baseline, backed by the admin certificate the
// bootstrap already issues) passes preflight with no hardware attached.
func TestPreflightAdminFactors_AcceptsAPlanItCanEnroll(t *testing.T) {
	plan, err := qrdbsdk.NewAdminEnrollmentPlan([]qrdbsdk.AdminFactor{qrdbsdk.FactorMTLS})
	if err != nil {
		t.Fatalf("NewAdminEnrollmentPlan: %v", err)
	}
	env := &ceremonyEnv{
		logger:         silentLogger(),
		enrollmentPlan: plan,
		adminCertPEM:   generateECDSACSR(t, "administrator"),
	}

	if err := preflightAdminFactors(context.Background(), env); err != nil {
		t.Fatalf("preflightAdminFactors(mtls plan) = %v, want nil", err)
	}
}
