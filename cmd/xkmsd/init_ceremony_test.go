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

	"github.com/jeremyhahn/go-xkms/pkg/config"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// testNodeConfig returns the *config.Config executeCeremony's single-admin
// path opens the durable qrdb node with: qrdb-backed storage rooted at
// dataDir, and the node's own barrier engaged with the "none" strategy so
// the node auto-unseals unattended and the test needs no SO-pin credential
// plumbing.
func testNodeConfig(dataDir string) *config.Config {
	return &config.Config{
		Storage: config.StorageConfig{Backend: "qrdb", Path: dataDir},
		Barrier: config.BarrierConfig{Enabled: true, Strategy: "none"},
	}
}

// silentLogger returns a slog.Logger that discards all output. Suitable for
// helpers under test that emit log lines we don't want polluting test output.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
}

// buildCeremonyService constructs a ceremony service backed by in-memory
// storage and the same software seal strategy `xkmsd init` uses.
// `officers` may be empty for single-admin mode; supplying it sets the
// matching Threshold automatically (M-of-M).
func buildCeremonyService(t *testing.T, officers []initialize.OfficerConfig) *initialize.CeremonyService {
	t.Helper()

	memBackend := storage.NewMemory()
	barrier, err := seal.NewBarrier(
		silentLogger(),
		memBackend,
		seal.BarrierConfig{RootKeyPath: "barrier/root-key"},
		seal.NewSoftwareStrategy(),
	)
	if err != nil {
		t.Fatalf("seal.NewBarrier: %v", err)
	}

	platformStore, err := seal.NewPlatformStore(memBackend, silentLogger())
	if err != nil {
		t.Fatalf("seal.NewPlatformStore: %v", err)
	}

	credService, err := credentials.New(
		&credentials.Config{Strategy: credentials.StrategyManual},
		platformStore,
		barrier,
		silentLogger(),
	)
	if err != nil {
		t.Fatalf("credentials.New: %v", err)
	}

	threshold := 0
	if len(officers) >= 2 {
		threshold = len(officers)
	}
	cfg := &initialize.CeremonyConfig{
		SOPin:                  "test-so-pin",
		UserPin:                "test-user-pin",
		CredentialSealStrategy: credentials.StrategyManual,
		Threshold:              threshold,
		Officers:               officers,
		Hostname:               "localhost",
	}

	cs, err := initialize.NewCeremonyService(cfg, barrier, credService, silentLogger())
	if err != nil {
		t.Fatalf("initialize.NewCeremonyService: %v", err)
	}
	return cs
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
// newCeremonyCA
// =============================================================================

func TestNewCeremonyCA_Success(t *testing.T) {
	env := &ceremonyEnv{logger: silentLogger(), hostname: "localhost", dataDir: t.TempDir()}
	caInstance, err := newCeremonyCA(context.Background(), env)
	if err != nil {
		t.Fatalf("newCeremonyCA: %v", err)
	}
	if caInstance == nil {
		t.Fatal("newCeremonyCA returned nil CA")
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

// =============================================================================
// executeCeremony — single-admin mode
// =============================================================================

func TestExecuteCeremony_SingleAdmin_WritesArtifacts(t *testing.T) {
	dataDir := t.TempDir()
	env := &ceremonyEnv{
		logger:   silentLogger(),
		hostname: "test.example.com",
		dataDir:  dataDir,
		nodeCfg:  testNodeConfig(dataDir),
	}
	cs := buildCeremonyService(t, nil)

	result, err := executeCeremony(context.Background(), cs, env)
	if err != nil {
		t.Fatalf("executeCeremony: %v", err)
	}
	if result == nil {
		t.Fatal("nil result")
		return
	}
	if result.State != initialize.StateOperational {
		t.Errorf("expected StateOperational, got %s", result.State)
	}
	if result.SPKIPin == "" {
		t.Error("expected non-empty SPKI pin")
	}
	if len(result.CACertPEM) == 0 {
		t.Error("expected non-empty CA cert PEM")
	}

	// CA bundle persisted.
	caBundlePath := filepath.Join(dataDir, "ca-bundle.pem")
	caBundle, err := os.ReadFile(caBundlePath)
	if err != nil {
		t.Fatalf("read ca-bundle.pem: %v", err)
	}
	if string(caBundle) != string(result.CACertPEM) {
		t.Error("persisted CA bundle does not match result")
	}

	// SPKI pin persisted, trailing newline included.
	pinPath := filepath.Join(dataDir, "spki-pin.txt")
	pinBytes, err := os.ReadFile(pinPath)
	if err != nil {
		t.Fatalf("read spki-pin.txt: %v", err)
	}
	want := result.SPKIPin + "\n"
	if string(pinBytes) != want {
		t.Errorf("SPKI pin file mismatch: want %q got %q", want, string(pinBytes))
	}
}

// =============================================================================
// executeCeremony — M-of-N mode
// =============================================================================

func TestExecuteCeremony_MofN_ReachesEnrolling(t *testing.T) {
	dataDir := t.TempDir()
	env := &ceremonyEnv{
		logger:   silentLogger(),
		hostname: "node.example.com",
		dataDir:  dataDir,
	}

	officers := []initialize.OfficerConfig{
		{Username: "officer-a", CSRPEM: generateECDSACSR(t, "officer-a")},
		{Username: "officer-b", CSRPEM: generateECDSACSR(t, "officer-b")},
	}
	cs := buildCeremonyService(t, officers)

	result, err := executeCeremony(context.Background(), cs, env)
	if err != nil {
		t.Fatalf("executeCeremony: %v", err)
	}
	if result.State != initialize.StateEnrolling {
		t.Errorf("expected StateEnrolling, got %s", result.State)
	}
	// CA bundle still persisted.
	if _, err := os.Stat(filepath.Join(dataDir, "ca-bundle.pem")); err != nil {
		t.Errorf("ca-bundle.pem should exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "spki-pin.txt")); err != nil {
		t.Errorf("spki-pin.txt should exist: %v", err)
	}
}

// =============================================================================
// executeCeremony — error propagation
// =============================================================================

func TestExecuteCeremony_AlreadyInitialized(t *testing.T) {
	dataDir := t.TempDir()
	env := &ceremonyEnv{
		logger:   silentLogger(),
		hostname: "localhost",
		dataDir:  dataDir,
		nodeCfg:  testNodeConfig(dataDir),
	}
	cs := buildCeremonyService(t, nil)

	if _, err := executeCeremony(context.Background(), cs, env); err != nil {
		t.Fatalf("first executeCeremony: %v", err)
	}
	// Second invocation must surface the upstream "already initialized"
	// error wrapped as ErrCeremonyInitFailed.
	_, err := executeCeremony(context.Background(), cs, env)
	if err == nil {
		t.Fatal("expected error on re-init")
	}
	if !errors.Is(err, ErrCeremonyInitFailed) {
		t.Errorf("expected ErrCeremonyInitFailed, got %v", err)
	}
}

// =============================================================================
// persistCABundle / persistSPKIPin
// =============================================================================

func TestPersistCABundle_Success(t *testing.T) {
	dir := t.TempDir()
	result := &initialize.InitResult{CACertPEM: []byte("ca-bytes")}
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
	result := &initialize.InitResult{}
	if err := persistCABundle(dir, result); err != nil {
		t.Fatalf("persistCABundle: %v", err)
	}
	// The file must NOT have been created when CACertPEM is empty.
	if _, err := os.Stat(filepath.Join(dir, "ca-bundle.pem")); !os.IsNotExist(err) {
		t.Errorf("ca-bundle.pem should not exist when CACertPEM is empty; err=%v", err)
	}
}

func TestPersistCABundle_BadDataDir(t *testing.T) {
	// Pointing at an existing file forces MkdirAll to fail because the
	// path component is not a directory. /dev/null is reliably present on
	// the test platforms covered by this repo.
	result := &initialize.InitResult{CACertPEM: []byte("x")}
	err := persistCABundle("/dev/null/cannot-mkdir", result)
	if err == nil {
		t.Fatal("expected error for non-directory data dir")
	}
	if !errors.Is(err, ErrCABundleWriteFailed) {
		t.Errorf("expected ErrCABundleWriteFailed, got %v", err)
	}
}

func TestPersistSPKIPin_Success(t *testing.T) {
	dir := t.TempDir()
	result := &initialize.InitResult{SPKIPin: "abc123"}
	if err := persistSPKIPin(dir, result); err != nil {
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
	result := &initialize.InitResult{}
	if err := persistSPKIPin(dir, result); err != nil {
		t.Fatalf("persistSPKIPin: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "spki-pin.txt")); !os.IsNotExist(err) {
		t.Errorf("spki-pin.txt should not exist when SPKIPin is empty; err=%v", err)
	}
}

func TestPersistSPKIPin_BadDataDir(t *testing.T) {
	result := &initialize.InitResult{SPKIPin: "x"}
	err := persistSPKIPin("/dev/null/cannot-mkdir", result)
	if err == nil {
		t.Fatal("expected error for non-directory data dir")
	}
	if !errors.Is(err, ErrSPKIPinWriteFailed) {
		t.Errorf("expected ErrSPKIPinWriteFailed, got %v", err)
	}
}

// =============================================================================
// printCeremonyOutcome — smoke coverage
// =============================================================================

func TestPrintCeremonyOutcome_SingleAdmin(t *testing.T) {
	originalStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = originalStderr })

	env := &ceremonyEnv{dataDir: "/var/lib/xkms"}
	result := &initialize.InitResult{
		State:     initialize.StateOperational,
		SPKIPin:   "deadbeef",
		CACertPEM: []byte("ca"),
	}
	printCeremonyOutcome(env, result)
	_ = w.Close()
	os.Stderr = originalStderr

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	out := string(got)
	for _, want := range []string{"Ceremony Outcome", "deadbeef", "/var/lib/xkms"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q; got:\n%s", want, out)
		}
	}
}

func TestPrintCeremonyOutcome_MofNMentionsClaim(t *testing.T) {
	originalStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = originalStderr })

	env := &ceremonyEnv{dataDir: "/data"}
	result := &initialize.InitResult{
		State:      initialize.StateEnrolling,
		SPKIPin:    "ff",
		CACertPEM:  []byte("ca"),
		ShareCount: 3,
	}
	printCeremonyOutcome(env, result)
	_ = w.Close()
	os.Stderr = originalStderr

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	out := string(got)
	for _, want := range []string{"Shamir shares", "claim-cert", "claim-share"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q; got:\n%s", want, out)
		}
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
// of running preflight before the ceremony changes any state: a planned PIV
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
// ceremony already issues) passes preflight with no hardware attached.
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
