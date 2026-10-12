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

package server

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
	"math/big"
	"testing"
	"time"

	noiseboot "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
)

// These tests run in BOTH builds and assert the same invariants in each. That
// is deliberate: the property under test is "the listener offers whatever suite
// this binary can run", and a test that only held under one set of build tags
// could not distinguish that from "the listener offers Noise". Run the package
// with -tags fips to exercise the FIPS half.

// testBundler is the CA bundle source the bootstrap listener serves. The
// handshake, not the bundle, is what these tests exercise, but the server
// parses what it is given, so the bundle has to be a real certificate.
type testBundler struct{ pem []byte }

func (b testBundler) CABundle() ([]byte, error) { return b.pem, nil }

// newTestBundler builds a self-signed P-256 CA certificate. P-256 with
// SHA-256 keeps the fixture itself approved, so the bundle is not what fails
// when this test runs under -tags fips.
func newTestBundler(t *testing.T) testBundler {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "xkms bootstrap test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	return testBundler{pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func newSuiteTestServer(t *testing.T, noiseCfg config.NoiseBootstrapConfig) *Server {
	t.Helper()
	return &Server{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		config: &config.Config{
			Bootstrap: config.BootstrapConfig{Noise: noiseCfg},
		},
	}
}

// TestLoadBootstrapKeys_AlwaysOffersApprovedSuite is the core of go-xkms#269:
// the approved suite is available in every build, so the listener must always
// come away with a P-256 key to offer it with. Under -tags fips this is the
// only suite there is, and before this change the loader gave up before
// reaching it.
func TestLoadBootstrapKeys_AlwaysOffersApprovedSuite(t *testing.T) {
	s := newSuiteTestServer(t, config.NoiseBootstrapConfig{})

	keys, err := s.loadBootstrapKeys()
	if err != nil {
		t.Fatalf("loadBootstrapKeys: %v", err)
	}
	defer keys.destroy()

	if keys.p256 == nil {
		t.Fatal("no P-256 key loaded: the approved suite is available in every build")
	}
	if len(keys.p256.PublicBytes()) != bootstrap.P256PublicKeySize {
		t.Fatalf("P-256 public key is %d bytes, want %d",
			len(keys.p256.PublicBytes()), bootstrap.P256PublicKeySize)
	}
}

// TestLoadBootstrapKeys_NoiseFollowsBuild asserts the Noise key is loaded
// exactly when this binary can run Noise -- present in a normal build, absent
// under -tags fips -- rather than being skipped or demanded unconditionally.
func TestLoadBootstrapKeys_NoiseFollowsBuild(t *testing.T) {
	s := newSuiteTestServer(t, config.NoiseBootstrapConfig{})

	keys, err := s.loadBootstrapKeys()
	if err != nil {
		t.Fatalf("loadBootstrapKeys: %v", err)
	}
	defer keys.destroy()

	noiseRunnable := bootstrap.EnsureSuiteAvailable(bootstrap.SuiteNoiseNK) == nil
	if noiseRunnable && keys.noise == nil {
		t.Fatal("Noise is runnable in this build but no Noise key was loaded")
	}
	if !noiseRunnable && keys.noise != nil {
		t.Fatal("Noise is not runnable in this build but a Noise key was loaded")
	}
}

// TestBootstrapListener_CompletesApprovedHandshake is the end-to-end proof that
// a build has a WORKING bootstrap handshake and not merely a compiling one: the
// keys the server loads are handed to a real listener, a real client runs the
// approved handshake against it, and the CA bundle comes back over the
// encrypted channel.
//
// Under -tags fips this is go-xkms#269's acceptance criterion. Before the fix
// the listener was never constructed at all in that build, because loading its
// only key failed.
func TestBootstrapListener_CompletesApprovedHandshake(t *testing.T) {
	s := newSuiteTestServer(t, config.NoiseBootstrapConfig{})

	bundler := newTestBundler(t)

	keys, err := s.loadBootstrapKeys()
	if err != nil {
		t.Fatalf("loadBootstrapKeys: %v", err)
	}
	defer keys.destroy()

	// Exactly the configuration startNoiseBootstrap builds, minus the timeouts
	// and the goroutine that owns it.
	srv, err := bootstrap.NewNoiseServer(&bootstrap.NoiseServerConfig{
		ListenAddr:    "127.0.0.1:0",
		StaticKey:     keys.noise,
		P256StaticKey: keys.p256,
		CABundler:     bundler,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewNoiseServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Stop(stopCtx)
	})

	client, err := noiseboot.NewClient(&noiseboot.ClientConfig{
		ServerAddr: srv.Addr().String(),
		// Provisioned with the responder's public point, and pinned to the
		// approved suite so this test cannot pass by silently running Noise.
		ServerP256StaticKey: keys.p256.PublicBytes(),
		Suite:               bootstrap.SuiteP256AESGCM,
		ConnectTimeout:      5 * time.Second,
		OperationTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("approved-suite handshake failed: %v", err)
	}

	resp, err := client.GetCABundle(ctx, "", "")
	if err != nil {
		t.Fatalf("GetCABundle over the approved suite: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("server returned an error response: %s", resp.Error)
	}
	if resp.BundlePEM != string(bundler.pem) {
		t.Fatalf("bundle round-trip mismatch:\n got %q\nwant %q", resp.BundlePEM, bundler.pem)
	}
}

// TestLoadBootstrapKeys_NoSuiteAvailable covers the error path a deployment
// hits when its build can run nothing: the failure must be a typed
// ErrNoBootstrapSuite naming both suites, raised while the listener is being
// configured, and must still reach bootstrap.ErrSuiteUnavailable through
// errors.Is so a caller can classify it.
func TestLoadBootstrapKeys_NoSuiteAvailable(t *testing.T) {
	refusal := func(byte) error {
		return errors.Join(bootstrap.ErrSuiteUnavailable, errors.New("refused for the test"))
	}
	original := ensureSuiteAvailable
	ensureSuiteAvailable = refusal
	t.Cleanup(func() { ensureSuiteAvailable = original })

	s := newSuiteTestServer(t, config.NoiseBootstrapConfig{})

	keys, err := s.loadBootstrapKeys()
	if keys != nil {
		keys.destroy()
		t.Fatal("keys were returned even though no suite is available")
	}

	var noSuite *ErrNoBootstrapSuite
	if !errors.As(err, &noSuite) {
		t.Fatalf("error is %T (%v), want *ErrNoBootstrapSuite", err, err)
	}
	if noSuite.Noise == nil || noSuite.P256 == nil {
		t.Fatalf("both rejection reasons must be recorded, got Noise=%v P256=%v",
			noSuite.Noise, noSuite.P256)
	}
	if !errors.Is(err, bootstrap.ErrSuiteUnavailable) {
		t.Fatal("errors.Is must reach bootstrap.ErrSuiteUnavailable through Unwrap")
	}
}

// noiseRunnable reports whether this binary can run the Noise_NK suite. It is
// false in a FIPS build, by either mechanism: the `fips` build tag, which
// compiles go-truststrap's X25519 out, and GOFIPS140 with GODEBUG=fips140=only,
// where crypto/ecdh refuses X25519 at run time.
func noiseRunnable() bool {
	return bootstrap.EnsureSuiteAvailable(bootstrap.SuiteNoiseNK) == nil
}

// requireNoiseRefused asserts the contract that REPLACES a Noise key test in a
// build that cannot run Noise: the loader must refuse and return no key.
//
// This is an assertion, not a skip. A Noise-key test cannot express its own
// intent in a build with no Noise, but "the loader quietly hands back a key
// anyway" is a real regression worth failing on, and it is the one this branch
// still catches. The refusal's identity is deliberately not asserted: under the
// `fips` tag it is go-truststrap's ErrFIPSUnsupported, while under
// GODEBUG=fips140=only it is crypto/ecdh's own refusal, and both are correct.
func requireNoiseRefused(t *testing.T, s *Server) {
	t.Helper()

	key, err := s.loadNoiseStaticKey()
	if key != nil {
		key.Destroy()
	}
	require.Error(t, err, "a build that cannot run Noise must refuse to load a Noise key")
	require.Nil(t, key, "a build that cannot run Noise must return no Noise key")
}
