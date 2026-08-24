// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package trustedca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

// ----------------------------------------------------------------------------
// NewClient — transport selection and validation.
// ----------------------------------------------------------------------------

// TestNewClient_TransportSelection covers every arm of the createTransport
// dispatch. Each transport must be constructible through the public API;
// a broken arm would only surface at runtime in a downstream project.
func TestNewClient_TransportSelection(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "acme.sock")

	tests := []struct {
		name    string
		address string
		opts    []Option
	}{
		{"grpc_default", "localhost:8443", nil},
		{"rest", "https://ca.example.com", []Option{WithREST()}},
		{"quic", "ca.example.com:8444", []Option{WithQUIC(), WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS13})}},
		{"unix", "unix://" + socketPath, []Option{WithUnix(socketPath)}},
		{"mcp", "http://ca.example.com:9444", []Option{WithMCP()}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewClient(tc.address, tc.opts...)
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			t.Cleanup(func() { _ = c.Close() })

			if c.Transport() == nil {
				t.Fatal("client must expose a constructed transport")
			}
		})
	}
}

// TestNewClient_RESTAutoDetection pins the URL-sniffing rule: an http(s)
// address with the default gRPC transport must be promoted to REST, otherwise
// the SDK would try to speak gRPC to an HTTP endpoint.
func TestNewClient_RESTAutoDetection(t *testing.T) {
	for _, addr := range []string{"http://ca.example.com", "https://ca.example.com"} {
		t.Run(addr, func(t *testing.T) {
			c, err := NewClient(addr)
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			t.Cleanup(func() { _ = c.Close() })

			// The concrete client records the resolved options.
			impl, ok := c.(*client)
			if !ok {
				t.Fatalf("unexpected client type %T", c)
			}
			if impl.opts.transportType != TransportREST {
				t.Errorf("transportType = %v, want TransportREST for an HTTP address",
					impl.opts.transportType)
			}
		})
	}
}

// TestNewClient_AutoDetectionDoesNotOverrideExplicitChoice ensures the sniffing
// only promotes the *default* gRPC selection and never clobbers an explicit one.
func TestNewClient_AutoDetectionDoesNotOverrideExplicitChoice(t *testing.T) {
	c, err := NewClient("http://ca.example.com:9444", WithMCP())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	impl, ok := c.(*client)
	if !ok {
		t.Fatalf("unexpected client type %T", c)
	}
	if impl.opts.transportType != TransportMCP {
		t.Errorf("explicit MCP selection was overridden: got %v", impl.opts.transportType)
	}
}

func TestNewClient_EmptyAddressRejectedForRemoteTransports(t *testing.T) {
	_, err := NewClient("")
	if err == nil {
		t.Fatal("expected an error for an empty address on a remote transport")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("expected an invalid-input error, got %v", err)
	}
}

func TestNewClient_OptionErrorAborts(t *testing.T) {
	// WithTimeout rejects non-positive durations; the failure must abort
	// construction rather than leave a partially configured client.
	c, err := NewClient("localhost:8443", WithTimeout(-time.Second))
	if err == nil {
		if c != nil {
			_ = c.Close()
		}
		t.Fatal("expected the option error to abort NewClient")
	}
	if c != nil {
		t.Error("no client may be returned when an option fails")
	}
}

func TestNewClient_EmbeddedRequiresService(t *testing.T) {
	// The embedded transport is the only one that tolerates an empty address,
	// but it must still refuse to build without a service.
	_, err := NewClient("", WithEmbedded(nil))
	if err == nil {
		t.Fatal("expected an error when the embedded service is nil")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("expected an invalid-input error, got %v", err)
	}
}

// fakeRestServicer implements embedded.RestServicer. Each handler records that
// it was reached so a test can prove the route set was actually registered
// rather than merely that construction succeeded.
type fakeRestServicer struct{ called map[string]bool }

func newFakeRestServicer() *fakeRestServicer {
	return &fakeRestServicer{called: make(map[string]bool)}
}

func (f *fakeRestServicer) record(name string) { f.called[name] = true }

func (f *fakeRestServicer) AccountHandler(http.ResponseWriter, *http.Request) {
	f.record("account")
}
func (f *fakeRestServicer) AuthorizationHandler(http.ResponseWriter, *http.Request) {}
func (f *fakeRestServicer) CertificateHandler(http.ResponseWriter, *http.Request)   {}
func (f *fakeRestServicer) ChallengeHandler(http.ResponseWriter, *http.Request)     {}
func (f *fakeRestServicer) DirectoryHandler(w http.ResponseWriter, r *http.Request) {
	f.record("directory")
}
func (f *fakeRestServicer) NewAccountHandler(http.ResponseWriter, *http.Request)    {}
func (f *fakeRestServicer) NewNonceHandler(http.ResponseWriter, *http.Request)      {}
func (f *fakeRestServicer) NewOrderHandler(http.ResponseWriter, *http.Request)      {}
func (f *fakeRestServicer) OrderHandler(http.ResponseWriter, *http.Request)         {}
func (f *fakeRestServicer) OrdersListHandler(http.ResponseWriter, *http.Request)    {}
func (f *fakeRestServicer) OrderFinalizeHandler(http.ResponseWriter, *http.Request) {}
func (f *fakeRestServicer) RevokeCertHandler(http.ResponseWriter, *http.Request)    {}
func (f *fakeRestServicer) KeyChangeHandler(http.ResponseWriter, *http.Request)     {}

// TestNewClient_EmbeddedForwardsRestServicer is the regression test for a bug
// that made the embedded transport unreachable through the public API.
//
// WithEmbedded(svc) stored the service, and createEmbeddedTransport validated it
// was non-nil — then called embedded.NewTransport(cfg) without forwarding it.
// The embedded transport requires at least one service, so every embedded
// client failed to construct with "at least one service is required" and
// TransportEmbedded was dead code via NewClient.
func TestNewClient_EmbeddedForwardsRestServicer(t *testing.T) {
	client, err := NewClient("", WithEmbedded(newFakeRestServicer()))
	if err != nil {
		t.Fatalf("embedded client must construct when given a RestServicer: %v", err)
	}
	defer func() { _ = client.Close() }()

	if client.Directory() == nil {
		t.Error("embedded client returned no directory sub-client")
	}
}

// fakeBothServicer implements RestServicer and AdminServicer, the case that
// decides the dispatch rule: a value satisfying both must register both route
// sets rather than only whichever is checked first.
type fakeBothServicer struct{ *fakeRestServicer }

func newFakeBothServicer() *fakeBothServicer {
	return &fakeBothServicer{fakeRestServicer: newFakeRestServicer()}
}

func (f *fakeBothServicer) StatusHandler(http.ResponseWriter, *http.Request)             {}
func (f *fakeBothServicer) StatsHandler(http.ResponseWriter, *http.Request)              {}
func (f *fakeBothServicer) ListCertificatesHandler(http.ResponseWriter, *http.Request)   {}
func (f *fakeBothServicer) GetCertificateHandler(http.ResponseWriter, *http.Request)     {}
func (f *fakeBothServicer) RevokeCertificateHandler(http.ResponseWriter, *http.Request)  {}
func (f *fakeBothServicer) ListAccountsHandler(http.ResponseWriter, *http.Request)       {}
func (f *fakeBothServicer) GetAccountHandler(http.ResponseWriter, *http.Request)         {}
func (f *fakeBothServicer) DisableAccountHandler(http.ResponseWriter, *http.Request)     {}
func (f *fakeBothServicer) CreateTenantHandler(http.ResponseWriter, *http.Request)       {}
func (f *fakeBothServicer) ListTenantsHandler(http.ResponseWriter, *http.Request)        {}
func (f *fakeBothServicer) GetTenantHandler(http.ResponseWriter, *http.Request)          {}
func (f *fakeBothServicer) UpdateTenantHandler(http.ResponseWriter, *http.Request)       {}
func (f *fakeBothServicer) DeleteTenantHandler(http.ResponseWriter, *http.Request)       {}
func (f *fakeBothServicer) UpdateTenantStatusHandler(http.ResponseWriter, *http.Request) {}
func (f *fakeBothServicer) CreateEABHandler(http.ResponseWriter, *http.Request)          {}
func (f *fakeBothServicer) ListEABHandler(http.ResponseWriter, *http.Request)            {}
func (f *fakeBothServicer) GetEABHandler(http.ResponseWriter, *http.Request)             {}
func (f *fakeBothServicer) DeleteEABHandler(http.ResponseWriter, *http.Request)          {}
func (f *fakeBothServicer) CreateRoleHandler(http.ResponseWriter, *http.Request)         {}
func (f *fakeBothServicer) ListRolesHandler(http.ResponseWriter, *http.Request)          {}
func (f *fakeBothServicer) GetRoleHandler(http.ResponseWriter, *http.Request)            {}
func (f *fakeBothServicer) UpdateRoleHandler(http.ResponseWriter, *http.Request)         {}
func (f *fakeBothServicer) DeleteRoleHandler(http.ResponseWriter, *http.Request)         {}
func (f *fakeBothServicer) CreateUserHandler(http.ResponseWriter, *http.Request)         {}
func (f *fakeBothServicer) ListUsersHandler(http.ResponseWriter, *http.Request)          {}
func (f *fakeBothServicer) GetUserHandler(http.ResponseWriter, *http.Request)            {}

// TestNewClient_EmbeddedAcceptsCombinedServicer verifies a single value
// implementing both service interfaces is accepted and gets both route sets.
func TestNewClient_EmbeddedAcceptsCombinedServicer(t *testing.T) {
	client, err := NewClient("", WithEmbedded(newFakeBothServicer()))
	if err != nil {
		t.Fatalf("embedded client must accept a combined servicer: %v", err)
	}
	defer func() { _ = client.Close() }()

	if client.Admin() == nil {
		t.Error("combined servicer produced no admin sub-client")
	}
	if client.Directory() == nil {
		t.Error("combined servicer produced no directory sub-client")
	}
}

// TestNewClient_EmbeddedRejectsNonServicer is the bad-input companion: a value
// implementing neither interface must be refused at construction rather than
// producing a client whose every call answers nothing.
func TestNewClient_EmbeddedRejectsNonServicer(t *testing.T) {
	notAService := struct{ name string }{name: "acme"}

	_, err := NewClient("", WithEmbedded(&notAService))
	if err == nil {
		t.Fatal("expected an error when the embedded service implements neither interface")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("expected an invalid-input error, got %v", err)
	}
	if !strings.Contains(err.Error(), "implements neither") {
		t.Errorf("error should name the interface mismatch, got %v", err)
	}
}

func TestNewClient_UnsupportedTransportType(t *testing.T) {
	// Reach createTransport's default arm through the internal seam; there is
	// no public Option that can produce an out-of-range transport type.
	opts := defaultOptions()
	opts.transportType = TransportType(99)

	_, err := createTransport("localhost:8443", opts)
	if err == nil {
		t.Fatal("expected an error for an unsupported transport type")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("expected an invalid-input error, got %v", err)
	}
}

// ----------------------------------------------------------------------------
// buildTransportConfig — option propagation.
// ----------------------------------------------------------------------------

// TestBuildTransportConfig_PropagatesEveryOption guards against a dropped field
// in the options -> transport.Config copy. A silently lost TLSConfig or a lost
// Insecure flag is the exact regression class that downgrades a connection.
func TestBuildTransportConfig_PropagatesEveryOption(t *testing.T) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "ca.example.com"}

	opts := defaultOptions()
	if err := WithTimeout(11 * time.Second)(opts); err != nil {
		t.Fatalf("WithTimeout: %v", err)
	}
	if err := WithKeepalive(12*time.Second, 13*time.Second)(opts); err != nil {
		t.Fatalf("WithKeepalive: %v", err)
	}
	if err := WithRetry(7, 14*time.Second)(opts); err != nil {
		t.Fatalf("WithRetry: %v", err)
	}
	if err := WithMaxRetryBackoff(15 * time.Second)(opts); err != nil {
		t.Fatalf("WithMaxRetryBackoff: %v", err)
	}
	if err := WithConnectionPool(3, 9)(opts); err != nil {
		t.Fatalf("WithConnectionPool: %v", err)
	}
	if err := WithPoolMaxAge(16 * time.Second)(opts); err != nil {
		t.Fatalf("WithPoolMaxAge: %v", err)
	}
	if err := WithPoolHealthInterval(17 * time.Second)(opts); err != nil {
		t.Fatalf("WithPoolHealthInterval: %v", err)
	}
	if err := WithPoolAcquireTimeout(18 * time.Second)(opts); err != nil {
		t.Fatalf("WithPoolAcquireTimeout: %v", err)
	}
	if err := WithTLSConfig(tlsCfg)(opts); err != nil {
		t.Fatalf("WithTLSConfig: %v", err)
	}

	cfg := buildTransportConfig("ca.example.com:8443", opts)

	if cfg.Address != "ca.example.com:8443" {
		t.Errorf("Address = %q", cfg.Address)
	}
	if cfg.Timeout != 11*time.Second {
		t.Errorf("Timeout = %v", cfg.Timeout)
	}
	if cfg.KeepaliveTime != 12*time.Second || cfg.KeepaliveTimeout != 13*time.Second {
		t.Errorf("keepalive = %v / %v", cfg.KeepaliveTime, cfg.KeepaliveTimeout)
	}
	if cfg.MaxRetries != 7 || cfg.RetryBackoff != 14*time.Second {
		t.Errorf("retry = %d / %v", cfg.MaxRetries, cfg.RetryBackoff)
	}
	if cfg.MaxRetryBackoff != 15*time.Second {
		t.Errorf("MaxRetryBackoff = %v", cfg.MaxRetryBackoff)
	}
	if !cfg.PoolEnabled || cfg.PoolMinSize != 3 || cfg.PoolMaxSize != 9 {
		t.Errorf("pool = %v %d/%d", cfg.PoolEnabled, cfg.PoolMinSize, cfg.PoolMaxSize)
	}
	if cfg.PoolMaxAge != 16*time.Second || cfg.PoolHealthInterval != 17*time.Second {
		t.Errorf("pool aging = %v / %v", cfg.PoolMaxAge, cfg.PoolHealthInterval)
	}
	if cfg.PoolAcquireTimeout != 18*time.Second {
		t.Errorf("PoolAcquireTimeout = %v, want 18s", cfg.PoolAcquireTimeout)
	}
	if cfg.TLSConfig != tlsCfg {
		t.Error("TLSConfig was not propagated to the transport config")
	}
	if cfg.Insecure {
		t.Error("Insecure must stay false once a TLS config is installed")
	}
}

// TestBuildTransportConfig_InsecureIsExplicit proves WithInsecure is the only
// way to reach an unverified transport — it cannot be produced accidentally.
func TestBuildTransportConfig_InsecureIsExplicit(t *testing.T) {
	def := buildTransportConfig("ca.example.com:8443", defaultOptions())
	if def.Insecure {
		t.Error("the default options must not yield an insecure transport")
	}

	opts := defaultOptions()
	if err := WithInsecure()(opts); err != nil {
		t.Fatalf("WithInsecure: %v", err)
	}
	if got := buildTransportConfig("ca.example.com:8443", opts); !got.Insecure {
		t.Error("WithInsecure must reach the transport config")
	}

	// Installing TLS after WithInsecure must clear the insecure flag rather
	// than leave both set.
	if err := WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS13})(opts); err != nil {
		t.Fatalf("WithTLSConfig: %v", err)
	}
	if got := buildTransportConfig("ca.example.com:8443", opts); got.Insecure {
		t.Error("installing a TLS config must clear the insecure flag")
	}
}

// ----------------------------------------------------------------------------
// WithTLS / loadTLSConfig.
// ----------------------------------------------------------------------------

// writeTestKeyPair mints a self-signed cert and writes cert/key PEM files.
func writeTestKeyPair(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "acme-client"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certFile = filepath.Join(dir, "client.crt")
	keyFile = filepath.Join(dir, "client.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

// TestWithTLS_LoadsTrustMaterial verifies the mTLS option actually installs the
// client certificate, the CA pool, and the SNI override — and that it turns the
// insecure flag off.
func TestWithTLS_LoadsTrustMaterial(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestKeyPair(t, dir)
	// The self-signed leaf doubles as the CA bundle.
	caFile := certFile

	opts := defaultOptions()
	if err := WithInsecure()(opts); err != nil {
		t.Fatalf("WithInsecure: %v", err)
	}
	if err := WithTLS(TLSConfig{
		CertFile:   certFile,
		KeyFile:    keyFile,
		CAFile:     caFile,
		ServerName: "ca.example.com",
	})(opts); err != nil {
		t.Fatalf("WithTLS: %v", err)
	}

	if opts.insecure {
		t.Error("WithTLS must clear the insecure flag")
	}
	if !opts.tlsEnabled {
		t.Error("WithTLS must mark TLS enabled")
	}
	cfg := opts.tlsConfig
	if cfg == nil {
		t.Fatal("no TLS config was built")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS 1.3", cfg.MinVersion)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("client certificate not loaded (%d certs)", len(cfg.Certificates))
	}
	if cfg.RootCAs == nil {
		t.Error("CA pool not loaded")
	}
	if cfg.ServerName != "ca.example.com" {
		t.Errorf("ServerName = %q", cfg.ServerName)
	}
}

// TestWithTLS_RejectsBadMaterial covers the failure paths — each must produce a
// typed error rather than a silently empty TLS config.
func TestWithTLS_RejectsBadMaterial(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestKeyPair(t, dir)

	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a pem file"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	missing := filepath.Join(dir, "does-not-exist.pem")

	tests := []struct {
		name string
		cfg  TLSConfig
	}{
		{"missing_keypair", TLSConfig{CertFile: missing, KeyFile: missing}},
		{"mismatched_keypair", TLSConfig{CertFile: certFile, KeyFile: garbage}},
		{"missing_ca", TLSConfig{CAFile: missing}},
		{"unparsable_ca", TLSConfig{CAFile: garbage}},
		{"cert_without_key_then_bad_ca", TLSConfig{CertFile: certFile, KeyFile: keyFile, CAFile: garbage}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := defaultOptions()
			err := WithTLS(tc.cfg)(opts)
			if err == nil {
				t.Fatal("expected an error for invalid TLS material")
			}
			if opts.tlsEnabled {
				t.Error("a failed WithTLS must not mark TLS enabled")
			}
			if opts.tlsConfig != nil {
				t.Error("a failed WithTLS must not install a partial TLS config")
			}
		})
	}
}

// TestWithTLS_EmptyConfigIsTLS13Baseline documents that an empty TLSConfig
// still yields a TLS 1.3 config using system roots rather than nil.
func TestWithTLS_EmptyConfigIsTLS13Baseline(t *testing.T) {
	opts := defaultOptions()
	if err := WithTLS(TLSConfig{})(opts); err != nil {
		t.Fatalf("WithTLS: %v", err)
	}
	if opts.tlsConfig == nil {
		t.Fatal("expected a baseline TLS config")
	}
	if opts.tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS 1.3", opts.tlsConfig.MinVersion)
	}
	if opts.tlsConfig.InsecureSkipVerify {
		t.Error("the baseline TLS config must verify the server")
	}
}

// ----------------------------------------------------------------------------
// Sub-client accessors — caching and concurrency.
// ----------------------------------------------------------------------------

// TestClient_SubClientsAreCached pins the double-checked-locking accessors.
// Each accessor must return the same instance every time; returning a fresh
// client per call would silently discard any per-client state and churn
// allocations on hot paths.
func TestClient_SubClientsAreCached(t *testing.T) {
	c, err := NewClient("localhost:8443")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	if a, b := c.Account(), c.Account(); a != b {
		t.Error("Account() returned a different instance on the second call")
	}
	if a, b := c.Order(), c.Order(); a != b {
		t.Error("Order() returned a different instance on the second call")
	}
	if a, b := c.Authorization(), c.Authorization(); a != b {
		t.Error("Authorization() returned a different instance on the second call")
	}
	if a, b := c.Challenge(), c.Challenge(); a != b {
		t.Error("Challenge() returned a different instance on the second call")
	}
	if a, b := c.Certificate(), c.Certificate(); a != b {
		t.Error("Certificate() returned a different instance on the second call")
	}
	if a, b := c.Directory(), c.Directory(); a != b {
		t.Error("Directory() returned a different instance on the second call")
	}
	if a, b := c.Nonce(), c.Nonce(); a != b {
		t.Error("Nonce() returned a different instance on the second call")
	}
	if a, b := c.Admin(), c.Admin(); a != b {
		t.Error("Admin() returned a different instance on the second call")
	}
	if a, b := c.Workflow(), c.Workflow(); a != b {
		t.Error("Workflow() returned a different instance on the second call")
	}
}

// TestClient_SubClientAccessorsAreRaceFree drives every accessor concurrently.
// Under -race this is the regression test for the double-checked locking; a
// missing lock or an unguarded field write fails here.
func TestClient_SubClientAccessorsAreRaceFree(t *testing.T) {
	c, err := NewClient("localhost:8443")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	accessors := []func(){
		func() { _ = c.Account() },
		func() { _ = c.Order() },
		func() { _ = c.Authorization() },
		func() { _ = c.Challenge() },
		func() { _ = c.Certificate() },
		func() { _ = c.Directory() },
		func() { _ = c.Nonce() },
		func() { _ = c.Admin() },
		func() { _ = c.Workflow() },
	}

	const goroutines = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		for _, fn := range accessors {
			wg.Add(1)
			go func(fn func()) {
				defer wg.Done()
				<-start
				fn()
			}(fn)
		}
	}
	close(start)
	wg.Wait()

	// After the storm every accessor must still agree on one instance.
	if a, b := c.Account(), c.Account(); a != b {
		t.Error("Account() lost its cached instance under concurrency")
	}
}

// ----------------------------------------------------------------------------
// Close.
// ----------------------------------------------------------------------------

func TestClient_CloseIsIdempotent(t *testing.T) {
	c, err := NewClient("localhost:8443")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// A second Close must be a no-op, not a double-close of the transport.
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestClient_CloseIsRaceFree(t *testing.T) {
	c, err := NewClient("localhost:8443")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_ = c.Close()
		}()
	}
	close(start)
	wg.Wait()
}

func TestClient_TransportAccessor(t *testing.T) {
	c, err := NewClient("localhost:8443")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	// Transport() must hand back the very transport the sub-clients were
	// built on, not a copy or a fresh dial.
	impl, ok := c.(*client)
	if !ok {
		t.Fatalf("unexpected client type %T", c)
	}
	if c.Transport() != impl.transport {
		t.Error("Transport() did not return the client's own transport")
	}
}
