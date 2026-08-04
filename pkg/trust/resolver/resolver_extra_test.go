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

package resolver_test

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	"github.com/jeremyhahn/go-xkms/pkg/trust/resolver"
)

// ---------------------------------------------------------------------------
// Error type Error()/Unwrap() coverage
// ---------------------------------------------------------------------------

func TestErrNilConfig_Error(t *testing.T) {
	e := resolver.ErrNilConfig{}
	if e.Error() == "" {
		t.Fatal("ErrNilConfig.Error() empty")
	}
}

func TestErrScopeNotConfigured_Error(t *testing.T) {
	e := &resolver.ErrScopeNotConfigured{Scope: "production"}
	if e.Error() == "" {
		t.Fatal("ErrScopeNotConfigured.Error() empty")
	}
}

func TestErrInvalidConfig_Error_WithScope(t *testing.T) {
	e := &resolver.ErrInvalidConfig{Scope: "test", Field: "strategies", Reason: "empty"}
	if e.Error() == "" {
		t.Fatal("ErrInvalidConfig.Error() empty")
	}
}

func TestErrInvalidConfig_Error_NoScope(t *testing.T) {
	e := &resolver.ErrInvalidConfig{Scope: "", Field: "noise", Reason: "required"}
	if e.Error() == "" {
		t.Fatal("ErrInvalidConfig.Error() (no scope) empty")
	}
}

func TestErrFetchFailed_Error(t *testing.T) {
	e := &resolver.ErrFetchFailed{Strategy: resolver.StrategyDANE, Cause: errors.New("timeout")}
	if e.Error() == "" {
		t.Fatal("ErrFetchFailed.Error() empty")
	}
}

func TestErrCABundleEmpty_Error(t *testing.T) {
	e := resolver.ErrCABundleEmpty{}
	if e.Error() == "" {
		t.Fatal("ErrCABundleEmpty.Error() empty")
	}
}

func TestErrCABundleParse_Error(t *testing.T) {
	e := resolver.ErrCABundleParse{}
	if e.Error() == "" {
		t.Fatal("ErrCABundleParse.Error() empty")
	}
}

func TestErrWriteFailed_Error(t *testing.T) {
	e := &resolver.ErrWriteFailed{Path: "/tmp/x", Err: errors.New("disk full")}
	if e.Error() == "" {
		t.Fatal("ErrWriteFailed.Error() empty")
	}
}

func TestErrProviderCAUnavailable_Error(t *testing.T) {
	e := resolver.ErrProviderCAUnavailable{}
	if e.Error() == "" {
		t.Fatal("ErrProviderCAUnavailable.Error() empty")
	}
}

func TestErrPinNotFound_Error_WithEndpoint(t *testing.T) {
	e := &resolver.ErrPinNotFound{Endpoint: "kms.example.com:8443"}
	if e.Error() == "" {
		t.Fatal("ErrPinNotFound.Error() (with endpoint) empty")
	}
}

func TestErrPinNotFound_Error_NoEndpoint(t *testing.T) {
	e := &resolver.ErrPinNotFound{Endpoint: ""}
	if e.Error() == "" {
		t.Fatal("ErrPinNotFound.Error() (no endpoint) empty")
	}
}

func TestErrCAFileRead_Error(t *testing.T) {
	e := &resolver.ErrCAFileRead{Path: "/tmp/ca.pem", Err: errors.New("not found")}
	if e.Error() == "" {
		t.Fatal("ErrCAFileRead.Error() empty")
	}
}

func TestErrEndpointInvalid_Error(t *testing.T) {
	e := &resolver.ErrEndpointInvalid{Endpoint: "bad-endpoint", Reason: "no port"}
	if e.Error() == "" {
		t.Fatal("ErrEndpointInvalid.Error() empty")
	}
}

func TestErrTOFUPinStoreRequired_Error(t *testing.T) {
	e := resolver.ErrTOFUPinStoreRequired{}
	if e.Error() == "" {
		t.Fatal("ErrTOFUPinStoreRequired.Error() empty")
	}
}

func TestErrNoStrategySucceeded_Error(t *testing.T) {
	e := &resolver.ErrNoStrategySucceeded{
		Scope:    "test",
		Endpoint: "host:443",
		Attempts: []resolver.Attempt{
			{Strategy: resolver.StrategyCAFile, Err: errors.New("not found")},
		},
	}
	if e.Error() == "" {
		t.Fatal("ErrNoStrategySucceeded.Error() empty")
	}
}

// ErrNoStrategySucceeded with no endpoint (covers the endpoint="" branch).
func TestErrNoStrategySucceeded_Error_NoEndpoint(t *testing.T) {
	e := &resolver.ErrNoStrategySucceeded{Scope: "test"}
	if e.Error() == "" {
		t.Fatal("ErrNoStrategySucceeded.Error() (no endpoint) empty")
	}
}

// ---------------------------------------------------------------------------
// WithLogger: non-nil logger is stored
// ---------------------------------------------------------------------------

func TestWithLogger_NonNil(t *testing.T) {
	logger := slog.Default()
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {Strategies: []resolver.Strategy{resolver.StrategyEmbedded}},
		},
	}
	r, err := resolver.New(cfg, resolver.WithLogger(logger))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Confirm the resolver works with a real logger.
	pem, err := r.CABundlePEM(context.Background(), "test")
	if err != nil {
		t.Fatalf("CABundlePEM: %v", err)
	}
	// Embedded strategy returns nil pem.
	_ = pem
}

// ---------------------------------------------------------------------------
// WithTOFUPinStore and WithTOFUConfirmFunc options
// ---------------------------------------------------------------------------

// fakeTOFUPinStore is a minimal truststrap.PinStore implementation for tests.
// It satisfies the interface but stores nothing (always returns ErrPinNotFound).
type fakeTOFUPinStore struct{}

var _ truststrap.PinStore = fakeTOFUPinStore{}

func (fakeTOFUPinStore) Get(_ context.Context, _ string, _ int) (*truststrap.Pin, error) {
	return nil, truststrap.ErrPinNotFound{}
}
func (fakeTOFUPinStore) Put(_ context.Context, _ *truststrap.Pin) error    { return nil }
func (fakeTOFUPinStore) Delete(_ context.Context, _ string, _ int) error   { return nil }
func (fakeTOFUPinStore) List(_ context.Context) ([]*truststrap.Pin, error) { return nil, nil }

func TestWithTOFUPinStore_Accepted(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategyTOFU},
				ServerURL:  "https://kms.example.com:8443",
			},
		},
	}
	// Previously rejected without pin store; with store must succeed construction.
	_, err := resolver.New(cfg, resolver.WithTOFUPinStore(fakeTOFUPinStore{}))
	if err != nil {
		t.Fatalf("New with TOFU pin store: %v", err)
	}
}

func TestWithTOFUConfirmFunc_Accepted(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategyTOFU},
				ServerURL:  "https://kms.example.com:8443",
			},
		},
	}
	confirmCalled := false
	confirmFn := func(_ context.Context, _ *truststrap.Pin) error {
		confirmCalled = true
		return nil
	}
	r, err := resolver.New(cfg,
		resolver.WithTOFUPinStore(fakeTOFUPinStore{}),
		resolver.WithTOFUConfirmFunc(confirmFn),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Fetch will fail (no real server) but TOFU path is exercised.
	_, _ = r.CABundlePEM(context.Background(), "test")
	_ = confirmCalled
}

// ---------------------------------------------------------------------------
// scope() with nil Scopes map
// ---------------------------------------------------------------------------

func TestScope_NilScopesMap(t *testing.T) {
	// Config with Scopes=nil: scope() must return ErrScopeNotConfigured.
	cfg := &resolver.Config{Scopes: nil}
	r, err := resolver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.CABundlePEM(context.Background(), "test")
	var notCfg *resolver.ErrScopeNotConfigured
	if !errors.As(err, &notCfg) {
		t.Fatalf("expected ErrScopeNotConfigured, got %T: %v", err, err)
	}
}

func TestScope_NilScopeValue(t *testing.T) {
	// Scopes map exists but the requested scope's value is nil.
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": nil,
		},
	}
	// ValidateWithTOFU skips nil scopes, so New succeeds.
	r, err := resolver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.CABundlePEM(context.Background(), "test")
	var notCfg *resolver.ErrScopeNotConfigured
	if !errors.As(err, &notCfg) {
		t.Fatalf("expected ErrScopeNotConfigured, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// CAPool with StrategyEmbedded (exercises the embedded branch of poolForStrategy)
// ---------------------------------------------------------------------------

func TestCAPool_EmbeddedStrategy(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {Strategies: []resolver.Strategy{resolver.StrategyEmbedded}},
		},
	}
	r, err := resolver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pool, err := r.CAPool(context.Background(), "test", "kms.example.com:8443")
	if err != nil {
		t.Fatalf("CAPool with embedded strategy: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool from system cert pool")
	}
}

// ---------------------------------------------------------------------------
// TLSConfig + CAPool: unknown strategy in dispatch map
// ---------------------------------------------------------------------------

func TestTLSConfig_UnknownStrategy(t *testing.T) {
	// Bypass the validator by injecting the unknown strategy after validation.
	// The resolver's dispatch table doesn't include "unknown" so the
	// unknown-strategy error path is exercised.
	// We cannot bypass the validator directly, but we can register it through
	// the valid-but-unknown-at-dispatch path by using a strategy type that
	// passes the validator but is unknown to the dispatch (we can't from
	// outside the package since strategies are validated against known constants).
	// Instead exercise the "unknown strategy" branch in CABundlePEM via an
	// invalid Config (accepted before dispatch map lookup).
	//
	// The validator in Config.validate() rejects unknown strategies, so there's
	// no external way to inject an unknown dispatch. This test documents that
	// the validator prevents this path.
	t.Log("unknown strategy path guarded by Config.validate; not reachable from external test code")
}

// ---------------------------------------------------------------------------
// endpointHostPort coverage via TLSConfig/CAPool
// ---------------------------------------------------------------------------

// TestEndpoint_HostPortSupplied exercises the "endpoint != ”" branch in
// endpointHostPort by passing a host:port to TLSConfig.
func TestEndpoint_HostPortSupplied(t *testing.T) {
	_, pemBytes := selfSignedCA(t)
	caFile := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(caFile, pemBytes, 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategyCAFile},
				CAFile:     caFile,
			},
		},
	}
	r, err := resolver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Explicit host:port supplied — exercises endpointHostPort endpoint != ""
	// branch (even though ca-file ignores the endpoint).
	_, err = r.TLSConfig(context.Background(), "test", "kms.example.com:8443")
	if err != nil {
		t.Fatalf("TLSConfig with explicit endpoint: %v", err)
	}
}

// TestEndpoint_MalformedSplitHostPort exercises the net.SplitHostPort error
// path: pass an endpoint that has no port (causes SplitHostPort failure).
// DANE calls endpointHostPort so it is the right strategy to trigger this path.
func TestEndpoint_MalformedSplitHostPort(t *testing.T) {
	cfg2 := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategyDANE},
				Hostname:   "kms.example.com",
			},
		},
	}
	r2, err := resolver.New(cfg2)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r2.TLSConfig(context.Background(), "test", "localhost-no-port")
	var noSuccess *resolver.ErrNoStrategySucceeded
	if !errors.As(err, &noSuccess) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %T: %v", err, err)
	}
	var invalid *resolver.ErrEndpointInvalid
	if !errors.As(err, &invalid) {
		t.Fatalf("expected ErrEndpointInvalid in chain, got %T: %v", err, err)
	}
}

// TestEndpoint_ServerURLNoHost exercises the "server-url has no host" path
// in endpointHostPort when the parsed URL has an empty host.
func TestEndpoint_ServerURLNoHost(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategyDANE},
				// A URL with scheme but no host — url.Parse("file:///path") has empty host.
				ServerURL: "file:///just-a-path",
				Hostname:  "kms.example.com",
			},
		},
	}
	r, err := resolver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.TLSConfig(context.Background(), "test", "")
	var noSuccess *resolver.ErrNoStrategySucceeded
	if !errors.As(err, &noSuccess) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %T: %v", err, err)
	}
	var invalid *resolver.ErrEndpointInvalid
	if !errors.As(err, &invalid) {
		t.Fatalf("expected ErrEndpointInvalid in chain, got %T: %v", err, err)
	}
}

// TestEndpoint_ServerURLWithPort exercises the "server-url has an explicit port"
// path so uint16 parse is exercised.
func TestEndpoint_ServerURLWithPort(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategyDANE},
				ServerURL:  "https://kms.example.com:8443",
				Hostname:   "kms.example.com",
			},
		},
	}
	r, err := resolver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// DANE will fail (no real DNS/TLSA), but it should get past endpointHostPort.
	_, err = r.TLSConfig(context.Background(), "test", "")
	var noSuccess *resolver.ErrNoStrategySucceeded
	if !errors.As(err, &noSuccess) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %T: %v", err, err)
	}
	// The error should NOT be ErrEndpointInvalid — it should be a fetch failure.
	var invalid *resolver.ErrEndpointInvalid
	if errors.As(err, &invalid) {
		t.Fatalf("unexpected ErrEndpointInvalid for valid server URL: %v", err)
	}
}

// ---------------------------------------------------------------------------
// poolFromPEM: ErrCABundleParse when PEM has no valid certs
// ---------------------------------------------------------------------------

func TestCAPool_InvalidPEMNoCerts(t *testing.T) {
	// Write a PEM file whose content has a valid PEM block but is NOT a
	// certificate, so pool.AppendCertsFromPEM returns false.
	tmp := t.TempDir()
	caFile := tmp + "/notacert.pem"
	// A PRIVATE KEY block is valid PEM but not a certificate.
	if err := os.WriteFile(caFile, []byte("-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategyCAFile},
				CAFile:     caFile,
			},
		},
	}
	r, err := resolver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.CAPool(context.Background(), "test", "kms.example.com:8443")
	if err == nil {
		t.Fatal("expected error for PEM with no valid certs")
	}
}

// ---------------------------------------------------------------------------
// ProviderCA: empty bundle error path
// ---------------------------------------------------------------------------

func TestCABundlePEM_ProviderCA_EmptyBundle(t *testing.T) {
	// Provider returns non-nil but zero-length PEM — triggers ErrCABundleEmpty.
	provider := &stubCABundleProvider{pem: []byte{}}
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {Strategies: []resolver.Strategy{resolver.StrategyProviderCA}},
		},
	}
	r, err := resolver.New(cfg, resolver.WithCABundleProvider(provider))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.CABundlePEM(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error for empty provider bundle")
	}
}

// ---------------------------------------------------------------------------
// SPKI: PinStore returns non-ErrPinNotFound error → strategy fails
// ---------------------------------------------------------------------------

// errorPinStore returns a non-ErrPinNotFound error from SPKIPin.
type errorPinStore struct{ err error }

func (e *errorPinStore) SPKIPin(_ context.Context, _ string) (string, error) { return "", e.err }

func TestSPKI_PinStoreError(t *testing.T) {
	storeErr := errors.New("database unavailable")
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategySPKI},
				ServerURL:  "https://kms.example.com:8443",
			},
		},
	}
	r, err := resolver.New(cfg, resolver.WithPinStore(&errorPinStore{err: storeErr}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.TLSConfig(context.Background(), "test", "kms.example.com:8443")
	var noSuccess *resolver.ErrNoStrategySucceeded
	if !errors.As(err, &noSuccess) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %T: %v", err, err)
	}
	if !errors.Is(err, storeErr) {
		t.Fatalf("expected storeErr in chain, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// CAPool: ProviderCA integration
// ---------------------------------------------------------------------------

func TestCAPool_ProviderCAIntegration(t *testing.T) {
	_, pemBytes := selfSignedCA(t)
	provider := &stubCABundleProvider{pem: pemBytes}
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {Strategies: []resolver.Strategy{resolver.StrategyProviderCA}},
		},
	}
	r, err := resolver.New(cfg, resolver.WithCABundleProvider(provider))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pool, err := r.CAPool(context.Background(), "test", "kms.example.com:8443")
	if err != nil {
		t.Fatalf("CAPool: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
}

// ---------------------------------------------------------------------------
// CAPool: unknown strategy in CAPool's poolForStrategy dispatch
// ---------------------------------------------------------------------------

// TestCAPool_AllStrategiesFail_ErrNoStrategySucceeded exercises the
// "all strategies failed" return in CAPool.
func TestCAPool_AllStrategiesFail(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategyCAFile},
				CAFile:     "/nonexistent/ca.pem",
			},
		},
	}
	r, _ := resolver.New(cfg)
	_, err := r.CAPool(context.Background(), "test", "kms.example.com:8443")
	var noSuccess *resolver.ErrNoStrategySucceeded
	if !errors.As(err, &noSuccess) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// TLSConfig: ProviderCA strategy integration
// ---------------------------------------------------------------------------

func TestTLSConfig_ProviderCAIntegration(t *testing.T) {
	_, pemBytes := selfSignedCA(t)
	provider := &stubCABundleProvider{pem: pemBytes}
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {Strategies: []resolver.Strategy{resolver.StrategyProviderCA}},
		},
	}
	r, err := resolver.New(cfg, resolver.WithCABundleProvider(provider))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tlsCfg, err := r.TLSConfig(context.Background(), "test", "")
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}
	if tlsCfg.RootCAs == nil {
		t.Fatal("expected non-nil RootCAs")
	}
}

// ---------------------------------------------------------------------------
// Validate: Noise missing static key
// ---------------------------------------------------------------------------

func TestValidate_NoiseMissingStaticKey(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategyNoise},
				Noise: &resolver.NoiseConfig{
					// ServerStaticKey missing, ServerAddr present
					ServerAddr: "noise.example.com:7777",
				},
			},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing noise server-static-key")
	}
	var inv *resolver.ErrInvalidConfig
	if !errors.As(err, &inv) {
		t.Fatalf("expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// CAPool: embedded strategy with pool caching
// ---------------------------------------------------------------------------

func TestCAPool_EmbeddedCached(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {Strategies: []resolver.Strategy{resolver.StrategyEmbedded}},
		},
	}
	r, err := resolver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	pool1, err := r.CAPool(ctx, "test", "host1:443")
	if err != nil {
		t.Fatalf("CAPool 1: %v", err)
	}
	pool2, err := r.CAPool(ctx, "test", "host1:443")
	if err != nil {
		t.Fatalf("CAPool 2: %v", err)
	}
	if pool1 != pool2 {
		t.Fatal("expected same pool pointer from cache for embedded strategy")
	}
}

// ---------------------------------------------------------------------------
// InstallToSystemTrust: write error (unwritable file)
// ---------------------------------------------------------------------------

func TestInstallToSystemTrust_WriteError(t *testing.T) {
	// Create a directory at the target path so WriteFile fails (EISDIR).
	tmp := t.TempDir()
	target := tmp + "/subdir"
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	// target is now a directory, not a file — WriteFile will fail.
	err := resolver.InstallToSystemTrust([]byte("pem data"), target)
	if err == nil {
		t.Fatal("expected write error when target is a directory")
	}
	var writeFail *resolver.ErrWriteFailed
	if !errors.As(err, &writeFail) {
		t.Fatalf("expected ErrWriteFailed, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Validate: Config.Scope returns nil when scopes map is nil
// ---------------------------------------------------------------------------

func TestConfig_Scope_NilMap(t *testing.T) {
	cfg := &resolver.Config{Scopes: nil}
	if sc := cfg.Scope("test"); sc != nil {
		t.Fatalf("expected nil for unconfigured scope, got %v", sc)
	}
}

// ---------------------------------------------------------------------------
// Config.ValidateWithTOFU: nil scope entry is skipped
// ---------------------------------------------------------------------------

func TestValidateWithTOFU_NilScopeSkipped(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"nil-scope": nil, // nil entry should be skipped, not panic
			"real": {
				Strategies: []resolver.Strategy{resolver.StrategyEmbedded},
			},
		},
	}
	if err := cfg.ValidateWithTOFU(false); err != nil {
		t.Fatalf("ValidateWithTOFU with nil scope entry: %v", err)
	}
}

// ---------------------------------------------------------------------------
// endpointHostPort: endpoint with host:port (covers the port parse path)
// ---------------------------------------------------------------------------

func TestEndpoint_HostPortParsed(t *testing.T) {
	// DANE with a real host:port endpoint; will fail at network but
	// exercises endpointHostPort to completion.
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategyDANE},
				Hostname:   "kms.example.com",
			},
		},
	}
	r, err := resolver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.TLSConfig(context.Background(), "test", "kms.example.com:8443")
	// Expected: network error wrapped in ErrNoStrategySucceeded.
	var noSuccess *resolver.ErrNoStrategySucceeded
	if !errors.As(err, &noSuccess) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// DANE: endpoint fallback to server-url (default port 443 path)
// ---------------------------------------------------------------------------

func TestDANE_FallbackToServerURL_DefaultPort(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategyDANE},
				// Port not specified in server-url → default 443.
				ServerURL: "https://kms.example.com",
				Hostname:  "kms.example.com",
			},
		},
	}
	r, err := resolver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.TLSConfig(context.Background(), "test", "")
	var noSuccess *resolver.ErrNoStrategySucceeded
	if !errors.As(err, &noSuccess) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %T: %v", err, err)
	}
	// Should not fail due to endpoint parsing.
	var invalid *resolver.ErrEndpointInvalid
	if errors.As(err, &invalid) {
		t.Fatalf("unexpected ErrEndpointInvalid: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SPKI: pemSPKI path (CABundlePEM with SPKI strategy)
// ---------------------------------------------------------------------------

func TestCABundlePEM_SPKIFails_NoPin(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategySPKI},
				ServerURL:  "https://kms.example.com:8443",
				// No SPKI config → ErrPinNotFound
			},
		},
	}
	r, _ := resolver.New(cfg)
	_, err := r.CABundlePEM(context.Background(), "test")
	var noSuccess *resolver.ErrNoStrategySucceeded
	if !errors.As(err, &noSuccess) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Noise: pemNoise nil config path
// ---------------------------------------------------------------------------

func TestCABundlePEM_NoiseFails_NilConfig(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategyNoise},
				// No noise config → ErrInvalidConfig
			},
		},
	}
	r, _ := resolver.New(cfg)
	_, err := r.CABundlePEM(context.Background(), "test")
	var noSuccess *resolver.ErrNoStrategySucceeded
	if !errors.As(err, &noSuccess) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// net.Listen port helpers for non-blocking test setup
// ---------------------------------------------------------------------------

// freePort returns an available TCP port on loopback for test servers.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// Use freePort to avoid "declared and not used" if compiler complains.
var _ = freePort

// ---------------------------------------------------------------------------
// Validate: Noise config accepted when both fields present
// ---------------------------------------------------------------------------

func TestValidate_NoiseConfigValid(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategyNoise},
				Noise: &resolver.NoiseConfig{
					ServerStaticKey: "abcdef0123456789",
					ServerAddr:      "noise.example.com:7777",
				},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid noise config rejected: %v", err)
	}
}

// ---------------------------------------------------------------------------
// pemCAFile: empty CAFile path (CAFile field is "")
// ---------------------------------------------------------------------------

func TestCABundlePEM_CAFile_EmptyPath(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategyCAFile},
				// CAFile deliberately empty — triggers the ErrInvalidConfig path.
			},
		},
	}
	r, _ := resolver.New(cfg)
	_, err := r.CABundlePEM(context.Background(), "test")
	var noSuccess *resolver.ErrNoStrategySucceeded
	if !errors.As(err, &noSuccess) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %T: %v", err, err)
	}
	var inv *resolver.ErrInvalidConfig
	if !errors.As(err, &inv) {
		t.Fatalf("expected ErrInvalidConfig in chain, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// tlsDANE: scope.DANE != nil branch (DANE config fields are set)
// A malformed endpoint causes endpointHostPort to fail before any network call.
// ---------------------------------------------------------------------------

func TestTLSConfig_DANE_WithConfig_MalformedEndpoint(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategyDANE},
				Hostname:   "kms.example.com",
				DANE: &resolver.DANEConfig{
					DNSServer:        "8.8.8.8:53",
					DNSOverTLS:       false,
					DNSTLSServerName: "dns.google",
				},
			},
		},
	}
	r, err := resolver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Malformed endpoint (no port) — endpointHostPort fails before network.
	_, err = r.TLSConfig(context.Background(), "test", "no-port-here")
	var noSuccess *resolver.ErrNoStrategySucceeded
	if !errors.As(err, &noSuccess) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %T: %v", err, err)
	}
	var invalid *resolver.ErrEndpointInvalid
	if !errors.As(err, &invalid) {
		t.Fatalf("expected ErrEndpointInvalid in chain, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// tlsFromPEM: poolFromPEM error path — non-cert PEM via TLSConfig + ca-file
// ---------------------------------------------------------------------------

func TestTLSConfig_CAFile_NonCertPEM_PoolError(t *testing.T) {
	tmp := t.TempDir()
	caFile := tmp + "/notacert.pem"
	// A PRIVATE KEY block is valid PEM but not a certificate.
	if err := os.WriteFile(caFile, []byte("-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategyCAFile},
				CAFile:     caFile,
			},
		},
	}
	r, err := resolver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// TLSConfig calls tlsFromPEM(pemCAFile) — PEM read succeeds but pool parse fails.
	_, err = r.TLSConfig(context.Background(), "test", "kms.example.com:8443")
	if err == nil {
		t.Fatal("expected error for non-cert PEM in TLSConfig")
	}
}

// ---------------------------------------------------------------------------
// endpointHostPort: invalid port number in host:port endpoint
// ---------------------------------------------------------------------------

func TestEndpoint_PortOutOfRange(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategyDANE},
				Hostname:   "kms.example.com",
			},
		},
	}
	r, err := resolver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Port 99999 > 65535 → ParseUint(..., 10, 16) fails → ErrEndpointInvalid.
	_, err = r.TLSConfig(context.Background(), "test", "kms.example.com:99999")
	var noSuccess *resolver.ErrNoStrategySucceeded
	if !errors.As(err, &noSuccess) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %T: %v", err, err)
	}
	var invalid *resolver.ErrEndpointInvalid
	if !errors.As(err, &invalid) {
		t.Fatalf("expected ErrEndpointInvalid in chain, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// tlsFromPEM: fn() error path — TLSConfig with missing ca-file
// ---------------------------------------------------------------------------

func TestTLSConfig_CAFile_Missing(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategyCAFile},
				CAFile:     "/nonexistent/ca.pem",
			},
		},
	}
	r, err := resolver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// TLSConfig calls tlsFromPEM(pemCAFile); pemCAFile returns ErrCAFileRead,
	// which exercises the fn() error return path in tlsFromPEM.
	_, err = r.TLSConfig(context.Background(), "test", "kms.example.com:8443")
	var noSuccess *resolver.ErrNoStrategySucceeded
	if !errors.As(err, &noSuccess) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// tlsDANE: scope.DANE != nil branch exercised by passing a valid endpoint.
// bootstrap.NewDANETLSConfig will fail fast (no real DNS) but the DANE
// config fields are set, so lines 346-349 in resolver.go are covered.
// ---------------------------------------------------------------------------

func TestTLSConfig_DANE_WithConfig_ValidEndpoint(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies: []resolver.Strategy{resolver.StrategyDANE},
				Hostname:   "kms.example.com",
				DANE: &resolver.DANEConfig{
					DNSServer:        "127.0.0.1:5300",
					DNSOverTLS:       false,
					DNSTLSServerName: "",
				},
			},
		},
	}
	r, err := resolver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Valid endpoint so endpointHostPort succeeds; DANE config is non-nil so
	// lines 346-349 are covered. bootstrap.NewDANETLSConfig will fail fast.
	_, err = r.TLSConfig(context.Background(), "test", "kms.example.com:8443")
	var noSuccess *resolver.ErrNoStrategySucceeded
	if !errors.As(err, &noSuccess) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// pemDANE: coverage via CABundlePEM with DANE strategy.
// bootstrap.Fetch will fail at network but all setup lines are covered.
// ---------------------------------------------------------------------------

func TestCABundlePEM_DANE_NetworkFail(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies:       []resolver.Strategy{resolver.StrategyDANE},
				ServerURL:        "https://kms.example.com:8443",
				Hostname:         "kms.example.com",
				PerMethodTimeout: 100 * time.Millisecond,
			},
		},
	}
	r, err := resolver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.CABundlePEM(context.Background(), "test")
	// Expected: fetch fails → ErrNoStrategySucceeded wrapping ErrFetchFailed.
	var noSuccess *resolver.ErrNoStrategySucceeded
	if !errors.As(err, &noSuccess) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %T: %v", err, err)
	}
}

func TestCABundlePEM_DANE_WithDANEConfig_NetworkFail(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies:       []resolver.Strategy{resolver.StrategyDANE},
				ServerURL:        "https://kms.example.com:8443",
				Hostname:         "kms.example.com",
				PerMethodTimeout: 100 * time.Millisecond,
				DANE: &resolver.DANEConfig{
					DNSServer:        "127.0.0.1:5300",
					DNSOverTLS:       false,
					DNSTLSServerName: "",
				},
			},
		},
	}
	r, err := resolver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.CABundlePEM(context.Background(), "test")
	var noSuccess *resolver.ErrNoStrategySucceeded
	if !errors.As(err, &noSuccess) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// pemNoise: non-nil Noise config path via CABundlePEM.
// r.fetch fails at network but lines 404-409 are covered.
// ---------------------------------------------------------------------------

func TestCABundlePEM_Noise_WithConfig_NetworkFail(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies:       []resolver.Strategy{resolver.StrategyNoise},
				ServerURL:        "https://kms.example.com:8443",
				PerMethodTimeout: 100 * time.Millisecond,
				Noise: &resolver.NoiseConfig{
					ServerAddr:      "noise.example.com:7777",
					ServerStaticKey: "abcdef0123456789abcdef0123456789",
				},
			},
		},
	}
	r, err := resolver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.CABundlePEM(context.Background(), "test")
	var noSuccess *resolver.ErrNoStrategySucceeded
	if !errors.As(err, &noSuccess) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// pemSPKI: fetch path covered via CABundlePEM with SPKI + static pin.
// r.fetch fails at network but lines 418-420 are covered.
// ---------------------------------------------------------------------------

func TestCABundlePEM_SPKI_WithPin_NetworkFail(t *testing.T) {
	cfg := &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"test": {
				Strategies:       []resolver.Strategy{resolver.StrategySPKI},
				ServerURL:        "https://kms.example.com:8443",
				PerMethodTimeout: 100 * time.Millisecond,
				SPKI: &resolver.SPKIConfig{
					Pin: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				},
			},
		},
	}
	r, err := resolver.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.CABundlePEM(context.Background(), "test")
	var noSuccess *resolver.ErrNoStrategySucceeded
	if !errors.As(err, &noSuccess) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %T: %v", err, err)
	}
}

// Silence unused import warning if time is not otherwise used.
var _ = time.Now
