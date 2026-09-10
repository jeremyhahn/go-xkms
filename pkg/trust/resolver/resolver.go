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

package resolver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
	"sync"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
)

// defaultEndpointPort is assumed when neither the caller's endpoint nor
// the scope's server-url carries an explicit port.
const defaultEndpointPort = uint16(443)

// Resolver resolves trust material for a (scope, endpoint) pair by
// walking the scope's ordered strategy chain and returning the first
// success.
type Resolver interface {
	// TLSConfig returns a *tls.Config whose certificate verification is
	// anchored by the first strategy in the scope chain that can produce
	// one. endpoint is the intended peer in "host:port" form; when empty,
	// the scope's server-url is used.
	TLSConfig(ctx context.Context, scope string, endpoint string) (*tls.Config, error)

	// CAPool returns an *x509.CertPool holding the CA bundle the first
	// successful strategy established. Successful pools are cached per
	// (scope, endpoint).
	CAPool(ctx context.Context, scope string, endpoint string) (*x509.CertPool, error)

	// CABundlePEM returns the raw PEM CA bundle for the scope. For the
	// embedded strategy it returns (nil, nil): the OS trust store is
	// authoritative and there is nothing to install.
	CABundlePEM(ctx context.Context, scope string) ([]byte, error)
}

// PinStore supplies per-endpoint SPKI pins captured during enrollment.
// A store with no pin for the endpoint returns *ErrPinNotFound so the
// resolver can fall back to the scope's static pin.
type PinStore interface {
	SPKIPin(ctx context.Context, endpoint string) (string, error)
}

// CABundleProvider supplies a CA bundle PEM for the provider-ca strategy.
type CABundleProvider interface {
	CABundle(ctx context.Context) ([]byte, error)
}

// Option configures optional resolver collaborators.
type Option func(*resolver)

// WithLogger sets the slog logger used for strategy WARN/DEBUG messages.
// When nil, slog.Default() is used.
func WithLogger(logger *slog.Logger) Option {
	return func(r *resolver) {
		if logger != nil {
			r.logger = logger
		}
	}
}

// WithPinStore injects a per-endpoint SPKI pin source. Endpoint pins
// take precedence over the scope's static pin.
func WithPinStore(store PinStore) Option {
	return func(r *resolver) {
		r.pinStore = store
	}
}

// WithCABundleProvider injects the CA bundle source required by the
// provider-ca strategy.
func WithCABundleProvider(provider CABundleProvider) Option {
	return func(r *resolver) {
		r.providerCA = provider
	}
}

// WithTOFUPinStore injects the TOFU pin persistence store required by
// the tofu strategy.
func WithTOFUPinStore(store truststrap.PinStore) Option {
	return func(r *resolver) {
		r.tofuPinStore = store
	}
}

// WithTOFUConfirmFunc injects an optional confirmation hook called before
// a newly captured TOFU pin is persisted. Returning an error aborts the
// bootstrap and prevents pin storage.
func WithTOFUConfirmFunc(fn func(ctx context.Context, pin *truststrap.Pin) error) Option {
	return func(r *resolver) {
		r.tofuConfirmFunc = fn
	}
}

// tlsStrategyFunc produces a *tls.Config for one strategy.
type tlsStrategyFunc func(ctx context.Context, scope *ScopeConfig, endpoint string) (*tls.Config, error)

// pemStrategyFunc produces a raw CA bundle PEM for one strategy.
type pemStrategyFunc func(ctx context.Context, scope *ScopeConfig, endpoint string) ([]byte, error)

// poolKey identifies a cached CA pool.
type poolKey struct {
	scope    string
	endpoint string
}

// poolEntry is a cached CA pool plus the PEM it was built from.
type poolEntry struct {
	pool *x509.CertPool
	pem  []byte
}

// resolver is the production Resolver implementation.
type resolver struct {
	config          *Config
	logger          *slog.Logger
	pinStore        PinStore
	providerCA      CABundleProvider
	tofuPinStore    truststrap.PinStore
	tofuConfirmFunc func(ctx context.Context, pin *truststrap.Pin) error
	tlsDispatch     map[Strategy]tlsStrategyFunc
	pemDispatch     map[Strategy]pemStrategyFunc
	cache           sync.Map // poolKey -> *poolEntry
}

// Compile-time interface check.
var _ Resolver = (*resolver)(nil)

// New validates the configuration and constructs a Resolver.
//
// When the tofu strategy is listed in any scope and no WithTOFUPinStore
// option is provided, New returns ErrTOFUPinStoreRequired.
func New(cfg *Config, opts ...Option) (Resolver, error) {
	if cfg == nil {
		return nil, ErrNilConfig{}
	}

	r := &resolver{
		config: cfg,
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(r)
	}

	// Validate including tofu-store presence.
	if err := cfg.ValidateWithTOFU(r.tofuPinStore != nil); err != nil {
		return nil, err
	}

	r.tlsDispatch = map[Strategy]tlsStrategyFunc{
		StrategyDANE:       r.tlsDANE,
		StrategyNoise:      r.tlsFromPEM(r.pemNoise),
		StrategySPKI:       r.tlsSPKI,
		StrategyEmbedded:   r.tlsEmbedded,
		StrategyCAFile:     r.tlsFromPEM(r.pemCAFile),
		StrategyProviderCA: r.tlsFromPEM(r.pemProviderCA),
		StrategyTOFU:       r.tlsTOFU,
	}
	r.pemDispatch = map[Strategy]pemStrategyFunc{
		StrategyDANE:       r.pemDANE,
		StrategyNoise:      r.pemNoise,
		StrategySPKI:       r.pemSPKI,
		StrategyEmbedded:   r.pemEmbedded,
		StrategyCAFile:     r.pemCAFile,
		StrategyProviderCA: r.pemProviderCA,
		StrategyTOFU:       r.pemTOFU,
	}
	return r, nil
}

// TLSConfig walks the scope chain and returns the first strategy's
// *tls.Config.
func (r *resolver) TLSConfig(ctx context.Context, scopeName string, endpoint string) (*tls.Config, error) {
	scope, err := r.scope(scopeName)
	if err != nil {
		return nil, err
	}

	attempts := make([]Attempt, 0, len(scope.Strategies))
	for _, strategy := range scope.Strategies {
		fn, ok := r.tlsDispatch[strategy]
		if !ok {
			attempts = append(attempts, Attempt{
				Strategy: strategy,
				Err:      &ErrInvalidConfig{Scope: scopeName, Field: "strategies", Reason: "unknown strategy: " + string(strategy)},
			})
			continue
		}
		tlsCfg, stratErr := fn(ctx, scope, endpoint)
		if stratErr != nil {
			r.logger.Warn("trust resolver: strategy failed",
				slog.String("scope", scopeName),
				slog.String("strategy", string(strategy)),
				slog.Any("error", stratErr))
			attempts = append(attempts, Attempt{Strategy: strategy, Err: stratErr})
			continue
		}
		r.logger.Debug("trust resolver: strategy succeeded",
			slog.String("scope", scopeName),
			slog.String("strategy", string(strategy)))
		return tlsCfg, nil
	}
	return nil, &ErrNoStrategySucceeded{Scope: scopeName, Endpoint: endpoint, Attempts: attempts}
}

// CAPool walks the scope chain and returns the first strategy's CA pool,
// caching successful results per (scope, endpoint).
func (r *resolver) CAPool(ctx context.Context, scopeName string, endpoint string) (*x509.CertPool, error) {
	key := poolKey{scope: scopeName, endpoint: endpoint}
	if cached, ok := r.cache.Load(key); ok {
		return cached.(*poolEntry).pool, nil
	}

	scope, err := r.scope(scopeName)
	if err != nil {
		return nil, err
	}

	attempts := make([]Attempt, 0, len(scope.Strategies))
	for _, strategy := range scope.Strategies {
		pool, pem, stratErr := r.poolForStrategy(ctx, scope, scopeName, strategy, endpoint)
		if stratErr != nil {
			r.logger.Warn("trust resolver: strategy failed",
				slog.String("scope", scopeName),
				slog.String("strategy", string(strategy)),
				slog.Any("error", stratErr))
			attempts = append(attempts, Attempt{Strategy: strategy, Err: stratErr})
			continue
		}
		r.logger.Debug("trust resolver: strategy succeeded",
			slog.String("scope", scopeName),
			slog.String("strategy", string(strategy)))
		r.cache.Store(key, &poolEntry{pool: pool, pem: pem})
		return pool, nil
	}
	return nil, &ErrNoStrategySucceeded{Scope: scopeName, Endpoint: endpoint, Attempts: attempts}
}

// CABundlePEM walks the scope chain and returns the first strategy's raw
// CA bundle PEM. The embedded strategy returns (nil, nil) by design: the
// OS trust store already holds the bundle.
func (r *resolver) CABundlePEM(ctx context.Context, scopeName string) ([]byte, error) {
	scope, err := r.scope(scopeName)
	if err != nil {
		return nil, err
	}

	attempts := make([]Attempt, 0, len(scope.Strategies))
	for _, strategy := range scope.Strategies {
		fn, ok := r.pemDispatch[strategy]
		if !ok {
			attempts = append(attempts, Attempt{
				Strategy: strategy,
				Err:      &ErrInvalidConfig{Scope: scopeName, Field: "strategies", Reason: "unknown strategy: " + string(strategy)},
			})
			continue
		}
		pem, stratErr := fn(ctx, scope, "")
		if stratErr != nil {
			r.logger.Warn("trust resolver: strategy failed",
				slog.String("scope", scopeName),
				slog.String("strategy", string(strategy)),
				slog.Any("error", stratErr))
			attempts = append(attempts, Attempt{Strategy: strategy, Err: stratErr})
			continue
		}
		r.logger.Debug("trust resolver: strategy succeeded",
			slog.String("scope", scopeName),
			slog.String("strategy", string(strategy)))
		return pem, nil
	}
	return nil, &ErrNoStrategySucceeded{Scope: scopeName, Attempts: attempts}
}

// scope returns the ScopeConfig or ErrScopeNotConfigured.
func (r *resolver) scope(name string) (*ScopeConfig, error) {
	if r.config.Scopes == nil {
		return nil, &ErrScopeNotConfigured{Scope: name}
	}
	sc, ok := r.config.Scopes[name]
	if !ok || sc == nil {
		return nil, &ErrScopeNotConfigured{Scope: name}
	}
	return sc, nil
}

// poolForStrategy builds a CA pool for one strategy. The embedded
// strategy returns the system pool with nil PEM.
func (r *resolver) poolForStrategy(ctx context.Context, scope *ScopeConfig, scopeName string, strategy Strategy, endpoint string) (*x509.CertPool, []byte, error) {
	if strategy == StrategyEmbedded {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, nil, &ErrFetchFailed{Strategy: strategy, Cause: err}
		}
		return pool, nil, nil
	}

	fn, ok := r.pemDispatch[strategy]
	if !ok {
		return nil, nil, &ErrInvalidConfig{
			Scope:  scopeName,
			Field:  "strategies",
			Reason: "unknown strategy: " + string(strategy),
		}
	}
	pem, err := fn(ctx, scope, endpoint)
	if err != nil {
		return nil, nil, err
	}
	pool, err := poolFromPEM(pem)
	if err != nil {
		return nil, nil, err
	}
	return pool, pem, nil
}

// tlsDANE builds a DANE/TLSA-verified *tls.Config for the endpoint.
func (r *resolver) tlsDANE(ctx context.Context, scope *ScopeConfig, endpoint string) (*tls.Config, error) {
	host, port, err := endpointHostPort(scope, endpoint)
	if err != nil {
		return nil, err
	}
	cfg := &bootstrap.DANEConfig{Hostname: scope.Hostname}
	if scope.DANE != nil {
		cfg.DNSServer = scope.DANE.DNSServer
		cfg.DNSOverTLS = scope.DANE.DNSOverTLS
		cfg.DNSTLSServerName = scope.DANE.DNSTLSServerName
	}
	return bootstrap.NewDANETLSConfig(ctx, cfg, host, port)
}

// tlsSPKI builds an SPKI-pinned *tls.Config.
func (r *resolver) tlsSPKI(ctx context.Context, scope *ScopeConfig, endpoint string) (*tls.Config, error) {
	pin, err := r.spkiPin(ctx, scope, endpoint)
	if err != nil {
		return nil, err
	}
	return bootstrap.NewSPKIPinTLSConfig(pin)
}

// tlsTOFU builds a trust-on-first-use *tls.Config keyed by the endpoint:
// the first connection captures and persists the leaf's SPKI pin, every
// later one must present it. This is the endpoint verifier the strategy's
// own documentation describes; the PEM path (pemTOFU) keeps fetching a CA
// bundle, the same split dane and spki already have (#139).
func (r *resolver) tlsTOFU(ctx context.Context, scope *ScopeConfig, endpoint string) (*tls.Config, error) {
	if r.tofuPinStore == nil {
		return nil, ErrTOFUPinStoreRequired{}
	}
	host, port, err := endpointHostPort(scope, endpoint)
	if err != nil {
		return nil, err
	}
	return bootstrap.NewTOFUTLSConfig(ctx, r.tofuPinStore,
		net.JoinHostPort(host, strconv.Itoa(int(port))), r.tofuConfirmFunc)
}

// tlsEmbedded returns a *tls.Config that verifies against the OS trust
// store (nil RootCAs selects the system pool).
func (r *resolver) tlsEmbedded(_ context.Context, _ *ScopeConfig, _ string) (*tls.Config, error) {
	return &tls.Config{MinVersion: tls.VersionTLS12}, nil
}

// tlsFromPEM adapts a PEM strategy into a TLS strategy by loading the
// bundle into a dedicated root pool.
func (r *resolver) tlsFromPEM(fn pemStrategyFunc) tlsStrategyFunc {
	return func(ctx context.Context, scope *ScopeConfig, endpoint string) (*tls.Config, error) {
		pem, err := fn(ctx, scope, endpoint)
		if err != nil {
			return nil, err
		}
		pool, err := poolFromPEM(pem)
		if err != nil {
			return nil, err
		}
		return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
	}
}

// pemDANE fetches the CA bundle over a DANE-verified channel.
func (r *resolver) pemDANE(ctx context.Context, scope *ScopeConfig, _ string) ([]byte, error) {
	cfg := r.fetchConfig(scope, bootstrap.ModeDANE)
	cfg.DANE = &bootstrap.DANEConfig{Hostname: scope.Hostname}
	if scope.DANE != nil {
		cfg.DANE.DNSServer = scope.DANE.DNSServer
		cfg.DANE.DNSOverTLS = scope.DANE.DNSOverTLS
		cfg.DANE.DNSTLSServerName = scope.DANE.DNSTLSServerName
	}
	return r.fetch(ctx, cfg, StrategyDANE)
}

// pemNoise fetches the CA bundle over a Noise_NK channel.
func (r *resolver) pemNoise(ctx context.Context, scope *ScopeConfig, _ string) ([]byte, error) {
	if scope.Noise == nil {
		return nil, &ErrInvalidConfig{
			Field:  "noise",
			Reason: "noise configuration is required for the noise strategy",
		}
	}
	cfg := r.fetchConfig(scope, bootstrap.ModeNoise)
	cfg.Noise = &bootstrap.NoiseConfig{
		ServerAddr:          scope.Noise.ServerAddr,
		ServerStaticKey:     scope.Noise.ServerStaticKey,
		ServerP256StaticKey: scope.Noise.ServerP256StaticKey,
	}
	return r.fetch(ctx, cfg, StrategyNoise)
}

// pemSPKI fetches the CA bundle over an SPKI-pinned TLS channel.
func (r *resolver) pemSPKI(ctx context.Context, scope *ScopeConfig, endpoint string) ([]byte, error) {
	pin, err := r.spkiPin(ctx, scope, endpoint)
	if err != nil {
		return nil, err
	}
	cfg := r.fetchConfig(scope, bootstrap.ModeSPKI)
	cfg.SPKI = &bootstrap.SPKIConfig{Pin: pin}
	return r.fetch(ctx, cfg, StrategySPKI)
}

// pemEmbedded returns (nil, nil): the ISO-embedded OS trust store is
// authoritative and there is no bundle to fetch or install.
func (r *resolver) pemEmbedded(_ context.Context, _ *ScopeConfig, _ string) ([]byte, error) {
	return nil, nil
}

// pemCAFile reads the scope's CA bundle file from disk.
func (r *resolver) pemCAFile(_ context.Context, scope *ScopeConfig, _ string) ([]byte, error) {
	if scope.CAFile == "" {
		return nil, &ErrInvalidConfig{
			Field:  "ca-file",
			Reason: "ca-file path is required for the ca-file strategy",
		}
	}
	pem, err := os.ReadFile(scope.CAFile)
	if err != nil {
		return nil, &ErrCAFileRead{Path: scope.CAFile, Err: err}
	}
	if len(pem) == 0 {
		return nil, ErrCABundleEmpty{}
	}
	return pem, nil
}

// pemProviderCA returns the injected CA bundle provider's bundle.
func (r *resolver) pemProviderCA(ctx context.Context, _ *ScopeConfig, _ string) ([]byte, error) {
	if r.providerCA == nil {
		return nil, ErrProviderCAUnavailable{}
	}
	pem, err := r.providerCA.CABundle(ctx)
	if err != nil {
		return nil, &ErrFetchFailed{Strategy: StrategyProviderCA, Cause: err}
	}
	if len(pem) == 0 {
		return nil, ErrCABundleEmpty{}
	}
	return pem, nil
}

// pemTOFU fetches the CA bundle using the TOFU strategy.
func (r *resolver) pemTOFU(ctx context.Context, scope *ScopeConfig, _ string) ([]byte, error) {
	if r.tofuPinStore == nil {
		return nil, ErrTOFUPinStoreRequired{}
	}
	cfg := r.fetchConfig(scope, bootstrap.ModeTOFU)
	cfg.TOFU = &bootstrap.TOFUConfig{
		PinStore:    r.tofuPinStore,
		ConfirmFunc: r.tofuConfirmFunc,
	}
	return r.fetch(ctx, cfg, StrategyTOFU)
}

// fetchConfig projects the scope's shared fields onto the bootstrap config
// for a single-mode fetch.
func (r *resolver) fetchConfig(scope *ScopeConfig, mode bootstrap.Mode) bootstrap.Config {
	return bootstrap.Config{
		Mode:             mode,
		ServerURL:        scope.ServerURL,
		BundlePath:       scope.BundlePath,
		PerMethodTimeout: scope.PerMethodTimeout,
		Logger:           r.logger,
	}
}

// fetch runs the bootstrap fetch and normalizes errors.
func (r *resolver) fetch(ctx context.Context, cfg bootstrap.Config, strategy Strategy) ([]byte, error) {
	bundle, err := bootstrap.Fetch(ctx, cfg)
	if err != nil {
		return nil, &ErrFetchFailed{Strategy: strategy, Cause: err}
	}
	if bundle == nil || len(bundle.PEM) == 0 {
		return nil, ErrCABundleEmpty{}
	}
	return bundle.PEM, nil
}

// spkiPin resolves the SPKI pin for an endpoint: the PinStore's
// per-endpoint pin takes precedence, falling back to the scope's static
// pin. A PinStore miss (ErrPinNotFound) is not fatal; any other store
// error is.
func (r *resolver) spkiPin(ctx context.Context, scope *ScopeConfig, endpoint string) (string, error) {
	if r.pinStore != nil && endpoint != "" {
		pin, err := r.pinStore.SPKIPin(ctx, endpoint)
		if err == nil && pin != "" {
			return pin, nil
		}
		if err != nil {
			var notFound *ErrPinNotFound
			if !errors.As(err, &notFound) {
				return "", err
			}
		}
	}
	if scope.SPKI != nil && scope.SPKI.Pin != "" {
		return scope.SPKI.Pin, nil
	}
	return "", &ErrPinNotFound{Endpoint: endpoint}
}

// endpointHostPort derives the peer host and port from the caller's
// endpoint ("host:port") or, when empty, from the scope's server-url.
func endpointHostPort(scope *ScopeConfig, endpoint string) (string, uint16, error) {
	if endpoint != "" {
		host, portStr, err := net.SplitHostPort(endpoint)
		if err != nil {
			return "", 0, &ErrEndpointInvalid{Endpoint: endpoint, Reason: err.Error()}
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return "", 0, &ErrEndpointInvalid{Endpoint: endpoint, Reason: "invalid port: " + err.Error()}
		}
		return host, uint16(port), nil
	}

	if scope.ServerURL == "" {
		return "", 0, &ErrEndpointInvalid{
			Endpoint: "",
			Reason:   "no endpoint given and scope server-url is empty",
		}
	}
	parsed, err := url.Parse(scope.ServerURL)
	if err != nil {
		return "", 0, &ErrEndpointInvalid{Endpoint: scope.ServerURL, Reason: err.Error()}
	}
	host := parsed.Hostname()
	if host == "" {
		return "", 0, &ErrEndpointInvalid{Endpoint: scope.ServerURL, Reason: "server-url has no host"}
	}
	port := defaultEndpointPort
	if portStr := parsed.Port(); portStr != "" {
		parsedPort, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return "", 0, &ErrEndpointInvalid{Endpoint: scope.ServerURL, Reason: "invalid port: " + err.Error()}
		}
		port = uint16(parsedPort)
	}
	return host, port, nil
}

// poolFromPEM parses a PEM CA bundle into a dedicated cert pool.
func poolFromPEM(pem []byte) (*x509.CertPool, error) {
	if len(pem) == 0 {
		return nil, ErrCABundleEmpty{}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, ErrCABundleParse{}
	}
	return pool, nil
}
