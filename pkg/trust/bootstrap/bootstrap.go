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

// Package bootstrap is the canonical trust-bootstrap dispatch layer
// for the xkms stack. It wraps go-truststrap with a single
// Fetch(ctx, cfg) entry point + a typed Mode enum, replacing the
// per-consumer inline dispatch logic that previously lived in
// cmd/xkmsctl, xkey/pkg/gui/services, and go-trusted-platform's
// pkg/bootstrap/client.go.
//
// Every consumer of trust bootstrap (the xkmsctl CLI, the xkey desktop
// GUI, the QuicBaaS SDK, and through it go-trusted-platform) MUST
// route through this package. There is exactly one canonical
// implementation of "select mode → build truststrap config →
// FetchCABundle → return PEM" in the stack, and it lives here.
//
// Typical caller:
//
//	cfg := bootstrap.Config{
//	    Mode:             bootstrap.ModeAuto,
//	    ServerURL:        "https://kms.example.com:8443",
//	    PerMethodTimeout: 10 * time.Second,
//	    Logger:           slog.Default(),
//	    DANE:             &bootstrap.DANEConfig{Hostname: "kms.example.com", DNSServer: "8.8.8.8:53"},
//	    Noise:            &bootstrap.NoiseConfig{ServerStaticKey: "abc...", ServerAddr: "kms.example.com:8445"},
//	    SPKI:             &bootstrap.SPKIConfig{Pin: "1234..."},
//	}
//	bundle, err := bootstrap.Fetch(ctx, cfg)
//	if err != nil { ... }
//	writeFile(bundle.PEM)
package bootstrap

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
)

// =============================================================================
// Types
// =============================================================================

// Mode identifies which trust-bootstrap strategy Fetch should run.
// Mode values match the canonical CLI verb (`quicbaas bootstrap <mode>`)
// and the SDK accessor name (Security().Trust().Bootstrap().<mode>).
type Mode string

const (
	// ModeAuto tries every configured method in DefaultMethodOrder
	// and returns the first success.
	ModeAuto Mode = "auto"

	// ModeDANE uses DNSSEC-validated TLSA records to verify the
	// server certificate before fetching the bundle over HTTPS.
	ModeDANE Mode = "dane"

	// ModeNoise establishes a Noise_NK channel pinned by the
	// server's static public key and fetches the bundle in-band.
	ModeNoise Mode = "noise"

	// ModeSPKI verifies the server certificate against a pre-shared
	// SHA-256 pin of its SubjectPublicKeyInfo and fetches the
	// bundle over HTTPS.
	ModeSPKI Mode = "spki"

	// ModeDirect fetches the bundle over HTTPS using the system's
	// default trust store. Last-resort fallback only — the server
	// must already have a publicly trusted certificate.
	ModeDirect Mode = "direct"

	// ModeTOFU uses trust-on-first-use SPKI pinning. On the first
	// connection the server's leaf certificate SPKI pin is captured
	// and persisted via TOFUConfig.PinStore. Subsequent connections
	// verify the stored pin exactly like ModeSPKI. ModeTOFU requires
	// explicit configuration of TOFUConfig.PinStore; it is never
	// included in the ModeAuto fallback chain unless the caller sets
	// Config.TOFU and includes ModeTOFU in Config.TOFUMethodOrder.
	ModeTOFU Mode = "tofu"
)

// DefaultNoisePort is the well-known port the Noise bootstrap channel
// listens on. Used by DeriveNoiseAddr when callers don't supply an
// explicit address.
const DefaultNoisePort = "8445"

// Config is the input to a single Fetch invocation. Callers populate
// Mode plus whichever sub-configs the chosen mode (or, for ModeAuto,
// the chosen ordering) requires. Sub-configs left nil mean "this mode
// is not configured" — ModeAuto skips them silently; single-mode
// Fetches error with ErrModeNotConfigured.
type Config struct {
	// Mode selects the dispatch strategy. Required.
	Mode Mode

	// ServerURL is the canonical xkms server URL (e.g.,
	// "https://kms.example.com:8443"). Used by every mode except
	// pure Noise; even Noise reads it to derive a default address
	// when NoiseConfig.ServerAddr is empty.
	ServerURL string

	// BundlePath overrides the default REST API path for the CA
	// bundle endpoint. Leave empty for go-truststrap's default
	// ("/api/v1/ca/bundle").
	BundlePath string

	// PerMethodTimeout caps each individual mode attempt. Used by
	// every mode and also by ModeAuto between fallbacks. Defaults
	// to go-truststrap's internal default when zero.
	PerMethodTimeout time.Duration

	// Logger is the slog logger truststrap will use. Nil disables
	// per-call logging (callers should still set this to keep
	// bootstrap audit trails complete).
	Logger *slog.Logger

	// DANE configures the DANE/TLSA mode. Required when
	// Mode == ModeDANE; optional knob for ModeAuto.
	DANE *DANEConfig

	// Noise configures the Noise_NK mode. Required when
	// Mode == ModeNoise; optional knob for ModeAuto.
	Noise *NoiseConfig

	// SPKI configures the SPKI-pin mode. Required when
	// Mode == ModeSPKI; optional knob for ModeAuto.
	SPKI *SPKIConfig

	// Direct configures the direct HTTPS mode. Required when
	// Mode == ModeDirect; optional knob for ModeAuto.
	Direct *DirectConfig

	// TOFU configures the trust-on-first-use mode. Required when
	// Mode == ModeTOFU. Under ModeAuto, TOFU is included only when
	// both TOFU is non-nil and TOFUMethodOrder contains ModeTOFU
	// (it is absent from the default order by design — a TOFU
	// fallback in a strictly pinned environment is a security hazard).
	TOFU *TOFUConfig

	// TOFUMethodOrder overrides the method order under ModeAuto to
	// include ModeTOFU. Leave nil to use truststrap's DefaultMethodOrder
	// (which does not include TOFU). Only consulted when Mode == ModeAuto
	// and TOFU != nil.
	TOFUMethodOrder []truststrap.Method
}

// DANEConfig holds the per-mode inputs the DANE/TLSA strategy needs.
type DANEConfig struct {
	// Hostname identifies the DNSSEC zone under which TLSA records
	// are published.
	Hostname string

	// DNSServer optionally pins the recursive resolver used for
	// the TLSA lookup (e.g., "8.8.8.8:53").
	DNSServer string

	// DNSOverTLS enables DoT for the TLSA lookup.
	DNSOverTLS bool

	// DNSTLSServerName carries the SNI / certificate name used when
	// DNSOverTLS is true.
	DNSTLSServerName string
}

// NoiseConfig holds the per-mode inputs the Noise_NK strategy needs.
type NoiseConfig struct {
	// ServerAddr is the explicit Noise bootstrap address
	// ("host:port"). When empty, Fetch derives one from
	// Config.ServerURL using DeriveNoiseAddr.
	ServerAddr string

	// ServerStaticKey is the hex-encoded 32-byte Curve25519 public
	// key of the server.
	ServerStaticKey string
}

// SPKIConfig holds the per-mode inputs the SPKI-pin strategy needs.
type SPKIConfig struct {
	// Pin is the hex-encoded SHA-256 SPKI pin of the server
	// certificate (64 hex characters).
	Pin string
}

// DirectConfig holds the per-mode inputs the direct HTTPS strategy
// needs. The struct has no fields today but is reserved so callers
// can express "direct mode is configured" symmetrically with the
// other modes (relevant under ModeAuto).
type DirectConfig struct{}

// TOFUConfig holds the per-mode inputs the trust-on-first-use strategy
// needs. PinStore is the only required field: it persists captured pins
// across process restarts.
//
// Security caveat: the first connection to a server under TOFU is
// unauthenticated — no pre-existing trust anchor validates the server's
// certificate. The captured SPKI pin is then used for all subsequent
// connections, providing strong continuity guarantees but no first-use
// authenticity. Use DANE, Noise, or SPKI when a pre-shared trust anchor
// is available.
type TOFUConfig struct {
	// PinStore persists captured pins. Required.
	// Use NewStoragePinStore to wrap any storage.Backend — including
	// the in-memory, file, PebbleDB, and qrdb backends. When the
	// backend is a Raft-replicated qrdb cluster every pin write
	// replicates through the Raft log.
	PinStore truststrap.PinStore

	// ConfirmFunc is an optional hook called before a newly captured
	// pin is persisted. Returning an error causes the bootstrap to
	// fail with truststrap.ErrTOFURejected and prevents pin storage.
	// When nil, new pins are auto-accepted with a WARNING log entry.
	ConfirmFunc func(ctx context.Context, pin *truststrap.Pin) error
}

// CABundle is the return value from a successful Fetch.
type CABundle struct {
	// PEM is the PEM-encoded certificate chain.
	PEM []byte

	// Certificates contains the individual DER-encoded
	// certificates that make up the bundle.
	Certificates [][]byte

	// ContentType records what go-truststrap reported the server
	// served (e.g., "application/pem-certificate-chain").
	ContentType string
}

// =============================================================================
// Errors
// =============================================================================

// ErrInvalidMode is returned when Config.Mode is unset or not one of
// the supported Mode values.
var ErrInvalidMode = errors.New("trust bootstrap: invalid mode")

// ErrModeNotConfigured is returned when a single-mode Fetch is called
// without the matching per-mode sub-config (e.g., Mode=ModeDANE but
// Config.DANE is nil).
var ErrModeNotConfigured = errors.New("trust bootstrap: mode not configured")

// ErrServerURLRequired is returned when Config.ServerURL is empty for
// any mode that needs it (every mode except pure-Noise when
// NoiseConfig.ServerAddr is explicit).
var ErrServerURLRequired = errors.New("trust bootstrap: server URL required")

// ErrFetch wraps a downstream go-truststrap failure. Use
// errors.Is(err, ErrFetch) to detect any fetch-level failure; use
// errors.Unwrap to recover the truststrap-typed cause for finer
// dispatch.
var ErrFetch = errors.New("trust bootstrap: fetch failed")

// FetchError carries the mode that was attempted alongside the
// underlying truststrap cause.
type FetchError struct {
	Mode  Mode
	Cause error
}

// Error implements error.
func (e *FetchError) Error() string {
	if e.Cause == nil {
		return "trust bootstrap: " + string(e.Mode) + " fetch failed"
	}
	return "trust bootstrap: " + string(e.Mode) + " fetch failed: " + e.Cause.Error()
}

// Is matches the ErrFetch sentinel.
func (e *FetchError) Is(target error) bool { return target == ErrFetch }

// Unwrap exposes the truststrap-typed cause for errors.Is / errors.As
// chains.
func (e *FetchError) Unwrap() error { return e.Cause }

// =============================================================================
// Public API
// =============================================================================

// Fetch executes a single trust-bootstrap attempt using the strategy
// named in cfg.Mode and returns the resulting CA bundle.
//
// The function is stateless: each call constructs a fresh truststrap
// bootstrapper, runs the fetch, closes it, and returns. There is no
// caching between calls.
func Fetch(ctx context.Context, cfg Config) (*CABundle, error) {
	switch cfg.Mode {
	case ModeAuto:
		return fetchAuto(ctx, cfg)
	case ModeDANE:
		return fetchDANE(ctx, cfg)
	case ModeNoise:
		return fetchNoise(ctx, cfg)
	case ModeSPKI:
		return fetchSPKI(ctx, cfg)
	case ModeDirect:
		return fetchDirect(ctx, cfg)
	case ModeTOFU:
		return fetchTOFU(ctx, cfg)
	default:
		return nil, ErrInvalidMode
	}
}

// DeriveNoiseAddr extracts the host portion of serverURL and appends
// the default Noise bootstrap port (DefaultNoisePort). It accepts
// either a full URL ("https://kms.example.com:8443") or a bare host.
// Returns an empty string if the input is empty.
func DeriveNoiseAddr(serverURL string) string {
	if serverURL == "" {
		return ""
	}
	addr := serverURL
	if idx := strings.Index(addr, "://"); idx >= 0 {
		addr = addr[idx+3:]
	}
	if idx := strings.Index(addr, "/"); idx >= 0 {
		addr = addr[:idx]
	}
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		addr = addr[:idx]
	}
	return addr + ":" + DefaultNoisePort
}

// =============================================================================
// Per-mode implementations
// =============================================================================

func fetchDANE(ctx context.Context, cfg Config) (*CABundle, error) {
	if cfg.DANE == nil {
		return nil, ErrModeNotConfigured
	}
	if cfg.ServerURL == "" {
		return nil, ErrServerURLRequired
	}
	bs, err := truststrap.NewDANEBootstrapper(&truststrap.DANEConfig{
		ServerURL:        cfg.ServerURL,
		Hostname:         cfg.DANE.Hostname,
		DNSServer:        cfg.DANE.DNSServer,
		DNSOverTLS:       cfg.DANE.DNSOverTLS,
		DNSTLSServerName: cfg.DANE.DNSTLSServerName,
		ConnectTimeout:   cfg.PerMethodTimeout,
		BundlePath:       cfg.BundlePath,
		Logger:           cfg.Logger,
	})
	if err != nil {
		return nil, &FetchError{Mode: ModeDANE, Cause: err}
	}
	defer func() { _ = bs.Close() }()
	return invoke(ctx, ModeDANE, bs)
}

func fetchNoise(ctx context.Context, cfg Config) (*CABundle, error) {
	if cfg.Noise == nil {
		return nil, ErrModeNotConfigured
	}
	addr := cfg.Noise.ServerAddr
	if addr == "" {
		addr = DeriveNoiseAddr(cfg.ServerURL)
	}
	if addr == "" {
		return nil, ErrServerURLRequired
	}
	bs, err := truststrap.NewNoiseBootstrapper(&truststrap.NoiseConfig{
		ServerAddr:       addr,
		ServerStaticKey:  cfg.Noise.ServerStaticKey,
		ConnectTimeout:   cfg.PerMethodTimeout,
		OperationTimeout: cfg.PerMethodTimeout,
		Logger:           cfg.Logger,
	})
	if err != nil {
		return nil, &FetchError{Mode: ModeNoise, Cause: err}
	}
	defer func() { _ = bs.Close() }()
	return invoke(ctx, ModeNoise, bs)
}

func fetchSPKI(ctx context.Context, cfg Config) (*CABundle, error) {
	if cfg.SPKI == nil {
		return nil, ErrModeNotConfigured
	}
	if cfg.ServerURL == "" {
		return nil, ErrServerURLRequired
	}
	bs, err := truststrap.NewSPKIBootstrapper(&truststrap.SPKIConfig{
		ServerURL:      cfg.ServerURL,
		SPKIPinSHA256:  cfg.SPKI.Pin,
		ConnectTimeout: cfg.PerMethodTimeout,
		BundlePath:     cfg.BundlePath,
		Logger:         cfg.Logger,
	})
	if err != nil {
		return nil, &FetchError{Mode: ModeSPKI, Cause: err}
	}
	defer func() { _ = bs.Close() }()
	return invoke(ctx, ModeSPKI, bs)
}

func fetchDirect(ctx context.Context, cfg Config) (*CABundle, error) {
	if cfg.Direct == nil {
		return nil, ErrModeNotConfigured
	}
	if cfg.ServerURL == "" {
		return nil, ErrServerURLRequired
	}
	bs, err := truststrap.NewDirectBootstrapper(&truststrap.DirectConfig{
		ServerURL:      cfg.ServerURL,
		BundlePath:     cfg.BundlePath,
		ConnectTimeout: cfg.PerMethodTimeout,
		Logger:         cfg.Logger,
	})
	if err != nil {
		return nil, &FetchError{Mode: ModeDirect, Cause: err}
	}
	defer func() { _ = bs.Close() }()
	return invoke(ctx, ModeDirect, bs)
}

func fetchTOFU(ctx context.Context, cfg Config) (*CABundle, error) {
	if cfg.TOFU == nil {
		return nil, ErrModeNotConfigured
	}
	if cfg.ServerURL == "" {
		return nil, ErrServerURLRequired
	}
	bs, err := truststrap.NewTOFUBootstrapper(&truststrap.TOFUConfig{
		ServerURL:      cfg.ServerURL,
		PinStore:       cfg.TOFU.PinStore,
		ConfirmFunc:    cfg.TOFU.ConfirmFunc,
		ConnectTimeout: cfg.PerMethodTimeout,
		BundlePath:     cfg.BundlePath,
		Logger:         cfg.Logger,
	})
	if err != nil {
		return nil, &FetchError{Mode: ModeTOFU, Cause: err}
	}
	defer func() { _ = bs.Close() }()
	return invoke(ctx, ModeTOFU, bs)
}

func fetchAuto(ctx context.Context, cfg Config) (*CABundle, error) {
	autoCfg := &truststrap.AutoConfig{
		PerMethodTimeout: cfg.PerMethodTimeout,
		Logger:           cfg.Logger,
	}
	if cfg.DANE != nil && cfg.ServerURL != "" {
		autoCfg.DANE = &truststrap.DANEConfig{
			ServerURL:        cfg.ServerURL,
			Hostname:         cfg.DANE.Hostname,
			DNSServer:        cfg.DANE.DNSServer,
			DNSOverTLS:       cfg.DANE.DNSOverTLS,
			DNSTLSServerName: cfg.DANE.DNSTLSServerName,
			ConnectTimeout:   cfg.PerMethodTimeout,
			BundlePath:       cfg.BundlePath,
			Logger:           cfg.Logger,
		}
	}
	if cfg.Noise != nil && cfg.Noise.ServerStaticKey != "" {
		addr := cfg.Noise.ServerAddr
		if addr == "" {
			addr = DeriveNoiseAddr(cfg.ServerURL)
		}
		autoCfg.Noise = &truststrap.NoiseConfig{
			ServerAddr:       addr,
			ServerStaticKey:  cfg.Noise.ServerStaticKey,
			ConnectTimeout:   cfg.PerMethodTimeout,
			OperationTimeout: cfg.PerMethodTimeout,
			Logger:           cfg.Logger,
		}
	}
	if cfg.SPKI != nil && cfg.SPKI.Pin != "" && cfg.ServerURL != "" {
		autoCfg.SPKI = &truststrap.SPKIConfig{
			ServerURL:      cfg.ServerURL,
			SPKIPinSHA256:  cfg.SPKI.Pin,
			ConnectTimeout: cfg.PerMethodTimeout,
			BundlePath:     cfg.BundlePath,
			Logger:         cfg.Logger,
		}
	}
	if cfg.Direct != nil && cfg.ServerURL != "" {
		autoCfg.Direct = &truststrap.DirectConfig{
			ServerURL:      cfg.ServerURL,
			BundlePath:     cfg.BundlePath,
			ConnectTimeout: cfg.PerMethodTimeout,
			Logger:         cfg.Logger,
		}
	}
	if cfg.TOFU != nil && cfg.TOFU.PinStore != nil && cfg.ServerURL != "" && len(cfg.TOFUMethodOrder) > 0 {
		autoCfg.TOFU = &truststrap.TOFUConfig{
			ServerURL:      cfg.ServerURL,
			PinStore:       cfg.TOFU.PinStore,
			ConfirmFunc:    cfg.TOFU.ConfirmFunc,
			ConnectTimeout: cfg.PerMethodTimeout,
			BundlePath:     cfg.BundlePath,
			Logger:         cfg.Logger,
		}
		autoCfg.MethodOrder = cfg.TOFUMethodOrder
	}
	if autoCfg.DANE == nil && autoCfg.Noise == nil && autoCfg.SPKI == nil && autoCfg.Direct == nil && autoCfg.TOFU == nil {
		return nil, ErrModeNotConfigured
	}

	resp, err := truststrap.AutoFetch(ctx, autoCfg)
	if err != nil {
		return nil, &FetchError{Mode: ModeAuto, Cause: err}
	}
	return toCABundle(resp), nil
}

// invoke runs FetchCABundle on a constructed bootstrapper and wraps
// the result + any error in this package's types.
func invoke(ctx context.Context, mode Mode, bs truststrap.Bootstrapper) (*CABundle, error) {
	resp, err := bs.FetchCABundle(ctx, nil)
	if err != nil {
		return nil, &FetchError{Mode: mode, Cause: err}
	}
	return toCABundle(resp), nil
}

// toCABundle copies the relevant fields out of go-truststrap's
// response shape into this package's CABundle type.
func toCABundle(resp *truststrap.CABundleResponse) *CABundle {
	if resp == nil {
		return nil
	}
	return &CABundle{
		PEM:          resp.BundlePEM,
		Certificates: resp.Certificates,
		ContentType:  resp.ContentType,
	}
}
