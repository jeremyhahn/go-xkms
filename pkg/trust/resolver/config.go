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

// Package resolver provides a generic, scope-keyed trust resolver. It maps a
// scope name and a peer endpoint onto a verified *tls.Config, *x509.CertPool,
// or raw CA bundle PEM using an ordered list of trust-bootstrap strategies.
//
// Strategy dispatch (DANE, Noise_NK, SPKI pin, TOFU) is delegated to the
// canonical xkms trust-bootstrap library (pkg/trust/bootstrap). This package
// owns only the scope scoping, the ordered fallback chain, pool caching, and
// local strategies (embedded OS trust, ca-file, provider-ca).
//
// Scopes are arbitrary string names configured under Config.Scopes. Platform
// layers that want named constants (default, bmc, internal) define those
// constants in their own layer and pass them as scope strings.
package resolver

import (
	"os"
	"strings"
	"time"
)

// Strategy identifies a single trust-establishment method within a
// scope's ordered chain.
type Strategy string

const (
	// StrategyDANE verifies the peer via DNSSEC-validated TLSA records
	// per RFC 7671.
	StrategyDANE Strategy = "dane"

	// StrategyNoise fetches the CA bundle over a Noise_NK channel
	// authenticated by the server's static public key.
	StrategyNoise Strategy = "noise"

	// StrategySPKI verifies the peer leaf certificate against a pinned
	// SHA-256 SubjectPublicKeyInfo digest (hex encoded).
	StrategySPKI Strategy = "spki"

	// StrategyEmbedded trusts the operating system trust store. No
	// network fetch is performed.
	StrategyEmbedded Strategy = "embedded"

	// StrategyCAFile trusts a CA bundle PEM file on local disk.
	StrategyCAFile Strategy = "ca-file"

	// StrategyProviderCA trusts the CA bundle supplied by an injected
	// CABundleProvider (e.g. the platform's own certificate authority).
	StrategyProviderCA Strategy = "provider-ca"

	// StrategyTOFU uses trust-on-first-use SPKI pinning. On the first
	// connection the server's leaf certificate SPKI pin is captured and
	// persisted via the injected TOFUPinStore. Subsequent connections
	// verify the stored pin exactly like StrategySPKI. Requires
	// WithTOFUPinStore to be passed at construction time.
	StrategyTOFU Strategy = "tofu"
)

// Config is the top-level trust: configuration. Each scope is optional;
// an unconfigured scope fails resolution with ErrScopeNotConfigured.
type Config struct {
	// Scopes maps scope names (arbitrary strings) to per-scope strategy
	// chains. Callers that want named constants should define them in
	// their own layer and pass them as string keys here.
	Scopes map[string]*ScopeConfig `yaml:"scopes,omitempty" json:"scopes,omitempty" mapstructure:"scopes"`
}

// ScopeConfig configures a single trust scope: the ordered strategy
// chain plus per-strategy inputs.
type ScopeConfig struct {
	// Strategies is the ordered fallback chain. The resolver tries each
	// strategy in turn and returns the first success.
	Strategies []Strategy `yaml:"strategies" json:"strategies" mapstructure:"strategies"`

	// ServerURL is the CA bundle server URL (e.g.
	// "https://kms.example.com:8443"). Used by the fetch strategies
	// (dane, noise, spki, tofu) and as the endpoint fallback when a
	// caller passes an empty endpoint.
	ServerURL string `yaml:"server-url" json:"server_url" mapstructure:"server-url"`

	// Hostname is the DNS name under which TLSA records are published.
	// Required for DANE when ServerURL (or the caller's endpoint) uses
	// an IP address, because TLSA records live under the hostname (e.g.
	// _8443._tcp.kms.example.com), not the IP.
	Hostname string `yaml:"hostname" json:"hostname" mapstructure:"hostname"`

	// BundlePath overrides the CA bundle REST endpoint path used by the
	// fetch strategies. Empty selects the library default.
	BundlePath string `yaml:"bundle-path" json:"bundle_path" mapstructure:"bundle-path"`

	// PerMethodTimeout caps each individual strategy attempt.
	PerMethodTimeout time.Duration `yaml:"per-method-timeout" json:"per_method_timeout" mapstructure:"per-method-timeout"`

	// InstallToSystemTrust requests that a fetched CA bundle be installed
	// into the OS trust store after a successful fetch.
	InstallToSystemTrust bool `yaml:"install-to-system-trust" json:"install_to_system_trust" mapstructure:"install-to-system-trust"`

	// DANE carries DANE/TLSA resolver options.
	DANE *DANEConfig `yaml:"dane,omitempty" json:"dane,omitempty" mapstructure:"dane"`

	// Noise carries Noise_NK client options.
	Noise *NoiseConfig `yaml:"noise,omitempty" json:"noise,omitempty" mapstructure:"noise"`

	// SPKI carries the SPKI pin options.
	SPKI *SPKIConfig `yaml:"spki,omitempty" json:"spki,omitempty" mapstructure:"spki"`

	// TOFU carries the trust-on-first-use options. PinStore is injected
	// via WithTOFUPinStore; this struct carries only the optional
	// confirm-func hook.
	TOFU *TOFUScopeConfig `yaml:"tofu,omitempty" json:"tofu,omitempty" mapstructure:"tofu"`

	// CAFile is the CA bundle PEM path for the ca-file strategy.
	CAFile string `yaml:"ca-file,omitempty" json:"ca_file,omitempty" mapstructure:"ca-file"`
}

// DANEConfig configures the DANE/TLSA resolver used by the dane strategy.
// An empty DNSServer selects the system resolver from /etc/resolv.conf;
// DNSSEC AD validation is always required.
type DANEConfig struct {
	DNSServer        string `yaml:"dns-server" json:"dns_server" mapstructure:"dns-server"`
	DNSOverTLS       bool   `yaml:"dns-over-tls" json:"dns_over_tls" mapstructure:"dns-over-tls"`
	DNSTLSServerName string `yaml:"dns-tls-server-name" json:"dns_tls_server_name" mapstructure:"dns-tls-server-name"`
}

// NoiseConfig configures the Noise bootstrap client used by the noise
// strategy. At least one server key is required: ServerStaticKey offers
// Noise_NK, which a FIPS build cannot run, and ServerP256StaticKey offers the
// approved P-256 suite, which every build can. A scope that must bootstrap
// under FIPS needs the P-256 key.
type NoiseConfig struct {
	ServerAddr          string `yaml:"server-addr" json:"server_addr" mapstructure:"server-addr"`
	ServerStaticKey     string `yaml:"server-static-key" json:"server_static_key" mapstructure:"server-static-key"`
	ServerP256StaticKey string `yaml:"server-p256-static-key" json:"server_p256_static_key" mapstructure:"server-p256-static-key"`
}

// SPKIConfig configures the SPKI pin used by the spki strategy.
//
// Either Pin (the hex-encoded SHA-256 of the server SPKI) or PinFile (a
// path on disk holding the same value) must be set. PinFile is resolved
// into Pin by Validate so callers see Pin populated regardless of which
// form the YAML used.
type SPKIConfig struct {
	// Pin is the hex-encoded SHA-256 SPKI pin (64 hex characters).
	Pin string `yaml:"pin" json:"pin" mapstructure:"pin"`

	// PinFile is an absolute path to a file containing the hex-encoded
	// SHA-256 SPKI pin (whitespace tolerated, single pin per file).
	// Resolved by Validate so callers see Pin populated regardless of
	// which form the YAML used.
	PinFile string `yaml:"pin-file" json:"pin_file" mapstructure:"pin-file"`
}

// TOFUScopeConfig holds per-scope TOFU knobs. The PinStore itself is
// injected at resolver construction time via WithTOFUPinStore so it is
// never serialised into config files.
type TOFUScopeConfig struct{}

// DefaultConfig returns a Config with the default scope configured for
// the standard fetch chain (dane, noise, spki) and a conservative
// per-method timeout.
func DefaultConfig() *Config {
	return &Config{
		Scopes: map[string]*ScopeConfig{
			"default": {
				Strategies:       []Strategy{StrategyDANE, StrategyNoise, StrategySPKI},
				PerMethodTimeout: 5 * time.Second,
			},
		},
	}
}

// Scope returns the ScopeConfig for the given scope name, or nil when
// the scope is not configured.
func (c *Config) Scope(scope string) *ScopeConfig {
	if c.Scopes == nil {
		return nil
	}
	return c.Scopes[scope]
}

// Validate checks every configured scope for invalid strategy chains
// and missing per-strategy inputs. SPKI pin files are resolved into the
// Pin field as a side effect. tofu strategy entries are validated to
// ensure a pin store will be available (pass hasTOFUStore=true when
// WithTOFUPinStore is provided at construction).
func (c *Config) Validate() error {
	return c.ValidateWithTOFU(false)
}

// ValidateWithTOFU is like Validate but also checks that any scope using
// the tofu strategy has a pin store available (hasTOFUStore must be true
// when WithTOFUPinStore is provided to New).
func (c *Config) ValidateWithTOFU(hasTOFUStore bool) error {
	for scope, sc := range c.Scopes {
		if sc == nil {
			continue
		}
		if err := sc.validate(scope, hasTOFUStore); err != nil {
			return err
		}
	}
	return nil
}

// validate checks a single scope for configuration errors.
func (s *ScopeConfig) validate(scope string, hasTOFUStore bool) error {
	if len(s.Strategies) == 0 {
		return &ErrInvalidConfig{
			Scope:  scope,
			Field:  "strategies",
			Reason: "at least one strategy is required",
		}
	}

	for _, strategy := range s.Strategies {
		switch strategy {
		case StrategyDANE, StrategyNoise, StrategySPKI,
			StrategyEmbedded, StrategyCAFile, StrategyProviderCA, StrategyTOFU:
			// valid
		default:
			return &ErrInvalidConfig{
				Scope:  scope,
				Field:  "strategies",
				Reason: "unknown strategy: " + string(strategy),
			}
		}
	}

	if s.HasStrategy(StrategyNoise) && s.Noise != nil {
		if s.Noise.ServerStaticKey == "" && s.Noise.ServerP256StaticKey == "" {
			return &ErrInvalidConfig{
				Scope:  scope,
				Field:  "noise.server-static-key",
				Reason: "a server static key (server-static-key or server-p256-static-key) is required for the noise strategy",
			}
		}
		if s.Noise.ServerAddr == "" {
			return &ErrInvalidConfig{
				Scope:  scope,
				Field:  "noise.server-addr",
				Reason: "server address is required for the noise strategy",
			}
		}
	}

	if s.HasStrategy(StrategySPKI) && s.SPKI != nil {
		// Resolve PinFile into Pin if Pin is unset. The autoinstall flow
		// writes a pin file on the target; this reconciliation lets the
		// YAML reference the file path instead of duplicating the value.
		// A scope without any pin is still valid here because a PinStore
		// may supply per-endpoint pins at resolution time.
		if s.SPKI.Pin == "" && s.SPKI.PinFile != "" {
			data, err := os.ReadFile(s.SPKI.PinFile)
			if err != nil {
				return &ErrInvalidConfig{
					Scope:  scope,
					Field:  "spki.pin-file",
					Reason: "could not read pin file: " + err.Error(),
				}
			}
			s.SPKI.Pin = strings.TrimSpace(string(data))
		}
	}

	if s.HasStrategy(StrategyTOFU) && !hasTOFUStore {
		return ErrTOFUPinStoreRequired{}
	}

	if s.PerMethodTimeout < 0 {
		return &ErrInvalidConfig{
			Scope:  scope,
			Field:  "per-method-timeout",
			Reason: "timeout must not be negative",
		}
	}

	return nil
}

// HasStrategy reports whether the scope's chain contains the given
// strategy.
func (s *ScopeConfig) HasStrategy(strategy Strategy) bool {
	for _, candidate := range s.Strategies {
		if candidate == strategy {
			return true
		}
	}
	return false
}
