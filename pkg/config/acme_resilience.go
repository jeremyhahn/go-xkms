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

package config

import (
	"errors"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/server/circuitbreaker"
)

// ErrACMEResilienceNegativeValue is returned when a resilience setting
// (circuit breaker threshold, timeout, or degradation cache knob) is
// configured with a negative value. Zero selects the built-in default; a
// negative value has no meaning.
var ErrACMEResilienceNegativeValue = errors.New("acme: resilience settings must not be negative")

// Default circuit breaker settings, applied whenever an
// ACMECircuitBreakerConfig field is left at its zero value. These match
// circuitbreaker.DefaultConfig.
const (
	// DefaultACMEBreakerMaxFailures is the number of consecutive failures
	// before a breaker opens.
	DefaultACMEBreakerMaxFailures = 5

	// DefaultACMEBreakerResetTimeoutSeconds is how long an open breaker waits
	// before testing recovery in half-open state.
	DefaultACMEBreakerResetTimeoutSeconds = 30

	// DefaultACMEBreakerHalfOpenMaxRequests caps concurrent probes while a
	// breaker is half-open.
	DefaultACMEBreakerHalfOpenMaxRequests = 1

	// DefaultACMEBreakerSuccessThreshold is the number of consecutive
	// half-open successes required to close a breaker.
	DefaultACMEBreakerSuccessThreshold = 2

	// DefaultACMEBreakerTimeoutSeconds bounds a single call a breaker
	// protects.
	DefaultACMEBreakerTimeoutSeconds = 10

	// DefaultACMEBreakerTargetCapacity is the maximum number of distinct
	// validation targets (see ACMECircuitBreakerConfig.TargetCapacity) a
	// per-target breaker group tracks at once. Only meaningful for HTTP01
	// and DNS01, the two per-target groups; matches
	// circuitbreaker.DefaultTargetCapacity.
	DefaultACMEBreakerTargetCapacity = 1000

	// DefaultACMEBreakerTargetIdleTimeoutSeconds evicts a validation target
	// that has not been used for at least this long, independent of
	// TargetCapacity. Only meaningful for HTTP01 and DNS01; matches
	// circuitbreaker.DefaultTargetIdleTTL.
	DefaultACMEBreakerTargetIdleTimeoutSeconds = 600
)

// Default degradation cache settings, applied whenever an
// ACMEDegradationConfig field is left at its zero value.
const (
	// DefaultACMEDegradationCacheTTLSeconds is how long a cached
	// directory/CA-bundle response is served as fresh.
	DefaultACMEDegradationCacheTTLSeconds = 60

	// DefaultACMEDegradationStaleTTLSeconds is how much longer a cached
	// response may still be served, as stale, while its backing dependency's
	// breaker is open.
	DefaultACMEDegradationStaleTTLSeconds = 300

	// DefaultACMEDegradationMaxCacheSize is the maximum number of entries
	// held in each degradation cache. The directory and CA-bundle caches
	// each hold at most one entry in practice, so this bound exists to cap
	// memory rather than to evict under normal operation.
	DefaultACMEDegradationMaxCacheSize = 32
)

// ACMEResilienceConfig configures the circuit breakers guarding the ACME
// server's outbound dependencies, and the degradation cache the directory
// and CA-bundle endpoints serve from while CA-bundle storage access is
// unavailable.
//
// Storage here means the CA/keystore-backed certificate storage the CA
// bundle is served from (pkg/ca), not the go-qrdb-backed ACME protocol state
// (accounts, orders, authorizations, challenges, nonces): that storage's
// consistency and retry semantics belong to go-qrdb, and lower layers win —
// it is never wrapped in a circuit breaker.
type ACMEResilienceConfig struct {
	// HTTP01 configures the circuit breaker guarding the http-01 challenge
	// verifier.
	HTTP01 ACMECircuitBreakerConfig `yaml:"http01"`

	// DNS01 configures the circuit breaker guarding the dns-01 challenge
	// verifier.
	DNS01 ACMECircuitBreakerConfig `yaml:"dns01"`

	// CTSubmitter configures the circuit breaker guarding Certificate
	// Transparency log submission.
	CTSubmitter ACMECircuitBreakerConfig `yaml:"ct_submitter"`

	// KMS configures the circuit breaker guarding the tenant KMS signer
	// (Params.KMSService in pkg/acme/server/handlers).
	KMS ACMECircuitBreakerConfig `yaml:"kms"`

	// Storage configures the circuit breaker guarding CA-bundle storage
	// access (see the type doc above for what this does and does not cover).
	Storage ACMECircuitBreakerConfig `yaml:"storage"`

	// Degradation configures the cache the directory and CA-bundle endpoints
	// serve from while the Storage breaker is open.
	Degradation ACMEDegradationConfig `yaml:"degradation"`
}

// Validate checks every circuit breaker and the degradation cache section.
func (c ACMEResilienceConfig) Validate() error {
	for _, cb := range []ACMECircuitBreakerConfig{c.HTTP01, c.DNS01, c.CTSubmitter, c.KMS, c.Storage} {
		if err := cb.Validate(); err != nil {
			return err
		}
	}
	return c.Degradation.Validate()
}

// ACMECircuitBreakerConfig configures a single circuit breaker. A zero value
// is valid and selects the defaults in circuitbreaker.DefaultConfig.
type ACMECircuitBreakerConfig struct {
	// MaxFailures is the number of consecutive failures before the breaker
	// opens. Zero selects DefaultACMEBreakerMaxFailures.
	MaxFailures uint32 `yaml:"max_failures"`

	// ResetTimeoutSeconds is how long the breaker stays open before testing
	// recovery in half-open state. Zero selects
	// DefaultACMEBreakerResetTimeoutSeconds.
	ResetTimeoutSeconds int `yaml:"reset_timeout_seconds"`

	// HalfOpenMaxRequests caps concurrent probes while the breaker is
	// half-open. Zero selects DefaultACMEBreakerHalfOpenMaxRequests.
	HalfOpenMaxRequests uint32 `yaml:"half_open_max_requests"`

	// SuccessThreshold is the number of consecutive half-open successes
	// required to close the breaker. Zero selects
	// DefaultACMEBreakerSuccessThreshold.
	SuccessThreshold uint32 `yaml:"success_threshold"`

	// TimeoutSeconds bounds a single call the breaker protects. Zero selects
	// DefaultACMEBreakerTimeoutSeconds.
	TimeoutSeconds int `yaml:"timeout_seconds"`

	// TargetCapacity bounds the number of distinct validation targets
	// tracked at once, each with its own breaker (see
	// circuitbreaker.TargetConfig.Capacity). Meaningful only on HTTP01 and
	// DNS01 -- the breakers guarding a per-account validation target rather
	// than a single fixed dependency -- and ignored on CTSubmitter/KMS/
	// Storage, which have exactly one target. Zero selects
	// DefaultACMEBreakerTargetCapacity.
	TargetCapacity int `yaml:"target_capacity"`

	// TargetIdleTimeoutSeconds evicts a validation target that has not been
	// used for at least this long, independent of TargetCapacity (see
	// circuitbreaker.TargetConfig.IdleTTL). Meaningful only on HTTP01 and
	// DNS01, for the same reason as TargetCapacity. Zero selects
	// DefaultACMEBreakerTargetIdleTimeoutSeconds.
	TargetIdleTimeoutSeconds int `yaml:"target_idle_timeout_seconds"`
}

// Validate checks that the configured durations are not negative. The
// unsigned counter fields cannot be negative by construction.
func (c ACMECircuitBreakerConfig) Validate() error {
	if c.ResetTimeoutSeconds < 0 || c.TimeoutSeconds < 0 || c.TargetCapacity < 0 || c.TargetIdleTimeoutSeconds < 0 {
		return ErrACMEResilienceNegativeValue
	}
	return nil
}

// ResolveTargetCapacity returns the configured per-target breaker capacity,
// substituting DefaultACMEBreakerTargetCapacity when unset. Meaningful only
// when this config backs a per-target breaker group (HTTP01, DNS01).
func (c ACMECircuitBreakerConfig) ResolveTargetCapacity() int {
	if c.TargetCapacity > 0 {
		return c.TargetCapacity
	}
	return DefaultACMEBreakerTargetCapacity
}

// ResolveTargetIdleTimeout returns the configured per-target idle eviction
// timeout, substituting DefaultACMEBreakerTargetIdleTimeoutSeconds when
// unset. Meaningful only when this config backs a per-target breaker group
// (HTTP01, DNS01).
func (c ACMECircuitBreakerConfig) ResolveTargetIdleTimeout() time.Duration {
	if c.TargetIdleTimeoutSeconds > 0 {
		return time.Duration(c.TargetIdleTimeoutSeconds) * time.Second
	}
	return DefaultACMEBreakerTargetIdleTimeoutSeconds * time.Second
}

// CircuitBreakerConfig maps this section onto a *circuitbreaker.Config named
// name, substituting circuitbreaker.DefaultConfig's values for any field left
// at its zero value. This is the one mapping between the daemon's YAML and
// the circuit breaker package, mirroring ACMEAuditConfig.AuditConfig.
func (c ACMECircuitBreakerConfig) CircuitBreakerConfig(name string) *circuitbreaker.Config {
	cfg := circuitbreaker.DefaultConfig(name)
	if c.MaxFailures > 0 {
		cfg.MaxFailures = c.MaxFailures
	}
	if c.ResetTimeoutSeconds > 0 {
		cfg.ResetTimeout = time.Duration(c.ResetTimeoutSeconds) * time.Second
	}
	if c.HalfOpenMaxRequests > 0 {
		cfg.HalfOpenMaxRequests = c.HalfOpenMaxRequests
	}
	if c.SuccessThreshold > 0 {
		cfg.SuccessThreshold = c.SuccessThreshold
	}
	if c.TimeoutSeconds > 0 {
		cfg.Timeout = time.Duration(c.TimeoutSeconds) * time.Second
	}
	return cfg
}

// ACMEDegradationConfig configures the cache the directory and CA-bundle
// endpoints serve from while the Storage circuit breaker is open.
type ACMEDegradationConfig struct {
	// CacheTTLSeconds is how long a cached response is served as fresh
	// before it is considered stale. Zero selects
	// DefaultACMEDegradationCacheTTLSeconds.
	CacheTTLSeconds int `yaml:"cache_ttl_seconds"`

	// StaleTTLSeconds is how much longer, past CacheTTLSeconds, a cached
	// response may still be served while the Storage breaker is open. Zero
	// selects DefaultACMEDegradationStaleTTLSeconds.
	StaleTTLSeconds int `yaml:"stale_ttl_seconds"`

	// MaxCacheSize is the maximum number of entries held in each
	// degradation cache. Zero selects DefaultACMEDegradationMaxCacheSize.
	MaxCacheSize int `yaml:"max_cache_size"`
}

// Validate checks that the configured values are not negative.
func (c ACMEDegradationConfig) Validate() error {
	if c.CacheTTLSeconds < 0 || c.StaleTTLSeconds < 0 || c.MaxCacheSize < 0 {
		return ErrACMEResilienceNegativeValue
	}
	return nil
}

// ResolveCacheTTL returns the configured fresh-cache TTL, substituting
// DefaultACMEDegradationCacheTTLSeconds when unset.
func (c ACMEDegradationConfig) ResolveCacheTTL() time.Duration {
	if c.CacheTTLSeconds > 0 {
		return time.Duration(c.CacheTTLSeconds) * time.Second
	}
	return DefaultACMEDegradationCacheTTLSeconds * time.Second
}

// ResolveStaleTTL returns the configured stale-serving window, substituting
// DefaultACMEDegradationStaleTTLSeconds when unset.
func (c ACMEDegradationConfig) ResolveStaleTTL() time.Duration {
	if c.StaleTTLSeconds > 0 {
		return time.Duration(c.StaleTTLSeconds) * time.Second
	}
	return DefaultACMEDegradationStaleTTLSeconds * time.Second
}

// ResolveMaxCacheSize returns the configured cache size, substituting
// DefaultACMEDegradationMaxCacheSize when unset.
func (c ACMEDegradationConfig) ResolveMaxCacheSize() int {
	if c.MaxCacheSize > 0 {
		return c.MaxCacheSize
	}
	return DefaultACMEDegradationMaxCacheSize
}
