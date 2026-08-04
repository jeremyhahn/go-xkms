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

package client

import (
	"errors"
	"time"
)

var (
	ErrInvalidDirectoryURL     = errors.New("acme-client-config: invalid directory URL")
	ErrInvalidTimeout          = errors.New("acme-client-config: timeout must be positive")
	ErrInvalidRetryAttempts    = errors.New("acme-client-config: retry attempts must be positive")
	ErrInvalidRenewalThreshold = errors.New("acme-client-config: renewal threshold must be between 0 and 1")
)

// Config defines the configuration for an ACME client
type Config struct {
	// DirectoryURL is the ACME directory endpoint
	DirectoryURL string `yaml:"directory-url" json:"directory_url" mapstructure:"directory-url"`

	// Timeout for HTTP requests
	Timeout time.Duration `yaml:"timeout" json:"timeout" mapstructure:"timeout"`

	// SystemCertPool controls whether to include the OS system certificate pool.
	// If true, the client uses x509.SystemCertPool() as the base, then adds
	// any TrustedRoots and/or fetched CA bundles on top.
	// If false, the client uses an empty pool with only explicitly provided
	// TrustedRoots and/or fetched CA bundles (for isolated/private CA environments).
	SystemCertPool bool `yaml:"system-cert-pool" json:"system_cert_pool" mapstructure:"system-cert-pool"`

	// RequestServerBundle indicates whether to request the server's CA bundle
	RequestServerBundle bool `yaml:"request-server-bundle" json:"request_server_bundle" mapstructure:"request-server-bundle"`

	// TrustedRoots contains PEM-encoded trusted root CA certificates
	TrustedRoots []string `yaml:"trusted-roots" json:"trusted_roots" mapstructure:"trusted-roots"`

	// RetryAttempts specifies the number of retry attempts for failed requests
	RetryAttempts int `yaml:"retry-attempts" json:"retry_attempts" mapstructure:"retry-attempts"`

	// RetryDelay specifies the delay between retry attempts
	RetryDelay time.Duration `yaml:"retry-delay" json:"retry_delay" mapstructure:"retry-delay"`

	// MaxRetryDelay specifies the maximum delay for exponential backoff
	MaxRetryDelay time.Duration `yaml:"max-retry-delay" json:"max_retry_delay" mapstructure:"max-retry-delay"`
}

// RenewalConfig defines the configuration for the auto-renewal service.
// YAML/mapstructure tags allow this to be loaded directly from configuration.
type RenewalConfig struct {
	// Enabled indicates whether auto-renewal is enabled
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// CheckInterval specifies how often to check for certificates needing renewal
	CheckInterval time.Duration `yaml:"check-interval,omitempty" json:"check_interval,omitempty" mapstructure:"check-interval"`

	// RenewalThreshold specifies when to renew (as fraction of validity period)
	// For example, 0.33 means renew when 1/3 of the validity period remains
	RenewalThreshold float64 `yaml:"renewal-threshold,omitempty" json:"renewal_threshold,omitempty" mapstructure:"renewal-threshold"`

	// MaxRetries specifies the maximum number of renewal retry attempts
	MaxRetries int `yaml:"max-retries,omitempty" json:"max_retries,omitempty" mapstructure:"max-retries"`

	// RetryInterval specifies the delay between renewal retry attempts
	RetryInterval time.Duration `yaml:"retry-interval,omitempty" json:"retry_interval,omitempty" mapstructure:"retry-interval"`

	// NotifyOnSuccess indicates whether to log successful renewals
	NotifyOnSuccess bool `yaml:"notify-on-success,omitempty" json:"notify_on_success,omitempty" mapstructure:"notify-on-success"`

	// NotifyOnFailure indicates whether to log failed renewals
	NotifyOnFailure bool `yaml:"notify-on-failure,omitempty" json:"notify_on_failure,omitempty" mapstructure:"notify-on-failure"`
}

// DefaultConfig returns the default ACME client configuration
func DefaultConfig() *Config {
	return &Config{
		DirectoryURL:        "",
		Timeout:             60 * time.Second,
		SystemCertPool:      false, // Default to isolated mode for private CA environments
		RequestServerBundle: false,
		TrustedRoots:        []string{},
		RetryAttempts:       3,
		RetryDelay:          1 * time.Second,
		MaxRetryDelay:       30 * time.Second,
	}
}

// DefaultRenewalConfig returns the default renewal service configuration
func DefaultRenewalConfig() *RenewalConfig {
	return &RenewalConfig{
		Enabled:          true,
		CheckInterval:    24 * time.Hour, // Check daily
		RenewalThreshold: 0.33,           // Renew when 1/3 of validity remains
		MaxRetries:       5,              // Retry up to 5 times
		RetryInterval:    1 * time.Hour,  // Wait 1 hour between retries
		NotifyOnSuccess:  true,
		NotifyOnFailure:  true,
	}
}

// Validate validates the client configuration
func (c *Config) Validate() error {
	if c.DirectoryURL == "" {
		return ErrInvalidDirectoryURL
	}

	if c.Timeout <= 0 {
		return ErrInvalidTimeout
	}

	if c.RetryAttempts < 0 {
		return ErrInvalidRetryAttempts
	}

	return nil
}

// Validate validates the renewal configuration
func (rc *RenewalConfig) Validate() error {
	if rc.RenewalThreshold < 0 || rc.RenewalThreshold > 1 {
		return ErrInvalidRenewalThreshold
	}

	if rc.CheckInterval <= 0 {
		return ErrInvalidTimeout
	}

	if rc.MaxRetries < 0 {
		return ErrInvalidRetryAttempts
	}

	return nil
}
