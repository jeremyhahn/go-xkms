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
	ErrInvalidDirectoryURL  = errors.New("acme-client-config: invalid directory URL")
	ErrInvalidTimeout       = errors.New("acme-client-config: timeout must be positive")
	ErrInvalidRetryAttempts = errors.New("acme-client-config: retry attempts must be positive")
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
