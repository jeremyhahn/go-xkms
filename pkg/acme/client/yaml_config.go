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
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// ACMEConfig is the top-level ACME configuration that contains both
// server and client configurations. This maps to the "acme:" YAML section.
type ACMEConfig struct {
	// Server contains ACME server configuration
	Server *ACMEServerConfig `yaml:"server" json:"server" mapstructure:"server"`

	// Client contains ACME client configuration
	Client *ACMEClientConfig `yaml:"client" json:"client" mapstructure:"client"`
}

// ACMEServerConfig contains ACME server configuration.
type ACMEServerConfig struct {
	// DirectoryURL is the ACME directory endpoint
	DirectoryURL string `yaml:"directory" json:"directory" mapstructure:"directory"`

	// TermsOfService is the path to the terms of service
	TermsOfService string `yaml:"terms-of-service" json:"terms_of_service" mapstructure:"terms-of-service"`

	// Challenges is the list of supported challenge types
	Challenges []string `yaml:"challenges" json:"challenges" mapstructure:"challenges"`
}

// ACMEClientConfig contains configuration for the ACME client.
type ACMEClientConfig struct {
	// DirectoryURL is the ACME directory endpoint
	DirectoryURL string `yaml:"directory" json:"directory" mapstructure:"directory"`

	// Account contains the ACME account configuration
	Account *ACMEAccountConfig `yaml:"account" json:"account" mapstructure:"account"`

	// Enrollment contains device enrollment configuration
	Enrollment *ACMEEnrollmentConfig `yaml:"enrollment" json:"enrollment" mapstructure:"enrollment"`

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

	// DNSServer is the DNS server address (host:port) to use for resolving
	// the ACME server's hostname. If not set, the platform's DNS service
	// is used if available, otherwise the system resolver is used.
	// Example: "10.99.99.2:53"
	DNSServer string `yaml:"dns-server" json:"dns_server" mapstructure:"dns-server"`
}

// ACMEAccountConfig contains ACME account configuration.
type ACMEAccountConfig struct {
	// Email is the account email address
	Email string `yaml:"email" json:"email" mapstructure:"email"`

	// Key contains the account key configuration
	Key *xkmssdk.KeyConfig `yaml:"key" json:"key" mapstructure:"key"`

	// Register indicates whether to register the account if it doesn't exist
	Register bool `yaml:"register" json:"register" mapstructure:"register"`
}

// ACMEEnrollmentConfig contains device enrollment configuration.
type ACMEEnrollmentConfig struct {
	// Challenge is the challenge type for enrollment (enroll-01, endorse-01, device-attest-01)
	Challenge string `yaml:"challenge" json:"challenge" mapstructure:"challenge"`

	// IPAddress is the device IP address (supports ${ENV_VAR} expansion)
	IPAddress string `yaml:"ip" json:"ip" mapstructure:"ip"`
}

// ACMECrossSignConfig contains cross-signing configuration.
type ACMECrossSignConfig struct {
	// DirectoryURL is the ACME directory endpoint of the cross-signing CA
	DirectoryURL string `yaml:"directory" json:"directory" mapstructure:"directory"`

	// ChallengeType is the challenge type for cross-signing
	ChallengeType string `yaml:"challenge" json:"challenge" mapstructure:"challenge"`

	// TrustedRoots contains PEM-encoded trusted root CA certificates
	TrustedRoots []string `yaml:"trusted-roots" json:"trusted_roots" mapstructure:"trusted-roots"`

	// RequestServerBundle indicates whether to request the server's CA bundle
	RequestServerBundle bool `yaml:"request-server-bundle" json:"request_server_bundle" mapstructure:"request-server-bundle"`
}

// ToConfig converts ACMEClientConfig to the internal Config type used by the ACME client.
func (c *ACMEClientConfig) ToConfig() *Config {
	return &Config{
		DirectoryURL:        c.DirectoryURL,
		SystemCertPool:      c.SystemCertPool,
		RequestServerBundle: c.RequestServerBundle,
		TrustedRoots:        c.TrustedRoots,
	}
}
