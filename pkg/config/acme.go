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
	"fmt"
)

// Error types returned when validating the ACME configuration section.
var (
	// ErrACMEMissingHTTPSAddr is returned when acme.enabled is true but no
	// HTTPS listen address has been configured.
	ErrACMEMissingHTTPSAddr = errors.New("acme: https_addr is required when acme.enabled is true")

	// ErrACMEMissingExternalURL is returned when acme.enabled is true but no
	// external URL has been configured. The external URL is the base URL
	// advertised in the ACME directory and used for Location headers.
	ErrACMEMissingExternalURL = errors.New("acme: external_url is required when acme.enabled is true")

	// ErrACMEMissingKeystoreBackend is returned when acme.enabled is true but
	// no keystore backend has been configured for the ACME CA to use.
	ErrACMEMissingKeystoreBackend = errors.New("acme: keystore_backend is required when acme.enabled is true")

	// ErrACMEMissingTLS is returned when acme.enabled is true, acme.reuse_tls
	// is false, and no TLS cert/key pair has been configured.
	ErrACMEMissingTLS = errors.New("acme: tls.cert_file and tls.key_file are required when acme.reuse_tls is false")
)

// ACMEConfig configures the optional ACME (RFC 8555) server that xkmsd may
// host alongside its primary protocol surfaces. When Enabled is false the
// ACME subsystem is not initialized and incurs no runtime overhead.
//
// The ACME server is always served on a dedicated HTTPS listener because
// RFC 8555 clients expect a standalone directory resource. The listener is
// configured via HTTPSAddr and uses either the inherited xkmsd TLS material
// (ReuseTLS == true) or its own certificate/key pair.
type ACMEConfig struct {
	// Enabled controls whether the ACME server is started. When false the
	// remainder of this config is ignored.
	Enabled bool `yaml:"enabled"`

	// HTTPSAddr is the listen address for the ACME HTTPS server (e.g. ":8443").
	HTTPSAddr string `yaml:"https_addr"`

	// ExternalURL is the externally-reachable base URL for the ACME server
	// (e.g. "https://acme.example.com"). This value is embedded in directory
	// responses and Location headers and must be reachable by ACME clients.
	ExternalURL string `yaml:"external_url"`

	// DirectoryPath is the path prefix mounted on the HTTPS listener. When
	// empty, "/acme" is used. All ACME endpoints are registered relative to
	// this prefix, e.g. "<DirectoryPath>/directory", "<DirectoryPath>/new-nonce".
	DirectoryPath string `yaml:"directory_path"`

	// TermsOfService is the URL advertised in the directory meta object.
	TermsOfService string `yaml:"terms_of_service"`

	// CAAIdentities is the list of CAA identities advertised in the directory
	// meta object. Empty disables CAA advertisement.
	CAAIdentities []string `yaml:"caa_identities"`

	// ExternalAccountRequired indicates that newAccount requests MUST include
	// an externalAccountBinding per RFC 8555 Section 7.3.4.
	ExternalAccountRequired bool `yaml:"external_account_required"`

	// EndorseEABRequired indicates that endorse-01 challenges require EAB.
	EndorseEABRequired bool `yaml:"endorse_eab_required"`

	// EndorseDeviceIDMetaKey is the EAB metadata key used to validate device
	// identity in endorse-01 challenges. Empty disables device-id validation.
	EndorseDeviceIDMetaKey string `yaml:"endorse_device_id_meta_key"`

	// Challenges controls which challenge verifiers are registered. At least
	// one challenge type must be enabled when ACME is enabled.
	Challenges ACMEChallengesConfig `yaml:"challenges"`

	// KeystoreBackend identifies the xkmsd keystore backend that the ACME CA
	// uses for key storage (e.g. "software", "pkcs8", "tpm2"). This must
	// match one of the enabled backends in the server config.
	KeystoreBackend string `yaml:"keystore_backend"`

	// DataDir is the directory where ACME object state (certificates, nonces,
	// authorizations, orders, accounts) is persisted. When empty, defaults to
	// "<storage.path>/acme".
	DataDir string `yaml:"data_dir"`

	// ReuseTLS indicates whether the ACME listener should reuse the xkmsd
	// TLS configuration (tls.cert_file/tls.key_file or CA-backed TLS). When
	// false the TLS section below is required.
	ReuseTLS bool `yaml:"reuse_tls"`

	// TLS configures the ACME listener's TLS settings when ReuseTLS is false.
	TLS ACMETLSConfig `yaml:"tls"`
}

// ACMEChallengesConfig selects which challenge verifiers are registered.
type ACMEChallengesConfig struct {
	// HTTP01 enables the http-01 challenge verifier (RFC 8555 Section 8.3).
	HTTP01 bool `yaml:"http01"`

	// DNS01 enables the dns-01 challenge verifier (RFC 8555 Section 8.4).
	DNS01 bool `yaml:"dns01"`
}

// ACMETLSConfig configures TLS for the ACME listener. These values are only
// consulted when ACMEConfig.ReuseTLS is false.
type ACMETLSConfig struct {
	// CertFile is the PEM-encoded server certificate.
	CertFile string `yaml:"cert_file"`

	// KeyFile is the PEM-encoded server private key.
	KeyFile string `yaml:"key_file"`

	// MinVersion specifies the minimum TLS version ("TLS1.2" or "TLS1.3").
	// Empty defaults to TLS1.3.
	MinVersion string `yaml:"min_version"`

	// MaxVersion specifies the maximum TLS version. Empty places no cap.
	MaxVersion string `yaml:"max_version"`

	// ClientAuth controls mTLS behavior: none, request, require, verify,
	// require_and_verify. Empty defaults to "none".
	ClientAuth string `yaml:"client_auth"`

	// ClientCAs is a list of PEM files containing CAs that may sign client
	// certificates when ClientAuth is not "none".
	ClientCAs []string `yaml:"client_cas"`
}

// Validate checks that the ACME configuration is complete when enabled.
// When Enabled is false this method is a no-op.
func (c *ACMEConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	if c.HTTPSAddr == "" {
		return ErrACMEMissingHTTPSAddr
	}
	if c.ExternalURL == "" {
		return ErrACMEMissingExternalURL
	}
	if c.KeystoreBackend == "" {
		return ErrACMEMissingKeystoreBackend
	}
	if !c.ReuseTLS && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		return ErrACMEMissingTLS
	}
	if !c.Challenges.HTTP01 && !c.Challenges.DNS01 {
		return fmt.Errorf("acme: at least one challenge type must be enabled (challenges.http01 or challenges.dns01)")
	}
	return nil
}
