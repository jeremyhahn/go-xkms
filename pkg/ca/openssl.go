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

// Package ca provides OpenSSL configuration utilities for the XKMSCA package.
//
// This file provides Subject-specific helpers that build on go-qrdb's OpenSSL
// configuration parser. The raw parsing of openssl.cnf files is delegated to
// the github.com/jeremyhahn/go-qrdb/sdk/go package.
package ca

import (
	"log"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// OpenSSLConfig contains parsed default values from the OpenSSL configuration
// file's [req_distinguished_name] section.
//
// These values are extracted from the *_default fields in the OpenSSL config:
//   - countryName_default -> Country
//   - stateOrProvinceName_default -> Province
//   - localityName_default -> Locality
//   - 0.organizationName_default -> Organization
//   - organizationalUnitName_default -> OrganizationalUnit
//   - commonName_default -> CommonName
type OpenSSLConfig struct {
	// Country is the default country code (2-letter ISO 3166-1 alpha-2).
	Country string

	// Province is the default state or province name.
	Province string

	// Locality is the default city or locality name.
	Locality string

	// Organization is the default organization name.
	Organization string

	// OrganizationalUnit is the default organizational unit name.
	OrganizationalUnit string

	// CommonName is the default common name, if specified.
	CommonName string
}

// ToSubject converts the OpenSSLConfig to a Subject struct.
//
// This creates a new Subject with all fields populated from the OpenSSL
// configuration defaults. Empty fields in OpenSSLConfig result in empty
// fields in the returned Subject.
func (o *OpenSSLConfig) ToSubject() Subject {
	return Subject{
		Country:            o.Country,
		Province:           o.Province,
		Locality:           o.Locality,
		Organization:       o.Organization,
		OrganizationalUnit: o.OrganizationalUnit,
		CommonName:         o.CommonName,
	}
}

// loadOpenSSLConfig finds and parses the OpenSSL configuration file,
// returning a Subject pointer for use in configuration merging.
//
// This function searches for the OpenSSL config file in standard locations,
// giving priority to the OPENSSL_CONF environment variable. Once found,
// it parses the [req_distinguished_name] section to extract default values.
//
// Returns nil if no OpenSSL config file is found or if no subject fields
// are populated.
func loadOpenSSLConfig() *Subject {
	opensslCfg, err := LoadOpenSSLConfig()
	if err != nil || opensslCfg == nil {
		return nil
	}

	subject := opensslCfg.ToSubject()

	// Only return if at least one field was populated
	if subject.CommonName != "" || subject.Organization != "" ||
		subject.OrganizationalUnit != "" || subject.Country != "" ||
		subject.Province != "" || subject.Locality != "" {
		return &subject
	}

	return nil
}

// LoadOpenSSLConfig finds and parses the OpenSSL configuration file.
//
// This function delegates to go-qrdb's SDK LoadOpenSSLConfig for the
// actual file discovery and parsing, then maps the result to the local
// OpenSSLConfig type.
//
// Returns nil with no error if no OpenSSL config file is found.
// Returns an error only if a config file is found but cannot be parsed.
func LoadOpenSSLConfig() (*OpenSSLConfig, error) {
	cfg, err := qrdbsdk.LoadOpenSSLConfig()
	if err != nil || cfg == nil {
		return nil, err
	}
	return &OpenSSLConfig{
		Country:            cfg.Country,
		Province:           cfg.Province,
		Locality:           cfg.Locality,
		Organization:       cfg.Organization,
		OrganizationalUnit: cfg.OrganizationalUnit,
		CommonName:         cfg.CommonName,
	}, nil
}

// mergeSubject merges source Subject values into destination where
// destination fields are empty.
func mergeSubject(dst, src *Subject) {
	if dst == nil || src == nil {
		return
	}

	if dst.CommonName == "" {
		dst.CommonName = src.CommonName
	}
	if dst.Organization == "" {
		dst.Organization = src.Organization
	}
	if dst.OrganizationalUnit == "" {
		dst.OrganizationalUnit = src.OrganizationalUnit
	}
	if dst.Country == "" {
		dst.Country = src.Country
	}
	if dst.Province == "" {
		dst.Province = src.Province
	}
	if dst.Locality == "" {
		dst.Locality = src.Locality
	}
	if dst.Address == "" {
		dst.Address = src.Address
	}
	if dst.PostalCode == "" {
		dst.PostalCode = src.PostalCode
	}
}

// applyOpenSSLDefaults applies OpenSSL configuration defaults to a Subject.
//
// This function applies default values from the OpenSSL configuration
// to any empty fields in the Subject. Existing non-empty values are preserved.
//
// Fields are only set if:
//  1. The corresponding Subject field is empty
//  2. The OpenSSLConfig has a non-empty value for that field
func applyOpenSSLDefaults(subject *Subject, opensslCfg *OpenSSLConfig) {
	if subject == nil || opensslCfg == nil {
		return
	}

	// Apply defaults only to empty fields
	if subject.Country == "" && opensslCfg.Country != "" {
		subject.Country = opensslCfg.Country
	}
	if subject.Province == "" && opensslCfg.Province != "" {
		subject.Province = opensslCfg.Province
	}
	if subject.Locality == "" && opensslCfg.Locality != "" {
		subject.Locality = opensslCfg.Locality
	}
	if subject.Organization == "" && opensslCfg.Organization != "" {
		subject.Organization = opensslCfg.Organization
	}
	if subject.OrganizationalUnit == "" && opensslCfg.OrganizationalUnit != "" {
		subject.OrganizationalUnit = opensslCfg.OrganizationalUnit
	}
	// Note: CommonName is typically not applied from OpenSSL defaults
	// as it should be explicitly set for each certificate
}

// TryLoadOpenSSLDefaults attempts to load OpenSSL defaults and apply them
// to the given Subject. This is a convenience function that logs warnings
// on failure but does not return errors, as OpenSSL defaults are optional.
//
// This function is safe to call even when no OpenSSL configuration exists.
func TryLoadOpenSSLDefaults(subject *Subject) {
	if subject == nil {
		return
	}
	opensslCfg, err := LoadOpenSSLConfig()
	if err != nil {
		log.Printf("ca: warning: failed to parse OpenSSL config: %v", err)
		return
	}
	if opensslCfg != nil {
		applyOpenSSLDefaults(subject, opensslCfg)
	}
}
