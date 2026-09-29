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

package entities

import "time"

// ACMECertificate represents an ACME certificate as defined in RFC 8555.
// It contains the certificate data and metadata about issuance and expiration.
type ACMECertificate struct {
	// NumericID is the auto-generated numeric entity ID derived from Serial
	// via FNV-1a hashing. This enables the Entity interface required by
	// GenericDAO. It is internal storage plumbing only - the certificate's
	// identity, for URLs, lookups, and revocation, is always Serial.
	NumericID uint64 `yaml:"numericId" json:"numericId"`

	// Serial is the certificate's X.509 serial number, encoded as the
	// full-precision value's canonical lowercase hexadecimal string (no
	// "0x" prefix, no leading zeros), matching the convention used
	// elsewhere in this codebase for certificate serials (see
	// pkg/xkms.servicer_ca.go and pkg/api/grpc/service_ca.go). Serial MUST
	// carry the certificate's entire serial number: truncating it (e.g. to
	// its low 64 bits) can make two distinct certificates collide.
	Serial string `yaml:"serial" json:"serial" index:"true"`

	CertURL   string    `yaml:"cert-url"  json:"cert_url"`
	PEM       string    `yaml:"pem" json:"pem"`
	IssuedAt  time.Time `yaml:"issued" json:"issued"`
	Status    string    `yaml:"status" json:"status"`
	ExpiresAt time.Time `yaml:"expires" json:"expires"`
}

// SetEntityID sets the numeric entity ID for GenericDAO compatibility.
func (cert *ACMECertificate) SetEntityID(id uint64) {
	cert.NumericID = id
}

// EntityID returns the numeric entity ID for GenericDAO compatibility.
// The numeric ID is derived from Serial via FNV-1a hashing the first time
// it is requested, then cached, mirroring Tenant and ExternalAccountBinding.
func (cert *ACMECertificate) EntityID() uint64 {
	if cert.NumericID == 0 && cert.Serial != "" {
		cert.NumericID = StringToEntityID(cert.Serial)
	}
	return cert.NumericID
}
