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
	ID        uint64    `yaml:"id" json:"id"`
	CertURL   string    `yaml:"cert-url"  json:"cert_url"`
	PEM       string    `yaml:"pem" json:"pem"`
	IssuedAt  time.Time `yaml:"issued" json:"issued"`
	Status    string    `yaml:"status" json:"status"`
	ExpiresAt time.Time `yaml:"expires" json:"expires"`
}

// SetEntityID sets the unique identifier for the certificate.
func (cert *ACMECertificate) SetEntityID(id uint64) {
	cert.ID = id
}

// EntityID returns the unique identifier for the certificate.
func (cert *ACMECertificate) EntityID() uint64 {
	return cert.ID
}
