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

// ACMEOrder represents an ACME order as defined in RFC 8555.
// An order is a request from a client to issue a certificate for a set of identifiers.
type ACMEOrder struct {
	ID             uint64           `yaml:"id" json:"id"`
	Status         string           `yaml:"status" json:"status"`
	Expires        string           `yaml:"expires" json:"expires,omitempty"`
	Identifiers    []ACMEIdentifier `yaml:"identifiers" json:"identifiers"`
	NotBefore      string           `yaml:"not-before" json:"notBefore,omitempty"`
	NotAfter       string           `yaml:"not-after" json:"notAfter,omitempty"`
	Error          *Error           `yaml:"error" json:"error,omitempty"`
	Authorizations []string         `yaml:"authorizations" json:"authorizations"`
	Finalize       string           `yaml:"finalize" json:"finalize"`
	Certificate    string           `yaml:"certificate" json:"certificate,omitempty"`
	CertificateURL string           `yaml:"certificate-url" json:"certificate_url,omitempty"`
	XSignedOrder   *ACMEOrder       `yaml:"x-signed-order" json:"x-signed-order,omitempty"`
	AccountID      uint64           `yaml:"account-id" json:"account_id" index:"accountId"`
	URL            string           `yaml:"url" json:"url"`
}

// SetEntityID sets the unique identifier for the order.
func (order *ACMEOrder) SetEntityID(id uint64) {
	order.ID = id
}

// EntityID returns the unique identifier for the order.
func (order *ACMEOrder) EntityID() uint64 {
	return order.ID
}
