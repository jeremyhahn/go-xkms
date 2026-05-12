// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package entities

import "time"

// ACMEAccount represents an ACME account as defined in RFC 8555.
// It contains account metadata, contact information, and references to orders.
type ACMEAccount struct {
	ID                     uint64      `yaml:"id" json:"id"`
	Contact                []string    `yaml:"contact" json:"contact,omitempty"`
	CreatedAt              time.Time   `yaml:"created" json:"created"`
	ExternalAccountBinding interface{} `yaml:"externalAccountBinding" json:"externalAccountBinding,omitempty"`
	Key                    string      `yaml:"key" json:"key"`
	OnlyReturnExisting     bool        `yaml:"onlyReturnExisting" json:"onlyReturnExisting,omitempty"`
	Orders                 string      `yaml:"orders" json:"orders"`
	Status                 string      `yaml:"status" json:"status"`
	TermsOfServiceAgreed   bool        `yaml:"termsOfServiceAgreed" json:"termsOfServiceAgreed,omitempty"`
	URL                    string      `yaml:"url" json:"url"`

	// TenantID is the tenant this account belongs to in multi-tenant deployments.
	// This is set from the EAB's TenantID during account creation with External Account Binding.
	// Empty string indicates the account belongs to the default/global tenant.
	TenantID string `yaml:"tenantId,omitempty" json:"tenantId,omitempty"`
}

// SetEntityID sets the unique identifier for the account.
func (account *ACMEAccount) SetEntityID(id uint64) {
	account.ID = id
}

// EntityID returns the unique identifier for the account.
func (account *ACMEAccount) EntityID() uint64 {
	return account.ID
}
