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

const (
	// AUTHORIZATION_INDEX_URL is the index key for authorization URL lookups.
	AUTHORIZATION_INDEX_URL = "url"
)

// ACMEAuthorization represents an ACME authorization as defined in RFC 8555.
// An authorization represents the server's authorization for an account to
// represent an identifier.
type ACMEAuthorization struct {
	ID         uint64          `yaml:"id" json:"id"`
	Identifier ACMEIdentifier  `yaml:"identifier" json:"identifier"`
	Status     string          `yaml:"status" json:"status"`
	Expires    string          `yaml:"expires" json:"expires"`
	Challenges []ACMEChallenge `yaml:"challenges" json:"challenges"`
	Wildcard   bool            `yaml:"wildcard" json:"wildcard"`
	AccountID  uint64          `yaml:"account-id" json:"account_id" index:"accountId"`
	OrderID    uint64
	URL        string `yaml:"url" json:"url"`
}

// SetEntityID sets the unique identifier for the authorization.
func (account *ACMEAuthorization) SetEntityID(id uint64) {
	account.ID = id
}

// EntityID returns the unique identifier for the authorization.
func (account *ACMEAuthorization) EntityID() uint64 {
	return account.ID
}
