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

// ACMEChallenge represents an ACME challenge as defined in RFC 8555.
// A challenge is a task that the client must complete to prove control
// over an identifier.
type ACMEChallenge struct {
	ID              uint64 `yaml:"id" json:"id"`
	Type            string `yaml:"type" json:"type"`
	URL             string `yaml:"url" json:"url"`
	Status          string `yaml:"status" json:"status"`
	Token           string `yaml:"token" json:"token"`
	Validated       string `yaml:"validated" json:"validated,omitempty"`
	Error           *Error `yaml:"error" json:"error,omitempty"`
	AccountID       uint64 `yaml:"account-id" json:"account_id" index:"accountId"`
	AuthorizationID uint64 `yaml:"authorization-id" json:"authorization_id" index:"authorizationId"`
}

// SetEntityID sets the unique identifier for the challenge.
func (challenge *ACMEChallenge) SetEntityID(id uint64) {
	challenge.ID = id
}

// EntityID returns the unique identifier for the challenge.
func (challenge *ACMEChallenge) EntityID() uint64 {
	return challenge.ID
}
