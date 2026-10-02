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
	AccountID       uint64 `yaml:"account-id" json:"account_id" index:"true"`
	AuthorizationID uint64 `yaml:"authorization-id" json:"authorization_id" index:"true"`

	// DeviceAttestation carries the attested key and device identity a
	// validated device-attest-01 challenge established, or the endorsement
	// key and activation key a validated enroll-01 challenge activated, kept
	// so finalization can bind the request to them. Nil for every other
	// challenge type, and nil until this challenge has validated.
	DeviceAttestation *DeviceAttestation `yaml:"device-attestation,omitempty" json:"device_attestation,omitempty"`
}

// SetEntityID sets the unique identifier for the challenge.
func (challenge *ACMEChallenge) SetEntityID(id uint64) {
	challenge.ID = id
}

// EntityID returns the unique identifier for the challenge.
func (challenge *ACMEChallenge) EntityID() uint64 {
	return challenge.ID
}
