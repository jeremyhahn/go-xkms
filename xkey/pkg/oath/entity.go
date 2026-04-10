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

package oath

import "time"

// OATHCredentialEntity is the DAO entity representation of an OATH TOTP/HOTP
// credential. It mirrors the Credential type with DAO-compatible field tags
// for indexed persistence via go-qrdb.
type OATHCredentialEntity struct {
	// ID is the auto-assigned DAO entity identifier.
	ID uint64 `json:"id"`

	// Name is the display name (e.g., "GitHub", "AWS").
	Name string `json:"name" index:"unique,ci"`

	// Issuer is the service provider name.
	Issuer string `json:"issuer" index:"true"`

	// AccountName is the user's account identifier (e.g., email).
	AccountName string `json:"account_name"`

	// Type is the OTP type: "totp" or "hotp".
	Type string `json:"type"`

	// Secret is the base32-encoded shared secret.
	Secret string `json:"secret"`

	// Algorithm is the hash algorithm: SHA1, SHA256, or SHA512.
	Algorithm string `json:"algorithm"`

	// Digits is the number of digits in the OTP (6, 7, or 8).
	Digits int `json:"digits"`

	// Period is the time step in seconds (TOTP only, typically 30).
	Period int `json:"period"`

	// Counter is the current counter value (HOTP only).
	Counter uint64 `json:"counter"`

	// BackendID identifies which backend manages this credential.
	BackendID string `json:"backend_id" index:"true"`

	// CreatedAt is when the credential was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the credential was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// EntityID returns the DAO entity identifier.
func (e *OATHCredentialEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the DAO entity identifier.
func (e *OATHCredentialEntity) SetEntityID(id uint64) { e.ID = id }
