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

package authenticator

import "github.com/jeremyhahn/go-xkms/pkg/types"

// FIDO2CredentialEntity is the DAO entity representation of a FIDO2 credential.
// It mirrors StoredCredential with DAO-compatible field tags for indexed
// persistence via go-qrdb. Binary fields are stored as hex or base64 encoded
// strings to support indexing and serialization.
type FIDO2CredentialEntity struct {
	// ID is the auto-assigned DAO entity identifier.
	ID uint64 `json:"id"`

	// CredentialIDHex is the hex-encoded credential ID (unique index for lookups).
	CredentialIDHex string `json:"credential_id_hex" index:"unique"`

	// RPID is the relying party identifier.
	RPID string `json:"rp_id" index:"true"`

	// RPName is the relying party display name.
	RPName string `json:"rp_name"`

	// UserIDHex is the hex-encoded user handle.
	UserIDHex string `json:"user_id_hex"`

	// UserName is the user name.
	UserName string `json:"user_name" index:"true"`

	// UserDisplayName is the user display name.
	UserDisplayName string `json:"user_display_name"`

	// PrivateKeyPKCS8Base64 is the base64-encoded PKCS#8 DER private key bytes.
	PrivateKeyPKCS8Base64 string `json:"private_key_pkcs8_base64"`

	// PublicKeyCOSEBase64 is the base64-encoded COSE public key.
	PublicKeyCOSEBase64 string `json:"public_key_cose_base64"`

	// Algorithm is the COSE algorithm identifier (e.g., -7 for ES256).
	Algorithm int `json:"algorithm"`

	// SignCount is the signature counter.
	SignCount uint32 `json:"sign_count"`

	// CreatedAt is the Unix timestamp of credential creation.
	CreatedAt int64 `json:"created_at"`

	// Discoverable indicates if this is a resident/discoverable credential.
	Discoverable bool `json:"discoverable"`

	// CredProtect is the credential protection level (0-3).
	CredProtect uint8 `json:"cred_protect"`

	// HMACSecretKeyBase64 is the base64-encoded per-credential hmac-secret key.
	HMACSecretKeyBase64 string `json:"hmac_secret_key_base64"`

	// BackendID identifies which key backend manages this credential's private key.
	BackendID types.BackendType `json:"backend_id"`
}

// EntityID returns the DAO entity identifier.
func (e *FIDO2CredentialEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the DAO entity identifier.
func (e *FIDO2CredentialEntity) SetEntityID(id uint64) { e.ID = id }
