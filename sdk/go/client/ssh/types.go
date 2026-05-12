// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package ssh

import "time"

// Key is the transport-safe representation of an SSH key. It carries
// only public-key material and metadata — the private half always
// lives behind the SDK in a *secure.Secret (embedded transport) or
// entirely server-side (REST / gRPC transports).
type Key struct {
	// Scope is the string form of the scope ("tenant", "user",
	// "service").
	Scope string `json:"scope"`

	// Owner is the scope-specific identifier.
	Owner string `json:"owner"`

	// Name is the human-visible key name, unique within (Scope,
	// Owner).
	Name string `json:"name"`

	// Algorithm is the canonical algorithm identifier — one of
	// "ed25519", "rsa", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521".
	Algorithm string `json:"algorithm"`

	// PublicKey is the OpenSSH authorized_keys-format public-key line
	// (no newline, no trailing comment).
	PublicKey string `json:"public_key"`

	// Fingerprint is the OpenSSH SHA256 fingerprint
	// ("SHA256:<base64>").
	Fingerprint string `json:"fingerprint"`

	// CreatedAt is when the key was generated or imported.
	CreatedAt time.Time `json:"created_at"`

	// Comment is the optional free-form key comment.
	Comment string `json:"comment,omitempty"`
}

// PublicKey is the transport-safe export of a public key without any
// other key metadata. Used by ExportPublic.
type PublicKey struct {
	// Algorithm mirrors Key.Algorithm.
	Algorithm string `json:"algorithm"`

	// Line is the authorized_keys-format line.
	Line string `json:"line"`

	// Fingerprint is the OpenSSH SHA256 fingerprint.
	Fingerprint string `json:"fingerprint"`
}

// Pin is the transport-safe representation of a host-key pin.
type Pin struct {
	Scope       string    `json:"scope"`
	Owner       string    `json:"owner"`
	Host        string    `json:"host"`
	Fingerprint string    `json:"fingerprint"`
	Algorithm   string    `json:"algorithm,omitempty"`
	AddedAt     time.Time `json:"added_at"`
	Source      string    `json:"source,omitempty"`
}

// AuthorizedEntry is the transport-safe representation of an
// authorized_keys entry.
type AuthorizedEntry struct {
	Scope   string   `json:"scope"`
	Owner   string   `json:"owner"`
	Name    string   `json:"name"`
	Line    string   `json:"line"`
	Options []string `json:"options,omitempty"`
	Comment string   `json:"comment,omitempty"`
}

// GenerateRequest carries inputs for KeysClient.Generate. Algorithm is
// a canonical identifier; RSABits is consulted only for the RSA
// algorithm (defaults to 4096 when zero).
type GenerateRequest struct {
	Scope     string `json:"scope"`
	Owner     string `json:"owner"`
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	RSABits   int    `json:"rsa_bits,omitempty"`
	Comment   string `json:"comment,omitempty"`
}

// ImportRequest carries inputs for KeysClient.Import. The PEM bytes
// arrive as []byte in-memory for the embedded transport. REST / gRPC
// transports (1c) will wrap these bytes in a secure.Buffer via a
// custom json.Unmarshaler so plaintext never lives in a Go string.
type ImportRequest struct {
	Scope   string `json:"scope"`
	Owner   string `json:"owner"`
	Name    string `json:"name"`
	PEM     []byte `json:"pem"`
	Comment string `json:"comment,omitempty"`
}

// GetKeyRequest identifies a single key.
type GetKeyRequest struct {
	Scope string `json:"scope"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// ListKeysRequest enumerates keys by (Scope, Owner). Either field may
// be empty to broaden the search.
type ListKeysRequest struct {
	Scope string `json:"scope,omitempty"`
	Owner string `json:"owner,omitempty"`
}

// DeleteKeyRequest removes a single key.
type DeleteKeyRequest struct {
	Scope string `json:"scope"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// ExportRequest identifies the key whose public material to export.
type ExportRequest struct {
	Scope string `json:"scope"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// AddKnownHostRequest persists a new host-key pin.
type AddKnownHostRequest struct {
	Scope       string `json:"scope"`
	Owner       string `json:"owner"`
	Host        string `json:"host"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm,omitempty"`
	Source      string `json:"source,omitempty"`
}

// ListKnownHostsRequest enumerates pins.
type ListKnownHostsRequest struct {
	Scope string `json:"scope,omitempty"`
	Owner string `json:"owner,omitempty"`
}

// RemoveKnownHostRequest removes a pin.
type RemoveKnownHostRequest struct {
	Scope string `json:"scope"`
	Owner string `json:"owner"`
	Host  string `json:"host"`
}

// AddAuthorizedKeyRequest persists a new authorized_keys entry.
type AddAuthorizedKeyRequest struct {
	Scope   string   `json:"scope"`
	Owner   string   `json:"owner"`
	Name    string   `json:"name"`
	Line    string   `json:"line"`
	Options []string `json:"options,omitempty"`
	Comment string   `json:"comment,omitempty"`
}

// ListAuthorizedKeysRequest enumerates authorized entries.
type ListAuthorizedKeysRequest struct {
	Scope string `json:"scope,omitempty"`
	Owner string `json:"owner,omitempty"`
}

// EmitRequest serializes an Entry into an authorized_keys line.
type EmitRequest struct {
	PublicKey string   `json:"public_key"`
	Options   []string `json:"options,omitempty"`
	Comment   string   `json:"comment,omitempty"`
}

// SessionDialRequest requests an outbound SSH session.
type SessionDialRequest struct {
	// KeyScope + KeyOwner + KeyName locate the authentication key.
	KeyScope string `json:"key_scope"`
	KeyOwner string `json:"key_owner"`
	KeyName  string `json:"key_name"`

	// HostKeyScope + HostKeyOwner locate the pin store. When empty the
	// KeyScope / KeyOwner are reused.
	HostKeyScope string `json:"host_key_scope,omitempty"`
	HostKeyOwner string `json:"host_key_owner,omitempty"`

	// Host + Port + User describe the target.
	Host string `json:"host"`
	Port int    `json:"port,omitempty"`
	User string `json:"user"`

	// TimeoutSeconds bounds the handshake. Zero uses the SDK default.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}
