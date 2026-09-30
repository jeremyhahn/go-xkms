// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package transport

// Key version states, as KeyVersionInfo.State and KeyVersionStateResponse.State
// report them.
const (
	// KeyVersionEnabled marks a version every operation may use.
	KeyVersionEnabled = "enabled"

	// KeyVersionDisabled marks a version no operation may use until it is
	// enabled again.
	KeyVersionDisabled = "disabled"

	// KeyVersionRetired marks a version whose key material has been deleted
	// for good.
	KeyVersionRetired = "retired"
)

// KeyVersionInfo describes one version of a key.
type KeyVersionInfo struct {
	// Version is the version number, counted from 1.
	Version uint32 `json:"version"`

	// State is "enabled", "disabled" or "retired".
	State string `json:"state"`

	// Current reports whether this is the version sign and encrypt use.
	Current bool `json:"current,omitempty"`

	// CreatedAt is when the version was created, RFC 3339 in UTC; empty for
	// version 1 of a key created before its first rotation was recorded.
	CreatedAt string `json:"created_at,omitempty"`

	// CreatedBy is the subject that created the version, when known.
	CreatedBy string `json:"created_by,omitempty"`

	// PublicKeyPEM is the version's public key, for an asymmetric version
	// that has not been retired.
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
}

// ListKeyVersionsRequest names the key whose versions to list.
type ListKeyVersionsRequest struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// ListKeyVersionsResponse lists a key's versions, oldest first.
type ListKeyVersionsResponse struct {
	KeyID   string `json:"key_id"`
	Backend string `json:"backend"`
	// CurrentVersion is the version sign and encrypt use.
	CurrentVersion uint32           `json:"current_version"`
	Versions       []KeyVersionInfo `json:"versions"`
}

// KeyVersionRequest names one version of a key, for EnableKeyVersion,
// DisableKeyVersion and RetireKeyVersion.
type KeyVersionRequest struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
	// Version is the version number, counted from 1.
	Version uint32 `json:"version"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// KeyVersionStateResponse reports one version's state after a change.
type KeyVersionStateResponse struct {
	KeyID   string `json:"key_id"`
	Version uint32 `json:"version"`
	// State is the version's state after the change.
	State string `json:"state"`
	// Changed reports whether the state changed; enabling an enabled
	// version changes nothing.
	Changed bool `json:"changed"`
}

// AllKeyVersionsRequest names the key whose versions EnableAllKeyVersions or
// DisableAllKeyVersions change.
type AllKeyVersionsRequest struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// AllKeyVersionsResponse reports the versions a bulk state change reached.
// Disabling never reaches the current version, and neither change reaches a
// retired one.
type AllKeyVersionsResponse struct {
	KeyID string `json:"key_id"`
	// State is the state the versions were set to.
	State string `json:"state"`
	// Versions lists the versions whose state changed, ascending.
	Versions []uint32 `json:"versions"`
	// Count is len(Versions).
	Count int `json:"count"`
}

// RotateScopeKeysRequest names the tenant whose keys RotateScopeKeys rotates.
// A tenant-scoped caller rotates its own tenant and may leave TenantID empty;
// only a system caller may name another tenant, and an empty TenantID from a
// system caller is the system tenant's own keys.
type RotateScopeKeysRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
}

// Key rotation result states.
const (
	// KeyRotationRotated is a key that now has a new current version.
	KeyRotationRotated = "rotated"

	// KeyRotationSkipped is a key rotate-all left alone on purpose: another
	// subsystem names it exactly, so a new version would never be used, or
	// it has a certificate a rotation would silently leave on the old
	// version. Reason says which.
	KeyRotationSkipped = "skipped"

	// KeyRotationFailed is a key, or a whole backend, that could not be
	// rotated. Error says why.
	KeyRotationFailed = "failed"
)

// KeyRotationResult is the outcome of rotating one key.
type KeyRotationResult struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
	// State is KeyRotationRotated, KeyRotationSkipped or KeyRotationFailed.
	State string `json:"state"`
	// KeyVersion is the new current version; zero unless rotated.
	KeyVersion uint32 `json:"key_version,omitempty"`
	// Reason says why a skipped key was left alone.
	Reason string `json:"reason,omitempty"`
	// Error describes why the key was not rotated; empty unless failed.
	Error string `json:"error,omitempty"`
}

// RotateScopeKeysResponse reports the rotation of every key in a tenant.
type RotateScopeKeysResponse struct {
	TenantID string              `json:"tenant_id"`
	Results  []KeyRotationResult `json:"results"`
	// Rotated, Skipped and Failed count the results in each state.
	Rotated int `json:"rotated"`
	Skipped int `json:"skipped"`
	Failed  int `json:"failed"`
}
