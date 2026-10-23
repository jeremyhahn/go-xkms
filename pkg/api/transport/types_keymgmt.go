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

// KeyStatus is the lifecycle state of a key or key version a key management
// request sets or a response reports.
type KeyStatus string

const (
	KeyStatusEnabled         KeyStatus = "enabled"
	KeyStatusDisabled        KeyStatus = "disabled"
	KeyStatusPendingDeletion KeyStatus = "pending_deletion"
	KeyStatusDeleted         KeyStatus = "deleted"
	KeyStatusRotating        KeyStatus = "rotating"
	KeyStatusCompromised     KeyStatus = "compromised"
)

// KeyUsage is an operation a key policy allows.
type KeyUsage string

const (
	KeyUsageEncrypt     KeyUsage = "encrypt"
	KeyUsageDecrypt     KeyUsage = "decrypt"
	KeyUsageSign        KeyUsage = "sign"
	KeyUsageVerify      KeyUsage = "verify"
	KeyUsageWrapKey     KeyUsage = "wrap_key"
	KeyUsageDeriveKey   KeyUsage = "derive_key"
	KeyUsageGenerateMAC KeyUsage = "generate_mac"
	KeyUsageVerifyMAC   KeyUsage = "verify_mac"
)

// KeyAlgorithm names the algorithm of a key in key management responses.
type KeyAlgorithm string

const (
	KeyAlgorithmAES128GCM         KeyAlgorithm = "AES-128-GCM"
	KeyAlgorithmAES192GCM         KeyAlgorithm = "AES-192-GCM"
	KeyAlgorithmAES256GCM         KeyAlgorithm = "AES-256-GCM"
	KeyAlgorithmChaCha20Poly1305  KeyAlgorithm = "ChaCha20-Poly1305"
	KeyAlgorithmXChaCha20Poly1305 KeyAlgorithm = "XChaCha20-Poly1305"
	KeyAlgorithmRSA2048           KeyAlgorithm = "RSA-2048"
	KeyAlgorithmRSA3072           KeyAlgorithm = "RSA-3072"
	KeyAlgorithmRSA4096           KeyAlgorithm = "RSA-4096"
	KeyAlgorithmECDSAP256         KeyAlgorithm = "ECDSA-P256"
	KeyAlgorithmECDSAP384         KeyAlgorithm = "ECDSA-P384"
	KeyAlgorithmECDSAP521         KeyAlgorithm = "ECDSA-P521"
	KeyAlgorithmEd25519           KeyAlgorithm = "Ed25519"
	KeyAlgorithmEd448             KeyAlgorithm = "Ed448"
	KeyAlgorithmX25519            KeyAlgorithm = "X25519"
	KeyAlgorithmX448              KeyAlgorithm = "X448"
	KeyAlgorithmHMACSHA256        KeyAlgorithm = "HMAC-SHA256"
	KeyAlgorithmHMACSHA384        KeyAlgorithm = "HMAC-SHA384"
	KeyAlgorithmHMACSHA512        KeyAlgorithm = "HMAC-SHA512"
)

// KeyManagementRequest names one key: GetKeyMetadata, GetKeyPolicy,
// DeleteKeyPolicy, GetKeyRotationPolicy, DeleteKeyRotationPolicy and
// ClearKeySafety take nothing more.
type KeyManagementRequest struct {
	Backend  string `json:"backend"`
	KeyID    string `json:"key_id"`
	TenantID string `json:"tenant_id,omitempty"`
}

// KeyManagementResponse confirms a change to one key at Timestamp (Unix
// seconds): DeleteKeyPolicy, DeleteKeyRotationPolicy, SetKeySafety and
// ClearKeySafety answer with it.
type KeyManagementResponse struct {
	KeyID     string `json:"key_id"`
	Timestamp int64  `json:"timestamp"`
}

// GetPublicKeyRequest asks for the public key of an asymmetric key. Version
// 0 is the current version.
type GetPublicKeyRequest struct {
	Backend  string `json:"backend"`
	KeyID    string `json:"key_id"`
	Version  uint64 `json:"version,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
}

// GetPublicKeyResponse carries the PKIX, DER-encoded public key.
type GetPublicKeyResponse struct {
	KeyID     string       `json:"key_id"`
	PublicKey []byte       `json:"public_key"`
	Algorithm KeyAlgorithm `json:"algorithm,omitempty"`
	Version   uint64       `json:"version"`
	Timestamp int64        `json:"timestamp"`
}

// RevokeKeyRequest revokes a key for good.
type RevokeKeyRequest struct {
	Backend  string `json:"backend"`
	KeyID    string `json:"key_id"`
	Reason   string `json:"reason,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
}

// RevokeKeyResponse reports the revoked key's status.
type RevokeKeyResponse struct {
	KeyID     string    `json:"key_id"`
	Status    KeyStatus `json:"status"`
	Timestamp int64     `json:"timestamp"`
}

// UpdateKeyStatusRequest enables or disables a key (Version 0) or one of
// its versions.
type UpdateKeyStatusRequest struct {
	Backend  string    `json:"backend"`
	KeyID    string    `json:"key_id"`
	Version  uint64    `json:"version,omitempty"`
	Status   KeyStatus `json:"status"`
	TenantID string    `json:"tenant_id,omitempty"`
}

// UpdateKeyStatusResponse reports the status set.
type UpdateKeyStatusResponse struct {
	KeyID     string    `json:"key_id"`
	Version   uint64    `json:"version,omitempty"`
	Status    KeyStatus `json:"status"`
	Timestamp int64     `json:"timestamp"`
}

// KeyMetadata is the non-secret description of a key.
type KeyMetadata struct {
	KeyID              string            `json:"key_id"`
	Name               string            `json:"name,omitempty"`
	Description        string            `json:"description,omitempty"`
	Algorithm          KeyAlgorithm      `json:"algorithm,omitempty"`
	Status             KeyStatus         `json:"status"`
	Usage              []KeyUsage        `json:"usage,omitempty"`
	Version            uint64            `json:"version"`
	Exportable         bool              `json:"exportable"`
	DeletionProtection bool              `json:"deletion_protection"`
	CreatedAt          int64             `json:"created_at,omitempty"`
	UpdatedAt          int64             `json:"updated_at,omitempty"`
	LastUsedAt         int64             `json:"last_used_at,omitempty"`
	RotationPolicy     *RotationPolicy   `json:"rotation_policy,omitempty"`
	Tags               map[string]string `json:"tags,omitempty"`
	Owner              string            `json:"owner,omitempty"`
}

// KeyMetadataResponse carries a key's metadata: GetKeyMetadata and
// UpdateKeyMetadata answer with it.
type KeyMetadataResponse struct {
	Metadata  *KeyMetadata `json:"metadata"`
	Timestamp int64        `json:"timestamp"`
}

// UpdateKeyMetadataRequest changes a key's mutable metadata. An empty Name
// or Description leaves it unchanged; Tags are merged into the key's tags
// and RemoveTags then removed.
type UpdateKeyMetadataRequest struct {
	Backend     string            `json:"backend"`
	KeyID       string            `json:"key_id"`
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	RemoveTags  []string          `json:"remove_tags,omitempty"`
	TenantID    string            `json:"tenant_id,omitempty"`
}

// KeyPolicy is a key's access policy. It narrows what RBAC grants and never
// widens it; every empty list or zero value imposes nothing.
type KeyPolicy struct {
	KeyID             string     `json:"key_id,omitempty"`
	Version           uint64     `json:"version,omitempty"`
	AllowedOperations []KeyUsage `json:"allowed_operations,omitempty"`
	AllowedPrincipals []string   `json:"allowed_principals,omitempty"`
	DeniedPrincipals  []string   `json:"denied_principals,omitempty"`
	ExpiresAt         int64      `json:"expires_at,omitempty"`
	RotationRequired  bool       `json:"rotation_required,omitempty"`
	MaxUsageCount     uint64     `json:"max_usage_count,omitempty"`
	RequireMFA        bool       `json:"require_mfa,omitempty"`
	UpdatedAt         int64      `json:"updated_at,omitempty"`
}

// SetKeyPolicyRequest sets a key's access policy.
type SetKeyPolicyRequest struct {
	Backend  string     `json:"backend"`
	KeyID    string     `json:"key_id"`
	Policy   *KeyPolicy `json:"policy"`
	TenantID string     `json:"tenant_id,omitempty"`
}

// SetKeyPolicyResponse reports the version of the policy stored.
type SetKeyPolicyResponse struct {
	KeyID         string `json:"key_id"`
	PolicyVersion uint64 `json:"policy_version"`
	Timestamp     int64  `json:"timestamp"`
}

// GetKeyPolicyResponse carries a key's access policy; Policy is nil when the
// key has none.
type GetKeyPolicyResponse struct {
	Policy    *KeyPolicy `json:"policy,omitempty"`
	Timestamp int64      `json:"timestamp"`
}

// RotationPolicy is a key's automatic rotation policy.
type RotationPolicy struct {
	Enabled         bool  `json:"enabled"`
	IntervalSeconds int64 `json:"interval_seconds"`
	NextRotation    int64 `json:"next_rotation,omitempty"`
	RetainVersions  int32 `json:"retain_versions,omitempty"`
	AutoRotate      bool  `json:"auto_rotate,omitempty"`
}

// SetKeyRotationPolicyRequest sets a key's rotation policy.
type SetKeyRotationPolicyRequest struct {
	Backend  string          `json:"backend"`
	KeyID    string          `json:"key_id"`
	Policy   *RotationPolicy `json:"policy"`
	TenantID string          `json:"tenant_id,omitempty"`
}

// KeyRotationPolicyResponse carries a key's rotation policy; Policy is nil
// when the key has none. SetKeyRotationPolicy and GetKeyRotationPolicy
// answer with it.
type KeyRotationPolicyResponse struct {
	KeyID     string          `json:"key_id"`
	Policy    *RotationPolicy `json:"policy,omitempty"`
	Timestamp int64           `json:"timestamp"`
}

// BackendRequest names a backend; empty is the default backend.
// GetSupportedAlgorithms, BackendStatus and BackendTest take it.
type BackendRequest struct {
	Backend  string `json:"backend"`
	TenantID string `json:"tenant_id,omitempty"`
}

// GetSupportedAlgorithmsResponse lists the algorithms a backend supports.
type GetSupportedAlgorithmsResponse struct {
	Algorithms []KeyAlgorithm `json:"algorithms"`
}

// BackendStatusResponse reports a backend's type, health and capabilities.
type BackendStatusResponse struct {
	BackendType  string          `json:"backend_type"`
	Status       string          `json:"status"`
	Device       string          `json:"device,omitempty"`
	Region       string          `json:"region,omitempty"`
	KeyID        string          `json:"key_id,omitempty"`
	PCRBanks     []string        `json:"pcr_banks,omitempty"`
	PCRRegisters []int32         `json:"pcr_registers,omitempty"`
	Capabilities map[string]bool `json:"capabilities,omitempty"`
	Timestamp    int64           `json:"timestamp"`
}

// BackendTestResponse reports a backend's seal and unseal round trip.
type BackendTestResponse struct {
	Success    bool   `json:"success"`
	DurationMS int64  `json:"duration_ms"`
	Message    string `json:"message,omitempty"`
	Timestamp  int64  `json:"timestamp"`
}

// SetKeySafetyRequest sets a symmetric AEAD key's usage limits (NIST SP
// 800-38D §8.3, RFC 8439 §4). A zero limit is off; at least one is set. A
// zero WarningPercent is the default threshold.
type SetKeySafetyRequest struct {
	Backend        string `json:"backend"`
	KeyID          string `json:"key_id"`
	MaxOperations  uint64 `json:"max_operations,omitempty"`
	MaxBytes       uint64 `json:"max_bytes,omitempty"`
	WarningPercent int32  `json:"warning_percent,omitempty"`
	TenantID       string `json:"tenant_id,omitempty"`
}

// SafetyWarning is the usage of one key with usage limits.
type SafetyWarning struct {
	Type           string  `json:"type"`
	Path           string  `json:"path"`
	UsagePercent   float64 `json:"usage_percent"`
	Status         string  `json:"status"`
	OperationsUsed uint64  `json:"operations_used"`
	BytesUsed      uint64  `json:"bytes_used"`
	MaxOperations  uint64  `json:"max_operations,omitempty"`
	MaxBytes       uint64  `json:"max_bytes,omitempty"`
}

// SafetyCheckRequest asks for the keys of the caller's tenant at or past
// their warning threshold.
type SafetyCheckRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
}

// SafetyCheckResponse lists the keys at or past their warning threshold.
type SafetyCheckResponse struct {
	Warnings  []SafetyWarning `json:"warnings"`
	Timestamp int64           `json:"timestamp"`
}

// SafetyReportRequest asks for the usage of every key of the caller's tenant
// with usage limits. Format is "", "json", "table" or "prometheus"; it names
// how a client renders the report, which the service returns structured.
type SafetyReportRequest struct {
	Format   string `json:"format,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
}

// SafetyReportResponse is the usage of every key with usage limits.
// TotalDEKs and the DEK counts are zero: data encryption keys are go-qrdb's
// (DEKClient), which reports their usage itself.
type SafetyReportResponse struct {
	AllItems       []SafetyWarning `json:"all_items"`
	TotalKeys      int32           `json:"total_keys"`
	TotalDEKs      int32           `json:"total_deks"`
	KeysAtWarning  int32           `json:"keys_at_warning"`
	KeysAtCritical int32           `json:"keys_at_critical"`
	DEKsAtWarning  int32           `json:"deks_at_warning"`
	DEKsAtCritical int32           `json:"deks_at_critical"`
	Timestamp      int64           `json:"timestamp"`
}
