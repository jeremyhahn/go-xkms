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

// Package keypolicy persists the management state of a key that its backend
// does not hold: its status, mutable metadata, access policy, rotation
// policy, AEAD usage limits and usage counters. One Record per key is stored
// through a go-qrdb DAO.
//
// A key policy narrows what RBAC already grants and never widens it: the
// service authorizes every request by permission first and consults the
// record only after that. A key with no record has no policy, so it falls
// back to RBAC alone.
package keypolicy

import (
	"slices"
	"time"
)

// Status is the key-level lifecycle state a record holds.
type Status string

const (
	// StatusEnabled is a usable key. A record with an empty Status is
	// enabled too.
	StatusEnabled Status = "enabled"

	// StatusDisabled is a key refused for every operation until enabled.
	StatusDisabled Status = "disabled"

	// StatusRevoked is a key refused for every operation for good.
	// Revocation is terminal.
	StatusRevoked Status = "revoked"
)

// Operation names a cryptographic use of a key a policy can allow.
type Operation string

const (
	OpEncrypt     Operation = "encrypt"
	OpDecrypt     Operation = "decrypt"
	OpSign        Operation = "sign"
	OpVerify      Operation = "verify"
	OpWrapKey     Operation = "wrap_key"
	OpDeriveKey   Operation = "derive_key"
	OpGenerateMAC Operation = "generate_mac"
	OpVerifyMAC   Operation = "verify_mac"

	// OpUnwrapKey is the inverse of OpWrapKey. A policy does not name it:
	// the wrap_key usage allows both directions, so it is checked as
	// OpWrapKey, and like decryption it does not count toward the safety
	// limits.
	OpUnwrapKey Operation = "unwrap_key"

	// OpExportKey releases a key's material from its keystore: export,
	// copy to another backend, or wrapping the key under another. A policy
	// cannot name it, because an exported key escapes every restriction
	// the policy places on it, so a key whose policy restricts its
	// operations is never exported. It does not count toward the safety
	// limits.
	OpExportKey Operation = "export_key"
)

// validOperations is the set of Operation values a policy may name.
var validOperations = map[Operation]bool{
	OpEncrypt: true, OpDecrypt: true, OpSign: true, OpVerify: true,
	OpWrapKey: true, OpDeriveKey: true, OpGenerateMAC: true, OpVerifyMAC: true,
}

// Valid reports whether op is an Operation a policy may name.
func (op Operation) Valid() bool { return validOperations[op] }

// permission returns the Operation a policy names to allow op.
func (op Operation) permission() Operation {
	if op == OpUnwrapKey {
		return OpWrapKey
	}
	return op
}

const (
	// DefaultWarningPercent is the usage percentage at which a key with
	// usage limits but no warning threshold of its own is reported.
	DefaultWarningPercent = 80

	// CriticalPercent is the usage percentage at which a key is reported
	// critical.
	CriticalPercent = 95

	// MaxGCMInvocations is the most authenticated-encryption invocations
	// one AES-GCM key may perform with random 96-bit IVs: NIST SP 800-38D
	// §8.3 bounds the probability of an IV collision by capping them at
	// 2^32.
	MaxGCMInvocations = 1 << 32
)

// Safety levels a usage report carries.
const (
	LevelWarning  = "warning"
	LevelCritical = "critical"
	LevelExceeded = "exceeded"
)

// Policy is a key's access policy. Every condition narrows: an empty list
// or a zero value imposes nothing.
type Policy struct {
	Version           uint64      `json:"version"`
	AllowedOperations []Operation `json:"allowed_operations,omitempty"`
	AllowedPrincipals []string    `json:"allowed_principals,omitempty"`
	DeniedPrincipals  []string    `json:"denied_principals,omitempty"`
	ExpiresAt         int64       `json:"expires_at,omitempty"`
	RotationRequired  bool        `json:"rotation_required,omitempty"`
	MaxUsageCount     uint64      `json:"max_usage_count,omitempty"`
	UpdatedAt         int64       `json:"updated_at"`
}

// Rotation is a key's automatic rotation policy.
type Rotation struct {
	Enabled         bool  `json:"enabled"`
	IntervalSeconds int64 `json:"interval_seconds"`
	NextRotation    int64 `json:"next_rotation"`
	RetainVersions  int32 `json:"retain_versions,omitempty"`
	AutoRotate      bool  `json:"auto_rotate,omitempty"`
}

// Safety is a key's AEAD usage limits. Each limit is off at zero; at least
// one is set.
//
// The limits bound the uses of one AEAD key: NIST SP 800-38D §8.3 caps the
// invocations of AES-GCM's authenticated encryption function under one key,
// and RFC 8439 §4 notes that ChaCha20-Poly1305 is safe for at most 2^64
// messages under one key but that a deployment should rotate far sooner.
type Safety struct {
	MaxOperations  uint64 `json:"max_operations,omitempty"`
	MaxBytes       uint64 `json:"max_bytes,omitempty"`
	WarningPercent int32  `json:"warning_percent"`
}

// Usage counts a key's uses since its record began tracking them. Uses
// counts every operation; Operations and Bytes count authenticated
// encryptions and their plaintext under one version's material (see
// Material), the quantities Safety limits.
type Usage struct {
	Uses       uint64 `json:"uses,omitempty"`
	Operations uint64 `json:"operations,omitempty"`
	Bytes      uint64 `json:"bytes,omitempty"`

	// Version is the key version whose material Operations and Bytes count.
	Version uint32 `json:"version,omitempty"`
}

// Record is the management state of one key.
type Record struct {
	KeyID        string            `json:"key_id"`
	Backend      string            `json:"backend"`
	DisplayName  string            `json:"display_name,omitempty"`
	Description  string            `json:"description,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	Status       Status            `json:"status,omitempty"`
	RevokeReason string            `json:"revoke_reason,omitempty"`
	Owner        string            `json:"owner,omitempty"`
	CreatedAt    int64             `json:"created_at"`
	UpdatedAt    int64             `json:"updated_at"`
	LastUsedAt   int64             `json:"last_used_at,omitempty"`
	Policy       *Policy           `json:"policy,omitempty"`
	Rotation     *Rotation         `json:"rotation,omitempty"`
	Safety       *Safety           `json:"safety,omitempty"`
	Usage        Usage             `json:"usage"`
}

// Implicit returns the record of a key that has none stored: enabled, with
// no policy and no limits.
func Implicit(keyID, backend string) *Record {
	return &Record{KeyID: keyID, Backend: backend}
}

// EffectiveStatus returns the record's status, StatusEnabled when unset.
func (r *Record) EffectiveStatus() Status {
	if r.Status == "" {
		return StatusEnabled
	}
	return r.Status
}

// Tracks reports whether the record counts the key's uses: only a key with
// usage limits or a usage-count policy needs its uses written back.
func (r *Record) Tracks() bool {
	return r.Safety != nil || (r.Policy != nil && r.Policy.MaxUsageCount > 0)
}

// Empty reports whether the record holds nothing worth storing, so that
// deleting its last policy can delete the record too.
func (r *Record) Empty() bool {
	return r.Status == "" && r.DisplayName == "" && r.Description == "" && len(r.Tags) == 0 &&
		r.Policy == nil && r.Rotation == nil && r.Safety == nil
}

// Check returns why the record refuses op by principal at now, or nil. A
// key that is not enabled is refused first, then each policy condition is
// checked, then an authenticated encryption of n bytes is checked against
// the usage limits.
func (r *Record) Check(principal string, op Operation, n uint64, now time.Time) error {
	if status := r.EffectiveStatus(); status != StatusEnabled {
		return &KeyUnavailableError{KeyID: r.KeyID, Status: status}
	}
	if r.Policy != nil {
		if reason := r.policyRefusal(principal, op, now); reason != "" {
			return &PolicyDeniedError{KeyID: r.KeyID, Operation: op, Reason: reason}
		}
	}
	if r.Safety != nil && countsTowardSafety(op) {
		if r.Safety.MaxOperations > 0 && r.Usage.Operations >= r.Safety.MaxOperations {
			return &SafetyLimitError{KeyID: r.KeyID, Limit: "operations"}
		}
		if r.Safety.MaxBytes > 0 && (r.Usage.Bytes >= r.Safety.MaxBytes || n > r.Safety.MaxBytes-r.Usage.Bytes) {
			return &SafetyLimitError{KeyID: r.KeyID, Limit: "bytes"}
		}
	}
	return nil
}

// policyRefusal returns the policy condition refusing op by principal at
// now, or "".
func (r *Record) policyRefusal(principal string, op Operation, now time.Time) string {
	p := r.Policy
	switch {
	case p.ExpiresAt > 0 && now.Unix() >= p.ExpiresAt:
		return "the policy has expired"
	case slices.Contains(p.DeniedPrincipals, principal):
		return "the principal is denied"
	case len(p.AllowedPrincipals) > 0 && !slices.Contains(p.AllowedPrincipals, principal):
		return "the principal is not allowed"
	case len(p.AllowedOperations) > 0 && !slices.Contains(p.AllowedOperations, op.permission()):
		return "the operation is not allowed"
	case p.MaxUsageCount > 0 && r.Usage.Uses >= p.MaxUsageCount:
		return "the usage count is exhausted"
	case p.RotationRequired && r.Rotation != nil && r.Rotation.NextRotation > 0 && now.Unix() >= r.Rotation.NextRotation:
		return "the key is overdue for rotation"
	}
	return ""
}

// Use records one use of the key for op over n bytes at now.
func (r *Record) Use(op Operation, n uint64, now time.Time) {
	r.Usage.Uses++
	if countsTowardSafety(op) {
		r.Usage.Operations++
		r.Usage.Bytes += n
	}
	r.LastUsedAt = now.Unix()
}

// Material points the safety counters at version v of the key's material and
// reports whether they count it. Operations and Bytes belong to one version:
// a newer version starts them from zero, and an older version, whose
// counters a rotation has already dropped, is refused (false). Versions only
// grow (keyversion.Record.AddCurrent), so counters made for a version are
// never zeroed while that version can still be counted.
func (r *Record) Material(v uint32) bool {
	switch {
	case v > r.Usage.Version:
		r.Usage.Version, r.Usage.Operations, r.Usage.Bytes = v, 0, 0
	case v < r.Usage.Version:
		return false
	}
	return true
}

// countsTowardSafety reports whether op invokes the authenticated
// encryption function the usage limits bound: encrypting and wrapping do,
// decrypting does not (NIST SP 800-38D §8.3 counts invocations of the
// authenticated encryption function).
func countsTowardSafety(op Operation) bool {
	return op == OpEncrypt || op == OpWrapKey
}

// UsagePercent returns how much of its tightest limit the key has used, in
// percent. It is zero for a record without limits.
func (r *Record) UsagePercent() float64 {
	if r.Safety == nil {
		return 0
	}
	var percent float64
	if r.Safety.MaxOperations > 0 {
		percent = max(percent, float64(r.Usage.Operations)/float64(r.Safety.MaxOperations)*100)
	}
	if r.Safety.MaxBytes > 0 {
		percent = max(percent, float64(r.Usage.Bytes)/float64(r.Safety.MaxBytes)*100)
	}
	return percent
}

// Level returns the record's safety level: LevelExceeded at or past a limit,
// LevelCritical from CriticalPercent, LevelWarning from its warning
// threshold, and "" below it.
func (r *Record) Level() string {
	if r.Safety == nil {
		return ""
	}
	percent := r.UsagePercent()
	warning := float64(r.Safety.WarningPercent)
	if warning == 0 {
		warning = DefaultWarningPercent
	}
	switch {
	case percent >= 100:
		return LevelExceeded
	case percent >= CriticalPercent:
		return LevelCritical
	case percent >= warning:
		return LevelWarning
	}
	return ""
}
