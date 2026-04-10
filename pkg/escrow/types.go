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

// Package escrow provides a pluggable external key escrow framework for go-xkms.
//
// Key escrow must be external (different system/location) per NIST SP 800-57.
// All key material is wrapped before escrow transmission using AES-KW (RFC 3394)
// or RSA-OAEP. The escrow agent never sees unwrapped key material.
//
// The package defines the EscrowAgent interface that implementations must satisfy,
// along with request/response types for escrow operations. Two implementations
// are provided: XKMS federation (pkg/escrow/xkms) for xkms-to-xkms replication,
// and a KMIP stub (pkg/escrow/kmip) awaiting the ovh/kmip-go dependency.
package escrow

import (
	"context"
	"time"
)

// Agent type constants identify the escrow agent protocol.
const (
	// AgentTypeKMIP identifies a KMIP protocol escrow agent.
	AgentTypeKMIP = "kmip"

	// AgentTypeXKMS identifies an xkms-to-xkms federation escrow agent.
	AgentTypeXKMS = "xkms"
)

// EscrowRequest contains the wrapped key material and metadata for escrow.
// The WrappedKey field must contain key material that has been wrapped with
// AES-KW (RFC 3394) or RSA-OAEP prior to submission.
type EscrowRequest struct {
	// KeyID identifies the key being escrowed.
	KeyID string `json:"key_id"`

	// WrappedKey is the key material wrapped with AES-KW or RSA-OAEP.
	// The escrow agent NEVER sees unwrapped key material.
	WrappedKey []byte `json:"wrapped_key"`

	// WrappingAlgorithm identifies how the key was wrapped.
	// Standard values: "AES-KW", "RSA-OAEP-SHA256".
	WrappingAlgorithm string `json:"wrapping_algorithm"`

	// KeyType describes the escrowed key type (e.g., "aes-256", "rsa-2048", "ec-p256").
	KeyType string `json:"key_type,omitempty"`

	// TenantID is the tenant scope. Empty means system-level escrow.
	TenantID string `json:"tenant_id,omitempty"`

	// Purpose describes why the key is being escrowed.
	// Standard values: "barrier", "signing-key", "backup".
	Purpose string `json:"purpose,omitempty"`

	// Metadata holds additional escrow metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Validate checks the request for required fields.
func (r *EscrowRequest) Validate() error {
	if r.KeyID == "" {
		return ErrEmptyKeyID
	}
	if len(r.WrappedKey) == 0 {
		return ErrNilWrappedKey
	}
	return nil
}

// EscrowReceipt is returned after a successful escrow operation.
type EscrowReceipt struct {
	// EscrowID is the unique identifier assigned by the escrow agent.
	EscrowID string `json:"escrow_id"`

	// KeyID is the original key identifier.
	KeyID string `json:"key_id"`

	// Agent identifies which escrow agent holds the key.
	Agent string `json:"agent"`

	// EscrowedAt is when the key was escrowed.
	EscrowedAt time.Time `json:"escrowed_at"`

	// ExpiresAt is when the escrow expires. Zero value means no expiry.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// RecoverRequest requests recovery of an escrowed key.
// At least one of EscrowID or KeyID must be set.
type RecoverRequest struct {
	// EscrowID is the escrow-assigned identifier.
	EscrowID string `json:"escrow_id,omitempty"`

	// KeyID is the original key identifier.
	KeyID string `json:"key_id,omitempty"`
}

// Validate checks the request for required fields.
func (r *RecoverRequest) Validate() error {
	if r.EscrowID == "" && r.KeyID == "" {
		return ErrEmptyKeyID
	}
	return nil
}

// RecoverResponse contains the recovered wrapped key material.
// The key material remains wrapped; the caller is responsible for unwrapping.
type RecoverResponse struct {
	// KeyID is the key identifier.
	KeyID string `json:"key_id"`

	// WrappedKey is the still-wrapped key material.
	WrappedKey []byte `json:"wrapped_key"`

	// WrappingAlgorithm identifies how the key is wrapped.
	WrappingAlgorithm string `json:"wrapping_algorithm"`
}

// EscrowRecord describes a single escrowed key in the escrow service.
type EscrowRecord struct {
	// EscrowID is the escrow-assigned unique identifier.
	EscrowID string `json:"escrow_id"`

	// KeyID is the original key identifier.
	KeyID string `json:"key_id"`

	// Agent identifies the escrow agent holding this key.
	Agent string `json:"agent"`

	// WrappingAlgorithm identifies how the key material was wrapped.
	WrappingAlgorithm string `json:"wrapping_algorithm"`

	// KeyType describes the escrowed key type.
	KeyType string `json:"key_type,omitempty"`

	// TenantID is the tenant scope.
	TenantID string `json:"tenant_id,omitempty"`

	// Purpose describes why the key was escrowed.
	Purpose string `json:"purpose,omitempty"`

	// EscrowedAt is when the key was escrowed.
	EscrowedAt time.Time `json:"escrowed_at"`

	// ExpiresAt is when the escrow expires. Zero value means no expiry.
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// Metadata holds additional escrow metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// EscrowAgent defines the pluggable interface for external key escrow.
// Implementations must ensure that key material is always transmitted
// in wrapped form and that the agent itself never accesses plaintext keys.
type EscrowAgent interface {
	// Type returns the agent type identifier (e.g., "kmip", "xkms").
	Type() string

	// Available reports whether the escrow agent can currently be reached.
	Available(ctx context.Context) bool

	// EscrowKey sends wrapped key material to the external escrow service.
	EscrowKey(ctx context.Context, req *EscrowRequest) (*EscrowReceipt, error)

	// RecoverKey retrieves wrapped key material from the escrow service.
	RecoverKey(ctx context.Context, req *RecoverRequest) (*RecoverResponse, error)

	// ListEscrowed returns all keys held by this escrow agent.
	ListEscrowed(ctx context.Context) ([]EscrowRecord, error)

	// RevokeEscrow removes an escrowed key from the service.
	RevokeEscrow(ctx context.Context, escrowID string) error

	// Close releases resources held by the agent.
	Close() error
}
