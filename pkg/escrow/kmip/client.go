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

// Package kmip provides an escrow.EscrowAgent implementation using the
// KMIP (Key Management Interoperability Protocol) standard.
//
// NOTE: This is a stub implementation. The KMIP protocol library
// github.com/ovh/kmip-go is NOT yet added to go.mod. All agent methods
// currently return escrow.ErrNotImplemented. Once the dependency is added,
// this package will implement full KMIP 1.4+ escrow operations including:
//   - KMIP Register for key escrow
//   - KMIP Get for key recovery
//   - KMIP Locate for listing escrowed keys
//   - KMIP Destroy for revoking escrowed keys
//   - mTLS transport per KMIP specification
package kmip

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/escrow"
)

// KMIPConfig configures the KMIP escrow agent.
type KMIPConfig struct {
	// Endpoint is the KMIP server address (e.g., "kmip://escrow.company.com:5696").
	Endpoint string `json:"endpoint"`

	// ClientCert is the path to the client TLS certificate PEM file.
	ClientCert string `json:"client_cert"`

	// ClientKey is the path to the client TLS private key PEM file.
	ClientKey string `json:"client_key"`

	// CACert is the path to the CA certificate PEM file.
	CACert string `json:"ca_cert"`
}

// Validate checks the configuration for required fields.
func (c *KMIPConfig) Validate() error {
	if c.Endpoint == "" {
		return escrow.ErrEmptyEndpoint
	}
	return nil
}

// KMIPAgent implements escrow.EscrowAgent using the KMIP protocol.
//
// NOTE: Requires github.com/ovh/kmip-go dependency (not yet added to go.mod).
// All methods currently return escrow.ErrNotImplemented.
type KMIPAgent struct {
	config *KMIPConfig
}

// Compile-time interface assertion.
var _ escrow.EscrowAgent = (*KMIPAgent)(nil)

// NewKMIPAgent creates a new KMIP escrow agent.
// The agent validates the configuration but does not establish a connection
// until an operation is invoked (all operations currently return ErrNotImplemented).
func NewKMIPAgent(config *KMIPConfig) (*KMIPAgent, error) {
	if config == nil {
		return nil, escrow.ErrAgentNotConfigured
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &KMIPAgent{
		config: config,
	}, nil
}

// Type returns the agent type identifier.
func (a *KMIPAgent) Type() string {
	return escrow.AgentTypeKMIP
}

// Available reports whether the KMIP server can be reached.
// Stub: always returns false until the KMIP library is integrated.
func (a *KMIPAgent) Available(_ context.Context) bool {
	return false
}

// EscrowKey sends wrapped key material to the KMIP server.
// Stub: returns ErrNotImplemented.
func (a *KMIPAgent) EscrowKey(_ context.Context, req *escrow.EscrowRequest) (*escrow.EscrowReceipt, error) {
	if req == nil {
		return nil, escrow.ErrNilRequest
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w: KMIP protocol library not yet integrated (requires github.com/ovh/kmip-go)",
		escrow.ErrNotImplemented)
}

// RecoverKey retrieves wrapped key material from the KMIP server.
// Stub: returns ErrNotImplemented.
func (a *KMIPAgent) RecoverKey(_ context.Context, req *escrow.RecoverRequest) (*escrow.RecoverResponse, error) {
	if req == nil {
		return nil, escrow.ErrNilRequest
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w: KMIP protocol library not yet integrated (requires github.com/ovh/kmip-go)",
		escrow.ErrNotImplemented)
}

// ListEscrowed returns all keys held by the KMIP server.
// Stub: returns ErrNotImplemented.
func (a *KMIPAgent) ListEscrowed(_ context.Context) ([]escrow.EscrowRecord, error) {
	return nil, fmt.Errorf("%w: KMIP protocol library not yet integrated (requires github.com/ovh/kmip-go)",
		escrow.ErrNotImplemented)
}

// RevokeEscrow removes an escrowed key from the KMIP server.
// Stub: returns ErrNotImplemented.
func (a *KMIPAgent) RevokeEscrow(_ context.Context, escrowID string) error {
	if escrowID == "" {
		return escrow.ErrEmptyKeyID
	}
	return fmt.Errorf("%w: KMIP protocol library not yet integrated (requires github.com/ovh/kmip-go)",
		escrow.ErrNotImplemented)
}

// Close releases resources held by the KMIP agent.
// Stub: no resources to release.
func (a *KMIPAgent) Close() error {
	return nil
}
