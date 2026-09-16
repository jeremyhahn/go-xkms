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

package xkms

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/escrow"
)

// EscrowServicer defines operations for external key escrow (pkg/escrow).
// Escrow state is owned by the configured external agents (KMIP server, or
// a remote go-xkms federation peer); this servicer is the sole entry point a
// transport may call — it never lets a transport reach an escrow.Registry or
// escrow.EscrowAgent directly. Escrow request/response types are the
// pkg/escrow domain types themselves (EscrowRequest, EscrowReceipt,
// RecoverRequest, RecoverResponse, EscrowRecord): they already carry the
// correct JSON tags and Validate() methods, so re-declaring them under
// pkg/api/transport would only duplicate the wire contract.
type EscrowServicer interface {
	EscrowKey(ctx context.Context, req *escrow.EscrowRequest) ([]*escrow.EscrowReceipt, error)
	RecoverKey(ctx context.Context, req *escrow.RecoverRequest) (*escrow.RecoverResponse, error)
	ListEscrowed(ctx context.Context) ([]escrow.EscrowRecord, error)
	RevokeEscrow(ctx context.Context, escrowID string) error
}

// EscrowKey sends wrapped key material to every configured escrow agent
// (belt-and-suspenders replication). The caller must have already wrapped
// the key material with AES-KW or RSA-OAEP: no escrow agent ever receives
// plaintext key material. Succeeds if at least one agent accepts the key.
func (s *XKMSService) EscrowKey(ctx context.Context, req *escrow.EscrowRequest) ([]*escrow.EscrowReceipt, error) {
	if s.escrow == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	return s.escrow.EscrowKeyAll(ctx, req)
}

// RecoverKey retrieves wrapped key material from the first configured escrow
// agent that has it. The returned key material remains wrapped; the caller
// is responsible for unwrapping it.
func (s *XKMSService) RecoverKey(ctx context.Context, req *escrow.RecoverRequest) (*escrow.RecoverResponse, error) {
	if s.escrow == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	return s.escrow.RecoverKeyAny(ctx, req)
}

// ListEscrowed returns the aggregated escrow records held across every
// configured escrow agent.
func (s *XKMSService) ListEscrowed(ctx context.Context) ([]escrow.EscrowRecord, error) {
	if s.escrow == nil {
		return nil, ErrNotConfigured
	}
	return s.escrow.ListAll(ctx)
}

// RevokeEscrow removes an escrowed key, identified by its escrow-assigned
// ID, from every configured escrow agent.
func (s *XKMSService) RevokeEscrow(ctx context.Context, escrowID string) error {
	if s.escrow == nil {
		return ErrNotConfigured
	}
	return s.escrow.RevokeEscrowAll(ctx, escrowID)
}
