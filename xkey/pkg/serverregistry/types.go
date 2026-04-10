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

package serverregistry

import (
	"context"
	"time"
)

// Protocol constants for server connections.
const (
	ProtocolREST = "rest"
	ProtocolGRPC = "grpc"
	ProtocolQUIC = "quic"
	ProtocolMCP  = "mcp"
)

// ServerEntry represents a registered xkms server.
type ServerEntry struct {
	URL             string    `json:"url"`            // "https://xkms.company.com:8443"
	Name            string    `json:"name"`           // Human-friendly label
	CAFingerprint   string    `json:"ca_fingerprint"` // SHA-256 fingerprint -> lookup in Trust Store
	Protocol        string    `json:"protocol"`       // "rest", "grpc", "quic", "mcp"
	RegisteredAt    time.Time `json:"registered_at"`
	LastConnectedAt time.Time `json:"last_connected_at"`
}

// Validate checks the entry for required fields.
func (e *ServerEntry) Validate() error {
	if e.URL == "" {
		return ErrInvalidURL
	}
	return nil
}

// ServerRegistry defines the persistence interface for server entries.
type ServerRegistry interface {
	Register(ctx context.Context, entry *ServerEntry) error
	Lookup(ctx context.Context, url string) (*ServerEntry, error)
	Update(ctx context.Context, entry *ServerEntry) error
	List(ctx context.Context) ([]*ServerEntry, error)
	Delete(ctx context.Context, url string) error
	Close() error
}
