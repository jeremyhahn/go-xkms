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

package nonce

import (
	"context"
	"sync"
)

// NonceService defines the interface for nonce generation and validation.
type NonceService interface {
	// Generate creates a new unique nonce.
	Generate() (string, error)

	// Redeem validates and marks a nonce as used.
	// Returns nil if valid, or an error if the nonce is invalid.
	Redeem(nonce string) error

	// Valid checks if a nonce is valid without marking it as used.
	Valid(nonce string) error

	// Prefix returns the nonce prefix (if any).
	Prefix() string
}

// Getter is the interface for getting nonces.
type Getter interface {
	// Nonce returns a new nonce.
	Nonce(ctx context.Context) (string, error)
}

// Redeemer is the interface for redeeming nonces.
type Redeemer interface {
	// Redeem validates and marks a nonce as used.
	Redeem(ctx context.Context, nonce string) error
}

// Ensure Service implements NonceService.
var _ NonceService = (*Service)(nil)

// ServiceAdapter adapts a NonceService to Getter and Redeemer interfaces.
type ServiceAdapter struct {
	service NonceService
}

// NewServiceAdapter creates a new adapter for the given NonceService.
func NewServiceAdapter(service NonceService) *ServiceAdapter {
	return &ServiceAdapter{service: service}
}

// Nonce implements Getter.
func (a *ServiceAdapter) Nonce(_ context.Context) (string, error) {
	return a.service.Generate()
}

// Redeem implements Redeemer.
func (a *ServiceAdapter) Redeem(_ context.Context, nonce string) error {
	return a.service.Redeem(nonce)
}

// MultiService manages multiple nonce services, each with a unique prefix.
// This is useful for distributed deployments where each node has its own
// nonce service but they need to validate nonces from any node.
type MultiService struct {
	services map[string]NonceService
	mu       sync.RWMutex
	local    NonceService
}

// NewMultiService creates a MultiService with the given local service.
func NewMultiService(local NonceService) *MultiService {
	m := &MultiService{
		services: make(map[string]NonceService),
		local:    local,
	}
	if local != nil && local.Prefix() != "" {
		m.services[local.Prefix()] = local
	}
	return m
}

// SetLocal replaces the local nonce service: the one Generate mints from and
// the one Redeem/Valid fall back to for an unprefixed or unregistered-prefix
// nonce. If the previous local service was registered under its own prefix,
// that registration is replaced by service's rather than left stale, so a
// caller that rotates its local service's signing epoch (a fresh counter
// window under the same prefix, e.g. to bound a nonce's lifetime) does not
// accumulate retired epochs in the registry.
func (m *MultiService) SetLocal(service NonceService) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.local != nil {
		if prefix := m.local.Prefix(); prefix != "" && m.services[prefix] == m.local {
			delete(m.services, prefix)
		}
	}
	m.local = service
	if service != nil {
		if prefix := service.Prefix(); prefix != "" {
			m.services[prefix] = service
		}
	}
}

// Register adds a remote nonce service.
func (m *MultiService) Register(service NonceService) {
	prefix := service.Prefix()
	if prefix == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.services[prefix] = service
}

// Unregister removes a nonce service by prefix.
func (m *MultiService) Unregister(prefix string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.services, prefix)
}

// Generate creates a new nonce using the local service.
func (m *MultiService) Generate() (string, error) {
	return m.local.Generate()
}

// Redeem validates a nonce by routing to the appropriate service based on prefix.
func (m *MultiService) Redeem(nonce string) error {
	if len(nonce) < PrefixLen {
		return m.local.Redeem(nonce)
	}

	prefix := nonce[:PrefixLen]

	m.mu.RLock()
	service, ok := m.services[prefix]
	m.mu.RUnlock()

	if !ok {
		// Unknown prefix, try local.
		return m.local.Redeem(nonce)
	}

	return service.Redeem(nonce)
}

// Valid checks if a nonce is valid by routing to the appropriate service.
func (m *MultiService) Valid(nonce string) error {
	if len(nonce) < PrefixLen {
		return m.local.Valid(nonce)
	}

	prefix := nonce[:PrefixLen]

	m.mu.RLock()
	service, ok := m.services[prefix]
	m.mu.RUnlock()

	if !ok {
		return m.local.Valid(nonce)
	}

	return service.Valid(nonce)
}

// Prefix returns the local service's prefix.
func (m *MultiService) Prefix() string {
	return m.local.Prefix()
}

// Ensure MultiService implements NonceService.
var _ NonceService = (*MultiService)(nil)
