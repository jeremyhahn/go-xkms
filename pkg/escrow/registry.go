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

package escrow

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Registry manages multiple escrow agents and provides a unified interface
// for escrowing keys across all registered agents simultaneously (belt and
// suspenders) and recovering from any available agent.
type Registry struct {
	mu     sync.RWMutex
	agents map[string]EscrowAgent
}

// NewRegistry creates a new empty escrow agent registry.
func NewRegistry() *Registry {
	return &Registry{
		agents: make(map[string]EscrowAgent),
	}
}

// Register adds an escrow agent to the registry under the given name.
// Returns an error if the name is empty, the agent is nil, or the name
// is already registered.
func (r *Registry) Register(name string, agent EscrowAgent) error {
	if name == "" {
		return ErrEmptyAgentName
	}
	if agent == nil {
		return ErrNilAgent
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.agents[name]; exists {
		return fmt.Errorf("%w: %s", ErrAgentAlreadyRegistered, name)
	}

	r.agents[name] = agent
	return nil
}

// Get returns an agent by name. Returns ErrAgentNotConfigured if the name
// is not found in the registry.
func (r *Registry) Get(name string) (EscrowAgent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	agent, exists := r.agents[name]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrAgentNotConfigured, name)
	}
	return agent, nil
}

// Agents returns a snapshot of all registered agent names.
func (r *Registry) Agents() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.agents))
	for name := range r.agents {
		names = append(names, name)
	}
	return names
}

// EscrowKeyAll sends the escrow request to ALL registered agents.
// This implements the belt-and-suspenders approach where key material is
// replicated to every escrow agent. Returns receipts from all agents that
// succeeded. Returns an error only if ALL agents fail.
func (r *Registry) EscrowKeyAll(ctx context.Context, req *EscrowRequest) ([]*EscrowReceipt, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}

	r.mu.RLock()
	agentsCopy := make(map[string]EscrowAgent, len(r.agents))
	for k, v := range r.agents {
		agentsCopy[k] = v
	}
	r.mu.RUnlock()

	if len(agentsCopy) == 0 {
		return nil, ErrRegistryEmpty
	}

	var (
		receipts []*EscrowReceipt
		errs     []error
	)

	for name, agent := range agentsCopy {
		receipt, err := agent.EscrowKey(ctx, req)
		if err != nil {
			errs = append(errs, fmt.Errorf("agent %s: %w", name, err))
			continue
		}
		receipts = append(receipts, receipt)
	}

	if len(receipts) == 0 {
		return nil, fmt.Errorf("%w: %w", ErrEscrowFailed, errors.Join(errs...))
	}

	return receipts, nil
}

// RecoverKeyAny tries each registered agent until one succeeds in recovering
// the requested key. Returns the first successful response. Returns an error
// if no agent can fulfill the request.
func (r *Registry) RecoverKeyAny(ctx context.Context, req *RecoverRequest) (*RecoverResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}

	r.mu.RLock()
	agentsCopy := make(map[string]EscrowAgent, len(r.agents))
	for k, v := range r.agents {
		agentsCopy[k] = v
	}
	r.mu.RUnlock()

	if len(agentsCopy) == 0 {
		return nil, ErrRegistryEmpty
	}

	var errs []error

	for name, agent := range agentsCopy {
		resp, err := agent.RecoverKey(ctx, req)
		if err != nil {
			errs = append(errs, fmt.Errorf("agent %s: %w", name, err))
			continue
		}
		return resp, nil
	}

	return nil, fmt.Errorf("%w: %w", ErrRecoverFailed, errors.Join(errs...))
}

// ListAll returns escrow records from all registered agents, aggregated
// into a single slice.
func (r *Registry) ListAll(ctx context.Context) ([]EscrowRecord, error) {
	r.mu.RLock()
	agentsCopy := make(map[string]EscrowAgent, len(r.agents))
	for k, v := range r.agents {
		agentsCopy[k] = v
	}
	r.mu.RUnlock()

	if len(agentsCopy) == 0 {
		return nil, ErrRegistryEmpty
	}

	var (
		allRecords []EscrowRecord
		errs       []error
	)

	for name, agent := range agentsCopy {
		records, err := agent.ListEscrowed(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("agent %s: %w", name, err))
			continue
		}
		allRecords = append(allRecords, records...)
	}

	if len(allRecords) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return allRecords, nil
}

// Close closes all registered agents and clears the registry.
func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error
	for name, agent := range r.agents {
		if err := agent.Close(); err != nil {
			errs = append(errs, fmt.Errorf("agent %s: %w", name, err))
		}
	}

	r.agents = make(map[string]EscrowAgent)

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
