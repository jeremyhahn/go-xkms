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
	"errors"
	"sync"

	xerrs "github.com/jeremyhahn/go-xkms/pkg/errs"
)

// AgentFactory constructs an EscrowAgent from an already-validated
// AgentConfig. Each escrow agent implementation (pkg/escrow/xkms,
// pkg/escrow/kmip) registers its factory via RegisterAgentFactory from an
// init() function, mirroring the backend-factory registration pattern in
// pkg/xkms/registry.go. This package cannot import the agent implementation
// packages directly: both already import pkg/escrow for the EscrowAgent
// interface and shared error types, so a direct import here would cycle.
type AgentFactory func(cfg *AgentConfig) (EscrowAgent, error)

var agentFactoriesMu sync.RWMutex
var agentFactories = make(map[string]AgentFactory)

// RegisterAgentFactory registers a factory function for the given agent
// type. Called from the init() function of each agent implementation
// package. Safe for concurrent use, though in practice it only ever runs
// sequentially from package init().
func RegisterAgentFactory(agentType string, factory AgentFactory) {
	agentFactoriesMu.Lock()
	defer agentFactoriesMu.Unlock()
	agentFactories[agentType] = factory
}

// NewAgent constructs an EscrowAgent from cfg, dispatching on cfg.Type via
// the map of registered agent factories. Returns ErrUnknownAgentType when no
// factory is registered for cfg.Type — this happens if the type is
// misspelled, or if the corresponding agent package was never imported (and
// therefore never ran its init() registration).
func NewAgent(cfg *AgentConfig) (EscrowAgent, error) {
	if cfg == nil {
		return nil, ErrAgentNotConfigured
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	agentFactoriesMu.RLock()
	factory, ok := agentFactories[cfg.Type]
	agentFactoriesMu.RUnlock()
	if !ok {
		return nil, &xerrs.Detail{Err: ErrUnknownAgentType, Detail: cfg.Type}
	}

	return factory(cfg)
}

// NewRegistryFromConfig builds a Registry from a Config, constructing and
// registering one agent per entry in cfg.Agents via NewAgent. Agents are
// registered under AgentConfig.Name when set, or AgentConfig.Type otherwise
// — a deployment running more than one agent of the same type must name each
// one explicitly, or registration fails with ErrAgentAlreadyRegistered.
//
// When cfg is nil or cfg.Enabled is false, NewRegistryFromConfig returns
// (nil, nil): escrow is off and no registry is constructed. Callers must
// treat a nil registry as "escrow not configured".
func NewRegistryFromConfig(cfg *Config) (*Registry, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	registry := NewRegistry()
	for i := range cfg.Agents {
		agentCfg := &cfg.Agents[i]
		agent, err := NewAgent(agentCfg)
		if err != nil {
			// Join rather than discard: Registry.Close aggregates per-agent
			// close failures, and a half-built registry that failed to release
			// an agent's handle is worth reporting alongside the cause.
			return nil, errors.Join(err, registry.Close())
		}

		name := agentCfg.Name
		if name == "" {
			name = agentCfg.Type
		}
		if err := registry.Register(name, agent); err != nil {
			return nil, errors.Join(err, registry.Close())
		}
	}

	return registry, nil
}
