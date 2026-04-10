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

package policy

import "sync"

// Engine evaluates MFA policies for operations. It is safe for
// concurrent use.
type Engine struct {
	mu     sync.RWMutex
	policy *MFAPolicy
}

// NewEngine creates a new policy engine with the given policy.
// If policy is nil, a default policy is used.
func NewEngine(p *MFAPolicy) *Engine {
	if p == nil {
		p = DefaultPolicy()
	}
	return &Engine{policy: p}
}

// DefaultPolicy returns the default MFA policy with sensible defaults.
// Default level is FIDO2, with 3FA required for barrier unseal, key export,
// tenant create, escrow key, and recover key operations.
func DefaultPolicy() *MFAPolicy {
	return &MFAPolicy{
		DefaultLevel: MFAFIDO2,
		Operations: map[string]*OperationPolicy{
			OpBarrierUnseal: {
				Operation:     OpBarrierUnseal,
				RequiredLevel: MFAFIDO2OATH,
				Description:   "Unsealing the barrier requires 3FA (FIDO2 + OATH)",
				Enforced:      true,
			},
			OpKeyExport: {
				Operation:     OpKeyExport,
				RequiredLevel: MFAFIDO2OATH,
				Description:   "Exporting keys requires 3FA (FIDO2 + OATH)",
				Enforced:      true,
			},
			OpTenantCreate: {
				Operation:     OpTenantCreate,
				RequiredLevel: MFAFIDO2OATH,
				Description:   "Creating tenants requires 3FA (FIDO2 + OATH)",
				Enforced:      true,
			},
			OpEscrowKey: {
				Operation:     OpEscrowKey,
				RequiredLevel: MFAFIDO2OATH,
				Description:   "Escrowing keys requires 3FA (FIDO2 + OATH)",
				Enforced:      true,
			},
			OpRecoverKey: {
				Operation:     OpRecoverKey,
				RequiredLevel: MFAFIDO2OATH,
				Description:   "Recovering keys requires 3FA (FIDO2 + OATH)",
				Enforced:      true,
			},
		},
	}
}

// Check evaluates whether the provided MFA level satisfies the
// policy for the given operation. Returns nil if satisfied,
// ErrInsufficientMFA if the level is not met and the policy is enforced.
// Non-enforced policies always return nil.
func (e *Engine) Check(operation string, provided MFALevel) error {
	if operation == "" {
		return ErrInvalidOperation
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	if op, ok := e.policy.Operations[operation]; ok {
		if !op.Enforced {
			return nil
		}
		if !op.RequiredLevel.SatisfiedBy(provided) {
			return ErrInsufficientMFA
		}
		return nil
	}

	// No explicit policy; fall back to default level.
	if !e.policy.DefaultLevel.SatisfiedBy(provided) {
		return ErrInsufficientMFA
	}
	return nil
}

// RequiredLevel returns the MFA level required for the given operation.
// If no explicit policy exists, the default level is returned.
func (e *Engine) RequiredLevel(operation string) MFALevel {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if op, ok := e.policy.Operations[operation]; ok {
		return op.RequiredLevel
	}
	return e.policy.DefaultLevel
}

// SetPolicy replaces the current policy. Returns ErrNilPolicy if
// the provided policy is nil.
func (e *Engine) SetPolicy(p *MFAPolicy) error {
	if p == nil {
		return ErrNilPolicy
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.policy = p
	return nil
}

// AddOperationPolicy adds a policy for a specific operation. If a policy
// for the operation already exists, it is replaced. Returns ErrNilPolicy
// if the policy is nil, or ErrInvalidOperation if the operation name is empty.
func (e *Engine) AddOperationPolicy(op *OperationPolicy) error {
	if op == nil {
		return ErrNilPolicy
	}
	if op.Operation == "" {
		return ErrInvalidOperation
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.policy.Operations == nil {
		e.policy.Operations = make(map[string]*OperationPolicy)
	}
	e.policy.Operations[op.Operation] = op
	return nil
}

// RemoveOperationPolicy removes the policy for a specific operation.
// Returns ErrInvalidOperation if the operation name is empty, or
// ErrPolicyNotFound if no policy exists for the operation.
func (e *Engine) RemoveOperationPolicy(operation string) error {
	if operation == "" {
		return ErrInvalidOperation
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.policy.Operations[operation]; !ok {
		return ErrPolicyNotFound
	}
	delete(e.policy.Operations, operation)
	return nil
}

// ListPolicies returns a copy of all operation policies. The returned
// slice is safe to modify without affecting the engine.
func (e *Engine) ListPolicies() []*OperationPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	policies := make([]*OperationPolicy, 0, len(e.policy.Operations))
	for _, op := range e.policy.Operations {
		copied := *op
		policies = append(policies, &copied)
	}
	return policies
}
