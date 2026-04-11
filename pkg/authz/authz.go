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

// Package authz provides the authorization interface for xkmsd.
//
// Standalone xkmsd uses built-in RBAC via RBACAuthorizer. Applications such
// as go-qrdb can replace the Authorizer with a custom implementation (e.g.,
// HybridProvider) to integrate external policy engines or attribute-based
// access control.
package authz

import "context"

// Authorizer defines the authorization interface for xkmsd.
// Standalone xkmsd uses built-in RBAC. go-qrdb replaces with HybridProvider.
type Authorizer interface {
	Authorize(ctx context.Context, req *AuthorizationRequest) (*AuthorizationDecision, error)
}

// AuthorizationRequest encapsulates the inputs needed for an authorization
// decision: who is asking, what role they claim, which resource they target,
// and which action they want to perform.
type AuthorizationRequest struct {
	// Subject is the user ID or username requesting access.
	Subject string

	// Role is the user's claimed role.
	Role string

	// Resource is the target resource category (e.g., "keys", "certs",
	// "users", "backends", "piv", "seal").
	Resource string

	// Action is the operation being requested (e.g., "read", "write",
	// "delete", "use", "manage").
	Action string

	// Context carries additional contextual information such as a specific
	// key ID, backend name, or tenant identifier.
	Context map[string]string
}

// AuthorizationDecision holds the result of an authorization check.
type AuthorizationDecision struct {
	// Allowed is true when the requested action is permitted.
	Allowed bool

	// Reason provides a human-readable explanation for the decision.
	Reason string
}

// NoOpAuthorizer unconditionally allows every request. It is intended for
// bootstrap, development, and no-auth deployment modes where authorization
// is intentionally disabled.
type NoOpAuthorizer struct{}

// Authorize always returns an allow decision regardless of the request content.
func (n *NoOpAuthorizer) Authorize(_ context.Context, _ *AuthorizationRequest) (*AuthorizationDecision, error) {
	return &AuthorizationDecision{Allowed: true, Reason: "no-op authorizer"}, nil
}
