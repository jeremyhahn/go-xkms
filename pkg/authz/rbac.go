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

package authz

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/rbac"
)

// Compile-time interface compliance checks.
var (
	_ Authorizer = (*RBACAuthorizer)(nil)
	_ Authorizer = (*NoOpAuthorizer)(nil)
)

// RBACAuthorizer implements the Authorizer interface by delegating permission
// checks to an underlying rbac.RBACAdapter. It translates the higher-level
// AuthorizationRequest into the Permission model used by the RBAC subsystem.
type RBACAuthorizer struct {
	adapter rbac.RBACAdapter
}

// NewRBACAuthorizer creates a new RBACAuthorizer backed by the given adapter.
func NewRBACAuthorizer(adapter rbac.RBACAdapter) *RBACAuthorizer {
	return &RBACAuthorizer{adapter: adapter}
}

// Authorize checks whether the subject identified in the request has the
// required permission (resource + action) through any of its assigned roles.
func (a *RBACAuthorizer) Authorize(ctx context.Context, req *AuthorizationRequest) (*AuthorizationDecision, error) {
	if req == nil {
		return nil, ErrInvalidRequest
	}

	if req.Subject == "" {
		return &AuthorizationDecision{Allowed: false, Reason: "empty subject"}, nil
	}

	perm := rbac.Permission{Resource: req.Resource, Action: req.Action}
	allowed, err := a.adapter.CheckPermission(ctx, req.Subject, perm)
	if err != nil {
		return nil, fmt.Errorf("authorization check failed: %w", err)
	}

	if !allowed {
		return &AuthorizationDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("role '%s' does not have permission %s:%s", req.Role, req.Resource, req.Action),
		}, nil
	}

	return &AuthorizationDecision{Allowed: true, Reason: "permitted"}, nil
}
