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

package auth

import (
	"context"
	"net/http"

	"google.golang.org/grpc/metadata"
)

// Compile-time interface check
var _ Authenticator = (*CompositeAuthenticator)(nil)

// CompositeAuthenticator chains multiple authenticators and returns the first
// successful authentication result. If all authenticators fail, the error from
// the last authenticator is returned.
type CompositeAuthenticator struct {
	authenticators []Authenticator
}

// NewCompositeAuthenticator creates a composite authenticator that tries each
// provided authenticator in order. At least one authenticator must be provided.
func NewCompositeAuthenticator(authenticators ...Authenticator) (*CompositeAuthenticator, error) {
	if len(authenticators) == 0 {
		return nil, ErrNoAuthenticators
	}
	// Copy the slice to prevent external mutation.
	chain := make([]Authenticator, len(authenticators))
	copy(chain, authenticators)
	return &CompositeAuthenticator{
		authenticators: chain,
	}, nil
}

// AuthenticateHTTP tries each authenticator in order for an HTTP request.
// Returns the identity from the first successful authenticator.
// If all authenticators fail, returns the error from the last one.
func (c *CompositeAuthenticator) AuthenticateHTTP(r *http.Request) (*Identity, error) {
	var lastErr error
	for _, auth := range c.authenticators {
		identity, err := auth.AuthenticateHTTP(r)
		if err == nil {
			return identity, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// AuthenticateGRPC tries each authenticator in order for a gRPC request.
// Returns the identity from the first successful authenticator.
// If all authenticators fail, returns the error from the last one.
func (c *CompositeAuthenticator) AuthenticateGRPC(ctx context.Context, md metadata.MD) (*Identity, error) {
	var lastErr error
	for _, auth := range c.authenticators {
		identity, err := auth.AuthenticateGRPC(ctx, md)
		if err == nil {
			return identity, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// Name returns the authenticator name.
func (c *CompositeAuthenticator) Name() string {
	return "composite"
}

// Authenticators returns a copy of the configured authenticator chain.
func (c *CompositeAuthenticator) Authenticators() []Authenticator {
	result := make([]Authenticator, len(c.authenticators))
	copy(result, c.authenticators)
	return result
}
