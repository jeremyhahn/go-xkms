// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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

// NoOpAuthenticator is an authenticator that allows all requests
// Use this for development or when authentication is handled externally
type NoOpAuthenticator struct{}

// NewNoOpAuthenticator creates a new no-op authenticator
func NewNoOpAuthenticator() *NoOpAuthenticator {
	return &NoOpAuthenticator{}
}

// AuthenticateHTTP always returns an anonymous identity
func (a *NoOpAuthenticator) AuthenticateHTTP(r *http.Request) (*Identity, error) {
	return &Identity{
		Subject: "anonymous",
		Claims:  make(map[string]interface{}),
		Attributes: map[string]string{
			"auth_method": "none",
		},
	}, nil
}

// AuthenticateGRPC always returns an anonymous identity
func (a *NoOpAuthenticator) AuthenticateGRPC(ctx context.Context, md metadata.MD) (*Identity, error) {
	return &Identity{
		Subject: "anonymous",
		Claims:  make(map[string]interface{}),
		Attributes: map[string]string{
			"auth_method": "none",
		},
	}, nil
}

// Name returns the authenticator name
func (a *NoOpAuthenticator) Name() string {
	return "noop"
}
