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

package config

import (
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
)

// CreateAuthenticator creates an authenticator from the configuration.
// Note: For adaptive authentication (which auto-switches based on user existence),
// use the server's initializeAuthentication method instead.
func (cfg *AuthConfig) CreateAuthenticator() (auth.Authenticator, error) {
	if !cfg.Enabled {
		return auth.NewNoOpAuthenticator(), nil
	}

	switch cfg.Type {
	case "noop", "none", "":
		return auth.NewNoOpAuthenticator(), nil

	case "mtls":
		return cfg.createMTLSAuthenticator()

	case "jwt":
		// JWT authentication requires additional configuration (public key)
		// and is typically set up in server initialization
		return nil, fmt.Errorf("JWT authenticator requires server-level configuration with public key")

	case "adaptive":
		// Adaptive authentication requires user store and is set up in server initialization
		return nil, fmt.Errorf("adaptive authenticator requires server-level configuration")

	default:
		return nil, fmt.Errorf("unknown auth type: %s", cfg.Type)
	}
}

// createMTLSAuthenticator creates an mTLS authenticator from config
func (cfg *AuthConfig) createMTLSAuthenticator() (auth.Authenticator, error) {
	if !cfg.MTLS {
		return nil, fmt.Errorf("mTLS authentication requested but not enabled in config")
	}

	// Use default mTLS configuration
	// Applications can customize claim/subject extraction via custom authenticator
	return auth.NewMTLSAuthenticator(nil), nil
}
