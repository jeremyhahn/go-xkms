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

package config

import (
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// CreateAuthenticator creates an authenticator from the configuration.
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
		return nil, &errs.Message{Msg: "JWT authenticator requires server-level configuration with public key"}

	case "adaptive":
		// Removed mode: fail with the replacement spelled out.
		return nil, &errs.Message{Msg: "auth.type \"adaptive\" was removed: use \"composite\" (derives the jwt+mtls session-vehicle chain)"}

	default:
		return nil, &errs.Message{Msg: fmt.Sprintf("unknown auth type: %s", cfg.Type)}
	}
}

// createMTLSAuthenticator creates an mTLS authenticator from config
func (cfg *AuthConfig) createMTLSAuthenticator() (auth.Authenticator, error) {
	if !cfg.MTLS {
		return nil, &errs.Message{Msg: "mTLS authentication requested but not enabled in config"}
	}

	// Use default mTLS configuration
	// Applications can customize claim/subject extraction via custom authenticator
	return auth.NewMTLSAuthenticator(nil), nil
}
