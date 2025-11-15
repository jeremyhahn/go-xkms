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

// CreateAuthenticator creates an authenticator from the configuration
func (cfg *AuthConfig) CreateAuthenticator() (auth.Authenticator, error) {
	if !cfg.Enabled {
		return auth.NewNoOpAuthenticator(), nil
	}

	switch cfg.Type {
	case "noop", "none", "":
		return auth.NewNoOpAuthenticator(), nil

	case "apikey":
		return cfg.createAPIKeyAuthenticator()

	case "mtls":
		return cfg.createMTLSAuthenticator()

	case "jwt":
		return nil, fmt.Errorf("JWT authenticator not yet implemented")

	default:
		return nil, fmt.Errorf("unknown auth type: %s", cfg.Type)
	}
}

// createAPIKeyAuthenticator creates an API key authenticator from config
func (cfg *AuthConfig) createAPIKeyAuthenticator() (auth.Authenticator, error) {
	if len(cfg.APIKeys) == 0 {
		return nil, fmt.Errorf("no API keys configured")
	}

	// Convert config API keys to authenticator format
	keys := make(map[string]*auth.Identity)
	for apiKey, keyConfig := range cfg.APIKeys {
		identity := &auth.Identity{
			Subject:    keyConfig.Subject,
			Claims:     make(map[string]interface{}),
			Attributes: make(map[string]string),
		}

		// Add roles
		if len(keyConfig.Roles) > 0 {
			identity.Claims["roles"] = keyConfig.Roles
		}

		// Add permissions
		if len(keyConfig.Permissions) > 0 {
			identity.Claims["permissions"] = keyConfig.Permissions
		}

		// Add additional claims
		for k, v := range keyConfig.Claims {
			identity.Claims[k] = v
		}

		keys[apiKey] = identity
	}

	return auth.NewAPIKeyAuthenticator(&auth.APIKeyConfig{
		Keys: keys,
	}), nil
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
