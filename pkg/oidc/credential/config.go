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

package credential

import (
	"context"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/oidc"
)

// ConfigError reports a configuration refused at creation.
type ConfigError struct {
	Detail string
	Err    error
}

// Error implements error.
func (e *ConfigError) Error() string {
	msg := ErrInvalidConfig.Error()
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns ErrInvalidConfig and the cause.
func (e *ConfigError) Unwrap() []error {
	if e.Err == nil {
		return []error{ErrInvalidConfig}
	}
	return []error{ErrInvalidConfig, e.Err}
}

// resolveConfig completes cfg from its template, discovers the endpoints of
// a refreshable provider configured by issuer alone, and validates the
// result.
func (s *Service) resolveConfig(ctx context.Context, cfg Config) (Config, error) {
	cfg.Scopes = append([]string(nil), cfg.Scopes...)
	if cfg.Template != "" {
		tmpl, err := oidc.GetTemplate(cfg.Template)
		if err != nil {
			return Config{}, &ConfigError{Err: err}
		}
		if tmpl.RequiresRegion {
			// AWS console credentials are regional and written to the local
			// AWS profile; they stay an xkey-local login.
			return Config{}, &ConfigError{Detail: "template " + tmpl.Name + " is a local xkey login, not a server credential"}
		}
		cfg.Template = tmpl.Name
		fill(&cfg.Issuer, tmpl.Issuer)
		fill(&cfg.ClientID, tmpl.ClientID)
		fill(&cfg.AuthorizationEndpoint, tmpl.ResolveAuthorizeEndpoint(""))
		fill(&cfg.TokenEndpoint, tmpl.ResolveTokenEndpoint(""))
		if len(cfg.Scopes) == 0 {
			cfg.Scopes = append([]string(nil), tmpl.Scopes...)
		}
		if cfg.TokenEncoding == "" {
			cfg.TokenEncoding = tmpl.TokenEncoding
		}
		if cfg.DeviceStyle == "" {
			cfg.DeviceStyle = tmpl.DeviceStyle
		}
		if tmpl.NoRefresh {
			cfg.NoRefresh = true
		}
		if cfg.TokenLifetime == 0 {
			cfg.TokenLifetime = tmpl.TokenLifetime
		}
	}

	if cfg.Issuer == "" {
		return Config{}, &ConfigError{Detail: "an issuer (or a template) is required"}
	}
	if err := cfg.TokenEncoding.Validate(); err != nil {
		return Config{}, &ConfigError{Err: err}
	}
	if err := cfg.DeviceStyle.Validate(); err != nil {
		return Config{}, &ConfigError{Err: err}
	}
	if cfg.RefreshMargin < 0 || cfg.TokenLifetime < 0 {
		return Config{}, &ConfigError{Detail: "durations must not be negative"}
	}
	if cfg.NoRefresh {
		// An imported-only token is never presented to the provider.
		return cfg, nil
	}
	if cfg.ClientID == "" {
		return Config{}, &ConfigError{Detail: "a client ID (or a template) is required"}
	}
	if cfg.TokenEndpoint == "" {
		discovered, err := oidc.DiscoverProvider(ctx, cfg.Issuer, s.httpClient)
		if err != nil {
			return Config{}, &ConfigError{Detail: "discovery failed", Err: err}
		}
		cfg.AuthorizationEndpoint = discovered.AuthorizationEndpoint
		cfg.TokenEndpoint = discovered.TokenEndpoint
		fill(&cfg.DeviceAuthorizationEndpoint, discovered.DeviceAuthorizationEndpoint)
	}
	if _, err := oidc.NewEndpointProvider(cfg.Issuer, oidc.Endpoints{
		Authorization:       cfg.AuthorizationEndpoint,
		Token:               cfg.TokenEndpoint,
		DeviceAuthorization: cfg.DeviceAuthorizationEndpoint,
	}, s.httpClient); err != nil {
		return Config{}, &ConfigError{Err: err}
	}
	return cfg, nil
}

// fill sets *dst to value when *dst is empty.
func fill(dst *string, value string) {
	if strings.TrimSpace(*dst) == "" {
		*dst = value
	}
}
