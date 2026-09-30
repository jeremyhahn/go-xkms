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

package server

import (
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// xkmsInviteConfigFromOperator translates the operator's YAML invite
// section into the xkms service's InviteConfig. DefaultTTL/MaxTTL are Go
// duration strings (e.g. "24h"), matching WebAuthnConfig.JWTExpiresIn's own
// convention; a malformed value is a startup-fatal configuration error
// rather than a silently-ignored default, the same treatment
// AttestationConfig.Verifiers() gets at this call site.
func xkmsInviteConfigFromOperator(cfg *config.InviteConfig) (xkms.InviteConfig, error) {
	out := xkms.InviteConfig{PublicBaseURL: cfg.PublicBaseURL}
	if cfg.DefaultTTL != "" {
		d, err := time.ParseDuration(cfg.DefaultTTL)
		if err != nil {
			return xkms.InviteConfig{}, &InviteConfigParseError{Field: "default_ttl", Value: cfg.DefaultTTL, Err: err}
		}
		out.DefaultTTL = d
	}
	if cfg.MaxTTL != "" {
		d, err := time.ParseDuration(cfg.MaxTTL)
		if err != nil {
			return xkms.InviteConfig{}, &InviteConfigParseError{Field: "max_ttl", Value: cfg.MaxTTL, Err: err}
		}
		out.MaxTTL = d
	}
	return out, nil
}

// InviteConfigParseError reports a malformed duration in the operator's
// invite configuration section.
type InviteConfigParseError struct {
	Field string
	Value string
	Err   error
}

// Error implements error.
func (e *InviteConfigParseError) Error() string {
	return "server: invalid invite." + e.Field + " " + `"` + e.Value + `": ` + e.Err.Error()
}

// Unwrap returns the underlying parse error.
func (e *InviteConfigParseError) Unwrap() error { return e.Err }
