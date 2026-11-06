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
	"errors"
	"testing"
)

func sessionConfig(session *SessionConfig) *Config {
	return &Config{
		Protocols: ProtocolsConfig{REST: true},
		Server:    ServerConfig{RESTPort: 8443},
		Logging:   LoggingConfig{Level: "info", Format: "json"},
		Datastore: DatastoreConfig{Path: "/data"},
		TLS:       TLSConfig{Enabled: true},
		Default:   "pkcs8",
		Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
		Auth:      AuthConfig{Session: session},
	}
}

func TestValidate_SessionAccessTokenType(t *testing.T) {
	tests := []struct {
		name    string
		session *SessionConfig
	}{
		{"no session block", nil},
		{"empty keeps JWT", &SessionConfig{}},
		{"at+jwt", &SessionConfig{AccessTokenType: "at+jwt"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := sessionConfig(tc.session).Validate(); err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestValidate_SessionAccessTokenTypeRefused(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"plain JWT spelled out", "JWT"},
		{"wrong case", "AT+JWT"},
		{"media type form", "application/at+jwt"},
		{"unrelated", "refresh"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := sessionConfig(&SessionConfig{AccessTokenType: tc.value}).Validate()
			var sessionErr *SessionConfigError
			if !errors.As(err, &sessionErr) {
				t.Fatalf("Validate() = %v, want *SessionConfigError", err)
			}
			if sessionErr.Field != "access_token_type" || sessionErr.Value != tc.value {
				t.Fatalf("SessionConfigError = %+v, want field access_token_type value %q", sessionErr, tc.value)
			}
			if sessionErr.Error() != "config: invalid auth.session.access_token_type: "+tc.value {
				t.Fatalf("Error() = %q", sessionErr.Error())
			}
		})
	}
}
