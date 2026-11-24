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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// clientAuthTestConfig is a valid configuration without PIV login, so the
// only check that can see tls.client_auth is the general one.
func clientAuthTestConfig(clientAuth string) *Config {
	return &Config{
		Protocols: ProtocolsConfig{REST: true},
		Server:    ServerConfig{RESTPort: 8443},
		Logging:   LoggingConfig{Level: "info", Format: "json"},
		TLS:       TLSConfig{Enabled: true, ServerCN: "test-server", ClientAuth: clientAuth},
		Datastore: DatastoreConfig{Path: "/data"},
		Default:   "pkcs8",
		Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
		CA:        &ca.MultiIdentityCAConfig{},
		Auth:      AuthConfig{},
	}
}

// An HSM-device xkmsd node is reached only over mTLS (SPEC row
// hsm-device-protocol). The server maps any unknown tls.client_auth to
// tls.NoClientCert, so a misspelt value must fail validation instead of
// silently serving without client certificates.
func TestValidate_ClientAuthOutsideTheDocumentedValuesIsRefused(t *testing.T) {
	invalid := []string{"requre", "REQUIRE_AND_VERIFY", "Require_And_Verify", " require_and_verify", "mtls"}
	for _, v := range invalid {
		t.Run("invalid_"+v, func(t *testing.T) {
			err := clientAuthTestConfig(v).Validate()
			if err == nil {
				t.Fatalf("Validate() accepted tls.client_auth %q", v)
			}
			msg := err.Error()
			if !strings.Contains(msg, "tls.client_auth") || !strings.Contains(msg, v) {
				t.Fatalf("Validate() error %q does not name tls.client_auth and %q", msg, v)
			}
		})
	}

	valid := []string{"", "none", "request", "require", "verify", "require_and_verify"}
	for _, v := range valid {
		t.Run("valid_"+v, func(t *testing.T) {
			if err := clientAuthTestConfig(v).Validate(); err != nil {
				t.Fatalf("Validate() refused tls.client_auth %q: %v", v, err)
			}
		})
	}
}
