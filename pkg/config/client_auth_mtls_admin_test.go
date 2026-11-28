package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestShippedConfigRequestsAdminClientCert covers issue #2254: xkmsd init
// provisions an mTLS administrator, so the shipped configs/xkmsd.yaml must
// request and verify client certificates when TLS is on, or the admin
// surface never sees that administrator's certificate.
func TestShippedConfigRequestsAdminClientCert(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "xkmsd.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%s): %v", path, err)
	}
	if !cfg.TLS.Enabled {
		t.Fatalf("%s: tls.enabled is false; the shipped config serves TLS", path)
	}
	if got := strings.ToLower(strings.TrimSpace(cfg.TLS.ClientAuth)); got != "verify" {
		t.Fatalf("%s: tls.client_auth = %q, want \"verify\" (request and verify a given client certificate)", path, got)
	}
}

// TestValidateRejectsMTLSAdminWithoutClientAuth: with TLS on and the auth
// chain accepting mTLS administrators, client_auth none is refused.
func TestValidateRejectsMTLSAdminWithoutClientAuth(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "xkmsd.yaml")
	cases := []struct {
		name  string
		setup func(c *Config)
	}{
		{"composite default methods", func(c *Config) { c.Auth.Type = "composite"; c.Auth.Composite = nil }},
		{"composite with mtls", func(c *Config) {
			c.Auth.Type = "composite"
			c.Auth.Composite = &CompositeAuthConfig{Methods: []string{"jwt", "mtls"}}
		}},
		{"type mtls", func(c *Config) { c.Auth.Type = "mtls" }},
	}
	for _, tc := range cases {
		for _, ca := range []string{"none", "", "Verify", " verify", "REQUEST", "optional"} {
			t.Run(tc.name+"/"+ca, func(t *testing.T) {
				cfg, err := Load(path)
				if err != nil {
					t.Fatalf("Load(%s): %v", path, err)
				}
				tc.setup(cfg)
				cfg.TLS.Enabled = true
				cfg.TLS.ClientAuth = ca
				err = cfg.Validate()
				if err == nil || !strings.Contains(err.Error(), "tls.client_auth") {
					t.Fatalf("Validate() = %v, want an error naming tls.client_auth", err)
				}
			})
		}
	}
}

// TestValidateAllowsNoClientAuthWithoutMTLSAdmin: a JWT-only chain, or TLS
// off, does not need client certificates.
func TestValidateAllowsNoClientAuthWithoutMTLSAdmin(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "xkmsd.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%s): %v", path, err)
	}
	cfg.Auth.Type = "composite"
	cfg.Auth.Composite = &CompositeAuthConfig{Methods: []string{"jwt"}}
	cfg.Auth.MTLS = false
	cfg.TLS.ClientAuth = "none"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() with a JWT-only chain: %v", err)
	}
}

// auth.type jwt selects only the JWT authenticator, so the mtls flag alone
// does not make the listener ask for a client certificate.
func TestValidateAllowsJWTTypeWithMTLSFlagAndNoClientAuth(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "xkmsd.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%s): %v", path, err)
	}
	cfg.Auth.Type = "jwt"
	cfg.Auth.Composite = nil
	cfg.Auth.MTLS = true
	cfg.TLS.ClientAuth = "none"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() with auth.type jwt and auth.mtls true: %v", err)
	}
}
