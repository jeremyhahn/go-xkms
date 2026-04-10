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

//go:build integration

package bootstrap

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/jeremyhahn/go-truststrap/pkg/dane"
	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
)

const (
	EnvServerURL = "BOOTSTRAP_SERVER_URL"
	EnvNoiseAddr = "BOOTSTRAP_NOISE_ADDR"
	EnvDNSServer = "BOOTSTRAP_DNS_SERVER"
	EnvHostname  = "BOOTSTRAP_HOSTNAME"
	EnvNoiseKey  = "BOOTSTRAP_NOISE_STATIC_KEY"
	EnvSPKIPin   = "BOOTSTRAP_SPKI_PIN"
	EnvTLSCA     = "BOOTSTRAP_TLS_CA"

	// xkmsBundlePath is the REST API path for the CA bootstrap bundle endpoint.
	// This matches the path hardcoded in go-truststrap for DANE/SPKI bootstrapping.
	xkmsBundlePath = "/v1/ca/bootstrap"
)

func requiredEnv(t *testing.T, key string) string {
	t.Helper()
	val := os.Getenv(key)
	if val == "" {
		t.Skipf("required environment variable %s not set", key)
	}
	return val
}

func optionalEnv(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}

func newResolver(t *testing.T, dnsServer string) truststrap.TLSAResolver {
	t.Helper()
	r, err := dane.NewResolver(&dane.ResolverConfig{
		Server:    dnsServer,
		RequireAD: false, // CoreDNS test instance does not set AD flag
	})
	if err != nil {
		t.Fatalf("create DANE resolver: %v", err)
	}
	return r
}

func validDANEConfig(t *testing.T) *truststrap.DANEConfig {
	t.Helper()
	dnsServer := requiredEnv(t, EnvDNSServer)
	return &truststrap.DANEConfig{
		ServerURL: requiredEnv(t, EnvServerURL),
		Hostname:  requiredEnv(t, EnvHostname),
		DNSServer: dnsServer,
		Resolver:  newResolver(t, dnsServer),
	}
}

func brokenDANEConfig(t *testing.T) *truststrap.DANEConfig {
	t.Helper()
	dnsServer := requiredEnv(t, EnvDNSServer)
	return &truststrap.DANEConfig{
		ServerURL: requiredEnv(t, EnvServerURL),
		Hostname:  "nonexistent.invalid",
		DNSServer: dnsServer,
		Resolver:  newResolver(t, dnsServer),
	}
}

func validNoiseConfig(t *testing.T) *truststrap.NoiseConfig {
	t.Helper()
	return &truststrap.NoiseConfig{
		ServerAddr:      requiredEnv(t, EnvNoiseAddr),
		ServerStaticKey: requiredEnv(t, EnvNoiseKey),
	}
}

func brokenNoiseConfig(t *testing.T) *truststrap.NoiseConfig {
	t.Helper()
	return &truststrap.NoiseConfig{
		ServerAddr:      requiredEnv(t, EnvNoiseAddr),
		ServerStaticKey: "0000000000000000000000000000000000000000000000000000000000000000",
	}
}

func validSPKIConfig(t *testing.T) *truststrap.SPKIConfig {
	t.Helper()
	return &truststrap.SPKIConfig{
		ServerURL:     requiredEnv(t, EnvServerURL),
		SPKIPinSHA256: requiredEnv(t, EnvSPKIPin),
	}
}

func brokenSPKIConfig(t *testing.T) *truststrap.SPKIConfig {
	t.Helper()
	return &truststrap.SPKIConfig{
		ServerURL:     requiredEnv(t, EnvServerURL),
		SPKIPinSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
	}
}

func validDirectConfig(t *testing.T) *truststrap.DirectConfig {
	t.Helper()
	return &truststrap.DirectConfig{
		ServerURL:  requiredEnv(t, EnvServerURL),
		BundlePath: xkmsBundlePath,
	}
}

func brokenDirectConfig(t *testing.T) *truststrap.DirectConfig {
	t.Helper()
	return &truststrap.DirectConfig{
		ServerURL: "https://192.0.2.1:9999", // RFC 5737 TEST-NET, unreachable
	}
}

func validateBundle(t *testing.T, resp *truststrap.CABundleResponse) {
	t.Helper()
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if len(resp.BundlePEM) == 0 {
		t.Fatal("expected non-empty BundlePEM")
	}
	if len(resp.Certificates) == 0 {
		t.Fatal("expected at least one certificate")
	}
	if resp.ContentType != "application/pem-certificate-chain" {
		t.Fatalf("expected content type application/pem-certificate-chain, got %q", resp.ContentType)
	}

	for i, der := range resp.Certificates {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("certificate %d invalid: %v", i, err)
		}
		if !cert.IsCA {
			t.Fatalf("certificate %d should be CA", i)
		}
	}
}
