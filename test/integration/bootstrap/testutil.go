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
	"context"
	"crypto/x509"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/dane"
	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

const (
	EnvServerURL = "BOOTSTRAP_SERVER_URL"
	EnvNoiseAddr = "BOOTSTRAP_NOISE_ADDR"
	EnvDNSServer = "BOOTSTRAP_DNS_SERVER"
	EnvHostname  = "BOOTSTRAP_HOSTNAME"
	EnvSPKIPin   = "BOOTSTRAP_SPKI_PIN"
	EnvTLSCA     = "BOOTSTRAP_TLS_CA"

	// xkmsBundlePath is the REST API path for the CA bootstrap bundle endpoint.
	// This matches the path hardcoded in go-truststrap for DANE/SPKI bootstrapping.
	xkmsBundlePath = "/v1/ca/bootstrap"
)

// Bootstrap listener key discovery (go-xkms#632).
//
// The Noise listener generates or unseals its own static key (go-xkms#35);
// there is no config field and no file for this suite to pre-determine it
// from, so — unlike every other BOOTSTRAP_* value — the Noise public key is
// never supplied by the harness as an environment variable. It is discovered
// from the running server itself, over the ordinary admin API, once per test
// binary run and shared by every subtest that needs it.
var (
	bootstrapKeysOnce sync.Once
	bootstrapKeysVal  *transport.BootstrapListenerKeysResponse
	bootstrapKeysErr  error
)

// discoveredBootstrapKeys returns the running server's trust-bootstrap
// listener public keys, discovering them on first use and caching the
// result for the rest of the test binary. A harness misconfiguration (the
// listener never comes up, or is unreachable) fails loudly — every caller's
// own *testing.T — rather than proceeding with an empty key.
func discoveredBootstrapKeys(t *testing.T) *transport.BootstrapListenerKeysResponse {
	t.Helper()
	bootstrapKeysOnce.Do(func() {
		bootstrapKeysVal, bootstrapKeysErr = fetchBootstrapKeys(t)
	})
	if bootstrapKeysErr != nil {
		t.Fatalf("discover bootstrap listener keys: %v", bootstrapKeysErr)
	}
	return bootstrapKeysVal
}

// fetchBootstrapKeys calls BootstrapListenerKeys over the SDK's REST
// transport, retrying briefly: the listener publishes its keys
// asynchronously in pkg/server's startNoiseBootstrap goroutine, which can
// still be running in the moment after the compose harness's health check
// (a plain GET /health) first goes green.
func fetchBootstrapKeys(t *testing.T) (*transport.BootstrapListenerKeysResponse, error) {
	t.Helper()
	tr := newSDKTransport(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for {
		resp, err := tr.BootstrapListenerKeys(ctx)
		if err == nil {
			return resp, nil
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// requiredEnv reads a harness-supplied environment variable.
//
// test/integration/bootstrap/docker-compose.yml exports every BOOTSTRAP_* value
// these tests consume, so a missing one means the compose harness is misconfigured.
// That is a broken run and must fail loudly rather than report a pass for a
// bootstrap mode that was never exercised.
func requiredEnv(t *testing.T, key string) string {
	t.Helper()
	val := os.Getenv(key)
	if val == "" {
		t.Fatalf("required environment variable %s is not set; the bootstrap harness "+
			"(test/integration/bootstrap/docker-compose.yml) must export it", key)
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
	keys := discoveredBootstrapKeys(t)
	if keys.NoisePublicKey == "" {
		t.Fatal("server reported no Noise_NK public key; the harness's non-FIPS " +
			"build must offer it (see bootstrap.noise.enabled in generate-test-certs.sh)")
	}
	return &truststrap.NoiseConfig{
		ServerAddr:      requiredEnv(t, EnvNoiseAddr),
		ServerStaticKey: keys.NoisePublicKey,
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
