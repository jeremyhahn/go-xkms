// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package resolver_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
	"github.com/jeremyhahn/go-xkms/pkg/trust/resolver"
)

// The tofu strategy on the TLS path (#139): the resolver hands back an
// endpoint verifier, not a bundle fetch, so a device that serves no CA
// bundle (a BMC with a self-signed certificate) can be verified.

func selfSignedLeaf(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func tofuScope() *resolver.Config {
	return &resolver.Config{
		Scopes: map[string]*resolver.ScopeConfig{
			"bmc": {
				Strategies: []resolver.Strategy{resolver.StrategyTOFU},
				ServerURL:  "https://bmc.example.com",
			},
		},
	}
}

func TestTLSConfig_TOFU_IsAnEndpointVerifier(t *testing.T) {
	store := truststrap.NewMemoryPinStore()
	r, err := resolver.New(tofuScope(), resolver.WithTOFUPinStore(store))
	if err != nil {
		t.Fatal(err)
	}

	// No bundle is fetched: the config comes back without any network.
	cfg, err := r.TLSConfig(context.Background(), "bmc", "bmc.example.com:443")
	if err != nil {
		t.Fatalf("TLSConfig(tofu) must not require a CA bundle: %v", err)
	}
	if cfg.VerifyConnection == nil || !cfg.SessionTicketsDisabled {
		t.Fatal("expected the custom-verifier shape")
	}

	leaf := selfSignedLeaf(t, "bmc.example.com")
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	if err := cfg.VerifyConnection(state); err != nil {
		t.Fatalf("first use must capture the self-signed leaf: %v", err)
	}
	if _, err := store.Get(context.Background(), "bmc.example.com", 443); err != nil {
		t.Fatalf("the pin must be persisted under the endpoint: %v", err)
	}
	if err := cfg.VerifyConnection(state); err != nil {
		t.Fatalf("the pinned leaf must keep verifying: %v", err)
	}

	other := tls.ConnectionState{PeerCertificates: []*x509.Certificate{selfSignedLeaf(t, "bmc.example.com")}}
	var mismatch *bootstrap.TOFUPinMismatchError
	if err := cfg.VerifyConnection(other); !errors.As(err, &mismatch) {
		t.Fatalf("a changed leaf must be refused with TOFUPinMismatchError, got %v", err)
	}
}

// The endpoint falls back to the scope's server-url, as it does for dane.
func TestTLSConfig_TOFU_EndpointFromServerURL(t *testing.T) {
	store := truststrap.NewMemoryPinStore()
	r, err := resolver.New(tofuScope(), resolver.WithTOFUPinStore(store))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := r.TLSConfig(context.Background(), "bmc", "")
	if err != nil {
		t.Fatal(err)
	}
	leaf := selfSignedLeaf(t, "bmc.example.com")
	if err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), "bmc.example.com", 443); err != nil {
		t.Fatalf("the pin must be keyed by the server-url's host and default port: %v", err)
	}
}

// The confirm hook injected at construction reaches the TLS path too.
func TestTLSConfig_TOFU_ConfirmFuncIsHonoured(t *testing.T) {
	refuse := errors.New("not this device")
	r, err := resolver.New(tofuScope(),
		resolver.WithTOFUPinStore(truststrap.NewMemoryPinStore()),
		resolver.WithTOFUConfirmFunc(func(context.Context, *truststrap.Pin) error { return refuse }))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := r.TLSConfig(context.Background(), "bmc", "bmc.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	leaf := selfSignedLeaf(t, "bmc.example.com")
	err = cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}})
	if !errors.Is(err, refuse) {
		t.Fatalf("the confirm hook's refusal must reach the caller, got %v", err)
	}
}

func TestTLSConfig_TOFU_InvalidEndpoint(t *testing.T) {
	r, err := resolver.New(tofuScope(), resolver.WithTOFUPinStore(truststrap.NewMemoryPinStore()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.TLSConfig(context.Background(), "bmc", "no-port-here")
	var failed *resolver.ErrNoStrategySucceeded
	if !errors.As(err, &failed) {
		t.Fatalf("expected the strategy to fail on the endpoint, got %v", err)
	}
}
