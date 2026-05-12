// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestDefaultChainOption(t *testing.T) {
	opt := DefaultChainOption()
	if opt == nil {
		t.Fatal("expected non-nil option")
	}
	if !opt.AllowFallback {
		t.Error("expected AllowFallback to be true")
	}
	if opt.PreferredChain != "" {
		t.Errorf("expected empty PreferredChain, got %q", opt.PreferredChain)
	}
}

func TestMatchesPreferredChain(t *testing.T) {
	tests := []struct {
		name          string
		chain         []*x509.Certificate
		preferredName string
		want          bool
	}{
		{
			name:          "empty chain",
			chain:         []*x509.Certificate{},
			preferredName: "Test Root",
			want:          false,
		},
		{
			name:          "empty preferred name",
			chain:         []*x509.Certificate{{Subject: pkix.Name{CommonName: "Test Root"}}},
			preferredName: "",
			want:          false,
		},
		{
			name: "matching common name",
			chain: []*x509.Certificate{
				{Subject: pkix.Name{CommonName: "Leaf"}},
				{Subject: pkix.Name{CommonName: "Test Root"}},
			},
			preferredName: "Test Root",
			want:          true,
		},
		{
			name: "case insensitive match",
			chain: []*x509.Certificate{
				{Subject: pkix.Name{CommonName: "Leaf"}},
				{Subject: pkix.Name{CommonName: "test root"}},
			},
			preferredName: "TEST ROOT",
			want:          true,
		},
		{
			name: "no match",
			chain: []*x509.Certificate{
				{Subject: pkix.Name{CommonName: "Leaf"}},
				{Subject: pkix.Name{CommonName: "Other Root"}},
			},
			preferredName: "Test Root",
			want:          false,
		},
		{
			name: "matches issuer common name",
			chain: []*x509.Certificate{
				{Subject: pkix.Name{CommonName: "Leaf"}},
				{
					Subject: pkix.Name{CommonName: "Intermediate"},
					Issuer:  pkix.Name{CommonName: "Test Root"},
				},
			},
			preferredName: "Test Root",
			want:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesPreferredChain(tt.chain, tt.preferredName)
			if got != tt.want {
				t.Errorf("matchesPreferredChain() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseLinkHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    []string
	}{
		{
			name:    "empty headers",
			headers: []string{},
			want:    nil,
		},
		{
			name:    "no alternate links",
			headers: []string{`<https://example.com>; rel="next"`},
			want:    nil,
		},
		{
			name:    "single alternate",
			headers: []string{`<https://example.com/alt1>; rel="alternate"`},
			want:    []string{"https://example.com/alt1"},
		},
		{
			name: "multiple alternates",
			headers: []string{
				`<https://example.com/alt1>; rel="alternate"`,
				`<https://example.com/alt2>; rel="alternate"`,
			},
			want: []string{"https://example.com/alt1", "https://example.com/alt2"},
		},
		{
			name:    "mixed headers",
			headers: []string{`<https://example.com/next>; rel="next"`, `<https://example.com/alt>; rel="alternate"`},
			want:    []string{"https://example.com/alt"},
		},
		{
			name:    "alternate without quotes",
			headers: []string{`<https://example.com/alt>; rel=alternate`},
			want:    []string{"https://example.com/alt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLinkHeaders(tt.headers)
			if len(got) != len(tt.want) {
				t.Errorf("parseLinkHeaders() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseLinkHeaders()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestChainToInfo(t *testing.T) {
	t.Run("nil chain returns nil", func(t *testing.T) {
		got := chainToInfo(nil, "https://example.com")
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("empty chain returns nil", func(t *testing.T) {
		got := chainToInfo([]*x509.Certificate{}, "https://example.com")
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("valid chain", func(t *testing.T) {
		chain := []*x509.Certificate{
			{Subject: pkix.Name{CommonName: "Leaf"}},
			{Subject: pkix.Name{CommonName: "Intermediate"}, Issuer: pkix.Name{CommonName: "Root CA"}},
			{Subject: pkix.Name{CommonName: "Root CA"}, Issuer: pkix.Name{CommonName: "Root CA"}},
		}
		info := chainToInfo(chain, "https://example.com/cert")

		if info == nil {
			t.Fatal("expected non-nil info")
		}
		if info.ChainLength != 3 {
			t.Errorf("expected ChainLength = 3, got %d", info.ChainLength)
		}
		if info.RootName != "Root CA" {
			t.Errorf("expected RootName = 'Root CA', got %q", info.RootName)
		}
		if info.URL != "https://example.com/cert" {
			t.Errorf("expected URL = 'https://example.com/cert', got %q", info.URL)
		}
	})
}

func TestSelectChainByRootName(t *testing.T) {
	chains := []*ChainInfo{
		{RootName: "Root A", ChainLength: 3},
		{RootName: "Root B", ChainLength: 2},
		{RootName: "Root C", ChainLength: 4},
	}

	t.Run("empty root name", func(t *testing.T) {
		got := SelectChainByRootName(chains, "")
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("finds matching chain", func(t *testing.T) {
		got := SelectChainByRootName(chains, "Root B")
		if got == nil {
			t.Fatal("expected non-nil chain")
		}
		if got.RootName != "Root B" {
			t.Errorf("expected RootName = 'Root B', got %q", got.RootName)
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		got := SelectChainByRootName(chains, "root a")
		if got == nil {
			t.Fatal("expected non-nil chain")
		}
		if got.RootName != "Root A" {
			t.Errorf("expected RootName = 'Root A', got %q", got.RootName)
		}
	})

	t.Run("no match returns nil", func(t *testing.T) {
		got := SelectChainByRootName(chains, "Nonexistent")
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
}

func TestSelectShortestChain(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		got := SelectShortestChain([]*ChainInfo{})
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("finds shortest", func(t *testing.T) {
		chains := []*ChainInfo{
			{RootName: "Root A", ChainLength: 3},
			{RootName: "Root B", ChainLength: 2},
			{RootName: "Root C", ChainLength: 4},
		}
		got := SelectShortestChain(chains)
		if got == nil {
			t.Fatal("expected non-nil chain")
		}
		if got.ChainLength != 2 {
			t.Errorf("expected ChainLength = 2, got %d", got.ChainLength)
		}
	})

	t.Run("single chain", func(t *testing.T) {
		chains := []*ChainInfo{
			{RootName: "Root A", ChainLength: 3},
		}
		got := SelectShortestChain(chains)
		if got == nil {
			t.Fatal("expected non-nil chain")
		}
		if got.ChainLength != 3 {
			t.Errorf("expected ChainLength = 3, got %d", got.ChainLength)
		}
	})
}

func TestSelectLongestChain(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		got := SelectLongestChain([]*ChainInfo{})
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("finds longest", func(t *testing.T) {
		chains := []*ChainInfo{
			{RootName: "Root A", ChainLength: 3},
			{RootName: "Root B", ChainLength: 2},
			{RootName: "Root C", ChainLength: 4},
		}
		got := SelectLongestChain(chains)
		if got == nil {
			t.Fatal("expected non-nil chain")
		}
		if got.ChainLength != 4 {
			t.Errorf("expected ChainLength = 4, got %d", got.ChainLength)
		}
	})

	t.Run("single chain", func(t *testing.T) {
		chains := []*ChainInfo{
			{RootName: "Root A", ChainLength: 3},
		}
		got := SelectLongestChain(chains)
		if got == nil {
			t.Fatal("expected non-nil chain")
		}
		if got.ChainLength != 3 {
			t.Errorf("expected ChainLength = 3, got %d", got.ChainLength)
		}
	})
}

func TestParseCertificateChain(t *testing.T) {
	t.Run("invalid PEM data", func(t *testing.T) {
		_, err := parseCertificateChain([]byte("not PEM data"))
		if err == nil {
			t.Error("expected error for invalid PEM")
		}
	})

	t.Run("empty data", func(t *testing.T) {
		_, err := parseCertificateChain([]byte{})
		if err == nil {
			t.Error("expected error for empty data")
		}
	})

	t.Run("valid PEM certificate", func(t *testing.T) {
		// Create a test certificate
		cert := createChainTestCert(t)

		// Encode to PEM
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})

		// Parse it back
		certs, err := parseCertificateChain(pemData)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(certs) != 1 {
			t.Errorf("expected 1 certificate, got %d", len(certs))
		}
		if certs[0].Subject.CommonName != cert.Subject.CommonName {
			t.Errorf("expected CN %q, got %q", cert.Subject.CommonName, certs[0].Subject.CommonName)
		}
	})

	t.Run("multiple PEM certificates", func(t *testing.T) {
		cert1 := createChainTestCert(t)
		cert2 := createChainTestCert(t)

		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert1.Raw,
		})
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert2.Raw,
		})...)

		certs, err := parseCertificateChain(pemData)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(certs) != 2 {
			t.Errorf("expected 2 certificates, got %d", len(certs))
		}
	})

	t.Run("PEM with non-certificate blocks", func(t *testing.T) {
		cert := createChainTestCert(t)

		// Include a private key block (should be ignored)
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: []byte("fake key data"),
		})
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)

		certs, err := parseCertificateChain(pemData)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(certs) != 1 {
			t.Errorf("expected 1 certificate, got %d", len(certs))
		}
	})

	t.Run("invalid certificate in PEM", func(t *testing.T) {
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("not a valid DER certificate"),
		})

		_, err := parseCertificateChain(pemData)
		if err == nil {
			t.Error("expected error for invalid certificate")
		}
	})
}

// createChainTestCert creates a self-signed test certificate for chain tests
func createChainTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}
