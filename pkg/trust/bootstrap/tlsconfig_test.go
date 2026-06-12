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

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/dane"
	"github.com/jeremyhahn/go-truststrap/pkg/spkipin"
	"github.com/miekg/dns"
)

// =============================================================================
// Test helpers
// =============================================================================

// newTestCert generates a self-signed ECDSA P-256 certificate for the
// given common name.
func newTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{cn},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// spkiSHA256Hex returns the hex-encoded SHA-256 digest of the
// certificate's SubjectPublicKeyInfo.
func spkiSHA256Hex(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// daneEERecord builds a DANE-EE (usage 3) SPKI/SHA-256 TLSA wire record
// pinning the given certificate.
func daneEERecord(cert *x509.Certificate) *dns.TLSA {
	return &dns.TLSA{
		Usage:        3, // DANE-EE
		Selector:     1, // SPKI
		MatchingType: 1, // SHA-256
		Certificate:  spkiSHA256Hex(cert),
	}
}

// startMockTLSADNS starts an in-process UDP DNS server that answers
// every TLSA query with the given records and AD flag, returning its
// listen address.
func startMockTLSADNS(t *testing.T, records []*dns.TLSA, setAD bool) string {
	t.Helper()

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.AuthenticatedData = setAD
		for _, q := range r.Question {
			if q.Qtype != dns.TypeTLSA {
				continue
			}
			for _, rec := range records {
				rr := new(dns.TLSA)
				rr.Hdr = dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeTLSA,
					Class:  dns.ClassINET,
					Ttl:    300,
				}
				rr.Usage = rec.Usage
				rr.Selector = rec.Selector
				rr.MatchingType = rec.MatchingType
				rr.Certificate = rec.Certificate
				m.Answer = append(m.Answer, rr)
			}
		}
		if err := w.WriteMsg(m); err != nil {
			t.Logf("mock DNS: write response: %v", err)
		}
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	server := &dns.Server{PacketConn: pc, Handler: handler}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown() })
	return pc.LocalAddr().String()
}

// =============================================================================
// NewDANETLSConfig
// =============================================================================

func TestNewDANETLSConfig_Success(t *testing.T) {
	cert := newTestCert(t, "kms.example.com")
	addr := startMockTLSADNS(t, []*dns.TLSA{daneEERecord(cert)}, true)

	cfg, err := NewDANETLSConfig(context.Background(), &DANEConfig{
		Hostname:  "kms.example.com",
		DNSServer: addr,
	}, "", 8443)
	if err != nil {
		t.Fatalf("NewDANETLSConfig: %v", err)
	}
	if cfg.ServerName != "kms.example.com" {
		t.Fatalf("expected ServerName kms.example.com; got %q", cfg.ServerName)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify (custom-verifier pattern)")
	}
	if !cfg.SessionTicketsDisabled {
		t.Fatal("expected SessionTicketsDisabled")
	}
	if cfg.VerifyConnection == nil {
		t.Fatal("expected VerifyConnection callback")
	}

	// The verifier must accept the pinned certificate...
	if err := cfg.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}); err != nil {
		t.Fatalf("VerifyConnection rejected pinned cert: %v", err)
	}
	// ...and reject any other.
	other := newTestCert(t, "kms.example.com")
	err = cfg.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{other},
	})
	if !errors.Is(err, dane.ErrTLSAVerificationFailed) {
		t.Fatalf("expected ErrTLSAVerificationFailed for unpinned cert; got %v", err)
	}
}

func TestNewDANETLSConfig_HostnameParamFallback(t *testing.T) {
	cert := newTestCert(t, "fallback.example.com")
	addr := startMockTLSADNS(t, []*dns.TLSA{daneEERecord(cert)}, true)

	cfg, err := NewDANETLSConfig(context.Background(), &DANEConfig{
		DNSServer: addr,
	}, "fallback.example.com", 8443)
	if err != nil {
		t.Fatalf("NewDANETLSConfig: %v", err)
	}
	if cfg.ServerName != "fallback.example.com" {
		t.Fatalf("expected hostname parameter as ServerName; got %q", cfg.ServerName)
	}
}

func TestNewDANETLSConfig_HostnameRequired(t *testing.T) {
	_, err := NewDANETLSConfig(context.Background(), nil, "", 8443)
	if !errors.Is(err, ErrHostnameRequired) {
		t.Fatalf("expected ErrHostnameRequired for nil cfg + empty hostname; got %v", err)
	}
	_, err = NewDANETLSConfig(context.Background(), &DANEConfig{}, "", 8443)
	if !errors.Is(err, ErrHostnameRequired) {
		t.Fatalf("expected ErrHostnameRequired for empty cfg.Hostname + empty hostname; got %v", err)
	}
}

func TestNewDANETLSConfig_DNSSECRequired(t *testing.T) {
	cert := newTestCert(t, "kms.example.com")
	addr := startMockTLSADNS(t, []*dns.TLSA{daneEERecord(cert)}, false)

	_, err := NewDANETLSConfig(context.Background(), &DANEConfig{
		Hostname:  "kms.example.com",
		DNSServer: addr,
	}, "", 8443)
	if !errors.Is(err, dane.ErrDNSSECRequired) {
		t.Fatalf("expected ErrDNSSECRequired without AD flag; got %v", err)
	}
}

func TestNewDANETLSConfig_NoRecords(t *testing.T) {
	addr := startMockTLSADNS(t, nil, true)

	_, err := NewDANETLSConfig(context.Background(), &DANEConfig{
		Hostname:  "kms.example.com",
		DNSServer: addr,
	}, "", 8443)
	if !errors.Is(err, dane.ErrNoTLSARecords) {
		t.Fatalf("expected ErrNoTLSARecords for empty answer; got %v", err)
	}
}

// =============================================================================
// NewSPKIPinTLSConfig
// =============================================================================

func TestNewSPKIPinTLSConfig_Success(t *testing.T) {
	cert := newTestCert(t, "kms.example.com")

	cfg, err := NewSPKIPinTLSConfig(spkiSHA256Hex(cert))
	if err != nil {
		t.Fatalf("NewSPKIPinTLSConfig: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify (custom-verifier pattern)")
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Fatal("expected VerifyPeerCertificate callback")
	}

	// The verifier must accept the pinned certificate...
	if err := cfg.VerifyPeerCertificate([][]byte{cert.Raw}, nil); err != nil {
		t.Fatalf("VerifyPeerCertificate rejected pinned cert: %v", err)
	}
	// ...and reject any other.
	other := newTestCert(t, "kms.example.com")
	if err := cfg.VerifyPeerCertificate([][]byte{other.Raw}, nil); err == nil {
		t.Fatal("expected pin mismatch error for unpinned cert")
	}
}

func TestNewSPKIPinTLSConfig_EmptyPin(t *testing.T) {
	_, err := NewSPKIPinTLSConfig("")
	if !errors.Is(err, spkipin.ErrNoPinConfigured) {
		t.Fatalf("expected ErrNoPinConfigured for empty pin; got %v", err)
	}
}

func TestNewSPKIPinTLSConfig_InvalidPin(t *testing.T) {
	_, err := NewSPKIPinTLSConfig("not-hex")
	if !errors.Is(err, spkipin.ErrInvalidPinFormat) {
		t.Fatalf("expected ErrInvalidPinFormat for malformed pin; got %v", err)
	}
}
