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

package ca

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestCheckIssuerNameConstraints(t *testing.T) {
	issuer := &x509.Certificate{
		PermittedIPRanges:       []*net.IPNet{mustCIDR(t, "10.4.0.0/24"), mustCIDR(t, "fd00:4::/64")},
		ExcludedIPRanges:        []*net.IPNet{mustCIDR(t, "10.4.0.128/25")},
		PermittedDNSDomains:     []string{"fabric.example.com", ".svc.example.com"},
		ExcludedDNSDomains:      []string{"bad.fabric.example.com"},
		PermittedURIDomains:     []string{"example.org"},
		PermittedEmailAddresses: []string{"ops@example.com", ".example.net", "example.org"},
	}
	cases := []struct {
		name string
		leaf x509.Certificate
		ok   bool
	}{
		{"ipv4 inside", x509.Certificate{IPAddresses: []net.IP{net.ParseIP("10.4.0.7")}}, true},
		{"ipv4 excluded", x509.Certificate{IPAddresses: []net.IP{net.ParseIP("10.4.0.200")}}, false},
		{"ipv4 outside", x509.Certificate{IPAddresses: []net.IP{net.ParseIP("10.5.0.7")}}, false},
		{"ipv6 inside", x509.Certificate{IPAddresses: []net.IP{net.ParseIP("fd00:4::9")}}, true},
		{"ipv6 outside", x509.Certificate{IPAddresses: []net.IP{net.ParseIP("fd00:5::9")}}, false},
		{"v4-mapped address is treated as IPv4", x509.Certificate{IPAddresses: []net.IP{net.ParseIP("::ffff:10.4.0.7")}}, true},
		{"dns exact", x509.Certificate{DNSNames: []string{"fabric.example.com"}}, true},
		{"dns subdomain", x509.Certificate{DNSNames: []string{"a.FABRIC.example.com"}}, true},
		{"dns excluded", x509.Certificate{DNSNames: []string{"x.bad.fabric.example.com"}}, false},
		{"dot constraint excludes apex", x509.Certificate{DNSNames: []string{"svc.example.com"}}, false},
		{"dot constraint admits subdomain", x509.Certificate{DNSNames: []string{"a.svc.example.com"}}, true},
		{"dns suffix trick", x509.Certificate{DNSNames: []string{"evilfabric.example.com"}}, false},
		{"uri host", x509.Certificate{URIs: []*url.URL{{Scheme: "spiffe", Host: "example.org", Path: "/w"}}}, true},
		{"uri foreign host", x509.Certificate{URIs: []*url.URL{{Scheme: "spiffe", Host: "example.com"}}}, false},
		{"email mailbox", x509.Certificate{EmailAddresses: []string{"OPS@example.com"}}, true},
		{"email other mailbox", x509.Certificate{EmailAddresses: []string{"dev@example.com"}}, false},
		{"email dot domain", x509.Certificate{EmailAddresses: []string{"a@mx.example.net"}}, true},
		{"email exact host", x509.Certificate{EmailAddresses: []string{"a@example.org"}}, true},
		{"email host subdomain refused", x509.Certificate{EmailAddresses: []string{"a@mx.example.org"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkIssuerNameConstraints(issuer, &tc.leaf)
			if tc.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrNameConstraintViolation) {
				t.Fatalf("err = %v, want ErrNameConstraintViolation", err)
			}
		})
	}
	if err := checkIssuerNameConstraints(nil, &x509.Certificate{DNSNames: []string{"anything"}}); err != nil {
		t.Fatalf("self-signed issuance must be unconstrained: %v", err)
	}
}

// TestCheckIssuerNameConstraints_AgreesWithPathValidation pins the pre-sign
// matcher to crypto/x509: for each address, a leaf signed directly under the
// tunnel subordinate verifies exactly when the matcher would have allowed it.
func TestCheckIssuerNameConstraints_AgreesWithPathValidation(t *testing.T) {
	f := newOverlayFixture(t)
	key := newECKey(t, elliptic.P256())
	for i, ip := range []string{"10.4.0.1", "10.4.0.255", "10.4.1.1", "fd00:4::1", "fd00:4:0:1::1", "192.0.2.1"} {
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 10)),
			Subject:      pkix.Name{CommonName: ip},
			IPAddresses:  []net.IP{net.ParseIP(ip)},
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, f.tunnel, key.Public(), f.tunnelKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		allowed := checkIssuerNameConstraints(f.tunnel, cert) == nil
		verifies := f.verify(t, cert, f.tunnel) == nil
		if allowed != verifies {
			t.Errorf("%s: pre-sign check allows=%v, path validation verifies=%v", ip, allowed, verifies)
		}
	}
}

func TestNameConstraints_Validate(t *testing.T) {
	if err := (&NameConstraints{PermittedDNSDomains: []string{".example.com"}, PermittedURIDomains: []string{"td_1.example"}}).Validate(); err != nil {
		t.Fatalf("valid constraints refused: %v", err)
	}
	bad := []*NameConstraints{
		nil,
		{PermittedDNSDomains: []string{""}},
		{PermittedDNSDomains: []string{"a..b"}},
		{ExcludedURIDomains: []string{"has space.com"}},
		{PermittedIPRanges: []*net.IPNet{{IP: net.ParseIP("10.0.0.0").To4(), Mask: net.CIDRMask(64, 128)}}},
		{PermittedIPRanges: []*net.IPNet{{IP: net.ParseIP("10.0.0.0").To4(), Mask: net.IPMask{255, 0, 255, 0}}}},
	}
	for i, nc := range bad {
		if err := nc.Validate(); !errors.Is(err, ErrInvalidNameConstraints) {
			t.Errorf("case %d: err = %v", i, err)
		}
	}
}
