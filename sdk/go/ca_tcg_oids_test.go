// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xkms

import (
	"crypto/x509"
	"encoding/asn1"
	"testing"

	pkgca "github.com/jeremyhahn/go-xkms/pkg/ca"
)

// TestTCGOIDReExports_MatchSpecValues pins every re-exported TCG DevID OID to
// the dotted value the specification assigns, so a consumer that checks
// certificate policies through the SDK sees exactly what pkg/ca issues.
func TestTCGOIDReExports_MatchSpecValues(t *testing.T) {
	asn1Cases := map[string]struct {
		got  asn1.ObjectIdentifier
		want string
	}{
		"OIDTCGKpAIKCertificate":      {OIDTCGKpAIKCertificate, "2.23.133.8.3"},
		"OIDTCGVerifiedTPMResidency":  {OIDTCGVerifiedTPMResidency, "2.23.133.11.1.1"},
		"OIDTCGVerifiedTPMFixed":      {OIDTCGVerifiedTPMFixed, "2.23.133.11.1.2"},
		"OIDTCGVerifiedTPMRestricted": {OIDTCGVerifiedTPMRestricted, "2.23.133.11.1.3"},
	}
	for name, tc := range asn1Cases {
		if tc.got.String() != tc.want {
			t.Errorf("%s = %s, want %s", name, tc.got, tc.want)
		}
	}

	policyCases := map[string]struct {
		got  x509.OID
		want string
	}{
		"TCGVerifiedTPMResidencyPolicy":  {TCGVerifiedTPMResidencyPolicy, "2.23.133.11.1.1"},
		"TCGVerifiedTPMFixedPolicy":      {TCGVerifiedTPMFixedPolicy, "2.23.133.11.1.2"},
		"TCGVerifiedTPMRestrictedPolicy": {TCGVerifiedTPMRestrictedPolicy, "2.23.133.11.1.3"},
	}
	for name, tc := range policyCases {
		if tc.got.String() != tc.want {
			t.Errorf("%s = %s, want %s", name, tc.got, tc.want)
		}
	}
}

// TestTCGOIDReExports_AliasPkgCA guards the re-export against drifting from
// the values pkg/ca actually stamps: a consumer comparing an SDK OID against a
// certificate issued by pkg/ca must get a match, not a lookalike.
func TestTCGOIDReExports_AliasPkgCA(t *testing.T) {
	if !OIDTCGVerifiedTPMRestricted.Equal(pkgca.OIDTCGVerifiedTPMRestricted) {
		t.Fatal("OIDTCGVerifiedTPMRestricted does not alias pkg/ca")
	}
	if !TCGVerifiedTPMRestrictedPolicy.Equal(pkgca.TCGVerifiedTPMRestrictedPolicy) {
		t.Fatal("TCGVerifiedTPMRestrictedPolicy does not alias pkg/ca")
	}
	// The two forms of the same OID must agree with each other, or a
	// consumer checking cert.Policies gets a different answer than one
	// checking cert.PolicyIdentifiers.
	if TCGVerifiedTPMRestrictedPolicy.String() != OIDTCGVerifiedTPMRestricted.String() {
		t.Fatalf("x509.OID form %s disagrees with asn1 form %s",
			TCGVerifiedTPMRestrictedPolicy, OIDTCGVerifiedTPMRestricted)
	}
}
