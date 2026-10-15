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

package peer_test

import (
	"encoding/asn1"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// TestDevIDOIDsMatchTheIssuer pins every object identifier package peer
// recognises a credential by to the one pkg/ca stamps when it issues that
// credential. The two are declared apart so that a consumer of the
// verification primitive does not link the certificate authority; this test is
// what stops them drifting into a validator that rejects everything its own CA
// issues.
func TestDevIDOIDsMatchTheIssuer(t *testing.T) {
	pairs := map[string][2]asn1.ObjectIdentifier{
		"tcg-cap-verifiedTPMFixed":      {peer.OIDTCGVerifiedTPMFixed, ca.OIDTCGVerifiedTPMFixed},
		"tcg-cap-verifiedTPMRestricted": {peer.OIDTCGVerifiedTPMRestricted, ca.OIDTCGVerifiedTPMRestricted},
		"tcg hwType TPM 2.0":            {peer.OIDTCGHwTypeTPM2, ca.OIDTCGHwTypeTPM2},
		"tcg-on-ekPermIdSha256":         {peer.OIDTCGOnEKPermIdSha256, ca.OIDTCGOnEKPermIdSha256},
		"id-on-hardwareModuleName":      {peer.OIDHardwareModuleName, ca.OIDHardwareModuleName},
		"id-on-permanentIdentifier":     {peer.OIDPermanentIdentifier, ca.OIDPermanentIdentifier},
	}
	for name, pair := range pairs {
		if !pair[0].Equal(pair[1]) {
			t.Errorf("%s: peer has %v, pkg/ca issues %v", name, pair[0], pair[1])
		}
	}

	// The x509.OID forms Go populates Certificate.Policies with must name the
	// same assertions as the asn1 forms.
	if !peer.OIDTCGVerifiedTPMFixedX509.Equal(ca.TCGVerifiedTPMFixedPolicy) {
		t.Errorf("verifiedTPMFixed policy form: peer has %v, pkg/ca issues %v",
			peer.OIDTCGVerifiedTPMFixedX509, ca.TCGVerifiedTPMFixedPolicy)
	}
	if !peer.OIDTCGVerifiedTPMRestrictedX509.Equal(ca.TCGVerifiedTPMRestrictedPolicy) {
		t.Errorf("verifiedTPMRestricted policy form: peer has %v, pkg/ca issues %v",
			peer.OIDTCGVerifiedTPMRestrictedX509, ca.TCGVerifiedTPMRestrictedPolicy)
	}
}
