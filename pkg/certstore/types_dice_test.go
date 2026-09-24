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

package certstore

import (
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
)

// diceOIDs is every DICE identifier this package registers, paired with the
// name OIDToName must return for it.
var diceOIDs = []struct {
	name string
	oid  asn1.ObjectIdentifier
	want string
}{
	{"arc", OIDTCGDice, "tcg-dice"},
	{"tcb info", OIDTCGDiceTcbInfo, "tcg-dice-TcbInfo"},
	{"endorsement manifest", OIDTCGDiceEndorsementManifest, "tcg-dice-endorsement-manifest"},
	{"endorsement manifest uri", OIDTCGDiceEndorsementManifestURI, "tcg-dice-endorsement-manifest-uri"},
	{"ueid", OIDTCGDiceUeid, "tcg-dice-Ueid"},
	{"multi tcb info", OIDTCGDiceMultiTcbInfo, "tcg-dice-MultiTcbInfo"},
	{"uccs evidence", OIDTCGDiceUccsEvidence, "tcg-dice-UCCS-evidence"},
	{"manifest evidence", OIDTCGDiceManifestEvidence, "tcg-dice-manifest-evidence"},
	{"kp arc", OIDTCGDiceKp, "tcg-dice-kp"},
	{"kp identityInit", OIDTCGDiceKpIdentityInit, "tcg-dice-kp-identityInit"},
	{"kp identityLoc", OIDTCGDiceKpIdentityLoc, "tcg-dice-kp-identityLoc"},
	{"kp attestInit", OIDTCGDiceKpAttestInit, "tcg-dice-kp-attestInit"},
	{"kp attestLoc", OIDTCGDiceKpAttestLoc, "tcg-dice-kp-attestLoc"},
	{"kp assertInit", OIDTCGDiceKpAssertInit, "tcg-dice-kp-assertInit"},
	{"kp assertLoc", OIDTCGDiceKpAssertLoc, "tcg-dice-kp-assertLoc"},
	{"kp eca", OIDTCGDiceKpECA, "tcg-dice-kp-eca"},
}

// TestDICEOIDsHaveNames checks that every DICE constant this file declares also
// has a name-table entry.
//
// A constant registered without a name renders as bare digits wherever a
// certificate is displayed, which is the failure this pairing exists to
// prevent: an operator inspecting a device certificate sees "2.23.133.5.4.1"
// and has no way to know it is looking at the device's firmware measurement.
func TestDICEOIDsHaveNames(t *testing.T) {
	for _, test := range diceOIDs {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, OIDToName(test.oid),
				"%s has no name-table entry", test.oid)
		})
	}
}

func TestIsDICEOID(t *testing.T) {
	for _, test := range diceOIDs {
		t.Run("recognises "+test.name, func(t *testing.T) {
			assert.True(t, IsDICEOID(test.oid))
			// The DICE arc sits under the TCG arc, so both must answer true.
			assert.True(t, IsTCGOID(test.oid),
				"a DICE identifier that is not a TCG identifier is under the wrong arc")
		})
	}
}

func TestIsDICEOIDRejectsEverythingElse(t *testing.T) {
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
	}{
		{"empty", asn1.ObjectIdentifier{}},
		{"the tcg arc itself", asn1.ObjectIdentifier{2, 23, 133}},
		{"a tcg attribute", OIDTCGAttributeTPMManufacturer},
		{"a tcg certificate type", OIDTCGKpEKCertificate},
		{"tcg platformClass but not dice", asn1.ObjectIdentifier{2, 23, 133, 5, 1}},
		{"truncated one short of the arc", asn1.ObjectIdentifier{2, 23, 133, 5}},
		{"a trusted platform oid", OIDTPNetworkZone},
		{"a standard x509 extension", OIDKeyUsage},
		{"a lookalike under a different root", asn1.ObjectIdentifier{1, 23, 133, 5, 4, 1}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.False(t, IsDICEOID(test.oid))
		})
	}
}

// TestDICEOIDsAreDistinct guards against a copy-paste that gives two
// identifiers the same value, which no compiler catches and which would make
// one extension impossible to tell from another.
func TestDICEOIDsAreDistinct(t *testing.T) {
	seen := make(map[string]string, len(diceOIDs))
	for _, test := range diceOIDs {
		key := test.oid.String()
		previous, duplicate := seen[key]
		assert.False(t, duplicate, "%s and %s are both %s", previous, test.name, key)
		seen[key] = test.name
	}
}
