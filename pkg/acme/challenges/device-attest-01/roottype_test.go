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

package deviceattest01

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
)

// rootTypeAliasInfo is an alias DiceTcbInfo whose vendorInfo names root, with
// notSecure as given.
func rootTypeAliasInfo(t *testing.T, root dice.RootType, notSecure bool) *dice.TcbInfo {
	t.Helper()
	vendorInfo, err := dice.RootTypeVendorInfo(root)
	require.NoError(t, err)
	return &dice.TcbInfo{
		Vendor:     "Automate The Things",
		FWIDs:      []dice.FWID{{HashAlg: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, Digest: make([]byte, 32)}},
		Flags:      &dice.OperationalFlags{NotSecure: notSecure},
		VendorInfo: vendorInfo,
	}
}

// rootTypeVerifier anchors leaf's key in a registry and, so that a
// software root is not refused by the operational-state policy, tolerates
// notSecure.
func rootTypeVerifier(t *testing.T, leaf *x509.Certificate) *TrustAnchorVerifier {
	t.Helper()
	return registryVerifier(t, TrustAnchors{
		Devices: testRegistry{hex.EncodeToString(diceUeid): {DeviceIDKey: leaf.RawSubjectPublicKeyInfo}},
		DICE:    DICEPolicy{PermittedFlags: dice.OperationalFlags{NotSecure: true}},
	})
}

func TestVerifyAttestationCarriesTheDICERootType(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		info     func(t *testing.T) *dice.TcbInfo
		expected dice.RootType
	}{
		{
			name:     "a hardware chain",
			info:     func(t *testing.T) *dice.TcbInfo { return rootTypeAliasInfo(t, dice.RootTypeHardware, false) },
			expected: dice.RootTypeHardware,
		},
		{
			name:     "a software chain",
			info:     func(t *testing.T) *dice.TcbInfo { return rootTypeAliasInfo(t, dice.RootTypeSoftware, true) },
			expected: dice.RootTypeSoftware,
		},
		{
			name:     "a hardware vendorInfo with notSecure set",
			info:     func(t *testing.T) *dice.TcbInfo { return rootTypeAliasInfo(t, dice.RootTypeHardware, true) },
			expected: dice.RootTypeSoftware,
		},
		{
			name: "a chain that declares nothing",
			info: func(*testing.T) *dice.TcbInfo {
				return &dice.TcbInfo{Vendor: "Automate The Things"}
			},
			expected: dice.RootTypeUnreported,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// The root type is read only from a chain that verified to a
			// trusted root (CA m452), so the alias is endorsed by a DeviceID
			// certificate under the configured DICE root.
			fixture := newDICEFixture(t, nil, true, false, false)
			leaf := mintAliasWithTcbInfo(t, &fixture.key.PublicKey, fixture.deviceID, fixture.key, x509.ECDSAWithSHA256, test.info(t))
			verifier := fixture.verifier(t, DICEPolicy{PermittedFlags: dice.OperationalFlags{NotSecure: true}})

			verified, err := VerifyAttestation(ctx, verifier, attestationPayload(t, diceLeafObject(leaf.Raw)), diceKeyAuth)
			require.NoError(t, err)
			assert.Equal(t, test.expected, verified.RootType)

			// The challenge and the finalize are two requests, so the root
			// type has to survive the record written in between.
			restored, err := FromRecord(verified.Record("permanent-identifier", hex.EncodeToString(diceUeid)))
			require.NoError(t, err)
			assert.Equal(t, test.expected, restored.RootType)
		})
	}
}

func TestVerifyAttestationReadsNoDICERootTypeUnderARawKeyRecord(t *testing.T) {
	// A raw DeviceID key anchors the alias, but no trusted root does, so
	// whatever the alias declares is not read (CA m452).
	deviceKey := newP256Key(t)
	leaf := mintAliasWithTcbInfo(t, &deviceKey.PublicKey, nil, deviceKey, x509.ECDSAWithSHA256, rootTypeAliasInfo(t, dice.RootTypeHardware, false))

	verified, err := VerifyAttestation(context.Background(), rootTypeVerifier(t, leaf), attestationPayload(t, diceLeafObject(leaf.Raw)), diceKeyAuth)
	require.NoError(t, err)
	assert.Equal(t, dice.RootTypeUnreported, verified.RootType)
}
