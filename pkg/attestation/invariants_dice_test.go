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

package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var diceTestNonce = []byte{0xC0, 0xFF, 0xEE, 0x01, 0x02, 0x03, 0x04, 0x05}

// newDICELeaf mints an alias certificate for the given key, echoing nonce in
// the eat_nonce claim of the tcg-dice-UCCS-evidence extension the way a DICE
// device does. A nil nonce leaves the extension off entirely, which is the
// device that answered without the challenge.
func newDICELeaf(t *testing.T, subject *ecdsa.PrivateKey, nonce []byte) *x509.Certificate {
	t.Helper()

	info := &dice.TcbInfo{
		Vendor:  "Automate The Things",
		Model:   "AVR-DICE",
		Version: "1.0.0",
		FWIDs: []dice.FWID{{
			HashAlg: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1},
			Digest:  make([]byte, 32),
		}},
	}
	extension, err := dice.CreateTcbInfoExtension(info)
	require.NoError(t, err)
	extensions := []pkix.Extension{extension}

	if nonce != nil {
		uccs, err := dice.CreateUccsEvidenceExtension(&dice.ClaimsSet{Nonce: nonce})
		require.NoError(t, err)
		extensions = append(extensions, uccs)
	}

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "Test DICE Alias"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: extensions,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, subject.Public(), issuerKey)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return leaf
}

func newDICEEvidence(t *testing.T, nonce, expected []byte) *Evidence {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leaf := newDICELeaf(t, key, nonce)
	return &Evidence{
		Format:            FormatDICE,
		Leaf:              leaf,
		SubjectSPKI:       leaf.RawSubjectPublicKeyInfo,
		ExpectedChallenge: expected,
	}
}

func TestDICEIsAKnownFormat(t *testing.T) {
	assert.Equal(t, "dice", FormatDICE)
	assert.True(t, KnownFormat(FormatDICE))
	assert.True(t, KnownFormat("DICE"), "format tags are normalised before lookup")
	assert.True(t, KnownFormat("  dice  "))
}

func TestDICEEvidencePassesTheInvariants(t *testing.T) {
	evidence := newDICEEvidence(t, diceTestNonce, diceTestNonce)
	require.NoError(t, VerifyInvariants(evidence))
}

// TestDICEEvidenceBindsTheCSRKey is the most important check in the path. An
// attestation chain is not secret -- it travels with every enrollment -- so
// without binding, anyone holding one could present it beside a CSR for a key
// they generated in software.
func TestDICEEvidenceBindsTheCSRKey(t *testing.T) {
	evidence := newDICEEvidence(t, diceTestNonce, diceTestNonce)

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherSPKI, err := x509.MarshalPKIXPublicKey(other.Public())
	require.NoError(t, err)

	evidence.SubjectSPKI = otherSPKI

	err = VerifyInvariants(evidence)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyNotBound)
}

func TestDICEEvidenceRejectsBadInput(t *testing.T) {
	t.Run("no subject key to bind", func(t *testing.T) {
		evidence := newDICEEvidence(t, diceTestNonce, diceTestNonce)
		evidence.SubjectSPKI = nil

		err := VerifyInvariants(evidence)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrKeyNotBound)
	})

	t.Run("no leaf to read the challenge from", func(t *testing.T) {
		evidence := newDICEEvidence(t, diceTestNonce, diceTestNonce)
		evidence.Leaf = nil

		err := VerifyInvariants(evidence)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBindingUnavailable)
	})

	t.Run("leaf carries no DICE evidence", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		template := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "Not A DICE Device"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		require.NoError(t, err)
		leaf, err := x509.ParseCertificate(der)
		require.NoError(t, err)

		err = VerifyInvariants(&Evidence{
			Format:            FormatDICE,
			Leaf:              leaf,
			SubjectSPKI:       leaf.RawSubjectPublicKeyInfo,
			ExpectedChallenge: diceTestNonce,
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBindingUnavailable)
	})
}

// TestDICEFreshnessIsAlwaysTheVerifiersNonce pins the freshness contract. A
// DICE device has no clock, so a nonce is the only thing that distinguishes a
// live answer from a replay -- and because the format declares a challenge
// mechanism, the gate refuses to run without one.
func TestDICEFreshnessIsAlwaysTheVerifiersNonce(t *testing.T) {
	t.Run("a replayed nonce is refused", func(t *testing.T) {
		evidence := newDICEEvidence(t, diceTestNonce, []byte("a different challenge"))

		err := VerifyInvariants(evidence)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrStaleEvidence)
	})

	t.Run("evidence with no challenge issued is refused", func(t *testing.T) {
		evidence := newDICEEvidence(t, diceTestNonce, nil)

		err := VerifyInvariants(evidence)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrStaleEvidence)
	})

	// A device that echoed nothing has no UCCS extension, so the gate cannot
	// read a challenge at all rather than reading a stale one. Both refuse,
	// and the difference is what an operator needs to tell a device that
	// answered late from one that did not answer the challenge mechanism.
	t.Run("a device that echoed nothing is refused", func(t *testing.T) {
		evidence := newDICEEvidence(t, nil, diceTestNonce)

		err := VerifyInvariants(evidence)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBindingUnavailable)
	})

	// The same device, with the nonce placed in DiceTcbInfo.vendorInfo
	// instead. It is still refused: the challenge lives in the eat_nonce
	// claim of tcg-dice-UCCS-evidence, and a fallback to the old placement
	// would mean evidence in the wrong field keeps verifying.
	t.Run("a nonce echoed in vendorInfo is refused", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		info := &dice.TcbInfo{Vendor: "Automate The Things", VendorInfo: diceTestNonce}
		extension, err := dice.CreateTcbInfoExtension(info)
		require.NoError(t, err)

		template := &x509.Certificate{
			SerialNumber:    big.NewInt(3),
			Subject:         pkix.Name{CommonName: "Test DICE Alias"},
			NotBefore:       time.Now().Add(-time.Hour),
			NotAfter:        time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{extension},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		require.NoError(t, err)
		leaf, err := x509.ParseCertificate(der)
		require.NoError(t, err)

		err = VerifyInvariants(&Evidence{
			Format:            FormatDICE,
			Leaf:              leaf,
			SubjectSPKI:       leaf.RawSubjectPublicKeyInfo,
			ExpectedChallenge: diceTestNonce,
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBindingUnavailable)
	})
}

// TestDICEProfileDeclaresAChallengeMechanism records the shape of the entry,
// so a later change that drops the extractor -- which would make the format
// silently unable to check freshness -- fails here rather than in the field.
func TestDICEProfileDeclaresAChallengeMechanism(t *testing.T) {
	profile, known := profiles[FormatDICE]
	require.True(t, known)

	assert.True(t, profile.bindLeafSPKI,
		"a DICE alias certificate certifies the attested key directly")
	assert.False(t, profile.bindTPMCertify,
		"DICE has no TPM2_Certify structure")
	require.NotNil(t, profile.challenge,
		"dropping the extractor would make freshness uncheckable for this format")
	assert.NotEmpty(t, profile.note)
}
