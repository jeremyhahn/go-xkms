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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const diceKeyAuth = "token.thumbprint-of-the-account-key"

// newDICELeafDER mints an alias certificate echoing challenge in the eat_nonce
// claim of its tcg-dice-UCCS-evidence extension, and returns its DER. A nil
// challenge leaves the extension off, which is a device that answered without
// the challenge.
func newDICELeafDER(t *testing.T, challenge []byte) []byte {
	t.Helper()
	der, _ := newDICEAlias(t, challenge)
	return der
}

// newDICEAlias is newDICELeafDER with the alias key as well, for a test that
// has to produce a certificate request for the key the device attested -- the
// comparison the binding gate makes.
func newDICEAlias(t *testing.T, challenge []byte) ([]byte, *ecdsa.PrivateKey) {
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

	if challenge != nil {
		uccs, err := dice.CreateUccsEvidenceExtension(&dice.ClaimsSet{Nonce: challenge})
		require.NoError(t, err)
		extensions = append(extensions, uccs)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "Test DICE Alias"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: extensions,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	return der, key
}

func diceAttestationObject(t *testing.T, challenge []byte) *AttestationObject {
	t.Helper()
	return &AttestationObject{
		Format: string(FormatDICE),
		AttStatement: AttestationStatement{
			X5c: []interface{}{newDICELeafDER(t, challenge)},
		},
	}
}

func TestFormatDICEIsRecognised(t *testing.T) {
	assert.Equal(t, "dice", FormatDICE.String())
	assert.True(t, ValidateAttestationFormat(FormatDICE))

	// The TPM format is unaffected, and nothing else became acceptable.
	assert.True(t, ValidateAttestationFormat(FormatTPM))
	assert.False(t, ValidateAttestationFormat(AttestationFormat("apple")))
	assert.False(t, ValidateAttestationFormat(AttestationFormat("")))
}

// TestValidateAttestationFormatTracksTheDispatchTable is why the two are the
// same map. A format the server says it supports but cannot dispatch would
// reach the end of Verify and be refused there, which reads to an operator as
// a broken device rather than an unimplemented format.
func TestValidateAttestationFormatTracksTheDispatchTable(t *testing.T) {
	for format := range evidenceVerifiers {
		assert.True(t, ValidateAttestationFormat(format),
			"%s can be dispatched but is not reported as supported", format)
	}
}

func TestVerifyDICEEvidenceAcceptsAMatchingNonce(t *testing.T) {
	// The device echoes SHA-256 of the key authorization, not the string.
	// DICENonce is exported precisely so a device, a provisioning tool and this
	// test agree on it rather than each hashing something slightly different.
	object := diceAttestationObject(t, DICENonce(diceKeyAuth))
	verified, err := verifyDICEEvidence(object, nil, diceKeyAuth)
	require.NoError(t, err)
	require.NotNil(t, verified)
	leaf := verified.Leaf

	// The verified leaf comes back rather than being discarded: the nonce says
	// the device answered this challenge and nothing about which key the CA is
	// about to certify, so the certificate the CSR is bound against has to
	// survive to finalization.
	require.NotNil(t, leaf, "the verified alias certificate was not returned")
	assert.Equal(t, "Test DICE Alias", leaf.Subject.CommonName)
}

// The digest is 32 bytes, which is inside EAT's 8-64 bound. The raw key
// authorization is 87 and is not, which is the whole reason for the hash -- so
// this asserts the size rather than leaving it to a comment that could drift
// from a constant somewhere else.
func TestDICENonceFitsTheEATBound(t *testing.T) {
	assert.Len(t, DICENonce(diceKeyAuth), 32)

	// A real key authorization is "<token>.<thumbprint>", and both halves are
	// base64url of 32 bytes -- 43 characters each. 87 total, against EAT's
	// ceiling of 64. The fixture above is shorter than a real one, which is
	// exactly how a strict bound would have passed CI and failed in the field.
	realistic := strings.Repeat("t", 43) + "." + strings.Repeat("p", 43)
	assert.Greater(t, len(realistic), 64,
		"a real key authorization exceeds the EAT ceiling; if this ever fails the hash may no longer be needed")
	assert.Len(t, DICENonce(realistic), 32)
}

func TestVerifyDICEEvidenceRejectsBadInput(t *testing.T) {
	tests := []struct {
		name    string
		object  func(*testing.T) *AttestationObject
		keyAuth string
	}{
		{
			// THE RULING, as a test. EAT bounds eat_nonce at 8-64 bytes and a
			// key authorization is 87 -- "<token>.<43-character thumbprint>" --
			// so the raw form cannot be carried by a conforming claims set at
			// all. A device that echoes it is refused even though it echoed
			// exactly the right secret, because accepting it would mean asking
			// every attester to emit evidence a strict EAT verifier rejects.
			name: "the RAW key authorization rather than its digest",
			object: func(t *testing.T) *AttestationObject {
				return diceAttestationObject(t, []byte(diceKeyAuth))
			},
			keyAuth: diceKeyAuth,
		},
		{
			name: "a replayed nonce",
			object: func(t *testing.T) *AttestationObject {
				return diceAttestationObject(t, []byte("a stale challenge"))
			},
			keyAuth: diceKeyAuth,
		},
		{
			name: "the nonce echoed in DiceTcbInfo.vendorInfo instead",
			object: func(t *testing.T) *AttestationObject {
				return &AttestationObject{
					Format: string(FormatDICE),
					AttStatement: AttestationStatement{
						X5c: []interface{}{newVendorInfoLeafDER(t, DICENonce(diceKeyAuth))},
					},
				}
			},
			keyAuth: diceKeyAuth,
		},
		{
			name: "a nonce of the wrong length",
			object: func(t *testing.T) *AttestationObject {
				return diceAttestationObject(t, DICENonce(diceKeyAuth)[:8])
			},
			keyAuth: diceKeyAuth,
		},
		{
			name:    "a device that echoed nothing",
			object:  func(t *testing.T) *AttestationObject { return diceAttestationObject(t, nil) },
			keyAuth: diceKeyAuth,
		},
		{
			name:    "no key authorization to bind to",
			object:  func(t *testing.T) *AttestationObject { return diceAttestationObject(t, DICENonce(diceKeyAuth)) },
			keyAuth: "",
		},
		{
			name: "no certificate chain",
			object: func(t *testing.T) *AttestationObject {
				return &AttestationObject{Format: string(FormatDICE)}
			},
			keyAuth: diceKeyAuth,
		},
		{
			name: "the leaf is not a byte string",
			object: func(t *testing.T) *AttestationObject {
				return &AttestationObject{
					Format:       string(FormatDICE),
					AttStatement: AttestationStatement{X5c: []interface{}{"not der"}},
				}
			},
			keyAuth: diceKeyAuth,
		},
		{
			name: "the leaf is not a certificate",
			object: func(t *testing.T) *AttestationObject {
				return &AttestationObject{
					Format:       string(FormatDICE),
					AttStatement: AttestationStatement{X5c: []interface{}{[]byte{0x30, 0x00}}},
				}
			},
			keyAuth: diceKeyAuth,
		},
		{
			name: "the leaf carries no DICE evidence",
			object: func(t *testing.T) *AttestationObject {
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
				return &AttestationObject{
					Format:       string(FormatDICE),
					AttStatement: AttestationStatement{X5c: []interface{}{der}},
				}
			},
			keyAuth: diceKeyAuth,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verified, err := verifyDICEEvidence(test.object(t), nil, test.keyAuth)
			require.Error(t, err, "malformed dice evidence was accepted")
			assert.Nil(t, verified, "a refused attestation must carry no leaf forward")
		})
	}
}

// newVendorInfoLeafDER mints an alias certificate that echoes the challenge in
// DiceTcbInfo.vendorInfo -- the placement this profile used to read, and no
// longer does. It exists so the refusal of that placement is a test rather
// than a comment.
func newVendorInfoLeafDER(t *testing.T, challenge []byte) []byte {
	t.Helper()

	extension, err := dice.CreateTcbInfoExtension(&dice.TcbInfo{
		Vendor:     "Automate The Things",
		VendorInfo: challenge,
	})
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:    big.NewInt(4),
		Subject:         pkix.Name{CommonName: "Test DICE Alias"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{extension},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	return der
}

// TestDICEVerificationConsultsNoClock is the freshness contract stated as a
// test. The device has no clock, so the only thing verifyDICEEvidence compares
// is the nonce -- a certificate whose validity window has passed is still
// accepted here, because expiry is the chain verifier's business and not a
// substitute for a challenge.
func TestDICEVerificationConsultsNoClock(t *testing.T) {
	extension, err := dice.CreateTcbInfoExtension(&dice.TcbInfo{Vendor: "Automate The Things"})
	require.NoError(t, err)

	uccs, err := dice.CreateUccsEvidenceExtension(&dice.ClaimsSet{Nonce: DICENonce(diceKeyAuth)})
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	expired := &x509.Certificate{
		SerialNumber:    big.NewInt(3),
		Subject:         pkix.Name{CommonName: "Long Expired Alias"},
		NotBefore:       time.Now().Add(-48 * time.Hour),
		NotAfter:        time.Now().Add(-24 * time.Hour),
		ExtraExtensions: []pkix.Extension{extension, uccs},
	}
	der, err := x509.CreateCertificate(rand.Reader, expired, expired, key.Public(), key)
	require.NoError(t, err)

	object := &AttestationObject{
		Format:       string(FormatDICE),
		AttStatement: AttestationStatement{X5c: []interface{}{der}},
	}
	_, err = verifyDICEEvidence(object, nil, diceKeyAuth)
	assert.NoError(t, err,
		"freshness here is the nonce; expiry belongs to the chain verifier")
}

// TestSetupRefusesDICE records the boundary. Setup builds evidence with a local
// TPM; a DICE device mints its own alias certificate, so there is nothing for
// this host to construct and saying so is not the same as a missing feature.
func TestSetupRefusesDICE(t *testing.T) {
	payload, err := Setup("keyauth", &mockKeyAttributes{keyAlgorithm: x509.ECDSA}, FormatDICE, &mockTPM{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidAttestationFormat)
	assert.Nil(t, payload)
}
