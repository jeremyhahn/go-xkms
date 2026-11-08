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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/stretchr/testify/require"
)

// selfSignedTestCert builds a minimal self-signed certificate carrying the
// given extra extensions, for exercising DeviceIdentity's certificate parsing
// without a real attestation device.
func selfSignedTestCert(t *testing.T, extraExtensions []pkix.Extension) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "device-attest-01 identity test"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: extraExtensions,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

// permanentIdentifierExtension builds a subjectAltName extension carrying a
// single RFC 4043 permanentIdentifier otherName, the same shape
// pkg/ca/tcg.go puts on an IAK certificate it issues.
func permanentIdentifierExtension(t *testing.T, value string) pkix.Extension {
	t.Helper()

	encoded, err := ca.MarshalPermanentIdentifier(value, nil)
	require.NoError(t, err)

	ext, err := ca.BuildSubjectAltName(
		pkix.Name{}, nil, nil, nil, nil,
		[]ca.OtherName{{TypeID: ca.OIDPermanentIdentifier, Value: encoded}},
		nil)
	require.NoError(t, err)
	return ext
}

func TestVerifiedAttestation_DeviceIdentity_TPM(t *testing.T) {
	ext := permanentIdentifierExtension(t, "urn:tpm:device:example-001")
	leaf := selfSignedTestCert(t, []pkix.Extension{ext})

	verified := &VerifiedAttestation{Format: FormatTPM, Leaf: leaf}

	identity, err := verified.DeviceIdentity()
	require.NoError(t, err)
	require.Equal(t, "urn:tpm:device:example-001", identity)
}

func TestVerifiedAttestation_DeviceIdentity_TPM_NoPermanentIdentifier(t *testing.T) {
	// No otherName at all: an AIK certificate meeting only WebAuthn Level 2
	// section 8.3.1's minimum (the TCG EK Credential Profile directoryName)
	// carries no permanentIdentifier, so this must be refused rather than
	// silently treated as "no identity to check".
	leaf := selfSignedTestCert(t, nil)

	verified := &VerifiedAttestation{Format: FormatTPM, Leaf: leaf}

	_, err := verified.DeviceIdentity()
	require.ErrorIs(t, err, ErrDeviceIdentityUnavailable)
}

func TestVerifiedAttestation_DeviceIdentity_DICE(t *testing.T) {
	ueid := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	ext, err := dice.CreateUeidExtension(ueid)
	require.NoError(t, err)

	leaf := selfSignedTestCert(t, []pkix.Extension{ext})
	verified := &VerifiedAttestation{Format: FormatDICE, Leaf: leaf}

	identity, err := verified.DeviceIdentity()
	require.NoError(t, err)
	require.Equal(t, "deadbeef", identity)
}

func TestVerifiedAttestation_DeviceIdentity_DICE_NoUeid(t *testing.T) {
	leaf := selfSignedTestCert(t, nil)
	verified := &VerifiedAttestation{Format: FormatDICE, Leaf: leaf}

	_, err := verified.DeviceIdentity()
	require.ErrorIs(t, err, ErrDeviceIdentityUnavailable)
}

func TestVerifiedAttestation_DeviceIdentity_UnknownFormat(t *testing.T) {
	leaf := selfSignedTestCert(t, nil)
	verified := &VerifiedAttestation{Format: AttestationFormat("unknown"), Leaf: leaf}

	_, err := verified.DeviceIdentity()
	require.ErrorIs(t, err, ErrDeviceIdentityUnavailable)
}

func TestVerifiedAttestation_DeviceIdentity_NoLeaf(t *testing.T) {
	verified := &VerifiedAttestation{Format: FormatTPM}

	_, err := verified.DeviceIdentity()
	require.Error(t, err)
}

func TestDeviceIdentityFromCertificate(t *testing.T) {
	ueid, err := dice.CreateUeidExtension([]byte{0x01, 0xAB})
	require.NoError(t, err)

	// The trusted-firmware profile: no tcg-dice-Ueid extension, the ueid is
	// CWT claim 256 (a byte string, type byte first) in the UCCS evidence.
	claimOnly, err := dice.CreateUccsEvidenceExtension(&dice.ClaimsSet{
		Nonce: bytes.Repeat([]byte{0x11}, 32),
		Other: map[int64][]byte{dice.ClaimUeid: {0x42, 0x01, 0xAB}},
	})
	require.NoError(t, err)
	conflicting, err := dice.CreateUccsEvidenceExtension(&dice.ClaimsSet{
		Nonce: bytes.Repeat([]byte{0x11}, 32),
		Other: map[int64][]byte{dice.ClaimUeid: {0x42, 0x01, 0xCD}},
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		format  AttestationFormat
		leaf    *x509.Certificate
		want    string
		wantErr bool
	}{
		{name: "dice reads the ueid claim when there is no extension", format: FormatDICE, leaf: selfSignedTestCert(t, []pkix.Extension{claimOnly}), want: "01ab"},
		{name: "dice refuses an extension and a claim that disagree", format: FormatDICE, leaf: selfSignedTestCert(t, []pkix.Extension{ueid, conflicting}), wantErr: true},
		{name: "tpm reads the permanentIdentifier", format: FormatTPM, leaf: selfSignedTestCert(t, []pkix.Extension{permanentIdentifierExtension(t, "aik-7")}), want: "aik-7"},
		{name: "dice reads the Ueid as hex", format: FormatDICE, leaf: selfSignedTestCert(t, []pkix.Extension{ueid}), want: "01ab"},
		{name: "tpm without a permanentIdentifier", format: FormatTPM, leaf: selfSignedTestCert(t, nil), wantErr: true},
		{name: "dice without a Ueid", format: FormatDICE, leaf: selfSignedTestCert(t, nil), wantErr: true},
		{name: "no certificate", format: FormatTPM, leaf: nil, wantErr: true},
		{name: "format with no identity source", format: AttestationFormat("packed"), leaf: selfSignedTestCert(t, nil), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeviceIdentityFromCertificate(tt.format, tt.leaf)
			if tt.wantErr {
				require.ErrorIs(t, err, ErrDeviceIdentityUnavailable)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestDeviceIdentityFromCertificate_TPMSubjectAltNameShapes(t *testing.T) {
	permanent := func(value string) ca.OtherName {
		encoded, err := ca.MarshalPermanentIdentifier(value, nil)
		require.NoError(t, err)
		return ca.OtherName{TypeID: ca.OIDPermanentIdentifier, Value: encoded}
	}
	hardwareModule := func() ca.OtherName {
		encoded, err := ca.MarshalHardwareModuleName(ca.OIDTCGHwTypeTPM2, []byte("serial"))
		require.NoError(t, err)
		return ca.OtherName{TypeID: ca.OIDHardwareModuleName, Value: encoded}
	}
	san := func(names ...ca.OtherName) *x509.Certificate {
		ext, err := ca.BuildSubjectAltName(pkix.Name{}, nil, nil, nil, nil, names, nil)
		require.NoError(t, err)
		return selfSignedTestCert(t, []pkix.Extension{ext})
	}

	t.Run("a hardwareModuleName beside the permanentIdentifier is genuine DevID", func(t *testing.T) {
		got, err := DeviceIdentityFromCertificate(FormatTPM, san(hardwareModule(), permanent("aik-1")))
		require.NoError(t, err)
		require.Equal(t, "aik-1", got)
	})
	t.Run("two permanentIdentifiers are ambiguous and refused", func(t *testing.T) {
		_, err := DeviceIdentityFromCertificate(FormatTPM, san(permanent("aik-1"), permanent("aik-2")))
		require.ErrorIs(t, err, ErrDeviceIdentityUnavailable)
	})
}
