// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package pivcert

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// attestationCA is a signing identity for building test chains.
type attestationCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// newAttestationCA builds a self-signed CA to anchor test attestation chains.
func newAttestationCA(t *testing.T, cn string) *attestationCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &attestationCA{cert: cert, key: key}
}

// issueAttestationCert signs a leaf carrying exts, as a device would.
func issueAttestationCert(t *testing.T, ca *attestationCA, exts []pkix.Extension) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "PIV Attestation 9a"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// fullAttestation is a populated attestation for round-trip tests.
func fullAttestation() *Attestation {
	fw := FirmwareVersion{Major: 5, Minor: 4, Patch: 3}
	serial := uint64(12345678)
	pin := PINPolicyOnce
	touch := TouchPolicyAlways
	ff := FormFactorUSBCKeychain | formFactorFIPSBit
	return &Attestation{
		FirmwareVersion: &fw,
		SerialNumber:    &serial,
		PINPolicy:       &pin,
		TouchPolicy:     &touch,
		FormFactor:      &ff,
	}
}

// --- Parsing ---

// TestParseAttestation_RoundTrip covers the values a policy is written
// against: firmware, serial, PIN and touch policy, form factor and FIPS.
func TestParseAttestation_RoundTrip(t *testing.T) {
	ca := newAttestationCA(t, "Test PIV Attestation Root")
	exts, err := BuildAttestationExtensions(fullAttestation())
	require.NoError(t, err)
	cert := issueAttestationCert(t, ca, exts)

	got, err := ParseAttestation(cert)
	require.NoError(t, err)
	require.NotNil(t, got)

	require.NotNil(t, got.FirmwareVersion)
	assert.Equal(t, "5.4.3", got.FirmwareVersion.String())
	assert.True(t, got.FirmwareVersion.AtLeast(5, 4, 3))
	assert.True(t, got.FirmwareVersion.AtLeast(5, 2, 0))
	assert.False(t, got.FirmwareVersion.AtLeast(5, 4, 4))
	assert.False(t, got.FirmwareVersion.AtLeast(6, 0, 0))

	require.NotNil(t, got.SerialNumber)
	assert.Equal(t, uint64(12345678), *got.SerialNumber)

	require.NotNil(t, got.PINPolicy)
	assert.Equal(t, PINPolicyOnce, *got.PINPolicy)
	assert.Equal(t, "once", got.PINPolicy.String())

	require.NotNil(t, got.TouchPolicy)
	assert.Equal(t, TouchPolicyAlways, *got.TouchPolicy)
	assert.Equal(t, "always", got.TouchPolicy.String())

	require.NotNil(t, got.FormFactor)
	assert.Equal(t, FormFactorUSBCKeychain, got.FormFactor.Base())
	assert.True(t, got.FormFactor.FIPS())
	assert.Equal(t, "usb-c-keychain+fips", got.FormFactor.String())

	assert.Empty(t, got.Unparseable)
	assert.True(t, got.HasAttestationExtensions())
}

// TestParseAttestation_NoExtensions covers an ordinary certificate. It is not
// an error — it simply is not an attestation.
// TestParseAttestation_AbsentIsNotUnparseable is the distinction #206 asks
// for. A device that reports a serial but no touch policy must not look like
// one whose touch policy could not be read: the first may be acceptable to a
// policy, the second means the evidence is not being understood.
func TestParseAttestation_AbsentIsNotUnparseable(t *testing.T) {
	ca := newAttestationCA(t, "Test PIV Attestation Root")
	serial := uint64(42)
	exts, err := BuildAttestationExtensions(&Attestation{SerialNumber: &serial})
	require.NoError(t, err)
	cert := issueAttestationCert(t, ca, exts)

	got, err := ParseAttestation(cert)
	require.NoError(t, err)

	require.NotNil(t, got.SerialNumber)
	assert.Nil(t, got.TouchPolicy, "absent extension yields a nil field")
	assert.False(t, got.IsUnparseable(OIDPINTouchPolicy),
		"an absent extension must not be reported as unparseable")
	assert.Empty(t, got.Unparseable)
}

// TestParseAttestation_MalformedIsUnparseable is the other half: present but
// undecodable is reported as such, and the field stays nil rather than
// carrying a guess.
func TestParseAttestation_MalformedIsUnparseable(t *testing.T) {
	ca := newAttestationCA(t, "Test PIV Attestation Root")
	cert := issueAttestationCert(t, ca, []pkix.Extension{
		{Id: OIDFirmwareVersion, Value: []byte{0x05}},            // too short
		{Id: OIDPINTouchPolicy, Value: []byte{0x02, 0x02, 0x02}}, // too long
		{Id: OIDFormFactor, Value: []byte{}},                     // empty
		{Id: OIDSerialNumber, Value: []byte{0xff, 0xfe, 0xfd}},   // not a DER INTEGER
	})

	got, err := ParseAttestation(cert)
	require.NoError(t, err)

	for _, oid := range []asn1.ObjectIdentifier{
		OIDFirmwareVersion, OIDPINTouchPolicy, OIDFormFactor, OIDSerialNumber,
	} {
		assert.True(t, got.IsUnparseable(oid), "%s must be reported unparseable", oid)
	}
	assert.Nil(t, got.FirmwareVersion)
	assert.Nil(t, got.PINPolicy)
	assert.Nil(t, got.TouchPolicy)
	assert.Nil(t, got.FormFactor)
	assert.Nil(t, got.SerialNumber)

	// It is still recognisably an attestation certificate, which is what a
	// presence check needs.
	assert.True(t, got.HasAttestationExtensions())
}

// TestParseAttestation_WrongFramingIsUnparseableNotAWrongValue is the test
// that makes this package's stated limitation safe rather than merely
// disclosed.
//
// The layout here is Yubico's documented one but has never been checked
// against a physical device, so the framing could be wrong — specifically,
// each value might sit inside an inner OCTET STRING rather than raw in
// extnValue. This builds exactly that alternative framing and asserts the
// parser reports it as UNPARSEABLE rather than decoding it into something
// plausible.
//
// Without this, a device disagreeing with our reading would yield a confident
// wrong answer: an OCTET STRING wrapping 04 03 00 is five bytes whose interior
// bytes would read as a firmware version if the parser were lenient about
// length, and a caller enforcing a firmware floor would act on fiction.
func TestParseAttestation_WrongFramingIsUnparseableNotAWrongValue(t *testing.T) {
	ca := newAttestationCA(t, "Test PIV Attestation Root")

	// The alternative framing: each value wrapped in an inner OCTET STRING.
	wrappedFirmware, err := asn1.Marshal([]byte{0x05, 0x04, 0x03})
	require.NoError(t, err)
	wrappedPolicies, err := asn1.Marshal([]byte{byte(PINPolicyOnce), byte(TouchPolicyAlways)})
	require.NoError(t, err)
	wrappedFormFactor, err := asn1.Marshal([]byte{byte(FormFactorUSBCKeychain)})
	require.NoError(t, err)

	cert := issueAttestationCert(t, ca, []pkix.Extension{
		{Id: OIDFirmwareVersion, Value: wrappedFirmware},
		{Id: OIDPINTouchPolicy, Value: wrappedPolicies},
		{Id: OIDFormFactor, Value: wrappedFormFactor},
	})

	got, err := ParseAttestation(cert)
	require.NoError(t, err)

	assert.Nil(t, got.FirmwareVersion,
		"a differently framed value must not be decoded into a version")
	assert.Nil(t, got.PINPolicy, "a differently framed value must not yield a PIN policy")
	assert.Nil(t, got.TouchPolicy,
		"a differently framed value must NEVER yield a touch policy: a caller would enforce it")
	assert.Nil(t, got.FormFactor, "a differently framed value must not yield a form factor")

	assert.True(t, got.IsUnparseable(OIDFirmwareVersion))
	assert.True(t, got.IsUnparseable(OIDPINTouchPolicy))
	assert.True(t, got.IsUnparseable(OIDFormFactor))
}

// TestParseAttestation_UnrecognisedPolicyValueIsNotUnparseable separates a
// value this build does not know from one it cannot read. A newer firmware
// defining a fourth touch policy decoded correctly; the caller simply will not
// match it against a known constant.
func TestParseAttestation_UnrecognisedPolicyValueIsNotUnparseable(t *testing.T) {
	ca := newAttestationCA(t, "Test PIV Attestation Root")
	cert := issueAttestationCert(t, ca, []pkix.Extension{
		{Id: OIDPINTouchPolicy, Value: []byte{0x09, 0x0a}},
		{Id: OIDFormFactor, Value: []byte{0x7f}},
	})

	got, err := ParseAttestation(cert)
	require.NoError(t, err)

	require.NotNil(t, got.TouchPolicy)
	assert.False(t, got.TouchPolicy.Known(), "0x0a is not a policy this build knows")
	assert.Equal(t, "unrecognized(0x0a)", got.TouchPolicy.String())
	assert.False(t, got.IsUnparseable(OIDPINTouchPolicy),
		"a decodable value this build does not recognise is not unparseable")

	require.NotNil(t, got.FormFactor)
	assert.False(t, got.FormFactor.FIPS())
	assert.Equal(t, "unrecognized(0x7f)", got.FormFactor.String())
}

func TestParseAttestation_NilCertificate(t *testing.T) {
	got, err := ParseAttestation(nil)
	require.Error(t, err)
	assert.Nil(t, got)
}

// TestParseAttestation_SerialEdgeCases covers the one field that is real
// ASN.1 rather than raw bytes.
func TestParseAttestation_SerialEdgeCases(t *testing.T) {
	ca := newAttestationCA(t, "Test PIV Attestation Root")

	negative, err := asn1.Marshal(big.NewInt(-1))
	require.NoError(t, err)
	huge, err := asn1.Marshal(new(big.Int).Lsh(big.NewInt(1), 96))
	require.NoError(t, err)
	trailing, err := asn1.Marshal(big.NewInt(7))
	require.NoError(t, err)
	trailing = append(trailing, 0x00)

	cases := []struct {
		name  string
		value []byte
	}{
		{"negative serial", negative},
		{"serial wider than uint64", huge},
		{"trailing bytes after the integer", trailing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert := issueAttestationCert(t, ca, []pkix.Extension{
				{Id: OIDSerialNumber, Value: tc.value},
			})
			got, err := ParseAttestation(cert)
			require.NoError(t, err)
			assert.Nil(t, got.SerialNumber)
			assert.True(t, got.IsUnparseable(OIDSerialNumber))
		})
	}

	// Zero is a legitimate value and must survive.
	zero, err := asn1.Marshal(big.NewInt(0))
	require.NoError(t, err)
	cert := issueAttestationCert(t, ca, []pkix.Extension{{Id: OIDSerialNumber, Value: zero}})
	got, err := ParseAttestation(cert)
	require.NoError(t, err)
	require.NotNil(t, got.SerialNumber)
	assert.Equal(t, uint64(0), *got.SerialNumber)
}

// --- Chain verification ---

// TestVerifyAttestation_TrustedChain is the positive case: a chain anchored to
// a root the caller supplied returns the decoded values.
// TestVerifyAttestation_UntrustedRootRejected proves the verifier actually
// verifies. A verifier that accepts everything passes every positive test ever
// written, so the negative case is the one that carries the weight: the same
// leaf, a root pool that does not contain its issuer, and a refusal.
func TestVerifyAttestation_UntrustedRootRejected(t *testing.T) {
	ca := newAttestationCA(t, "Test PIV Attestation Root")
	other := newAttestationCA(t, "Some Other Root")
	exts, err := BuildAttestationExtensions(fullAttestation())
	require.NoError(t, err)
	leaf := issueAttestationCert(t, ca, exts)

	roots := x509.NewCertPool()
	roots.AddCert(other.cert)

	got, err := VerifyAttestation([]*x509.Certificate{leaf}, &AttestationVerifyOptions{
		TrustedRoots: roots,
	})
	require.Error(t, err, "a chain that does not anchor must be refused")
	assert.Nil(t, got, "no attestation values may be returned from an unverified chain")

	var chainErr *VerifyChainError
	assert.ErrorAs(t, err, &chainErr)
}

// TestVerifyAttestation_IntermediateFromChain covers the real shape: the slot
// certificate is signed by the device attestation certificate (f9), which the
// device presents alongside it, and only the vendor root is configured.
func TestVerifyAttestation_IntermediateFromChain(t *testing.T) {
	root := newAttestationCA(t, "Test PIV Attestation Root")

	// The device attestation certificate, itself a CA, signed by the root.
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	deviceTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "YubiKey PIV Attestation f9"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	deviceDER, err := x509.CreateCertificate(rand.Reader, deviceTmpl, root.cert, &deviceKey.PublicKey, root.key)
	require.NoError(t, err)
	deviceCert, err := x509.ParseCertificate(deviceDER)
	require.NoError(t, err)

	exts, err := BuildAttestationExtensions(fullAttestation())
	require.NoError(t, err)
	leaf := issueAttestationCert(t, &attestationCA{cert: deviceCert, key: deviceKey}, exts)

	roots := x509.NewCertPool()
	roots.AddCert(root.cert)

	// Only the root is configured; the intermediate comes from the presented
	// chain, which is how a device supplies it.
	got, err := VerifyAttestation([]*x509.Certificate{leaf, deviceCert},
		&AttestationVerifyOptions{TrustedRoots: roots})
	require.NoError(t, err)
	require.NotNil(t, got.SerialNumber)
	assert.Equal(t, uint64(12345678), *got.SerialNumber)

	// Without the intermediate the same chain must NOT verify, which shows the
	// intermediate is doing the work rather than the root matching directly.
	_, err = VerifyAttestation([]*x509.Certificate{leaf},
		&AttestationVerifyOptions{TrustedRoots: roots})
	assert.Error(t, err)
}

// TestVerifyAttestation_NoRootsRefused covers the fail-closed default. An
// unanchored attestation is evidence of nothing, so a missing root pool is an
// error rather than a pass.
func TestVerifyAttestation_NoRootsRefused(t *testing.T) {
	ca := newAttestationCA(t, "Test PIV Attestation Root")
	exts, err := BuildAttestationExtensions(fullAttestation())
	require.NoError(t, err)
	leaf := issueAttestationCert(t, ca, exts)

	for _, tc := range []struct {
		name string
		opts *AttestationVerifyOptions
	}{
		{"nil options", nil},
		{"nil root pool", &AttestationVerifyOptions{}},
		{"empty root pool", &AttestationVerifyOptions{TrustedRoots: x509.NewCertPool()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := VerifyAttestation([]*x509.Certificate{leaf}, tc.opts)
			require.Error(t, err)
			assert.Nil(t, got)
		})
	}
}

// TestVerifyAttestation_ExpiredChainRejected covers temporal validity, and
// that CurrentTime is honoured for reasoning about evidence captured earlier.
func TestVerifyAttestation_ExpiredChainRejected(t *testing.T) {
	ca := newAttestationCA(t, "Test PIV Attestation Root")
	exts, err := BuildAttestationExtensions(fullAttestation())
	require.NoError(t, err)
	leaf := issueAttestationCert(t, ca, exts)

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	// A year hence, both certificates have expired.
	_, err = VerifyAttestation([]*x509.Certificate{leaf}, &AttestationVerifyOptions{
		TrustedRoots: roots,
		CurrentTime:  time.Now().Add(365 * 24 * time.Hour),
	})
	assert.Error(t, err, "an expired chain must be refused")

	// Within the window it verifies, which shows the refusal above was the
	// clock rather than something else.
	_, err = VerifyAttestation([]*x509.Certificate{leaf}, &AttestationVerifyOptions{
		TrustedRoots: roots,
		CurrentTime:  time.Now().Add(time.Hour),
	})
	assert.NoError(t, err)
}

// TestVerifyAttestation_EmptyChain covers the input-validation path.
func TestVerifyAttestation_EmptyChain(t *testing.T) {
	roots := x509.NewCertPool()
	roots.AddCert(newAttestationCA(t, "root").cert)

	got, err := VerifyAttestation(nil, &AttestationVerifyOptions{TrustedRoots: roots})
	require.Error(t, err)
	assert.Nil(t, got)
}

// TestVerifyAttestation_VerifiedChainWithNoExtensions covers the case a policy
// must not confuse with success: the chain is genuinely trusted, and the
// certificate says nothing this build can read. A nil error is not a satisfied
// policy, and the returned attestation is what says so.
func TestVerifyAttestation_VerifiedChainWithNoExtensions(t *testing.T) {
	ca := newAttestationCA(t, "Test PIV Attestation Root")
	leaf := issueAttestationCert(t, ca, nil)

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	got, err := VerifyAttestation([]*x509.Certificate{leaf}, &AttestationVerifyOptions{
		TrustedRoots: roots,
	})
	require.NoError(t, err, "the chain is trusted, so verification succeeds")
	require.NotNil(t, got)
	assert.False(t, got.HasAttestationExtensions(),
		"but it carries no attestation evidence, and the caller must check")
	assert.Nil(t, got.FirmwareVersion)
	assert.Nil(t, got.TouchPolicy)
	assert.Empty(t, got.Unparseable)
}

// TestBuildAttestationExtensions_Partial covers emitting only what is set, and
// that the paired policy extension needs both halves.
func TestBuildAttestationExtensions_Partial(t *testing.T) {
	serial := uint64(99)
	exts, err := BuildAttestationExtensions(&Attestation{SerialNumber: &serial})
	require.NoError(t, err)
	require.Len(t, exts, 1)
	assert.True(t, exts[0].Id.Equal(OIDSerialNumber))

	// A PIN policy with no touch policy emits nothing: the two share one
	// extension and a device reports them together.
	pin := PINPolicyAlways
	exts, err = BuildAttestationExtensions(&Attestation{PINPolicy: &pin})
	require.NoError(t, err)
	assert.Empty(t, exts)

	_, err = BuildAttestationExtensions(nil)
	assert.Error(t, err)
}

// --- Rendering ---

// TestAttestationValueRendering covers the strings an operator reads in a log
// or an error. An unrecognised value must render as itself rather than as a
// neighbouring known one: someone diagnosing a refused login needs to see that
// the device reported something this build does not model, not a policy name
// that was never sent.
func TestAttestationValueRendering(t *testing.T) {
	t.Run("pin policy", func(t *testing.T) {
		for value, want := range map[PINPolicy]string{
			PINPolicyNever:  "never",
			PINPolicyOnce:   "once",
			PINPolicyAlways: "always",
			PINPolicy(0x00): "unrecognized(0x00)",
			PINPolicy(0x7e): "unrecognized(0x7e)",
		} {
			assert.Equal(t, want, value.String())
		}
		assert.True(t, PINPolicyNever.Known())
		assert.True(t, PINPolicyOnce.Known())
		assert.True(t, PINPolicyAlways.Known())
		assert.False(t, PINPolicy(0x7e).Known())
	})

	t.Run("touch policy", func(t *testing.T) {
		for value, want := range map[TouchPolicy]string{
			TouchPolicyNever:  "never",
			TouchPolicyAlways: "always",
			TouchPolicyCached: "cached",
			TouchPolicy(0x00): "unrecognized(0x00)",
		} {
			assert.Equal(t, want, value.String())
		}
		assert.True(t, TouchPolicyCached.Known())
		assert.False(t, TouchPolicy(0x00).Known())
	})

	t.Run("form factor", func(t *testing.T) {
		for value, want := range map[FormFactor]string{
			FormFactorUSBAKeychain:                     "usb-a-keychain",
			FormFactorUSBANano:                         "usb-a-nano",
			FormFactorUSBCKeychain:                     "usb-c-keychain",
			FormFactorUSBCNano:                         "usb-c-nano",
			FormFactorLightning:                        "lightning",
			FormFactorUSBAKeychain | formFactorFIPSBit: "usb-a-keychain+fips",
			FormFactorLightning | formFactorFIPSBit:    "lightning+fips",
			FormFactor(0x0f):                           "unrecognized(0x0f)",
			FormFactor(0x8f):                           "unrecognized(0x0f)+fips",
		} {
			assert.Equal(t, want, value.String())
		}
	})

	t.Run("firmware version ordering", func(t *testing.T) {
		v := FirmwareVersion{Major: 5, Minor: 4, Patch: 3}
		assert.Equal(t, "5.4.3", v.String())
		assert.True(t, v.AtLeast(4, 9, 9), "a lower major is below")
		assert.True(t, v.AtLeast(5, 3, 9), "a lower minor is below")
		assert.False(t, v.AtLeast(5, 5, 0), "a higher minor is above")
		assert.False(t, v.AtLeast(6, 0, 0), "a higher major is above")
	})
}

// TestAttestation_NilReceivers covers the accessors on a nil attestation, which
// a caller reaches after an error path.
func TestAttestation_NilReceivers(t *testing.T) {
	var att *Attestation
	assert.False(t, att.HasAttestationExtensions())
	assert.False(t, att.IsUnparseable(OIDFormFactor))

	empty := &Attestation{}
	assert.False(t, empty.HasAttestationExtensions())
	assert.False(t, empty.IsUnparseable(OIDFormFactor))
}
