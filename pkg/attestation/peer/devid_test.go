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

package peer

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// TestDevIDOIDsMatchTheIssuer pins every object identifier this package
// recognises a credential by to the one pkg/ca stamps when it issues that
// credential. The two are declared apart so that a consumer of the
// verification primitive does not link the certificate authority; this test is
// what stops them drifting into a validator that rejects everything its own CA
// issues.
func TestDevIDOIDsMatchTheIssuer(t *testing.T) {
	pairs := map[string][2]asn1.ObjectIdentifier{
		"tcg-cap-verifiedTPMFixed":      {oidTCGVerifiedTPMFixed, ca.OIDTCGVerifiedTPMFixed},
		"tcg-cap-verifiedTPMRestricted": {oidTCGVerifiedTPMRestricted, ca.OIDTCGVerifiedTPMRestricted},
		"tcg hwType TPM 2.0":            {oidTCGHwTypeTPM2, ca.OIDTCGHwTypeTPM2},
		"tcg-on-ekPermIdSha256":         {oidTCGOnEKPermIdSha256, ca.OIDTCGOnEKPermIdSha256},
		"id-on-hardwareModuleName":      {oidHardwareModuleName, ca.OIDHardwareModuleName},
		"id-on-permanentIdentifier":     {oidPermanentIdentifier, ca.OIDPermanentIdentifier},
	}
	for name, pair := range pairs {
		if !pair[0].Equal(pair[1]) {
			t.Errorf("%s: peer has %v, pkg/ca issues %v", name, pair[0], pair[1])
		}
	}

	// The x509.OID forms Go populates Certificate.Policies with must name the
	// same assertions as the asn1 forms.
	if !oidTCGVerifiedTPMFixedX509.Equal(ca.TCGVerifiedTPMFixedPolicy) {
		t.Errorf("verifiedTPMFixed policy form: peer has %v, pkg/ca issues %v",
			oidTCGVerifiedTPMFixedX509, ca.TCGVerifiedTPMFixedPolicy)
	}
	if !oidTCGVerifiedTPMRestrictedX509.Equal(ca.TCGVerifiedTPMRestrictedPolicy) {
		t.Errorf("verifiedTPMRestricted policy form: peer has %v, pkg/ca issues %v",
			oidTCGVerifiedTPMRestrictedX509, ca.TCGVerifiedTPMRestrictedPolicy)
	}
}

// devIDOptions shape an issued device credential. The zero value issues the
// canonical IDevID that pkg/ca produces from a TCG-CSR-IDEVID: digitalSignature
// alone, the residency and fixed assertions as certificate policies, the fixed
// assertion as the TCG extended key usage, and both §8.1 subjectAltName
// otherNames.
type devIDOptions struct {
	// attestation issues the IAK form: the restricted assertion instead of
	// the fixed one.
	attestation bool
	// policies overrides the certificate policies, when set.
	policies []x509.OID
	// noPolicies issues a credential with no certificate policies at all, so
	// the TCG assertion can only come from the extended key usage.
	noPolicies bool
	// unknownEKU overrides the TCG extended key usage, when set.
	unknownEKU []asn1.ObjectIdentifier
	// noUnknownEKU issues a credential with no TCG extended key usage.
	noUnknownEKU bool
	// keyUsage overrides the key usage.
	keyUsage x509.KeyUsage
	// isCA marks the credential a certificate authority.
	isCA bool
	// notBefore and notAfter override the validity window.
	notBefore, notAfter time.Time
	// hwType overrides the hardware module name's hwType.
	hwType asn1.ObjectIdentifier
	// hwSerial overrides the hardware module name's hwSerialNum.
	hwSerial *string
	// permID overrides the permanent identifier's identifierValue.
	permID *string
	// assigner overrides the permanent identifier's assigner.
	assigner asn1.ObjectIdentifier
	// noAssigner omits the assigner field entirely.
	noAssigner bool
	// omitHardwareName omits the hardware module name otherName.
	omitHardwareName bool
	// omitPermanentID omits the permanent identifier otherName.
	omitPermanentID bool
	// omitSAN omits the subjectAltName extension entirely.
	omitSAN bool
	// issuer and issuerKey override the issuing intermediate.
	issuer    *x509.Certificate
	issuerKey crypto.Signer
}

// issueDevID issues a device credential for pub and returns the parsed
// certificate.
func (c *testCA) issueDevID(t *testing.T, pub crypto.PublicKey, opts devIDOptions) *x509.Certificate {
	t.Helper()

	assertion := oidTCGVerifiedTPMFixed
	assertionPolicy := oidTCGVerifiedTPMFixedX509
	if opts.attestation {
		assertion = oidTCGVerifiedTPMRestricted
		assertionPolicy = oidTCGVerifiedTPMRestrictedX509
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "device-1", SerialNumber: "SN-1"},
		NotBefore:             fixtureNow.Add(-time.Hour),
		NotAfter:              fixtureNow.Add(12 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{assertion},
		Policies:              []x509.OID{assertionPolicy},
		BasicConstraintsValid: true,
	}
	if opts.keyUsage != 0 {
		tmpl.KeyUsage = opts.keyUsage
	}
	if opts.isCA {
		tmpl.IsCA = true
	}
	if !opts.notBefore.IsZero() {
		tmpl.NotBefore = opts.notBefore
	}
	if !opts.notAfter.IsZero() {
		tmpl.NotAfter = opts.notAfter
	}
	if opts.policies != nil {
		tmpl.Policies = opts.policies
	}
	if opts.noPolicies {
		tmpl.Policies = nil
	}
	if opts.unknownEKU != nil {
		tmpl.UnknownExtKeyUsage = opts.unknownEKU
	}
	if opts.noUnknownEKU {
		tmpl.UnknownExtKeyUsage = nil
	}
	if !opts.omitSAN {
		tmpl.ExtraExtensions = []pkix.Extension{devIDSAN(t, opts)}
	}

	issuer, issuerKey := c.intermediate, crypto.Signer(c.intermediateKey)
	if opts.issuer != nil {
		issuer, issuerKey = opts.issuer, opts.issuerKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, pub, issuerKey)
	if err != nil {
		t.Fatalf("issue DevID: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse DevID: %v", err)
	}
	return cert
}

// devIDSAN builds the subjectAltName extension of a DevID credential: the two
// TCG DevID v1 r12 §8.1 otherNames, plus a dNSName so the encoding is
// exercised alongside an ordinary general name the way a real credential
// carries one.
func devIDSAN(t *testing.T, opts devIDOptions) pkix.Extension {
	t.Helper()

	var names []byte
	if !opts.omitHardwareName {
		hwType := oidTCGHwTypeTPM2
		if opts.hwType != nil {
			hwType = opts.hwType
		}
		serial := "IFX:0a0b:0c0d"
		if opts.hwSerial != nil {
			serial = *opts.hwSerial
		}
		value, err := asn1.Marshal(tcgHardwareModuleName{HWType: hwType, HWSerial: []byte(serial)})
		if err != nil {
			t.Fatalf("marshal hardware module name: %v", err)
		}
		names = append(names, otherName(t, oidHardwareModuleName, value)...)
	}
	if !opts.omitPermanentID {
		identifier := "b2c3d4e5f6"
		if opts.permID != nil {
			identifier = *opts.permID
		}
		assigner := oidTCGOnEKPermIdSha256
		if opts.assigner != nil {
			assigner = opts.assigner
		}

		var value []byte
		var err error
		if opts.noAssigner {
			// encoding/asn1 always writes an OPTIONAL field, so a permanent
			// identifier without an assigner has to be marshaled from a type
			// that does not have the field.
			value, err = asn1.Marshal(struct {
				IdentifierValue string `asn1:"utf8"`
			}{identifier})
		} else {
			value, err = asn1.Marshal(tcgPermanentIdentifier{IdentifierValue: identifier, Assigner: assigner})
		}
		if err != nil {
			t.Fatalf("marshal permanent identifier: %v", err)
		}
		names = append(names, otherName(t, oidPermanentIdentifier, value)...)
	}

	dns, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("device-1.example.com")})
	if err != nil {
		t.Fatalf("marshal dNSName: %v", err)
	}
	names = append(names, dns...)

	value, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      names,
	})
	if err != nil {
		t.Fatalf("marshal subjectAltName: %v", err)
	}
	return pkix.Extension{Id: oidSubjectAltNameExt, Value: value}
}

// otherName encodes one GeneralName of CHOICE otherName the way pkg/ca's
// BuildSubjectAltName does: context tag [0] IMPLICIT over the SEQUENCE, whose
// value is wrapped in context tag [0] EXPLICIT.
func otherName(t *testing.T, typeID asn1.ObjectIdentifier, value []byte) []byte {
	t.Helper()
	typeDER, err := asn1.Marshal(typeID)
	if err != nil {
		t.Fatalf("marshal otherName type: %v", err)
	}
	explicit, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: value})
	if err != nil {
		t.Fatalf("marshal otherName value: %v", err)
	}
	encoded, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      append(typeDER, explicit...),
	})
	if err != nil {
		t.Fatalf("marshal otherName: %v", err)
	}
	return encoded
}

// devIDPolicy is the policy the fixture credentials verify under: the test
// CA's anchors and intermediates at the fixture clock.
func (c *testCA) devIDPolicy() DevIDPolicy {
	return DevIDPolicy{
		Anchors:       c.anchors(),
		Intermediates: c.intermediates(),
		CurrentTime:   fixtureNow,
	}
}

// requireDevIDError asserts that err is a *DevIDError whose reason names the
// check that was supposed to fail.
func requireDevIDError(t *testing.T, err error, substring string) {
	t.Helper()
	var de *DevIDError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v, want *DevIDError", err)
	}
	if !strings.Contains(de.Reason, substring) {
		t.Fatalf("reason = %q, want it to mention %q", de.Reason, substring)
	}
}

func TestVerifyIDevID_AcceptsCanonicalCredential(t *testing.T) {
	testCA := newTestCA(t)
	key := newECKey(t, elliptic.P256())
	cert := testCA.issueDevID(t, &key.PublicKey, devIDOptions{})

	if err := VerifyIDevID(context.Background(), cert, testCA.devIDPolicy()); err != nil {
		t.Fatalf("VerifyIDevID: %v", err)
	}
	if !IsIDevID(cert) {
		t.Fatal("IsIDevID = false for a canonical device identity credential")
	}
	// The two classes are distinguished, not merely recognised: §8.2 marks
	// them differently to prevent one being presented as the other.
	if IsIAK(cert) {
		t.Fatal("IsIAK = true for a device identity credential")
	}
	if err := VerifyIAK(context.Background(), cert, testCA.devIDPolicy()); err == nil {
		t.Fatal("VerifyIAK accepted a device identity credential")
	}
}

func TestVerifyIAK_AcceptsCanonicalCredential(t *testing.T) {
	testCA := newTestCA(t)
	key := newECKey(t, elliptic.P256())
	cert := testCA.issueDevID(t, &key.PublicKey, devIDOptions{attestation: true})

	if err := VerifyIAK(context.Background(), cert, testCA.devIDPolicy()); err != nil {
		t.Fatalf("VerifyIAK: %v", err)
	}
	if !IsIAK(cert) || IsIDevID(cert) {
		t.Fatalf("IsIAK = %v, IsIDevID = %v for an attestation credential", IsIAK(cert), IsIDevID(cert))
	}
	if err := VerifyIDevID(context.Background(), cert, testCA.devIDPolicy()); err == nil {
		t.Fatal("VerifyIDevID accepted an attestation key credential")
	}
}

// TestVerifyDevID_AcceptsTheExtendedKeyUsageEncoding: TCG DevID v1 r12 gives
// the assertion two encodings — a certificate policy (§8.2) and an extended
// key usage (§8.1) — and pkg/ca stamps both. A credential carrying only the
// extended key usage is still asserting it.
func TestVerifyDevID_AcceptsTheExtendedKeyUsageEncoding(t *testing.T) {
	testCA := newTestCA(t)
	key := newECKey(t, elliptic.P256())
	cert := testCA.issueDevID(t, &key.PublicKey, devIDOptions{noPolicies: true})

	if len(cert.Policies) != 0 {
		t.Fatalf("fixture carries %d certificate policies, want none", len(cert.Policies))
	}
	if err := VerifyIDevID(context.Background(), cert, testCA.devIDPolicy()); err != nil {
		t.Fatalf("VerifyIDevID: %v", err)
	}
}

// TestVerifyIDevID_RejectsMissingTCGAssertion: a certificate a trusted CA
// issued to a device, with no TCG assertion at all, is an ordinary client
// certificate. Accepting it would make every certificate from the same CA a
// device identity.
func TestVerifyIDevID_RejectsMissingTCGAssertion(t *testing.T) {
	testCA := newTestCA(t)
	key := newECKey(t, elliptic.P256())
	cert := testCA.issueDevID(t, &key.PublicKey, devIDOptions{noPolicies: true, noUnknownEKU: true})

	err := VerifyIDevID(context.Background(), cert, testCA.devIDPolicy())
	requireDevIDError(t, err, "tcg-cap-verifiedTPMFixed")
	if IsIDevID(cert) {
		t.Fatal("IsIDevID = true for a certificate carrying no TCG assertion")
	}
}

// TestVerifyIDevID_RejectsTheOtherClassAssertion: §8.2 forbids combining the
// two assertions, and an identity key is Unrestricted by construction. A
// certificate asserting Restricted is an attestation credential; treating it
// as an identity is the spoofing the two markers exist to prevent.
func TestVerifyIDevID_RejectsTheOtherClassAssertion(t *testing.T) {
	testCA := newTestCA(t)
	key := newECKey(t, elliptic.P256())
	cert := testCA.issueDevID(t, &key.PublicKey, devIDOptions{
		policies:   []x509.OID{oidTCGVerifiedTPMFixedX509, oidTCGVerifiedTPMRestrictedX509},
		unknownEKU: []asn1.ObjectIdentifier{oidTCGVerifiedTPMFixed, oidTCGVerifiedTPMRestricted},
	})

	err := VerifyIDevID(context.Background(), cert, testCA.devIDPolicy())
	requireDevIDError(t, err, "tcg-cap-verifiedTPMRestricted")

	// Symmetrically for the attestation class.
	err = VerifyIAK(context.Background(), cert, testCA.devIDPolicy())
	requireDevIDError(t, err, "tcg-cap-verifiedTPMFixed")
}

func TestVerifyIDevID_RejectsWrongKeyUsage(t *testing.T) {
	testCA := newTestCA(t)
	key := newECKey(t, elliptic.P256())

	cases := map[string]struct {
		opts devIDOptions
		want string
	}{
		"no digital signature": {
			opts: devIDOptions{keyUsage: x509.KeyUsageKeyEncipherment},
			want: "digitalSignature",
		},
		"certificate signer": {
			opts: devIDOptions{keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign},
			want: "certificate- or CRL-signing",
		},
		"revocation signer": {
			opts: devIDOptions{keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign},
			want: "certificate- or CRL-signing",
		},
		"certificate authority": {
			opts: devIDOptions{isCA: true, keyUsage: x509.KeyUsageDigitalSignature},
			want: "CA basic constraint",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cert := testCA.issueDevID(t, &key.PublicKey, tc.opts)
			err := VerifyIDevID(context.Background(), cert, testCA.devIDPolicy())
			requireDevIDError(t, err, tc.want)
		})
	}
}

func TestVerifyIDevID_RejectsCertificateOutsideItsValidityWindow(t *testing.T) {
	testCA := newTestCA(t)
	key := newECKey(t, elliptic.P256())

	expired := testCA.issueDevID(t, &key.PublicKey, devIDOptions{
		notBefore: fixtureNow.Add(-48 * time.Hour),
		notAfter:  fixtureNow.Add(-time.Hour),
	})
	requireDevIDError(t, VerifyIDevID(context.Background(), expired, testCA.devIDPolicy()), "expired at")

	future := testCA.issueDevID(t, &key.PublicKey, devIDOptions{
		notBefore: fixtureNow.Add(time.Hour),
		notAfter:  fixtureNow.Add(48 * time.Hour),
	})
	requireDevIDError(t, VerifyIDevID(context.Background(), future, testCA.devIDPolicy()), "not valid until")

	// The shape predicate deliberately ignores time: an expired credential is
	// still recognisably a device identity, which is why it must never be
	// used as the authorization decision.
	if !IsIDevID(expired) {
		t.Fatal("IsIDevID = false for an expired but well-formed credential")
	}
}

func TestVerifyIDevID_RejectsWrongChain(t *testing.T) {
	testCA := newTestCA(t)
	foreign := newTestCA(t)
	key := newECKey(t, elliptic.P256())

	// Issued by a CA the policy does not anchor.
	cert := foreign.issueDevID(t, &key.PublicKey, devIDOptions{})
	err := VerifyIDevID(context.Background(), cert, testCA.devIDPolicy())
	requireDevIDError(t, err, "does not chain")

	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("chain rejection does not unwrap to an x509 error: %v", err)
	}

	// Anchored correctly but with no path to the root: the intermediate that
	// issued the credential is not supplied.
	orphan := testCA.issueDevID(t, &key.PublicKey, devIDOptions{})
	policy := testCA.devIDPolicy()
	policy.Intermediates = nil
	requireDevIDError(t, VerifyIDevID(context.Background(), orphan, policy), "does not chain")

	// Self-issued: the peer is its own anchor for everything but the policy's
	// pool.
	selfKey := newECKey(t, elliptic.P256())
	self := selfSign(t, &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "self"},
		NotBefore:    fixtureNow.Add(-time.Hour),
		NotAfter:     fixtureNow.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		Policies:     []x509.OID{oidTCGVerifiedTPMFixedX509},
	}, selfKey)
	requireDevIDError(t, VerifyIDevID(context.Background(), self, testCA.devIDPolicy()), "does not chain")
}

// TestVerifyIDevID_RejectsMissingOrWrongDeviceNames covers the §8.1
// subjectAltName otherNames, which are what bind the credential to a TPM. A
// credential without them names no hardware.
func TestVerifyIDevID_RejectsMissingOrWrongDeviceNames(t *testing.T) {
	testCA := newTestCA(t)
	key := newECKey(t, elliptic.P256())
	empty := ""

	cases := map[string]struct {
		opts devIDOptions
		want string
	}{
		"no subject alternative name": {
			opts: devIDOptions{omitSAN: true},
			want: "no subjectAltName",
		},
		"no hardware module name": {
			opts: devIDOptions{omitHardwareName: true},
			want: "no RFC 4108 hardware module name",
		},
		"no permanent identifier": {
			opts: devIDOptions{omitPermanentID: true},
			want: "no RFC 4043 permanent identifier",
		},
		"hardware is not a TPM 2.0": {
			opts: devIDOptions{hwType: asn1.ObjectIdentifier{2, 23, 133, 1, 1}},
			want: "not the TPM 2.0 OID",
		},
		"no hardware serial number": {
			opts: devIDOptions{hwSerial: &empty},
			want: "no hwSerialNum",
		},
		"no identifier value": {
			opts: devIDOptions{permID: &empty},
			want: "no identifierValue",
		},
		"no assigner": {
			opts: devIDOptions{noAssigner: true},
			want: "no assigner",
		},
		"wrong assigner": {
			opts: devIDOptions{assigner: asn1.ObjectIdentifier{1, 2, 3, 4}},
			want: "not tcg-on-ekPermIdSha256",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cert := testCA.issueDevID(t, &key.PublicKey, tc.opts)
			requireDevIDError(t, VerifyIDevID(context.Background(), cert, testCA.devIDPolicy()), tc.want)
			if IsIDevID(cert) {
				t.Fatal("IsIDevID = true for a credential that names no TPM")
			}
		})
	}
}

// TestVerifyIDevID_RejectsCallerMistakesWithTypedErrors: the caller's own
// mistakes are kept apart from the device's, so a gate can tell a
// misconfigured verifier from a rejected device.
func TestVerifyIDevID_RejectsCallerMistakesWithTypedErrors(t *testing.T) {
	testCA := newTestCA(t)
	key := newECKey(t, elliptic.P256())
	cert := testCA.issueDevID(t, &key.PublicKey, devIDOptions{})

	requireDevIDError(t, VerifyIDevID(context.Background(), nil, testCA.devIDPolicy()), "no certificate")

	policy := testCA.devIDPolicy()
	policy.Anchors = nil
	err := VerifyIDevID(context.Background(), cert, policy)
	var pe *DevIDPolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want *DevIDPolicyError", err)
	}
	if pe.Field != "Anchors" {
		t.Fatalf("field = %q, want Anchors", pe.Field)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = VerifyIDevID(ctx, cert, testCA.devIDPolicy())
	var ce *ContextError
	if !errors.As(err, &ce) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want *ContextError wrapping context.Canceled", err)
	}

	if IsIDevID(nil) || IsIAK(nil) {
		t.Fatal("a nil certificate is not a credential")
	}
}

// TestVerifyIDevID_UsesTheCurrentTimeByDefault proves the zero CurrentTime
// means now rather than the zero instant, which would reject every credential
// as not yet valid.
func TestVerifyIDevID_UsesTheCurrentTimeByDefault(t *testing.T) {
	// Both the credential and the CA that issued it are valid around the real
	// clock. The fixture CA is anchored to the pinned fixture instant, so it
	// could not show this: its own chain would be the thing that expired.
	now := time.Now().UTC()
	rootKey := newECKey(t, elliptic.P256())
	root := selfSign(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "current root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, rootKey)
	anchors := x509.NewCertPool()
	anchors.AddCert(root)

	// issueDevID takes its issuer from the options, so no fixture CA is
	// involved in this credential.
	key := newECKey(t, elliptic.P256())
	cert := (&testCA{}).issueDevID(t, &key.PublicKey, devIDOptions{
		issuer:    root,
		issuerKey: rootKey,
		notBefore: now.Add(-time.Hour),
		notAfter:  now.Add(time.Hour),
	})

	// A zero CurrentTime must mean now. Were it the zero instant, every
	// credential would be rejected as not yet valid.
	if err := VerifyIDevID(context.Background(), cert, DevIDPolicy{Anchors: anchors}); err != nil {
		t.Fatalf("VerifyIDevID with a default clock: %v", err)
	}
}

// TestVerifySameDevice_AcceptsAPairFromOneTPM: an IDevID and an IAK issued for
// one TPM carry the same hardware module name and permanent identifier.
func TestVerifySameDevice_AcceptsAPairFromOneTPM(t *testing.T) {
	testCA := newTestCA(t)
	identity := testCA.issueDevID(t, &newECKey(t, elliptic.P256()).PublicKey, devIDOptions{})
	attestation := testCA.issueDevID(t, &newECKey(t, elliptic.P256()).PublicKey, devIDOptions{attestation: true})

	if err := VerifySameDevice(identity, attestation); err != nil {
		t.Fatalf("VerifySameDevice: %v", err)
	}
}

// TestVerifySameDevice_RefusesCredentialsFromDifferentTPMs: a relayed quote is
// signed by another TPM's attestation key, whose names differ from the
// connection's identity credential. Each name is checked on its own.
func TestVerifySameDevice_RefusesCredentialsFromDifferentTPMs(t *testing.T) {
	otherSerial := "IFX:ffff:eeee"
	otherID := "0123456789"
	cases := map[string]struct {
		opts  devIDOptions
		field string
	}{
		"different hardware serial":       {opts: devIDOptions{attestation: true, hwSerial: &otherSerial}, field: "hardwareModuleName"},
		"different permanent identifier":  {opts: devIDOptions{attestation: true, permID: &otherID}, field: "permanentIdentifier"},
		"different hardware module type":  {opts: devIDOptions{attestation: true, hwType: asn1.ObjectIdentifier{2, 23, 133, 1, 1}}, field: "hardwareModuleName"},
		"different permanent id assigner": {opts: devIDOptions{attestation: true, assigner: asn1.ObjectIdentifier{1, 2, 3}}, field: "permanentIdentifier"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			testCA := newTestCA(t)
			identity := testCA.issueDevID(t, &newECKey(t, elliptic.P256()).PublicKey, devIDOptions{})
			attestation := testCA.issueDevID(t, &newECKey(t, elliptic.P256()).PublicKey, tc.opts)

			err := VerifySameDevice(identity, attestation)
			var mismatch *DeviceMismatchError
			if !errors.As(err, &mismatch) {
				t.Fatalf("VerifySameDevice = %v, want *DeviceMismatchError", err)
			}
			if mismatch.Field != tc.field {
				t.Fatalf("mismatch field = %q, want %q", mismatch.Field, tc.field)
			}
		})
	}
}

// TestVerifySameDevice_RefusesCredentialsWithoutDeviceNames: a certificate
// that does not name its TPM cannot be paired with anything; that is a
// *DevIDError naming the credential, never a pass.
func TestVerifySameDevice_RefusesCredentialsWithoutDeviceNames(t *testing.T) {
	testCA := newTestCA(t)
	identity := testCA.issueDevID(t, &newECKey(t, elliptic.P256()).PublicKey, devIDOptions{})
	attestation := testCA.issueDevID(t, &newECKey(t, elliptic.P256()).PublicKey, devIDOptions{attestation: true})
	bareIdentity := testCA.issueDevID(t, &newECKey(t, elliptic.P256()).PublicKey, devIDOptions{omitSAN: true})
	bareAttestation := testCA.issueDevID(t, &newECKey(t, elliptic.P256()).PublicKey, devIDOptions{attestation: true, omitPermanentID: true})

	cases := map[string]struct {
		identity, attestation *x509.Certificate
		credential            string
	}{
		"no identity certificate":          {nil, attestation, "IDevID"},
		"no attestation certificate":       {identity, nil, "IAK"},
		"identity without device names":    {bareIdentity, attestation, "IDevID"},
		"attestation without permanent id": {identity, bareAttestation, "IAK"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := VerifySameDevice(tc.identity, tc.attestation)
			var devErr *DevIDError
			if !errors.As(err, &devErr) {
				t.Fatalf("VerifySameDevice = %v, want *DevIDError", err)
			}
			if devErr.Credential != tc.credential {
				t.Fatalf("credential = %q, want %q", devErr.Credential, tc.credential)
			}
		})
	}
}
