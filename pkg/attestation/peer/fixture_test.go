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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sort"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
)

// fixtureNow is the clock every test pins the verifier to, so certificate
// validity and evidence age are deterministic.
var fixtureNow = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

// testCA is a two-tier CA (root -> intermediate) that issues attestation-key
// certificates with or without the Restricted policy.
type testCA struct {
	root            *x509.Certificate
	rootKey         *ecdsa.PrivateKey
	intermediate    *x509.Certificate
	intermediateKey *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	ca := &testCA{}
	ca.rootKey = newECKey(t, elliptic.P256())
	ca.root = selfSign(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             fixtureNow.Add(-time.Hour),
		NotAfter:              fixtureNow.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, ca.rootKey)

	ca.intermediateKey = newECKey(t, elliptic.P256())
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test intermediate"},
		NotBefore:             fixtureNow.Add(-time.Hour),
		NotAfter:              fixtureNow.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, ca.root, &ca.intermediateKey.PublicKey, ca.rootKey)
	if err != nil {
		t.Fatalf("intermediate: %v", err)
	}
	ca.intermediate, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse intermediate: %v", err)
	}
	return ca
}

func newECKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ec key: %v", err)
	}
	return key
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	return key
}

func selfSign(t *testing.T, tmpl *x509.Certificate, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert
}

// akCertOptions shape an issued attestation-key certificate.
type akCertOptions struct {
	unrestricted bool
	notAfter     time.Time
	issuer       *x509.Certificate
	issuerKey    crypto.Signer
}

// issueAK issues an attestation-key certificate for pub from the
// intermediate (or the issuer in opts) and returns it PEM encoded.
func (ca *testCA) issueAK(t *testing.T, pub crypto.PublicKey, opts akCertOptions) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "iak"},
		NotBefore:    fixtureNow.Add(-time.Hour),
		NotAfter:     fixtureNow.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if !opts.notAfter.IsZero() {
		tmpl.NotAfter = opts.notAfter
	}
	if !opts.unrestricted {
		tmpl.Policies = []x509.OID{oidTCGVerifiedTPMRestrictedX509}
	}
	issuer, issuerKey := ca.intermediate, crypto.Signer(ca.intermediateKey)
	if opts.issuer != nil {
		issuer, issuerKey = opts.issuer, opts.issuerKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, pub, issuerKey)
	if err != nil {
		t.Fatalf("issue AK: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (ca *testCA) anchors() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.root)
	return pool
}

func (ca *testCA) intermediates() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.intermediate)
	return pool
}

// quoteOptions shape a synthetic TPMS_ATTEST.
type quoteOptions struct {
	// extraData is the qualifying data; defaults to the nonce.
	extraData []byte
	// bank is the PCR bank; defaults to SHA-256.
	bank tpm2.TPMAlgID
	// digestHash computes the PCR digest; defaults to the bank's hash.
	digestHash crypto.Hash
	// digest overrides the computed PCR digest.
	digest []byte
	// attestType overrides TPM_ST_ATTEST_QUOTE.
	attestType tpm2.TPMST
	// magic overrides TPM_GENERATED_VALUE.
	magic tpm2.TPMGenerated
	// extraBank adds a second, non-empty bank selection.
	extraBank bool
	// noSelection empties the PCR selection.
	noSelection bool
	// clock is the TPMS_CLOCK_INFO.
	clock tpm2.TPMSClockInfo
	// firmware is the firmware version.
	firmware uint64
}

// buildQuote marshals a TPMS_ATTEST quote over the PCR values, computing the
// digest the way a TPM does: the selected values in ascending index order
// under the signing hash.
func buildQuote(t *testing.T, nonce []byte, pcrs map[int][]byte, opts quoteOptions) []byte {
	t.Helper()
	indices := make([]int, 0, len(pcrs))
	for idx := range pcrs {
		indices = append(indices, idx)
	}
	sort.Ints(indices)

	bank := opts.bank
	if bank == 0 {
		bank = tpm2.TPMAlgSHA256
	}
	hash := opts.digestHash
	if hash == 0 {
		hash = map[tpm2.TPMAlgID]crypto.Hash{
			tpm2.TPMAlgSHA1:   crypto.SHA1,
			tpm2.TPMAlgSHA256: crypto.SHA256,
			tpm2.TPMAlgSHA384: crypto.SHA384,
			tpm2.TPMAlgSHA512: crypto.SHA512,
		}[bank]
	}
	h := hash.New()
	selection := make([]uint, 0, len(indices))
	for _, idx := range indices {
		h.Write(pcrs[idx])
		selection = append(selection, uint(idx))
	}
	digest := h.Sum(nil)
	if opts.digest != nil {
		digest = opts.digest
	}

	extra := nonce
	if opts.extraData != nil {
		extra = opts.extraData
	}
	attestType := tpm2.TPMSTAttestQuote
	if opts.attestType != 0 {
		attestType = opts.attestType
	}
	magic := tpm2.TPMGeneratedValue
	if opts.magic != 0 {
		magic = opts.magic
	}

	selections := []tpm2.TPMSPCRSelection{{Hash: bank, PCRSelect: tpm2.PCClientCompatible.PCRs(selection...)}}
	if opts.noSelection {
		selections = []tpm2.TPMSPCRSelection{{Hash: bank, PCRSelect: []byte{0, 0, 0}}}
	}
	if opts.extraBank {
		selections = append(selections, tpm2.TPMSPCRSelection{Hash: tpm2.TPMAlgSHA384, PCRSelect: tpm2.PCClientCompatible.PCRs(0)})
	}

	attested := tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
		PCRSelect: tpm2.TPMLPCRSelection{PCRSelections: selections},
		PCRDigest: tpm2.TPM2BDigest{Buffer: digest},
	})
	if attestType == tpm2.TPMSTAttestCertify {
		attested = tpm2.NewTPMUAttest(tpm2.TPMSTAttestCertify, &tpm2.TPMSCertifyInfo{
			Name:          tpm2.TPM2BName{Buffer: []byte("certified")},
			QualifiedName: tpm2.TPM2BName{Buffer: []byte("qualified")},
		})
	}
	attest := tpm2.TPMSAttest{
		Magic:           magic,
		Type:            attestType,
		QualifiedSigner: tpm2.TPM2BName{Buffer: []byte("test-ak")},
		ExtraData:       tpm2.TPM2BData{Buffer: extra},
		ClockInfo:       opts.clock,
		FirmwareVersion: opts.firmware,
		Attested:        attested,
	}
	return tpm2.Marshal(attest)
}

func digestOf(hash crypto.Hash, data []byte) []byte {
	switch hash {
	case crypto.SHA384:
		d := sha512.Sum384(data)
		return d[:]
	case crypto.SHA512:
		d := sha512.Sum512(data)
		return d[:]
	default:
		d := sha256.Sum256(data)
		return d[:]
	}
}

func signRSAPKCS1(t *testing.T, key *rsa.PrivateKey, hash crypto.Hash, quoted []byte) []byte {
	t.Helper()
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, digestOf(hash, quoted))
	if err != nil {
		t.Fatalf("rsa sign: %v", err)
	}
	return sig
}

func signRSAPSS(t *testing.T, key *rsa.PrivateKey, hash crypto.Hash, quoted []byte) []byte {
	t.Helper()
	sig, err := rsa.SignPSS(rand.Reader, key, hash, digestOf(hash, quoted), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		t.Fatalf("rsa-pss sign: %v", err)
	}
	return sig
}

func signECDSAASN1(t *testing.T, key *ecdsa.PrivateKey, hash crypto.Hash, quoted []byte) []byte {
	t.Helper()
	sig, err := ecdsa.SignASN1(rand.Reader, key, digestOf(hash, quoted))
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}
	return sig
}

func signECDSARaw(t *testing.T, key *ecdsa.PrivateKey, hash crypto.Hash, quoted []byte) []byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, key, digestOf(hash, quoted))
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}
	coordLen := (key.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*coordLen)
	r.FillBytes(out[:coordLen])
	s.FillBytes(out[coordLen:])
	return out
}

// goldenPCRs is the PCR set the fixture quotes: two firmware registers and
// PCR 10, the IMA register.
func goldenPCRs() map[int][]byte {
	return map[int][]byte{
		0:  fillPCR(0x11, 32),
		7:  fillPCR(0x77, 32),
		10: fillPCR(0xaa, 32),
	}
}

func fillPCR(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// fixture is an enrolled peer: an RSA attestation key with a Restricted
// certificate from the two-tier CA, a nonce, and the PCR state it quotes.
type fixture struct {
	ca    *testCA
	key   *rsa.PrivateKey
	nonce []byte
	pcrs  map[int][]byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return &fixture{
		ca:    newTestCA(t),
		key:   newRSAKey(t),
		nonce: []byte("nonce-0123456789abcdef0123456789"),
		pcrs:  goldenPCRs(),
	}
}

// evidence produces evidence for a quote over the fixture PCRs whose
// qualifying data is the fixture nonce, signed RSASSA, with a Restricted
// certificate and a collection time one minute before the verifier clock.
func (f *fixture) evidence(t *testing.T) Evidence {
	t.Helper()
	return f.evidenceFor(t, buildQuote(t, f.nonce, f.pcrs, quoteOptions{}))
}

// evidenceFor wraps an arbitrary quote in the fixture's identity.
func (f *fixture) evidenceFor(t *testing.T, quoted []byte) Evidence {
	t.Helper()
	return Evidence{
		Quote:            quoted,
		Signature:        signRSAPKCS1(t, f.key, crypto.SHA256, quoted),
		Nonce:            f.nonce,
		PCRs:             copyPCRs(f.pcrs),
		AKCertificatePEM: f.ca.issueAK(t, &f.key.PublicKey, akCertOptions{}),
		CollectedAt:      fixtureNow.Add(-time.Minute),
	}
}

// policy is the policy the fixture evidence passes: the CA anchors, the
// fixture PCRs as baseline, PCR 10 required, a ten-minute age bound and no
// channel binding.
func (f *fixture) policy() Policy {
	return Policy{
		Anchors:        f.ca.anchors(),
		Intermediates:  f.ca.intermediates(),
		Baseline:       copyPCRs(f.pcrs),
		RequiredPCRs:   []int{10},
		MaxEvidenceAge: 10 * time.Minute,
	}
}

func (f *fixture) verifier() Verifier {
	return NewVerifier(WithClock(func() time.Time { return fixtureNow }))
}

// allChecks is what a passing verdict reports.
var allChecks = Checks{
	AKCertificate:  true,
	Signature:      true,
	Nonce:          true,
	ChannelBinding: true,
	PCRDigest:      true,
	RequiredPCRs:   true,
	Baseline:       true,
	Freshness:      true,
}
