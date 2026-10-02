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

package dice

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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

// testNonce is the challenge the verifier issues in these tests. Freshness in
// this profile is always a nonce -- the device has no clock -- so every test
// chain echoes this value in the eat_nonce claim of its tcg-dice-UCCS-evidence
// extension.
var testNonce = []byte{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
	0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF}

// testUeid is the device identifier the test chains report.
var testUeid = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

// testChain is a three-certificate DICE chain: a manufacturer root, a
// device-resident embedded CA, and the alias leaf whose key is the one being
// certified.
type testChain struct {
	root  *x509.Certificate
	eca   *x509.Certificate
	leaf  *x509.Certificate
	roots *x509.CertPool
}

// certs returns the chain in the leaf-first order Verify expects.
func (c *testChain) certs() []*x509.Certificate {
	return []*x509.Certificate{c.leaf, c.eca, c.root}
}

// chainOption adjusts how a test chain is built.
type chainOption func(*chainConfig)

type chainConfig struct {
	tcbInfo     *TcbInfo
	rawTcbInfo  []byte
	omitTcbInfo bool
	nonce       []byte
	rawUccs     []byte
	omitUccs    bool
	claimsOther map[int64][]byte
	ueid        []byte
	omitUeid    bool
	leafKey     crypto.Signer
	notBefore   time.Time
	notAfter    time.Time
	ecaHasDICE  bool
	ecaKey      crypto.Signer
	rawECATcb   []byte
	leafSigAlg  x509.SignatureAlgorithm
}

// withTcbInfo replaces the leaf's DiceTcbInfo.
func withTcbInfo(info *TcbInfo) chainOption {
	return func(c *chainConfig) { c.tcbInfo = info }
}

// withRawTcbInfo puts already-encoded bytes in the extension, so a test can
// present evidence the encoder in this package would refuse to produce.
func withRawTcbInfo(value []byte) chainOption {
	return func(c *chainConfig) { c.rawTcbInfo = value }
}

// withoutTcbInfo leaves the leaf with no DiceTcbInfo extension.
func withoutTcbInfo() chainOption {
	return func(c *chainConfig) { c.omitTcbInfo = true }
}

// withNonce replaces the challenge the leaf echoes in its eat_nonce claim.
func withNonce(nonce []byte) chainOption {
	return func(c *chainConfig) { c.nonce = nonce }
}

// withRawUccs puts already-encoded bytes in the tcg-dice-UCCS-evidence
// extension, so a test can present a claims set the encoder in this package
// would refuse to produce.
func withRawUccs(value []byte) chainOption {
	return func(c *chainConfig) { c.rawUccs = value }
}

// withoutUccs leaves the leaf with no tcg-dice-UCCS-evidence extension, which
// is a device that answered without the challenge.
func withoutUccs() chainOption {
	return func(c *chainConfig) { c.omitUccs = true }
}

// withClaim adds a claim, given as the raw CBOR item, beside the nonce in the
// leaf's claims set.
func withClaim(key int64, cborItem []byte) chainOption {
	return func(c *chainConfig) {
		if c.claimsOther == nil {
			c.claimsOther = map[int64][]byte{}
		}
		c.claimsOther[key] = cborItem
	}
}

// ueidClaim is value as the CBOR byte string a ueid claim carries.
func ueidClaim(value []byte) []byte {
	return append([]byte{0x40 | byte(len(value))}, value...)
}

// withoutUeid leaves the leaf with no tcg-dice-Ueid extension.
func withoutUeid() chainOption {
	return func(c *chainConfig) { c.omitUeid = true }
}

// withUeid replaces the leaf's device identifier.
func withUeid(value []byte) chainOption {
	return func(c *chainConfig) { c.ueid = value }
}

// withLeafKey gives the leaf a key other than ECDSA P-256.
func withLeafKey(key crypto.Signer) chainOption {
	return func(c *chainConfig) { c.leafKey = key }
}

// withValidity sets the leaf's validity window.
func withValidity(notBefore, notAfter time.Time) chainOption {
	return func(c *chainConfig) {
		c.notBefore = notBefore
		c.notAfter = notAfter
	}
}

// withDICEOnECA marks the embedded CA as device-resident by giving it a UEID
// extension, which is what brings it under the ECDSA P-256 constraint.
func withDICEOnECA() chainOption {
	return func(c *chainConfig) { c.ecaHasDICE = true }
}

// withECAKey gives the embedded CA a key other than ECDSA P-256.
func withECAKey(key crypto.Signer) chainOption {
	return func(c *chainConfig) { c.ecaKey = key }
}

// withRawECATcbInfo puts already-encoded bytes in a CRITICAL tcg-dice-TcbInfo
// extension on the embedded CA, so a test can present an INTERMEDIATE whose
// evidence no verifier can read. The leaf is where every other test puts
// malformed evidence, and the leaf is the one certificate Verify decodes.
func withRawECATcbInfo(value []byte) chainOption {
	return func(c *chainConfig) { c.rawECATcb = value }
}

// withLeafSignatureAlgorithm signs the leaf with something other than the
// ECDSA-SHA256 an element performs.
func withLeafSignatureAlgorithm(alg x509.SignatureAlgorithm) chainOption {
	return func(c *chainConfig) { c.leafSigAlg = alg }
}

func mustP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func mustP384(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	return key
}

func mustEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return key
}

// newTestChain builds a DICE chain in memory. Nothing here touches the host:
// three key generations and three self-contained signings.
func newTestChain(t *testing.T, options ...chainOption) *testChain {
	t.Helper()

	config := &chainConfig{
		tcbInfo: &TcbInfo{
			Vendor:     "Automate The Things",
			Model:      "AVR-DICE",
			Version:    "1.0.0",
			SVN:        intPtr(1),
			Layer:      intPtr(0),
			FWIDs:      []FWID{{HashAlg: oidSHA256, Digest: make([]byte, 32)}},
			VendorInfo: []byte("avr-tier-hardware"),
		},
		nonce:     testNonce,
		ueid:      testUeid,
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(24 * time.Hour),
	}
	for _, option := range options {
		option(config)
	}

	// The issuing chain's validity is deliberately wide. These tests move the
	// verifier's clock to exercise the leaf's window, and a CA that expired
	// alongside the leaf would make every such test fail for the wrong reason.
	caNotBefore := time.Now().Add(-365 * 24 * time.Hour)
	caNotAfter := time.Now().Add(365 * 24 * time.Hour)

	rootKey := mustP256(t)
	root := signCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test DICE Manufacturer Root"},
		NotBefore:             caNotBefore,
		NotAfter:              caNotAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, rootKey, rootKey.Public())

	ecaKey := config.ecaKey
	if ecaKey == nil {
		ecaKey = mustP256(t)
	}
	ecaTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test DICE Embedded CA"},
		NotBefore:             caNotBefore,
		NotAfter:              caNotAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if config.ecaHasDICE {
		extension, err := CreateUeidExtension(testUeid)
		require.NoError(t, err)
		ecaTemplate.ExtraExtensions = append(ecaTemplate.ExtraExtensions, extension)
	}
	if config.rawECATcb != nil {
		ecaTemplate.ExtraExtensions = append(ecaTemplate.ExtraExtensions, pkix.Extension{
			Id: OIDTcbInfo, Critical: true, Value: config.rawECATcb,
		})
	}
	eca := signCertificate(t, ecaTemplate, root, rootKey, ecaKey.Public())

	leafKey := config.leafKey
	if leafKey == nil {
		leafKey = mustP256(t)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "Test DICE Alias"},
		NotBefore:             config.notBefore,
		NotAfter:              config.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    config.leafSigAlg,
	}
	switch {
	case config.rawTcbInfo != nil:
		leafTemplate.ExtraExtensions = append(leafTemplate.ExtraExtensions, pkix.Extension{
			Id: OIDTcbInfo, Critical: true, Value: config.rawTcbInfo,
		})
	case !config.omitTcbInfo:
		extension, err := CreateTcbInfoExtension(config.tcbInfo)
		require.NoError(t, err)
		leafTemplate.ExtraExtensions = append(leafTemplate.ExtraExtensions, extension)
	}
	switch {
	case config.rawUccs != nil:
		leafTemplate.ExtraExtensions = append(leafTemplate.ExtraExtensions, pkix.Extension{
			Id: OIDUccsEvidence, Critical: true, Value: config.rawUccs,
		})
	case !config.omitUccs:
		extension, err := CreateUccsEvidenceExtension(&ClaimsSet{Nonce: config.nonce, Other: config.claimsOther})
		require.NoError(t, err)
		leafTemplate.ExtraExtensions = append(leafTemplate.ExtraExtensions, extension)
	}
	if !config.omitUeid {
		extension, err := CreateUeidExtension(config.ueid)
		require.NoError(t, err)
		leafTemplate.ExtraExtensions = append(leafTemplate.ExtraExtensions, extension)
	}
	leaf := signCertificate(t, leafTemplate, eca, ecaKey, leafKey.Public())

	roots := x509.NewCertPool()
	roots.AddCert(root)

	return &testChain{root: root, eca: eca, leaf: leaf, roots: roots}
}

// signCertificate creates and re-parses one certificate. Re-parsing matters:
// it is what populates UnhandledCriticalExtensions, which is the field the
// critical-TcbInfo workaround exists for.
func signCertificate(
	t *testing.T,
	template, parent *x509.Certificate,
	signer crypto.Signer,
	public crypto.PublicKey,
) *x509.Certificate {
	t.Helper()

	issuer := parent
	if issuer == nil {
		issuer = template
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer, public, signer)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// defaultOptions are the verification options the happy-path tests use.
func defaultOptions(chain *testChain) *VerifyOptions {
	return &VerifyOptions{
		TrustedRoots:  chain.roots,
		ExpectedNonce: testNonce,
	}
}

func TestVerifyAcceptsAWellFormedChain(t *testing.T) {
	chain := newTestChain(t)

	evidence, err := Verify(chain.certs(), defaultOptions(chain))
	require.NoError(t, err)
	require.NotNil(t, evidence)

	assert.Equal(t, "Automate The Things", evidence.TcbInfo.Vendor)
	assert.Equal(t, "AVR-DICE", evidence.TcbInfo.Model)
	require.NotNil(t, evidence.TcbInfo.Layer)
	assert.Equal(t, 0, *evidence.TcbInfo.Layer)
	assert.Equal(t, testUeid, evidence.Ueid)
	assert.False(t, evidence.Flags.Any(), "an absent flags field means no state is active")

	require.NotNil(t, evidence.Claims, "the claims set the nonce was read from is reported")
	assert.Equal(t, testNonce, evidence.Claims.Nonce)
}

func TestVerifyRejectsBadInput(t *testing.T) {
	chain := newTestChain(t)

	tests := []struct {
		name  string
		chain []*x509.Certificate
		opts  *VerifyOptions
		want  error
	}{
		{
			name:  "nil options",
			chain: chain.certs(),
			opts:  nil,
			want:  ErrNilVerifyOptions,
		},
		{
			name:  "empty chain",
			chain: nil,
			opts:  defaultOptions(chain),
			want:  ErrEmptyChain,
		},
		{
			name:  "nil certificate in the chain",
			chain: []*x509.Certificate{chain.leaf, nil},
			opts:  defaultOptions(chain),
			want:  ErrNilCertificate,
		},
		{
			name:  "no nonce was issued",
			chain: chain.certs(),
			opts:  &VerifyOptions{TrustedRoots: chain.roots},
			want:  ErrNonceRequired,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence, err := Verify(test.chain, test.opts)
			require.Error(t, err)
			assert.ErrorIs(t, err, test.want)
			assert.Nil(t, evidence)
		})
	}
}

// TestVerifyRefusesAReplayedNonce is the freshness contract. The device has no
// clock, so this check is the only thing standing between a live answer and a
// recording of an earlier one.
func TestVerifyRefusesAReplayedNonce(t *testing.T) {
	chain := newTestChain(t)

	options := defaultOptions(chain)
	options.ExpectedNonce = []byte("a different challenge entirely!!")

	evidence, err := Verify(chain.certs(), options)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNonceMismatch)
	assert.Nil(t, evidence)
}

func TestVerifyRefusesANonceOfTheWrongLength(t *testing.T) {
	chain := newTestChain(t)

	options := defaultOptions(chain)
	options.ExpectedNonce = testNonce[:8]

	evidence, err := Verify(chain.certs(), options)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNonceMismatch)
	assert.Nil(t, evidence)
}

// TestVerifyAcceptsAnACMEKeyAuthorizationNonce pins the one place this
// verifier is deliberately more permissive than EAT.
//
// EAT bounds eat_nonce at 8 to 64 bytes. The upper bound is not enforced,
// because the ACME device-attest-01 flow in this repository uses the key
// authorization as the challenge and "<token>.<RFC 7638 thumbprint>" is longer
// than 64 bytes on its own -- a verifier refusing it would be refusing the
// echo of its own challenge. The leniency runs only in the direction that
// makes a nonce harder to guess.
func TestVerifyAcceptsAnACMEKeyAuthorizationNonce(t *testing.T) {
	keyAuth := []byte(
		"tOkEn0123456789abcdefghijklmnopqrstuvwxyzABC." +
			"thUmBpRiNt0123456789abcdefghijklmnopqrstuvw")
	require.Greater(t, len(keyAuth), 64, "the fixture must exceed EAT's ceiling to mean anything")

	chain := newTestChain(t, withNonce(keyAuth))

	options := defaultOptions(chain)
	options.ExpectedNonce = keyAuth

	evidence, err := Verify(chain.certs(), options)
	require.NoError(t, err)
	assert.Equal(t, keyAuth, evidence.Claims.Nonce)
}

// TestVerifyRefusesAGuessableNonce is the lower bound EAT places on a nonce,
// enforced where the claims set is read. A challenge short enough to guess
// establishes no freshness, so evidence carrying one is refused before it is
// compared against anything.
func TestVerifyRefusesAGuessableNonce(t *testing.T) {
	chain := newTestChain(t, withRawUccs(mustDecodeHex(t,
		"300c"+"040a"+vecBadClaimsNonceShort)))

	options := defaultOptions(chain)
	options.ExpectedNonce = testNonce[:7]

	evidence, err := Verify(chain.certs(), options)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNonceClaimLength)
	assert.Nil(t, evidence)
}

// TestVerifyRefusesADeviceThatEchoedNoNonce covers the two ways a device can
// fail to answer: no UCCS extension at all, and an extension whose claims set
// omits the nonce. Both are refused, and each says which happened.
//
// Neither falls back to DiceTcbInfo.vendorInfo. The first case puts a nonce
// there and is still refused, which is the point: a device that echoes the
// challenge in the wrong field must not verify, or moving the challenge to the
// specification's own mechanism bought nothing.
func TestVerifyRefusesADeviceThatEchoedNoNonce(t *testing.T) {
	t.Run("no UCCS extension, and the nonce in vendorInfo instead", func(t *testing.T) {
		chain := newTestChain(t,
			withoutUccs(),
			withTcbInfo(&TcbInfo{Vendor: "Automate The Things", VendorInfo: testNonce}),
		)

		evidence, err := Verify(chain.certs(), defaultOptions(chain))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUccsEvidenceNotFound,
			"vendorInfo is not a fallback for the eat_nonce claim")
		assert.Nil(t, evidence)
	})

	t.Run("a claims set with no eat_nonce claim", func(t *testing.T) {
		chain := newTestChain(t, withRawUccs(mustDecodeHex(t,
			"300f"+"040d"+vecBadClaimsNoNonce)))

		evidence, err := Verify(chain.certs(), defaultOptions(chain))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNonceClaimMissing)
		assert.Nil(t, evidence)
	})
}

// TestVerifyRefusesAClaimsSetItCannotRead pins that malformed UCCS evidence
// reaches the caller as a refusal rather than as a device that simply did not
// answer. The distinction is what an operator needs to tell a broken device
// from a stale one.
func TestVerifyRefusesAClaimsSetItCannotRead(t *testing.T) {
	chain := newTestChain(t, withRawUccs(mustDecodeHex(t, vecBadUccsEmptyOctets)))

	evidence, err := Verify(chain.certs(), defaultOptions(chain))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMalformedUccsEvidence)
	assert.Nil(t, evidence)
}

// TestVerifyRefusesNonP256Keys pins the hardware constraint. The root of trust
// is an ATECC608A, which holds P-256 keys and has no hardware Ed25519; a DICE
// certificate presenting anything else was not produced by that hardware.
func TestVerifyRefusesNonP256Keys(t *testing.T) {
	t.Run("ed25519 leaf", func(t *testing.T) {
		chain := newTestChain(t, withLeafKey(mustEd25519(t)))

		evidence, err := Verify(chain.certs(), defaultOptions(chain))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUnsupportedKeyType)
		assert.Nil(t, evidence)
	})

	t.Run("p-384 leaf", func(t *testing.T) {
		chain := newTestChain(t, withLeafKey(mustP384(t)))

		evidence, err := Verify(chain.certs(), defaultOptions(chain))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUnsupportedKeyType)
		assert.Nil(t, evidence)
	})

	t.Run("device-resident embedded CA on p-384", func(t *testing.T) {
		chain := newTestChain(t, withDICEOnECA(), withECAKey(mustP384(t)))

		evidence, err := Verify(chain.certs(), defaultOptions(chain))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUnsupportedKeyType)
		assert.Nil(t, evidence)
	})
}

// TestVerifyDoesNotConstrainTheIssuingAuthority is the other half of that
// constraint. The manufacturer CA that anchors the device is not the hardware
// root of trust, so there is no reason its key should be held to the device's
// curve -- and holding it there would refuse every deployment whose CA is
// stronger than its devices.
func TestVerifyDoesNotConstrainTheIssuingAuthority(t *testing.T) {
	chain := newTestChain(t, withECAKey(mustP384(t)))

	evidence, err := Verify(chain.certs(), defaultOptions(chain))
	require.NoError(t, err)
	assert.NotNil(t, evidence)
}

func TestVerifyRefusesAnUnanchoredChain(t *testing.T) {
	chain := newTestChain(t)
	other := newTestChain(t)

	options := defaultOptions(chain)
	options.TrustedRoots = other.roots

	evidence, err := Verify(chain.certs(), options)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrChainVerificationFailed)
	assert.Nil(t, evidence)
}

// TestVerifyAnchorsACriticalTcbInfoChain is the regression for the crypto/x509
// interaction. The specification says the TcbInfo extension SHOULD be
// critical, and crypto/x509 refuses any chain carrying a critical extension it
// does not recognise, so a verifier that does not clear the entry cannot
// anchor a spec-conformant DICE chain at all.
func TestVerifyAnchorsACriticalTcbInfoChain(t *testing.T) {
	chain := newTestChain(t)
	require.NotEmpty(t, chain.leaf.UnhandledCriticalExtensions,
		"the fixture is not exercising the critical-extension path")

	_, err := chain.leaf.Verify(x509.VerifyOptions{
		Roots:         chain.roots,
		Intermediates: poolOf(chain.eca),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	require.Error(t, err, "crypto/x509 should refuse the raw chain")
	assert.Contains(t, err.Error(), "unhandled critical extension")

	// Verify handles it, because this package does handle the extension.
	evidence, err := Verify(chain.certs(), defaultOptions(chain))
	require.NoError(t, err)
	assert.NotNil(t, evidence)
}

func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

func TestVerifyRefusesAnExpiredLeaf(t *testing.T) {
	chain := newTestChain(t, withValidity(
		time.Now().Add(-48*time.Hour),
		time.Now().Add(-24*time.Hour),
	))

	evidence, err := Verify(chain.certs(), defaultOptions(chain))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrChainVerificationFailed)
	assert.Nil(t, evidence)
}

// TestVerifyCurrentTimeIsTheVerifiersClockOnly checks that CurrentTime moves
// only the certificate expiry check. It is the verifier's clock; no value the
// device supplies is ever compared against it.
func TestVerifyCurrentTimeIsTheVerifiersClockOnly(t *testing.T) {
	past := time.Now().Add(-48 * time.Hour)
	chain := newTestChain(t, withValidity(past, past.Add(time.Hour)))

	options := defaultOptions(chain)
	options.CurrentTime = past.Add(30 * time.Minute)

	evidence, err := Verify(chain.certs(), options)
	require.NoError(t, err, "a chain valid at the given instant should verify")
	assert.NotNil(t, evidence)
}

// A leaf carrying only UCCS evidence VERIFIES, because r23 section 6.1.4 says
// that extension "MAY be used in addition to or in place of DiceTcbInfoSeq or
// DiceTcbInfo". This used to refuse, which meant the verifier disagreed with
// the only profile a 4 KB-constrained device can mint -- the AVR alias
// certificate emits exactly one extension, because its TBS is a PROGMEM
// template and a second one costs flash the part does not have.
func TestVerifyAcceptsAUccsOnlyLeaf(t *testing.T) {
	chain := newTestChain(t, withoutTcbInfo())

	evidence, err := Verify(chain.certs(), defaultOptions(chain))
	require.NoError(t, err)
	require.NotNil(t, evidence)
	assert.Nil(t, evidence.TcbInfo, "there was none to decode")
	assert.NotNil(t, evidence.Claims, "the nonce still came from the claims set")
}

// But a caller whose policy depends on the operational flags must ask for the
// structure that carries them. "No flags" and "flags say notSecure is clear"
// are different facts, and a UCCS-only certificate states the first while
// looking like the second.
func TestVerifyRefusesAUccsOnlyLeafWhenTcbInfoIsRequired(t *testing.T) {
	chain := newTestChain(t, withoutTcbInfo())

	options := defaultOptions(chain)
	options.RequireTcbInfo = true

	evidence, err := Verify(chain.certs(), options)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTcbInfoNotFound)
	assert.Nil(t, evidence)
}

// RequireMeasurement implies it: a measurement cannot be demanded from a
// structure that is allowed to be absent, and reaching the FWID check with a
// nil TcbInfo would panic rather than refuse.
func TestVerifyRequireMeasurementImpliesRequireTcbInfo(t *testing.T) {
	chain := newTestChain(t, withoutTcbInfo())

	options := defaultOptions(chain)
	options.RequireMeasurement = true

	_, err := Verify(chain.certs(), options)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTcbInfoNotFound)
}

func TestVerifyRefusesMalformedEvidence(t *testing.T) {
	chain := newTestChain(t, withRawTcbInfo(mustDecodeHex(t, vecBadFiveFlagBits)))

	evidence, err := Verify(chain.certs(), defaultOptions(chain))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnknownOperationalFlag)
	assert.Nil(t, evidence)
}

func TestVerifyRefusesOperationalStatesTheVerifierDoesNotPermit(t *testing.T) {
	tests := []struct {
		name      string
		reported  OperationalFlags
		permitted OperationalFlags
		accepted  bool
	}{
		{
			name:     "notSecure is refused by default",
			reported: OperationalFlags{NotSecure: true},
			accepted: false,
		},
		{
			name:     "debug is refused by default",
			reported: OperationalFlags{Debug: true},
			accepted: false,
		},
		{
			name:     "recovery is refused by default",
			reported: OperationalFlags{Recovery: true},
			accepted: false,
		},
		{
			name:     "notConfigured is refused by default",
			reported: OperationalFlags{NotConfigured: true},
			accepted: false,
		},
		{
			name:      "an operator may permit a software-only tier explicitly",
			reported:  OperationalFlags{NotSecure: true},
			permitted: OperationalFlags{NotSecure: true},
			accepted:  true,
		},
		{
			name:      "permitting one state does not permit another",
			reported:  OperationalFlags{NotSecure: true, Debug: true},
			permitted: OperationalFlags{NotSecure: true},
			accepted:  false,
		},
		{
			name:      "a device in no declared state is accepted",
			reported:  OperationalFlags{},
			permitted: OperationalFlags{},
			accepted:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			flags := test.reported
			chain := newTestChain(t, withTcbInfo(&TcbInfo{
				Vendor:     "Automate The Things",
				Flags:      &flags,
				VendorInfo: testNonce,
			}))

			options := defaultOptions(chain)
			options.PermittedFlags = test.permitted

			evidence, err := Verify(chain.certs(), options)
			if test.accepted {
				require.NoError(t, err)
				require.NotNil(t, evidence)
				assert.Equal(t, test.reported, evidence.Flags)
				return
			}
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrOperationalStateNotPermitted)
			assert.Nil(t, evidence)
		})
	}
}

func TestVerifyUeidHandling(t *testing.T) {
	t.Run("reports the ueid when the leaf carries one", func(t *testing.T) {
		chain := newTestChain(t)

		evidence, err := Verify(chain.certs(), defaultOptions(chain))
		require.NoError(t, err)
		assert.Equal(t, testUeid, evidence.Ueid)
	})

	t.Run("reports no ueid when none is carried or required", func(t *testing.T) {
		chain := newTestChain(t, withoutUeid())

		evidence, err := Verify(chain.certs(), defaultOptions(chain))
		require.NoError(t, err)
		assert.Nil(t, evidence.Ueid)
	})

	t.Run("reports the ueid a leaf states as a claim", func(t *testing.T) {
		claimUeid := append([]byte{0x01}, testUeid...)
		chain := newTestChain(t, withoutUeid(), withClaim(ClaimUeid, ueidClaim(claimUeid)))

		options := defaultOptions(chain)
		options.ExpectedUeid = claimUeid

		evidence, err := Verify(chain.certs(), options)
		require.NoError(t, err)
		assert.Equal(t, claimUeid, evidence.Ueid)
	})

	t.Run("refuses a leaf whose extension and claim disagree", func(t *testing.T) {
		chain := newTestChain(t, withClaim(ClaimUeid, ueidClaim([]byte{1, 2, 3})))

		evidence, err := Verify(chain.certs(), defaultOptions(chain))
		require.ErrorIs(t, err, ErrUeidConflict)
		assert.Nil(t, evidence)
	})

	t.Run("refuses a missing ueid when one is required", func(t *testing.T) {
		chain := newTestChain(t, withoutUeid())

		options := defaultOptions(chain)
		options.RequireUeid = true

		evidence, err := Verify(chain.certs(), options)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUeidNotFound)
		assert.Nil(t, evidence)
	})

	t.Run("accepts the expected ueid", func(t *testing.T) {
		chain := newTestChain(t)

		options := defaultOptions(chain)
		options.ExpectedUeid = testUeid

		evidence, err := Verify(chain.certs(), options)
		require.NoError(t, err)
		assert.Equal(t, testUeid, evidence.Ueid)
	})

	t.Run("refuses a different device", func(t *testing.T) {
		chain := newTestChain(t, withUeid([]byte{9, 9, 9, 9}))

		options := defaultOptions(chain)
		options.ExpectedUeid = testUeid

		evidence, err := Verify(chain.certs(), options)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUeidMismatch)
		assert.Nil(t, evidence)
	})

	t.Run("refuses a ueid of the wrong length", func(t *testing.T) {
		chain := newTestChain(t, withUeid(testUeid[:4]))

		options := defaultOptions(chain)
		options.ExpectedUeid = testUeid

		evidence, err := Verify(chain.certs(), options)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUeidMismatch)
		assert.Nil(t, evidence)
	})
}

func TestVerifyMeasurementRequirement(t *testing.T) {
	t.Run("accepts a leaf that measured its firmware", func(t *testing.T) {
		chain := newTestChain(t)

		options := defaultOptions(chain)
		options.RequireMeasurement = true

		evidence, err := Verify(chain.certs(), options)
		require.NoError(t, err)
		assert.Len(t, evidence.TcbInfo.FWIDs, 1)
	})

	t.Run("refuses an identity with no measurement behind it", func(t *testing.T) {
		chain := newTestChain(t, withTcbInfo(&TcbInfo{
			Vendor:     "Automate The Things",
			VendorInfo: testNonce,
		}))

		options := defaultOptions(chain)
		options.RequireMeasurement = true

		evidence, err := Verify(chain.certs(), options)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNoMeasurement)
		assert.Nil(t, evidence)
	})
}

// TestVerifyWithoutTrustedRootsStillChecksEverythingElse documents what a nil
// TrustedRoots means: anchoring is the caller's business, and every other
// check still runs.
func TestVerifyWithoutTrustedRootsStillChecksEverythingElse(t *testing.T) {
	chain := newTestChain(t)

	evidence, err := Verify(chain.certs(), &VerifyOptions{ExpectedNonce: testNonce})
	require.NoError(t, err)
	assert.NotNil(t, evidence)

	// The nonce is still checked.
	evidence, err = Verify(chain.certs(), &VerifyOptions{ExpectedNonce: []byte("wrong")})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNonceMismatch)
	assert.Nil(t, evidence)
}

func TestVerifySingleCertificateChain(t *testing.T) {
	// A leaf on its own, with no anchoring requested. This is the shape a
	// caller uses when it has established trust by another route.
	chain := newTestChain(t)

	evidence, err := Verify([]*x509.Certificate{chain.leaf}, &VerifyOptions{
		ExpectedNonce: testNonce,
	})
	require.NoError(t, err)
	assert.Equal(t, testUeid, evidence.Ueid)
}

// TestVerifyDeviceSignatureRejectsAnyOtherAlgorithm covers the check directly.
// It cannot be reached through a built chain: crypto/x509 picks ECDSA-SHA256
// for a P-256 issuer, so the only way a device-resident key signs with
// anything else is a hand-crafted certificate -- which is exactly the case the
// check exists for.
func TestVerifyDeviceSignatureRejectsAnyOtherAlgorithm(t *testing.T) {
	accepted := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "Alias"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	require.NoError(t, verifyDeviceSignature(accepted))

	for _, algorithm := range []x509.SignatureAlgorithm{
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
		x509.PureEd25519,
		x509.SHA256WithRSA,
	} {
		refused := &x509.Certificate{
			Subject:            pkix.Name{CommonName: "Alias"},
			SignatureAlgorithm: algorithm,
		}
		err := verifyDeviceSignature(refused)
		require.Error(t, err, "%s was accepted", algorithm)
		assert.ErrorIs(t, err, ErrUnsupportedSignatureAlgorithm)
	}
}

// TestDescribeSubjectFallsBackToTheSerial keeps a refusal readable when the
// certificate has no common name, which a DICE alias certificate often does
// not.
func TestDescribeSubjectFallsBackToTheSerial(t *testing.T) {
	named := &x509.Certificate{Subject: pkix.Name{CommonName: "Test DICE Alias"}}
	assert.Equal(t, "Test DICE Alias", describeSubject(named))

	anonymous := &x509.Certificate{SerialNumber: big.NewInt(4242)}
	assert.Equal(t, "with serial 4242", describeSubject(anonymous))
}

// TestVerifyChecksTheSignatureOfWhatADeviceResidentKeySigned confirms the two
// checks land on the two different certificates they belong to.
func TestVerifyChecksTheSignatureOfWhatADeviceResidentKeySigned(t *testing.T) {
	chain := newTestChain(t, withDICEOnECA())

	// The embedded CA is device-resident, so its own key is constrained and
	// the leaf it signed is checked for the hardware's signature algorithm.
	require.True(t, HasExtensions(chain.eca))
	assert.Equal(t, x509.ECDSAWithSHA256, chain.leaf.SignatureAlgorithm)

	evidence, err := Verify(chain.certs(), defaultOptions(chain))
	require.NoError(t, err)
	assert.NotNil(t, evidence)
}

// TestVerifyRefusesAnIntermediateWhoseCriticalEvidenceIsUnreadable is the
// anchoring hole, as a test.
//
// Anchoring clears the DICE OIDs from every certificate's unhandled-critical
// set so crypto/x509 does not refuse a chain for carrying the critical
// TcbInfo the specification asks for. Verify decodes the LEAF's evidence and
// nothing above it, so before this check an intermediate could carry critical
// DICE evidence no verifier on earth can read and still anchor -- with the
// refusal crypto/x509 would have made suppressed by this package on a promise
// it did not keep.
func TestVerifyRefusesAnIntermediateWhoseCriticalEvidenceIsUnreadable(t *testing.T) {
	// A SEQUENCE whose single element is a context tag outside the ten
	// DiceTcbInfo defines: well-formed DER, meaningless as evidence.
	malformed := []byte{0x30, 0x03, 0xBF, 0x7F, 0x00}

	chain := newTestChain(t, withRawECATcbInfo(malformed))
	require.Contains(t, oidStrings(chain.eca.UnhandledCriticalExtensions), OIDTcbInfo.String(),
		"the intermediate must present the extension as critical for this to be the case under test")

	evidence, err := Verify(chain.certs(), defaultOptions(chain))
	require.Error(t, err, "an intermediate carrying unreadable critical DICE evidence anchored")
	assert.ErrorIs(t, err, ErrCriticalEvidenceUnreadable)
	assert.Nil(t, evidence)
}

// The other half of the same rule: readable critical evidence on an
// intermediate is carried, not refused. A check that failed closed on every
// intermediate would be indistinguishable from one that worked.
func TestVerifyAcceptsAnIntermediateWhoseCriticalEvidenceDecodes(t *testing.T) {
	info, err := MarshalTcbInfo(&TcbInfo{
		Vendor: "Automate The Things",
		Model:  "AVR-DICE Embedded CA",
		Layer:  intPtr(1),
	})
	require.NoError(t, err)

	chain := newTestChain(t, withRawECATcbInfo(info))
	evidence, err := Verify(chain.certs(), defaultOptions(chain))
	require.NoError(t, err)
	assert.NotNil(t, evidence)
}

// TestVerifyRequiresADeviceSignedLeafWhenAsked covers the chain shape a
// constrained device actually presents: the alias leaf with its issuer
// ABSENT, because the DeviceID certificate is held by whoever provisioned the
// part rather than by a device with nowhere to keep it.
//
// The signature algorithm is the issuer's property, so verifyDeviceKeys checks
// it on certificates a device-resident key signed -- and with no such issuer
// in the chain there is nothing for it to check. A caller that knows the
// leaf's issuer is the element says so, and then an alias signed with
// ECDSA-SHA384 is refused instead of accepted.
func TestVerifyRequiresADeviceSignedLeafWhenAsked(t *testing.T) {
	chain := newTestChain(t, withLeafSignatureAlgorithm(x509.ECDSAWithSHA384))
	require.Equal(t, x509.ECDSAWithSHA384, chain.leaf.SignatureAlgorithm)
	require.False(t, HasExtensions(chain.eca),
		"the issuer must carry no DICE evidence, or the leaf is checked for another reason")

	// Without the statement there is nothing in the chain that says the leaf's
	// issuer was a device, so the leaf's algorithm is not the verifier's to
	// judge. This is the pre-existing behaviour, pinned so the option's effect
	// is unambiguous.
	evidence, err := Verify(chain.certs(), defaultOptions(chain))
	require.NoError(t, err)
	assert.NotNil(t, evidence)

	opts := defaultOptions(chain)
	opts.RequireDeviceSignedLeaf = true
	evidence, err = Verify(chain.certs(), opts)
	require.Error(t, err, "an alias signed with ECDSA-SHA384 passed a device-signed-leaf profile")
	assert.ErrorIs(t, err, ErrUnsupportedSignatureAlgorithm)
	assert.Nil(t, evidence)

	// And the algorithm the element does perform still passes under the same
	// option, so the option refuses a signature rather than a profile.
	ordinary := newTestChain(t)
	opts = defaultOptions(ordinary)
	opts.RequireDeviceSignedLeaf = true
	evidence, err = Verify(ordinary.certs(), opts)
	require.NoError(t, err)
	assert.NotNil(t, evidence)
}

// oidStrings renders an OID slice for an assertion message.
func oidStrings(oids []asn1.ObjectIdentifier) []string {
	out := make([]string, 0, len(oids))
	for _, oid := range oids {
		out = append(out, oid.String())
	}
	return out
}
