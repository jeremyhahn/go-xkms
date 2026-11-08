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

package avr

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	aggeneric "github.com/jeremyhahn/trusted-firmware/sdk/go"

	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ------------------------------------------------- the bytes a real device emits

// The one test that proves this package verifies the firmware rather than its
// own idea of the firmware: the certificate is the frozen vector
// arduino-generic pins its own C implementation against.
func TestAttestKeyVerifiesTheCertificateARealDeviceEmits(t *testing.T) {
	der, err := hex.DecodeString(vecAliasCertHex)
	require.NoError(t, err)
	nonce, err := hex.DecodeString(vecAliasCertNonceHex)
	require.NoError(t, err)
	require.Len(t, nonce, aggeneric.AliasNonceLen)

	link := secureElementLink().answerAttestCert(der)
	b := newTestBackend(t, link)

	result, err := b.AttestKey(context.Background(), &types.KeyAttributes{CN: DefaultKeyCN}, nonce)
	require.NoError(t, err)

	att, ok := result.(*Attestation)
	require.True(t, ok)
	assert.Equal(t, FormatDICE, att.Format)
	assert.Equal(t, der, att.CertificateDER, "a gateway forwards the device's bytes verbatim")
	assert.Equal(t, nonce, att.Claims.Nonce)
	assert.Equal(t, types.AttestLevelHardware, att.AttestLevel)
	assert.Equal(t, aggeneric.CryptoSecureElement, att.CryptoTier)
	assert.False(t, att.Anchored, "no roots were configured")
	assert.Equal(t, "ag Alias", att.Certificate.Subject.CommonName)

	// The ueid and the firmware measurement travel as CWT claims inside the
	// UCCS extension, not as X.509 extensions, so they reach a caller through
	// Claims.Other as the raw CBOR the device encoded.
	ueid, ok := att.Claims.Other[256]
	require.True(t, ok, "the claims set carries a ueid at CWT key 256")
	assert.Contains(t, hex.EncodeToString(ueid), vecAliasCertUeidHex)
	assert.Contains(t, att.Claims.Other, int64(273), "and a measurement at key 273")
}

// TestCheckAliasCertificate_UnknownCryptoTierFailsSafeAndLogs proves that
// checkAliasCertificate does not silently discard AttestLevel's error for a
// crypto tier this host cannot classify: a cryptographically valid DICE chain
// still comes back with AttestLevel stamped Unattested (the safe direction)
// rather than the whole attestation being refused, and the reason is logged
// rather than lost (go-xkms#1347).
//
// hasDeviceKey already refuses AttestKey for an unclassified tier through the
// public entry point, so this drives checkAliasCertificate directly -- the
// step that runs strictly after the chain is proved genuine -- to pin the
// fallback for any future caller that reaches it without that guard.
func TestCheckAliasCertificate_UnknownCryptoTierFailsSafeAndLogs(t *testing.T) {
	der, err := hex.DecodeString(vecAliasCertHex)
	require.NoError(t, err)
	nonce, err := hex.DecodeString(vecAliasCertNonceHex)
	require.NoError(t, err)

	var buf bytes.Buffer
	b := &Backend{
		logger: slog.New(slog.NewTextHandler(&buf, nil)),
		caps:   aggeneric.Caps{CryptoTier: aggeneric.CryptoTier(9)},
	}

	att, err := b.checkAliasCertificate(der, nonce)
	require.NoError(t, err, "an unclassified crypto tier must not fail an otherwise-valid attestation")
	assert.Equal(t, types.AttestLevelUnattested, att.AttestLevel,
		"the attestation must fail safe to Unattested rather than assume a level")
	assert.Contains(t, buf.String(), "device reports a crypto tier this host cannot classify",
		"AttestLevel's error must be logged instead of discarded")
}

// The device's own certificate must page across the wire and reassemble byte
// for byte: 471 bytes is eight pages of 60, and the last one is short.
func TestAttestKeyReassemblesAPagedCertificate(t *testing.T) {
	der, err := hex.DecodeString(vecAliasCertHex)
	require.NoError(t, err)
	nonce, err := hex.DecodeString(vecAliasCertNonceHex)
	require.NoError(t, err)

	link := secureElementLink().answerAttestCert(der)
	b := newTestBackend(t, link)

	result, err := b.AttestKey(context.Background(), &types.KeyAttributes{CN: DefaultKeyCN}, nonce)
	require.NoError(t, err)

	assert.Len(t, result.(*Attestation).CertificateDER, 471)
	attestRequests := 0
	for _, req := range link.requests {
		if req.Cmd() == aggeneric.CmdAttestCert {
			attestRequests++
		}
	}
	assert.Equal(t, 8, attestRequests, "471 bytes is eight pages of sixty")
}

// ------------------------------------------------------------------ the nonce

// The challenge is SHA-256 of the ACME key authorization, and this package must
// not compute it: deviceattest01.DICENonce is the one place that hashing
// happens, so a device, a provisioning tool and a test cannot each hash
// something slightly different.
func TestAttestKeyTakesTheNonceItIsGivenAndDoesNotHashIt(t *testing.T) {
	const keyAuth = "sometoken.YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5"
	nonce := deviceattest01.DICENonce(keyAuth)
	require.Len(t, nonce, aggeneric.AliasNonceLen)

	device := newAliasDevice(t)
	link := secureElementLink().answerAttestCert(device.mint(t, nonce))
	b := newTestBackend(t, link)

	result, err := b.AttestKey(context.Background(), &types.KeyAttributes{CN: DefaultKeyCN}, nonce)
	require.NoError(t, err)

	// What reached the device is the nonce the caller supplied, unchanged. A
	// backend that hashed again would have sent SHA-256 of the digest.
	var sent []byte
	for _, req := range link.requests {
		if req.Cmd() == aggeneric.CmdAttestCert && len(req.Payload) == aggeneric.AliasNonceLen {
			sent = req.Payload
		}
	}
	assert.Equal(t, nonce, sent)
	assert.Equal(t, nonce, result.(*Attestation).Nonce)
}

// The device's two nonces are different widths on purpose. Sixteen bytes is
// runtime freshness in the evidence frame; a device handed it as an enrolment
// challenge cannot tell it was truncated, so it is refused here.
func TestAttestKeyRefusesTheEvidenceFrameNonceWidth(t *testing.T) {
	link := secureElementLink()
	b := newTestBackend(t, link)
	before := len(link.requests)

	for _, n := range []int{0, aggeneric.AttestNonceLen, 31, 33, 64} {
		_, err := b.AttestKey(context.Background(),
			&types.KeyAttributes{CN: DefaultKeyCN}, make([]byte, n))

		require.ErrorIs(t, err, ErrInvalidNonce, "width %d", n)
		assert.Contains(t, err.Error(), "DICENonce",
			"the message names the function that produces the right value")
	}
	assert.Len(t, link.requests, before, "a wrong width costs no round trip")
}

// The nonce is the only thing separating a live answer from a replayed
// recording, because the device has no clock. A certificate that echoes a
// different challenge is refused, however well formed it is.
func TestAttestKeyRefusesAReplayedCertificate(t *testing.T) {
	device := newAliasDevice(t)
	yesterday := make([]byte, aggeneric.AliasNonceLen)
	yesterday[0] = 0xAA
	today := make([]byte, aggeneric.AliasNonceLen)
	today[0] = 0xBB

	link := secureElementLink().answerAttestCert(device.mint(t, yesterday))
	b := newTestBackend(t, link)

	_, err := b.AttestKey(context.Background(), &types.KeyAttributes{CN: DefaultKeyCN}, today)

	assert.ErrorIs(t, err, dice.ErrNonceMismatch)
}

// A device that put its challenge somewhere other than the eat_nonce claim of
// tcg-dice-UCCS-evidence does not verify on that account. There is no fallback
// to another field.
func TestAttestKeyRefusesACertificateWithNoEvidenceExtension(t *testing.T) {
	device := newAliasDevice(t)
	nonce := make([]byte, aggeneric.AliasNonceLen)

	link := secureElementLink().answerAttestCert(device.mintWithout(t))
	b := newTestBackend(t, link)

	_, err := b.AttestKey(context.Background(), &types.KeyAttributes{CN: DefaultKeyCN}, nonce)

	assert.ErrorIs(t, err, dice.ErrUccsEvidenceNotFound)
}

// -------------------------------------------------------------- device residency

// Device residency is enforced by dice.Verify and tested there. What this
// package still owes is proof that the constraint survives the WHOLE path --
// paged off a device, parsed, and refused -- which is
// TestAttestKeyRefusesANonP256CertificateEndToEnd below. The two unit tests
// that drove the backend's own checkDeviceResident went with the function.
func TestAttestKeyRefusesBytesThatAreNotACertificate(t *testing.T) {
	link := secureElementLink().answerAttestCert([]byte("this is not DER at all, not even close"))
	b := newTestBackend(t, link)

	_, err := b.AttestKey(context.Background(),
		&types.KeyAttributes{CN: DefaultKeyCN}, make([]byte, aggeneric.AliasNonceLen))

	assert.ErrorIs(t, err, ErrMalformedCertificate)
}

// ------------------------------------------------------------------- anchoring

func TestAttestKeyAnchorsAgainstConfiguredRoots(t *testing.T) {
	device := newAliasDevice(t)
	nonce := make([]byte, aggeneric.AliasNonceLen)
	nonce[0] = 0x7F

	link := secureElementLink().answerAttestCert(device.mint(t, nonce))
	b := newAnchoredBackend(t, link, device)

	result, err := b.AttestKey(context.Background(), &types.KeyAttributes{CN: DefaultKeyCN}, nonce)
	require.NoError(t, err)

	assert.True(t, result.(*Attestation).Anchored)
}

// A certificate from a device the operator never enrolled is refused, not
// returned with Anchored false. Anchored false means no roots were configured;
// it never means anchoring ran and did not hold.
func TestAttestKeyRefusesACertificateFromAnUnknownIssuer(t *testing.T) {
	stranger := newAliasDevice(t)
	ours := newAliasDevice(t)
	nonce := make([]byte, aggeneric.AliasNonceLen)

	link := secureElementLink().answerAttestCert(stranger.mint(t, nonce))
	b := newAnchoredBackend(t, link, ours)

	_, err := b.AttestKey(context.Background(), &types.KeyAttributes{CN: DefaultKeyCN}, nonce)

	assert.ErrorIs(t, err, dice.ErrChainVerificationFailed)
}

func TestInitAttestationRefusesATrustStoreItCannotLoad(t *testing.T) {
	cfg := testConfig()
	cfg.Attestation = &AttestationConfig{
		TrustStore: &truststore.Config{ExternalRootPaths: []string{
			filepath.Join(t.TempDir(), "there-is-no-such-file.pem"),
		}},
	}

	_, err := NewBackend(context.Background(), cfg, newTestDevice(secureElementLink()))

	assert.ErrorIs(t, err, ErrTrustStoreInit)
}

func TestInitAttestationRefusesAnUnparseableIntermediate(t *testing.T) {
	cfg := testConfig()
	cfg.Attestation = &AttestationConfig{Intermediates: [][]byte{[]byte("not a certificate")}}

	_, err := NewBackend(context.Background(), cfg, newTestDevice(secureElementLink()))

	require.ErrorIs(t, err, ErrTrustStoreInit)
	assert.Contains(t, err.Error(), "intermediate 0")
}

// ------------------------------------------------------------- the device refuses

// A software-tier device knows exactly what a certificate is and has no public
// half to certify, so it answers "unsupported" -- which is a DIFFERENT fact
// from "unknown command", and the difference tells an operator whether to
// change the build or change the part.
func TestAttestKeySurfacesASoftwareTierDeviceAsUnsupported(t *testing.T) {
	link := newFakeLink().answer(aggeneric.CmdCaps,
		capsPayload(aggeneric.CryptoSoftware, aggeneric.FeatureAttest, aggeneric.AlgECDSAP256SHA256))
	link.refuse(aggeneric.CmdAttestCert, aggeneric.StatusErrUnsupported)
	b := newTestBackend(t, link)

	_, err := b.AttestKey(context.Background(),
		&types.KeyAttributes{CN: DefaultKeyCN}, make([]byte, aggeneric.AliasNonceLen))

	require.ErrorIs(t, err, ErrUnsupportedByDevice)
	assert.NotErrorIs(t, err, ErrCommandUnavailable)
}

func TestAttestKeyReportsAFirmwareWithoutTheCommand(t *testing.T) {
	link := secureElementLink() // no ATTEST_CERT entry: answered ErrUnknownCmd
	b := newTestBackend(t, link)

	_, err := b.AttestKey(context.Background(),
		&types.KeyAttributes{CN: DefaultKeyCN}, make([]byte, aggeneric.AliasNonceLen))

	assert.ErrorIs(t, err, ErrCommandUnavailable)
}

func TestAttestKeyReportsAnUnprovisionedDevice(t *testing.T) {
	link := secureElementLink().refuse(aggeneric.CmdAttestCert, aggeneric.StatusErrNotProvisioned)
	b := newTestBackend(t, link)

	_, err := b.AttestKey(context.Background(),
		&types.KeyAttributes{CN: DefaultKeyCN}, make([]byte, aggeneric.AliasNonceLen))

	assert.ErrorIs(t, err, ErrNotProvisioned)
}

// ------------------------------------------------------------------- guard rails

func TestAttestKeyRefusesTheCallsItCannotAnswer(t *testing.T) {
	link := secureElementLink()
	b := newTestBackend(t, link)
	ctx := context.Background()
	nonce := make([]byte, aggeneric.AliasNonceLen)
	before := len(link.requests)

	_, err := b.AttestKey(ctx, nil, nonce)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)

	_, err = b.AttestKey(ctx, &types.KeyAttributes{CN: "not-this-device"}, nonce)
	assert.ErrorIs(t, err, ErrUnknownKey)

	assert.Len(t, link.requests, before)

	require.NoError(t, b.Close())
	_, err = b.AttestKey(ctx, &types.KeyAttributes{CN: DefaultKeyCN}, nonce)
	assert.ErrorIs(t, err, ErrBackendClosed)
}

// A device with no crypto provider has no identity to attest to, so nothing is
// asked of it.
func TestAttestKeyRefusesWhenTheDeviceHasNoProvider(t *testing.T) {
	link := newFakeLink().answer(aggeneric.CmdCaps, capsPayload(aggeneric.CryptoNone, 0, 0))
	b := newTestBackend(t, link)
	before := len(link.requests)

	_, err := b.AttestKey(context.Background(),
		&types.KeyAttributes{CN: DefaultKeyCN}, make([]byte, aggeneric.AliasNonceLen))

	assert.ErrorIs(t, err, ErrNoDeviceKey)
	assert.Len(t, link.requests, before)
}

func TestCapabilitiesNowClaimAttestation(t *testing.T) {
	b := newTestBackend(t, secureElementLink())

	assert.True(t, b.Capabilities().Attestation)

	var _ types.AttestingKeyProvider = b
}

// ------------------------------------------------------------------- test device

// aliasDevice mints alias certificates the way the firmware does: a DeviceID
// key that signs, and a leaf carrying exactly one extension --
// tcg-dice-UCCS-evidence, critical. It emits NO DiceTcbInfo and NO
// tcg-dice-Ueid, because the AVR profile does not: the ueid and the firmware
// measurement travel as CWT claims inside the evidence extension, since the
// certificate is assembled on an 8-bit part from a 230-byte template and every
// extra extension costs flash it does not have.
type aliasDevice struct {
	deviceID     *ecdsa.PrivateKey
	deviceIDCert *x509.Certificate
	deviceIDDER  []byte

	// The manufacturer root the DeviceID certificate descends from. Three
	// levels rather than two because that is the real shape: an operator
	// anchors on the manufacturer, and the DeviceID certificate in between is
	// supplied by configuration since the device has nowhere to keep it.
	rootDER []byte
}

func newAliasDevice(t *testing.T) *aliasDevice {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ag Manufacturer Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "ag DeviceID"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &aliasDevice{deviceID: key, deviceIDCert: cert, deviceIDDER: der, rootDER: rootDER}
}

// mint produces an alias certificate carrying the challenge.
func (d *aliasDevice) mint(t *testing.T, nonce []byte) []byte {
	t.Helper()
	ext, err := dice.CreateUccsEvidenceExtension(&dice.ClaimsSet{Nonce: nonce})
	require.NoError(t, err)
	return d.sign(t, []pkix.Extension{ext})
}

// mintWithout produces one with no evidence extension at all.
func (d *aliasDevice) mintWithout(t *testing.T) []byte {
	t.Helper()
	return d.sign(t, nil)
}

// mintSignedWith produces an alias certificate signed with an algorithm other
// than the ECDSA-SHA256 the element performs. The DeviceID key still signs it,
// so this is the certificate a host would see if the signing side ever changed
// algorithm -- not a forgery from elsewhere.
func (d *aliasDevice) mintSignedWith(t *testing.T, nonce []byte, alg x509.SignatureAlgorithm) []byte {
	t.Helper()
	ext, err := dice.CreateUccsEvidenceExtension(&dice.ClaimsSet{Nonce: nonce})
	require.NoError(t, err)

	alias, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(3),
		Subject:            pkix.Name{CommonName: "ag Alias"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		ExtraExtensions:    []pkix.Extension{ext},
		SignatureAlgorithm: alg,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, d.deviceIDCert, &alias.PublicKey, d.deviceID)
	require.NoError(t, err)
	return der
}

// mintOnCurve produces one whose subject key is on some other curve, which the
// element could not have generated.
func (d *aliasDevice) mintOnCurve(t *testing.T, nonce []byte, curve elliptic.Curve) []byte {
	t.Helper()
	ext, err := dice.CreateUccsEvidenceExtension(&dice.ClaimsSet{Nonce: nonce})
	require.NoError(t, err)
	return d.signOn(t, []pkix.Extension{ext}, curve)
}

func (d *aliasDevice) sign(t *testing.T, extensions []pkix.Extension) []byte {
	t.Helper()
	return d.signOn(t, extensions, elliptic.P256())
}

func (d *aliasDevice) signOn(t *testing.T, extensions []pkix.Extension, curve elliptic.Curve) []byte {
	t.Helper()
	alias, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(3),
		Subject:         pkix.Name{CommonName: "ag Alias"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		ExtraExtensions: extensions,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, d.deviceIDCert, &alias.PublicKey, d.deviceID)
	require.NoError(t, err)
	return der
}

// newAnchoredBackend attaches a backend anchored on this device's manufacturer
// root, with the DeviceID certificate supplied as an intermediate.
//
// The root goes to a file because that is the configuration path an operator
// uses. t.TempDir removes it, so the checkout is as clean after the test as
// before -- a run that left a file behind would fail CI on a dirty tree.
func newAnchoredBackend(t *testing.T, link *fakeLink, device *aliasDevice) *Backend {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manufacturer-root.pem")
	require.NoError(t, os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: device.rootDER}), 0o600))

	cfg := testConfig()
	cfg.Attestation = &AttestationConfig{
		TrustStore:    &truststore.Config{ExternalRootPaths: []string{path}},
		Intermediates: [][]byte{device.deviceIDDER},
	}

	b, err := NewBackend(context.Background(), cfg, newTestDevice(link))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })
	return b
}

// The residency check runs on the path a device actually takes, not only when
// called directly: a certificate that is well formed, correctly anchored and on
// the wrong curve must still be refused.
func TestAttestKeyRefusesANonP256CertificateEndToEnd(t *testing.T) {
	device := newAliasDevice(t)
	nonce := make([]byte, aggeneric.AliasNonceLen)

	// Signed by the P-256 DeviceID key, so the signature algorithm is the one
	// the element makes and only the SUBJECT key is wrong. Otherwise the
	// signature check fires first and the curve check is never reached.
	link := secureElementLink().answerAttestCert(device.mintOnCurve(t, nonce, elliptic.P384()))
	b := newTestBackend(t, link)

	_, err := b.AttestKey(context.Background(), &types.KeyAttributes{CN: DefaultKeyCN}, nonce)

	require.ErrorIs(t, err, dice.ErrUnsupportedKeyType)
	assert.Contains(t, err.Error(), "P-384")
}

// Intermediates are parsed once at construction rather than per attestation. A
// backend that deferred it would discover a bad configuration in front of a
// device waiting to enrol.
func TestInitAttestationLoadsIntermediatesWithoutATrustStore(t *testing.T) {
	device := newAliasDevice(t)
	cfg := testConfig()
	cfg.Attestation = &AttestationConfig{Intermediates: [][]byte{device.deviceIDDER}}

	b, err := NewBackend(context.Background(), cfg, newTestDevice(secureElementLink()))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })

	// No roots, so nothing anchors -- and Anchored says so rather than the
	// intermediates standing in for an anchor.
	nonce := make([]byte, aggeneric.AliasNonceLen)
	link := secureElementLink().answerAttestCert(device.mint(t, nonce))
	b2, err := NewBackend(context.Background(), cfg, newTestDevice(link))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b2.Close()) })

	result, err := b2.AttestKey(context.Background(), &types.KeyAttributes{CN: DefaultKeyCN}, nonce)
	require.NoError(t, err)
	assert.False(t, result.(*Attestation).Anchored)
}

// The disagreement this used to pin is closed. dice.Verify demanded a
// DiceTcbInfo extension that the AVR alias profile does not carry, so the
// backend open-coded the checks instead; r23 section 6.1.4 says UCCS "MAY be
// used in addition to or in place of DiceTcbInfoSeq or DiceTcbInfo", so the
// verifier was wrong rather than the device. This asserts the fix, because a
// regression there would silently send the backend back to a long way round
// that no longer exists.
func TestDiceVerifyAcceptsTheProfileTheDeviceEmits(t *testing.T) {
	der, err := hex.DecodeString(vecAliasCertHex)
	require.NoError(t, err)
	nonce, err := hex.DecodeString(vecAliasCertNonceHex)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	// No TrustedRoots: this asserts the EVIDENCE contract, not anchoring. The
	// certificate is self-signed by the device's own DeviceID key, which is
	// what the AVR profile produces.
	evidence, err := dice.Verify([]*x509.Certificate{leaf}, &dice.VerifyOptions{
		ExpectedNonce: nonce,
	})
	require.NoError(t, err, "a UCCS-only leaf is conforming and must verify")
	require.NotNil(t, evidence)
	assert.Nil(t, evidence.TcbInfo, "the AVR profile carries no DiceTcbInfo")
	require.NotNil(t, evidence.Claims)
	assert.Equal(t, nonce, evidence.Claims.Nonce)
}

// TestAttestKeyRefusesAnAliasThatIsNotECDSASHA256Signed covers what this
// backend promises about the certificates it accepts.
//
// The signature algorithm belongs to the ISSUER, so dice.Verify checks it on
// certificates a device-resident key signed -- and in both chain shapes this
// backend ever sees there is no such certificate to check it on. The ordinary
// chain is the alias leaf alone; the anchored chain adds a DeviceID
// certificate that carries no DICE extension of its own and is therefore not
// classified as device-resident. Without the profile saying that the leaf's
// issuer IS the element, an alias signed with ECDSA-SHA384 verified against a
// backend whose documentation promises the one algorithm the part emits.
func TestAttestKeyRefusesAnAliasThatIsNotECDSASHA256Signed(t *testing.T) {
	device := newAliasDevice(t)
	nonce := bytes.Repeat([]byte{0x31}, aggeneric.AliasNonceLen)
	der := device.mintSignedWith(t, nonce, x509.ECDSAWithSHA384)

	// Both shapes, because each reaches dice.Verify with a different chain and
	// neither of them carries a device-resident issuer.
	t.Run("unanchored", func(t *testing.T) {
		b := newTestBackend(t, secureElementLink().answerAttestCert(der))
		_, err := b.AttestKey(context.Background(), &types.KeyAttributes{CN: DefaultKeyCN}, nonce)
		require.Error(t, err, "an alias signed with ECDSA-SHA384 was accepted")
		assert.ErrorIs(t, err, dice.ErrUnsupportedSignatureAlgorithm)
	})

	t.Run("anchored", func(t *testing.T) {
		require.False(t, dice.HasExtensions(device.deviceIDCert),
			"the DeviceID certificate must carry no DICE evidence, or it is checked for another reason")

		b := newAnchoredBackend(t, secureElementLink().answerAttestCert(der), device)
		_, err := b.AttestKey(context.Background(), &types.KeyAttributes{CN: DefaultKeyCN}, nonce)
		require.Error(t, err, "an alias signed with ECDSA-SHA384 was accepted")
		assert.ErrorIs(t, err, dice.ErrUnsupportedSignatureAlgorithm)
	})

	// And the algorithm the element does emit still passes, so what is refused
	// is a signature and not the profile.
	b := newTestBackend(t, secureElementLink().answerAttestCert(device.mint(t, nonce)))
	_, err := b.AttestKey(context.Background(), &types.KeyAttributes{CN: DefaultKeyCN}, nonce)
	require.NoError(t, err)
}
