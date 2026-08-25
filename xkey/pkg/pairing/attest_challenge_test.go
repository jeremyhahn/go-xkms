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

package pairing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests pin the #129 wire contract at the byte level. They exist
// separately from the CLI's pairing tests because this is the half xkey-android
// must reproduce in Kotlin: every constant, offset and length prefix here is
// something a second implementation has to get exactly right, and the vectors
// published on the issue are generated from these same rules.

// fixed returns n bytes of b, so a transcript failure names which field moved
// rather than showing two walls of random hex.
func fixed(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func validTranscriptInputs() (purpose string, nonce, binding, fingerprint []byte) {
	return AttestPurposePair, fixed(0x01, AttestNonceSize),
		fixed(0x02, AttestChannelBindingSize), fixed(0x03, AttestFingerprintSize)
}

// TestBuildAttestTranscriptLaysOutTheContract pins the exact bytes.
//
// The assertion is on the layout, field by field at its stated offset, rather
// than on a golden hash: a golden hash tells a second implementer that
// something is wrong and nothing about where, and the whole point of this
// contract is that someone is writing the other half of it from the spec.
func TestBuildAttestTranscriptLaysOutTheContract(t *testing.T) {
	purpose, nonce, binding, fingerprint := validTranscriptInputs()

	transcript, err := BuildAttestTranscript(purpose, nonce, binding, fingerprint)
	require.NoError(t, err)

	domainLen := len(AttestTranscriptDomain)
	require.Equal(t, domainLen+1+len(purpose)+96, len(transcript),
		"domain || len8(purpose) || purpose || nonce(32) || binding(32) || fingerprint(32)")

	at := 0
	assert.Equal(t, AttestTranscriptDomain, string(transcript[at:at+domainLen]), "domain prefix")
	at += domainLen

	assert.Equal(t, byte(len(purpose)), transcript[at], "one-byte purpose length prefix")
	at++

	assert.Equal(t, purpose, string(transcript[at:at+len(purpose)]), "purpose")
	at += len(purpose)

	assert.Equal(t, nonce, transcript[at:at+AttestNonceSize], "nonce")
	at += AttestNonceSize

	assert.Equal(t, binding, transcript[at:at+AttestChannelBindingSize], "channel binding")
	at += AttestChannelBindingSize

	assert.Equal(t, fingerprint, transcript[at:at+AttestFingerprintSize], "device fingerprint")
}

// TestBuildAttestTranscriptSeparatesEveryInput is the property the layout
// exists for: no two distinct sets of inputs may produce the same bytes.
//
// Without it a signature obtained for one exchange verifies for another, which
// is the whole class of attack the nonce, the purpose and the binding are
// there to prevent.
func TestBuildAttestTranscriptSeparatesEveryInput(t *testing.T) {
	purpose, nonce, binding, fingerprint := validTranscriptInputs()

	base, err := BuildAttestTranscript(purpose, nonce, binding, fingerprint)
	require.NoError(t, err)

	variants := map[string]struct {
		purpose                     string
		nonce, binding, fingerprint []byte
	}{
		"a different purpose":     {AttestPurposeReattest, nonce, binding, fingerprint},
		"a different nonce":       {purpose, fixed(0xf1, AttestNonceSize), binding, fingerprint},
		"a different binding":     {purpose, nonce, fixed(0xf2, AttestChannelBindingSize), fingerprint},
		"a different fingerprint": {purpose, nonce, binding, fixed(0xf3, AttestFingerprintSize)},
	}

	for name, v := range variants {
		t.Run(name, func(t *testing.T) {
			other, err := BuildAttestTranscript(v.purpose, v.nonce, v.binding, v.fingerprint)
			require.NoError(t, err)
			assert.NotEqual(t, base, other,
				"changing one input must change the transcript, or a signature moves between exchanges")
		})
	}
}

// TestBuildAttestTranscriptLengthPrefixIsNotDecorative shows what the purpose
// length prefix buys.
//
// Concatenating purpose directly ahead of a fixed-width nonce would let a
// longer purpose eat the nonce's first bytes: ("pair", 0xAA…) and ("pairª",
// 0xAA… shifted) would serialize identically. The prefix makes the split
// unambiguous, so these two must differ.
func TestBuildAttestTranscriptLengthPrefixIsNotDecorative(t *testing.T) {
	_, nonce, binding, fingerprint := validTranscriptInputs()

	short, err := BuildAttestTranscript("pair", nonce, binding, fingerprint)
	require.NoError(t, err)

	// The same bytes, one shifted from the purpose into the nonce.
	shiftedNonce := append([]byte{'X'}, nonce[:AttestNonceSize-1]...)
	long, err := BuildAttestTranscript("pairX", shiftedNonce, binding, fingerprint)
	require.NoError(t, err)

	assert.NotEqual(t, short, long,
		"an unprefixed concatenation would make these two the same byte string")
}

// TestBuildAttestTranscriptRefusesMalformedInputs covers the refusals.
//
// A short input must not produce a shorter transcript both sides could still
// agree on: that would be a working protocol with a weaker binding than the
// one documented, and nothing would report it.
func TestBuildAttestTranscriptRefusesMalformedInputs(t *testing.T) {
	purpose, nonce, binding, fingerprint := validTranscriptInputs()

	cases := map[string]struct {
		purpose                     string
		nonce, binding, fingerprint []byte
		wantErr                     error
	}{
		"empty purpose":     {"", nonce, binding, fingerprint, ErrAttestPurpose},
		"short nonce":       {purpose, fixed(0x01, 16), binding, fingerprint, ErrAttestTranscriptField},
		"long nonce":        {purpose, fixed(0x01, 33), binding, fingerprint, ErrAttestTranscriptField},
		"nil nonce":         {purpose, nil, binding, fingerprint, ErrAttestTranscriptField},
		"short binding":     {purpose, nonce, fixed(0x02, 31), fingerprint, ErrAttestTranscriptField},
		"nil binding":       {purpose, nonce, nil, fingerprint, ErrAttestTranscriptField},
		"short fingerprint": {purpose, nonce, binding, fixed(0x03, 20), ErrAttestTranscriptField},
		"nil fingerprint":   {purpose, nonce, binding, nil, ErrAttestTranscriptField},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			transcript, err := BuildAttestTranscript(tc.purpose, tc.nonce, tc.binding, tc.fingerprint)
			require.Error(t, err)
			require.ErrorIs(t, err, tc.wantErr)
			assert.Nil(t, transcript, "a refused transcript must not be signable")
		})
	}
}

// TestComputeAttestChannelBindingIsOrderedAndSeparated pins the anti-relay
// value.
//
// Two properties matter and both are easy to lose. The keys go in
// initiator-then-responder order, which is the only ordering both ends can
// agree on without further negotiation — "mine then theirs" gives the two ends
// different values and every connection fails. And the prologue is
// length-prefixed, so the first-pairing case (no prologue) cannot collide with
// a reconnect.
func TestComputeAttestChannelBindingIsOrderedAndSeparated(t *testing.T) {
	initiator := fixed(0x11, AttestStaticKeySize)
	responder := fixed(0x22, AttestStaticKeySize)
	prologue := fixed(0x33, 32)

	base, err := ComputeAttestChannelBinding(initiator, responder, prologue)
	require.NoError(t, err)
	require.Len(t, base, AttestChannelBindingSize)

	swapped, err := ComputeAttestChannelBinding(responder, initiator, prologue)
	require.NoError(t, err)
	assert.NotEqual(t, base, swapped, "the key order must matter, or the two ends can disagree silently")

	noPrologue, err := ComputeAttestChannelBinding(initiator, responder, nil)
	require.NoError(t, err)
	assert.NotEqual(t, base, noPrologue, "a first pairing must not share a binding with a reconnect")

	otherPrologue, err := ComputeAttestChannelBinding(initiator, responder, fixed(0x44, 32))
	require.NoError(t, err)
	assert.NotEqual(t, base, otherPrologue)

	// Same inputs, same value: the binding has to be reproducible or the peer
	// cannot compute it independently.
	again, err := ComputeAttestChannelBinding(initiator, responder, prologue)
	require.NoError(t, err)
	assert.Equal(t, base, again)
}

// TestComputeAttestChannelBindingRefusesWrongSizedKeys guards against a
// truncated or absent key hashing into a binding that still "works".
func TestComputeAttestChannelBindingRefusesWrongSizedKeys(t *testing.T) {
	good := fixed(0x11, AttestStaticKeySize)

	cases := map[string][2][]byte{
		"short initiator": {fixed(0x11, 31), good},
		"nil initiator":   {nil, good},
		"short responder": {good, fixed(0x22, 16)},
		"nil responder":   {good, nil},
	}

	for name, keys := range cases {
		t.Run(name, func(t *testing.T) {
			binding, err := ComputeAttestChannelBinding(keys[0], keys[1], nil)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrAttestTranscriptField)
			assert.Nil(t, binding)
		})
	}
}

// TestVerifyGenesisChallenge pins what the genesis challenge does and does not
// have to be.
//
// It must carry the contract's prefix, so a chain minted for an unrelated
// Android attestation cannot be presented to this protocol. Trailing bytes are
// deliberately allowed: a prover may append install-unique material without a
// protocol version bump.
func TestVerifyGenesisChallenge(t *testing.T) {
	exact := []byte(AttestGenesisChallenge)

	require.NoError(t, VerifyGenesisChallenge(exact),
		"the contract's own constant must verify")
	require.NoError(t, VerifyGenesisChallenge(append(append([]byte(nil), exact...), 0x01, 0x02)),
		"trailing install-unique bytes are reserved, not a refusal")

	for name, challenge := range map[string][]byte{
		"empty":                nil,
		"truncated prefix":     exact[:len(exact)-1],
		"unrelated app":        []byte("some-other-app-challenge"),
		"prefix in the middle": append([]byte("xx"), exact...),
	} {
		t.Run(name, func(t *testing.T) {
			err := VerifyGenesisChallenge(challenge)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrAttestGenesisChallenge)
		})
	}
}

// leafForKey issues a self-signed certificate carrying key's public half, so
// the signature tests have a leaf to verify against without needing a whole
// attestation chain.
func leafForKey(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "attested key"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return leaf
}

// signTranscript is the prover half: SHA-256 then ECDSA ASN.1 DER.
func signTranscript(t *testing.T, key *ecdsa.PrivateKey, transcript []byte) []byte {
	t.Helper()

	digest := sha256.Sum256(transcript)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	require.NoError(t, err)
	return sig
}

// TestVerifyAttestChallengeSignatureAcceptsALiveProof is the happy path, and
// pins the digest and encoding a Kotlin prover must match:
// Signature("SHA256withECDSA") over the transcript, DER encoded.
func TestVerifyAttestChallengeSignatureAcceptsALiveProof(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := leafForKey(t, key)

	purpose, nonce, binding, fingerprint := validTranscriptInputs()
	transcript, err := BuildAttestTranscript(purpose, nonce, binding, fingerprint)
	require.NoError(t, err)

	sig := signTranscript(t, key, transcript)

	require.NoError(t, VerifyAttestChallengeSignature(leaf, AttestSignatureES256, sig, transcript))
}

// TestVerifyAttestChallengeSignatureRefusals covers every way the proof can
// fail to be one.
func TestVerifyAttestChallengeSignatureRefusals(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := leafForKey(t, key)

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	purpose, nonce, binding, fingerprint := validTranscriptInputs()
	transcript, err := BuildAttestTranscript(purpose, nonce, binding, fingerprint)
	require.NoError(t, err)
	good := signTranscript(t, key, transcript)

	otherTranscript, err := BuildAttestTranscript(AttestPurposeReattest, nonce, binding, fingerprint)
	require.NoError(t, err)

	cases := map[string]struct {
		algorithm string
		signature []byte
		wantErr   error
		why       string
	}{
		"no signature at all": {
			AttestSignatureES256, nil, ErrAttestSignatureMissing,
			"the signature IS the freshness proof; its absence cannot be a pass",
		},
		"empty signature": {
			AttestSignatureES256, []byte{}, ErrAttestSignatureMissing, "same",
		},
		"unnamed algorithm": {
			"", good, ErrAttestSignatureAlgorithm,
			"the algorithm is checked, not inferred from the key",
		},
		"algorithm this build does not implement": {
			"RS256", good, ErrAttestSignatureAlgorithm,
			"a peer must not select a verification path by mislabelling its signature",
		},
		"signature by another key": {
			AttestSignatureES256, signTranscript(t, other, transcript), ErrAttestSignatureInvalid,
			"possession of the attested key is the claim",
		},
		"signature over another transcript": {
			AttestSignatureES256, signTranscript(t, key, otherTranscript), ErrAttestSignatureInvalid,
			"a signature for a different exchange must not carry over",
		},
		"garbage bytes": {
			AttestSignatureES256, []byte{0x30, 0x00, 0xff}, ErrAttestSignatureInvalid,
			"a malformed DER signature is a refusal, not a panic",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := VerifyAttestChallengeSignature(leaf, tc.algorithm, tc.signature, transcript)
			require.Error(t, err, tc.why)
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestVerifyAttestChallengeSignatureRefusesTheWrongCurve pins that ES256 means
// P-256.
//
// Accepting P-384 under the ES256 label would let the peer choose the strength
// of its own proof while the record still says ES256 — and, worse, would make
// the algorithm field decorative.
func TestVerifyAttestChallengeSignatureRefusesTheWrongCurve(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	leaf := leafForKey(t, key)

	purpose, nonce, binding, fingerprint := validTranscriptInputs()
	transcript, err := BuildAttestTranscript(purpose, nonce, binding, fingerprint)
	require.NoError(t, err)

	err = VerifyAttestChallengeSignature(leaf, AttestSignatureES256,
		signTranscript(t, key, transcript), transcript)

	require.Error(t, err)
	require.ErrorIs(t, err, ErrAttestKeyNotECDSA)
}

// TestAttestedKeyFingerprintHashesTheSPKI pins the identity derivation, which
// is the one value stored in the pairing record and echoed on the wire.
//
// The expectation is built from the key's own marshalled SubjectPublicKeyInfo
// rather than from the function under test, so a change to what gets hashed
// turns this red instead of moving both sides together.
func TestAttestedKeyFingerprintHashesTheSPKI(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := leafForKey(t, key)

	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	want := sha256.Sum256(spki)

	got, err := AttestedKeyFingerprint(leaf)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	hexForm, err := AttestedKeyFingerprintHex(leaf)
	require.NoError(t, err)
	assert.Equal(t, AttestFingerprintSize*2, len(hexForm),
		"the hex form is what the record stores and the identity ack carries")

	// A different key must give a different identity, or the value identifies
	// nothing.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	other, err := AttestedKeyFingerprint(leafForKey(t, otherKey))
	require.NoError(t, err)
	assert.NotEqual(t, got, other)

	// The SAME key in a REISSUED certificate must give the SAME identity: that
	// stability across honest re-attestation is why the SPKI is hashed rather
	// than the leaf DER.
	reissued := leafForKey(t, key)
	require.NotEqual(t, leaf.Raw, reissued.Raw, "the fixture must actually reissue")
	reissuedFP, err := AttestedKeyFingerprint(reissued)
	require.NoError(t, err)
	assert.Equal(t, got, reissuedFP)
}

// TestAttestHelpersRefuseANilCertificateRatherThanPanicking covers the three
// exported entry points that dereference a caller-supplied certificate.
//
// They are exported and re-exported through pkg/phone, so they are reachable
// from callers this package does not control — "no caller would pass nil" is
// not a property they can rest on, and a panic in a verification helper takes
// down a long-running consumer instead of refusing one connection. Absence of
// evidence is a verification failure like any other. (Codex, #124.)
func TestAttestHelpersRefuseANilCertificateRatherThanPanicking(t *testing.T) {
	t.Run("AttestedKeyFingerprint", func(t *testing.T) {
		fp, err := AttestedKeyFingerprint(nil)
		require.ErrorIs(t, err, ErrAttestNilCertificate)
		assert.Equal(t, [AttestFingerprintSize]byte{}, fp,
			"no identity may be produced from no certificate")
	})

	t.Run("AttestedKeyFingerprintHex", func(t *testing.T) {
		fp, err := AttestedKeyFingerprintHex(nil)
		require.ErrorIs(t, err, ErrAttestNilCertificate)
		assert.Empty(t, fp)
	})

	t.Run("VerifyAttestChallengeSignature", func(t *testing.T) {
		// A NON-EMPTY signature and the right algorithm, so the nil check is
		// what refuses rather than the earlier missing-signature guard — with
		// an empty signature this would pass on the wrong branch and prove
		// nothing about the dereference.
		_, nonce, binding, fingerprint := validTranscriptInputs()
		transcript, err := BuildAttestTranscript(AttestPurposePair, nonce, binding, fingerprint)
		require.NoError(t, err)

		err = VerifyAttestChallengeSignature(nil, AttestSignatureES256, []byte{0x30, 0x06}, transcript)
		require.ErrorIs(t, err, ErrAttestNilCertificate)
	})
}

// TestNoiseSessionChannelBindingRefusesBeforeTheHandshake guards the ordering
// mistake that would make the binding meaningless: computing it before there
// is an authenticated peer static key to bind to.
func TestNoiseSessionChannelBindingRefusesBeforeTheHandshake(t *testing.T) {
	session, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	binding, err := session.AttestChannelBinding()

	require.Error(t, err, "there is no peer key to bind to yet")
	require.ErrorIs(t, err, ErrNoiseHandshakeFailed)
	assert.Nil(t, binding)
}

// TestNoiseSessionPrologueIsCopiedOut guards the accessor the channel binding
// reads through: handing out the live slice would let a caller desynchronize
// the binding from the prologue the handshake actually ran under.
func TestNoiseSessionPrologueIsCopiedOut(t *testing.T) {
	session, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	prologue := fixed(0x55, 32)
	session.SetPrologue(prologue)

	got := session.Prologue()
	require.Equal(t, prologue, got)

	got[0] ^= 0xff
	assert.Equal(t, prologue, session.Prologue(), "the accessor must not expose the stored slice")

	prologue[1] ^= 0xff
	assert.NotEqual(t, prologue, session.Prologue(), "the setter must not retain the caller's slice")
}

// TestAttestDeviceRequestCarriesNoChannelBinding pins the ABSENCE of a field,
// which is a strange thing to test until you see what absence buys (#129).
//
// The binding was briefly sent as a diagnostic. It was removed because a prover
// that signs the value it was handed and a prover that derives its own are
// BYTE-INDISTINGUISHABLE to the verifier under normal operation — they diverge
// only under exactly the relay attack the binding exists to stop, at which
// point the relayed signature verifies. A request field named channelBinding
// carrying 32 bytes reads as "sign this"; that it means the opposite is a trap
// no verifier can detect.
//
// So the security property is structural: the dangerous implementation is not
// merely forbidden, it is unwritable, because there is nothing to echo.
//
// It asserts on the STRUCT's field set rather than on a marshalled instance,
// and that is not a stylistic choice — the first version of this test
// marshalled a request and asserted the JSON did not contain "channelBinding".
// It passed with the field restored, because `omitempty` omits an unset field:
// the test could not tell "the field does not exist" from "the field exists and
// I did not set it", which is the entire distinction. Measured, not reasoned.
//
// Enumerating the fields also gives the right friction: adding ANY field to a
// wire request now requires editing this test, which is a decision that should
// cost something.
func TestAttestDeviceRequestCarriesNoChannelBinding(t *testing.T) {
	typ := reflect.TypeOf(LocalAttestDeviceParams{})

	var tags []string
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		tags = append(tags, name)

		assert.NotEqual(t, "channelBinding", name,
			"the request must not carry a channel binding; each side derives its own, "+
				"and supplying it makes the vulnerable prover indistinguishable from the correct one")
	}

	// The exact wire shape, so this cannot pass by the struct being empty and
	// so any addition is a deliberate edit rather than a silent one.
	assert.ElementsMatch(t, []string{"protocolVersion", "nonce", "purpose"}, tags,
		"the version 2 request is exactly protocolVersion, nonce, purpose")
}
