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

package securityevent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cose "github.com/veraison/go-cose"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

var (
	// bootNonce is the challenge the alias certificate's UCCS was minted
	// over at boot; verifierNonce is the one the Verifier issued for the
	// record. They differ, as they do on a device.
	bootNonce     = []byte("boot-nonce-0123456789")
	verifierNonce = []byte("verifier-nonce-0123456789")
)

// device is a test DICE device: a manufacturer root, the alias leaf it
// issued, and the alias key that signs evidence.
type device struct {
	aliasKey *ecdsa.PrivateKey
	chain    [][]byte
	roots    *x509.CertPool
}

func newDevice(t *testing.T) *device {
	t.Helper()
	rootKey := mustKey(t, elliptic.P256())
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test DICE Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	uccs, err := dice.CreateUccsEvidenceExtension(&dice.ClaimsSet{Nonce: bootNonce})
	require.NoError(t, err)
	aliasKey := mustKey(t, elliptic.P256())
	aliasTemplate := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "Test DICE Alias"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{uccs},
	}
	aliasDER, err := x509.CreateCertificate(rand.Reader, aliasTemplate, root, aliasKey.Public(), rootKey)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(root)
	return &device{aliasKey: aliasKey, chain: [][]byte{aliasDER}, roots: roots}
}

func mustKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	return key
}

func mustCBOR(t *testing.T, v any) []byte {
	t.Helper()
	encoded, err := cbor.Marshal(v)
	require.NoError(t, err)
	return encoded
}

// testRecord is a security-event Claims-Set: two entries, none dropped.
func testRecord(t *testing.T) []byte {
	return mustCBOR(t, map[int64]any{
		1: 2,
		2: 0,
		3: [][]uint64{{100, 1, 4, 0}, {101, 2, 4, 1}},
	})
}

func sha256Digest(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// sign wraps payload in a COSE_Sign1_Tagged signed by key under alg.
func sign(t *testing.T, key crypto.Signer, alg cose.Algorithm, payload []byte) []byte {
	t.Helper()
	signer, err := cose.NewSigner(alg, key)
	require.NoError(t, err)
	msg := cose.NewSign1Message()
	msg.Headers.Protected.SetAlgorithm(alg)
	msg.Payload = payload
	require.NoError(t, msg.Sign(rand.Reader, nil, signer))
	encoded, err := msg.MarshalCBOR()
	require.NoError(t, err)
	return encoded
}

// claimsWith is the evidence Claims-Set over nonce with submods.
func claimsWith(t *testing.T, nonce []byte, submods any) []byte {
	claims := map[int64]any{dice.ClaimEatNonce: nonce}
	if submods != nil {
		claims[ClaimSubmods] = submods
	}
	return mustCBOR(t, claims)
}

// digestSubmods is a submods claim holding the record's detached digest.
func digestSubmods(alg any, digest []byte) map[string]any {
	return map[string]any{SubmoduleName: []any{alg, digest}}
}

// evidenceFor is what a conforming device returns for record and nonce.
func (d *device) evidenceFor(t *testing.T, record, nonce []byte) *types.SecurityEventEvidence {
	payload := claimsWith(t, nonce, digestSubmods(-16, sha256Digest(record)))
	return &types.SecurityEventEvidence{
		Evidence: sign(t, d.aliasKey, cose.AlgorithmES256, payload),
		Chain:    d.chain,
		Record:   record,
	}
}

func (d *device) options() *Options {
	return &Options{
		Nonce: verifierNonce,
		DICE:  dice.VerifyOptions{TrustedRoots: d.roots, ExpectedNonce: bootNonce},
	}
}

func TestAppraiseAcceptsFreshMatchingRecord(t *testing.T) {
	d := newDevice(t)
	record := testRecord(t)

	result, err := Appraise(d.evidenceFor(t, record, verifierNonce), d.options())
	require.NoError(t, err)
	assert.Equal(t, record, result.Record)
	require.NotNil(t, result.Device)
	assert.Equal(t, bootNonce, result.Device.Claims.Nonce)
}

func TestAppraiseAcceptsTextHashAlgorithm(t *testing.T) {
	d := newDevice(t)
	record := testRecord(t)
	sum := sha512.Sum384(record)
	payload := claimsWith(t, verifierNonce, digestSubmods("SHA-384", sum[:]))
	evidence := &types.SecurityEventEvidence{
		Evidence: sign(t, d.aliasKey, cose.AlgorithmES256, payload),
		Chain:    d.chain,
		Record:   record,
	}

	_, err := Appraise(evidence, d.options())
	require.NoError(t, err)
}

func TestAppraiseRejectsUnhashableHashAlgorithm(t *testing.T) {
	d := newDevice(t)
	record := testRecord(t)
	digest := sha256Digest(record)

	tests := map[string]struct {
		alg any
	}{
		"array algorithm":       {alg: []any{}},
		"byte string algorithm": {alg: []byte{0}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			payload := claimsWith(t, verifierNonce, digestSubmods(tc.alg, digest))
			evidence := &types.SecurityEventEvidence{
				Evidence: sign(t, d.aliasKey, cose.AlgorithmES256, payload),
				Chain:    d.chain,
				Record:   record,
			}

			var err error
			require.NotPanics(t, func() { _, err = Appraise(evidence, d.options()) })
			require.ErrorIs(t, err, ErrUnsupportedHashAlgorithm)
		})
	}
}

func TestAppraiseRejectsChangedRecord(t *testing.T) {
	d := newDevice(t)
	evidence := d.evidenceFor(t, testRecord(t), verifierNonce)
	// The adapter drops the second entry before forwarding the record.
	evidence.Record = mustCBOR(t, map[int64]any{1: 1, 2: 0, 3: [][]uint64{{100, 1, 4, 0}}})

	_, err := Appraise(evidence, d.options())
	require.ErrorIs(t, err, ErrRecordDigestMismatch)
}

func TestAppraiseRejectsWrongNonce(t *testing.T) {
	d := newDevice(t)
	evidence := d.evidenceFor(t, testRecord(t), []byte("an-earlier-verifier-nonce"))

	_, err := Appraise(evidence, d.options())
	require.ErrorIs(t, err, ErrNonceMismatch)
}

func TestAppraiseRejectsBadSignature(t *testing.T) {
	d := newDevice(t)
	record := testRecord(t)
	payload := claimsWith(t, verifierNonce, digestSubmods(-16, sha256Digest(record)))

	tests := map[string][]byte{
		"signed by another key": sign(t, mustKey(t, elliptic.P256()), cose.AlgorithmES256, payload),
		"signed with ES384":     sign(t, mustKey(t, elliptic.P384()), cose.AlgorithmES384, payload),
	}
	for name, signed := range tests {
		t.Run(name, func(t *testing.T) {
			evidence := &types.SecurityEventEvidence{Evidence: signed, Chain: d.chain, Record: record}
			_, err := Appraise(evidence, d.options())
			require.ErrorIs(t, err, ErrSignature)
		})
	}
}

func TestAppraiseRejectsMissingAlgorithmHeader(t *testing.T) {
	d := newDevice(t)
	evidence := d.evidenceFor(t, testRecord(t), verifierNonce)
	msg := cose.NewSign1Message()
	require.NoError(t, msg.UnmarshalCBOR(evidence.Evidence))
	delete(msg.Headers.Protected, cose.HeaderLabelAlgorithm)
	msg.Headers.RawProtected = nil
	encoded, err := msg.MarshalCBOR()
	require.NoError(t, err)
	evidence.Evidence = encoded

	_, err = Appraise(evidence, d.options())
	require.ErrorIs(t, err, ErrSignature)
}

func TestAppraiseRejectsInvalidInputs(t *testing.T) {
	d := newDevice(t)
	valid := d.evidenceFor(t, testRecord(t), verifierNonce)

	_, err := Appraise(nil, d.options())
	require.ErrorIs(t, err, ErrNilEvidence)

	_, err = Appraise(valid, nil)
	require.ErrorIs(t, err, ErrNilOptions)

	opts := d.options()
	opts.Nonce = nil
	_, err = Appraise(valid, opts)
	require.ErrorIs(t, err, ErrNonceRequired)
}

func TestAppraiseRejectsSignerChain(t *testing.T) {
	d := newDevice(t)
	record := testRecord(t)

	tests := map[string]struct {
		chain [][]byte
		roots *x509.CertPool
		want  error
	}{
		"empty chain":       {chain: nil, roots: d.roots, want: ErrMalformedChain},
		"unparseable chain": {chain: [][]byte{{0x30, 0x00}}, roots: d.roots, want: ErrMalformedChain},
		"unanchored chain":  {chain: d.chain, roots: x509.NewCertPool(), want: ErrUntrustedSigner},
		"nil roots":         {chain: d.chain, roots: nil, want: ErrUntrustedSigner},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			evidence := d.evidenceFor(t, record, verifierNonce)
			evidence.Chain = tc.chain
			opts := d.options()
			opts.DICE.TrustedRoots = tc.roots
			_, err := Appraise(evidence, opts)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestAppraiseRejectsMalformedEvidence(t *testing.T) {
	d := newDevice(t)
	record := testRecord(t)
	digest := sha256Digest(record)

	tests := map[string]struct {
		evidence []byte
		want     error
	}{
		"not a COSE_Sign1": {
			evidence: mustCBOR(t, []int{1, 2, 3}),
			want:     ErrMalformedEvidence,
		},
		"payload is not a Claims-Set": {
			evidence: sign(t, d.aliasKey, cose.AlgorithmES256, mustCBOR(t, []int{1})),
			want:     ErrMalformedEvidence,
		},
		"no submods claim": {
			evidence: sign(t, d.aliasKey, cose.AlgorithmES256, claimsWith(t, verifierNonce, nil)),
			want:     ErrNoDetachedDigest,
		},
		"submods is not a map": {
			evidence: sign(t, d.aliasKey, cose.AlgorithmES256, claimsWith(t, verifierNonce, 7)),
			want:     ErrMalformedEvidence,
		},
		"submods has no record entry": {
			evidence: sign(t, d.aliasKey, cose.AlgorithmES256,
				claimsWith(t, verifierNonce, map[string]any{"other": []any{-16, digest}})),
			want: ErrNoDetachedDigest,
		},
		"record entry is an inline Claims-Set": {
			evidence: sign(t, d.aliasKey, cose.AlgorithmES256,
				claimsWith(t, verifierNonce, map[string]any{SubmoduleName: map[int64]any{1: 2}})),
			want: ErrNoDetachedDigest,
		},
		"detached digest has three elements": {
			evidence: sign(t, d.aliasKey, cose.AlgorithmES256,
				claimsWith(t, verifierNonce, map[string]any{SubmoduleName: []any{-16, digest, 0}})),
			want: ErrMalformedEvidence,
		},
		"hash algorithm below the int64 range": {
			evidence: sign(t, d.aliasKey, cose.AlgorithmES256,
				claimsWith(t, verifierNonce, map[string]any{SubmoduleName: []any{
					cbor.RawMessage{0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, digest,
				}})),
			want: ErrMalformedEvidence,
		},
		"unsupported hash algorithm": {
			evidence: sign(t, d.aliasKey, cose.AlgorithmES256,
				claimsWith(t, verifierNonce, digestSubmods("SHA-1", digest))),
			want: ErrUnsupportedHashAlgorithm,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			evidence := &types.SecurityEventEvidence{Evidence: tc.evidence, Chain: d.chain, Record: record}
			_, err := Appraise(evidence, d.options())
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestAppraiseRejectsMalformedRecord(t *testing.T) {
	d := newDevice(t)

	// The device signed each of these, so the digest matches and only the
	// record's shape is wrong.
	tests := map[string][]byte{
		"empty record":     {},
		"record is a list": mustCBOR(t, []int{1, 2}),
		"trailing data":    append(testRecord(t), 0x00),
		"truncated map":    testRecord(t)[:4],
	}
	for name, record := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Appraise(d.evidenceFor(t, record, verifierNonce), d.options())
			require.ErrorIs(t, err, ErrMalformedRecord)
		})
	}
}
