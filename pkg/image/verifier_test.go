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

package image

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/encoding"
)

// errTestRoots is the error a failing testRoots answers with.
var errTestRoots = errors.New("test: root store unavailable")

// statement returns the JSON in-toto statement naming f's repository at
// digest.
func (f *signerFixture) statement(t *testing.T, digest string) []byte {
	t.Helper()
	statement, err := newStatement(f.registry.host()+"/team/app", digest, PredicateTypeCosign, json.RawMessage(`{"Data":""}`))
	require.NoError(t, err)
	payload, err := json.Marshal(statement)
	require.NoError(t, err)
	return payload
}

// attestation returns an attestation of payload signed by key, carrying
// certificate and f's root as its chain.
func (f *signerFixture) attestation(t *testing.T, key crypto.Signer, certificate *x509.Certificate, payload []byte) *Attestation {
	t.Helper()
	env, err := signEnvelope(key, PayloadTypeInToto, payload)
	require.NoError(t, err)
	envelope, err := json.Marshal(env)
	require.NoError(t, err)
	certificatePEM, err := encoding.EncodeCertificatePEM(certificate)
	require.NoError(t, err)
	chainPEM, err := encoding.EncodeCertificatePEM(f.pki.certificate)
	require.NoError(t, err)
	return &Attestation{Envelope: envelope, PredicateType: PredicateTypeCosign, Certificate: certificatePEM, Chain: chainPEM}
}

// validAttestation returns an attestation of f's image that verifies.
func (f *signerFixture) validAttestation(t *testing.T) *Attestation {
	t.Helper()
	key := newECDSAKey(t)
	return f.attestation(t, key, f.pki.codeSigning(t, key.Public()), f.statement(t, f.digest))
}

// pushAttestation stores attestation for f's image.
func (f *signerFixture) pushAttestation(t *testing.T, attestation *Attestation) {
	t.Helper()
	reference, subject := pinned(t, f.client, f.ref)
	result, err := f.client.PushAttestation(t.Context(), reference, subject, attestation)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestNewVerifier_Errors(t *testing.T) {
	f := newSignerFixture(t, registryConfig{})
	roots := f.pki.roots()

	tests := map[string]struct {
		cfg  *VerifierConfig[purpose]
		want error
	}{
		"no config":   {cfg: nil, want: ErrRegistryRequired},
		"no registry": {cfg: &VerifierConfig[purpose]{Roots: roots, Purpose: testPurpose}, want: ErrRegistryRequired},
		"no roots":    {cfg: &VerifierConfig[purpose]{Registry: f.client, Purpose: testPurpose}, want: ErrRootStoreRequired},
		"no purpose":  {cfg: &VerifierConfig[purpose]{Registry: f.client, Roots: roots}, want: ErrRootPurposeRequired},
		"timestamp required without roots": {
			cfg:  &VerifierConfig[purpose]{Registry: f.client, Roots: roots, Purpose: testPurpose, RequireTimestamp: true},
			want: ErrTimestampRootsRequired,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			verifier, err := NewVerifier(tt.cfg)
			require.ErrorIs(t, err, tt.want)
			assert.Nil(t, verifier)
		})
	}
}

func TestVerifier_VerifyImage_Refused(t *testing.T) {
	// The image is signed correctly; each verifier refuses it.
	f := newSignerFixture(t, registryConfig{referrers: true})
	_, err := f.signer(t, newECDSAKey(t), nil).SignImage(t.Context(), f.ref, nil)
	require.NoError(t, err)

	tests := map[string]struct {
		cfg   VerifierConfig[purpose]
		want  error
		cause error
	}{
		"other roots": {
			// The attestation's chain carries f's root, which grants no trust.
			cfg:   VerifierConfig[purpose]{Roots: newTestPKI(t).roots()},
			want:  ErrNoValidAttestation,
			cause: ErrUntrustedSigner,
		},
		"no roots for the purpose": {
			cfg:  VerifierConfig[purpose]{Roots: &testRoots{byPurpose: map[purpose][]*x509.Certificate{"other": {f.pki.certificate}}}},
			want: ErrNoTrustedRoots,
		},
		"root store fails": {
			cfg:   VerifierConfig[purpose]{Roots: &testRoots{err: errTestRoots}},
			want:  ErrNoTrustedRoots,
			cause: errTestRoots,
		},
		"other predicate type": {
			cfg:   VerifierConfig[purpose]{PredicateType: "https://slsa.dev/provenance/v1"},
			want:  ErrNoValidAttestation,
			cause: ErrPredicateTypeMismatch,
		},
		"timestamp required": {
			cfg:   VerifierConfig[purpose]{TimestampRoots: f.pki.pool, RequireTimestamp: true},
			want:  ErrNoValidAttestation,
			cause: ErrTimestampRequired,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := f.verifier(t, tt.cfg).VerifyImage(t.Context(), f.ref)
			require.ErrorIs(t, err, tt.want)
			if tt.cause != nil {
				require.ErrorIs(t, err, tt.cause)
			}
			assert.Nil(t, result)
		})
	}
}

func TestVerifier_VerifyImage_InvalidAttestation(t *testing.T) {
	otherImage := "sha256:" + strings.Repeat("ef", 32)

	tests := map[string]struct {
		attestation func(t *testing.T, f *signerFixture) *Attestation
		want        error
	}{
		"another key's certificate": {
			attestation: func(t *testing.T, f *signerFixture) *Attestation {
				return f.attestation(t, newECDSAKey(t), f.pki.codeSigning(t, newECDSAKey(t).Public()), f.statement(t, f.digest))
			},
			want: ErrSignatureInvalid,
		},
		"another image": {
			attestation: func(t *testing.T, f *signerFixture) *Attestation {
				key := newECDSAKey(t)
				return f.attestation(t, key, f.pki.codeSigning(t, key.Public()), f.statement(t, otherImage))
			},
			want: ErrSubjectMismatch,
		},
		"not a statement": {
			attestation: func(t *testing.T, f *signerFixture) *Attestation {
				key := newECDSAKey(t)
				return f.attestation(t, key, f.pki.codeSigning(t, key.Public()), []byte(`[]`))
			},
			want: ErrInvalidStatement,
		},
		"server authentication certificate": {
			attestation: func(t *testing.T, f *signerFixture) *Attestation {
				key := newECDSAKey(t)
				certificate := f.pki.issue(t, key.Public(), &x509.Certificate{
					KeyUsage:    x509.KeyUsageDigitalSignature,
					ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				})
				return f.attestation(t, key, certificate, f.statement(t, f.digest))
			},
			want: ErrNotCodeSigning,
		},
		"no digitalSignature key usage": {
			attestation: func(t *testing.T, f *signerFixture) *Attestation {
				key := newECDSAKey(t)
				certificate := f.pki.issue(t, key.Public(), &x509.Certificate{
					KeyUsage:    x509.KeyUsageContentCommitment,
					ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
				})
				return f.attestation(t, key, certificate, f.statement(t, f.digest))
			},
			want: ErrNotCodeSigning,
		},
		"no certificate": {
			attestation: func(t *testing.T, f *signerFixture) *Attestation {
				attestation := f.validAttestation(t)
				attestation.Certificate = nil
				return attestation
			},
			want: ErrInvalidAttestation,
		},
		"garbage certificate": {
			attestation: func(t *testing.T, f *signerFixture) *Attestation {
				attestation := f.validAttestation(t)
				attestation.Certificate = []byte("garbage")
				return attestation
			},
			want: ErrInvalidAttestation,
		},
		"two certificates": {
			attestation: func(t *testing.T, f *signerFixture) *Attestation {
				attestation := f.validAttestation(t)
				attestation.Certificate = slices.Concat(attestation.Certificate, attestation.Chain)
				return attestation
			},
			want: ErrInvalidAttestation,
		},
		"garbage chain": {
			attestation: func(t *testing.T, f *signerFixture) *Attestation {
				attestation := f.validAttestation(t)
				attestation.Chain = []byte("garbage")
				return attestation
			},
			want: ErrInvalidAttestation,
		},
		"garbage envelope": {
			attestation: func(t *testing.T, f *signerFixture) *Attestation {
				attestation := f.validAttestation(t)
				attestation.Envelope = []byte(`{"n":1}`)
				return attestation
			},
			want: ErrInvalidEnvelope,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := newSignerFixture(t, registryConfig{referrers: true})
			f.pushAttestation(t, tt.attestation(t, f))

			result, err := f.verifier(t, VerifierConfig[purpose]{}).VerifyImage(t.Context(), f.ref)
			require.ErrorIs(t, err, ErrNoValidAttestation)
			require.ErrorIs(t, err, tt.want)
			assert.Nil(t, result)
		})
	}
}

// corruptTimestamp gives layer i of f's .att tag a timestamp annotation that
// does not decode, and returns the layer's digest.
func (f *signerFixture) corruptTimestamp(t *testing.T, i int) string {
	t.Helper()
	tag := strings.Replace(f.digest, ":", "-", 1) + ".att"
	stored, ok := f.registry.manifest("team/app", tag)
	require.True(t, ok)
	var manifest Manifest
	require.NoError(t, json.Unmarshal(stored.body, &manifest))
	manifest.Layers[i].Annotations[annotationTimestamp] = "{"
	body, err := json.Marshal(manifest)
	require.NoError(t, err)
	f.registry.storeRaw("team/app", tag, stored.mediaType, body)
	return manifest.Layers[i].Digest
}

func TestVerifier_VerifyImage_SkipsMalformedAttestation(t *testing.T) {
	f := newSignerFixture(t, registryConfig{})
	f.pushAttestation(t, f.validAttestation(t))
	f.pushAttestation(t, f.validAttestation(t))
	f.corruptTimestamp(t, 0)

	result, err := f.verifier(t, VerifierConfig[purpose]{}).VerifyImage(t.Context(), f.ref)
	require.NoError(t, err, "a malformed attestation does not hide a valid one")
	assert.Equal(t, f.digest, result.Digest)
}

func TestVerifier_VerifyImage_OnlyMalformedAttestation(t *testing.T) {
	f := newSignerFixture(t, registryConfig{})
	f.pushAttestation(t, f.validAttestation(t))
	layer := f.corruptTimestamp(t, 0)

	result, err := f.verifier(t, VerifierConfig[purpose]{}).VerifyImage(t.Context(), f.ref)
	require.ErrorIs(t, err, ErrNoValidAttestation)
	require.ErrorIs(t, err, ErrInvalidAttestation)
	assert.ErrorContains(t, err, layer, "the failure names its layer")
	assert.Nil(t, result)
}

func TestVerifier_VerifyImage_TimestampedExpiredCertificate(t *testing.T) {
	// A certificate that has since expired verifies at the time its
	// envelope was timestamped.
	f := newSignerFixture(t, registryConfig{referrers: true})
	now := time.Now()
	stamped := now.Add(-90 * time.Minute).UTC().Truncate(time.Second)
	tsa := newTestTSA(t, f.pki, tsaConfig{tamper: func(info *tstInfo) { info.GenTime = stamped }})

	key := newECDSAKey(t)
	certificate := f.pki.codeSigningBetween(t, key.Public(), now.Add(-2*time.Hour), now.Add(-time.Hour))
	attestation := f.attestation(t, key, certificate, f.statement(t, f.digest))
	timestamp, err := tsa.client(t).Timestamp(t.Context(), attestation.Envelope)
	require.NoError(t, err)
	attestation.Timestamp = timestamp
	f.pushAttestation(t, attestation)

	result, err := f.verifier(t, VerifierConfig[purpose]{TimestampRoots: f.pki.pool}).VerifyImage(t.Context(), f.ref)
	require.NoError(t, err)
	require.NotNil(t, result.Timestamp)
	assert.True(t, stamped.Equal(result.Timestamp.Time))

	result, err = f.verifier(t, VerifierConfig[purpose]{}).VerifyImage(t.Context(), f.ref)
	require.ErrorIs(t, err, ErrUntrustedSigner, "an unverified timestamp leaves the certificate checked now")
	assert.Nil(t, result)
}

func TestVerifier_VerifyImage_TimestampUntrusted(t *testing.T) {
	f := newSignerFixture(t, registryConfig{referrers: true})
	tsa := newTestTSA(t, newTestPKI(t), tsaConfig{})
	_, err := f.signer(t, newECDSAKey(t), tsa.client(t)).SignImage(t.Context(), f.ref, nil)
	require.NoError(t, err)

	result, err := f.verifier(t, VerifierConfig[purpose]{TimestampRoots: f.pki.pool}).VerifyImage(t.Context(), f.ref)
	require.ErrorIs(t, err, ErrNoValidAttestation)
	require.ErrorIs(t, err, ErrTimestampUntrusted)
	assert.Nil(t, result)

	result, err = f.verifier(t, VerifierConfig[purpose]{}).VerifyImage(t.Context(), f.ref)
	require.NoError(t, err, "without timestamp roots the timestamp is not checked")
	assert.Nil(t, result.Timestamp)
}

func TestVerifier_VerifyImage_Errors(t *testing.T) {
	f := newSignerFixture(t, registryConfig{referrers: true})
	verifier := f.verifier(t, VerifierConfig[purpose]{})

	tests := map[string]struct {
		ref  string
		want error
	}{
		"invalid reference": {ref: "gcr.io/MyImage:v1", want: ErrInvalidReference},
		"no such image":     {ref: f.registry.host() + "/team/app:missing", want: ErrManifestNotFound},
		"unsigned image":    {ref: f.ref, want: ErrNoAttestation},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := verifier.VerifyImage(t.Context(), tt.ref)
			require.ErrorIs(t, err, tt.want)
			assert.Nil(t, result)
		})
	}
}
