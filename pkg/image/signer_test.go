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
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/encoding"
)

// errTestIssuer is the error a refusing testIssuer answers with.
var errTestIssuer = errors.New("test: issuer refused")

// signerFixture is a registry holding one image, and the PKI that certifies
// the image's signers.
type signerFixture struct {
	pki      *testPKI
	registry *testRegistry
	client   RegistryClient
	ref      string
	digest   string
}

func newSignerFixture(t *testing.T, config registryConfig) *signerFixture {
	t.Helper()
	registry := newTestRegistry(t, config)
	ref, digest := registry.seedImage(t, "team/app", "v1")
	return &signerFixture{
		pki:      newTestPKI(t),
		registry: registry,
		client:   registry.client(t, nil),
		ref:      ref,
		digest:   digest,
	}
}

// signer returns a Signer of key, certified by f's PKI, that timestamps
// with timestamper when it is set.
func (f *signerFixture) signer(t *testing.T, key crypto.Signer, timestamper Timestamper) *Signer {
	t.Helper()
	signer, err := NewSigner(&SignerConfig{
		Signer:      key,
		Certificate: f.pki.codeSigning(t, key.Public()),
		Chain:       []*x509.Certificate{f.pki.certificate},
		Registry:    f.client,
		Timestamper: timestamper,
	})
	require.NoError(t, err)
	return signer
}

// verifier returns a Verifier of f's registry configured by cfg, trusting
// f's PKI unless cfg names other roots.
func (f *signerFixture) verifier(t *testing.T, cfg VerifierConfig[purpose]) *Verifier {
	t.Helper()
	cfg.Registry = f.client
	cfg.Purpose = testPurpose
	if cfg.Roots == nil {
		cfg.Roots = f.pki.roots()
	}
	verifier, err := NewVerifier(&cfg)
	require.NoError(t, err)
	return verifier
}

// codeSigningBetween issues a code-signing certificate for key, valid from
// notBefore to notAfter.
func (p *testPKI) codeSigningBetween(t *testing.T, key crypto.PublicKey, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	return p.issue(t, key, &x509.Certificate{
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
	})
}

func TestNewSigner(t *testing.T) {
	f := newSignerFixture(t, registryConfig{})
	key := newECDSAKey(t)
	certificate := f.pki.codeSigning(t, key.Public())

	signer, err := NewSigner(&SignerConfig{Signer: key, Certificate: certificate, Registry: f.client})
	require.NoError(t, err)
	decoded, err := encoding.DecodeCertificateChainPEM(signer.certificatePEM)
	require.NoError(t, err)
	require.Len(t, decoded, 1)
	assert.Equal(t, certificate.Raw, decoded[0].Raw)
	assert.Empty(t, signer.chainPEM, "the chain is optional")

	signer, err = NewSigner(&SignerConfig{
		Signer:      key,
		Certificate: certificate,
		Chain:       []*x509.Certificate{f.pki.certificate},
		Registry:    f.client,
	})
	require.NoError(t, err)
	chain, err := encoding.DecodeCertificateChainPEM(signer.chainPEM)
	require.NoError(t, err)
	require.Len(t, chain, 1)
	assert.Equal(t, f.pki.certificate.Raw, chain[0].Raw)
}

func TestNewSigner_Errors(t *testing.T) {
	f := newSignerFixture(t, registryConfig{})
	key := newECDSAKey(t)
	certificate := f.pki.codeSigning(t, key.Public())
	// An ECDH key agreement key: no signature algorithm accepts it.
	exchange, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now()

	config := func(certificate *x509.Certificate) *SignerConfig {
		return &SignerConfig{Signer: key, Certificate: certificate, Registry: f.client}
	}
	tests := map[string]struct {
		cfg  *SignerConfig
		want error
	}{
		"no config":      {cfg: nil, want: ErrSignerRequired},
		"no signer":      {cfg: &SignerConfig{Certificate: certificate, Registry: f.client}, want: ErrSignerRequired},
		"no certificate": {cfg: &SignerConfig{Signer: key, Registry: f.client}, want: ErrCertificateRequired},
		"no registry":    {cfg: &SignerConfig{Signer: key, Certificate: certificate}, want: ErrRegistryRequired},
		"unsupported key": {
			cfg:  &SignerConfig{Signer: failingSigner{public: exchange.PublicKey()}, Certificate: certificate, Registry: f.client},
			want: ErrUnsupportedKey,
		},
		"another key's certificate": {cfg: config(f.pki.codeSigning(t, newECDSAKey(t).Public())), want: ErrKeyMismatch},
		"server authentication": {
			cfg: config(f.pki.issue(t, key.Public(), &x509.Certificate{
				KeyUsage:    x509.KeyUsageDigitalSignature,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})),
			want: ErrNotCodeSigning,
		},
		"no digital signature": {
			cfg: config(f.pki.issue(t, key.Public(), &x509.Certificate{
				KeyUsage:    x509.KeyUsageContentCommitment,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			})),
			want: ErrNotCodeSigning,
		},
		"expired": {
			cfg:  config(f.pki.codeSigningBetween(t, key.Public(), now.Add(-2*time.Hour), now.Add(-time.Hour))),
			want: ErrCertificateNotValid,
		},
		"not yet valid": {
			cfg:  config(f.pki.codeSigningBetween(t, key.Public(), now.Add(time.Hour), now.Add(2*time.Hour))),
			want: ErrCertificateNotValid,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			signer, err := NewSigner(tt.cfg)
			require.ErrorIs(t, err, tt.want)
			assert.Nil(t, signer)
		})
	}
}

func TestSigner_SignImage(t *testing.T) {
	for name, key := range signerKeys(t) {
		t.Run(name, func(t *testing.T) {
			f := newSignerFixture(t, registryConfig{referrers: true})

			result, err := f.signer(t, key, nil).SignImage(t.Context(), f.ref, nil)
			require.NoError(t, err)
			assert.Equal(t, f.digest, result.Digest)
			assert.Empty(t, result.Timestamp)
			assert.True(t, result.Push.ReferrerIndexed)
			assert.Equal(t, strings.Replace(f.digest, ":", "-", 1)+".att", result.Push.AttestationTag)
			_, tagged := f.registry.manifest("team/app", result.Push.AttestationTag)
			assert.True(t, tagged, "the .att tag is written beside the referrer")

			env, err := parseEnvelope(result.Envelope)
			require.NoError(t, err)
			statement, err := parseStatement(env.Payload)
			require.NoError(t, err)
			assert.Equal(t, PredicateTypeCosign, statement.PredicateType)
			require.Len(t, statement.Subject, 1)
			assert.Equal(t, f.registry.host()+"/team/app", statement.Subject[0].Name)
			assert.True(t, statement.names(f.digest))

			verified, err := f.verifier(t, VerifierConfig[purpose]{}).VerifyImage(t.Context(), f.ref)
			require.NoError(t, err)
			assert.Equal(t, f.digest, verified.Digest)
			assert.Equal(t, statement, verified.Statement)
			assert.True(t, key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(verified.Certificate.PublicKey))
			assert.Nil(t, verified.Timestamp)
		})
	}
}

func TestSigner_SignImage_AttestationTag(t *testing.T) {
	// A registry without the referrers API keeps every attestation in the
	// .att tag alone.
	f := newSignerFixture(t, registryConfig{})
	signer := f.signer(t, newECDSAKey(t), nil)

	first, err := signer.SignImage(t.Context(), f.ref, nil)
	require.NoError(t, err)
	assert.False(t, first.Push.ReferrerIndexed)
	second, err := signer.SignImage(t.Context(), f.ref, &SignOptions{
		PredicateType: "https://slsa.dev/provenance/v1",
		Predicate:     json.RawMessage(`{"buildDefinition":{}}`),
	})
	require.NoError(t, err)
	assert.Equal(t, first.Push.AttestationTag, second.Push.AttestationTag)

	reference, _ := pinned(t, f.client, f.ref)
	attestations, err := f.client.Attestations(t.Context(), reference)
	require.NoError(t, err)
	assert.Len(t, attestations, 2, "the tag keeps every attestation")

	verified, err := f.verifier(t, VerifierConfig[purpose]{PredicateType: "https://slsa.dev/provenance/v1"}).VerifyImage(t.Context(), f.ref)
	require.NoError(t, err, "the second attestation verifies after the first is refused")
	assert.Equal(t, "https://slsa.dev/provenance/v1", verified.Statement.PredicateType)
	assert.JSONEq(t, `{"buildDefinition":{}}`, string(verified.Statement.Predicate))
}

func TestSigner_SignImage_Timestamp(t *testing.T) {
	f := newSignerFixture(t, registryConfig{referrers: true})
	tsa := newTestTSA(t, f.pki, tsaConfig{})

	result, err := f.signer(t, newECDSAKey(t), tsa.client(t)).SignImage(t.Context(), f.ref, nil)
	require.NoError(t, err)
	require.NotEmpty(t, result.Timestamp)
	info, err := VerifyTimestamp(result.Timestamp, result.Envelope, f.pki.pool)
	require.NoError(t, err, "the timestamp covers the pushed envelope")
	assert.Equal(t, tsa.certificate.Raw, info.Certificate.Raw)

	verified, err := f.verifier(t, VerifierConfig[purpose]{TimestampRoots: f.pki.pool, RequireTimestamp: true}).VerifyImage(t.Context(), f.ref)
	require.NoError(t, err)
	require.NotNil(t, verified.Timestamp)
	assert.Equal(t, info.SerialNumber, verified.Timestamp.SerialNumber)
	assert.Equal(t, info.Time, verified.Timestamp.Time)
}

func TestSigner_SignImage_Errors(t *testing.T) {
	f := newSignerFixture(t, registryConfig{referrers: true})
	key := newECDSAKey(t)
	signer := f.signer(t, key, nil)

	expired := f.signer(t, key, nil)
	now := time.Now()
	expired.certificate = f.pki.codeSigningBetween(t, key.Public(), now.Add(-2*time.Hour), now.Add(-time.Hour))

	tests := map[string]struct {
		signer *Signer
		ref    string
		opts   *SignOptions
		want   error
	}{
		"invalid reference": {signer: signer, ref: "gcr.io/MyImage:v1", want: ErrInvalidReference},
		"no such image":     {signer: signer, ref: f.registry.host() + "/team/app:missing", want: ErrManifestNotFound},
		"no predicate": {
			signer: signer,
			ref:    f.ref,
			opts:   &SignOptions{PredicateType: "https://slsa.dev/provenance/v1"},
			want:   ErrInvalidStatement,
		},
		"expired certificate": {signer: expired, ref: f.ref, want: ErrCertificateNotValid},
		"signing fails":       {signer: f.signer(t, failingSigner{public: key.Public()}, nil), ref: f.ref, want: ErrSigningFailed},
		"timestamp rejected": {
			signer: f.signer(t, key, newTestTSA(t, f.pki, tsaConfig{status: 2}).client(t)),
			ref:    f.ref,
			want:   ErrTimestampRejected,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := tt.signer.SignImage(t.Context(), tt.ref, tt.opts)
			require.ErrorIs(t, err, tt.want)
			assert.Nil(t, result)
		})
	}
}

func TestSigner_SignImage_RegistryUnavailable(t *testing.T) {
	f := newSignerFixture(t, registryConfig{})
	signer := f.signer(t, newECDSAKey(t), nil)
	f.registry.unavailable.Store(100)

	result, err := signer.SignImage(t.Context(), f.ref, nil)
	require.ErrorIs(t, err, ErrRegistryUnavailable)
	assert.Nil(t, result)
}

func TestSignOptions_Predicate(t *testing.T) {
	// Signing time is written in UTC whatever the local zone.
	now := time.Date(2026, 10, 15, 13, 0, 0, 0, time.FixedZone("UTC+1", 3600))
	cosignDefault := `{"Data":"","Timestamp":"2026-10-15T12:00:00Z"}`

	tests := map[string]struct {
		opts          *SignOptions
		predicateType string
		predicate     string
	}{
		"no options":       {opts: nil, predicateType: PredicateTypeCosign, predicate: cosignDefault},
		"cosign default":   {opts: &SignOptions{}, predicateType: PredicateTypeCosign, predicate: cosignDefault},
		"cosign predicate": {opts: &SignOptions{Predicate: json.RawMessage(`{"Data":"x"}`)}, predicateType: PredicateTypeCosign, predicate: `{"Data":"x"}`},
		"other type": {
			opts:          &SignOptions{PredicateType: "https://slsa.dev/provenance/v1", Predicate: json.RawMessage(`{"buildDefinition":{}}`)},
			predicateType: "https://slsa.dev/provenance/v1",
			predicate:     `{"buildDefinition":{}}`,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			predicateType, predicate, err := tt.opts.predicate(now)
			require.NoError(t, err)
			assert.Equal(t, tt.predicateType, predicateType)
			assert.JSONEq(t, tt.predicate, string(predicate))
		})
	}
}

func TestSignOptions_Predicate_Missing(t *testing.T) {
	opts := &SignOptions{PredicateType: "https://slsa.dev/provenance/v1"}
	predicateType, predicate, err := opts.predicate(time.Now())
	require.ErrorIs(t, err, ErrInvalidStatement, "only the cosign predicate has a default")
	assert.Empty(t, predicateType)
	assert.Nil(t, predicate)
}

func TestRequestCodeSigningCertificate(t *testing.T) {
	f := newSignerFixture(t, registryConfig{})
	for name, key := range signerKeys(t) {
		t.Run(name, func(t *testing.T) {
			issuer := &testIssuer{t: t, pki: f.pki}
			certificate, err := RequestCodeSigningCertificate(t.Context(), issuer, key, "tenant-a", "release signer")
			require.NoError(t, err)
			assert.Equal(t, ca.ProfileNameCodeSigning, issuer.profile)
			assert.Equal(t, "tenant-a", issuer.tenant)
			assert.Equal(t, "release signer", certificate.Subject.CommonName)
			assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, certificate.ExtKeyUsage)
			assert.True(t, key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(certificate.PublicKey))

			signer, err := NewSigner(&SignerConfig{Signer: key, Certificate: certificate, Registry: f.client})
			require.NoError(t, err, "the issued certificate signs images")
			assert.NotNil(t, signer)
		})
	}
}

func TestRequestCodeSigningCertificate_Errors(t *testing.T) {
	pki := newTestPKI(t)
	key := newECDSAKey(t)

	issuer := func(edit func(*x509.Certificate), err error) func(t *testing.T) CertificateIssuer {
		return func(t *testing.T) CertificateIssuer {
			return &testIssuer{t: t, pki: pki, edit: edit, err: err}
		}
	}
	tests := map[string]struct {
		issuer     func(t *testing.T) CertificateIssuer
		signer     crypto.Signer
		tenantID   string
		commonName string
		want       error
		cause      error
	}{
		"no issuer": {
			issuer:     func(*testing.T) CertificateIssuer { return nil },
			signer:     key,
			commonName: "release signer",
			want:       ErrIssuerRequired,
		},
		"no signer":         {issuer: issuer(nil, nil), signer: nil, commonName: "release signer", want: ErrSignerRequired},
		"no tenant":         {issuer: issuer(nil, nil), signer: key, tenantID: " ", commonName: "release signer", want: ca.ErrTenantRequired},
		"blank common name": {issuer: issuer(nil, nil), signer: key, commonName: " \t", want: ErrCommonNameRequired},
		"request unsigned": {
			issuer:     issuer(nil, nil),
			signer:     failingSigner{public: key.Public()},
			commonName: "release signer",
			want:       ErrCSRFailed,
			cause:      errTestSigner,
		},
		"issuer refuses": {
			issuer:     issuer(nil, errTestIssuer),
			signer:     key,
			commonName: "release signer",
			want:       ErrCertificateRequestFailed,
			cause:      errTestIssuer,
		},
		"not code signing": {
			issuer: issuer(func(template *x509.Certificate) {
				template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			}, nil),
			signer:     key,
			commonName: "release signer",
			want:       ErrNotCodeSigning,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tenantID := tt.tenantID
			if tenantID == "" {
				tenantID = "tenant-a"
			}
			certificate, err := RequestCodeSigningCertificate(t.Context(), tt.issuer(t), tt.signer, tenantID, tt.commonName)
			require.ErrorIs(t, err, tt.want)
			if tt.cause != nil {
				require.ErrorIs(t, err, tt.cause)
			}
			assert.Nil(t, certificate)
		})
	}
}
