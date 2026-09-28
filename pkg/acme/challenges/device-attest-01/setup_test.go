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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// scriptedTPM answers Setup's three questions from fixed values, so each of
// Setup's refusals can be reached without a TPM. The simulator tests
// (setup_simulator_test.go) are where the statement meets a real TPM.
type scriptedTPM struct {
	iak         *types.KeyAttributes
	iakErr      error
	iakCert     *x509.Certificate
	iakCertErr  error
	result      *tpm2.CertifyResult
	certifyErr  error
	certifiedAs []byte
}

func (s *scriptedTPM) IAKAttributes() (*types.KeyAttributes, error) { return s.iak, s.iakErr }

func (s *scriptedTPM) IAKCertificate() (*x509.Certificate, error) { return s.iakCert, s.iakCertErr }

func (s *scriptedTPM) CertifyKey(_ *types.KeyAttributes, nonce []byte, _ store.KeyBackend) (*tpm2.CertifyResult, error) {
	s.certifiedAs = nonce
	return s.result, s.certifyErr
}

var errScripted = errors.New("scripted failure")

func workingTPM(t *testing.T) *scriptedTPM {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(newAIKIssuer(t, "AIK CA").issue(t, key.Public(), nil))
	require.NoError(t, err)
	return &scriptedTPM{
		iak:     &types.KeyAttributes{SignatureAlgorithm: x509.ECDSAWithSHA256},
		iakCert: cert,
		result: &tpm2.CertifyResult{
			CertifyInfo:           []byte("certInfo"),
			Signature:             []byte("sig"),
			AttestedKeyPublicArea: []byte("pubArea"),
		},
	}
}

func TestSetupBuildsTheStatementFromTheCertification(t *testing.T) {
	tpm := workingTPM(t)

	payload, err := Setup(tpmKeyAuth, tpm, &types.KeyAttributes{CN: "device"}, nil)
	require.NoError(t, err)

	want, err := TPMExtraData(coseES256, tpmKeyAuth)
	require.NoError(t, err)
	assert.Equal(t, want, tpm.certifiedAs, "the certification must be over TPMExtraData(alg, keyAuth)")

	var request AttestationRequest
	require.NoError(t, json.Unmarshal(payload, &request))
	object, err := ParseAttestationObject(request.AttStmt)
	require.NoError(t, err)

	assert.Equal(t, string(FormatTPM), object.Format)
	statement := object.AttStatement
	assert.Equal(t, "2.0", statement.Ver)
	assert.Equal(t, coseES256, statement.Alg)
	assert.Equal(t, []interface{}{tpm.iakCert.Raw}, statement.X5c)
	assert.Equal(t, []byte("sig"), statement.Sig)
	assert.Equal(t, []byte("certInfo"), statement.CertInfo)
	assert.Equal(t, []byte("pubArea"), statement.PubArea)
}

func TestSetupRefusals(t *testing.T) {
	key := &types.KeyAttributes{CN: "device"}
	cases := map[string]struct {
		keyAuth *string // nil answers tpmKeyAuth
		tpm     func(*scriptedTPM) TrustedPlatformModule
		key     *types.KeyAttributes
		want    error
	}{
		"no TPM": {
			tpm:  func(*scriptedTPM) TrustedPlatformModule { return nil },
			key:  key,
			want: ErrAttestationKeyUnavailable,
		},
		"no key": {
			tpm:  func(s *scriptedTPM) TrustedPlatformModule { return s },
			want: ErrNoCertificateKey,
		},
		"no IAK": {
			tpm:  func(s *scriptedTPM) TrustedPlatformModule { s.iakErr = errScripted; return s },
			key:  key,
			want: ErrAttestationKeyUnavailable,
		},
		"an IAK algorithm with no COSE identifier": {
			tpm: func(s *scriptedTPM) TrustedPlatformModule {
				s.iak.SignatureAlgorithm = x509.PureEd25519
				return s
			},
			key:  key,
			want: ErrInvalidKeyAlgorithm,
		},
		"no IAK certificate": {
			tpm:  func(s *scriptedTPM) TrustedPlatformModule { s.iakCertErr = errScripted; return s },
			key:  key,
			want: ErrAttestationKeyUnavailable,
		},
		"no key authorization": {
			keyAuth: new(string),
			tpm:     func(s *scriptedTPM) TrustedPlatformModule { return s },
			key:     key,
			want:    ErrTPMAttestationInvalid,
		},
		"the TPM refuses to certify": {
			tpm:  func(s *scriptedTPM) TrustedPlatformModule { s.certifyErr = errScripted; return s },
			key:  key,
			want: ErrCertifyFailed,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			keyAuth := tpmKeyAuth
			if tc.keyAuth != nil {
				keyAuth = *tc.keyAuth
			}
			payload, err := Setup(keyAuth, tc.tpm(workingTPM(t)), tc.key, nil)
			assert.ErrorIs(t, err, tc.want)
			assert.Nil(t, payload)
		})
	}
}

func TestSetupJoinsTheTPMsCause(t *testing.T) {
	tpm := workingTPM(t)
	tpm.certifyErr = errScripted

	_, err := Setup(tpmKeyAuth, tpm, &types.KeyAttributes{CN: "device"}, nil)
	assert.ErrorIs(t, err, ErrCertifyFailed)
	assert.ErrorIs(t, err, errScripted)
}

// Every alg Setup can emit must be one the verifier maps back to the same
// signature algorithm, or a device would answer in a dialect the server
// cannot read.
func TestCOSEAlgorithmsRoundTripThroughTheVerifier(t *testing.T) {
	require.NotEmpty(t, coseAlgorithms)
	for signatureAlgorithm, alg := range coseAlgorithms {
		t.Run(signatureAlgorithm.String(), func(t *testing.T) {
			back, err := coseSignatureAlgorithm(int64(alg))
			require.NoError(t, err)
			assert.Equal(t, signatureAlgorithm, back)
		})
	}
	_, mapped := coseAlgorithms[x509.PureEd25519]
	assert.False(t, mapped, "a TPM IAK cannot sign with Ed25519")
	assert.Equal(t, webauthncose.AlgPS256, coseAlgorithms[x509.SHA256WithRSAPSS], "the default IAK answers with PS256")
}
