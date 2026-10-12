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

package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAnswerCredentialChallenge_NilKey_Error proves AnswerCredentialChallenge
// refuses a nil ActivationKey with the typed ErrActivationKeyRequired,
// before it ever touches the TPM (a zero-value *TPM2, which would panic on
// any real TPM command, is enough to prove this).
func TestAnswerCredentialChallenge_NilKey_Error(t *testing.T) {
	tpm := &TPM2{}
	_, err := tpm.AnswerCredentialChallenge(nil, &CredentialChallenge{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrActivationKeyRequired)
}

// TestAnswerCredentialChallenge_NilChallenge_Error proves
// AnswerCredentialChallenge refuses a nil CredentialChallenge with the typed
// ErrCredentialChallengeRequired, before it ever touches the TPM.
func TestAnswerCredentialChallenge_NilChallenge_Error(t *testing.T) {
	tpm := &TPM2{}
	_, err := tpm.AnswerCredentialChallenge(&ActivationKey{}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCredentialChallengeRequired)
}

// TestTransientEKTemplate_MatchesCertificateKey proves the transient EK is
// built from the TCG low-range template matching the certificate's key:
// L-1 (RSA-2048) and L-2 (ECC NIST P-256).
func TestTransientEKTemplate_MatchesCertificateKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	got, err := transientEKTemplate(ekCertIndexRSA2048, &x509.Certificate{PublicKey: &rsaKey.PublicKey})
	require.NoError(t, err)
	assert.Equal(t, tpm2.RSAEKTemplate, got)

	got, err = transientEKTemplate(ekCertIndexECCP256, &x509.Certificate{PublicKey: &eccKey.PublicKey})
	require.NoError(t, err)
	assert.Equal(t, tpm2.ECCEKTemplate, got)
}

// TestTransientEKTemplate_Unsupported proves every certificate with no
// low-range template -- another key size or curve, another key type, or a
// certificate in the high range -- is refused with ErrEKTemplateUnsupported.
func TestTransientEKTemplate_Unsupported(t *testing.T) {
	rsa3072, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name  string
		index tpm2.TPMHandle
		key   crypto.PublicKey
	}{
		{"RSA-3072", ekCertIndexRSA2048, &rsa3072.PublicKey},
		{"P-384", ekCertIndexECCP256, &p384.PublicKey},
		{"Ed25519", ekCertIndexRSA2048, edPub},
		{"high range", ekCertHighRangeStart, &rsa2048.PublicKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := transientEKTemplate(tt.index, &x509.Certificate{PublicKey: tt.key})
			assert.ErrorIs(t, err, ErrEKTemplateUnsupported)
		})
	}
}
