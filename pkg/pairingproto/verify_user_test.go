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

package pairingproto

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyUserVerificationGenesisChallenge(t *testing.T) {
	t.Run("accepts the prefix alone and with reserved trailing bytes", func(t *testing.T) {
		require.NoError(t, VerifyUserVerificationGenesisChallenge([]byte(UserVerificationGenesisChallenge)))
		require.NoError(t, VerifyUserVerificationGenesisChallenge(
			append([]byte(UserVerificationGenesisChallenge), 0x01, 0x02)))
	})

	t.Run("refuses a DAK genesis challenge", func(t *testing.T) {
		err := VerifyUserVerificationGenesisChallenge([]byte(AttestGenesisChallenge + "-padding"))
		require.ErrorIs(t, err, ErrUserVerificationGenesisChallenge)
		assert.NotErrorIs(t, err, ErrAttestGenesisChallenge)
	})

	t.Run("refuses a challenge shorter than the prefix", func(t *testing.T) {
		err := VerifyUserVerificationGenesisChallenge([]byte("xkey"))
		require.ErrorIs(t, err, ErrUserVerificationGenesisChallenge)
		assert.Contains(t, err.Error(), "want at least")
	})

	t.Run("a UVK genesis challenge is not a DAK one", func(t *testing.T) {
		require.ErrorIs(t, VerifyGenesisChallenge([]byte(UserVerificationGenesisChallenge)), ErrAttestGenesisChallenge)
	})
}

// TestVerifyUserWireFieldNames pins the JSON the Kotlin peer reads and writes:
// a renamed field silently decodes to its zero value on the other side.
func TestVerifyUserWireFieldNames(t *testing.T) {
	params, err := json.Marshal(LocalVerifyUserParams{
		ProtocolVersion: AttestProtocolV2,
		Nonce:           []byte{0x01},
		RPName:          "example.com",
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"protocolVersion":2,"nonce":"AQ==","rpName":"example.com"}`, string(params))

	result, err := json.Marshal(LocalVerifyUserResult{
		ProtocolVersion:    AttestProtocolV2,
		CertificateChain:   [][]byte{{0x02}},
		Signature:          []byte{0x03},
		SignatureAlgorithm: AttestSignatureES256,
	})
	require.NoError(t, err)
	assert.JSONEq(t,
		`{"protocolVersion":2,"certificateChain":["Ag=="],"signature":"Aw==","signatureAlgorithm":"ES256"}`,
		string(result))

	var decoded LocalVerifyUserResult
	require.Error(t, json.Unmarshal([]byte(`{"signature":"not base64!"}`), &decoded),
		"a malformed signature is a decode error, never an empty signature")
}

func TestVerifyUserIsALocalMethod(t *testing.T) {
	assert.Equal(t, "local.verifyUser", MethodLocalVerifyUser)
	assert.True(t, IsLocalMethod(MethodLocalVerifyUser))
	assert.False(t, IsLocalMethod("local.verifyuser"), "method names are case-sensitive")
}

func TestValidateVerifyUserRPName(t *testing.T) {
	t.Run("accepts a domain, a display name and the maximum length", func(t *testing.T) {
		require.NoError(t, ValidateVerifyUserRPName("example.com"))
		require.NoError(t, ValidateVerifyUserRPName("Exämple Bank"))
		require.NoError(t, ValidateVerifyUserRPName(strings.Repeat("a", VerifyUserRPNameMaxLen)))
	})

	refused := map[string]string{
		"empty":        "",
		"over-long":    strings.Repeat("a", VerifyUserRPNameMaxLen+1),
		"invalid UTF8": "example\xff.com",
	}
	for name, rpName := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			require.ErrorIs(t, ValidateVerifyUserRPName(rpName), ErrVerifyUserRPName)
		})
	}
}

func TestBuildVerifyUserTranscript(t *testing.T) {
	nonce, binding, fingerprint := vecRamp(0x00), vecRamp(0x40), vecRamp(0x80)

	t.Run("appends the length-prefixed RP name to the verify-user transcript", func(t *testing.T) {
		base, err := BuildAttestTranscript(AttestPurposeVerifyUser, nonce, binding, fingerprint)
		require.NoError(t, err)

		transcript, err := BuildVerifyUserTranscript(nonce, binding, fingerprint, "rp")
		require.NoError(t, err)
		assert.Equal(t, append(base, 0x02, 'r', 'p'), transcript)
	})

	t.Run("a different RP name is a different transcript", func(t *testing.T) {
		a, err := BuildVerifyUserTranscript(nonce, binding, fingerprint, "a.example")
		require.NoError(t, err)
		b, err := BuildVerifyUserTranscript(nonce, binding, fingerprint, "b.example")
		require.NoError(t, err)
		assert.NotEqual(t, a, b)
	})

	t.Run("refuses an invalid RP name", func(t *testing.T) {
		_, err := BuildVerifyUserTranscript(nonce, binding, fingerprint, "")
		require.ErrorIs(t, err, ErrVerifyUserRPName)
	})

	t.Run("refuses a short nonce", func(t *testing.T) {
		_, err := BuildVerifyUserTranscript(nonce[:31], binding, fingerprint, "example.com")
		require.ErrorIs(t, err, ErrAttestTranscriptField)
	})
}
