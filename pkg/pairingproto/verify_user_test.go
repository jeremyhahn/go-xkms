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
	"crypto/sha256"
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

// TestVerifyUserRefusalCodes pins the wire code of each phone-side refusal of
// local.verifyUser (#1712) and the typed error the desktop maps it to. The
// four must stay apart: a refusal the desktop cannot tell from another is one
// it cannot report.
func TestVerifyUserRefusalCodes(t *testing.T) {
	refusals := []struct {
		name     string
		code     int
		wantCode int
		want     error
	}{
		{"user cancelled", ErrorCodeUserCancelled, -32001, ErrUserCancelled},
		{"no biometric enrolled", ErrorCodeVerifyUserNotEnrolled, -32041, ErrUserVerificationNotEnrolled},
		{"lockout", ErrorCodeVerifyUserLockout, -32042, ErrUserVerificationLockout},
		{"not paired", ErrorCodeNotPaired, -32043, ErrNotPaired},
	}
	for i, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantCode, tt.code)
			err := MapVerifyUserRPCError(&RPCError{Code: tt.code, Message: "refused"})
			require.ErrorIs(t, err, tt.want)
			for j, other := range refusals {
				if j != i {
					assert.NotErrorIs(t, err, other.want, "%s must not read as %s", tt.name, other.name)
				}
			}
		})
	}

	t.Run("other codes map as any response", func(t *testing.T) {
		assert.ErrorIs(t, MapVerifyUserRPCError(&RPCError{Code: ErrorCodeBiometricFailed}), ErrBiometricFailed)
		assert.ErrorIs(t, MapVerifyUserRPCError(&RPCError{Code: -1}), ErrProtocolError)
		assert.NoError(t, MapVerifyUserRPCError(nil))
	})
}

func TestValidateVerifyUserRPName(t *testing.T) {
	t.Run("accepts a name up to the bound", func(t *testing.T) {
		require.NoError(t, ValidateVerifyUserRPName("example.com"))
		require.NoError(t, ValidateVerifyUserRPName(strings.Repeat("a", VerifyUserRPNameMaxLen)))
		require.NoError(t, ValidateVerifyUserRPName("Bücherei Zürich"), "the bound is in bytes of UTF-8, not ASCII only")
	})

	t.Run("refuses a name over the bound", func(t *testing.T) {
		err := ValidateVerifyUserRPName(strings.Repeat("a", VerifyUserRPNameMaxLen+1))
		require.ErrorIs(t, err, ErrVerifyUserRPName)
		assert.Contains(t, err.Error(), "65 bytes")
	})

	t.Run("counts bytes, not characters", func(t *testing.T) {
		// 33 two-byte characters: 33 runes, 66 bytes.
		require.ErrorIs(t, ValidateVerifyUserRPName(strings.Repeat("é", 33)), ErrVerifyUserRPName)
	})

	t.Run("refuses an empty name", func(t *testing.T) {
		require.ErrorIs(t, ValidateVerifyUserRPName(""), ErrVerifyUserRPName)
	})

	t.Run("refuses a name that is not UTF-8", func(t *testing.T) {
		require.ErrorIs(t, ValidateVerifyUserRPName("example\xff.com"), ErrVerifyUserRPName)
	})

	t.Run("refuses a control character the prompt would render", func(t *testing.T) {
		require.ErrorIs(t, ValidateVerifyUserRPName("example.com\nApproved by your bank"), ErrVerifyUserRPName)
		require.ErrorIs(t, ValidateVerifyUserRPName("example\u0085.com"), ErrVerifyUserRPName, "a C1 control too")
	})
}

func TestBuildVerifyUserTranscript(t *testing.T) {
	nonce := vecRamp(0x00)
	binding := vecRamp(0x40)
	fingerprint := vecRamp(0x80)

	t.Run("is the verify-user attest transcript followed by the RP name hash", func(t *testing.T) {
		transcript, err := BuildVerifyUserTranscript("example.com", nonce, binding, fingerprint)
		require.NoError(t, err)

		base, err := BuildAttestTranscript(AttestPurposeVerifyUser, nonce, binding, fingerprint)
		require.NoError(t, err)
		rpNameHash := sha256.Sum256([]byte("example.com"))
		assert.Equal(t, append(base, rpNameHash[:]...), transcript)
	})

	t.Run("binds the RP name", func(t *testing.T) {
		first, err := BuildVerifyUserTranscript("example.com", nonce, binding, fingerprint)
		require.NoError(t, err)
		second, err := BuildVerifyUserTranscript("example.org", nonce, binding, fingerprint)
		require.NoError(t, err)
		assert.NotEqual(t, first, second, "a signature for one RP must not verify for another")
	})

	t.Run("refuses an invalid RP name", func(t *testing.T) {
		_, err := BuildVerifyUserTranscript(strings.Repeat("a", VerifyUserRPNameMaxLen+1), nonce, binding, fingerprint)
		require.ErrorIs(t, err, ErrVerifyUserRPName)
	})

	t.Run("refuses a malformed attest field", func(t *testing.T) {
		_, err := BuildVerifyUserTranscript("example.com", nonce[:31], binding, fingerprint)
		require.ErrorIs(t, err, ErrAttestTranscriptField)
	})
}
