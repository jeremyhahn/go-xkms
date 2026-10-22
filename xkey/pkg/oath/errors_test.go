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

package oath

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testBase32Secret = "JBSWY3DPEHPK3PXP"

func TestDetailError(t *testing.T) {
	err := &DetailError{Err: ErrInvalidCredential, Detail: ": account name or issuer required"}

	require.Equal(t, ErrInvalidCredential.Error()+": account name or issuer required", err.Error())
	require.ErrorIs(t, err, ErrInvalidCredential)
	require.NotErrorIs(t, err, ErrInvalidSecret)
}

func TestSentinelCauseError(t *testing.T) {
	cause := io.ErrUnexpectedEOF
	err := &SentinelCauseError{Sentinel: ErrInvalidSecret, Cause: cause}

	require.Equal(t, ErrInvalidSecret.Error()+": "+cause.Error(), err.Error())
	require.ErrorIs(t, err, ErrInvalidSecret, "callers match the sentinel")
	require.ErrorIs(t, err, cause, "callers also reach the underlying cause")
	require.NotErrorIs(t, err, ErrInvalidCredential)
}

func TestWrappedError(t *testing.T) {
	cause := io.ErrShortBuffer
	err := &WrappedError{Msg: "oath: failed to generate secret", Err: cause}

	require.Equal(t, "oath: failed to generate secret: "+cause.Error(), err.Error())
	require.ErrorIs(t, err, cause)
}

func TestMessageError(t *testing.T) {
	err := &MessageError{Msg: "oath: something"}

	require.Equal(t, "oath: something", err.Error())
	require.Nil(t, errors.Unwrap(err))
}

func TestGenerator_GenerateAt_RejectsHOTP(t *testing.T) {
	cred, err := ParseURI("otpauth://hotp/Example:alice?secret=" + rfcTestSecret + "&issuer=Example&counter=0&algorithm=SHA256")
	require.NoError(t, err)
	gen, err := NewGenerator(cred)
	require.NoError(t, err)

	code, err := gen.GenerateAt(time.Unix(59, 0))

	require.Empty(t, code)
	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	require.Contains(t, msgErr.Error(), "TOTP")
}

func TestGenerateCredentialID_MatchesManualEntry(t *testing.T) {
	// The pairing bridge derives a credential ID with GenerateCredentialID
	// before the credential exists, so it must agree with the ID the
	// constructors assign.
	tests := []struct {
		name        string
		issuer      string
		accountName string
		want        string
	}{
		{name: "issuer and account", issuer: "GitHub", accountName: "Alice@Example.com", want: "github:alice@example.com"},
		{name: "issuer only", issuer: "GitHub", want: "github"},
		{name: "account only", accountName: "Alice", want: "alice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred, err := NewCredentialFromManualEntry(tt.accountName, tt.issuer, testBase32Secret)
			require.NoError(t, err)

			got := GenerateCredentialID(tt.issuer, tt.accountName)

			require.Equal(t, tt.want, got)
			require.Equal(t, cred.ID, got)
		})
	}
}

func TestGenerateCredentialID_EmptyInputsAreUnique(t *testing.T) {
	first := GenerateCredentialID("", "")
	second := GenerateCredentialID("", "")

	require.Regexp(t, `^oath-[0-9a-f]+$`, first)
	require.NotEqual(t, first, second)
}
