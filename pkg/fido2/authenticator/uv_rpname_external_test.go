package authenticator_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator"
	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
)

// The authenticator refuses, before the UV ceremony, exactly the RP names the
// production phone verifier (pairingproto.ValidateVerifyUserRPName, reached
// through NewUserVerifier.NewChallenge) refuses before it contacts the phone.
// A name the verifier refuses but the authenticator passes would spend a
// uvRetries count with no verification attempted.
func TestValidateUserVerificationRPName_MatchesProductionVerifier(t *testing.T) {
	require.Equal(t, pairingproto.VerifyUserRPNameMaxLen, authenticator.UserVerificationRPNameMaxLen)

	for _, name := range []string{
		"example.com",
		strings.Repeat("a", pairingproto.VerifyUserRPNameMaxLen),
		strings.Repeat("a", pairingproto.VerifyUserRPNameMaxLen+1),
		strings.Repeat("é", 32),
		strings.Repeat("é", 33),
		"example\xff.com",
		"example.com\nApproved by your bank",
		"example\u0085.com",
		"example" + string(rune(0x202e)) + ".com", // a format character, not a control: accepted by both
	} {
		verifierErr := pairingproto.ValidateVerifyUserRPName(name)
		authErr := authenticator.ValidateUserVerificationRPName(name)
		if verifierErr != nil {
			require.ErrorIs(t, authErr, authenticator.ErrInvalidParameter, "%q is refused by the verifier", name)
		} else {
			assert.NoError(t, authErr, "%q is accepted by the verifier", name)
		}
	}
}
