package phone

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator"
	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator/keybackend"
	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
)

// The phone backend is a UserVerifier whether or not it can verify a user, so
// it reports availability: the authenticator advertises uv only when it is.
var _ keybackend.UserVerificationAvailability = (*PhoneKeyBackend)(nil)

func TestUserVerificationAvailable_NoVerifierIsUnavailable(t *testing.T) {
	backend := &PhoneKeyBackend{
		cfg: &PhoneKeyBackendConfig{},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	backend.connected.Store(true)
	require.False(t, backend.UserVerificationAvailable())
}

func TestUserVerificationAvailable_ConfiguredVerifierIsAvailable(t *testing.T) {
	backend := connectedVerifyUserBackend(t, func(context.Context, pairingproto.RPCExchange, []byte, string) error {
		return nil
	})
	require.True(t, backend.UserVerificationAvailable())
	require.NoError(t, backend.VerifyUser(context.Background(), "example.com"))
	require.True(t, backend.UserVerificationAvailable(), "a phone that verifies stays available")
}

// A phone that answers local.verifyUser with method-not-found does not
// implement it: the backend stops reporting UV as available, and the refusal
// is unavailable (no uvRetries spent), so retries never block UV.
func TestUserVerificationAvailable_PeerWithoutVerifyUserIsUnavailable(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	backend := refusingPhone(t, func(ctx context.Context, exchange pairingproto.RPCExchange, _ []byte, _ string) error {
		resp, err := exchange(ctx, pairingproto.NewRequest(pairingproto.MethodLocalVerifyUser, nil))
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: %w", errVerifierRefused, resp.Error)
	}, pairingproto.ErrorCodeMethodNotFound)
	require.True(t, backend.UserVerificationAvailable(), "support is assumed until the phone refuses the method")

	err := backend.VerifyUser(context.Background(), "example.com")
	require.ErrorIs(t, err, keybackend.ErrUserVerificationUnavailable, "a missing method spends no uvRetries")
	require.False(t, backend.UserVerificationAvailable())
}

// An authenticator over the real phone backend without a configured verifier
// advertises no uv in getInfo.
func TestGetInfo_PhoneBackendWithoutVerifierAdvertisesNoUv(t *testing.T) {
	backend := &PhoneKeyBackend{
		cfg: &PhoneKeyBackendConfig{},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	auth, err := authenticator.NewAuthenticator(&authenticator.Config{
		UserPresenceHandler: authenticator.NewAutoGrantHandler(),
		Storage:             authenticator.NewMemoryStorage(),
		EnablePIN:           true,
		// The pinUvAuthToken surface, where uv=true promises the UV token
		// path; without it a phone's in-operation UV is the CTAP 2.0 form.
		EnableCredentialManagement: true,
		PINMinLength:               4,
		PINMaxRetries:              8,
		SupportedAlgorithms:        []int{authenticator.COSEAlgES256},
		KeyBackend:                 backend,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = auth.Close() })

	resp, err := auth.ProcessCBOR(authenticator.CmdGetInfo, nil)
	require.NoError(t, err)
	require.Equal(t, byte(authenticator.StatusOK), resp[0])
	var info struct {
		Options map[string]bool `cbor:"4,keyasint"`
	}
	require.NoError(t, cbor.Unmarshal(resp[1:], &info))
	uv, ok := info.Options["uv"]
	require.False(t, ok && uv, "uv is not advertised without a verifier")
}
