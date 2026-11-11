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

package attestation

import (
	"context"
	"errors"
	"log/slog"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	"github.com/jeremyhahn/go-xkms/sdk/go/userverify"
)

// On-demand user verification (ruling 167): the desktop asks the phone to
// verify its user now, and judges the user-verification key's answer with the
// library decision, userverify.Verify, before the FIDO2 authenticator mints a
// pinUvAuthToken. This file is the exchange on the pairing session; the wire
// contract and the check order are xkey/docs/phone-hsm/engineering.md,
// "On-demand user verification".

// ErrUserVerificationExchangeFailed indicates the verify-user exchange itself
// failed — transport, encoding, a mismatched response or an RPC error such as
// a cancelled prompt — rather than the evidence being bad.
var ErrUserVerificationExchangeFailed = errors.New("attestation: user verification exchange failed")

// ErrUserVerificationTrustUnavailable indicates the trust a verification is
// judged against could not be loaded — devices.yaml or the trust store could
// not be read — so no prompt was sent and the user was neither verified nor
// refused.
var ErrUserVerificationTrustUnavailable = errors.New("attestation: user verification trust could not be loaded")

// NewUserVerifier builds the verify-user exchange a phone backend runs on its
// established session when the authenticator needs a user verification. It
// draws a fresh challenge for the relying party, sends local.verifyUser, refuses a response that
// does not answer the request, and judges the answer with userverify.Verify.
//
// loadTrust is called per verification, as for NewLiveAttestor, so a root the
// operator installs takes effect on the next use.
func NewUserVerifier(
	loadTrust func() (*xkms.AndroidDeviceTrust, error),
	logger *slog.Logger,
) pairingproto.VerifyUserFunc {
	if logger == nil {
		logger = slog.Default()
	}

	return func(ctx context.Context, exchange pairingproto.RPCExchange, channelBinding []byte, rpName string) error {
		trust, err := loadTrust()
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrUserVerificationTrustUnavailable, Cause: err}
		}

		challenge, err := userverify.NewChallenge(channelBinding, rpName)
		if err != nil {
			return err
		}

		req := pairingproto.NewRequest(pairingproto.MethodLocalVerifyUser, challenge.Params())
		req.Generation = attestRequestGeneration

		resp, err := exchange(ctx, req)
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrUserVerificationExchangeFailed, Cause: err}
		}

		// Step 1. Checked before the RPC error, since a refusal of some other
		// request is not ours.
		if resp.ID != req.ID || resp.Generation != req.Generation {
			mismatch := &ResponseMismatchError{
				RequestID: req.ID, RequestGeneration: req.Generation,
				ResponseID: resp.ID, ResponseGeneration: resp.Generation,
			}
			logger.Error("user verification refused: response does not answer the request", "error", mismatch)
			return &SentinelCauseError{Sentinel: ErrUserVerificationExchangeFailed, Cause: mismatch}
		}
		if resp.Error != nil {
			logger.Error("user verification refused by the phone",
				"code", resp.Error.Code, "message", resp.Error.Message)
			return &SentinelCauseError{Sentinel: ErrUserVerificationExchangeFailed, Cause: resp.Error}
		}

		result, err := pairingproto.DecodeResult[pairingproto.LocalVerifyUserResult](resp)
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrUserVerificationExchangeFailed, Cause: err}
		}

		if err := userverify.Verify(result, challenge, trust); err != nil {
			logger.Error("user verification refused", "error", err)
			return err
		}
		return nil
	}
}
