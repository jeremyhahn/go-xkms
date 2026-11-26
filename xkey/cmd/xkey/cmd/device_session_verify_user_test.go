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

package cmd

import (
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// verifyUserThroughBackend connects a PhoneKeyBackend to device over an
// in-memory transport, with live attestation and user verification wired
// as newPairedDeviceBackendConfig wires them, and returns the result of one
// VerifyUser call for rpName. trusted is the CA the desktop trusts.
func verifyUserThroughBackend(t *testing.T, trusted *attesttest.CA, dak *attesttest.DAK, device *attesttest.Phone, rpName string) error {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	record := &PairedDevice{
		Name:                       "bound",
		Address:                    "00:11:22:33:44:55",
		DeviceFingerprint:          hex.EncodeToString(dak.Fingerprint()),
		AttestationProtocolVersion: pairingproto.AttestProtocolV2,
	}
	loadTrust := func() (*xkms.AndroidDeviceTrust, error) {
		return &xkms.AndroidDeviceTrust{Roots: trusted.Pool(), Applications: attesttest.Applications()}, nil
	}

	localKey, err := bootstrap.GenerateNoiseStaticKey()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	initiator, responder := attesttest.NewMemTransportPair()
	backend, err := phone.NewPhoneKeyBackendWithTransport(&phone.PhoneKeyBackendConfig{
		LocalStaticKey:            localKey,
		OwnsStaticKey:             true,
		ExpectedRemoteStatic:      device.StaticPublicKey(),
		ExpectedDeviceFingerprint: dak.Fingerprint(),
		RequireLiveAttestation:    true,
		LiveAttest:                attestation.NewLiveAttestor(attestation.DeviceBindingFor(*record), loadTrust, logger),
		VerifyUser:                attestation.NewUserVerifier(loadTrust, logger),
		OperationTimeout:          10 * time.Second,
		Logger:                    logger,
	}, initiator)
	require.NoError(t, err)
	defer func() { require.NoError(t, backend.Close()) }()

	// Two exchanges: the reconnect's local.attestDevice, then local.verifyUser.
	done := make(chan error, 1)
	device.Serve(ctx, t, responder, true, 2, done)

	require.NoError(t, backend.Connect(ctx), "the device must still pass the reconnect's liveness proof")
	verifyErr := backend.VerifyUser(ctx, rpName)
	require.NoError(t, <-done, "phone responder failed")
	return verifyErr
}

// TestPhoneKeyBackendVerifyUser_ThroughAttestedPhone drives ruling 167 end to
// end: a paired phone answers local.verifyUser with its user-verification key
// and the desktop checks the Google-root chain and the fresh signature.
func TestPhoneKeyBackendVerifyUser_ThroughAttestedPhone(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())

	t.Run("a biometric-bound key under the trusted root verifies the user", func(t *testing.T) {
		device := attesttest.NewPairedPhone(t, dak, dak.Fingerprint())
		device.UVK = attesttest.NewUVK(t, ca, attesttest.UserVerificationKeyClaims())

		require.NoError(t, verifyUserThroughBackend(t, ca, dak, device, "example.com"))
		require.Equal(t, "example.com", device.VerifyUserRPName(), "the phone is asked on behalf of the RP")
	})

	t.Run("a token with no RP is asked for on behalf of the authenticator", func(t *testing.T) {
		device := attesttest.NewPairedPhone(t, dak, dak.Fingerprint())
		device.UVK = attesttest.NewUVK(t, ca, attesttest.UserVerificationKeyClaims())

		require.NoError(t, verifyUserThroughBackend(t, ca, dak, device, ""))
		require.Equal(t, phone.VerifyUserAuthenticatorName, device.VerifyUserRPName())
	})

	t.Run("a key under an untrusted root is refused", func(t *testing.T) {
		rogue := attesttest.NewCA(t, "Rogue Attestation Root")
		device := attesttest.NewPairedPhone(t, dak, dak.Fingerprint())
		device.UVK = attesttest.NewUVK(t, rogue, attesttest.UserVerificationKeyClaims())

		require.ErrorIs(t, verifyUserThroughBackend(t, ca, dak, device, "example.com"), attestation.ErrUserVerificationFailed)
	})

	t.Run("a signature that does not cover this challenge is refused", func(t *testing.T) {
		device := attesttest.NewPairedPhone(t, dak, dak.Fingerprint())
		device.UVK = attesttest.NewUVK(t, ca, attesttest.UserVerificationKeyClaims())
		device.MutateVerifyUser = func(r *pairingproto.LocalVerifyUserResult) {
			r.Signature[len(r.Signature)-1] ^= 0xff
		}

		require.ErrorIs(t, verifyUserThroughBackend(t, ca, dak, device, "example.com"), attestation.ErrUserVerificationFailed)
	})
}
