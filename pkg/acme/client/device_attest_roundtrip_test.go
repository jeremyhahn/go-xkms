//go:build codec_json && tpm_simulator

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

package client

import (
	"context"
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests run the Go client's DeviceAttest against the real ACME server
// handlers (pkg/acme/server/handlers) and the real device-attest-01 verifier.
// The server refuses a challenge whose attested identity is not the order's
// identifier (go-xkms#828), so a client that names anything but the device's
// own identity -- the IP address it used to send -- cannot get a certificate.
//
// The client opens no listener and names no address: draft-ietf-acme-device-
// attest has it POST the attestation, and the test server is built with no way
// to reach the device at all.

// TestDeviceAttestRoundTripAgainstTheRealServer is the client-to-server round
// trip: the client names the device's own identity, the real handler
// validates the challenge against the real verifier, and the certificate that
// finalization issues is for the attested key and carries that identity.
func TestDeviceAttestRoundTripAgainstTheRealServer(t *testing.T) {
	issuer := newAttestationCA(t)
	adapter := newSimulatedDeviceAdapter(t, issuer)
	server := startDeviceAttestServer(t, issuer.cert, issuer.key, issuer.verifier(t))
	client := newDeviceAttestRoundTripClient(t, server)

	cert, err := client.DeviceAttest(context.Background(), &EnrollmentConfig{
		Challenge:  string(ChallengeTypeDeviceAttest01),
		TPMModule:  adapter,
		CommonName: "device.example.com",
		Timeout:    10 * time.Second,
	})
	require.NoError(t, err)

	attested, err := adapter.CreateAttestedKey("device.example.com", "unused.keyauth")
	require.NoError(t, err)
	assert.True(t, cert.PublicKey.(*ecdsa.PublicKey).Equal(attested.Signer.Public()),
		"the certificate must be for the key the TPM attested")
	assert.Equal(t, "device.example.com", cert.Subject.CommonName)
	select {
	case issued := <-server.issued:
		assert.Equal(t, issued.Raw, cert.Raw)
	default:
		t.Fatal("the server issued no certificate")
	}
}

// impersonatingTPM is a device that claims an identity its AIK certificate
// does not carry.
type impersonatingTPM struct {
	*XKMSTPMAdapter
	claimed string
}

func (d impersonatingTPM) DeviceIdentity() (string, error) { return d.claimed, nil }

// A device that names another device's identity is refused: the evidence is
// genuine, but the attested identity is not the order's identifier, so the
// challenge is unauthorized and no certificate is issued.
func TestDeviceAttestRoundTripRefusesAnotherDevicesIdentity(t *testing.T) {
	issuer := newAttestationCA(t)
	adapter := newSimulatedDeviceAdapter(t, issuer)
	server := startDeviceAttestServer(t, issuer.cert, issuer.key, issuer.verifier(t))
	client := newDeviceAttestRoundTripClient(t, server)

	cert, err := client.DeviceAttest(context.Background(), &EnrollmentConfig{
		Challenge:  string(ChallengeTypeDeviceAttest01),
		TPMModule:  impersonatingTPM{XKMSTPMAdapter: adapter, claimed: "some-other-device"},
		CommonName: "device.example.com",
		Timeout:    10 * time.Second,
	})
	require.ErrorContains(t, err, "urn:ietf:params:acme:error:unauthorized")
	assert.Nil(t, cert)
	assert.Empty(t, server.issued, "no certificate may be issued for an identity the evidence does not carry")
}

func TestXKMSTPMAdapterDeviceIdentityIsTheIAKCertificatesPermanentIdentifier(t *testing.T) {
	adapter := newSimulatedDeviceAdapter(t, newAttestationCA(t))

	identity, err := adapter.DeviceIdentity()
	require.NoError(t, err)
	assert.Equal(t, simulatedDeviceIdentity, identity)
}

// device-attest-01 contacts no device, so its configuration needs no address:
// the server never dials one and the client opens no listener. The challenges
// whose server does dial the device still require it.
func TestEnrollmentConfigValidate_AddressByChallenge(t *testing.T) {
	adapter := newSimulatedDeviceAdapter(t, newAttestationCA(t))

	t.Run("device-attest-01 needs no address", func(t *testing.T) {
		config := &EnrollmentConfig{Challenge: string(ChallengeTypeDeviceAttest01), TPMModule: adapter}
		require.NoError(t, config.Validate())
	})

	for _, challenge := range []ChallengeType{ChallengeTypeEnroll01, ChallengeTypeEndorse01} {
		t.Run(string(challenge)+" requires the address the server dials", func(t *testing.T) {
			config := &EnrollmentConfig{Challenge: string(challenge), TPMModule: adapter}
			assert.ErrorIs(t, config.Validate(), ErrInvalidIPAddress)
		})
	}
}
