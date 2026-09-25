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

package xkms_test

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend/avr"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time proof the AVR aliases ARE the upstream types rather than
// lookalikes, following the peer and DICE surfaces.
//
// A lookalike compiles, passes every test in this package, and fails at the one
// place it matters: a consumer handing a value across the SDK boundary into the
// canonical implementation. Assignability in both directions rules that out.
var (
	_ avr.Config                = xkms.AVRConfig{}
	_ xkms.AVRConfig            = avr.Config{}
	_ avr.AttestationConfig     = xkms.AVRAttestationConfig{}
	_ xkms.AVRAttestationConfig = avr.AttestationConfig{}
	_ avr.Attestation           = xkms.AVRAttestation{}
	_ xkms.AVRAttestation       = avr.Attestation{}
	_ avr.Identity              = xkms.AVRIdentity{}
	_ xkms.AVRIdentity          = avr.Identity{}
	_ avr.Health                = xkms.AVRHealth{}
	_ xkms.AVRHealth            = avr.Health{}
	_ avr.Algorithms            = xkms.AVRAlgorithms{}
	_ xkms.AVRAlgorithms        = avr.Algorithms{}
	_ *avr.Backend              = (*xkms.AVRBackend)(nil)
	_ *xkms.AVRBackend          = (*avr.Backend)(nil)
	_ *avr.DeviceKey            = (*xkms.AVRDeviceKey)(nil)
	_ *xkms.AVRDeviceKey        = (*avr.DeviceKey)(nil)
	_ avr.Algorithm             = xkms.AVRAlgorithmECDSAP256SHA256
	_ xkms.AVRAlgorithm         = avr.AlgorithmEd25519
)

// TestAVRBackendIsConstructableFromTheSDK is the finding this file answers.
//
// BackendTypeAVR was exported on its own: a label for a capability with no way
// to configure or construct it, which left a consumer needing
// go-xkms/pkg/backend/avr -- an import go-trusted-platform's layer guard
// refuses outright. Reaching the constructor and its refusals through the SDK
// is what makes the backend usable rather than merely named.
func TestAVRBackendIsConstructableFromTheSDK(t *testing.T) {
	require.NotNil(t, xkms.NewAVRBackend)
	require.NotNil(t, xkms.DefaultAVRConfig)

	config := xkms.DefaultAVRConfig()
	require.NotNil(t, config)
	assert.Equal(t, xkms.AVRDefaultKeyCN, config.KeyCN)
	assert.Equal(t, xkms.AVRDefaultRequestTimeout, config.RequestTimeout)

	// The enum value and the backend it names are reachable from the same
	// place, which was the whole complaint.
	assert.Equal(t, xkms.BackendTypeAVR, (&avr.Backend{}).Type())

	// A refusal the constructor makes, classified through the SDK's sentinel
	// rather than through pkg/.
	backend, err := xkms.NewAVRBackend(context.Background(), nil, nil)
	require.Error(t, err)
	assert.Nil(t, backend)
	assert.ErrorIs(t, err, xkms.ErrAVRNilConfig)

	backend, err = xkms.NewAVRBackend(context.Background(), config, nil)
	require.Error(t, err)
	assert.Nil(t, backend)
	assert.ErrorIs(t, err, xkms.ErrAVRNilDevice)
}

// TestAVRErrorsAreTheCanonicalSentinels pins identity rather than equality, for
// the reason the DICE surface does: an alias to a copy compiles and never
// matches under errors.Is.
func TestAVRErrorsAreTheCanonicalSentinels(t *testing.T) {
	pairs := []struct {
		name string
		sdk  error
		pkg  error
	}{
		{"nil config", xkms.ErrAVRNilConfig, avr.ErrNilConfig},
		{"nil device", xkms.ErrAVRNilDevice, avr.ErrNilDevice},
		{"backend closed", xkms.ErrAVRBackendClosed, avr.ErrBackendClosed},
		{"unknown key", xkms.ErrAVRUnknownKey, avr.ErrUnknownKey},
		{"invalid nonce", xkms.ErrAVRInvalidNonce, avr.ErrInvalidNonce},
		{"signing unsupported", xkms.ErrAVRSigningUnsupported, avr.ErrSigningUnsupported},
		{"generation unsupported", xkms.ErrAVRGenerationUnsupported, avr.ErrGenerationUnsupported},
		{"malformed certificate", xkms.ErrAVRMalformedCertificate, avr.ErrMalformedCertificate},
		{"unknown crypto tier", xkms.ErrAVRUnknownCryptoTier, avr.ErrUnknownCryptoTier},
		{"command unavailable", xkms.ErrAVRCommandUnavailable, avr.ErrCommandUnavailable},
		{"device unreachable", xkms.ErrAVRDeviceUnreachable, avr.ErrDeviceUnreachable},
		{"trust store init", xkms.ErrAVRTrustStoreInit, avr.ErrTrustStoreInit},
	}

	for _, pair := range pairs {
		t.Run(pair.name, func(t *testing.T) {
			assert.Same(t, pair.pkg, pair.sdk, "the SDK re-exports a copy rather than the sentinel")
		})
	}
}

// The format string is the one the ACME challenge uses for the same evidence.
// Two names for one format is how a caller routing on it ends up with a branch
// that never runs.
func TestAVRFormatMatchesTheChallengeFormat(t *testing.T) {
	assert.Equal(t, "dice", xkms.AVRFormatDICE)
}
