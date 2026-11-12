//go:build codec_json

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

package handlers

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
)

// possessionApplicationEvidence is the application evidence
// devicePossessionCSR's measurements carry.
var possessionApplicationEvidence, _ = hex.DecodeString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

// newRequiringRegistry installs on service a device registry whose DICE policy
// requires a registered application reference, as serviceRegistry installs
// the default one.
func newRequiringRegistry(t *testing.T, service *RestService) *registeredDevices {
	t.Helper()
	registry := deviceRegistry{}
	verifier, err := deviceattest01.NewTrustAnchorVerifier(deviceattest01.TrustAnchors{
		Devices: registry,
		DICE:    deviceattest01.DICEPolicy{RequireApplicationReference: true},
	})
	require.NoError(t, err)
	registered := &registeredDevices{TrustAnchorVerifier: verifier, registry: registry}
	if service.attestingVerifiers == nil {
		service.attestingVerifiers = make(map[string]common.AttestingVerifier)
	}
	service.attestingVerifiers[common.ChallengeTypeDeviceAttest01] = NewDeviceAttestVerifier(registered)
	return registered
}

// TestBindDeviceAttestationKey_ApplicationReference is SPEC.md:41's open item
// at the finalize handler: a DICE possession request's application evidence
// is matched against the reference the device's provisioning record
// registers.
func TestBindDeviceAttestationKey_ApplicationReference(t *testing.T) {
	require.Len(t, possessionApplicationEvidence, deviceattest01.ApplicationReferenceSize)
	flipped := bytes.Clone(possessionApplicationEvidence)
	flipped[len(flipped)-1] ^= 0xff
	mismatch := deviceattest01.ErrPossessionApplicationEvidenceMismatch.Error()

	tests := []struct {
		name      string
		arrange   func(t *testing.T, setup *deviceBindSetup)
		wantType  string
		wantInMsg string
	}{
		{
			name: "a matching reference issues",
			arrange: func(t *testing.T, setup *deviceBindSetup) {
				setReference(setup, possessionApplicationEvidence)
			},
		},
		{
			name: "a mismatched reference is a bad request",
			arrange: func(t *testing.T, setup *deviceBindSetup) {
				setReference(setup, flipped)
			},
			wantType:  common.ErrTypeBadCSR,
			wantInMsg: mismatch,
		},
		{
			name:    "no reference is admitted by default",
			arrange: func(t *testing.T, setup *deviceBindSetup) {},
		},
		{
			name: "no reference under a policy that requires one is a bad request",
			arrange: func(t *testing.T, setup *deviceBindSetup) {
				newRequiringRegistry(t, setup.service).provision(t, setup.ueid, setup.key)
			},
			wantType:  common.ErrTypeBadCSR,
			wantInMsg: mismatch,
		},
		{
			name: "a malformed reference is unauthorized",
			arrange: func(t *testing.T, setup *deviceBindSetup) {
				setReference(setup, possessionApplicationEvidence[:deviceattest01.ApplicationReferenceSize-1])
			},
			wantType: common.ErrTypeUnauthorized,
		},
		{
			name: "a withdrawn device is unauthorized",
			arrange: func(t *testing.T, setup *deviceBindSetup) {
				setup.registry.withdraw(setup.ueid)
			},
			wantType: common.ErrTypeUnauthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := newDeviceBindSetup(t)
			tt.arrange(t, setup)
			csr := deviceAttestCSR(t, setup.key, setup.rec)

			problem := setup.service.bindDeviceAttestationKey(context.Background(), setup.rec, deviceAttestOrder(setup.rec), csr)
			if tt.wantType == "" {
				require.Nil(t, problem)
				return
			}
			requireProblem(t, problem, tt.wantType)
			if tt.wantInMsg != "" {
				require.Contains(t, problem.Detail, tt.wantInMsg)
			}
			if tt.wantType == common.ErrTypeUnauthorized {
				// The registry's cause is logged, never returned.
				require.NotContains(t, problem.Detail, "32 bytes")
				require.NotContains(t, problem.Detail, deviceattest01.ErrProvisioningRecordInvalid.Error())
			}
		})
	}
}

// setReference registers reference as the application reference of the
// device setup provisioned.
func setReference(setup *deviceBindSetup, reference []byte) {
	setup.registry.registry[hex.EncodeToString(setup.ueid)].ApplicationReference = bytes.Clone(reference)
}
