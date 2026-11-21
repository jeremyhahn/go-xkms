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

// possessionMeasurements is the measurements claim (273) carrying
// possessionApplicationEvidence, in device-attest-01's pinned shape: the
// test devices' alias certificates and possession requests both carry it.
var possessionMeasurements, _ = hex.DecodeString("81821901025854a50050bcc710071a6653c1967ef0d3d5ede421016374667702a2181f6374667718210103a111a20782015820ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad1818636170700c00")

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
			name: "no reference is a bad request with the default config",
			arrange: func(t *testing.T, setup *deviceBindSetup) {
				setReference(setup, nil)
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
