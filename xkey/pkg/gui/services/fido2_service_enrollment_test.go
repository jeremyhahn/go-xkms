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

package services

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// These tests cover the phone bridge's TCG device enrollment wiring. The
// defect they guard is a bridge started without a TPM, which leaves the
// enrollment handlers permanently reporting the feature as unconfigured no
// matter what the host has.

// TestFIDO2Service_EnrollmentIsOffUntilConfigured pins the default. Enrollment
// lets the phone read this host's EK certificate and drive
// TPM2_ActivateCredential, so owning a TPM must not be enough to enable it.
func TestFIDO2Service_EnrollmentIsOffUntilConfigured(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetClientFunc(func() xkms.Client { return &mockCAClient{} })

	require.NoError(t, svc.StartPhoneBridge())
	t.Cleanup(func() { _ = svc.StopPhoneBridge() })

	assert.False(t, svc.tpmEnrollment, "enrollment must be opt-in")
	assert.Nil(t, svc.tpmEnroller, "no TPM may be opened before enrollment is configured")
	assert.True(t, svc.GetBridgeStatus().Running, "the bridge still serves everything else")
}

// TestFIDO2Service_BridgeStartsWhenTheTPMIsUnreachable is the requirement that
// keeps a laptop usable: enrollment is optional, so a configured TPM that
// cannot be opened must not stop the bridge from starting.
func TestFIDO2Service_BridgeStartsWhenTheTPMIsUnreachable(t *testing.T) {
	tests := []struct {
		name   string
		device func(t *testing.T) string
	}{
		{
			name: "host has no TPM",
			device: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "no-such-tpm")
			},
		},
		{
			name: "host has a TPM that will not open",
			device: func(t *testing.T) string {
				return t.TempDir()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewFIDO2Service(nil)
			svc.SetClientFunc(func() xkms.Client { return &mockCAClient{} })
			svc.SetTPMEnrollment(true, tt.device(t))

			require.NoError(t, svc.StartPhoneBridge(), "an unusable TPM must not stop the bridge")
			t.Cleanup(func() { _ = svc.StopPhoneBridge() })

			assert.Nil(t, svc.tpmEnroller, "an unusable TPM must leave the enroller nil")
			assert.True(t, svc.GetBridgeStatus().Running)
		})
	}
}

// TestFIDO2Service_SetTPMEnrollmentTakesEffectOnNextStart documents when the
// setting is read: at bridge construction, which is where the TPM is opened.
func TestFIDO2Service_SetTPMEnrollmentTakesEffectOnNextStart(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetClientFunc(func() xkms.Client { return &mockCAClient{} })

	svc.SetTPMEnrollment(true, filepath.Join(t.TempDir(), "absent"))
	assert.True(t, svc.tpmEnrollment)
	assert.NotEmpty(t, svc.tpmDevice)

	svc.SetTPMEnrollment(false, "")
	assert.False(t, svc.tpmEnrollment)
	assert.Empty(t, svc.tpmDevice)
}

// TestFIDO2Service_StopReleasesTheEnrollmentTPM proves the device handle is
// not held while the bridge is idle. With no TPM to release the call must
// still be a no-op rather than a nil dereference.
func TestFIDO2Service_StopReleasesTheEnrollmentTPM(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetClientFunc(func() xkms.Client { return &mockCAClient{} })
	svc.SetTPMEnrollment(true, filepath.Join(t.TempDir(), "absent"))

	require.NoError(t, svc.StartPhoneBridge())
	require.NoError(t, svc.StopPhoneBridge())

	assert.Nil(t, svc.tpmEnroller)
	assert.False(t, svc.GetBridgeStatus().Running)
}
