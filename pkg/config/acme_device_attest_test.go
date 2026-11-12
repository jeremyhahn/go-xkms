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

package config

import (
	"errors"
	"testing"
)

// device-attest-01 verifies against configured trust anchors, so enabling it
// with none is a configuration the daemon must not start with.
func TestACMEConfig_Validate_DeviceAttestAnchors(t *testing.T) {
	tests := []struct {
		name       string
		challenges ACMEChallengesConfig
		wantErr    error
	}{
		{"disabled needs no anchors", ACMEChallengesConfig{HTTP01: true}, nil},
		{"enabled with no anchors is refused", ACMEChallengesConfig{DeviceAttest01: true}, ErrACMEDeviceAttestNoAnchors},
		{"enabled with empty anchor lists is refused", ACMEChallengesConfig{DeviceAttest01: true, DeviceAttest: ACMEDeviceAttestConfig{TPMRoots: []string{}, DICERoots: []string{}}}, ErrACMEDeviceAttestNoAnchors},
		{"a policy flag is not an anchor", ACMEChallengesConfig{DeviceAttest01: true, DeviceAttest: ACMEDeviceAttestConfig{DICERequireMeasurement: true}}, ErrACMEDeviceAttestNoAnchors},
		{"a TPM root is enough", ACMEChallengesConfig{DeviceAttest01: true, DeviceAttest: ACMEDeviceAttestConfig{TPMRoots: []string{"/etc/xkms/tpm-root.pem"}}}, nil},
		{"a DICE root is enough", ACMEChallengesConfig{DeviceAttest01: true, DeviceAttest: ACMEDeviceAttestConfig{DICERoots: []string{"/etc/xkms/dice-root.pem"}}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := enabledACME()
			cfg.Challenges = tt.challenges
			if err := cfg.Validate(); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestACMEDeviceAttestConfig_HasAnchors(t *testing.T) {
	if (ACMEDeviceAttestConfig{}).HasAnchors() {
		t.Fatal("an empty configuration reported anchors")
	}
	if !(ACMEDeviceAttestConfig{DICERoots: []string{"root.pem"}}).HasAnchors() {
		t.Fatal("a configured DICE root was not reported")
	}
}

// TestLoad_ACMEDeviceAttestKeys pins the YAML names an operator writes: a
// misspelled key would load as nothing and leave device-attest-01 refusing to
// start with an error that does not mention the typo.
func TestLoad_ACMEDeviceAttestKeys(t *testing.T) {
	cfg, err := Load(writeConfigBody(t, "", `
acme:
  challenges:
    device_attest01: true
    device_attest:
      tpm_roots: ["/etc/xkms/tpm-root.pem"]
      dice_roots: ["/etc/xkms/dice-root.pem", "/etc/xkms/dice-root-2.pem"]
      dice_require_device_signed_leaf: true
      dice_require_measurement: true
      dice_require_tcb_info: true
      dice_require_application_reference: true
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ACME == nil {
		t.Fatal("cfg.ACME = nil")
	}
	got := cfg.ACME.Challenges
	if !got.DeviceAttest01 {
		t.Error("device_attest01 did not load")
	}
	want := ACMEDeviceAttestConfig{
		TPMRoots:                        []string{"/etc/xkms/tpm-root.pem"},
		DICERoots:                       []string{"/etc/xkms/dice-root.pem", "/etc/xkms/dice-root-2.pem"},
		DICERequireDeviceSignedLeaf:     true,
		DICERequireMeasurement:          true,
		DICERequireTCBInfo:              true,
		DICERequireApplicationReference: true,
	}
	if len(got.DeviceAttest.TPMRoots) != 1 || got.DeviceAttest.TPMRoots[0] != want.TPMRoots[0] ||
		len(got.DeviceAttest.DICERoots) != 2 || got.DeviceAttest.DICERoots[1] != want.DICERoots[1] ||
		got.DeviceAttest.DICERequireDeviceSignedLeaf != want.DICERequireDeviceSignedLeaf ||
		got.DeviceAttest.DICERequireMeasurement != want.DICERequireMeasurement ||
		got.DeviceAttest.DICERequireTCBInfo != want.DICERequireTCBInfo ||
		got.DeviceAttest.DICERequireApplicationReference != want.DICERequireApplicationReference {
		t.Fatalf("DeviceAttest = %+v, want %+v", got.DeviceAttest, want)
	}
}
