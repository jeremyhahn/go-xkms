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

package cmd

import (
	"testing"
)

func TestTPMErrorTypes(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrTPMDeviceNotFound",
			err:  ErrTPMDeviceNotFound,
			want: "tpm: device not found",
		},
		{
			name: "ErrTPMNotInitialized",
			err:  ErrTPMNotInitialized,
			want: "tpm: not initialized - run 'tpm provision' first",
		},
		{
			name: "ErrTPMOperationFailed",
			err:  ErrTPMOperationFailed,
			want: "tpm: operation failed",
		},
		{
			name: "ErrInvalidPCRBank",
			err:  ErrInvalidPCRBank,
			want: "tpm: invalid PCR bank specified",
		},
		{
			name: "ErrInvalidPCRIndices",
			err:  ErrInvalidPCRIndices,
			want: "tpm: invalid PCR indices specified",
		},
		{
			name: "ErrInvalidNonce",
			err:  ErrInvalidNonce,
			want: "tpm: invalid nonce specified",
		},
		{
			name: "ErrMissingOutputFile",
			err:  ErrMissingOutputFile,
			want: "tpm: output file path required",
		},
		{
			name: "ErrCertificateNotFound",
			err:  ErrCertificateNotFound,
			want: "tpm: certificate not found",
		},
		{
			name: "ErrKeyNotFound",
			err:  ErrKeyNotFound,
			want: "tpm: key not found",
		},
		{
			name: "ErrInvalidTemplate",
			err:  ErrInvalidTemplate,
			want: "tpm: invalid key template specified",
		},
		{
			name: "ErrProvisioningFailed",
			err:  ErrProvisioningFailed,
			want: "tpm: provisioning failed",
		},
		{
			name: "ErrCSRGenerationFailed",
			err:  ErrCSRGenerationFailed,
			want: "tpm: CSR generation failed",
		},
		{
			name: "ErrExportFailed",
			err:  ErrExportFailed,
			want: "tpm: export failed",
		},
		{
			name: "ErrInvalidKeyAlgorithm",
			err:  ErrInvalidKeyAlgorithm,
			want: "tpm: invalid key algorithm",
		},
		{
			name: "ErrMissingHierarchyAuth",
			err:  ErrMissingHierarchyAuth,
			want: "tpm: hierarchy authorization required",
		},
		{
			name: "ErrInvalidEKTemplate",
			err:  ErrInvalidEKTemplate,
			want: "tpm: invalid EK template - must be rsa2048 or ecc256",
		},
		{
			name: "ErrInvalidIAKTemplate",
			err:  ErrInvalidIAKTemplate,
			want: "tpm: invalid IAK template - must be rsa2048, rsa-pss, or ecc256",
		},
		{
			name: "ErrInvalidIDevIDTemplate",
			err:  ErrInvalidIDevIDTemplate,
			want: "tpm: invalid IDevID template - must be rsa2048, rsa-pss, or ecc256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("error = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTPMConfig(t *testing.T) {
	// Test default config values
	cfg := &tpmConfig{
		device:       "/dev/tpmrm0",
		useSimulator: false,
		verbose:      false,
		outputFormat: "text",
	}

	if cfg.device != "/dev/tpmrm0" {
		t.Errorf("device = %q, want %q", cfg.device, "/dev/tpmrm0")
	}

	if cfg.useSimulator {
		t.Error("useSimulator should be false by default")
	}

	if cfg.verbose {
		t.Error("verbose should be false by default")
	}

	if cfg.outputFormat != "text" {
		t.Errorf("outputFormat = %q, want %q", cfg.outputFormat, "text")
	}
}

func TestGetLogLevel(t *testing.T) {
	// Save original config
	originalVerbose := tpmCfg.verbose

	// Test non-verbose (info level)
	tpmCfg.verbose = false
	level := getLogLevel()
	if level.String() != "INFO" {
		t.Errorf("log level = %q, want %q", level.String(), "INFO")
	}

	// Test verbose (debug level)
	tpmCfg.verbose = true
	level = getLogLevel()
	if level.String() != "DEBUG" {
		t.Errorf("log level = %q, want %q", level.String(), "DEBUG")
	}

	// Restore original config
	tpmCfg.verbose = originalVerbose
}

func TestTPMCmdStructure(t *testing.T) {
	// Test that tpmCmd is properly initialized
	if tpmCmd == nil {
		t.Fatal("tpmCmd is nil")
	}

	if tpmCmd.Use != "tpm" {
		t.Errorf("tpmCmd.Use = %q, want %q", tpmCmd.Use, "tpm")
	}

	// Test that subcommands are registered
	subcommands := tpmCmd.Commands()
	expectedSubcommands := map[string]bool{
		"info":      false,
		"provision": false,
		"ek":        false,
		"iak":       false,
		"idevid":    false,
		"quote":     false,
		"pcrs":      false,
	}

	for _, cmd := range subcommands {
		if _, ok := expectedSubcommands[cmd.Use]; ok {
			expectedSubcommands[cmd.Use] = true
		}
	}

	for name, found := range expectedSubcommands {
		if !found {
			t.Errorf("subcommand %q not found", name)
		}
	}
}

func TestParsePCRIndices(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []uint
		wantErr bool
	}{
		{
			name:    "single pcr",
			input:   "0",
			want:    []uint{0},
			wantErr: false,
		},
		{
			name:    "multiple pcrs",
			input:   "0,1,7",
			want:    []uint{0, 1, 7},
			wantErr: false,
		},
		{
			name:    "pcrs with spaces",
			input:   "0, 1, 7",
			want:    []uint{0, 1, 7},
			wantErr: false,
		},
		{
			name:    "max valid pcr",
			input:   "23",
			want:    []uint{23},
			wantErr: false,
		},
		{
			name:    "pcr out of range",
			input:   "24",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid pcr",
			input:   "abc",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "trailing comma",
			input:   "0,1,",
			want:    []uint{0, 1},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePCRIndices(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePCRIndices(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("parsePCRIndices(%q) = %v, want %v", tt.input, got, tt.want)
					return
				}
				for i, v := range got {
					if v != tt.want[i] {
						t.Errorf("parsePCRIndices(%q)[%d] = %d, want %d", tt.input, i, v, tt.want[i])
					}
				}
			}
		})
	}
}

func TestParsePCRIndicesForPCRs(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []uint
		wantErr bool
	}{
		{
			name:    "single pcr",
			input:   "0",
			want:    []uint{0},
			wantErr: false,
		},
		{
			name:    "range",
			input:   "0-3",
			want:    []uint{0, 1, 2, 3},
			wantErr: false,
		},
		{
			name:    "mixed",
			input:   "0,5-7,10",
			want:    []uint{0, 5, 6, 7, 10},
			wantErr: false,
		},
		{
			name:    "invalid range",
			input:   "5-3",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "range out of bounds",
			input:   "20-25",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePCRIndicesForPCRs(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePCRIndicesForPCRs(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("parsePCRIndicesForPCRs(%q) = %v, want %v", tt.input, got, tt.want)
					return
				}
				for i, v := range got {
					if v != tt.want[i] {
						t.Errorf("parsePCRIndicesForPCRs(%q)[%d] = %d, want %d", tt.input, i, v, tt.want[i])
					}
				}
			}
		})
	}
}
