// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build tpm2

package tpm2

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	if cfg.DevicePath == "" {
		t.Error("DevicePath should not be empty")
	}

	if cfg.SRKHandle == 0 {
		t.Error("SRKHandle should not be zero")
	}

	if cfg.UseSimulator {
		t.Error("UseSimulator should default to false")
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "valid hardware config",
			config:  &Config{DevicePath: "/dev/tpmrm0", SRKHandle: 0x81000001, CN: "test-srk"},
			wantErr: false,
		},
		{
			name:    "valid simulator config",
			config:  &Config{UseSimulator: true, SimulatorHost: "localhost", SimulatorPort: 2321, SRKHandle: 0x81000001, CN: "test-srk"},
			wantErr: false,
		},
		{
			name:    "missing device path",
			config:  &Config{SRKHandle: 0x81000001, CN: "test-srk"},
			wantErr: true,
		},
		{
			name:    "missing SRK handle",
			config:  &Config{DevicePath: "/dev/tpmrm0", CN: "test-srk"},
			wantErr: true,
		},
		{
			name:    "missing CN",
			config:  &Config{DevicePath: "/dev/tpmrm0", SRKHandle: 0x81000001},
			wantErr: true,
		},
		{
			name:    "simulator without host",
			config:  &Config{UseSimulator: true, SimulatorPort: 2321, SRKHandle: 0x81000001, CN: "test-srk"},
			wantErr: true,
		},
		{
			name:    "simulator without port",
			config:  &Config{UseSimulator: true, SimulatorHost: "localhost", SRKHandle: 0x81000001, CN: "test-srk"},
			wantErr: true,
		},
		{
			name:    "invalid SRK handle range",
			config:  &Config{DevicePath: "/dev/tpmrm0", SRKHandle: 0x80000000, CN: "test-srk"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_IsPersistentHandle(t *testing.T) {
	tests := []struct {
		name   string
		handle uint32
		want   bool
	}{
		{
			name:   "valid persistent handle - start of range",
			handle: 0x81000000,
			want:   true,
		},
		{
			name:   "valid persistent handle - middle of range",
			handle: 0x81000001,
			want:   true,
		},
		{
			name:   "valid persistent handle - end of range",
			handle: 0x81FFFFFF,
			want:   true,
		},
		{
			name:   "transient handle",
			handle: 0x80000000,
			want:   false,
		},
		{
			name:   "invalid handle - too high",
			handle: 0x82000000,
			want:   false,
		},
		{
			name:   "invalid handle - too low",
			handle: 0x80FFFFFF,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPersistentHandle(tt.handle); got != tt.want {
				t.Errorf("IsPersistentHandle(%#x) = %v, want %v", tt.handle, got, tt.want)
			}
		})
	}
}
