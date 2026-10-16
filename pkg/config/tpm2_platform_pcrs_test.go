package config

import (
	"errors"
	"slices"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"gopkg.in/yaml.v3"
)

// tpm2BackendConfig is a config whose only backend is an enabled TPM2 backend
// sealing to platformPCRs.
func tpm2BackendConfig(platformPCRs tpm2.PCRSet) *Config {
	return &Config{
		Protocols: ProtocolsConfig{REST: true},
		Server:    ServerConfig{RESTPort: 8443},
		Logging:   LoggingConfig{Level: "info", Format: "json"},
		Datastore: DatastoreConfig{Path: "/data"},
		TLS:       TLSConfig{Enabled: true},
		Default:   "tpm2",
		Backends: BackendsConfig{
			TPM2: &TPM2Config{Enabled: true, DevicePath: "/dev/tpmrm0", PlatformPCRs: platformPCRs},
		},
	}
}

func TestValidate_TPM2PlatformPCRs(t *testing.T) {
	for _, set := range []tpm2.PCRSet{nil, {7, 11}, {0, 7, 14}} {
		if err := tpm2BackendConfig(set).Validate(); err != nil {
			t.Errorf("Validate() with sealing set %v error = %v, want nil", set, err)
		}
	}
}

func TestValidate_TPM2PlatformPCRs_Refused(t *testing.T) {
	tests := map[string]struct {
		set     tpm2.PCRSet
		wantErr error
	}{
		"resettable PCR 16": {set: tpm2.PCRSet{7, 16}, wantErr: tpm2.ErrPlatformPCRResettable},
		"resettable PCR 23": {set: tpm2.PCRSet{23}, wantErr: tpm2.ErrPlatformPCRResettable},
		"out of range":      {set: tpm2.PCRSet{24}, wantErr: tpm2.ErrPlatformPCROutOfRange},
		"duplicate":         {set: tpm2.PCRSet{7, 7}, wantErr: tpm2.ErrPlatformPCRDuplicate},
		"explicit empty":    {set: tpm2.PCRSet{}, wantErr: tpm2.ErrPlatformPCRSetEmpty},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := tpm2BackendConfig(tt.set).Validate()
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestTPM2Config_PlatformPCRsYAML(t *testing.T) {
	var cfg TPM2Config
	if err := yaml.Unmarshal([]byte("platform-pcrs: [7, 14]\n"), &cfg); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	if !slices.Equal(cfg.PlatformPCRs, tpm2.PCRSet{7, 14}) {
		t.Errorf("PlatformPCRs = %v, want [7 14]", cfg.PlatformPCRs)
	}

	var refused TPM2Config
	err := yaml.Unmarshal([]byte("platform-pcrs: [7, 16]\n"), &refused)
	if !errors.Is(err, tpm2.ErrPlatformPCRResettable) {
		t.Errorf("yaml.Unmarshal() error = %v, want %v", err, tpm2.ErrPlatformPCRResettable)
	}
}
