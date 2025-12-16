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

package tpm2

import (
	"fmt"
	"os"

	"github.com/jeremyhahn/go-keychain/pkg/logging"
	pkgtpm2 "github.com/jeremyhahn/go-keychain/pkg/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Config holds the configuration for the TPM2 backend
type Config struct {
	// Device is the path to the TPM device (e.g., "/dev/tpmrm0")
	Device string `yaml:"device" json:"device"`

	// KeyDir is the directory where TPM key blobs are stored
	KeyDir string `yaml:"key_dir" json:"key_dir"`

	// UseSimulator indicates whether to use the TPM simulator instead of hardware
	UseSimulator bool `yaml:"use_simulator" json:"use_simulator"`

	// SimulatorHost is the hostname for the TPM simulator (default: "localhost")
	SimulatorHost string `yaml:"simulator_host" json:"simulator_host"`

	// SimulatorPort is the port for the TPM simulator (default: 2321)
	SimulatorPort int `yaml:"simulator_port" json:"simulator_port"`

	// EncryptSession enables encrypted sessions for CPU<->TPM communication
	EncryptSession bool `yaml:"encrypt_session" json:"encrypt_session"`

	// SRKHandle is the persistent handle for the Storage Root Key (default: 0x81000001)
	SRKHandle uint32 `yaml:"srk_handle" json:"srk_handle"`

	// EKHandle is the persistent handle for the Endorsement Key (default: 0x81010001)
	EKHandle uint32 `yaml:"ek_handle" json:"ek_handle"`

	// Hash specifies the hash algorithm to use (default: "SHA-256")
	Hash string `yaml:"hash" json:"hash"`

	// PlatformPolicy enables platform PCR policy authorization
	PlatformPolicy bool `yaml:"platform_policy" json:"platform_policy"`

	// PlatformPCR is the PCR index used for platform policy (default: 0)
	PlatformPCR uint `yaml:"platform_pcr" json:"platform_pcr"`

	// PlatformPCRBank is the PCR bank hash algorithm (default: "SHA256")
	PlatformPCRBank string `yaml:"platform_pcr_bank" json:"platform_pcr_bank"`

	// CN is the common name prefix for keys created by this backend
	CN string `yaml:"cn" json:"cn"`

	// Logger is the logger instance to use
	Logger *logging.Logger `yaml:"-" json:"-"`

	// Tracker is the AEAD safety tracker
	Tracker types.AEADSafetyTracker `yaml:"-" json:"-"`

	// TPMConfig is the underlying TPM2 library configuration
	// If set, this takes precedence over individual config fields
	TPMConfig *pkgtpm2.Config `yaml:"-" json:"-"`
}

// Validate validates the TPM2 backend configuration
func (c *Config) Validate() error {
	if c.Device == "" && !c.UseSimulator {
		c.Device = "/dev/tpmrm0"
	}

	if c.KeyDir == "" {
		c.KeyDir = "./tpm2-keys"
	}

	if c.SRKHandle == 0 {
		c.SRKHandle = 0x81000001
	}

	if c.EKHandle == 0 {
		c.EKHandle = 0x81010001
	}

	if c.Hash == "" {
		c.Hash = "SHA-256"
	}

	if c.PlatformPCRBank == "" {
		c.PlatformPCRBank = "SHA256"
	}

	if c.CN == "" {
		c.CN = "keychain"
	}

	// Check if device exists (unless using simulator)
	if !c.UseSimulator && c.Device != "" {
		if _, err := os.Stat(c.Device); os.IsNotExist(err) {
			return fmt.Errorf("%w: device %s does not exist", ErrTPMNotAvailable, c.Device)
		}
	}

	return nil
}

// ToTPMConfig converts the backend config to the TPM2 library config
func (c *Config) ToTPMConfig() *pkgtpm2.Config {
	if c.TPMConfig != nil {
		return c.TPMConfig
	}

	return &pkgtpm2.Config{
		Device:          c.Device,
		UseSimulator:    c.UseSimulator,
		EncryptSession:  c.EncryptSession,
		Hash:            c.Hash,
		PlatformPCR:     c.PlatformPCR,
		PlatformPCRBank: c.PlatformPCRBank,
		Tracker:         c.Tracker,
		EK: &pkgtpm2.EKConfig{
			Handle:       c.EKHandle,
			KeyAlgorithm: "RSA",
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		SSRK: &pkgtpm2.SRKConfig{
			Handle:       c.SRKHandle,
			KeyAlgorithm: "RSA",
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
	}
}
