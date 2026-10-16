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

package tpm2

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// platformSRKHandle is the TCG-reserved persistent handle for the Platform
// SRK (TPM 2.0 Part 1, Table 8 "Reserved Handles": platform-specific storage
// range) and matches pkgtpm2.DefaultConfig.PlatformSRK.SRKHandle. This
// backend uses the Platform SRK, not the Shared SRK at c.SRKHandle, as its
// own storage parent (see ToTPMConfig).
const platformSRKHandle = 0x81000002

// Config holds the configuration for the TPM2 backend
type Config struct {
	// Device is the path to the TPM device (e.g., "/dev/tpmrm0")
	Device string `yaml:"device" json:"device"`

	// Keys is the store TPM key blobs are persisted in: TPMBlob entities in
	// the caller's tpm2 database (see store.NewBlobStore, or
	// store.NewBackendBlobStore for a storage.Backend datastore). It is the
	// ONLY store NewBackend uses: this package never opens one of its own.
	// Not serializable (Go value); a caller building Config from yaml/json
	// sets it after unmarshaling.
	Keys *store.BlobStore `yaml:"-" json:"-"`

	// UseSimulator indicates whether to use the TPM simulator instead of hardware
	UseSimulator bool `yaml:"use_simulator" json:"use_simulator"`

	// SimulatorHost is the hostname for the TPM simulator (default: "localhost")
	SimulatorHost string `yaml:"simulator_host" json:"simulator_host"`

	// SimulatorPort is the port for the TPM simulator (default: 2321)
	SimulatorPort int `yaml:"simulator_port" json:"simulator_port"`

	// SRKHandle is the persistent handle for the Storage Root Key (default: 0x81000001)
	SRKHandle uint32 `yaml:"srk_handle" json:"srk_handle"`

	// EKHandle is the persistent handle for the Endorsement Key (default: 0x81010001)
	EKHandle uint32 `yaml:"ek_handle" json:"ek_handle"`

	// Deliberately no HierarchyAuth field here. The Owner hierarchy
	// authorization needed to create or evict this backend's Storage Root
	// Key is never stored in configuration -- it is supplied only at the
	// moment of the operation. This backend's own storage parent is the
	// Platform SRK (see ToTPMConfig and Backend.srkAttrs in backend.go),
	// which never carries one for the same reason pkgtpm2.PlatformSRKConfig
	// does not (see that type's doc comment): a config-literal auth field
	// that nothing legitimate reads is exactly the defect this project's
	// no-config-literal-auth rule forbids. A caller who needs a non-default
	// Owner hierarchy auth for genuine TCG provisioning supplies a
	// fully-formed pkgtpm2.Config via TPMConfig instead, which reaches
	// TPM2_CreatePrimary through the soPIN argument to
	// Provision/Install/ProvisionOwner or
	// PlatformKeyStore.Initialize/EnrollPlatformSRK, not through this struct.

	// Hash specifies the hash algorithm to use (default: "SHA-256")
	Hash string `yaml:"hash" json:"hash"`

	// PlatformPCRSelection is the platform policy's sealing PCR set and
	// bank, passed through to pkgtpm2.Config, which defaults and validates
	// the set. Unset fields resolve to pkgtpm2.DefaultPlatformPCRSelection.
	pkgtpm2.PlatformPCRSelection `yaml:",inline"`

	// CN is the common name prefix for keys created by this backend
	CN string `yaml:"cn" json:"cn"`

	// Logger is the logger instance to use
	Logger *slog.Logger `yaml:"-" json:"-"`

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

	// Keys has no default: callers derive it from their own datastore --
	// e.g. pkg/server's tpm2 DAO factory, or an SDK/library caller's
	// datastore handle -- and supply it explicitly.
	if c.Keys == nil {
		return &errs.Detail{
			Err:    ErrKeysRequired,
			Detail: "Keys must be set explicitly; this package never opens a key store of its own",
		}
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
		c.PlatformPCRBank = pkgtpm2.PCRBankSHA256
	}

	if c.CN == "" {
		c.CN = "xkms"
	}

	// Check if device exists (unless using simulator)
	if !c.UseSimulator && c.Device != "" {
		if _, err := os.Stat(c.Device); os.IsNotExist(err) {
			return &errs.Detail{Err: ErrTPMNotAvailable, Detail: fmt.Sprintf("device %s does not exist", c.Device)}
		}
	}

	return nil
}

// ToTPMConfig converts the backend config to the TPM2 library config.
//
// When UseSimulator is true AND SimulatorHost is non-empty, the config maps
// the simulator address to CommandAddress / PlatformAddress so NewTPM2 opens
// a TCP connection to the external simulator (e.g. swtpm). When SimulatorHost
// is empty, UseSimulator passes through to NewTPM2 which uses the in-memory
// go-tpm-tools simulator (requires the tpm_simulator build tag).
func (c *Config) ToTPMConfig() *pkgtpm2.Config {
	if c.TPMConfig != nil {
		return c.TPMConfig
	}

	cfg := &pkgtpm2.Config{
		Device:               c.Device,
		UseSimulator:         c.UseSimulator,
		Hash:                 c.Hash,
		PlatformPCRSelection: c.PlatformPCRSelection,
		Tracker:              c.Tracker,
		EK: &pkgtpm2.EKConfig{
			Handle:       c.EKHandle,
			CertHandle:   0x01C00002, // TCG standard RSA EK cert NV index
			KeyAlgorithm: "RSA",
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		// SSRK is provisioned exactly per the TCG-standard workflow (empty
		// hierarchy auth, well-known template, no platform policy -- see
		// pkgtpm2.SRKConfig). This backend never authorizes with it and never
		// carries a hierarchy auth for it: an operator who needs a non-default
		// Owner hierarchy auth for genuine TCG provisioning supplies a
		// fully-formed pkgtpm2.Config via TPMConfig instead of through this
		// struct.
		SSRK: &pkgtpm2.SRKConfig{
			Handle:       c.SRKHandle,
			KeyAlgorithm: "RSA",
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		// PlatformSRK is the storage parent this backend actually uses for
		// its own key operations (see Backend.srkAttrs in backend.go): xkms's
		// own purposes, which do not need to follow the TCG-standard SSRK
		// workflow. PlatformPolicy is always true here, matching
		// pkgtpm2.DefaultConfig and the PSRK enrollment path
		// (pkg/tpm2/platform_keystore.go's Initialize/EnrollPlatformSRK):
		// the design settled in go-xkms#677 is authValue = user PIN,
		// authPolicy = platform PCR policy, unconditionally, with no plain
		// password-only shape. Deriving both this backend's autodetected
		// Platform SRK and the enrolled one from the same PlatformPolicy:
		// true is what go-xkms#997 fixes -- a backend built with the old
		// PlatformPolicy: false here created a Platform SRK with no
		// AuthPolicy baked into its template, which disagreed with the one
		// enrollment created and left the two unable to interoperate. Its
		// owner-hierarchy authorization is likewise never taken from this
		// struct, for the same reason SSRK carries none: duplicating a
		// hierarchy-auth field here risks it being wired to the wrong key,
		// which is exactly the defect this config previously had (a
		// HierarchyAuth field that fed SSRK instead of PlatformSRK).
		PlatformSRK: &pkgtpm2.PlatformSRKConfig{
			SRKHandle:      platformSRKHandle,
			PlatformPolicy: true,
		},
	}

	// When a SimulatorHost is provided alongside UseSimulator, the backend
	// targets an external TPM daemon (e.g. swtpm) over TCP rather than the
	// in-memory go-tpm-tools simulator. Wire the address into CommandAddress
	// so pkgtpm2.NewTPM2 selects the TCP transport path.
	if c.UseSimulator && c.SimulatorHost != "" {
		port := c.SimulatorPort
		if port <= 0 {
			port = 2321 // swtpm convention
		}
		cfg.CommandAddress = fmt.Sprintf("%s:%d", c.SimulatorHost, port)
		// PlatformAddress defaults to CommandAddress port+1 inside NewTPM2;
		// explicit assignment here makes the intent visible to readers.
		cfg.PlatformAddress = fmt.Sprintf("%s:%d", c.SimulatorHost, port+1)
		// Clear UseSimulator so NewTPM2 uses the TCP path, not simulatorOpener.
		cfg.UseSimulator = false
	}

	return cfg
}
