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

package backendregistry

import "sync/atomic"

// BackendCategory represents the type of cryptographic backend.
type BackendCategory string

const (
	CategorySoftware BackendCategory = "software"
	CategoryTPM2     BackendCategory = "tpm2"
	CategoryPKCS11   BackendCategory = "pkcs11"
	CategoryXKMS     BackendCategory = "xkms"
	CategoryPhone    BackendCategory = "phone"
)

// String returns the human-readable name for a BackendCategory.
func (c BackendCategory) String() string {
	if name, ok := categoryNames[c]; ok {
		return name
	}
	return "unknown"
}

var categoryNames = map[BackendCategory]string{
	CategorySoftware: "software",
	CategoryTPM2:     "tpm2",
	CategoryPKCS11:   "pkcs11",
	CategoryXKMS:     "xkms",
	CategoryPhone:    "phone",
}

// ValidCategories contains all valid BackendCategory values for validation.
var ValidCategories = map[BackendCategory]struct{}{
	CategorySoftware: {},
	CategoryTPM2:     {},
	CategoryPKCS11:   {},
	CategoryXKMS:     {},
	CategoryPhone:    {},
}

// BackendLocation represents whether a backend is local or remote.
type BackendLocation string

const (
	LocationLocal  BackendLocation = "local"
	LocationRemote BackendLocation = "remote"
)

// String returns the human-readable name for a BackendLocation.
func (l BackendLocation) String() string {
	if name, ok := locationNames[l]; ok {
		return name
	}
	return "unknown"
}

var locationNames = map[BackendLocation]string{
	LocationLocal:  "local",
	LocationRemote: "remote",
}

// ValidLocations contains all valid BackendLocation values for validation.
var ValidLocations = map[BackendLocation]struct{}{
	LocationLocal:  {},
	LocationRemote: {},
}

// BackendState represents the operational state of a backend.
type BackendState int32

const (
	StateUninitialized BackendState = iota
	StateReady
	StateSealed
	StateLocked
	StateError
	StateOffline
)

// String returns the human-readable name for a BackendState.
func (s BackendState) String() string {
	if name, ok := stateNames[s]; ok {
		return name
	}
	return "unknown"
}

var stateNames = map[BackendState]string{
	StateUninitialized: "uninitialized",
	StateReady:         "ready",
	StateSealed:        "sealed",
	StateLocked:        "locked",
	StateError:         "error",
	StateOffline:       "offline",
}

// Capability represents a feature that a backend supports.
type Capability string

const (
	CapFIDO2       Capability = "fido2"
	CapPIV         Capability = "piv"
	CapOATH        Capability = "oath"
	CapPasswords   Capability = "passwords"
	CapSigning     Capability = "signing"
	CapSealing     Capability = "sealing"
	CapAttestation Capability = "attestation"
	CapEncryption  Capability = "encryption"
)

// String returns the human-readable name for a Capability.
func (c Capability) String() string {
	if name, ok := capabilityNames[c]; ok {
		return name
	}
	return "unknown"
}

var capabilityNames = map[Capability]string{
	CapFIDO2:       "fido2",
	CapPIV:         "piv",
	CapOATH:        "oath",
	CapPasswords:   "passwords",
	CapSigning:     "signing",
	CapSealing:     "sealing",
	CapAttestation: "attestation",
	CapEncryption:  "encryption",
}

// ValidCapabilities contains all valid Capability values for validation.
var ValidCapabilities = map[Capability]struct{}{
	CapFIDO2:       {},
	CapPIV:         {},
	CapOATH:        {},
	CapPasswords:   {},
	CapSigning:     {},
	CapSealing:     {},
	CapAttestation: {},
	CapEncryption:  {},
}

// RegisteredBackend represents a cryptographic backend registered in the registry.
type RegisteredBackend struct {
	// ID is a unique identifier for this backend (e.g., "software", "tpm2-default").
	ID string

	// Location indicates whether this backend is local or remote.
	Location BackendLocation

	// Category indicates the type of backend (software, tpm2, pkcs11, etc.).
	Category BackendCategory

	// DisplayName is a human-readable name for GUI display.
	DisplayName string

	// Capabilities maps feature flags to whether this backend supports them.
	Capabilities map[Capability]bool

	// Metadata holds arbitrary key-value metadata for this backend.
	Metadata map[string]string

	// state holds the operational state atomically for lock-free access.
	state atomic.Int32
}

// State returns the current operational state of this backend.
func (b *RegisteredBackend) State() BackendState {
	return BackendState(b.state.Load())
}

// SetState atomically sets the operational state of this backend.
func (b *RegisteredBackend) SetState(s BackendState) {
	b.state.Store(int32(s))
}

// HasCapability returns true if this backend supports the given capability.
// Returns false if the Capabilities map is nil or the capability is not present.
func (b *RegisteredBackend) HasCapability(cap Capability) bool {
	if b.Capabilities == nil {
		return false
	}
	return b.Capabilities[cap]
}
