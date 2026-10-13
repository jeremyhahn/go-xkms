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

package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/types"
	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// XKMS service-singleton surface re-exported so the xkey GUI/CLI drive the
// process-global pkg/xkms service (key lifecycle, backend registry and the PIV
// manager) through the SDK.
//
// pkgxkms.ResetPIV is surfaced as XKMSResetPIV because ResetPIV in piv.go
// already aliases the pivcert backend reset helper. The pkgxkms.New backend
// constructor is already re-exported as NewServiceBackend in service.go.

// --- Backend / service singleton ---
//
// The pkgxkms.New backend constructor is already re-exported as
// NewServiceBackend in service.go; this file does not duplicate it.

// Get returns the process-global XKMS service, initializing it on first use.
var Get = pkgxkms.Get

// Reset tears down the process-global XKMS service (primarily for tests).
var Reset = pkgxkms.Reset

// IsInitialized reports whether the process-global XKMS service is ready.
var IsInitialized = pkgxkms.IsInitialized

// AutoInitialize initializes the XKMS service from an AutoConfig.
var AutoInitialize = pkgxkms.AutoInitialize

// Backends lists the registered full-service backend names.
var Backends = pkgxkms.Backends

// GetBackend returns a registered backend by name.
var GetBackend = pkgxkms.GetBackend

// GetBackendFactory returns the factory for a backend type.
var GetBackendFactory = pkgxkms.GetBackendFactory

// ExternalBackend describes a backend implemented in another module: its
// type name and the ServiceBackendFactory that constructs its KeyProvider.
type ExternalBackend = pkgxkms.ExternalBackend

// RegisterExternalBackend makes a backend implemented in another module a
// first-class backend type. Call it from that module's init function.
var RegisterExternalBackend = pkgxkms.RegisterExternalBackend

// BackendTypeRegistrationError reports a refused RegisterExternalBackend.
type BackendTypeRegistrationError = types.BackendTypeRegistrationError

var (
	// ErrInvalidBackendTypeName refuses a backend type name the Key ID
	// format cannot carry.
	ErrInvalidBackendTypeName = types.ErrInvalidBackendTypeName

	// ErrBackendTypeRegistered refuses a backend type name already held by
	// a built-in backend or an earlier registration.
	ErrBackendTypeRegistered = types.ErrBackendTypeRegistered

	// ErrNilBackendFactory refuses an external backend without a factory.
	ErrNilBackendFactory = pkgxkms.ErrNilBackendFactory
)

// RegisterServiceBackend registers a backend instance under a name.
var RegisterServiceBackend = pkgxkms.RegisterServiceBackend

// UnregisterBackend removes a registered backend by name.
var UnregisterBackend = pkgxkms.UnregisterBackend

const (
	// BackendTPM2 is the TPM 2.0 backend type identifier.
	BackendTPM2 = pkgxkms.BackendTPM2
	// BackendPKCS11 is the PKCS#11 backend type identifier.
	BackendPKCS11 = pkgxkms.BackendPKCS11
)

// --- Key operations ---

// Signer returns a crypto.Signer for the key identified by attrs.
var Signer = pkgxkms.Signer

// ListKeys lists key attributes, optionally scoped to a backend.
var ListKeys = pkgxkms.ListKeys

// DeleteKey deletes the key identified by attrs.
var DeleteKey = pkgxkms.DeleteKey

// WrapKey wraps key material for import using a backend's wrapping key.
var WrapKey = pkgxkms.WrapKey

// UnwrapKey unwraps previously wrapped key material.
var UnwrapKey = pkgxkms.UnwrapKey

// ExportKey exports a key as wrapped material using the given algorithm.
var ExportKey = pkgxkms.ExportKey

// WrapKeyByID wraps a server-side target key with a server-side wrapping
// key, both identified by key ID and backend (the PKCS#11 C_WrapKey
// primitive).
var WrapKeyByID = pkgxkms.WrapKeyByID

// UnwrapKeyByID unwraps key material with a server-side unwrapping key and
// imports the result as a new key (the PKCS#11 C_UnwrapKey primitive).
var UnwrapKeyByID = pkgxkms.UnwrapKeyByID

// --- PIV manager ---

// PIVKeyGenerator generates PIV keys for the PIV manager.
type PIVKeyGenerator = pkgxkms.PIVKeyGenerator

// PIVManagerConfig configures the PIV manager.
type PIVManagerConfig = pkgxkms.PIVManagerConfig

// InitializePIV initializes the PIV manager.
var InitializePIV = pkgxkms.InitializePIV

// XKMSResetPIV factory-resets the PIV manager state.
var XKMSResetPIV = pkgxkms.ResetPIV

// SetPIVBackendResolver sets the resolver used to locate PIV backends.
var SetPIVBackendResolver = pkgxkms.SetPIVBackendResolver

// RegisterPIVStore registers a PIV certificate store for a backend.
var RegisterPIVStore = pkgxkms.RegisterPIVStore

// NewSoftwarePIVKeyGenerator constructs the software PIV key generator.
var NewSoftwarePIVKeyGenerator = pkgxkms.NewSoftwarePIVKeyGenerator

// ListPIVSlots lists PIV slots and their occupancy.
var ListPIVSlots = pkgxkms.ListPIVSlots

// GeneratePIVKey generates a PIV key in a slot.
var GeneratePIVKey = pkgxkms.GeneratePIVKey

// GeneratePIVCSR generates a CSR for a PIV slot key.
var GeneratePIVCSR = pkgxkms.GeneratePIVCSR

// SelfSignExistingPIVKey self-signs the certificate for an existing PIV key.
var SelfSignExistingPIVKey = pkgxkms.SelfSignExistingPIVKey

// GetPIVCertificate retrieves a PIV slot certificate.
var GetPIVCertificate = pkgxkms.GetPIVCertificate

// StorePIVCertificate stores a certificate in a PIV slot.
var StorePIVCertificate = pkgxkms.StorePIVCertificate

// ImportPIVCertificate imports a certificate into a PIV slot.
var ImportPIVCertificate = pkgxkms.ImportPIVCertificate

// ExportPIVCertificate exports a PIV slot certificate.
var ExportPIVCertificate = pkgxkms.ExportPIVCertificate

// DeletePIVCertificate deletes a certificate from a PIV slot.
var DeletePIVCertificate = pkgxkms.DeletePIVCertificate
