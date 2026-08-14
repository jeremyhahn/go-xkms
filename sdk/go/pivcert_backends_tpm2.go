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

//go:build tpm2

package xkms

import pivtpm2 "github.com/jeremyhahn/go-xkms/pkg/pivcert/tpm2"

// TPM2 NV-backed PIV certificate storage re-exported behind the tpm2 build
// tag, matching pkg/pivcert/tpm2. The xkey TPM2 PIV paths reach these through
// the SDK only when built with -tags tpm2, mirroring the PKCS#11 split in
// pivcert_backends_pkcs11.go.
//
// The names carry PIV prefixes because the bare New SDK name aliases the xkms
// backend client constructor.

// PIVTPM2Backend is the concrete TPM2 NV-backed PIV certificate store returned
// by the NewPIVTPM2Backend* constructors.
type PIVTPM2Backend = pivtpm2.TPM2CertStorage

// PIVTPM2Config configures the TPM2 NV-backed PIV certificate store.
type PIVTPM2Config = pivtpm2.Config

// PIVTPM2SlotModel reports which PIV slots hold a certificate in TPM NV RAM.
type PIVTPM2SlotModel = pivtpm2.PIVSlotModel

// PIVTPM2TranslatedError reports the pivcert sentinel a TPM failure maps onto
// while keeping the TPM response code reachable through errors.Is.
type PIVTPM2TranslatedError = pivtpm2.TranslatedError

const (
	// PIVTPM2DefaultBaseIndex is the first NV index of the range PIV
	// certificates are stored in.
	PIVTPM2DefaultBaseIndex = pivtpm2.DefaultBaseIndex

	// PIVTPM2DefaultMaxCertSize is the default maximum NV record size in bytes.
	PIVTPM2DefaultMaxCertSize = pivtpm2.DefaultMaxCertSize
)

// NewPIVTPM2Backend constructs a TPM2 NV-backed PIV certificate store over an
// open TPM connection.
var NewPIVTPM2Backend = pivtpm2.New

// NewPIVTPM2BackendFromCertStorage constructs a TPM2 NV-backed PIV certificate
// store over an existing hardware certificate store.
var NewPIVTPM2BackendFromCertStorage = pivtpm2.NewFromCertStorage

// NewPIVTPM2SlotModel constructs the PIV slot model over TPM NV certificate
// storage.
var NewPIVTPM2SlotModel = pivtpm2.NewPIVSlotModel

// PIVTPM2SlotToCertID returns the immutable NV certificate ID a PIV slot is
// stored under.
var PIVTPM2SlotToCertID = pivtpm2.PIVSlotToCertID

// PIVTPM2CertIDToSlot returns the PIV slot an NV certificate ID belongs to.
var PIVTPM2CertIDToSlot = pivtpm2.CertIDToPIVSlot
