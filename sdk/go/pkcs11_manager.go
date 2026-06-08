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
	pkcs11manager "github.com/jeremyhahn/go-xkms/pkg/pkcs11/manager"
	pkcs11module "github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// PKCS#11 module/manager surface re-exported so the xkey GUI/CLI drive HSM
// module lifecycle and low-level token operations through the SDK. Identifiers
// carry PKCS11Manager*/PKCS11* prefixes to stay unambiguous in the flat SDK
// namespace (the bare New SDK name already aliases the xkms backend client
// constructor).

// --- Module manager (pkg/pkcs11/manager) ---

// PKCS11Manager manages the lifecycle of PKCS#11 modules and their connections.
type PKCS11Manager = pkcs11manager.Manager

// PKCS11ManagerBackend is the crypto-backend interface a managed PKCS#11 module
// satisfies.
type PKCS11ManagerBackend = pkcs11manager.Backend

// PKCS11Connection is a live connection to a PKCS#11 token.
type PKCS11Connection = pkcs11manager.Connection

// PKCS11ModuleInfo describes a registered PKCS#11 module.
type PKCS11ModuleInfo = pkcs11manager.ModuleInfo

// PKCS11SlotInfo describes a slot exposed by a PKCS#11 module.
type PKCS11SlotInfo = pkcs11manager.SlotInfo

// PKCS11TokenInfo describes a token present in a slot.
type PKCS11TokenInfo = pkcs11manager.TokenInfo

const (
	// PKCS11ModuleStateError indicates a module that failed to load.
	PKCS11ModuleStateError = pkcs11manager.ModuleStateError
	// PKCS11ModuleStateLoaded indicates a successfully loaded module.
	PKCS11ModuleStateLoaded = pkcs11manager.ModuleStateLoaded
)

// NewPKCS11Manager constructs a PKCS#11 module manager.
var NewPKCS11Manager = pkcs11manager.New

// ProbePKCS11Modules probes well-known PKCS#11 module paths by name.
var ProbePKCS11Modules = pkcs11manager.ProbeModulesWithNames

// --- Low-level module (pkg/pkcs11/module) ---

// PKCS11Attribute is a PKCS#11 object attribute.
type PKCS11Attribute = pkcs11module.Attribute

// PKCS11AttributeType is a PKCS#11 attribute type code.
type PKCS11AttributeType = pkcs11module.AttributeType

// PKCS11Mechanism is a PKCS#11 cryptographic mechanism.
type PKCS11Mechanism = pkcs11module.Mechanism

// PKCS11MechanismType is a PKCS#11 mechanism type code.
type PKCS11MechanismType = pkcs11module.MechanismType

// PKCS11ECDHParams holds ECDH key-derivation parameters.
type PKCS11ECDHParams = pkcs11module.ECDHParams

// PKCS11KDFType is a PKCS#11 key-derivation function selector.
type PKCS11KDFType = pkcs11module.KDFType

// PKCS11ObjectHandle is a handle to a PKCS#11 object.
type PKCS11ObjectHandle = pkcs11module.ObjectHandle

// PKCS11Transport is the transport abstraction used by the module client.
type PKCS11Transport = pkcs11module.PKCS11Transport

// PKCS11SessionFlag is a PKCS#11 session flag.
type PKCS11SessionFlag = pkcs11module.SessionFlag

// PKCS11SessionHandle is a handle to an open PKCS#11 session.
type PKCS11SessionHandle = pkcs11module.SessionHandle

// PKCS11SlotID identifies a PKCS#11 slot.
type PKCS11SlotID = pkcs11module.SlotID

// PKCS11UserType identifies a PKCS#11 login user type.
type PKCS11UserType = pkcs11module.UserType

const (
	// PKCS11CKMECDH1DeriveMechanism is CKM_ECDH1_DERIVE.
	PKCS11CKMECDH1DeriveMechanism = pkcs11module.CKM_ECDH1_DERIVE
	// PKCS11CKMECDH1CofactorDeriveMechanism is CKM_ECDH1_COFACTOR_DERIVE.
	PKCS11CKMECDH1CofactorDeriveMechanism = pkcs11module.CKM_ECDH1_COFACTOR_DERIVE
	// PKCS11CKROK is the CKR_OK return code.
	PKCS11CKROK = pkcs11module.CKR_OK
)

// GetGlobalPKCS11Module returns the process-global PKCS#11 module instance.
var GetGlobalPKCS11Module = pkcs11module.GetGlobalModule

// SetGlobalPKCS11Module sets the process-global PKCS#11 module instance.
var SetGlobalPKCS11Module = pkcs11module.SetGlobalModule

// WithPKCS11Client configures the module to use the given transport client.
var WithPKCS11Client = pkcs11module.WithClient

// NewPKCS11Module constructs a low-level PKCS#11 module instance.
var NewPKCS11Module = pkcs11module.New
