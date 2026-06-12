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

package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/factor"
	fido2factor "github.com/jeremyhahn/go-xkms/pkg/factor/fido2"
	mtlsfactor "github.com/jeremyhahn/go-xkms/pkg/factor/mtls"
	pivfactor "github.com/jeremyhahn/go-xkms/pkg/factor/piv"
	pkcs11factor "github.com/jeremyhahn/go-xkms/pkg/factor/pkcs11"
)

// qrdb Factor adapters (from pkg/factor/{fido2,piv,pkcs11,mtls}).
//
// These factors satisfy the go-qrdb seal Factor interface so a qrdb node
// embedded by a downstream composer can use xkms hardware as an unseal
// factor. Each is re-exported with a hardware-type prefix because every
// factor package exposes the same Factor/Config/New shape.

// FIDO2Factor is the FIDO2 hmac-secret qrdb unseal factor.
type FIDO2Factor = fido2factor.Factor

// FIDO2FactorConfig configures the FIDO2 unseal factor.
type FIDO2FactorConfig = fido2factor.Config

// NewFIDO2Factor constructs a FIDO2 unseal factor.
var NewFIDO2Factor = fido2factor.New

// PIVFactor is the PIV smart-card qrdb unseal factor.
type PIVFactor = pivfactor.Factor

// PIVFactorConfig configures the PIV unseal factor.
type PIVFactorConfig = pivfactor.Config

// NewPIVFactor constructs a PIV unseal factor.
var NewPIVFactor = pivfactor.New

// PKCS11Factor is the PKCS#11 (HSM/token) qrdb unseal factor.
type PKCS11Factor = pkcs11factor.Factor

// PKCS11FactorConfig configures the PKCS#11 unseal factor.
type PKCS11FactorConfig = pkcs11factor.Config

// NewPKCS11Factor constructs a PKCS#11 unseal factor.
var NewPKCS11Factor = pkcs11factor.New

// MTLSFactor is the mTLS certificate-possession qrdb unseal factor.
type MTLSFactor = mtlsfactor.Factor

// MTLSFactorConfig configures the mTLS unseal factor.
type MTLSFactorConfig = mtlsfactor.Config

// NewMTLSFactor constructs an mTLS unseal factor.
var NewMTLSFactor = mtlsfactor.New

// --- Canonical factor composition (from pkg/factor) ---

// FactorConfig is the configuration type for the canonical four-factor
// composition (PIV, PKCS#11, FIDO2, mTLS). The zero value is valid and
// yields software-backed PIV plus DER/COSE-verifying PKCS#11, FIDO2, and
// certificate-possession mTLS factors.
type FactorConfig = factor.Config

// DefaultAuthFactors returns the canonical go-xkms hardware auth-factor plugin
// slice (piv, pkcs11, fido2, mtls) constructed from cfg. Downstream composers
// that want the standard four-factor set without constructing a registry call
// this function and pass the result to XKMSCryptoConfig.Factors.
var DefaultAuthFactors = factor.DefaultFactors

// NewDefaultFactorRegistry constructs and registers the canonical go-xkms auth
// factors (piv, pkcs11, fido2, mtls) into a fresh qrdb AuthFactorRegistry.
var NewDefaultFactorRegistry = factor.NewDefaultRegistry
