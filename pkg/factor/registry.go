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

// Package factor composes the go-xkms hardware auth-factor plugins (PIV,
// PKCS#11, FIDO2) into a single qrdb AuthFactorRegistry. qrdb owns the registry
// abstraction; go-xkms owns the concrete factor implementations and registers
// them here so that downstream binaries (quicbaas, the platform webservice) can
// inject the populated registry via the qrdb server constructor's
// WithFactorRegistry option.
package factor

import (
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/factor/fido2"
	"github.com/jeremyhahn/go-xkms/pkg/factor/piv"
	"github.com/jeremyhahn/go-xkms/pkg/factor/pkcs11"
	xkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Config configures the default factor registry. The zero value is valid and
// yields software-backed PIV plus DER/COSE-verifying PKCS#11 and FIDO2 factors.
type Config struct {
	// PIVGenerator produces crypto.Signers for PIV slots. When nil, a
	// software-only generator is used. Inject a hardware-backed generator
	// (PKCS#11 / TPM2) for hardware PIV deployments.
	PIVGenerator xkms.PIVKeyGenerator

	// PKCS11Mechanism overrides the default PKCS#11 signing mechanism recorded
	// on enrollments. Empty uses the package default (CKM_ECDSA_SHA256).
	PKCS11Mechanism string

	// FIDO2RPID overrides the default WebAuthn Relying Party id recorded on
	// FIDO2 enrollments and challenges. Empty uses the package default.
	FIDO2RPID string

	// ChallengeTTLSeconds overrides the challenge validity window for every
	// factor. Zero uses each factor's default (five minutes).
	ChallengeTTLSeconds int
}

// NewDefaultRegistry constructs and registers the canonical go-xkms auth
// factors (piv, pkcs11, fido2) into a fresh qrdb AuthFactorRegistry. It returns
// an error only if registration fails (which cannot happen for distinct,
// non-nil, non-empty factor names but is surfaced for completeness).
func NewDefaultRegistry(cfg Config) (*qrdbsdk.AuthFactorRegistry, error) {
	registry := qrdbsdk.NewFactorRegistry()

	factors := []qrdbsdk.AuthFactorPlugin{
		piv.New(piv.Config{
			Generator:           cfg.PIVGenerator,
			ChallengeTTLSeconds: cfg.ChallengeTTLSeconds,
		}),
		pkcs11.New(pkcs11.Config{
			DefaultMechanism:    cfg.PKCS11Mechanism,
			ChallengeTTLSeconds: cfg.ChallengeTTLSeconds,
		}),
		fido2.New(fido2.Config{
			RPID:                cfg.FIDO2RPID,
			ChallengeTTLSeconds: cfg.ChallengeTTLSeconds,
		}),
	}

	for _, f := range factors {
		if err := registry.Register(f); err != nil {
			return nil, err
		}
	}

	return registry, nil
}
